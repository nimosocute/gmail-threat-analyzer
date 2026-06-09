(() => {
  if (window.__BL_GMAIL_SCANNER_LIGHT__) return;
  window.__BL_GMAIL_SCANNER_LIGHT__ = true;

  const CURRENT_BATCH_KEY = "bl_current_batch_items";
  const CURRENT_BATCH_META_KEY = "bl_current_batch_meta";
  const CURRENT_BATCH_BINDINGS_KEY = "bl_current_batch_bindings";
  const CURRENT_BATCH_BINDINGS_META_KEY = "bl_current_batch_bindings_meta";

  const STATE = {
    settings: {
      backendBaseUrl: "http://127.0.0.1:8000"
    },
    currentBatchItems: [],
    currentBatchBindings: [],
    itemsByKey: new Map(),
    bindingByMsgId: new Map(),
    bindingByThreadId: new Map(),
    analyzeBusy: false,
    currentRoute: location.href,
    inboxTimer: null,
    openMailTimer: null,
    topBannerTimer: null,
    observer: null,
    lastAnalyzedKey: "",
    pendingBoundItemKey: "",
    pendingOpenAt: 0
  };

  const CONFIG = {
    ROUTE_POLL_MS: 1200,
    INBOX_RENDER_DEBOUNCE_MS: 500,
    OPEN_MAIL_DEBOUNCE_MS: 700,
    MAX_ROWS_TO_ANNOTATE: 200,
    PENDING_OPEN_KEY_MS: 15000
  };

  function normalizeText(value) {
    return String(value || "")
      .toLowerCase()
      .replace(/\s+/g, " ")
      .trim();
  }

  function escapeHtml(value) {
    return String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function normalizeUrl(base, path) {
    const cleanBase = String(base || "").replace(/\/+$/, "");
    const cleanPath = String(path || "").startsWith("/") ? path : `/${path || ""}`;
    return `${cleanBase}${cleanPath}`;
  }

  function toSafeNumber(value) {
    const num = Number(value);
    return Number.isFinite(num) ? num : 0;
  }

  function uniqueStrings(values) {
    return Array.from(
      new Set(
        (Array.isArray(values) ? values : [])
          .map((item) => String(item || "").trim())
          .filter(Boolean)
      )
    );
  }

  function normalizeGmailId(value) {
    const raw = String(value || "").trim().replace(/^<+|>+$/g, "");
    if (!raw) return "";

    const numericMatch = raw.match(/\d{15,}/);
    if (numericMatch) return numericMatch[0];

    const hexMatch = raw.match(/\b[0-9a-f]{12,}\b/i);
    if (hexMatch) {
      try {
        return BigInt(`0x${hexMatch[0]}`).toString(10);
      } catch {
        return "";
      }
    }

    return "";
  }

  function getBadgeMeta(label, score) {
    const text = normalizeText(label);
    const numericScore = Number(score || 0);

    if (
      text.includes("cực kỳ nguy hiểm") ||
      text.includes("nguy hiểm") ||
      text.includes("phish") ||
      text.includes("danger") ||
      numericScore >= 70
    ) {
      return { text: "Nguy hiểm", className: "bl-badge-danger", tone: "danger" };
    }

    if (
      text.includes("đáng ngờ") ||
      text.includes("nghi ngờ") ||
      text.includes("sus") ||
      text.includes("warn") ||
      numericScore >= 35
    ) {
      return { text: "Nghi ngờ", className: "bl-badge-warn", tone: "warn" };
    }

    return { text: "An toàn", className: "bl-badge-safe", tone: "safe" };
  }

  function getItemByKey(itemKey) {
    const key = String(itemKey || "").trim();
    if (!key) return null;
    return STATE.itemsByKey.get(key) || null;
  }

  function buildBatchItemFromStorage(entry) {
    if (!entry || typeof entry !== "object") return null;
    return {
      key: String(entry.key || entry.id || "").trim(),
      id: String(entry.id || entry.key || "").trim(),
      scan_session_id: String(entry.scan_session_id || "").trim(),
      scan_order: Number.isFinite(Number(entry.scan_order)) ? Number(entry.scan_order) : 0,
      mail_id: String(entry.mail_id || "").trim(),
      subject: String(entry.subject || "").trim(),
      sender: String(entry.sender || "").trim(),
      sender_email: String(entry.sender_email || "").trim(),
      label: String(entry.label || entry.verdict || "Không rõ").trim(),
      score: toSafeNumber(entry.score),
      issues: uniqueStrings(entry.issues || []),
      triggered_rules: Array.isArray(entry.triggered_rules) ? entry.triggered_rules : [],
      urls: uniqueStrings(entry.urls || []),
      attachments: uniqueStrings(entry.attachments || []),
      source: String(entry.source || "scan-imap-batch").trim(),
      updated_at: String(entry.updated_at || new Date().toISOString()).trim(),
      raw_summary: entry.raw_summary || null,
      raw_email: entry.raw_email || null,
      auth: entry.auth || null,
      url_debug: entry.url_debug || null,
      confidence: String(entry.confidence || "").trim(),
      attack_type: String(entry.attack_type || "").trim()
    };
  }

  function rebuildLookups(items, bindings) {
    STATE.currentBatchItems = Array.isArray(items) ? items.filter(Boolean) : [];
    STATE.currentBatchBindings = Array.isArray(bindings) ? bindings.filter(Boolean) : [];
    STATE.itemsByKey = new Map();
    STATE.bindingByMsgId = new Map();
    STATE.bindingByThreadId = new Map();

    for (const item of STATE.currentBatchItems) {
      if (item?.key) STATE.itemsByKey.set(item.key, item);
    }

    for (const binding of STATE.currentBatchBindings) {
      const msgId = normalizeGmailId(binding?.gmail_msgid);
      const thrId = normalizeGmailId(binding?.gmail_thrid);
      if (msgId) STATE.bindingByMsgId.set(msgId, binding);
      if (thrId) STATE.bindingByThreadId.set(thrId, binding);
    }
  }

  async function loadCurrentBatch() {
    const data = await chrome.storage.local.get({
      [CURRENT_BATCH_KEY]: [],
      [CURRENT_BATCH_BINDINGS_KEY]: [],
      [CURRENT_BATCH_META_KEY]: null,
      [CURRENT_BATCH_BINDINGS_META_KEY]: null
    });

    const items = Array.isArray(data[CURRENT_BATCH_KEY])
      ? data[CURRENT_BATCH_KEY].map(buildBatchItemFromStorage).filter(Boolean)
      : [];
    const bindings = Array.isArray(data[CURRENT_BATCH_BINDINGS_KEY]) ? data[CURRENT_BATCH_BINDINGS_KEY] : [];
    rebuildLookups(items, bindings);
    return { items, bindings };
  }

  async function getSettings() {
    const settings = await chrome.storage.sync.get({
      backendBaseUrl: "http://127.0.0.1:8000"
    });
    STATE.settings = settings;
    return settings;
  }

  async function apiFetch(path, options = {}) {
    const settings = await getSettings();
    const url = normalizeUrl(settings.backendBaseUrl, path);

    const res = await fetch(url, options);
    const text = await res.text();

    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${typeof data === "string" ? data : JSON.stringify(data)}`);
    }

    return data;
  }

  function ensureStyles() {
    if (document.getElementById("bl-gmail-style")) return;

    const style = document.createElement("style");
    style.id = "bl-gmail-style";
    style.textContent = `
      .bl-mail-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        margin-left: 8px;
        padding: 2px 8px;
        border-radius: 999px;
        font-size: 11px;
        font-weight: 700;
        line-height: 1.5;
        vertical-align: middle;
        border: 1px solid transparent;
        pointer-events: none;
      }
      .bl-badge-safe { background:#ecfdf3; color:#166534; border-color:#86efac; }
      .bl-badge-warn { background:#fffbeb; color:#92400e; border-color:#fcd34d; }
      .bl-badge-danger { background:#fef2f2; color:#991b1b; border-color:#fca5a5; }
      .bl-top-banner {
        position: fixed; top: 12px; right: 20px; z-index: 999999;
        padding: 10px 14px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.18);
        font-size: 13px; font-weight: 700; max-width: 420px; font-family: Arial, sans-serif;
      }
      .bl-top-banner.safe { background:#ecfdf3; color:#166534; border:1px solid #86efac; }
      .bl-top-banner.warn { background:#fffbeb; color:#92400e; border:1px solid #fcd34d; }
      .bl-top-banner.danger { background:#fef2f2; color:#991b1b; border:1px solid #fca5a5; }
      .bl-side-panel {
        position: fixed; top: 78px; right: 18px; width: 360px; max-height: calc(100vh - 96px);
        overflow: auto; z-index: 999998; background: #ffffff; border:1px solid #e5e7eb;
        border-radius: 16px; box-shadow: 0 12px 32px rgba(0,0,0,0.18); padding: 14px; font-family: Arial, sans-serif;
      }
      .bl-side-panel h3 { margin: 0 0 10px; font-size: 17px; }
      .bl-side-panel .bl-row { margin-bottom: 10px; }
      .bl-side-panel .bl-label { color:#6b7280; font-size:12px; margin-bottom:4px; }
      .bl-side-panel .bl-value { font-size:13px; color:#111827; word-break:break-word; }
      .bl-side-panel ul { margin:8px 0 0 18px; padding:0; }
      .bl-side-panel li { margin-bottom:6px; font-size:13px; line-height:1.45; }
      .bl-link-flag {
        outline: 2px solid #ef4444 !important;
        outline-offset: 2px !important;
        border-radius: 4px !important;
        background: rgba(239, 68, 68, 0.08) !important;
      }
      .bl-mini-note { font-size: 12px; color:#6b7280; margin-top:8px; }
      .bl-panel-close {
        border:none; background:transparent; font-size:18px; cursor:pointer; float:right; line-height:1; color:#6b7280;
      }
    `;
    document.documentElement.appendChild(style);
  }

  function showTopBanner(message, tone = "safe", autoHideMs = 3000) {
    ensureStyles();

    let el = document.getElementById("bl-top-banner");
    if (!el) {
      el = document.createElement("div");
      el.id = "bl-top-banner";
      el.className = "bl-top-banner";
      document.body.appendChild(el);
    }

    el.className = `bl-top-banner ${tone}`;
    el.textContent = message;
    el.style.display = "block";

    if (STATE.topBannerTimer) clearTimeout(STATE.topBannerTimer);
    if (autoHideMs > 0) {
      STATE.topBannerTimer = setTimeout(() => {
        if (el) el.style.display = "none";
      }, autoHideMs);
    }
  }

function uniqElements(elements) {
  const seen = new Set();
  const out = [];

  for (const el of elements) {
    if (!(el instanceof HTMLElement)) continue;
    if (seen.has(el)) continue;
    seen.add(el);
    out.push(el);
  }

  return out;
}

function findInboxRows() {
  const rawCandidates = uniqElements([
    ...document.querySelectorAll('tr.zA'),
    ...document.querySelectorAll('tr[role="row"][jscontroller]'),
    ...document.querySelectorAll('[data-legacy-thread-id]'),
    ...document.querySelectorAll('[data-thread-perm-id]'),
    ...document.querySelectorAll('[data-thread-id]')
  ]);

  const rows = uniqElements(
    rawCandidates
      .map((node) => node.closest('tr[role="row"]') || node)
      .filter(Boolean)
  );

  return rows
    .filter((row) => !row.closest("#bl-side-panel"))
    .filter((row) => {
      const subject = getRowSubject(row);
      const senderInfo = getRowSenderInfo(row);
      return !!(subject || senderInfo.display || senderInfo.email);
    })
    .slice(0, CONFIG.MAX_ROWS_TO_ANNOTATE);
}

  function getRowSubject(row) {
    const candidates = [row.querySelector(".bog"), row.querySelector(".y6 span"), row.querySelector("span[id]")];
    for (const el of candidates) {
      const text = el?.textContent?.trim();
      if (text) return text;
    }
    return "";
  }

  function getRowSenderInfo(row) {
    const candidates = [row.querySelector("span[email]"), row.querySelector(".yP"), row.querySelector(".zF")];
    for (const el of candidates) {
      if (!el) continue;
      const text = String(el.textContent || "").trim();
      const emailAttr = String(el.getAttribute?.("email") || "").trim();
      if (text || emailAttr) return { display: text, email: emailAttr };
    }
    return { display: "", email: "" };
  }

  function getNormalizedAttrFromScope(scope, attrNames = [], normalizer = (v) => String(v || "").trim()) {
    const values = [];

    const collectFromNode = (node) => {
      if (!(node instanceof Element)) return;
      for (const attr of attrNames) {
        const value = node.getAttribute(attr);
        if (value) values.push(value);
      }
    };

    collectFromNode(scope);

    if (scope && scope.querySelectorAll) {
      const selector = attrNames.map((attr) => `[${attr}]`).join(",");
      if (selector) {
        for (const el of scope.querySelectorAll(selector)) collectFromNode(el);
      }
    }

    for (const value of values) {
      const normalized = normalizer(value);
      if (normalized) return normalized;
    }

    return "";
  }

  function getNormalizedAttrFromAncestors(node, attrNames = [], normalizer = (v) => String(v || "").trim()) {
  let current = node instanceof Element ? node : null;

  while (current) {
    for (const attr of attrNames) {
      const value = current.getAttribute?.(attr);
      if (!value) continue;

      const normalized = normalizer(value);
      if (normalized) return normalized;
    }
    current = current.parentElement;
  }

  return "";
}

function extractThreadIdFromHref(scope) {
  if (!(scope instanceof Element)) return "";

  const anchors = Array.from(scope.querySelectorAll('a[href]'));
  for (const a of anchors) {
    const href = String(a.getAttribute("href") || a.href || "").trim();
    if (!href) continue;

    const directMatch =
      href.match(/#(?:inbox|all|sent|spam|drafts|starred|important|scheduled|snoozed|category\/[^/]+|label\/[^/]+)\/([^/?&#]+)/i) ||
      href.match(/[#/](FMfcgz[a-zA-Z0-9_-]+)$/i) ||
      href.match(/[#/]([a-zA-Z0-9_-]{12,})$/);

    if (directMatch?.[1]) {
      const normalized = normalizeGmailId(directMatch[1]);
      if (normalized) return normalized;
    }
  }

  return "";
}

function extractInboxRowExactIds(row) {
  if (!(row instanceof HTMLElement)) return { gmail_msgid: "", gmail_thrid: "" };

  const msgAttrs = [
    "data-legacy-message-id",
    "data-message-id",
    "data-legacy-last-message-id",
    "data-last-message-id"
  ];

  const thrAttrs = [
    "data-legacy-thread-id",
    "data-thread-perm-id",
    "data-thread-id"
  ];

  const gmailMsgId =
    getNormalizedAttrFromScope(row, msgAttrs, normalizeGmailId) ||
    getNormalizedAttrFromAncestors(row, msgAttrs, normalizeGmailId);

  const gmailThreadId =
    getNormalizedAttrFromScope(row, thrAttrs, normalizeGmailId) ||
    getNormalizedAttrFromAncestors(row, thrAttrs, normalizeGmailId);

  return {
    gmail_msgid: gmailMsgId || "",
    gmail_thrid: gmailThreadId || ""
  };
}

  function extractOpenMailExactIds() {
    const scopes = [document.querySelector('div[role="main"]'), document.querySelector('.nH'), document].filter(Boolean);

    let gmailMsgId = "";
    let gmailThreadId = "";

    for (const scope of scopes) {
      if (!gmailMsgId) {
        gmailMsgId = getNormalizedAttrFromScope(
          scope,
          ["data-legacy-message-id", "data-message-id", "data-legacy-last-message-id", "data-last-message-id"],
          normalizeGmailId
        );
      }

      if (!gmailThreadId) {
        gmailThreadId = getNormalizedAttrFromScope(
          scope,
          ["data-thread-perm-id", "data-legacy-thread-id", "data-thread-id"],
          normalizeGmailId
        );
      }

      if (gmailMsgId || gmailThreadId) break;
    }

    return { gmail_msgid: gmailMsgId, gmail_thrid: gmailThreadId };
  }

  function getBindingByExactIds({ gmail_msgid = "", gmail_thrid = "" } = {}) {
    const msgId = normalizeGmailId(gmail_msgid);
    if (msgId && STATE.bindingByMsgId.has(msgId)) return STATE.bindingByMsgId.get(msgId);

    const thrId = normalizeGmailId(gmail_thrid);
    if (thrId && STATE.bindingByThreadId.has(thrId)) return STATE.bindingByThreadId.get(thrId);

    return null;
  }

  function getBoundItemByExactIds(ids) {
    const binding = getBindingByExactIds(ids);
    const item = getItemByKey(binding?.item_key || "");
    return item || null;
  }

  function injectBadgeIntoRow(row, item) {
    const subjectNode = row.querySelector(".bog") || row.querySelector(".y6 span") || row.querySelector("span[id]");
    if (!subjectNode || !item) return;

    const meta = getBadgeMeta(item.label, item.score);
    let badge = row.querySelector(".bl-mail-badge");

    if (!badge) {
      badge = document.createElement("span");
      badge.className = "bl-mail-badge";
      badge.setAttribute("data-bl-owned", "1");
      subjectNode.insertAdjacentElement("afterend", badge);
    }

    badge.className = `bl-mail-badge ${meta.className}`;
    badge.textContent = `${meta.text} • ${item.score ?? 0}`;
    badge.dataset.blKey = item.key;
    row.dataset.blKey = item.key;
  }

  function clearBadgeFromRow(row) {
    row.querySelectorAll(".bl-mail-badge").forEach((el) => el.remove());
    delete row.dataset.blKey;
    delete row.dataset.blGmailMsgid;
    delete row.dataset.blGmailThrid;
  }

  function rememberPendingBoundItemKeyFromEventTarget(target) {
    if (!(target instanceof HTMLElement)) return;
    const row = target.closest('tr[role="row"]');
    if (!row) return;

    const exactIds = extractInboxRowExactIds(row);
    const item = getBoundItemByExactIds(exactIds);
    if (!item?.key) return;

    STATE.pendingBoundItemKey = item.key;
    STATE.pendingOpenAt = Date.now();
  }

  function annotateInboxRows() {
    const rows = findInboxRows();
    if (!STATE.currentBatchBindings.length || !STATE.currentBatchItems.length) {
      rows.forEach(clearBadgeFromRow);
      return;
    }

    rows.forEach((row) => {
      const exactIds = extractInboxRowExactIds(row);
      row.dataset.blGmailMsgid = exactIds.gmail_msgid || "";
      row.dataset.blGmailThrid = exactIds.gmail_thrid || "";

      const matched = getBoundItemByExactIds(exactIds);
      if (!matched) {
        clearBadgeFromRow(row);
        return;
      }

      injectBadgeIntoRow(row, matched);
    });
  }

  function getOpenMailSubject() {
    const selectors = ['h2[data-thread-perm-id]', 'h2.hP', '.ha h2', 'div[role="main"] h2'];
    const badSubjects = new Set(['tìm kiếm', 'search', 'hộp thư đến', 'inbox']);

    for (const selector of selectors) {
      const nodes = Array.from(document.querySelectorAll(selector));
      for (const el of nodes) {
        const text = (el.textContent || '').trim();
        const normalized = normalizeText(text);
        if (!text || text.length <= 1) continue;
        if (badSubjects.has(normalized)) continue;
        return text;
      }
    }

    const fallbackCandidates = Array.from(document.querySelectorAll('h2, [role="heading"]'));
    for (const el of fallbackCandidates) {
      const text = (el.textContent || '').trim();
      const normalized = normalizeText(text);
      if (!text || text.length <= 1) continue;
      if (badSubjects.has(normalized)) continue;
      return text;
    }

    return '';
  }

  function getOpenMailSenderInfo() {
    const senderEl =
      document.querySelector('.gD[email]') ||
      document.querySelector('span[email]') ||
      document.querySelector('.gD') ||
      document.querySelector('.go');

    return {
      senderName: (senderEl?.textContent || '').trim(),
      senderEmail: senderEl?.getAttribute?.('email') || ''
    };
  }

  function getVisibleBodyContainer() {
    const bodies = Array.from(document.querySelectorAll('.a3s.aiL, .a3s')).filter((el) => el && el.offsetParent !== null);
    return bodies[0] || null;
  }

  function extractUrlsAndAnchorPairs(container) {
    if (!container) return { urls: [], anchor_pairs: [] };
    const anchors = Array.from(container.querySelectorAll('a[href]'));
    const urls = [];
    const anchorPairs = [];

    for (const a of anchors) {
      const href = a.href || a.getAttribute('href') || '';
      const text = (a.textContent || '').trim();
      if (!href) continue;
      urls.push(href);
      anchorPairs.push([href, text]);
    }

    return {
      urls: uniqueStrings(urls),
      anchor_pairs: anchorPairs
    };
  }

  function extractAttachments() {
    const chips = Array.from(document.querySelectorAll('[download_url], .aQA, .aQH'));
    const out = [];
    for (const node of chips) {
      const text = (node.textContent || '').trim();
      if (text && text.length < 200) out.push(text);
    }
    return uniqueStrings(out);
  }

  function buildAnalyzePayloadFromOpenMail() {
    const subject = getOpenMailSubject();
    const senderInfo = getOpenMailSenderInfo();
    const bodyContainer = getVisibleBodyContainer();
    if (!subject || !bodyContainer) return null;

    const bodyText = (bodyContainer.innerText || '').trim();
    const bodyHtml = bodyContainer.innerHTML || '';
    const extracted = extractUrlsAndAnchorPairs(bodyContainer);
    const attachments = extractAttachments();
    const exactIds = extractOpenMailExactIds();

    const sender = senderInfo.senderEmail
      ? `${senderInfo.senderName || senderInfo.senderEmail} <${senderInfo.senderEmail}>`
      : senderInfo.senderName || '';

    return {
      subject,
      sender,
      sender_email: senderInfo.senderEmail || '',
      gmail_msgid: exactIds.gmail_msgid || '',
      gmail_thrid: exactIds.gmail_thrid || '',
      reply_to: '',
      to: '',
      cc: '',
      return_path: '',
      body_text: bodyText,
      body_html: bodyHtml,
      urls: extracted.urls,
      anchor_pairs: extracted.anchor_pairs,
      attachments,
      attachment_meta: [],
      auth: {},
      received_headers: [],
      headers_preview: ''
    };
  }

  function removeOldLinkFlags() {
    document.querySelectorAll('.bl-link-flag').forEach((el) => el.classList.remove('bl-link-flag'));
  }

  function flagSuspiciousLinksByItem(item) {
    removeOldLinkFlags();

    const bodyContainer = getVisibleBodyContainer();
    if (!bodyContainer) return;

    const issuesText = uniqueStrings(item?.issues || []).join(' ').toLowerCase();
    const rulesText = (item?.triggered_rules || [])
      .map((rule) => (typeof rule === 'string' ? rule : rule?.rule || ''))
      .join(' ')
      .toLowerCase();

    const shouldFlagLinks = [issuesText, rulesText].join(' ').includes('url') || [issuesText, rulesText].join(' ').includes('link');
    if (!shouldFlagLinks) return;

    const links = Array.from(bodyContainer.querySelectorAll('a[href]'));
    const suspiciousUrls = new Set((item?.urls || []).map((u) => String(u || '').trim()));

    for (const link of links) {
      const href = String(link.href || '').trim();
      if (!href) continue;
      if (!suspiciousUrls.size || suspiciousUrls.has(href)) {
        link.classList.add('bl-link-flag');
      }
    }
  }

  function ensurePanel() {
    let panel = document.getElementById('bl-side-panel');
    if (!panel) {
      panel = document.createElement('div');
      panel.id = 'bl-side-panel';
      panel.className = 'bl-side-panel';
      panel.setAttribute('data-bl-owned', '1');
      panel.style.display = 'none';
      document.body.appendChild(panel);
    }
    return panel;
  }

  function hidePanel() {
    const panel = document.getElementById('bl-side-panel');
    if (panel) panel.style.display = 'none';
    removeOldLinkFlags();
  }

  function renderSidePanelFromItem(item, openMail) {
    const panel = ensurePanel();
    const meta = getBadgeMeta(item.label, item.score);
    const issues = uniqueStrings(item.issues || []);
    const rules = Array.isArray(item.triggered_rules) ? item.triggered_rules : [];

    const issuesHtml = issues.length
      ? `<ul>${issues.slice(0, 12).map((issue) => `<li>${escapeHtml(issue)}</li>`).join('')}</ul>`
      : `<div class="bl-value">Chưa có issue chi tiết.</div>`;

    const rulesHtml = rules.length
      ? `<ul>${rules.slice(0, 12).map((rule) => {
          const name = typeof rule === 'string' ? rule : rule?.rule || '';
          const reason = typeof rule === 'string' ? '' : rule?.reason || '';
          return `<li><b>${escapeHtml(name)}</b>${reason ? `: ${escapeHtml(reason)}` : ''}</li>`;
        }).join('')}</ul>`
      : `<div class="bl-value">Chưa có rule chi tiết.</div>`;

    panel.innerHTML = `
      <button class="bl-panel-close" title="Đóng">×</button>
      <h3>Phân tích mail</h3>

      <div class="bl-row">
        <div class="bl-label">Tiêu đề</div>
        <div class="bl-value">${escapeHtml(openMail.subject || item.subject || '')}</div>
      </div>

      <div class="bl-row">
        <div class="bl-label">Người gửi</div>
        <div class="bl-value">${escapeHtml(openMail.sender || item.sender || '')}</div>
      </div>

      <div class="bl-row">
        <div class="bl-label">Trạng thái</div>
        <div class="bl-value">
          <span class="bl-mail-badge ${meta.className}" style="margin-left:0;">${escapeHtml(meta.text)} • ${escapeHtml(String(item.score ?? 0))}</span>
        </div>
      </div>

      <div class="bl-row">
        <div class="bl-label">Điểm nghi ngờ</div>
        <div class="bl-value">${escapeHtml(String(item.score ?? 0))}</div>
      </div>

      <div class="bl-row">
        <div class="bl-label">Nguồn</div>
        <div class="bl-value">${escapeHtml(String(item.source || 'scan-imap-batch'))}</div>
      </div>

      ${item.attack_type ? `
      <div class="bl-row">
        <div class="bl-label">Loại tấn công</div>
        <div class="bl-value">${escapeHtml(item.attack_type)}</div>
      </div>` : ''}

      ${item.confidence ? `
      <div class="bl-row">
        <div class="bl-label">Confidence</div>
        <div class="bl-value">${escapeHtml(item.confidence)}</div>
      </div>` : ''}

      <div class="bl-row">
        <div class="bl-label">Các điểm nghi ngờ</div>
        ${issuesHtml}
      </div>

      <div class="bl-row">
        <div class="bl-label">Rule kích hoạt</div>
        ${rulesHtml}
      </div>

      <div class="bl-mini-note">Panel chỉ dùng exact binding của batch scan hiện tại. Không match exact thì mới gọi analyze-email cho chính mail đang mở.</div>
    `;

    const closeBtn = panel.querySelector('.bl-panel-close');
    if (closeBtn) closeBtn.onclick = () => hidePanel();
    panel.style.display = 'block';

    flagSuspiciousLinksByItem(item);
  }

  function renderSidePanelFromAnalyze(analyzeResult, openMail) {
    const tempItem = {
      label: analyzeResult?.label || 'Không rõ',
      score: toSafeNumber(analyzeResult?.score),
      issues: uniqueStrings(analyzeResult?.issues || []),
      triggered_rules: Array.isArray(analyzeResult?.evidence?.fired_rules)
        ? analyzeResult.evidence.fired_rules.map((rule) => ({
            rule: String(rule?.rule || '').trim(),
            reason: String(rule?.reason || '').trim()
          }))
        : [],
      urls: uniqueStrings(openMail?.urls || []),
      source: 'analyze-email-fallback'
    };

    renderSidePanelFromItem(tempItem, openMail);
  }

  async function analyzeOpenMailNow() {
    if (STATE.analyzeBusy) return;

    const payloadMail = buildAnalyzePayloadFromOpenMail();
    if (!payloadMail) {
      hidePanel();
      return;
    }

    const key = [
      payloadMail.subject,
      payloadMail.sender_email,
      payloadMail.gmail_msgid,
      payloadMail.gmail_thrid,
      payloadMail.body_text.slice(0, 120)
    ].join('|');

    if (STATE.lastAnalyzedKey === key) return;
    STATE.lastAnalyzedKey = key;

    const exactItem = getBoundItemByExactIds({
      gmail_msgid: payloadMail.gmail_msgid,
      gmail_thrid: payloadMail.gmail_thrid
    });
    if (exactItem) {
      renderSidePanelFromItem(exactItem, payloadMail);
      return;
    }

    const hasFreshPendingKey =
      STATE.pendingBoundItemKey &&
      Date.now() - STATE.pendingOpenAt <= CONFIG.PENDING_OPEN_KEY_MS &&
      STATE.itemsByKey.has(STATE.pendingBoundItemKey);

    if (hasFreshPendingKey) {
      const pendingItem = STATE.itemsByKey.get(STATE.pendingBoundItemKey);
      STATE.pendingBoundItemKey = '';
      STATE.pendingOpenAt = 0;
      renderSidePanelFromItem(pendingItem, {
        ...payloadMail,
        subject: pendingItem?.subject || payloadMail.subject,
        sender: pendingItem?.sender || payloadMail.sender,
        sender_email: pendingItem?.sender_email || payloadMail.sender_email
      });
      return;
    }

    STATE.analyzeBusy = true;
    try {
      const analyzeResult = await apiFetch('/api/analyze-email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json'
        },
        body: JSON.stringify({
          email: payloadMail,
          enable_online_checks: true
        })
      });

      renderSidePanelFromAnalyze(analyzeResult, payloadMail);
    } catch (err) {
      console.error('BL analyzeOpenMail error:', err);
    } finally {
      STATE.analyzeBusy = false;
    }
  }

  function debounce(fn, wait, keyName) {
    return (...args) => {
      if (STATE[keyName]) clearTimeout(STATE[keyName]);
      STATE[keyName] = setTimeout(() => fn(...args), wait);
    };
  }

  const debouncedAnnotateInbox = debounce(() => annotateInboxRows(), CONFIG.INBOX_RENDER_DEBOUNCE_MS, 'inboxTimer');
  const debouncedAnalyzeOpenMail = debounce(() => analyzeOpenMailNow(), CONFIG.OPEN_MAIL_DEBOUNCE_MS, 'openMailTimer');

  function isInboxLikePage() {
    return location.href.includes('mail.google.com');
  }

  function isReadingMail() {
    return !!getVisibleBodyContainer() && !!getOpenMailSubject();
  }

  async function refreshForCurrentView() {
    if (document.hidden) return;
    await loadCurrentBatch();

    if (isInboxLikePage()) debouncedAnnotateInbox();
    if (isReadingMail()) {
      debouncedAnalyzeOpenMail();
    } else {
      hidePanel();
      STATE.lastAnalyzedKey = '';
      STATE.pendingBoundItemKey = '';
      STATE.pendingOpenAt = 0;
    }
  }

  function startRoutePolling() {
    setInterval(async () => {
      if (location.href !== STATE.currentRoute) {
        STATE.currentRoute = location.href;
        STATE.lastAnalyzedKey = '';
        await refreshForCurrentView();
      }
    }, CONFIG.ROUTE_POLL_MS);
  }

  function startLightObserver() {
    if (STATE.observer) {
      try { STATE.observer.disconnect(); } catch (_) {}
    }

    STATE.observer = new MutationObserver((mutations) => {
      let shouldCheckInbox = false;
      let shouldCheckOpenMail = false;

      for (const m of mutations) {
        if (m.type !== 'childList') continue;
        if (m.target && m.target.id === 'bl-side-panel') continue;

        const added = Array.from(m.addedNodes || []);
        for (const node of added) {
          if (!(node instanceof HTMLElement)) continue;
          if (node.closest && node.closest('#bl-side-panel')) continue;
          if (node.getAttribute && node.getAttribute('data-bl-owned') === '1') continue;

          if (
            node.matches?.('tr[role="row"]') ||
            node.querySelector?.('tr[role="row"]') ||
            node.querySelector?.('.bog')
          ) {
            shouldCheckInbox = true;
          }

          if (
            node.querySelector?.('.a3s.aiL, .a3s') ||
            node.matches?.('.a3s.aiL, .a3s') ||
            node.querySelector?.('h2')
          ) {
            shouldCheckOpenMail = true;
          }
        }
      }

      if (shouldCheckInbox) debouncedAnnotateInbox();
      if (shouldCheckOpenMail) debouncedAnalyzeOpenMail();
    });

    const main = document.body || document.documentElement;
    STATE.observer.observe(main, { childList: true, subtree: true });
  }

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "BL_CAPTURE_INBOX_ROWS") {
    const domRows = findInboxRows();

    console.groupCollapsed("[content][capture] DOM rows");
    console.log("[content][capture] raw row count =", domRows.length);

    const rows = domRows
      .map((row, index) => {
        const subject = getRowSubject(row);
        const senderInfo = getRowSenderInfo(row);
        const exactIds = extractInboxRowExactIds(row);

        const out = {
          row_index: index,
          subject,
          sender: senderInfo.display || senderInfo.email || "",
          gmail_msgid: exactIds.gmail_msgid || "",
          gmail_thrid: exactIds.gmail_thrid || ""
        };

        console.log(`[content][capture][row ${index}]`, out, row);
        return out;
      })
      .filter((row) => row.subject || row.sender || row.gmail_msgid || row.gmail_thrid);

    console.table(rows.map((r) => ({
      row_index: r.row_index,
      subject: r.subject,
      sender: r.sender,
      gmail_msgid: r.gmail_msgid,
      gmail_thrid: r.gmail_thrid
    })));

    console.log("[content][capture] summary =", {
      total: rows.length,
      withExactIds: rows.filter((r) => r.gmail_msgid || r.gmail_thrid).length
    });
    console.groupEnd();

    sendResponse({ ok: true, rows });
    return true;
  }

  return false;
});

  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== 'local') return;
    if (!changes[CURRENT_BATCH_KEY] && !changes[CURRENT_BATCH_BINDINGS_KEY]) return;

    loadCurrentBatch().then(() => {
      debouncedAnnotateInbox();
      if (isReadingMail()) debouncedAnalyzeOpenMail();
    }).catch((err) => console.error('BL storage sync error:', err));
  });

  document.addEventListener('mousedown', (event) => {
    rememberPendingBoundItemKeyFromEventTarget(event.target);
  }, true);

  document.addEventListener('click', (event) => {
    rememberPendingBoundItemKeyFromEventTarget(event.target);
  }, true);

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) refreshForCurrentView();
  });

  async function init() {
    ensureStyles();
    await getSettings();
    await loadCurrentBatch();
    await refreshForCurrentView();
    startRoutePolling();
    startLightObserver();
  }

  init().catch((err) => {
    console.error('BL init error:', err);
    showTopBanner('Extension Gmail khởi tạo thất bại.', 'danger');
  });
})(); 