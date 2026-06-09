const DASHBOARD_HISTORY_KEY = "bl_dashboard_history";
const DASHBOARD_META_KEY = "bl_dashboard_meta";

const searchInput = document.getElementById("searchInput");
const sessionFilter = document.getElementById("sessionFilter");
const btnRefresh = document.getElementById("btnRefresh");
const btnClearHistory = document.getElementById("btnClearHistory");
const summaryText = document.getElementById("summaryText");
const mailList = document.getElementById("mailList");
const detailPane = document.getElementById("detailPane");

const state = {
  history: [],
  items: [],
  selectedKey: null,
  meta: null,
  sourceEntries: []
};

function pretty(data) {
  try {
    return JSON.stringify(data, null, 2);
  } catch {
    return String(data);
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function normalizeText(value) {
  return String(value ?? "").trim();
}

function formatDate(isoText) {
  if (!isoText) return "";
  const date = new Date(isoText);
  if (Number.isNaN(date.getTime())) return String(isoText);
  return date.toLocaleString("vi-VN");
}

function getByPath(obj, path) {
  if (!obj || !path) return undefined;
  const parts = path.split(".");
  let current = obj;
  for (const part of parts) {
    if (current == null || typeof current !== "object" || !(part in current)) {
      return undefined;
    }
    current = current[part];
  }
  return current;
}

function firstDefined(obj, paths) {
  for (const path of paths) {
    const value = getByPath(obj, path);
    if (value !== undefined && value !== null && value !== "") return value;
  }
  return undefined;
}

function toSafeNumber(value) {
  const num = Number(value);
  return Number.isFinite(num) ? num : null;
}

function uniqueStrings(values) {
  const seen = new Set();
  const out = [];
  for (const value of Array.isArray(values) ? values : []) {
    const cleaned = normalizeText(value);
    if (!cleaned || seen.has(cleaned)) continue;
    seen.add(cleaned);
    out.push(cleaned);
  }
  return out;
}

function splitRuleString(value) {
  return uniqueStrings(
    String(value || "")
      .split(/\s*,\s*/)
      .map((v) => v.trim())
      .filter(Boolean)
  );
}

function splitIssueString(value) {
  return uniqueStrings(
    String(value || "")
      .split(/\s*\|\s*/)
      .map((v) => v.trim())
      .filter(Boolean)
  );
}

function getScore(email) {
  return toSafeNumber(
    firstDefined(email, [
      "score",
      "risk_score",
      "phishing_score",
      "raw_summary.Điểm",
      "raw_analysis.score"
    ])
  );
}

function getLabel(email) {
  return firstDefined(email, [
    "label",
    "risk_label",
    "classification",
    "verdict",
    "raw_summary.Trạng thái",
    "raw_analysis.label"
  ]) ?? null;
}

function getBadgeClass(score, label) {
  const labelText = String(label ?? "").toLowerCase();

  if (labelText.includes("nguy")) return "red";
  if (labelText.includes("sus") || labelText.includes("nghi")) return "yellow";
  if (labelText.includes("safe") || labelText.includes("an toàn")) return "green";

  if (typeof score === "number") {
    if (score >= 80) return "red";
    if (score >= 50) return "yellow";
    return "green";
  }

  return "gray";
}

function flattenTriggerValue(value, prefix = "") {
  const out = [];

  if (value == null) return out;

  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    out.push(prefix ? `${prefix}: ${String(value)}` : String(value));
    return out;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      out.push(...flattenTriggerValue(item, prefix));
    }
    return out;
  }

  if (typeof value === "object") {
    const named = value.rule || value.name || value.id || value.key || value.title;
    if (named) {
      const pieces = [String(named)];
      if (value.reason) pieces.push(`reason=${value.reason}`);
      if (value.score !== undefined && value.score !== null && value.score !== "") {
        pieces.push(`score=${value.score}`);
      }
      out.push(pieces.join(" | "));
      return out;
    }

    for (const [k, v] of Object.entries(value)) {
      out.push(...flattenTriggerValue(v, prefix ? `${prefix}.${k}` : k));
    }
  }

  return out;
}

function getTriggerItems(email) {
  const directTriggered = email?.triggered_rules;
  if (Array.isArray(directTriggered) && directTriggered.length) {
    return uniqueStrings(flattenTriggerValue(directTriggered)).slice(0, 200);
  }

  const fromSummary = splitRuleString(firstDefined(email, ["raw_summary.Rules kích hoạt", "rules", "triggered_rules"]));
  if (fromSummary.length) return fromSummary;

  return [];
}

function getIssues(email) {
  const direct = uniqueStrings(Array.isArray(email?.issues) ? email.issues : []);
  if (direct.length) return direct;

  const fromSummary = splitIssueString(firstDefined(email, ["raw_summary.Chi tiết vi phạm"]));
  return fromSummary;
}

function getDebugSections(email) {
  const sections = [];
  const keys = ["raw_summary", "raw_email", "raw_analysis", "auth", "url_debug"];
  for (const key of keys) {
    if (email && typeof email[key] === "object" && email[key] !== null) {
      sections.push({ title: key, value: email[key] });
    }
  }
  return sections;
}

function dedupeHistory(items) {
  const map = new Map();

  for (const item of Array.isArray(items) ? items : []) {
    const key = item?.key || item?.id || `${normalizeText(item?.subject)}||${normalizeText(item?.sender_email || item?.sender)}`;
    if (!key) continue;

    const previous = map.get(key);
    if (!previous) {
      map.set(key, { ...item, key, id: key });
      continue;
    }

    const prevUpdated = new Date(previous?.updated_at || 0).getTime();
    const currUpdated = new Date(item?.updated_at || 0).getTime();

    map.set(key, {
      ...previous,
      ...item,
      key,
      id: key,
      triggered_rules: Array.isArray(item?.triggered_rules) && item.triggered_rules.length
        ? item.triggered_rules
        : previous.triggered_rules,
      issues: Array.isArray(item?.issues) && item.issues.length
        ? item.issues
        : previous.issues,
      updated_at: currUpdated >= prevUpdated ? item.updated_at : previous.updated_at
    });
  }

  return Array.from(map.values()).sort((a, b) => {
    const ta = new Date(a?.updated_at || 0).getTime();
    const tb = new Date(b?.updated_at || 0).getTime();
    return tb - ta;
  });
}

function buildItems(history) {
  const items = [];
  const selectedSource = sessionFilter.value;
  const query = normalizeText(searchInput.value).toLowerCase();

  for (const email of history) {
    const source = normalizeText(email.source || "unknown");
    if (selectedSource !== "all" && source !== selectedSource) continue;

    const subject = normalizeText(email.subject || "(Không có subject)");
    const sender = normalizeText(email.sender || email.sender_email || "");
    const issues = getIssues(email);
    const triggers = getTriggerItems(email);

    const haystack = [
      subject,
      sender,
      normalizeText(email.sender_email),
      normalizeText(email.label),
      normalizeText(email.verdict),
      issues.join(" "),
      triggers.join(" ")
    ].join(" ").toLowerCase();

    if (query && !haystack.includes(query)) continue;

    items.push({
      key: email.key || email.id,
      email
    });
  }

  items.sort((a, b) => {
    const ta = new Date(a.email?.updated_at || 0).getTime();
    const tb = new Date(b.email?.updated_at || 0).getTime();
    return tb - ta;
  });

  return items;
}

function renderSessionOptions(history) {
  const currentValue = sessionFilter.value || "all";
  const sourceCounts = new Map();

  for (const item of history) {
    const source = normalizeText(item.source || "unknown");
    sourceCounts.set(source, (sourceCounts.get(source) || 0) + 1);
  }

  state.sourceEntries = Array.from(sourceCounts.entries());

  if (state.sourceEntries.length <= 1) {
    const only = state.sourceEntries[0];
    const label = only
      ? `${only[0]} • ${only[1]} mail`
      : "Chưa có nguồn dữ liệu";

    sessionFilter.innerHTML = `<option value="all">${escapeHtml(label)}</option>`;
    sessionFilter.value = "all";
    sessionFilter.disabled = true;
    sessionFilter.style.display = "none";
    return;
  }

  const options = ['<option value="all">Tất cả nguồn dữ liệu</option>'];
  for (const [source, count] of state.sourceEntries) {
    options.push(`<option value="${escapeHtml(source)}">${escapeHtml(source)} • ${count} mail</option>`);
  }

  sessionFilter.innerHTML = options.join("");
  sessionFilter.disabled = false;
  sessionFilter.style.display = "";

  if ([...sessionFilter.options].some((opt) => opt.value === currentValue)) {
    sessionFilter.value = currentValue;
  } else {
    sessionFilter.value = "all";
  }
}

function renderSummary(history, items) {
  const totalEmails = history.length;
  const lastUpdatedAt = state.meta?.last_updated_at
    ? ` • Cập nhật: ${formatDate(state.meta.last_updated_at)}`
    : "";
  summaryText.textContent = `Tổng mail debug: ${totalEmails} • Đang hiển thị: ${items.length}${lastUpdatedAt}`;
}

function ensureSelection(items) {
  if (!items.length) {
    state.selectedKey = null;
    return;
  }
  if (!items.some((item) => item.key === state.selectedKey)) {
    state.selectedKey = items[0].key;
  }
}

function renderMailList(items) {
  if (!items.length) {
    mailList.innerHTML = '<div class="empty">Chưa có mail nào trong dashboard.</div>';
    return;
  }

  mailList.innerHTML = items.map((item) => {
    const email = item.email;
    const subject = email.subject || "(Không có subject)";
    const sender = email.sender || email.sender_email || "(Không có sender)";
    const score = getScore(email);
    const label = getLabel(email);
    const badgeClass = getBadgeClass(score, label);
    const triggers = getTriggerItems(email);
    const issues = getIssues(email);

    let badgeText = "Chưa có score";
    if (label && score !== null) badgeText = `${label} • ${score}`;
    else if (label) badgeText = String(label);
    else if (score !== null) badgeText = `Score • ${score}`;

    return `
      <div class="mail-item ${item.key === state.selectedKey ? "active" : ""}" data-key="${escapeHtml(item.key)}">
        <div class="mail-subject">${escapeHtml(subject)}</div>
        <div style="margin-bottom:8px;">
          <span class="badge ${badgeClass}">${escapeHtml(badgeText)}</span>
        </div>
        <div class="mail-meta">
          <div><strong>Sender:</strong> ${escapeHtml(sender)}</div>
          <div><strong>Updated:</strong> ${escapeHtml(formatDate(email.updated_at || ""))}</div>
          <div><strong>Source:</strong> ${escapeHtml(email.source || "unknown")}</div>
          <div><strong>Rules:</strong> ${triggers.length} • <strong>Issues:</strong> ${issues.length}</div>
        </div>
      </div>
    `;
  }).join("");

  mailList.querySelectorAll(".mail-item").forEach((node) => {
    node.addEventListener("click", () => {
      state.selectedKey = node.dataset.key;
      renderAll();
    });
  });
}

function renderDetail(items) {
  const current = items.find((item) => item.key === state.selectedKey);
  if (!current) {
    detailPane.innerHTML = '<div class="empty">Chọn một mail để xem chi tiết debug.</div>';
    return;
  }

  const email = current.email;
  const score = getScore(email);
  const label = getLabel(email);
  const badgeClass = getBadgeClass(score, label);
  const triggers = getTriggerItems(email);
  const issues = getIssues(email);
  const debugSections = getDebugSections(email);
  const urls = uniqueStrings(email.urls || []);
  const attachments = uniqueStrings(email.attachments || []);

  let badgeText = "Chưa có score";
  if (label && score !== null) badgeText = `${label} • ${score}`;
  else if (label) badgeText = String(label);
  else if (score !== null) badgeText = `Score • ${score}`;

  const metaCards = [
    { label: "Subject", value: email.subject || "(Không có subject)" },
    { label: "Sender", value: email.sender || email.sender_email || "(Không có sender)" },
    { label: "Sender email", value: email.sender_email || "" },
    { label: "Label", value: label || "" },
    { label: "Score", value: score ?? "" },
    { label: "Updated", value: formatDate(email.updated_at || "") },
    { label: "Source", value: email.source || "unknown" },
    { label: "Mail ID", value: email.mail_id || "" }
  ];

  detailPane.innerHTML = `
    <div class="detail-title">${escapeHtml(email.subject || "(Không có subject)")}</div>

    <div style="margin-bottom:14px;">
      <span class="badge ${badgeClass}">${escapeHtml(badgeText)}</span>
    </div>

    <div class="grid">
      ${metaCards.map((card) => `
        <div class="card">
          <div class="card-label">${escapeHtml(card.label)}</div>
          <div class="card-value">${escapeHtml(card.value)}</div>
        </div>
      `).join("")}
    </div>

    <div class="section">
      <h3>Issues</h3>
      ${issues.length
        ? `<div class="chips">${issues.map((item) => `<div class="chip">${escapeHtml(item)}</div>`).join("")}</div>`
        : '<div class="card"><div class="card-value">Không có issues đã lưu.</div></div>'}
    </div>

    <div class="section">
      <h3>Trigger / rule / indicator đã bắt được</h3>
      ${triggers.length
        ? `<div class="chips">${triggers.map((item) => `<div class="chip">${escapeHtml(item)}</div>`).join("")}</div>`
        : '<div class="card"><div class="card-value">Không có rule đã lưu.</div></div>'}
    </div>

    <div class="section">
      <h3>URLs</h3>
      ${urls.length ? `<pre>${escapeHtml(pretty(urls))}</pre>` : '<div class="card"><div class="card-value">Không có URL đã lưu.</div></div>'}
    </div>

    <div class="section">
      <h3>Attachments</h3>
      ${attachments.length ? `<pre>${escapeHtml(pretty(attachments))}</pre>` : '<div class="card"><div class="card-value">Không có attachment đã lưu.</div></div>'}
    </div>

    ${debugSections.map((section) => `
      <div class="section">
        <h3>${escapeHtml(section.title)}</h3>
        <pre>${escapeHtml(pretty(section.value))}</pre>
      </div>
    `).join("")}

    <div class="section">
      <h3>Raw email JSON</h3>
      <pre>${escapeHtml(pretty(email))}</pre>
    </div>
  `;
}

function renderAll() {
  state.items = buildItems(state.history);
  ensureSelection(state.items);
  renderSummary(state.history, state.items);
  renderMailList(state.items);
  renderDetail(state.items);
}

async function loadData() {
  const data = await chrome.storage.local.get({
    [DASHBOARD_HISTORY_KEY]: [],
    [DASHBOARD_META_KEY]: null
  });

  const dashboardHistory = Array.isArray(data[DASHBOARD_HISTORY_KEY])
    ? data[DASHBOARD_HISTORY_KEY]
    : [];

  state.history = dedupeHistory(dashboardHistory);
  state.meta = data[DASHBOARD_META_KEY] || null;

  renderSessionOptions(state.history);
  renderAll();
}

async function sendMessageSafe(message) {
  try {
    const response = await chrome.runtime.sendMessage(message);
    return response;
  } catch {
    return null;
  }
}

async function requestBackgroundRefresh() {
  const messages = [
    { type: "dashboard_force_refresh" },
    { action: "dashboard_force_refresh" },
    { type: "refresh_scan_data" },
    { action: "refresh_scan_data" },
    { type: "scan_imap_batch" },
    { action: "scan_imap_batch" },
    { type: "fetch_imap_emails" },
    { action: "fetch_imap_emails" }
  ];

  for (const message of messages) {
    const response = await sendMessageSafe(message);
    if (response && (response.ok !== undefined || response.started !== undefined || response.accepted !== undefined)) {
      return true;
    }
  }

  return false;
}

async function waitForStorageChange(previousMeta, previousCount, timeoutMs = 8000) {
  const startedAt = Date.now();
  const previousStamp = previousMeta?.last_updated_at || "";

  while (Date.now() - startedAt < timeoutMs) {
    const data = await chrome.storage.local.get({
      [DASHBOARD_HISTORY_KEY]: [],
      [DASHBOARD_META_KEY]: null
    });

    const history = Array.isArray(data[DASHBOARD_HISTORY_KEY]) ? data[DASHBOARD_HISTORY_KEY] : [];
    const meta = data[DASHBOARD_META_KEY] || null;
    const currentStamp = meta?.last_updated_at || "";

    if (history.length !== previousCount || currentStamp !== previousStamp) {
      return true;
    }

    await new Promise((resolve) => setTimeout(resolve, 700));
  }

  return false;
}

searchInput.addEventListener("input", () => renderAll());
sessionFilter.addEventListener("change", () => renderAll());

btnRefresh.addEventListener("click", async () => {
  const oldText = btnRefresh.textContent;
  const previousMeta = state.meta;
  const previousCount = state.history.length;

  btnRefresh.disabled = true;
  btnRefresh.textContent = "Đang làm mới...";

  try {
    const requested = await requestBackgroundRefresh();
    if (requested) {
      await waitForStorageChange(previousMeta, previousCount, 8000);
    }
    await loadData();
  } finally {
    btnRefresh.disabled = false;
    btnRefresh.textContent = oldText;
  }
});

btnClearHistory.addEventListener("click", async () => {
  const ok = confirm("Bạn có chắc muốn xóa toàn bộ lịch sử scan đã lưu không?");
  if (!ok) return;

  await chrome.storage.local.set({
    [DASHBOARD_HISTORY_KEY]: [],
    [DASHBOARD_META_KEY]: null,
    scan_history: [],
    last_scan_result: null
  });

  state.selectedKey = null;
  await loadData();
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local") return;
  if (changes[DASHBOARD_HISTORY_KEY] || changes[DASHBOARD_META_KEY]) {
    loadData();
  }
});

(async function init() {
  await loadData();
})();
