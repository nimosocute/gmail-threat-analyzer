const backendUrlEl = document.getElementById("backendUrl");
const apiPathEl = document.getElementById("apiPath");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");

const emailEl = document.getElementById("email");
const appPasswordEl = document.getElementById("appPassword");
const mailboxLabelEl = document.getElementById("mailboxLabel");
const limitEl = document.getElementById("limit");
const rememberLoginEl = document.getElementById("rememberLogin");

const btnHealth = document.getElementById("btnHealth");
const btnSaved = document.getElementById("btnSaved");
const btnFetch = document.getElementById("btnFetch");
const btnClear = document.getElementById("btnClear");
const btnDashboard = document.getElementById("btnDashboard");
const openOptions = document.getElementById("openOptions");

const DASHBOARD_HISTORY_KEY = "bl_dashboard_history";
const DASHBOARD_META_KEY = "bl_dashboard_meta";
const CURRENT_BATCH_KEY = "bl_current_batch_items";
const CURRENT_BATCH_META_KEY = "bl_current_batch_meta";
const CURRENT_BATCH_BINDINGS_KEY = "bl_current_batch_bindings";
const CURRENT_BATCH_BINDINGS_META_KEY = "bl_current_batch_bindings_meta";

const DEBUG_BIND = true;

function dlog(...args) {
  if (!DEBUG_BIND) return;
  console.log(...args);
}

function dwarn(...args) {
  if (!DEBUG_BIND) return;
  console.warn(...args);
}

function dtable(label, rows) {
  if (!DEBUG_BIND) return;
  try {
    console.groupCollapsed(label);
    console.table(Array.isArray(rows) ? rows : [rows]);
    console.groupEnd();
  } catch (err) {
    console.log(label, rows);
  }
}

function dslice(arr, n = 10) {
  return Array.isArray(arr) ? arr.slice(0, n) : [];
}

function normalizeText(value) {
  return String(value || "").toLowerCase().replace(/\s+/g, " ").trim();
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

function extractEmailFromSender(sender) {
  const raw = String(sender || "");
  const angle = raw.match(/<([^>]+)>/);
  if (angle && angle[1]) return angle[1].trim();

  const plain = raw.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  return plain ? plain[0].trim() : "";
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

function makeBindingKey({ gmailMsgId, gmailThreadId }) {
  const msgId = normalizeGmailId(gmailMsgId);
  if (msgId) return `gmailmsg::${msgId}`;

  const thrId = normalizeGmailId(gmailThreadId);
  if (thrId) return `gmailthrid::${thrId}`;

  return "";
}

function makeDashboardKey({ mailId, subject, senderEmail, date }) {
  const cleanId = String(mailId || "").trim();
  if (cleanId) return `mailid::${cleanId}`;

  return [
    "mail",
    normalizeText(subject),
    normalizeText(senderEmail),
    normalizeText(date)
  ].join("||");
}

function makeLooseMatchKey(item) {
  return [
    normalizeText(item?.subject),
    normalizeText(item?.sender_email || extractEmailFromSender(item?.sender)),
    normalizeText(item?.updated_at)
  ].join("||");
}

function mergeDashboardHistory(existing, incoming) {
  const base = Array.isArray(existing) ? [...existing] : [];
  const add = Array.isArray(incoming) ? incoming : [];
  const hasAnalyzedIncoming = add.some((item) => item?.source === "scan-imap-batch");

  let filteredBase = base;

  if (hasAnalyzedIncoming) {
    const incomingMailIds = new Set(
      add
        .map((item) => String(item?.mail_id || "").trim())
        .filter(Boolean)
    );

    const incomingLooseKeys = new Set(add.map(makeLooseMatchKey));

    filteredBase = base.filter((item) => {
      const currentMailId = String(item?.mail_id || "").trim();
      const looseKey = makeLooseMatchKey(item);
      const isOldFetchOnly = item?.source === "fetch-imap-emails";

      if (!isOldFetchOnly) return true;
      if (currentMailId && incomingMailIds.has(currentMailId)) return false;
      if (incomingLooseKeys.has(looseKey)) return false;
      return true;
    });
  }

  const map = new Map();

  for (const item of filteredBase) {
    const key = item?.key || item?.id;
    if (!key) continue;
    map.set(key, item);
  }

  for (const item of add) {
    const key = item?.key || item?.id;
    if (!key) continue;
    map.set(key, item);
  }

  return Array.from(map.values()).sort((a, b) => {
    const ta = new Date(a?.updated_at || 0).getTime();
    const tb = new Date(b?.updated_at || 0).getTime();
    return tb - ta;
  });
}

function buildDashboardEntries(data) {
  const rows = Array.isArray(data?.rows) ? data.rows : [];
  const emails = Array.isArray(data?.emails) ? data.emails : [];

  const emailById = new Map();
  for (const email of emails) {
    const id = String(email?.id || "").trim();
    if (id) emailById.set(id, email);
  }

  if (rows.length) {
    return rows.map((row) => {
      const mailId = row?.ID ?? row?.Id ?? row?.id ?? "";
      const rawEmail = emailById.get(String(mailId).trim()) || null;

      const subject =
        row?.["Tiêu đề"] ??
        row?.Subject ??
        row?.subject ??
        rawEmail?.subject ??
        "(Không có subject)";

      const sender =
        row?.["Người gửi"] ??
        row?.Sender ??
        row?.sender ??
        rawEmail?.sender ??
        rawEmail?.sender_email ??
        "(Không có sender)";

      const senderEmail = rawEmail?.sender_email || extractEmailFromSender(sender);

      const label =
        row?.["Trạng thái"] ??
        row?.Label ??
        row?.label ??
        row?.verdict ??
        "Không rõ";

      const score = row?.["Điểm"] ?? row?.Score ?? row?.score ?? 0;

      const updatedAt =
        row?.["Thời gian"] ??
        row?.updated_at ??
        rawEmail?.date ??
        new Date().toISOString();

      const issues = splitIssueString(row?.["Chi tiết vi phạm"] || row?.issues || "");
      const triggeredRules = splitRuleString(row?.["Rules kích hoạt"] || row?.triggered_rules || "");

      const key = makeDashboardKey({ mailId, subject, senderEmail, date: updatedAt });

      return {
        id: key,
        key,
        mail_id: String(mailId || ""),
        subject,
        sender,
        sender_email: senderEmail || "",
        label,
        verdict: label,
        score: toSafeNumber(score),
        triggered_rules: triggeredRules,
        issues,
        urls: Array.isArray(rawEmail?.urls) ? rawEmail.urls : [],
        attachments: Array.isArray(rawEmail?.attachments) ? rawEmail.attachments : [],
        source: "scan-imap-batch",
        updated_at: updatedAt,
        raw_summary: row,
        raw_email: rawEmail,
        auth: rawEmail?.auth || null,
        url_debug: rawEmail?.url_debug || null
      };
    });
  }

  return emails.map((email) => {
    const senderEmail = email?.sender_email || extractEmailFromSender(email?.sender);
    const updatedAt = email?.date || new Date().toISOString();
    const key = makeDashboardKey({
      mailId: email?.id || "",
      subject: email?.subject || "(Không có subject)",
      senderEmail,
      date: updatedAt
    });

    return {
      id: key,
      key,
      mail_id: String(email?.id || ""),
      subject: email?.subject || "(Không có subject)",
      sender: email?.sender || senderEmail || "(Không có sender)",
      sender_email: senderEmail || "",
      label: "Chưa phân tích",
      verdict: "Chưa phân tích",
      score: 0,
      triggered_rules: [],
      issues: [],
      urls: Array.isArray(email?.urls) ? email.urls : [],
      attachments: Array.isArray(email?.attachments) ? email.attachments : [],
      source: "fetch-imap-emails",
      updated_at: updatedAt,
      raw_email: email,
      auth: email?.auth || null,
      url_debug: email?.url_debug || null
    };
  });
}

function buildCurrentBatchItems(data) {
  const rows = Array.isArray(data?.rows) ? data.rows : [];
  const emails = Array.isArray(data?.emails) ? data.emails : [];
  const emailById = new Map();
  const scanSessionId = makeId();

  for (const email of emails) {
    const id = String(email?.id || "").trim();
    if (id) emailById.set(id, email);
  }

  return rows.map((row, index) => {
    const mailId = row?.ID ?? row?.Id ?? row?.id ?? "";
    const rawEmail = emailById.get(String(mailId).trim()) || null;

    const subject =
      row?.["Tiêu đề"] ??
      row?.Subject ??
      row?.subject ??
      rawEmail?.subject ??
      "(Không có subject)";

    const sender =
      row?.["Người gửi"] ??
      row?.Sender ??
      row?.sender ??
      rawEmail?.sender ??
      rawEmail?.sender_email ??
      "(Không có sender)";

    const senderEmail = rawEmail?.sender_email || extractEmailFromSender(sender);
    const label = row?.["Trạng thái"] ?? row?.Label ?? row?.label ?? row?.verdict ?? "Không rõ";
    const score = row?.["Điểm"] ?? row?.Score ?? row?.score ?? 0;
    const updatedAt =
      row?.["Thời gian"] ??
      row?.updated_at ??
      rawEmail?.date ??
      new Date().toISOString();

    const issues = splitIssueString(row?.["Chi tiết vi phạm"] || row?.issues || "");
    const triggeredRules = splitRuleString(row?.["Rules kích hoạt"] || row?.triggered_rules || "");

    return {
      id: `scanitem::${scanSessionId}::${index}`,
      key: `scanitem::${scanSessionId}::${index}`,
      scan_session_id: scanSessionId,
      scan_order: index,
      mail_id: String(mailId || ""),

      subject,
      sender,
      sender_email: senderEmail || "",

      // QUAN TRỌNG: lưu exact Gmail id nếu backend có
      gmail_msgid: String(
        row?.gmail_msgid ||
        rawEmail?.gmail_msgid ||
        rawEmail?.gmail_message_id ||
        rawEmail?.message_id ||
        rawEmail?.msg_id ||
        ""
      ).trim(),

      gmail_thrid: String(
        row?.gmail_thrid ||
        rawEmail?.gmail_thrid ||
        rawEmail?.gmail_thread_id ||
        rawEmail?.thread_id ||
        rawEmail?.thr_id ||
        ""
      ).trim(),

      label,
      verdict: label,
      score: toSafeNumber(score),
      triggered_rules: triggeredRules,
      issues,
      urls: Array.isArray(rawEmail?.urls) ? rawEmail.urls : [],
      attachments: Array.isArray(rawEmail?.attachments) ? rawEmail.attachments : [],
      source: "scan-imap-batch",
      updated_at: updatedAt,
      raw_summary: row,
      raw_email: rawEmail,
      auth: rawEmail?.auth || null,
      url_debug: rawEmail?.url_debug || null
    };
  });
}

async function getActiveGmailTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = Array.isArray(tabs) ? tabs[0] : null;
  if (!tab?.id) return null;
  if (!String(tab.url || "").startsWith("https://mail.google.com/")) return null;
  return tab;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function captureInboxRowsFromActiveGmailTab() {
  const delays = [0, 350, 800];

  for (let attempt = 0; attempt < delays.length; attempt++) {
    try {
      if (delays[attempt] > 0) {
        await sleep(delays[attempt]);
      }

      const tab = await getActiveGmailTab();
      if (!tab?.id) {
        console.warn("[popup][capture] no active Gmail tab");
        return [];
      }

      const response = await chrome.tabs.sendMessage(tab.id, { type: "BL_CAPTURE_INBOX_ROWS" });
      const rows = Array.isArray(response?.rows) ? response.rows : [];

      console.log(`[popup][capture] attempt ${attempt + 1}`, {
        total: rows.length,
        withExactIds: rows.filter((r) => r?.gmail_msgid || r?.gmail_thrid).length,
        sample: rows.slice(0, 5)
      });

      if (rows.length) return rows;
    } catch (err) {
      console.warn(`[popup][capture] attempt ${attempt + 1} failed`, err);
    }
  }

  return [];
}

function buildExactScanTargets(capturedRows, maxTargets = Infinity) {
  const rows = Array.isArray(capturedRows) ? capturedRows : [];
  const hardLimit = Number.isFinite(Number(maxTargets)) ? Math.max(1, Number(maxTargets)) : Infinity;
  const seen = new Set();
  const targets = [];

  for (const row of rows) {
    if (!row) continue;
    if (targets.length >= hardLimit) break;

    const gmailMsgId = normalizeGmailId(row.gmail_msgid);
    const gmailThreadId = normalizeGmailId(row.gmail_thrid);

    if (!gmailMsgId && !gmailThreadId) continue;

    const dedupeKey = `${gmailMsgId || ""}::${gmailThreadId || ""}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    targets.push({
      row_index: Number.isFinite(Number(row.row_index)) ? Number(row.row_index) : null,
      subject: String(row.subject || "").trim(),
      sender: String(row.sender || "").trim(),
      gmail_msgid: gmailMsgId || "",
      gmail_thrid: gmailThreadId || ""
    });
  }

  dtable("[exact] targets", targets);
  return targets;
}

function buildExactBindings(entries, capturedRows) {
  const bindings = [];
  const rows = Array.isArray(capturedRows) ? capturedRows : [];
  const items = Array.isArray(entries) ? entries : [];

  const itemByMsgId = new Map();
  const itemByThreadId = new Map();
  const usedItemKeys = new Set();

  for (const item of items) {
    if (!item) continue;

    const msgId = normalizeGmailId(item.gmail_msgid);
    const thrId = normalizeGmailId(item.gmail_thrid);

    if (msgId && !itemByMsgId.has(msgId)) itemByMsgId.set(msgId, item);
    if (thrId && !itemByThreadId.has(thrId)) itemByThreadId.set(thrId, item);
  }

  dlog("[exact] map sizes =", {
    msgIds: itemByMsgId.size,
    thrIds: itemByThreadId.size
  });

  for (const row of rows) {
    if (!row) continue;

    const msgId = normalizeGmailId(row.gmail_msgid);
    const thrId = normalizeGmailId(row.gmail_thrid);
    const bindingKey = makeBindingKey({
      gmailMsgId: msgId,
      gmailThreadId: thrId
    });

    if (!bindingKey) continue;

    let item = null;
    let matchedBy = "";

    if (msgId && itemByMsgId.has(msgId)) {
      item = itemByMsgId.get(msgId) || null;
      matchedBy = "exact-msgid";
    }

    if (!item && thrId && itemByThreadId.has(thrId)) {
      item = itemByThreadId.get(thrId) || null;
      matchedBy = "exact-thrid";
    }

    const itemKey = String(item?.key || item?.id || item?.mail_id || "").trim();
    if (!item || !itemKey || usedItemKeys.has(itemKey)) continue;

    usedItemKeys.add(itemKey);

    bindings.push({
      id: bindingKey,
      key: bindingKey,
      item_key: itemKey,
      gmail_msgid: msgId || "",
      gmail_thrid: thrId || "",
      row_index: Number.isFinite(Number(row.row_index)) ? Number(row.row_index) : null,
      row_subject: String(row.subject || "").trim(),
      row_sender: String(row.sender || "").trim(),
      label: item.label || item.verdict || "Không rõ",
      score: toSafeNumber(item.score),
      matched_by: matchedBy,
      updated_at: new Date().toISOString()
    });
  }

  dtable("[exact] final bindings", bindings);
  return bindings;
}

function isHttpNotFoundError(err) {
  const message = String(err?.message || err || "");
  return /HTTP\s+(404|405)\b/i.test(message);
}

async function tryExactUiTargetScan(settings, payload, capturedRows) {
  const targetLimit = Number.isFinite(Number(payload?.limit)) ? Math.max(1, Number(payload.limit)) : 10;
  const targets = buildExactScanTargets(capturedRows, targetLimit);
  if (!targets.length) {
    return {
      used: false,
      reason: "no-exact-targets",
      data: null
    };
  }

  const exactUrl = normalizeUrl(settings.backendBaseUrl, "/api/scan-imap-targets");
  const exactPayload = {
    ...payload,
    limit: targetLimit,
    targets,
    strict_exact: true
  };

  try {
    const data = await fetchJson(exactUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify(exactPayload)
    });

    const rowsCount = Array.isArray(data?.rows) ? data.rows.length : 0;
    const emailsCount = Array.isArray(data?.emails) ? data.emails.length : 0;
    const count = Number(data?.count || Math.max(rowsCount, emailsCount));
    const exactFailed = data?.ok === false || count <= 0 || (rowsCount <= 0 && emailsCount <= 0);

    if (exactFailed) {
      console.warn("[exact] exact endpoint returned no items, fallback to batch", {
        message: data?.message,
        count,
        exact_meta: data?.exact_meta || null
      });
      return {
        used: false,
        reason: "exact-empty-or-error",
        data: null,
        exact_error: data || null
      };
    }

    return {
      used: true,
      endpoint: "/api/scan-imap-targets",
      request_payload: exactPayload,
      data
    };
  } catch (err) {
    if (isHttpNotFoundError(err)) {
      console.warn("[exact] endpoint not available, fallback to batch", err);
      return {
        used: false,
        reason: "endpoint-not-available",
        data: null
      };
    }
    throw err;
  }
}

function buildCurrentBatchBindings(entries, capturedRows) {
  const bindings = [];
  const rows = Array.isArray(capturedRows) ? capturedRows : [];
  const items = Array.isArray(entries) ? entries : [];

  const norm = (text) => {
    if (!text) return "";
    return String(text)
      .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
      .replace(/đ/g, "d").replace(/Đ/g, "D")
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  };

  const escapeRegExp = (text) => String(text || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  const extractDisplayName = (senderText, rawEmail) => {
    let s = String(senderText || "");
    if (rawEmail) {
      s = s.replace(new RegExp(escapeRegExp(rawEmail), "ig"), " ");
    }
    return norm(s.replace(/[<>"]/g, " "));
  };

  const toTimestamp = (value) => {
    if (!value) return 0;
    const t = Date.parse(value);
    return Number.isFinite(t) ? t : 0;
  };

  const sameOrContains = (a, b) => {
    if (!a || !b) return false;
    return a === b || a.includes(b) || b.includes(a);
  };

  const preparedItems = items
    .filter(Boolean)
    .map((item, idx) => {
      const rawEmail =
        item.sender_email ||
        extractEmailFromSender(item.sender) ||
        "";

      return {
        raw: item,
        idx,
        scanOrder: Number.isFinite(Number(item.scan_order)) ? Number(item.scan_order) : idx,
        nSub: norm(item.subject),
        nEmail: rawEmail ? norm(String(rawEmail).split("@")[0]) : "",
        nName: extractDisplayName(item.sender || "", rawEmail),
        nMsgId: normalizeGmailId(
          item.gmail_msgid ||
          item.gmail_message_id ||
          item.message_id ||
          item.msg_id ||
          ""
        ),
        nThrId: normalizeGmailId(
          item.gmail_thrid ||
          item.gmail_thread_id ||
          item.thread_id ||
          item.thr_id ||
          ""
        ),
        ts: toTimestamp(item.updated_at || item.date || item.created_at),
        used: false
      };
    });

  dtable(
    "[bind] preparedItems",
    preparedItems.map((item) => ({
      idx: item.idx,
      scanOrder: item.scanOrder,
      nSub: item.nSub,
      nEmail: item.nEmail,
      nName: item.nName,
      nMsgId: item.nMsgId,
      nThrId: item.nThrId,
      used: item.used,
      raw_mail_id: item.raw?.mail_id,
      raw_subject: item.raw?.subject,
      raw_sender: item.raw?.sender
    }))
  );

  const itemByExactMsgId = new Map();
  const itemByExactThrId = new Map();

  for (const item of preparedItems) {
    if (item.nMsgId && !itemByExactMsgId.has(item.nMsgId)) {
      itemByExactMsgId.set(item.nMsgId, item);
    }
    if (item.nThrId && !itemByExactThrId.has(item.nThrId)) {
      itemByExactThrId.set(item.nThrId, item);
    }
  }

  dlog("[bind] exact map sizes =", {
    msgIds: itemByExactMsgId.size,
    thrIds: itemByExactThrId.size
  });

  for (const row of rows) {
    if (!row) continue;

    const rSub = norm(row.subject);
    const rSender = norm(row.sender);
    const gMsgId = normalizeGmailId(row.gmail_msgid);
    const gThrId = normalizeGmailId(row.gmail_thrid);

    const rowEmail = extractEmailFromSender(row.sender || "") || "";
    const rEmail = rowEmail ? norm(String(rowEmail).split("@")[0]) : "";
    const rName = extractDisplayName(row.sender || "", rowEmail);
    const rTs = toTimestamp(row.updated_at || row.date || row.timestamp);

    console.groupCollapsed(
      `[bind][row ${row.row_index}] ${String(row.subject || "").slice(0, 80)}`
    );

    dlog("[bind][row] raw =", row);
    dlog("[bind][row] normalized =", {
      row_index: row.row_index,
      rSub,
      rSender,
      rEmail,
      rName,
      gMsgId,
      gThrId,
      rTs
    });

    let chosen = null;
    let chosenReason = "";

    // 1) Exact Gmail ID
    if (gMsgId && itemByExactMsgId.has(gMsgId)) {
      const item = itemByExactMsgId.get(gMsgId);
      dlog("[bind][row] exact msg candidate =", {
        gMsgId,
        item_idx: item?.idx,
        item_subject: item?.raw?.subject,
        item_sender: item?.raw?.sender,
        used: item?.used
      });
      if (item && !item.used) {
        chosen = item;
        chosenReason = "exact-msgid";
      }
    } else {
      dlog("[bind][row] no exact msg match", { gMsgId });
    }

    if (!chosen && gThrId && itemByExactThrId.has(gThrId)) {
      const item = itemByExactThrId.get(gThrId);
      dlog("[bind][row] exact thread candidate =", {
        gThrId,
        item_idx: item?.idx,
        item_subject: item?.raw?.subject,
        item_sender: item?.raw?.sender,
        used: item?.used
      });
      if (item && !item.used) {
        chosen = item;
        chosenReason = "exact-thrid";
      }
    } else if (!chosen) {
      dlog("[bind][row] no exact thread match", { gThrId });
    }

    // 2) row_index <-> scan_order
    if (!chosen && Number.isFinite(Number(row.row_index))) {
      const rowIndex = Number(row.row_index);

      const indexCandidates = preparedItems
        .filter((item) => !item.used && item.scanOrder === rowIndex)
        .map((item) => ({
          idx: item.idx,
          scanOrder: item.scanOrder,
          subject_ok: !!(rSub && item.nSub && sameOrContains(rSub, item.nSub)),
          email_ok: !!(rEmail && item.nEmail && sameOrContains(rEmail, item.nEmail)),
          name_ok: !!(rName && item.nName && sameOrContains(rName, item.nName)),
          raw_subject: item.raw?.subject,
          raw_sender: item.raw?.sender
        }));

      dtable(`[bind][row ${row.row_index}] indexCandidates`, indexCandidates);

      const indexCandidate = preparedItems.find((item) => {
        if (item.used) return false;
        if (item.scanOrder !== rowIndex) return false;

        const subjectOk = !!(rSub && item.nSub && sameOrContains(rSub, item.nSub));
        const emailOk = !!(rEmail && item.nEmail && sameOrContains(rEmail, item.nEmail));
        const nameExactOk = !!(rName && item.nName && rName === item.nName);

  // scan_order chỉ được dùng khi subject khớp
        if (!subjectOk) return false;

  // sender là điều kiện phụ, không bắt buộc tuyệt đối
        if (emailOk || nameExactOk || !rSender) return true;

  // Nếu subject đã khớp mạnh thì vẫn cho qua
        return true;
      });

      if (indexCandidate) {
        chosen = indexCandidate;
        chosenReason = "scan_order";
      } else {
        dlog("[bind][row] no scan_order candidate");
      }
    }

    // 3) near index +/-1
    if (!chosen && Number.isFinite(Number(row.row_index))) {
      const rowIndex = Number(row.row_index);
      const nearCandidates = preparedItems
        .filter((item) => !item.used && Math.abs(item.scanOrder - rowIndex) <= 1)
        .map((item) => {
          let score = 0;

          if (rSub && item.nSub) {
            if (rSub === item.nSub) score += 1000;
            else if (sameOrContains(rSub, item.nSub)) score += 700;
          }

          if (rEmail && item.nEmail) {
            if (rEmail === item.nEmail) score += 500;
            else if (sameOrContains(rEmail, item.nEmail)) score += 250;
          }

          if (rName && item.nName) {
            if (rName === item.nName) score += 450;
            else if (sameOrContains(rName, item.nName)) score += 200;
          }

          if (rTs && item.ts) {
            const diff = Math.abs(rTs - item.ts);
            if (diff <= 60 * 1000) score += 80;
            else if (diff <= 5 * 60 * 1000) score += 40;
          }

          return {
            item,
            score,
            item_idx: item.idx,
            scanOrder: item.scanOrder,
            raw_subject: item.raw?.subject,
            raw_sender: item.raw?.sender
          };
        })
        .filter((x) => x.score >= 900)
        .sort((a, b) => b.score - a.score);

      dtable(
        `[bind][row ${row.row_index}] nearCandidates`,
        nearCandidates.map((x) => ({
          item_idx: x.item_idx,
          scanOrder: x.scanOrder,
          score: x.score,
          raw_subject: x.raw_subject,
          raw_sender: x.raw_sender
        }))
      );

      if (nearCandidates.length === 1) {
        chosen = nearCandidates[0].item;
        chosenReason = "near-scan-order";
      } else if (nearCandidates.length > 1) {
        dlog("[bind][row] nearCandidates ambiguous, skip", {
          count: nearCandidates.length
        });
      }
    }

    // 4) fuzzy
    if (!chosen) {
      const fuzzyCandidates = preparedItems
        .filter((item) => !item.used)
        .map((item) => {
          let score = 0;
          let senderMatched = false;
          const reasons = [];

          if (rSub && item.nSub) {
            if (rSub === item.nSub) {
              score += 1000;
              reasons.push("subject-exact");
            } else if (sameOrContains(rSub, item.nSub)) {
              score += 700;
              reasons.push("subject-contains");
            } else {
              return null;
            }
          } else {
            return null;
          }

          if (rEmail && item.nEmail) {
            if (rEmail === item.nEmail) {
              score += 500;
              senderMatched = true;
              reasons.push("email-exact");
            } else if (sameOrContains(rEmail, item.nEmail)) {
              score += 250;
              senderMatched = true;
              reasons.push("email-contains");
            }
          }

          if (rName && item.nName) {
           if (rName === item.nName) {
            score += 450;
            senderMatched = true;
            reasons.push("name-exact");
            }
          }

          if (!senderMatched) {
            reasons.push("reject-no-sender-match");
            return null;
          }

          if (rTs && item.ts) {
            const diff = Math.abs(rTs - item.ts);
            if (diff <= 60 * 1000) {
              score += 80;
              reasons.push("time-<=60s");
            } else if (diff <= 5 * 60 * 1000) {
              score += 40;
              reasons.push("time-<=5m");
            }
          }

          return {
            item,
            score,
            reasons,
            item_idx: item.idx,
            scanOrder: item.scanOrder,
            raw_subject: item.raw?.subject,
            raw_sender: item.raw?.sender,
            nSub: item.nSub,
            nEmail: item.nEmail,
            nName: item.nName
          };
        })
        .filter(Boolean)
        .sort((a, b) => b.score - a.score);

      dtable(
        `[bind][row ${row.row_index}] fuzzyCandidates`,
        fuzzyCandidates.slice(0, 10).map((x) => ({
          item_idx: x.item_idx,
          scanOrder: x.scanOrder,
          score: x.score,
          reasons: x.reasons.join(", "),
          raw_subject: x.raw_subject,
          raw_sender: x.raw_sender,
          nSub: x.nSub,
          nEmail: x.nEmail,
          nName: x.nName
        }))
      );

      const top = fuzzyCandidates[0];
      const second = fuzzyCandidates[1];

      if (top && top.score >= 1400) {
        if (!second || Math.abs(top.score - second.score) >= 120) {
          chosen = top.item;
          chosenReason = "fuzzy";
        } else {
          dlog("[bind][row] fuzzy ambiguous top-second too close", {
            top: top.score,
            second: second.score
          });
        }
      } else {
        dlog("[bind][row] no fuzzy candidate strong enough", {
          top: top?.score || 0
        });
      }
    }

    const bindingKey = makeBindingKey({
      gmailMsgId: row.gmail_msgid,
      gmailThreadId: row.gmail_thrid
    });

    dlog("[bind][row] bindingKey =", bindingKey);

    if (!chosen) {
      dwarn("[bind][row] SKIP: no chosen item");
      console.groupEnd();
      continue;
    }

    if (!bindingKey) {
      dwarn("[bind][row] SKIP: no bindingKey");
      console.groupEnd();
      continue;
    }

    dlog("[bind][row] CHOSEN =", {
      reason: chosenReason,
      item_idx: chosen.idx,
      scanOrder: chosen.scanOrder,
      raw_subject: chosen.raw?.subject,
      raw_sender: chosen.raw?.sender,
      raw_mail_id: chosen.raw?.mail_id,
      nMsgId: chosen.nMsgId,
      nThrId: chosen.nThrId
    });

    bindings.push({
      id: bindingKey,
      key: bindingKey,
      item_key: chosen.raw.key || chosen.raw.id || chosen.raw.mail_id || "",
      gmail_msgid: row.gmail_msgid || "",
      gmail_thrid: row.gmail_thrid || "",
      row_index: row.row_index,
      row_subject: String(row.subject || "").trim(),
      row_sender: String(row.sender || "").trim(),
      label: chosen.raw.label || chosen.raw.verdict || "Không rõ",
      score: toSafeNumber(chosen.raw.score),
      updated_at: new Date().toISOString()
    });

    chosen.used = true;
    dlog("[bind][row] marked used item_idx =", chosen.idx);
    console.groupEnd();
  }

  dtable(
    "[bind] final bindings",
    bindings.map((b, i) => ({
      i,
      key: b.key,
      item_key: b.item_key,
      row_index: b.row_index,
      row_subject: b.row_subject,
      row_sender: b.row_sender,
      gmail_msgid: b.gmail_msgid,
      gmail_thrid: b.gmail_thrid,
      label: b.label,
      score: b.score
    }))
  );

  dlog("[bind] final totals =", {
    rows: rows.length,
    items: items.length,
    bindings: bindings.length
  });

  return bindings;
}

function setLoading(isLoading) {
  btnHealth.disabled = isLoading;
  btnSaved.disabled = isLoading;
  btnFetch.disabled = isLoading;
  btnClear.disabled = isLoading;
}

function setStatus(text, ok = null) {
  statusEl.textContent = text;
  statusEl.className = ok === true ? "value ok" : ok === false ? "value bad" : "value";
}

function pretty(data) {
  try {
    return JSON.stringify(data, null, 2);
  } catch {
    return String(data);
  }
}

function normalizeUrl(base, path) {
  const cleanBase = (base || "").replace(/\/+$/, "");
  const cleanPath = (path || "").startsWith("/") ? path : `/${path || ""}`;
  return `${cleanBase}${cleanPath}`;
}

function makeId() {
  try {
    if (globalThis.crypto && typeof globalThis.crypto.randomUUID === "function") {
      return globalThis.crypto.randomUUID();
    }
  } catch {}
  return `scan_${Date.now()}_${Math.random().toString(16).slice(2)}`;
}

async function migrateStoredApiPath() {
  const current = await chrome.storage.sync.get({ apiPath: "/api/scan-imap-batch" });

  if (!current.apiPath || current.apiPath === "/" || current.apiPath === "/api/fetch-imap-emails") {
    await chrome.storage.sync.set({ apiPath: "/api/scan-imap-batch" });
    return "/api/scan-imap-batch";
  }

  return current.apiPath;
}

async function getSettings() {
  const apiPath = await migrateStoredApiPath();
  return chrome.storage.sync.get({
    backendBaseUrl: "http://127.0.0.1:8000",
    apiPath,
    healthPath: "/health"
  });
}

async function refreshUi() {
  const settings = await getSettings();
  backendUrlEl.textContent = settings.backendBaseUrl;
  apiPathEl.textContent = `${settings.apiPath} (+ /api/scan-imap-targets)`;
}

async function fetchJson(url, options = {}) {
  const res = await fetch(url, options);
  const text = await res.text();

  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }

  if (!res.ok) {
    throw new Error(`HTTP ${res.status}: ${pretty(data)}`);
  }

  return data;
}

async function saveFormLocal() {
  await chrome.storage.local.set({
    popup_email: emailEl.value.trim(),
    popup_mailboxLabel: mailboxLabelEl.value.trim(),
    popup_limit: limitEl.value,
    popup_rememberLogin: rememberLoginEl.value
  });
}

async function loadFormLocal() {
  const data = await chrome.storage.local.get({
    popup_email: "",
    popup_mailboxLabel: "Hộp thư đến (INBOX)",
    popup_limit: "10",
    popup_rememberLogin: "false"
  });

  emailEl.value = data.popup_email;
  mailboxLabelEl.value = data.popup_mailboxLabel;
  limitEl.value = data.popup_limit;
  rememberLoginEl.value = data.popup_rememberLogin;
}

async function loadSavedLoginIntoForm(showStatus = false) {
  try {
    const settings = await getSettings();
    const url = normalizeUrl(settings.backendBaseUrl, "/api/saved-login");
    const data = await fetchJson(url, {
      method: "GET",
      headers: { "Accept": "application/json" }
    });

    if (data && data.email) {
      emailEl.value = data.email || "";
      appPasswordEl.value = data.password || "";
      mailboxLabelEl.value = data.mailbox_label || "Hộp thư đến (INBOX)";
      limitEl.value = String(data.mail_limit || 10);
      rememberLoginEl.value = "true";

      if (showStatus) {
        setStatus("Đã nạp đăng nhập đã lưu", true);
        resultEl.textContent = pretty(data);
      }
      return data;
    }

    if (showStatus) {
      setStatus("Chưa có đăng nhập đã lưu", false);
      resultEl.textContent = pretty(data);
    }
    return null;
  } catch (err) {
    if (showStatus) {
      setStatus("Không lấy được đăng nhập đã lưu", false);
      resultEl.textContent = err.message || String(err);
    }
    return null;
  }
}

function buildSafeRequestPayload(payload) {
  return {
    email: payload.email,
    mailbox_label: payload.mailbox_label,
    limit: payload.limit,
    remember_login: payload.remember_login
  };
}

async function persistScanResult(data, payload, settings, capturedRowsBeforeScan = []) {
  const existing = await chrome.storage.local.get({
    scan_history: [],
    last_scan_result: null,
    [DASHBOARD_HISTORY_KEY]: [],
    [DASHBOARD_META_KEY]: null,
    [CURRENT_BATCH_KEY]: [],
    [CURRENT_BATCH_META_KEY]: null,
    [CURRENT_BATCH_BINDINGS_KEY]: [],
    [CURRENT_BATCH_BINDINGS_META_KEY]: null
  });

  const history = Array.isArray(existing.scan_history) ? existing.scan_history : [];
  const dashboardHistory = Array.isArray(existing[DASHBOARD_HISTORY_KEY])
    ? existing[DASHBOARD_HISTORY_KEY]
    : [];

  const record = {
    id: makeId(),
    created_at: new Date().toISOString(),
    backend_base_url: settings.backendBaseUrl,
    api_path: settings.apiPath,
    request: buildSafeRequestPayload(payload),
    summary: {
      ok: data?.ok ?? null,
      message: data?.message ?? "",
      count: data?.count ?? (Array.isArray(data?.emails) ? data.emails.length : 0)
    },
    emails: Array.isArray(data?.emails) ? data.emails : [],
    raw: data
  };

  history.unshift(record);

  const incomingDashboardEntries = buildDashboardEntries(data);
  const mergedDashboard = mergeDashboardHistory(dashboardHistory, incomingDashboardEntries);
  const currentBatchItems = buildCurrentBatchItems(data);

  dlog("[persist] backend raw summary =", {
    ok: data?.ok,
    message: data?.message,
    rows: Array.isArray(data?.rows) ? data.rows.length : 0,
    emails: Array.isArray(data?.emails) ? data.emails.length : 0,
    count: data?.count
  });

  dtable(
    "[persist] rows sample",
    dslice((Array.isArray(data?.rows) ? data.rows : []).map((r, i) => ({
      i,
      id: r?.ID ?? r?.Id ?? r?.id ?? "",
      subject: r?.["Tiêu đề"] ?? r?.Subject ?? r?.subject ?? "",
      sender: r?.["Người gửi"] ?? r?.Sender ?? r?.sender ?? "",
      label: r?.["Trạng thái"] ?? r?.Label ?? r?.label ?? r?.verdict ?? "",
      score: r?.["Điểm"] ?? r?.Score ?? r?.score ?? ""
    })), 15)
  );

  dtable(
    "[persist] emails sample",
    dslice((Array.isArray(data?.emails) ? data.emails : []).map((e, i) => ({
      i,
      id: e?.id || "",
      subject: e?.subject || "",
      sender: e?.sender || "",
      sender_email: e?.sender_email || "",
      gmail_msgid: e?.gmail_msgid || e?.gmail_message_id || e?.message_id || e?.msg_id || "",
      gmail_thrid: e?.gmail_thrid || e?.gmail_thread_id || e?.thread_id || e?.thr_id || "",
      date: e?.date || ""
    })), 15)
  );

  dtable(
    "[persist] currentBatchItems sample",
    dslice(currentBatchItems.map((item, i) => ({
      i,
      scan_order: item?.scan_order,
      mail_id: item?.mail_id,
      subject: item?.subject,
      sender: item?.sender,
      sender_email: item?.sender_email,
      gmail_msgid: item?.gmail_msgid || "",
      gmail_thrid: item?.gmail_thrid || "",
      label: item?.label,
      score: item?.score,
      updated_at: item?.updated_at
    })), 15)
  );

  let capturedRows = Array.isArray(capturedRowsBeforeScan) ? capturedRowsBeforeScan : [];
  if (!capturedRows.length) capturedRows = await captureInboxRowsFromActiveGmailTab();

  dtable(
    "[persist] capturedRows final sample",
    dslice(capturedRows.map((row, i) => ({
      i,
      row_index: row?.row_index,
      subject: row?.subject,
      sender: row?.sender,
      gmail_msgid: row?.gmail_msgid,
      gmail_thrid: row?.gmail_thrid,
      date: row?.date || row?.timestamp || ""
    })), 20)
  );

  const useExactOnlyBinding = data?.exact_mode === true;
  const rowsForBinding = useExactOnlyBinding
    ? capturedRows
    : capturedRows.slice(0, currentBatchItems.length);

  dtable(
    "[persist] rowsForBinding",
    rowsForBinding.map((row, i) => ({
      i,
      row_index: row?.row_index,
      subject: row?.subject,
      sender: row?.sender,
      gmail_msgid: row?.gmail_msgid,
      gmail_thrid: row?.gmail_thrid
    }))
  );

  const currentBatchBindings = useExactOnlyBinding
    ? buildExactBindings(currentBatchItems, rowsForBinding)
    : buildCurrentBatchBindings(currentBatchItems, rowsForBinding);
  const scanSessionId = currentBatchItems[0]?.scan_session_id || makeId();
  const nowIso = new Date().toISOString();

  dtable(
    "[persist] bindings result",
    dslice(currentBatchBindings.map((b, i) => ({
      i,
      key: b?.key,
      item_key: b?.item_key,
      row_index: b?.row_index,
      row_subject: b?.row_subject,
      row_sender: b?.row_sender,
      gmail_msgid: b?.gmail_msgid,
      gmail_thrid: b?.gmail_thrid,
      label: b?.label,
      score: b?.score
    })), 30)
  );

  dlog("[persist] totals =", {
    currentBatchItems: currentBatchItems.length,
    capturedRows: capturedRows.length,
    bindings: currentBatchBindings.length
  });

  await chrome.storage.local.set({
    scan_history: history.slice(0, 100),
    last_scan_result: record,
    [CURRENT_BATCH_KEY]: currentBatchItems,
    [CURRENT_BATCH_META_KEY]: {
      total: currentBatchItems.length,
      bound_total: currentBatchBindings.length,
      last_updated_at: nowIso,
      scan_session_id: scanSessionId,
      strict_binding_only: true,
      exact_mode: useExactOnlyBinding,
      backend_endpoint: data?.endpoint_used || settings.apiPath
    },
    [CURRENT_BATCH_BINDINGS_KEY]: currentBatchBindings,
    [CURRENT_BATCH_BINDINGS_META_KEY]: {
      total: currentBatchBindings.length,
      last_updated_at: nowIso,
      scan_session_id: scanSessionId,
      strict_binding_only: true,
      exact_mode: useExactOnlyBinding
    },
    [DASHBOARD_HISTORY_KEY]: mergedDashboard.slice(0, 500),
    [DASHBOARD_META_KEY]: {
      total: mergedDashboard.length,
      last_updated_at: nowIso,
      last_scan_session_id: scanSessionId
    }
  });

  return {
    currentBatchItems,
    currentBatchBindings
  };
}

btnHealth.addEventListener("click", async () => {
  setLoading(true);
  setStatus("Đang kiểm tra backend...");
  resultEl.textContent = "Đang gọi /health ...";

  try {
    const settings = await getSettings();
    const url = normalizeUrl(settings.backendBaseUrl, settings.healthPath);
    const data = await fetchJson(url, {
      method: "GET",
      headers: { "Accept": "application/json" }
    });

    setStatus("Backend đang hoạt động", true);
    resultEl.textContent = pretty(data);
  } catch (err) {
    setStatus("Không kết nối được backend", false);
    resultEl.textContent = err.message || String(err);
  } finally {
    setLoading(false);
  }
});

btnSaved.addEventListener("click", async () => {
  setLoading(true);
  setStatus("Đang lấy đăng nhập đã lưu...");
  resultEl.textContent = "Đang gọi /api/saved-login ...";

  try {
    await loadSavedLoginIntoForm(true);
  } finally {
    setLoading(false);
  }
});

btnFetch.addEventListener("click", async () => {
  setLoading(true);
  setStatus("Đang scan mail...");
  resultEl.textContent = "Đang gọi API scan mail ...";

  try {
    const settings = await getSettings();
    const url = normalizeUrl(settings.backendBaseUrl, settings.apiPath);

    let passwordToUse = appPasswordEl.value.trim();
    if (!passwordToUse) {
      const saved = await loadSavedLoginIntoForm(false);
      if (saved?.password) {
        passwordToUse = saved.password;
        appPasswordEl.value = saved.password;
      }
    }

    const payload = {
      email: emailEl.value.trim(),
      app_password: passwordToUse,
      mailbox_label: mailboxLabelEl.value.trim() || "Hộp thư đến (INBOX)",
      limit: Number(limitEl.value || 10),
      remember_login: rememberLoginEl.value === "true"
    };

    await saveFormLocal();

    const capturedRowsBeforeScan = await captureInboxRowsFromActiveGmailTab();

    const exactScan = await tryExactUiTargetScan(settings, payload, capturedRowsBeforeScan);

    let data;
    let endpointUsed = settings.apiPath;

    if (exactScan.used && exactScan.data) {
      data = {
        ...exactScan.data,
        endpoint_used: exactScan.endpoint,
        exact_mode: exactScan.data?.exact_mode === true
      };
      endpointUsed = exactScan.endpoint;
    } else {
      data = await fetchJson(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify(payload)
      });
      data = {
        ...data,
        endpoint_used: settings.apiPath,
        exact_mode: data?.exact_mode === true
      };
    }

    const persisted = await persistScanResult(data, payload, settings, capturedRowsBeforeScan);

    const bound = persisted.currentBatchBindings.length;
    const total = persisted.currentBatchItems.length;
    const modeText = data?.exact_mode ? "exact" : "batch";
    const requested = Array.isArray(capturedRowsBeforeScan)
      ? Math.min(capturedRowsBeforeScan.length, payload.limit)
      : payload.limit;
    const matched = Number(data?.exact_meta?.matched_total || total);
    const unmatched = Number(data?.exact_meta?.unmatched_total || Math.max(0, requested - matched));
    setStatus(
      `Scan mail thành công • ${modeText} • requested ${requested} • matched ${matched} • skip ${unmatched} • bound ${bound}/${total}`,
      true
    );
    resultEl.textContent = pretty({
      ...data,
      strict_binding_only: true,
      bound_total: bound,
      scan_total: total,
      requested_total: requested,
      matched_total: matched,
      skipped_total: unmatched,
      endpoint_used: endpointUsed
    });

    if (payload.remember_login) {
      await loadSavedLoginIntoForm(false);
    }
  } catch (err) {
    setStatus("Scan mail thất bại", false);
    resultEl.textContent = err.message || String(err);
  } finally {
    setLoading(false);
  }
});

btnClear.addEventListener("click", async () => {
  setLoading(true);
  setStatus("Đang xóa đăng nhập đã lưu...");
  resultEl.textContent = "Đang gọi DELETE /api/saved-login ...";

  try {
    const settings = await getSettings();
    const url = normalizeUrl(settings.backendBaseUrl, "/api/saved-login");
    const data = await fetchJson(url, {
      method: "DELETE",
      headers: { "Accept": "application/json" }
    });

    appPasswordEl.value = "";
    setStatus("Đã xóa đăng nhập đã lưu", true);
    resultEl.textContent = pretty(data);
  } catch (err) {
    setStatus("Xóa đăng nhập thất bại", false);
    resultEl.textContent = err.message || String(err);
  } finally {
    setLoading(false);
  }
});

btnDashboard.addEventListener("click", () => {
  const url = chrome.runtime.getURL("dashboard.html");
  window.open(url, "_blank");
});

openOptions.addEventListener("click", (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

(async function init() {
  await refreshUi();
  await loadFormLocal();
  await loadSavedLoginIntoForm(false);
})();
