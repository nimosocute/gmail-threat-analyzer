chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.sync.get([
    "backendBaseUrl",
    "apiPath",
    "healthPath"
  ]);

  const patch = {};

  if (!current.backendBaseUrl) patch.backendBaseUrl = "http://127.0.0.1:8000";
  if (!current.apiPath || current.apiPath === "/" || current.apiPath === "/api/fetch-imap-emails") patch.apiPath = "/api/scan-imap-batch";
  if (!current.healthPath) patch.healthPath = "/health";

  if (Object.keys(patch).length > 0) {
    await chrome.storage.sync.set(patch);
  }
});


chrome.runtime.onStartup.addListener(async () => {
  const current = await chrome.storage.sync.get(["apiPath"]);
  if (!current.apiPath || current.apiPath === "/" || current.apiPath === "/api/fetch-imap-emails") {
    await chrome.storage.sync.set({ apiPath: "/api/scan-imap-batch" });
  }
});
