const backendBaseUrlEl = document.getElementById("backendBaseUrl");
const apiPathEl = document.getElementById("apiPath");
const healthPathEl = document.getElementById("healthPath");
const saveBtn = document.getElementById("saveBtn");
const msgEl = document.getElementById("msg");

async function loadSettings() {
  const data = await chrome.storage.sync.get({
    backendBaseUrl: "http://127.0.0.1:8000",
    apiPath: "/api/scan-imap-batch",
    healthPath: "/health"
  });

  backendBaseUrlEl.value = data.backendBaseUrl;
  apiPathEl.value = data.apiPath;
  healthPathEl.value = data.healthPath;
}

saveBtn.addEventListener("click", async () => {
  const payload = {
    backendBaseUrl: backendBaseUrlEl.value.trim() || "http://127.0.0.1:8000",
    apiPath: apiPathEl.value.trim() || "/api/scan-imap-batch",
    healthPath: healthPathEl.value.trim() || "/health"
  };

  await chrome.storage.sync.set(payload);
  msgEl.textContent = "Đã lưu cài đặt.";
  setTimeout(() => {
    msgEl.textContent = "";
  }, 2000);
});

loadSettings();
