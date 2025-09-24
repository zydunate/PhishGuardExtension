
// Placeholder: future enhancements to use remote API
const flagEl = document.getElementById("flagForms");
const apiEl = document.getElementById("api");
const status = document.getElementById("status");

chrome.storage.sync.get({ flagForms: true, apiEndpoint: "" }, (cfg) => {
  flagEl.checked = cfg.flagForms;
  apiEl.value = cfg.apiEndpoint;
});

document.getElementById("save").addEventListener("click", () => {
  chrome.storage.sync.set({ flagForms: flagEl.checked, apiEndpoint: apiEl.value || "" }, () => {
    status.textContent = "Saved.";
    setTimeout(() => status.textContent = "", 1000);
  });
});
