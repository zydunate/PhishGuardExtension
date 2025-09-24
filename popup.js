
import { analyzeUrl } from "./analyzer.js";

const urlEl = document.getElementById("url");
const out = document.getElementById("out");
document.getElementById("scan").addEventListener("click", run);
urlEl.addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });

async function run() {
  const u = urlEl.value.trim();
  const res = analyzeUrl(u);
  render(res);
  chrome.runtime.sendMessage({ type: "ANALYZE_URL", url: u }, () => {});
}

function pill(label) {
  if (label === "malicious") return '<span class="pill bad">Malicious</span>';
  if (label === "suspicious") return '<span class="pill warn">Suspicious</span>';
  return '<span class="pill ok">Safe</span>';
}

function render(res) {
  out.innerHTML = `
    <div>${pill(res.label)} <small>score ${res.score}/100</small></div>
    <div style="word-break: break-all;"><small>${res.normalized || res.url}</small></div>
    <ul>${res.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join("") || "<li>No issues detected</li>"}</ul>
  `;
}

function escapeHtml(s) { return s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

// Autofill with current tab URL
chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
  if (tabs[0]?.url) urlEl.value = tabs[0].url;
});
