
import { analyzeUrl } from "./analyzer.js";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "pg-scan-link",
    title: "Scan link with PhishGuard",
    contexts: ["link"]
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "pg-scan-link" && info.linkUrl) {
    const res = analyzeUrl(info.linkUrl);
    await chrome.storage.local.set({ lastScan: res });
    chrome.action.setBadgeText({ text: badge(res.label), tabId: tab.id });
    chrome.action.setBadgeBackgroundColor({ color: badgeColor(res.label) });
  }
});

chrome.runtime.onMessage.addListener(async (msg, sender, sendResponse) => {
  if (msg?.type === "PAGE_SCAN") {
    const res = msg.data;
    await chrome.storage.local.set({ pageScan: res });
    if (sender.tab?.id) {
      chrome.action.setBadgeText({ text: badge(res.label), tabId: sender.tab.id });
      chrome.action.setBadgeBackgroundColor({ color: badgeColor(res.label) });
    }
  } else if (msg?.type === "ANALYZE_URL") {
    const res = analyzeUrl(msg.url);
    chrome.storage.local.set({ lastScan: res });
    sendResponse(res);
  }
  return true;
});

function badge(label) {
  return label === "malicious" ? "BAD" : label === "suspicious" ? "WARN" : "OK";
}
function badgeColor(label) {
  return label === "malicious" ? "#D32F2F" : label === "suspicious" ? "#F57C00" : "#2E7D32";
}
