
import { analyzeUrl } from "./analyzer.js";

(async function () {
  try {
    const res = analyzeUrl(location.href);
    chrome.runtime.sendMessage({ type: "PAGE_SCAN", data: res });
  } catch (e) {
    // ignore
  }
})();
