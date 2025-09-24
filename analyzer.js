
// Simple heuristic URL analyzer for PhishGuard Chrome Extension (MV3)
export function analyzeUrl(raw) {
  const result = {
    url: raw,
    normalized: "",
    label: "safe",
    score: 0,          // 0..100
    reasons: []
  };
  if (!raw) {
    result.label = "unknown";
    result.reasons.push("No URL provided");
    return result;
  }
  let url;
  try {
    // Add scheme if missing
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(raw)) raw = "http://" + raw;
    url = new URL(raw);
  } catch (e) {
    result.label = "unknown";
    result.reasons.push("Malformed URL");
    return result;
  }
  result.normalized = url.href;

  const host = url.hostname.toLowerCase();

  // Rule 1: Non-HTTPS
  if (url.protocol !== "https:") {
    result.score += 25;
    result.reasons.push("Connection is not HTTPS");
  }

  // Rule 2: IP address host
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes("xn--")) {
    result.score += 20;
    result.reasons.push("Host looks like an IP address or punycode");
  }

  // Rule 3: Common suspicious keywords
  const kw = ["login", "verify", "update", "password", "support", "account", "security", "urgent"];
  if (kw.some(k => url.pathname.toLowerCase().includes(k) || url.search.toLowerCase().includes(k))) {
    result.score += 10;
    result.reasons.push("Contains high-risk keywords");
  }

  // Rule 4: Shorteners / new TLDs often abused (heuristic only)
  const shorteners = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","rb.gy"];
  if (shorteners.includes(host)) {
    result.score += 15;
    result.reasons.push("URL shortener detected");
  }

  // Rule 5: Explicitly flag forms platforms per user's policy
  const flaggedForms = [
    "forms.gle",
    "docs.google.com",
    "forms.office.com",
    "forms.microsoft.com",
    "forms.cloud.microsoft"
  ];
  if (flaggedForms.some(d => host === d || host.endsWith("." + d))) {
    result.score = Math.max(result.score, 80);
    result.reasons.push("Form-hosting domain flagged by policy");
  }

  // Labeling
  if (result.score >= 70) result.label = "malicious";
  else if (result.score >= 40) result.label = "suspicious";
  else result.label = "safe";

  return result;
}
