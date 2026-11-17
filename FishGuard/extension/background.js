importScripts("domains.js", "detector.js", "openphish.js", "phishing-database.js", "cert-polska.js", "metamask-feed.js");

const API = "http://127.0.0.1:8000/api/v1";
const BLOCKED_PAGE = chrome.runtime.getURL("blocked.html");
const POPUP_PAGE = chrome.runtime.getURL("popup.html");
const warnings = new Map();
const bypasses = new Map();
const clearLeftoverRetryRules = chrome.declarativeNetRequest.getSessionRules().then(rules => {
  const ids = rules.filter(rule => rule.action.type === "allow").map(rule => rule.id);
  if (ids.length) return chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids });
}).catch(() => {});
const navigations = new Map();
let statsWrites = Promise.resolve();
let feedRefresh;
let openPhishRefresh;
let openPhishUrls;

async function getOpenPhishUrls() {
  if (!OPENPHISH_ENABLED) return new Set();
  if (!openPhishUrls) {
    const { openPhishSnapshot = [] } = await chrome.storage.local.get("openPhishSnapshot");
    openPhishUrls = new Set(Array.isArray(openPhishSnapshot) ? openPhishSnapshot : []);
  }
  return openPhishUrls;
}

function refreshOpenPhish() {
  if (!OPENPHISH_ENABLED) return Promise.resolve();
  if (openPhishRefresh) return openPhishRefresh;
  openPhishRefresh = (async () => {
    const response = await fetch(OPENPHISH_FEED, { credentials: "omit", redirect: "error",
      cache: "no-store", referrerPolicy: "no-referrer", signal: AbortSignal.timeout(15000) });
    if (!response.ok || !response.body) throw new Error("OpenPhish download failed");
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 8 * 1024 * 1024) { await reader.cancel(); throw new Error("Feed too large"); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    const snapshot = OpenPhish.parse(new TextDecoder().decode(bytes));
    await chrome.storage.local.set({ openPhishSnapshot: snapshot });
    openPhishUrls = new Set(snapshot);
  })().catch(error => console.warn("OpenPhish refresh failed:", error.message))
    .finally(() => { openPhishRefresh = undefined; });
  return openPhishRefresh;
}

async function api(path, options) {
  const response = await fetch(API + path, {
    ...options, signal: AbortSignal.timeout(3500), credentials: "omit",
    redirect: "error", cache: "no-store", referrerPolicy: "no-referrer",
  });
  if (!response.ok) throw new Error("FishGuard API returned " + response.status);
  return response.json();
}

// Dynamic DNR rules are the browser's persistent cache. Keep the last successful
// snapshot during downtime and replace it atomically when the API recovers.
function refreshFeed() {
  if (feedRefresh) return feedRefresh;
  feedRefresh = (async () => {
    const { domains } = await api("/threat-feed");
    if (!Array.isArray(domains) || domains.length > 2000) throw new Error("Invalid feed");
    const verified = [...new Set(domains)].sort();
    if (verified.some(host => typeof host !== "string" || host.length > 253 ||
      !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/.test(host) ||
      TRUSTED_ROOTS.some(root => PhishGuard.isUnder(root, host)))) throw new Error("Invalid feed domain");
    const previous = await chrome.declarativeNetRequest.getDynamicRules();
    if (JSON.stringify(previous.flatMap(rule => rule.condition.requestDomains || []).sort()) ===
        JSON.stringify(verified)) return;
    const addRules = [];
    for (let i = 0; i < verified.length; i += 100) {
      addRules.push({
        id: i / 100 + 1, priority: 1, action: { type: "block" },
        condition: { requestDomains: verified.slice(i, i + 100),
          resourceTypes: ["main_frame", "sub_frame"] },
      });
    }
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: previous.map(rule => rule.id), addRules,
    });
  })().catch(error => console.warn("Threat feed refresh failed:", error.message))
    .finally(() => { feedRefresh = undefined; });
  return feedRefresh;
}

async function startFeed() {
  if (!await chrome.alarms.get("threat-feed")) {
    await chrome.alarms.create("threat-feed", { periodInMinutes: 15 });
  }
  await refreshFeed();
  if (!await chrome.alarms.get("phishing-database")) {
    await chrome.alarms.create("phishing-database", { periodInMinutes: 720 });
  }
  void PhishingDatabase.refresh();
  if (!await chrome.alarms.get("cert-polska")) {
    await chrome.alarms.create("cert-polska", { periodInMinutes: 5 });
  }
  void CertPolska.refresh();
  if (!await chrome.alarms.get("metamask-feed")) {
    await chrome.alarms.create("metamask-feed", { periodInMinutes: 720 });
  }
  void MetaMaskFeed.refresh();
  if (OPENPHISH_ENABLED) {
    if (!await chrome.alarms.get("openphish-feed")) {
      await chrome.alarms.create("openphish-feed", { periodInMinutes: 720 });
    }
    void refreshOpenPhish();
  } else {
    await chrome.alarms.clear("openphish-feed");
    await chrome.storage.local.remove("openPhishSnapshot");
  }
}
chrome.runtime.onInstalled.addListener(() => {
  // Remove values written by older versions, including historical raw URLs.
  void chrome.storage.local.remove(["tabVerdicts", "bypass_active_url", "backendStatus",
    "scanned_count", "blocked_count", "urlhausSnapshot", "urlhausUpdated"]);
  void chrome.alarms.clear("urlhaus-feed");
  void startFeed();
});
chrome.runtime.onStartup.addListener(() => { void startFeed(); });
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === "threat-feed") void refreshFeed();
  if (alarm.name === "openphish-feed") void refreshOpenPhish();
  if (alarm.name === "phishing-database") void PhishingDatabase.refresh();
  if (alarm.name === "cert-polska") void CertPolska.refresh();
  if (alarm.name === "metamask-feed") void MetaMaskFeed.refresh();
});

function count(blocked) {
  statsWrites = statsWrites.catch(() => {}).then(async () => {
    const { scannedCount = 0, blockedCount = 0 } = await chrome.storage.local.get([
      "scannedCount", "blockedCount",
    ]);
    await chrome.storage.local.set({
      scannedCount: scannedCount + 1, blockedCount: blockedCount + Number(blocked),
    });
  });
  return statsWrites;
}

function setBadge(tabId, status) {
  const text = { trusted: "OK", suspicious: "?", blocked: "!" }[status] || "";
  const color = { trusted: "#047857", suspicious: "#92400e", blocked: "#b91c1c" }[status];
  void chrome.action.setBadgeText({ tabId, text }).catch(() => {});
  if (color) void chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => {});
}

async function inspectNavigation(details, countNavigation) {
  const { tabId, url: raw, documentId } = details;
  const url = PhishGuard.parse(raw);
  if (details.frameId !== 0 || details.documentLifecycle !== "active") return;
  if (raw.startsWith(BLOCKED_PAGE + "?")) return;
  const ticket = {};
  navigations.set(tabId, ticket);
  const bypass = takeRetry(tabId);
  warnings.delete(tabId);
  if (!url) return;
  let verdict = PhishGuard.evaluate(url);
  const listed = (OPENPHISH_ENABLED && (await getOpenPhishUrls()).has(OpenPhish.canonical(raw))) ||
    await PhishingDatabase.contains(raw).catch(() => false) || await CertPolska.contains(raw).catch(() => false) ||
    await MetaMaskFeed.contains(raw).catch(() => false);
  if (listed) verdict = { host: url.hostname, status: "blocked", score: 100, reasons: ["blocklist"] };
  if (navigations.get(tabId) !== ticket) return;
  const explicitlyAllowed = bypass?.url === url.href && bypass.expires > Date.now();
  const block = verdict.status === "blocked" && !explicitlyAllowed;
  if (!block) {
    setBadge(tabId, explicitlyAllowed ? "suspicious" : verdict.status);
    if (countNavigation) await count(false);
    return;
  }

  // The frame may have changed while the service worker was retrieving it.
  const frame = await chrome.webNavigation.getFrame({ tabId, frameId: 0 });
  if (navigations.get(tabId) !== ticket || frame?.documentId !== documentId || frame.url !== raw) return;
  await showWarning(tabId, verdict, url.href, "skip");
}

function takeRetry(tabId) {
  const retry = bypasses.get(tabId);
  if (!retry) return;
  bypasses.delete(tabId);
  void chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [retry.ruleId] })
    .catch(logNavigationError);
  return retry;
}

async function showWarning(tabId, verdict, retryUrl, back) {
  const warning = { id: crypto.randomUUID(), url: retryUrl, expires: Date.now() + 60_000 };
  warnings.set(tabId, warning);
  const params = new URLSearchParams({ host: verdict.host, score: verdict.score,
    reasons: verdict.reasons.join(","), id: warning.id, back });
  setTimeout(() => {
    if (warnings.get(tabId) === warning) warnings.delete(tabId);
  }, 60_000);
  await chrome.tabs.update(tabId, { url: BLOCKED_PAGE + "?" + params });
  setBadge(tabId, "blocked");
  await count(true);
}

function logNavigationError(error) {
  console.warn("Navigation check failed:", error.message);
}

async function inspectFailedNavigation(details) {
  const { tabId, url: raw, documentId } = details;
  if (details.frameId !== 0 || details.documentLifecycle !== "active" ||
      !documentId || details.error === "net::ERR_ABORTED") return;
  const url = PhishGuard.parse(raw);
  if (!url) return;
  const bypass = takeRetry(tabId);
  if (bypass?.url === url.href && bypass.expires > Date.now() &&
      details.error !== "net::ERR_BLOCKED_BY_CLIENT") return;

  const ticket = navigations.get(tabId);
  let verdict = PhishGuard.evaluate(url);
  if (verdict.status !== "blocked" && details.error === "net::ERR_BLOCKED_BY_CLIENT") {
    const rules = await chrome.declarativeNetRequest.getDynamicRules();
    verdict = PhishGuard.evaluate(url, rules.flatMap(rule => rule.condition.requestDomains || []));
  }
  if (verdict.status !== "blocked") return;

  // A DNS error or DNR block can leave a browser error document. Only
  // replace it if it still belongs to this failed top-level navigation.
  const frame = await chrome.webNavigation.getFrame({ tabId, frameId: 0 });
  if (navigations.get(tabId) !== ticket || !frame?.errorOccurred ||
      frame.documentId !== documentId || frame.url !== raw) return;
  await showWarning(tabId, verdict, url.href, "skip");
}

chrome.webNavigation.onBeforeNavigate.addListener(details => {
  if (details.frameId === 0) navigations.set(details.tabId, {});
});
chrome.webNavigation.onCommitted.addListener(details => {
  void inspectNavigation(details, true).catch(logNavigationError);
});
chrome.webNavigation.onHistoryStateUpdated.addListener(details => {
  void inspectNavigation(details, false).catch(logNavigationError);
});
chrome.webNavigation.onErrorOccurred.addListener(details => {
  void inspectFailedNavigation(details).catch(logNavigationError);
});
chrome.tabs.onRemoved.addListener(tabId => {
  warnings.delete(tabId);
  takeRetry(tabId);
  navigations.delete(tabId);
});

chrome.runtime.onMessage.addListener((request, sender, respond) => {
  if (sender.id !== chrome.runtime.id || !request) return;
  if (request.action === "check-feed-link" && sender.tab && PhishGuard.parse(sender.url) &&
      typeof request.url === "string" && request.url.length <= 8192) {
    Promise.all([PhishingDatabase.contains(request.url).catch(() => false),
      CertPolska.contains(request.url).catch(() => false), MetaMaskFeed.contains(request.url).catch(() => false)])
      .then(results => respond({ listed: results.some(Boolean) }));
    return true;
  }
  if (request.action === "popup-feed-check" && sender.url === POPUP_PAGE && Number.isInteger(request.tabId)) {
    (async () => {
      const tab = await chrome.tabs.get(request.tabId);
      if (!tab.active || !PhishGuard.parse(tab.url)) return { ok: false };
      const results = await Promise.all([
        OPENPHISH_ENABLED ? getOpenPhishUrls().then(urls => urls.has(OpenPhish.canonical(tab.url))) : false,
        PhishingDatabase.contains(tab.url), CertPolska.contains(tab.url), MetaMaskFeed.contains(tab.url),
      ]);
      return { ok: true, listed: results.some(Boolean) };
    })().then(respond, () => respond({ ok: false }));
    return true;
  }
  if (request.action === "warn-link" && Number.isInteger(sender.tab?.id) &&
      Number.isInteger(sender.frameId) && sender.documentId && typeof request.url === "string" &&
      request.url.length <= 8192 && typeof request.newTab === "boolean") {
    (async () => {
      const url = PhishGuard.parse(request.url);
      if (!url || !PhishGuard.parse(sender.url)) return { ok: false };
      let verdict = PhishGuard.evaluate(url);
      const listed = (OPENPHISH_ENABLED && (await getOpenPhishUrls()).has(OpenPhish.canonical(url.href))) ||
        await PhishingDatabase.contains(url.href).catch(() => false) || await CertPolska.contains(url.href).catch(() => false) ||
        await MetaMaskFeed.contains(url.href).catch(() => false);
      if (listed) verdict = { host: url.hostname, status: "blocked", score: 100, reasons: ["blocklist"] };
      if (verdict.status !== "blocked") return { ok: false };
      const frame = await chrome.webNavigation.getFrame({ tabId: sender.tab.id, frameId: sender.frameId });
      if (frame?.documentId !== sender.documentId || frame.documentLifecycle !== "active") return { ok: false };
      const tabId = request.newTab ? (await chrome.tabs.create({ windowId: sender.tab.windowId,
        index: sender.tab.index + 1, openerTabId: sender.tab.id })).id : sender.tab.id;
      await showWarning(tabId, verdict, url.href, request.newTab ? "close" : "previous");
      return { ok: true };
    })().then(respond, () => respond({ ok: false }));
    return true;
  }
  if (request.action === "report-false-positive" && sender.url?.startsWith(BLOCKED_PAGE + "?") && sender.frameId === 0) {
    const warning = warnings.get(sender.tab?.id);
    const params = new URL(sender.url).searchParams;
    const host = params.get("host");
    const parsed = host && PhishGuard.parse("https://" + host);
    if (!request.id || params.get("id") !== request.id || !parsed || parsed.hostname !== host ||
        parsed.username || parsed.password || parsed.port || parsed.pathname !== "/" || parsed.search || parsed.hash ||
        (warning && warning.id === request.id && PhishGuard.parse(warning.url)?.hostname !== host)) {
      respond({ ok: false }); return;
    }
    api("/report", { method: "POST", headers: { "Content-Type": "application/json",
      "X-PhishGuard-Client": "extension-v1" }, body: JSON.stringify({ url: "https://" + host,
        category: "false_positive", reason: "User reported an incorrect warning" }) })
      .then(() => respond({ ok: true }), () => respond({ ok: false }));
    return true;
  }
  if (request.action === "proceed" && sender.url?.startsWith(BLOCKED_PAGE + "?") && sender.frameId === 0) {
    const tabId = sender.tab?.id;
    const warning = warnings.get(tabId);
    if (!warning || warning.id !== request.id || warning.expires <= Date.now() || bypasses.has(tabId)) {
      respond({ ok: false });
      return;
    }
    warnings.delete(tabId);
    (async () => {
      await clearLeftoverRetryRules;
      const target = new URL(warning.url);
      target.hash = "";
      const regexFilter = "^" + target.href.replace(/[.*+?^$(){}|[\]\\]/g, "\\$&") + "$";
      const retry = { url: warning.url, ruleId: tabId + 1, expires: Date.now() + 10_000 };
      bypasses.set(tabId, retry);
      try {
        await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [retry.ruleId], addRules: [{
          id: retry.ruleId, priority: 2, action: { type: "allow" },
          condition: { tabIds: [tabId], resourceTypes: ["main_frame"], regexFilter, isUrlFilterCaseSensitive: true },
        }] });
        setTimeout(() => {
          if (bypasses.get(tabId) === retry) takeRetry(tabId);
        }, 10_000);
        const frame = await chrome.webNavigation.getFrame({ tabId, frameId: 0 });
        if (frame?.documentId !== sender.documentId || bypasses.get(tabId) !== retry) {
          throw new Error("Warning is no longer active");
        }
        await chrome.tabs.update(tabId, { url: warning.url });
        return { ok: true };
      } catch {
        if (bypasses.get(tabId) === retry) takeRetry(tabId);
        return { ok: false };
      }
    })().then(respond, () => respond({ ok: false }));
    return true;
  }

  if (request.action === "report" && sender.url === POPUP_PAGE && Number.isInteger(request.tabId)) {
    (async () => {
      const tab = await chrome.tabs.get(request.tabId);
      const url = PhishGuard.parse(tab.url);
      let host = url?.hostname;
      if (tab.url?.startsWith(BLOCKED_PAGE + "?")) {
        const warningHost = new URL(tab.url).searchParams.get("host");
        if (warningHost && PhishGuard.parse("https://" + warningHost)?.hostname === warningHost) {
          host = warningHost;
        }
      }
      if (!tab.active || !host) return { ok: false };
      // Reports are explicit and contain only the hostname.
      await api("/report", { method: "POST", headers: { "Content-Type": "application/json",
        "X-PhishGuard-Client": "extension-v1" },
        body: JSON.stringify({ url: "https://" + host }) });
      return { ok: true };
    })().then(respond, () => respond({ ok: false }));
    return true;
  }
});
