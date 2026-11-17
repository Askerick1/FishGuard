// Domain data: MetaMask eth-phishing-detect, see THIRD_PARTY_NOTICES.md.
const METAMASK_FEED_URL = "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json";
const MetaMaskFeed = (() => {
  let snapshot, loading, refreshPromise;
  function domains(values) {
    if (!Array.isArray(values) || values.length > 500000) throw new Error("Invalid MetaMask list");
    const result = new Set();
    let invalid = 0;
    for (const value of values) {
      if (typeof value !== "string" || value.length > 253 || !/^[a-z0-9.-]+$/i.test(value)) { invalid++; continue; }
      let host;
      try { host = new URL("https://" + value).hostname.replace(/\.$/, ""); } catch { invalid++; continue; }
      if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(host)) {
        invalid++; continue;
      }
      result.add(host);
    }
    if (invalid > Math.max(10, values.length * 0.05)) throw new Error("Too many invalid MetaMask domains");
    return [...result];
  }
  function parse(text) {
    const config = JSON.parse(text);
    const blocked = domains(config.blacklist), allowed = domains(config.whitelist);
    if (!blocked.length) throw new Error("Empty MetaMask blocklist");
    return { blocked, allowed };
  }
  function compile(data) {
    return data && Array.isArray(data.blocked) && Array.isArray(data.allowed) ?
      { blocked: new Set(data.blocked), allowed: new Set(data.allowed) } : null;
  }
  async function load() {
    if (snapshot) return snapshot;
    if (!loading) loading = chrome.storage.local.get("metaMaskSnapshot").then(data => {
      if (!snapshot) snapshot = compile(data.metaMaskSnapshot);
      return snapshot;
    }).finally(() => { loading = undefined; });
    return loading;
  }
  async function contains(raw) {
    const url = PhishGuard.parse(raw), data = await load();
    if (!url || !data) return false;
    const labels = url.hostname.replace(/\.$/, "").split(".");
    let blocked = false, allowed = false;
    for (let i = 0; i < labels.length - 1; i++) {
      const host = labels.slice(i).join(".");
      blocked ||= data.blocked.has(host);
      allowed ||= data.allowed.has(host);
    }
    // MetaMask exceptions apply only to its own list, not other threat sources.
    return blocked && !allowed;
  }
  function refresh() {
    if (refreshPromise) return refreshPromise;
    refreshPromise = (async () => {
      const response = await fetch(METAMASK_FEED_URL, { credentials: "omit", redirect: "error",
        cache: "no-store", referrerPolicy: "no-referrer", signal: AbortSignal.timeout(30000) });
      if (!response.ok || !response.body) throw new Error("MetaMask download failed");
      const reader = response.body.getReader(), chunks = [];
      let size = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > 8 * 1024 * 1024) { await reader.cancel(); throw new Error("MetaMask list too large"); }
        chunks.push(value);
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
      const next = parse(new TextDecoder().decode(bytes));
      const previous = snapshot;
      snapshot = compile(next);
      try {
        await chrome.storage.local.set({ metaMaskSnapshot: next, metaMaskUpdated: Date.now() });
      } catch (error) {
        snapshot = previous;
        throw error;
      }
    })().catch(error => console.warn("MetaMask feed refresh failed:", error.message))
      .finally(() => { refreshPromise = undefined; });
    return refreshPromise;
  }
  return { parse, contains, refresh };
})();
