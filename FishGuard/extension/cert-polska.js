const CERT_POLSKA_URL = "https://hole.cert.pl/domains/v2/domains.txt";
const CertPolska = (() => {
  let connection, refreshPromise;
  function open() {
    if (!connection) connection = new Promise((resolve, reject) => {
      const request = indexedDB.open("cert-polska", 1);
      request.onupgradeneeded = () => {
        request.result.createObjectStore("a");
        request.result.createObjectStore("b");
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    }).catch(error => { connection = undefined; throw error; });
    return connection;
  }
  async function activeStore() {
    const { certPolskaActive } = await chrome.storage.local.get("certPolskaActive");
    return certPolskaActive === "a" || certPolskaActive === "b" ? certPolskaActive : null;
  }
  function parse(text) {
    const result = new Set();
    for (const raw of text.split(/\r?\n/)) {
      const host = raw.trim().toLowerCase();
      if (!host || host.startsWith("#")) continue;
      if (host.length > 253 || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(host)) {
        throw new Error("Invalid CERT Polska domain");
      }
      result.add(host);
    }
    if (!result.size || result.size > 500000) throw new Error("Invalid CERT Polska list");
    return [...result];
  }
  function write(database, store, hosts, clear = false) {
    return new Promise((resolve, reject) => {
      const tx = database.transaction(store, "readwrite"), target = tx.objectStore(store);
      if (clear) target.clear();
      for (const host of hosts) target.put(1, host);
      tx.oncomplete = resolve;
      tx.onerror = tx.onabort = () => reject(tx.error || new Error("Database write failed"));
    });
  }
  async function contains(raw) {
    const url = PhishGuard.parse(raw);
    if (!url) return false;
    const active = await activeStore();
    if (!active) return false;
    const database = await open();
    const labels = url.hostname.replace(/\.$/, "").split(".");
    if (labels.length < 2) return false;
    return new Promise((resolve, reject) => {
      const transaction = database.transaction(active), store = transaction.objectStore(active);
      let matched = false;
      for (let i = 0; i < labels.length - 1; i++) {
        const request = store.getKey(labels.slice(i).join("."));
        request.onsuccess = () => { if (request.result !== undefined) matched = true; };
      }
      transaction.oncomplete = () => resolve(matched);
      transaction.onerror = transaction.onabort = () => reject(transaction.error || new Error("Lookup failed"));
    });
  }
  function refresh() {
    if (refreshPromise) return refreshPromise;
    refreshPromise = (async () => {
      const response = await fetch(CERT_POLSKA_URL, { credentials: "omit", redirect: "error", cache: "no-store",
        referrerPolicy: "no-referrer", signal: AbortSignal.timeout(30000) });
      if (!response.ok || !response.body) throw new Error("CERT Polska download failed");
      const reader = response.body.getReader(), chunks = [];
      let size = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > 8 * 1024 * 1024) { await reader.cancel(); throw new Error("CERT Polska list too large"); }
        chunks.push(value);
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
      const hosts = parse(new TextDecoder().decode(bytes));
      const next = await activeStore() === "a" ? "b" : "a", database = await open();
      await write(database, next, [], true);
      for (let i = 0; i < hosts.length; i += 2000) await write(database, next, hosts.slice(i, i + 2000));
      await chrome.storage.local.set({ certPolskaActive: next, certPolskaUpdated: Date.now() });
    })().catch(error => console.warn("CERT Polska refresh failed:", error.message))
      .finally(() => { refreshPromise = undefined; });
    return refreshPromise;
  }
  return { parse, contains, refresh };
})();
