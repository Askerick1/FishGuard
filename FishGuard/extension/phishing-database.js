// Phishing.Database contributors, MIT license; see THIRD_PARTY_NOTICES.md.
const PHISHING_DATABASE_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt";
const PhishingDatabase = (() => {
  let dbPromise, refreshPromise;
  function db() {
    if (!dbPromise) dbPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open("phishing-database", 1);
      request.onupgradeneeded = () => {
        request.result.createObjectStore("a");
        request.result.createObjectStore("b");
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    }).catch(error => { dbPromise = undefined; throw error; });
    return dbPromise;
  }
  async function activeStore() {
    const { phishingDatabaseActive } = await chrome.storage.local.get("phishingDatabaseActive");
    return phishingDatabaseActive === "a" || phishingDatabaseActive === "b" ? phishingDatabaseActive : null;
  }
  async function contains(raw) {
    const key = OpenPhish.canonical(raw);
    if (!key) return false;
    const active = await activeStore();
    if (!active) return false;
    const database = await db();
    return new Promise((resolve, reject) => {
      const request = database.transaction(active).objectStore(active).getKey(key);
      request.onsuccess = () => resolve(request.result !== undefined);
      request.onerror = () => reject(request.error);
    });
  }
  function write(database, store, urls, clear = false) {
    return new Promise((resolve, reject) => {
      const transaction = database.transaction(store, "readwrite");
      const target = transaction.objectStore(store);
      if (clear) target.clear();
      for (const url of urls) target.put(1, url);
      transaction.oncomplete = resolve;
      transaction.onerror = transaction.onabort = () => reject(transaction.error || new Error("Database write failed"));
    });
  }
  function refresh() {
    if (refreshPromise) return refreshPromise;
    refreshPromise = (async () => {
      const response = await fetch(PHISHING_DATABASE_URL, { credentials: "omit", redirect: "error",
        cache: "no-store", referrerPolicy: "no-referrer", signal: AbortSignal.timeout(300000) });
      if (!response.ok || !response.body) throw new Error("Phishing.Database download failed");
      const active = await activeStore();
      const next = active === "a" ? "b" : "a";
      const database = await db();
      await write(database, next, [], true);
      const reader = response.body.getReader(), decoder = new TextDecoder();
      let carry = "", size = 0, count = 0, batch = [];
      async function addLine(line) {
        const url = OpenPhish.canonical(line.trim());
        if (url) { batch.push(url); count++; }
        if (batch.length >= 2000) { await write(database, next, batch); batch = []; }
      }
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > 128 * 1024 * 1024) { await reader.cancel(); throw new Error("Feed too large"); }
        const lines = (carry + decoder.decode(value, { stream: true })).split("\n");
        carry = lines.pop();
        if (carry.length > 8192) throw new Error("Invalid feed line");
        for (const line of lines) await addLine(line);
      }
      await addLine(carry + decoder.decode());
      if (batch.length) await write(database, next, batch);
      if (!count) throw new Error("Empty phishing feed");
      await chrome.storage.local.set({ phishingDatabaseActive: next, phishingDatabaseUpdated: Date.now() });
    })().catch(error => console.warn("Phishing.Database refresh failed:", error.message))
      .finally(() => { refreshPromise = undefined; });
    return refreshPromise;
  }
  return { contains, refresh };
})();
