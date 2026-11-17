const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

test("feed import stages a snapshot and preserves it after a failed update", async () => {
  const stores = { a: new Map(), b: new Map() }, settings = {};
  let feed = "https://shared.test/bad?q=1\nhttps://other.test/login\n", fail = false;
  const database = {
    createObjectStore() {},
    transaction(name) {
      const transaction = { objectStore: () => ({
        clear: () => stores[name].clear(),
        put: (value, key) => stores[name].set(key, value),
        getKey: key => { const req = {}; setImmediate(() => {
          req.result = stores[name].has(key) ? key : undefined; req.onsuccess();
        }); return req; },
      }) };
      setImmediate(() => transaction.oncomplete?.());
      return transaction;
    },
  };
  const context = vm.createContext({ URL, TextDecoder, AbortSignal,
    console: { warn() {} },
    chrome: { storage: { local: {
      get: async key => ({ [key]: settings[key] }),
      set: async values => Object.assign(settings, values),
    } } },
    indexedDB: { open() { const req = {}; setImmediate(() => {
      req.result = database; req.onupgradeneeded(); req.onsuccess();
    }); return req; } },
    fetch: async () => {
      if (fail) throw new Error("offline");
      const chunks = [new TextEncoder().encode(feed.slice(0, 23)), new TextEncoder().encode(feed.slice(23))];
      return { ok: true, body: { getReader: () => ({ read: async () => chunks.length ?
        { done: false, value: chunks.shift() } : { done: true } }) } };
    },
  });
  const read = name => fs.readFileSync(path.join(__dirname, "extension", name), "utf8");
  vm.runInContext(read("openphish.js") + "\n" + read("phishing-database.js"), context);
  const service = vm.runInContext("PhishingDatabase", context);
  await service.refresh();
  assert.equal(await service.contains("https://shared.test/bad?q=1#x"), true);
  assert.equal(await service.contains("https://shared.test/bad?q=2"), false);
  assert.equal(await service.contains("https://shared.test/"), false);
  const active = settings.phishingDatabaseActive;
  fail = true;
  await service.refresh();
  assert.equal(settings.phishingDatabaseActive, active);
  assert.equal(await service.contains("https://other.test/login"), true);
  fail = false;
  feed = "https://new.test/\n";
  await service.refresh();
  assert.notEqual(settings.phishingDatabaseActive, active);
  assert.equal(await service.contains("https://new.test/"), true);
  assert.equal(await service.contains("https://other.test/login"), false);
});
