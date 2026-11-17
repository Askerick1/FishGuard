const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

test("CERT Polska matches listed domains and subdomains and replaces removed entries", async () => {
  const stores = { a: new Map(), b: new Map() }, settings = {};
  let feed = "bad.example.test\nother.test\n", fail = false;
  const database = { createObjectStore() {}, transaction(name) {
    const transaction = { objectStore: () => ({ clear: () => stores[name].clear(),
      put: (value, key) => stores[name].set(key, value),
      getKey: key => { const req = {}; queueMicrotask(() => {
        req.result = stores[name].has(key) ? key : undefined; req.onsuccess();
      }); return req; },
    }) };
    setImmediate(() => transaction.oncomplete?.());
    return transaction;
  } };
  const context = vm.createContext({ URL, TextDecoder, Uint8Array, AbortSignal, console: { warn() {} },
    chrome: { storage: { local: { get: async key => ({ [key]: settings[key] }),
      set: async values => Object.assign(settings, values) } } },
    indexedDB: { open() { const req = {}; setImmediate(() => {
      req.result = database; req.onupgradeneeded(); req.onsuccess();
    }); return req; } },
    fetch: async () => {
      if (fail) throw new Error("offline");
      const chunks = [new TextEncoder().encode(feed)];
      return { ok: true, body: { getReader: () => ({ read: async () => chunks.length ?
        { done: false, value: chunks.shift() } : { done: true } }) } };
    },
  });
  const read = name => fs.readFileSync(path.join(__dirname, "extension", name), "utf8");
  vm.runInContext(read("domains.js") + "\n" + read("detector.js") + "\n" + read("cert-polska.js"), context);
  const service = vm.runInContext("CertPolska", context);
  await service.refresh();
  assert.equal(await service.contains("https://BAD.example.test/path"), true);
  assert.equal(await service.contains("https://sub.bad.example.test/"), true);
  assert.equal(await service.contains("https://example.test/"), false);
  assert.equal(await service.contains("https://notbad.example.test/"), false);
  fail = true;
  await service.refresh();
  assert.equal(await service.contains("https://other.test/"), true);
  fail = false;
  feed = "new.test\n";
  await service.refresh();
  assert.equal(await service.contains("https://other.test/"), false);
  assert.equal(await service.contains("https://new.test/"), true);
  assert.throws(() => service.parse("bad domain\n"));
});
