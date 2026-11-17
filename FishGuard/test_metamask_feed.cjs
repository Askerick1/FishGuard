const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

test("MetaMask feed matches domain boundaries, respects exceptions and retains successful snapshot", async () => {
  const settings = {};
  let config = { blacklist: ["bad.example.test", "shared.test"], whitelist: ["safe.shared.test"] };
  let fail = false;
  const context = vm.createContext({ URL, TextDecoder, Uint8Array, AbortSignal, console: { warn() {} },
    chrome: { storage: { local: { get: async key => ({ [key]: settings[key] }),
      set: async values => Object.assign(settings, values) } } },
    fetch: async () => {
      if (fail) throw new Error("offline");
      const chunks = [new TextEncoder().encode(JSON.stringify(config))];
      return { ok: true, body: { getReader: () => ({ read: async () => chunks.length ?
        { done: false, value: chunks.shift() } : { done: true } }) } };
    },
  });
  const read = name => fs.readFileSync(path.join(__dirname, "extension", name), "utf8");
  vm.runInContext(read("domains.js") + "\n" + read("detector.js") + "\n" + read("metamask-feed.js"), context);
  const service = vm.runInContext("MetaMaskFeed", context);
  await service.refresh();
  assert.equal(await service.contains("https://bad.example.test/"), true);
  assert.equal(await service.contains("https://sub.bad.example.test/"), true);
  assert.equal(await service.contains("https://example.test/"), false);
  assert.equal(await service.contains("https://notbad.example.test/"), false);
  assert.equal(await service.contains("https://safe.shared.test/"), false);
  assert.equal(await service.contains("https://unsafe.shared.test/"), true);
  fail = true;
  await service.refresh();
  assert.equal(await service.contains("https://bad.example.test/"), true);
  fail = false;
  config = { blacklist: ["new.test"], whitelist: [] };
  await service.refresh();
  assert.equal(await service.contains("https://bad.example.test/"), false);
  assert.equal(await service.contains("https://new.test/"), true);
  assert.throws(() => service.parse('{"blacklist":[],"whitelist":[]}'));
});
