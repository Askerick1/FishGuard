const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

async function popup(feed) {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, { dataset: {}, addEventListener() {} });
    return elements.get(id);
  };
  const chrome = {
    storage: { local: { get: async () => ({ phishguard_lang: "en" }) } },
    tabs: { query: async () => [{ id: 1, url: "https://example.test/" }] },
    declarativeNetRequest: { getDynamicRules: async () => [] },
    runtime: { getURL: name => `chrome-extension://id/${name}`,
      sendMessage: async () => { if (feed instanceof Error) throw feed; return feed; } },
  };
  const context = vm.createContext({ URL, chrome, document: { getElementById: element }, window: {} });
  const read = file => fs.readFileSync(path.join(__dirname, "extension", file), "utf8");
  vm.runInContext(["domains.js", "detector.js", "popup.js"].map(read).join("\n"), context);
  await new Promise(resolve => setImmediate(resolve));
  return { status: element("main-card").dataset.status, title: element("status-title").textContent };
}

test("popup reflects feed matches and does not claim a clean result if the check fails", async () => {
  assert.deepEqual(await popup({ ok: true, listed: true }), { status: "blocked", title: "Threat Detected!" });
  assert.deepEqual(await popup({ ok: true, listed: false }), { status: "clear", title: "No threat detected" });
  assert.deepEqual(await popup(new Error("worker unavailable")), { status: "unknown", title: "Not checked" });
});
