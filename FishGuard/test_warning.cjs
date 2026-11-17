const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

test("link warning is rechecked and opens the existing page in the correct tab", async () => {
  let messageHandler, committed, update, created, retryRule, report;
  const event = () => ({ addListener() {} });
  const chrome = {
    runtime: { id: "extension", getURL: file => "chrome-extension://extension/" + file,
      onInstalled: event(), onStartup: event(), onMessage: { addListener(fn) { messageHandler = fn; } } },
    alarms: { onAlarm: event() },
    webNavigation: { onBeforeNavigate: event(), onCommitted: { addListener(fn) { committed = fn; } }, onHistoryStateUpdated: event(),
      onErrorOccurred: event(), getFrame: async () => ({ documentId: "doc", documentLifecycle: "active" }) },
    tabs: { onRemoved: event(), get: async id => ({ id, active: true, url: "https://feed.test/path" }),
      create: async options => { created = options; return { id: 9 }; },
      update: async (id, options) => { update = { id, ...options }; } },
    action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {} },
    storage: { local: { get: async () => ({ openPhishSnapshot: ["https://feed.test/path"] }), set: async () => {} } },
    declarativeNetRequest: { getSessionRules: async () => [],
      updateSessionRules: async ({ addRules }) => { retryRule = addRules?.[0]; } },
  };
  const context = vm.createContext({ URL, URLSearchParams, chrome, console, crypto: { randomUUID: () => "id" },
    setTimeout() {}, AbortSignal, fetch: async (url, options) => {
      report = { url, body: JSON.parse(options.body) }; return { ok: true, json: async () => ({}) };
    } });
  context.importScripts = (...files) => files.forEach(file => vm.runInContext(
    fs.readFileSync(path.join(__dirname, "extension", file), "utf8")
      .replace("const OPENPHISH_ENABLED = false", "const OPENPHISH_ENABLED = true"), context));
  vm.runInContext(fs.readFileSync(path.join(__dirname, "extension", "background.js"), "utf8"), context);
  const sender = { id: "extension", tab: { id: 1, windowId: 2, index: 0 }, frameId: 0,
    documentId: "doc", url: "https://page.test/" };
  const send = (request, source = sender) => new Promise(resolve => {
    const async = messageHandler(request, source, resolve);
    if (!async) resolve(undefined);
  });
  const popup = { ...sender, url: "chrome-extension://extension/popup.html" };
  assert.equal((await send({ action: "popup-feed-check", tabId: 1 }, popup)).listed, true);
  assert.equal(await send({ action: "popup-feed-check", tabId: 1 }, sender), undefined);
  assert.equal((await send({ action: "warn-link", url: "https://paypal-login-verify.com/", newTab: false })).ok, true);
  assert.equal(update.id, 1);
  assert.ok(update.url.startsWith("chrome-extension://extension/blocked.html?"));
  assert.equal(new URL(update.url).searchParams.get("host"), "paypal-login-verify.com");
  assert.equal(new URL(update.url).searchParams.get("back"), "previous");
  assert.equal((await send({ action: "warn-link", url: "https://paypal-login-verify.com/", newTab: true })).ok, true);
  assert.equal(created.openerTabId, 1);
  assert.equal(update.id, 9);
  assert.equal(new URL(update.url).searchParams.get("back"), "close");
  assert.equal((await send({ action: "warn-link", url: "https://ordinary.test/", newTab: false })).ok, false);

  const target = "https://www.amtso.org/check-desktop-phishing-page/?test=x+y#demo";
  assert.equal((await send({ action: "warn-link", url: target, newTab: false })).ok, true);
  const warning = { ...sender, url: update.url };
  const params = new URL(warning.url).searchParams;
  assert.equal(params.get("reasons"), "blocklist");
  assert.equal((await send({ action: "report-false-positive", id: "wrong" }, warning)).ok, false);
  assert.equal((await send({ action: "report-false-positive", id: params.get("id") }, warning)).ok, true);
  assert.equal(report.body.category, "false_positive");
  assert.equal(report.body.url, "https://www.amtso.org");
  assert.equal((await send({ action: "proceed", id: params.get("id") }, warning)).ok, true);
  assert.equal(update.url, target);
  assert.equal(retryRule.action.type, "allow");
  assert.equal(retryRule.condition.tabIds.join(","), "1");
  assert.equal(retryRule.condition.resourceTypes.join(","), "main_frame");
  const matches = new RegExp(retryRule.condition.regexFilter);
  assert.equal(matches.test(target.split("#")[0]), true);
  assert.equal(matches.test(target.split("?")[0]), false);
  assert.equal((await send({ action: "proceed", id: params.get("id") }, warning)).ok, false);
  committed({ tabId: 1, url: target, frameId: 0, documentLifecycle: "active", documentId: "next" });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(retryRule, undefined);
  assert.equal(update.url, target);
});
