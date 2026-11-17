const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

test("hover and click use the updated URL-specific feed", async () => {
  const listeners = {}, storageListeners = [];
  let indicator, prevented = false, warningRequest;
  class Element {
    constructor(href) { this.href = href; this.baseURI = "https://page.test/"; this.isConnected = true; }
    matches() { return Boolean(this.href); }
    getAttribute(name) { return name === "href" ? this.href : null; }
    contains(other) { return this === other; }
    getBoundingClientRect() { return { right: 100, top: 30 }; }
    setAttribute(name, value) { this[name] = value; }
    remove() { indicator = null; }
  }
  const window = { innerWidth: 800, innerHeight: 600, alert() {},
    addEventListener(name, handler) { listeners[name] = handler; } };
  window.top = window;
  const document = { title: "", createElement: () => { const el = new Element(); el.style = {}; return el; },
    documentElement: { appendChild(el) { indicator = el; } } };
  const context = vm.createContext({ URL, window, document, Element,
    HTMLFormElement: class {}, HTMLInputElement: class {}, location: { href: "https://page.test/" },
    chrome: { runtime: { sendMessage: async request => { warningRequest = request; return { ok: true }; } },
      i18n: { getUILanguage: () => "en" }, storage: {
      local: { get: async () => ({ openPhishSnapshot: ["https://shared.test/bad?q=1"] }) },
      onChanged: { addListener(fn) { storageListeners.push(fn); } },
    } } });
  const read = name => fs.readFileSync(path.join(__dirname, "extension", name), "utf8");
  vm.runInContext(read("domains.js") + "\n" + read("detector.js") + "\n" +
    read("openphish.js").replace("const OPENPHISH_ENABLED = false", "const OPENPHISH_ENABLED = true") +
    "\n" + read("links.js"), context);
  await new Promise(resolve => setImmediate(resolve));
  const link = new Element("https://shared.test/bad?q=1");
  const event = { isTrusted: true, type: "click", composedPath: () => [link],
    preventDefault() { prevented = true; }, stopImmediatePropagation() {} };
  listeners.pointerover(event);
  assert.equal(indicator?.textContent, "!");
  assert.equal(indicator?.["aria-label"], "Dangerous link");
  listeners.click(event);
  assert.equal(prevented, true);
  assert.equal(warningRequest.action, "warn-link");
  assert.equal(warningRequest.url, "https://shared.test/bad?q=1");
  assert.equal(warningRequest.newTab, false);
  listeners.auxclick({ ...event, type: "auxclick", button: 1 });
  assert.equal(warningRequest.newTab, true);
  storageListeners[0]({ openPhishSnapshot: { newValue: ["https://shared.test/other"] } }, "local");
  assert.equal(indicator, null);
  prevented = false;
  listeners.click(event);
  assert.equal(prevented, false);
});

test("sensitive form metadata is checked without reading values", () => {
  const listeners = {};
  class Input {
    constructor(attrs, type = "text") { this.attrs = attrs; this.type = type; this.labels = []; }
    getAttribute(name) { return this.attrs[name] || null; }
    matches() { return false; }
    get value() { throw new Error("field values must not be read"); }
  }
  class Form { constructor(field) { this.elements = [field]; this.action = "https://payapl.test/"; } }
  const window = { addEventListener(name, fn) { listeners[name] = fn; }, alert() {} };
  window.top = window;
  const context = vm.createContext({ URL, window, document: { title: "" }, Element: class {},
    HTMLFormElement: Form, HTMLInputElement: Input, location: { href: "https://payapl.test/" },
    chrome: { i18n: { getUILanguage: () => "en" }, storage: {
      local: { get: async () => ({}) }, onChanged: { addListener() {} } } } });
  const read = name => fs.readFileSync(path.join(__dirname, "extension", name), "utf8");
  vm.runInContext(["domains.js", "detector.js", "openphish.js", "links.js"].map(read).join("\n"), context);
  function submit(field) {
    let stopped = false;
    listeners.submit({ isTrusted: true, target: new Form(field),
      preventDefault() { stopped = true; }, stopImmediatePropagation() {} });
    return stopped;
  }
  assert.equal(submit(new Input({ autocomplete: "cc-number" })), true);
  assert.equal(submit(new Input({ name: "cvv" })), true);
  assert.equal(submit(new Input({ autocomplete: "one-time-code" })), true);
  assert.equal(submit(new Input({ name: "cardboard" })), false);
  context.location.href = "https://shop.example/";
  const field = new Input({ autocomplete: "cc-number" });
  let stopped = false;
  const form = new Form(field); form.action = "https://payments.example/";
  listeners.submit({ isTrusted: true, target: form, preventDefault() { stopped = true; }, stopImmediatePropagation() {} });
  assert.equal(stopped, false);
});
