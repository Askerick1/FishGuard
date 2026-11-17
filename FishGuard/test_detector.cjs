const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

const read = file => fs.readFileSync(path.join(__dirname, "extension", file), "utf8");
const context = vm.createContext({ URL });
vm.runInContext(read("domains.js") + "\n" + read("detector.js"), context);
const detector = vm.runInContext("PhishGuard", context);
const classify = raw => detector.evaluate(detector.parse(raw));

test("Azerbaijani bank names are blocked outside verified roots while official subdomains stay trusted", () => {
  for (const root of ["accessbank.az", "afb.az", "abb-bank.az", "ibar.az", "asb.az", "atb.az",
    "azerturkbank.az", "bankavrasiya.az", "bankofbaku.com", "bankrespublika.az", "premiumbank.az",
    "vtb.az", "expressbank.az", "xalqbank.az", "kapitalbank.az", "birbank.az", "birbank.business",
    "yelo.az", "pashabank.az", "rabitabank.com", "turanbank.az", "unibank.az", "yapikredi.com.az",
    "ziraatbank.az", "bmibaku.az", "cbar.az"]) {
    assert.equal(classify("https://login." + root + "/").status, "trusted", root);
  }
  for (const host of ["birbank.test", "birbnak.test", "kap1talbank.az", "kap1talbank.test",
    "kаpitalbank.test", "birbank.shared.test", "bir.bank.test", "bankofbaku.az", "bankeurasia.test", "btb.az",
    "afb-bank.test", "abb-bank.test", "btb-bank.test", "vtb-bank.test", "cbar-az.test"]) {
    assert.equal(classify("https://" + host).status, "blocked", host);
  }
  assert.equal(classify("https://accessbnak.test/").status, "suspicious");
  assert.equal(classify("https://accessbnak.test/verify").status, "blocked");
  for (const host of ["abb.test", "asb.test", "yelo.test", "mybirbankreview.test"]) {
    assert.notEqual(classify("https://" + host).status, "blocked", host);
  }
});

test("OpenPhish matches full canonical URLs, preserving path and query", () => {
  vm.runInContext(read("openphish.js"), context);
  const feed = vm.runInContext("OpenPhish", context);
  const urls = new Set(feed.parse("https://EXAMPLE.test:443/bad?q=1#fragment\nnot-a-url\n"));
  assert.ok(urls.has(feed.canonical("https://example.test/bad?q=1#other")));
  for (const raw of ["https://example.test/", "https://example.test/bad?q=2", "http://example.test/bad?q=1"]) {
    assert.equal(urls.has(feed.canonical(raw)), false);
  }
  assert.throws(() => feed.parse("not-a-url"));
});

test("trusted DNS label boundaries include official Google subdomains", () => {
  for (const host of ["google.com", "accounts.google.com", "docs.google.com", "GOOGLE.COM.",
    "a.b.c.accounts.google.com", "docs.google.az", "online.yapikredi.com.az", "id.login.gov.az"]) {
    assert.equal(classify("https://" + host + "/verify/login?password=secret#security").status, "trusted", host);
  }
  assert.equal(classify("https://notgoogle.com/").status, "clear");
  assert.equal(classify("https://google.company/").status, "suspicious");
});

test("strong impersonation signals block, weak signals do not", () => {
  for (const raw of [
    "https://google.com.security-check.xyz/",
    "https://google.com%2esecurity-check.xyz/",
    "https://google.com@neutral.test/",
    "https://paypal-login-verify.com/",
    "https://pаypal.com/",
    "https://%D1%80aypal.com/",
    "https://kap1talbank.az./",
  ]) {
    assert.equal(classify(raw).status, "blocked", raw);
  }
  assert.equal(classify("https://payapl.com/").status, "suspicious");
  assert.equal(classify("https://bücher.de/").status, "clear");
  assert.equal(classify("https://a.b.c.example.xyz/%76erify").status, "clear");
  assert.ok(classify("https://a.b.c.example.xyz/%76erify").reasons.includes("pathAction"));
  assert.ok(classify("http://2130706433/").reasons.includes("ip"));
  assert.ok(classify("http://[::1]/").reasons.includes("ip"));
  assert.equal(detector.parse("javascript:alert(1)"), null);
  assert.equal(detector.parse("http://["), null);
});

test("PayPal lookalikes are blocked regardless of test or com suffix", () => {
  for (const raw of ["https://paypa1.test/", "https://paypa1.com/", "https://www.paypa1.com/"]) {
    assert.equal(classify(raw).status, "blocked", raw);
  }
  assert.equal(classify("https://paypal.com/").status, "trusted");
  assert.equal(classify("https://www.paypal.com/").status, "trusted");
});

test("query and fragment have no effect and URL secrets stay out of verdicts", () => {
  const clean = classify("https://ordinary.test/");
  const sensitive = classify("https://ordinary.test/?token=secret#password");
  assert.deepEqual(sensitive, clean);
  assert.equal(JSON.stringify(classify("https://user:secret@ordinary.test/reset?token=secret")).includes("secret"), false);
});

test("bundled network rules match the local detector list", () => {
  const [rule] = JSON.parse(read("rules.json"));
  assert.deepEqual(rule.condition.requestDomains, Array.from(vm.runInContext("BUNDLED_BLOCKLIST", context)));
  assert.deepEqual(rule.condition.resourceTypes, ["main_frame", "sub_frame"]);
  assert.equal(rule.action.type, "block");
});

test("AMTSO launch page stays accessible and only the desktop test URL is blocked", () => {
  const rule = JSON.parse(read("rules.json")).find(candidate => candidate.id === 2);
  const networkMatch = new RegExp(rule.condition.regexFilter);
  for (const [raw, blocked] of [
    ["https://www.amtso.org/feature-settings-check-phishing-page/", false],
    ["https://www.amtso.org/check-desktop-phishing-page/", true],
    ["https://amtso.org./check-desktop-phishing-page?check=1", true],
    ["https://www.amtso.org/check-desktop-phishing-page/other", false],
    ["https://www.amtso.org.example/check-desktop-phishing-page/", false],
  ]) {
    assert.equal(networkMatch.test(raw), blocked, raw);
    assert.equal(classify(raw).reasons.includes("blocklist"), blocked, raw);
  }
});

test("independent signals and password form context increase protection", () => {
  assert.equal(classify("https://payapl.com/verify").status, "suspicious");
  assert.equal(classify("https://payapl.xyz/verify").status, "blocked");
  for (const [raw, expected] of [
    ["https://payapl.test/", "blocked"],
    ["https://accounts.google.com/signin", "trusted"],
    ["https://ordinary.test/login", "clear"],
  ]) {
    assert.equal(detector.evaluate(detector.parse(raw), undefined, true).status, expected);
  }
});

test("multi-character lookalikes and missing domain dots need corroborating risk", () => {
  for (const raw of ["https://arnazon.com/", "https://rnicrosoft.com/", "https://googlecom.test/"]) {
    assert.equal(classify(raw).status, "suspicious", raw);
  }
  assert.ok(classify("https://arnazon.com/").reasons.includes("visualTypo"));
  assert.ok(classify("https://googlecom.test/").reasons.includes("missingDot"));
  assert.equal(classify("https://arnazon.xyz/verify").status, "blocked");
  assert.equal(detector.evaluate(detector.parse("https://googlecom.test/"), undefined, true).status, "blocked");
  for (const raw of ["https://amazon.com/", "https://microsoft.com/", "https://google.com/",
    "https://googlecommerce.example/", "https://garnazon.example/", "https://bücher.de/"]) {
    assert.notEqual(classify(raw).status, "blocked", raw);
  }
});

test("credential form checks combine page signals and detect HTTPS downgrade", () => {
  const risk = (page, destination, title) => detector.credentialRisk(
    detector.parse(page), detector.parse(destination), title);
  assert.equal(risk("https://ordinary.test/", "http://ordinary.test/login", "Login").reason, "insecureForm");
  assert.equal(risk("https://google.ordinary.test/", "https://google.ordinary.test/", "Google account sign in").reason, "brandForm");
  assert.equal(risk("https://google.ordinary.test/", "https://google.ordinary.test/", "Article about Google"), null);
  assert.equal(risk("https://ordinary.test/", "https://ordinary.test/", "Google account sign in"), null);
  assert.equal(risk("https://accounts.google.com/", "https://accounts.google.com/", "Google account sign in"), null);
  assert.equal(risk("https://ordinary.test/", "https://paypal-login-verify.com/", "Login").reason, "riskyForm");
});
