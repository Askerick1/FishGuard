// Offline evaluation of the extension's URL heuristics; no browsing or feed lookups.
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const file = process.argv[2];
if (!file) {
  console.error("Usage: node benchmark_detector.cjs <labeled-urls.json>");
  process.exit(1);
}
const rows = JSON.parse(fs.readFileSync(file, "utf8"));
if (!Array.isArray(rows) || !rows.length) throw new Error("Expected a nonempty JSON array");
const context = vm.createContext({ URL });
for (const name of ["domains.js", "detector.js"]) {
  vm.runInContext(fs.readFileSync(path.join(__dirname, "extension", name), "utf8"), context);
}
const detector = vm.runInContext("PhishGuard", context);
const counts = { phishing: { total: 0, blocked: 0, suspicious: 0 },
  legitimate: { total: 0, blocked: 0, suspicious: 0 } };
for (const row of rows) {
  if (!row || !Object.hasOwn(counts, row.label) || typeof row.url !== "string") {
    throw new Error("Each row requires url and label (phishing or legitimate)");
  }
  const url = detector.parse(row.url);
  if (!url) throw new Error("Invalid HTTP(S) URL in input");
  const result = detector.evaluate(url);
  const group = counts[row.label];
  group.total++;
  if (result.status === "blocked" || result.status === "suspicious") group[result.status]++;
}
for (const [label, group] of Object.entries(counts)) {
  const percent = n => group.total ? (100 * n / group.total).toFixed(1) + "%" : "n/a";
  console.log(`${label}: ${group.total} URLs; blocked ${group.blocked} (${percent(group.blocked)}); ` +
    `suspicious ${group.suspicious} (${percent(group.suspicious)})`);
}
console.log("URL heuristics only; excludes feeds, forms and browser navigation. " +
  "Metrics depend on the supplied labels and sample.");
