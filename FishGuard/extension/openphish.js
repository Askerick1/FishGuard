// Change to true only after reviewing the OpenPhish terms in README.md.
const OPENPHISH_ENABLED = true;
const OPENPHISH_FEED = "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt";

const OpenPhish = (() => {
  function canonical(raw) {
    if (typeof raw !== "string" || raw.length > 4096) return null;
    try {
      const url = new URL(raw);
      if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) return null;
      url.hash = "";
      return url.href;
    } catch { return null; }
  }

  function parse(text) {
    const urls = new Set();
    for (const line of text.split(/\r?\n/)) {
      const value = canonical(line.trim());
      if (value) urls.add(value);
    }
    if (!urls.size || urls.size > 50000) throw new Error("Invalid OpenPhish feed");
    return [...urls];
  }
  return { canonical, parse };
})();
