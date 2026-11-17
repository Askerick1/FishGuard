const PhishGuard = (() => {
  const brands = [...new Set(TRUSTED_ROOTS.map(root => root.split(".")[0]))]
    .filter(brand => !["login", "digital", "edu", "justice", "customs", "sosial"].includes(brand))
    .sort((a, b) => b.length - a.length);
  const compoundSuffixes = new Set(["com.az", "gov.az", "edu.az", "net.az", "org.az",
    "co.uk", "org.uk", "com.au", "com.tr", "co.jp", "co.in", "com.br"]);
  const riskySuffixes = new Set(["xyz", "top", "buzz", "click", "cfd", "sbs", "icu", "tk", "site"]);
  const bankNames = new Set(AZ_BANK_ROOTS.map(root => root.split(".")[0]).filter(name => name.length > 4)
    .map(name => name.replaceAll("-", "")).concat([
      "afbbank", "abbbank", "asbbank", "azerbaycansenayebanki", "atbbank", "bankeurasia", "bankbtb", "btbbank",
      "bankvtb", "vtbbank", "yelobank", "yapikredibank", "bankmelliiran", "mellibank", "centralbankazerbaijan",
    ]));
  const shortBankNames = new Set(["afb", "abb", "iba", "ibar", "asb", "atb", "btb", "vtb", "yelo", "cbar"]);
  const allBankNames = [...bankNames, ...shortBankNames];
  const longBankNames = [...bankNames].filter(name => name.length >= 7);
  const priorityBankNames = ["birbank", "kapitalbank"];
  const bankCountry = /^(?:az|azerbaijan|azerbaycan)$/;
  const actionWords = /(?:^|[^\p{L}\p{N}])(?:login|signin|verify|verification|secure|security|accounts?|password|wallet|billing|recovery|update|auth|support|tracking|giris|hesab|odenis|tesdiq|parol|kargo|odeme|tehlukesizlik)(?=$|[^\p{L}\p{N}])/iu;
  const confusables = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y",
    "і": "i", "ӏ": "l", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "к": "k",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ε": "e", "ι": "i", "ı": "i",
  };
  const isUnder = (host, root) => host === root || host.endsWith("." + root);
  const isTrusted = host => TRUSTED_ROOTS.some(root => isUnder(host, root));

  function parse(raw) {
    try {
      const url = new URL(raw);
      if ((url.protocol === "https:" || url.protocol === "http:") &&
          url.hostname.length <= 254) return url;
    } catch {
      // The browser parser rejects malformed network URLs.
    }
    return null;
  }

  // Decode browser-normalized A-labels using the RFC 3492 bias adaptation.
  // This is used for comparison only. The ASCII hostname is shown to users.
  function decodeLabel(label) {
    if (!label.startsWith("xn--")) return label;
    const encoded = label.slice(4);
    const delimiter = encoded.lastIndexOf("-");
    const output = [...encoded.slice(0, Math.max(0, delimiter))].map(c => c.codePointAt(0));
    let point = 128, index = 0, bias = 72;
    for (let cursor = delimiter + 1; cursor < encoded.length;) {
      const previous = index;
      let weight = 1;
      for (let base = 36; ; base += 36) {
        const character = encoded.charCodeAt(cursor++);
        const digit = character >= 97 && character <= 122 ? character - 97 : character - 22;
        const threshold = Math.max(1, Math.min(26, base - bias));
        if (!Number.isInteger(digit) || digit < 0 || digit >= 36) return label;
        index += digit * weight;
        if (index > 0x7fffffff) return label;
        if (digit < threshold) break;
        weight *= 36 - threshold;
        if (weight > 0x7fffffff) return label;
      }
      const length = output.length + 1;
      let delta = Math.floor((index - previous) / (previous === 0 ? 700 : 2));
      delta += Math.floor(delta / length);
      bias = 0;
      while (delta > 455) {
        delta = Math.floor(delta / 35);
        bias += 36;
      }
      bias += Math.floor(36 * delta / (delta + 38));
      point += Math.floor(index / length);
      index %= length;
      if (point > 0x10ffff) return label;
      output.splice(index++, 0, point);
    }
    return String.fromCodePoint(...output);
  }

  function skeleton(label) {
    return [...label.normalize("NFKD").replace(/\p{M}|-/gu, "")]
      .map(character => confusables[character] || character).join("");
  }

  // Checks edit distance <= 1, including a single adjacent transposition.
  function oneEdit(a, b) {
    if (a === b || Math.abs(a.length - b.length) > 1) return false;
    if (a.length > b.length) [a, b] = [b, a];
    let i = 0;
    while (i < a.length && a[i] === b[i]) i++;
    if (a.length < b.length) return a.slice(i) === b.slice(i + 1);
    return a.slice(i + 1) === b.slice(i + 1) ||
      (a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2));
  }

  // One visual substitution involving multiple characters (e.g. rn for m).
  // Require an otherwise exact match; short brand names are too ambiguous.
  function visualPair(label, brand) {
    if (brand.length < 6) return false;
    for (const [from, to] of [["rn", "m"], ["vv", "w"], ["cl", "d"]]) {
      for (let i = label.indexOf(from); i !== -1; i = label.indexOf(from, i + 1)) {
        if (label.slice(0, i) + to + label.slice(i + from.length) === brand) return true;
      }
    }
    return false;
  }

  function bankRisk(labels, registrant, suffixLength, hasAction, pathAction) {
    const tld = labels.at(-1);
    const names = labels.slice(0, -suffixLength);
    // Compare DNS labels, including tenant labels on shared hosting.
    for (const [i, label] of names.entries()) {
      if (i > 0 && bankNames.has(skeleton(names[i - 1] + label))) return "bankImpersonation";
      const forms = new Set([skeleton(label), skeleton(label.replaceAll("1", "i"))]);
      for (const form of forms) {
        if (bankNames.has(form)) return "bankImpersonation";
        if (shortBankNames.has(form) && (tld === "az" || hasAction || pathAction)) return "bankImpersonation";
        for (const name of allBankNames) {
          const extra = form.startsWith(name) ? form.slice(name.length) :
            form.endsWith(name) ? form.slice(0, -name.length) : "";
          if (extra && (bankCountry.test(extra) || actionWords.test(extra))) return "bankImpersonation";
        }
        if (priorityBankNames.some(name => oneEdit(form, name) || visualPair(form, name))) {
          return "bankImpersonation";
        }
      }
    }
    const normalized = skeleton(registrant);
    const close = longBankNames.some(name => oneEdit(normalized, name) || visualPair(normalized, name));
    if (close) return tld === "az" || hasAction || pathAction ? "bankImpersonation" : "bankLookalike";
    return null;
  }

  function evaluate(url, blocklist = BUNDLED_BLOCKLIST, credentialForm = false) {
    const host = url.hostname.replace(/\.$/, "");
    const result = (status, score, reasons) => ({ host, status, score, reasons });
    // AMTSO publishes a harmless, URL-specific desktop test. Keep in sync with rules.json.
    if ((host === "amtso.org" || host === "www.amtso.org") &&
        /^\/check-desktop-phishing-page\/?$/.test(url.pathname)) {
      return result("blocked", 100, ["blocklist"]);
    }
    if (blocklist.some(root => isUnder(host, root))) return result("blocked", 100, ["blocklist"]);
    if (isTrusted(host)) return result("trusted", 0, []);

    const labels = host.split(".");
    const tld = labels.at(-1);
    const suffixLength = compoundSuffixes.has(labels.slice(-2).join(".")) ? 2 : 1;
    const registrant = labels.at(-(suffixLength + 1)) || "";
    const subdomains = labels.slice(0, -(suffixLength + 1));
    const unicodeLabels = labels.map(decodeLabel);
    const unicodeRegistrant = decodeLabel(registrant);
    const normalized = skeleton(unicodeRegistrant);
    const idn = labels.some(label => label.startsWith("xn--"));
    const userInfo = url.username !== "" || url.password !== "";
    let path = url.pathname.slice(0, 2048);
    try { path = decodeURIComponent(path); } catch { /* Keep the encoded path. */ }
    const hostAction = actionWords.test(unicodeLabels.join("."));
    const pathAction = actionWords.test(path);
    const banking = bankRisk(unicodeLabels, unicodeRegistrant, suffixLength, hostAction, pathAction);
    const reasons = [];
    let score = 0;
    function add(weight, reason) {
      score += weight;
      reasons.push(reason);
    }

    // Trust uses exact DNS label boundaries. The suffix hints above only
    // select which label to compare for typo scoring.
    const embeddedRoot = TRUSTED_ROOTS.some(root => ("." + host + ".").includes("." + root + "."));
    const homograph = brands.find(brand => brand.length >= 4 &&
      (normalized === brand || normalized.replaceAll("l", "i") === brand) &&
      (idn || registrant !== brand));
    const combo = brands.find(brand => {
      if (brand.length < 3 || registrant === brand) return false;
      if (hostAction && ("-" + registrant + "-").includes("-" + brand + "-")) return true;
      if (brand.length < 5) return false;
      return (normalized.startsWith(brand) && actionWords.test(normalized.slice(brand.length))) ||
        (normalized.endsWith(brand) && actionWords.test(normalized.slice(0, -brand.length)));
    });
    const exactBrand = brands.find(brand => brand.length >= 4 && registrant === brand);
    const typo = brands.find(brand => brand.length >= 5 &&
      (oneEdit(registrant.replaceAll("-", ""), brand) || oneEdit(normalized, brand)));
    const visualTypo = brands.find(brand => visualPair(normalized, brand));
    const missingDot = TRUSTED_ROOTS.some(root => root.split(".")[0].length >= 5 &&
      registrant === root.replaceAll(".", ""));
    const brandSubdomain = subdomains.some(label => brands.includes(skeleton(decodeLabel(label))));

    // Brand signals overlap. Apply only the strongest one.
    if (embeddedRoot) add(100, "embeddedRoot");
    else if (banking === "bankImpersonation") add(75, banking);
    else if (homograph) add(idn ? 95 : 77, "lookalike");
    else if (combo) add(83, "combo");
    else if (exactBrand) add(62, "brand");
    else if (typo) add(45, "typo");
    else if (visualTypo) add(45, "visualTypo");
    else if (missingDot) add(45, "missingDot");
    else if (banking) add(45, banking);
    else if (brandSubdomain) add(38, "brand");

    if (userInfo) {
      const username = url.username.toLowerCase().replace(/\.$/, "");
      add(isTrusted(username) ? 85 : 45, "credentials");
    }
    if (idn && unicodeLabels.some(label => /\p{Script=Latin}/u.test(label) &&
      /\p{Script=Cyrillic}|\p{Script=Greek}/u.test(label))) add(20, "mixedScript");
    if (/^\[|^\d+\.\d+\.\d+\.\d+$/.test(host)) add(22, "ip");
    if (riskySuffixes.has(tld)) add(10, "suffix");
    if (subdomains.length >= 3) add(8, "depth");
    if (hostAction) add(19, "hostAction");
    if (pathAction) add(hostAction ? 7 : 11, "pathAction");
    // A password form alone is normal. It reinforces an already risky URL.
    if (credentialForm && score >= 40) score += 25;
    score = Math.min(score, 100);
    return result(score >= 65 ? "blocked" : score >= 45 ? "suspicious" : "clear", score, reasons);
  }

  // Page titles are untrusted and can mention a brand for innocent reasons.
  // Use them only to reinforce an already suspicious password form.
  function credentialRisk(page, destination, title = "") {
    if (!page || !destination) return null;
    if (page.protocol === "https:" && destination.protocol === "http:") {
      return { host: destination.hostname, reason: "insecureForm" };
    }
    for (const url of [page, destination]) {
      if (evaluate(url, BUNDLED_BLOCKLIST, true).status === "blocked") {
        return { host: url.hostname, reason: "riskyForm" };
      }
    }
    const verdict = evaluate(page);
    if (verdict.status === "trusted" || verdict.score < 30) return null;
    const words = String(title).slice(0, 300).toLowerCase().split(/[^\p{L}\p{N}]+/u);
    const claimsBrand = brands.some(brand => brand.length >= 5 && words.includes(brand));
    if (claimsBrand && words.some(word => /^(login|signin|sign|verify|verification|account|accounts|giris|hesab|daxil)$/.test(word))) {
      return { host: page.hostname, reason: "brandForm" };
    }
    return null;
  }

  return { parse, evaluate, credentialRisk, isUnder, isTrusted };
})();
