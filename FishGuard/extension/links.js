(() => {
  const previews = new WeakMap();
  let feedUrls = new Set();
  let feedVersion = 0;
  let hoveredLink = null;
  let indicator;
  let databaseResults = new Map();
  const messages = {
    az: "FishGuard bu şübhəli keçidi blokladı",
    en: "FishGuard blocked this suspicious link",
    ru: "FishGuard заблокировал подозрительную ссылку",
  };
  const dangerLabels = { az: "Təhlükəli keçid", en: "Dangerous link", ru: "Опасная ссылка" };
  const formMessages = {
    az: "FishGuard şübhəli formanın göndərilməsini dayandırdı",
    en: "FishGuard stopped a suspicious form submission",
    ru: "FishGuard остановил отправку подозрительной формы",
  };

  function setFeed(snapshot) {
    feedUrls = new Set(Array.isArray(snapshot) ? snapshot : []);
    feedVersion++;
    if (hoveredLink) showIndicator(hoveredLink);
  }
  let changed = false;
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    if (changes.phishingDatabaseActive || changes.phishingDatabaseUpdated ||
        changes.certPolskaActive || changes.certPolskaUpdated || changes.metaMaskUpdated) {
      databaseResults = new Map();
      feedVersion++;
      if (hoveredLink) checkDatabase(hoveredLink);
    }
    if (OPENPHISH_ENABLED && changes.openPhishSnapshot) {
        changed = true;
        setFeed(changes.openPhishSnapshot.newValue);
    }
  });
  if (OPENPHISH_ENABLED) {
    chrome.storage.local.get("openPhishSnapshot").then(data => {
      if (!changed) setFeed(data.openPhishSnapshot);
    }).catch(() => {});
  }

  const pageUrl = PhishGuard.parse(location.href);
  if (pageUrl && window.top !== window && PhishGuard.evaluate(pageUrl).status === "blocked") {
    window.stop();
    location.replace("about:blank");
    return;
  }

  function prevent(event, host) {
    event.preventDefault();
    event.stopImmediatePropagation();
    const language = chrome.i18n.getUILanguage().split("-")[0];
    window.alert((formMessages[language] || formMessages.en) + "\n" + host);
  }

  function linkFrom(event) {
    return event.composedPath().find(node => node instanceof Element &&
      node.matches("a[href], area[href]"));
  }

  function evaluateLink(link) {
    const raw = link.getAttribute("href");
    if (!raw) return null;
    let target;
    try { target = new URL(raw, link.baseURI); } catch { return null; }
    const cached = previews.get(link);
    if (cached?.href === target.href && cached.feedVersion === feedVersion) return cached.verdict;
    const url = PhishGuard.parse(target.href);
    const listed = url && ((OPENPHISH_ENABLED && feedUrls.has(OpenPhish.canonical(target.href))) ||
      databaseResults.get(target.href) === true);
    const verdict = listed ? { host: url.hostname, status: "blocked", reasons: ["blocklist"] } :
      url && PhishGuard.evaluate(url);
    previews.set(link, { href: target.href, verdict, feedVersion });
    return verdict;
  }

  function checkDatabase(link) {
    let href;
    try { href = new URL(link.getAttribute("href"), link.baseURI).href; } catch { return; }
    if (!PhishGuard.parse(href) || databaseResults.has(href)) return;
    const current = databaseResults;
    current.set(href, false);
    chrome.runtime.sendMessage({ action: "check-feed-link", url: href }).then(result => {
      if (databaseResults !== current) return;
      if (result?.listed) {
        current.set(href, true);
        feedVersion++;
        if (hoveredLink === link) showIndicator(link);
      }
    }).catch(() => { if (databaseResults === current) current.delete(href); });
  }

  function hideIndicator() {
    indicator?.remove();
    indicator = null;
  }

  function showIndicator(link) {
    hideIndicator();
    const verdict = evaluateLink(link);
    if (verdict?.status !== "blocked" || !link.isConnected) return;
    const rect = link.getBoundingClientRect();
    indicator = document.createElement("span");
    indicator.textContent = "!";
    indicator.setAttribute("role", "img");
    indicator.setAttribute("aria-label", dangerLabels[chrome.i18n.getUILanguage().split("-")[0]] || dangerLabels.en);
    indicator.style.cssText = "all:initial;position:fixed;z-index:2147483647;pointer-events:none;" +
      "width:18px;height:18px;border-radius:50%;background:#c81e1e;color:white;" +
      "font:bold 13px/18px sans-serif;text-align:center;box-shadow:0 1px 4px #0008;";
    indicator.style.left = Math.max(0, Math.min(window.innerWidth - 18, rect.right + 3)) + "px";
    indicator.style.top = Math.max(0, Math.min(window.innerHeight - 18, rect.top)) + "px";
    document.documentElement.appendChild(indicator);
  }

  window.addEventListener("pointerover", event => {
    if (!event.isTrusted) return;
    const link = linkFrom(event);
    if (link !== hoveredLink) {
      hoveredLink = link || null;
      if (link) { showIndicator(link); checkDatabase(link); } else hideIndicator();
    }
  }, { capture: true, passive: true });
  window.addEventListener("pointerout", event => {
    if (hoveredLink && !hoveredLink.contains(event.relatedTarget)) {
      hoveredLink = null;
      hideIndicator();
    }
  }, { capture: true, passive: true });
  window.addEventListener("scroll", () => { hoveredLink = null; hideIndicator(); }, { capture: true, passive: true });

  function checkClick(event) {
    if (!event.isTrusted || (event.type === "auxclick" && event.button !== 1)) return;
    const link = linkFrom(event);
    const verdict = link && evaluateLink(link);
    if (verdict?.status === "blocked") {
      event.preventDefault();
      event.stopImmediatePropagation();
      const newTab = event.type === "auxclick" || event.ctrlKey || event.metaKey || event.shiftKey ||
        (link.getAttribute("target") || "").toLowerCase() === "_blank";
      chrome.runtime.sendMessage({ action: "warn-link", url: new URL(link.getAttribute("href"), link.baseURI).href,
        newTab: Boolean(newTab) }).then(result => {
        if (!result?.ok) {
          const language = chrome.i18n.getUILanguage().split("-")[0];
          window.alert((messages[language] || messages.en) + "\n" + verdict.host);
        }
      }).catch(() => {
        const language = chrome.i18n.getUILanguage().split("-")[0];
        window.alert((messages[language] || messages.en) + "\n" + verdict.host);
      });
    }
  }
  window.addEventListener("click", checkClick, true);
  window.addEventListener("auxclick", checkClick, true);

  // Use explicit autocomplete tokens and field metadata; never inspect values.
  function sensitiveField(field) {
    if (!(field instanceof HTMLInputElement) || field.matches(":disabled") ||
        ["hidden", "submit", "button", "reset"].includes(field.type)) return false;
    if (field.type === "password") return true;
    const autocomplete = (field.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/);
    if (autocomplete.some(token => ["cc-number", "cc-csc", "one-time-code"].includes(token))) return true;
    const metadata = ["name", "id", "placeholder", "aria-label"].map(name => field.getAttribute(name) || "")
      .concat(Array.from(field.labels || [], label => label.textContent || "")).join(" ").slice(0, 1000).toLowerCase();
    return /(?:^|[^a-z0-9])(?:cvv2?|cvc2?|card[\s_-]*(?:number|no)|credit[\s_-]*card[\s_-]*number|otp|one[\s_-]*time[\s_-]*(?:code|password))(?=$|[^a-z0-9])/i.test(metadata);
  }

  // Inspect form structure and destination only. Never access field values.
  window.addEventListener("submit", event => {
    const form = event.target;
    if (!event.isTrusted || !(form instanceof HTMLFormElement) ||
        !Array.from(form.elements).some(sensitiveField)) return;
    const destination = event.submitter?.hasAttribute("formaction") ?
      event.submitter.formAction : form.action;
    const risk = PhishGuard.credentialRisk(PhishGuard.parse(location.href),
      PhishGuard.parse(destination), document.title);
    if (risk) prevent(event, risk.host);
  }, true);
})();
