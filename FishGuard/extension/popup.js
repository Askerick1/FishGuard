const translations = {
  az: {
    secured: "Aşkar təhlükə yoxdur", trusted: "Etibarlı domen", suspicious: "Şübhəli ünvan", unknown: "Yoxlanılmayıb", report_error: "Şikayət göndərilmədi.",
    threat: "Təhlükə Aşkarlandı!",
    scanned: "Yoxlanıldı",
    blocked: "Bloklandı",
    report: "Şübhəli saytı bildir",
    online: "aktiv",
    report_success: "Cari sayt uğurla şikayət edildi!",
    new_tab: "—"
  },
  en: {
    secured: "No threat detected", trusted: "Trusted domain", suspicious: "Suspicious address", unknown: "Not checked", report_error: "The report could not be sent.",
    threat: "Threat Detected!",
    scanned: "Scanned",
    blocked: "Blocked",
    report: "Report Suspicious Site",
    online: "online",
    report_success: "Current site successfully reported!",
    new_tab: "—"
  },
  ru: {
    secured: "Угроза не обнаружена", trusted: "Доверенный домен", suspicious: "Подозрительный адрес", unknown: "Проверка недоступна", report_error: "Не удалось отправить жалобу.",
    threat: "Обнаружена угроза!",
    scanned: "Просканировано",
    blocked: "Заблокировано",
    report: "Сообщить о сайте",
    online: "в сети",
    report_success: "Жалоба на сайт успешно отправлена!",
    new_tab: "—"
  }
};

const el = id => document.getElementById(id);

async function initPopup() {
  const settings = await chrome.storage.local.get(["phishguard_lang", "scannedCount", "blockedCount"]);
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = PhishGuard.parse(tab?.url);
  const warning = tab?.url?.startsWith(chrome.runtime.getURL("blocked.html") + "?");
  const warningHost = warning ? new URL(tab.url).searchParams.get("host") : null;
  let verdict;
  if (url) {
    const rules = await chrome.declarativeNetRequest.getDynamicRules();
    const domains = rules.flatMap(rule => rule.condition.requestDomains || []);
    verdict = PhishGuard.evaluate(url, [...BUNDLED_BLOCKLIST, ...domains]);
  }
  let feedCheck;
  if (url) {
    try { feedCheck = await chrome.runtime.sendMessage({ action: "popup-feed-check", tabId: tab.id }); }
    catch { /* Do not present an incomplete check as a clean result. */ }
  }
  const status = warning || feedCheck?.listed || verdict?.status === "blocked" ? "blocked" :
    url && !feedCheck?.ok ? "unknown" : verdict?.status || "unknown";
  el("main-card").dataset.status = status;
  el("stat-scanned").textContent = settings.scannedCount || 0;
  el("stat-blocked").textContent = settings.blockedCount || 0;
  const switcher = el("lang-switcher");
  switcher.value = Object.hasOwn(translations, settings.phishguard_lang) ? settings.phishguard_lang : "az";
  const language = () => translations[switcher.value] || translations.az;
  function render() {
    const t = language();
    el("current-url").textContent = verdict?.host || warningHost || t.new_tab;
    const key = { blocked: "threat", clear: "secured" }[status] || status;
    el("status-title").textContent = t[key];
    el("label-scanned").textContent = t.scanned;
    el("label-blocked").textContent = t.blocked;
    el("text-report").textContent = t.report;
  }
  switcher.addEventListener("change", async () => {
    await chrome.storage.local.set({ phishguard_lang: switcher.value });
    render();
  });
  const report = el("report-btn");
  report.disabled = !verdict && !warningHost;
  report.addEventListener("click", async () => {
    report.disabled = true;
    try {
      const result = await chrome.runtime.sendMessage({ action: "report", tabId: tab.id });
      window.alert(result?.ok ? language().report_success : language().report_error);
    } catch {
      window.alert(language().report_error);
    } finally {
      report.disabled = false;
    }
  });
  render();
}

void initPopup().catch(() => {
  el("status-title").textContent = translations.az.unknown;
  el("report-btn").disabled = true;
});
