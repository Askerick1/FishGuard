const blockedTexts = {
  az: {
    online: "aktiv",
    title: "Diqqət! Fırıldaqçılıq Təhlükəsi",
    desc: "Ünvanda fırıldaqçılıq əlamətləri aşkarlandı.",
    urlLabel: "Bloklanan ünvan / Blocked domain",
    analysisLabel: "Analiz nəticəsi:",
    adviceLabel: "Tövsiyə:",
    adviceVal: "Bu səhifəyə heç bir şəxsi məlumat, şifrə və ya bank kartı məlumatlarını daxil etməyin.",
    btnBack: "Geri qayıt",
    btnProceed: "Hər halda keç",
    btnReport: "Bu xətadır",
    reportSent: "Bildiriş yoxlama üçün göndərildi.",
    reportFailed: "Bildiriş göndərilmədi. Yerli xidmətin işlədiyini yoxlayın.",
    confirmMsg: "Diqqət! Bu saxta səhifəyə keçid etmək təhlükəlidir. Davam etmək istəyirsiniz?"
  },
  en: {
    online: "online",
    title: "Warning! Phishing Threat Detected",
    desc: "This address shows signs of phishing.",
    urlLabel: "Blocked domain",
    analysisLabel: "Analysis Result:",
    adviceLabel: "Advice:",
    adviceVal: "Do not enter any personal data, passwords, or bank card details on this page.",
    btnBack: "Go back",
    btnProceed: "Proceed anyway",
    btnReport: "This is a mistake",
    reportSent: "Report sent for review.",
    reportFailed: "Could not send the report. Check that the local service is running.",
    confirmMsg: "Warning! Proceeding to this fake page is dangerous. Do you want to continue?"
  },
  ru: {
    online: "в сети",
    title: "Внимание! Угроза фишинга",
    desc: "В адресе обнаружены признаки фишинга.",
    urlLabel: "Заблокированный домен",
    analysisLabel: "Результат анализа:",
    adviceLabel: "Совет:",
    adviceVal: "Не вводите на этой странице личные данные, пароли или данные банковских карт.",
    btnBack: "Вернуться назад",
    btnProceed: "Всё равно перейти",
    btnReport: "Это ошибка",
    reportSent: "Сообщение отправлено на проверку.",
    reportFailed: "Не удалось отправить сообщение. Проверьте, что локальный сервис запущен.",
    confirmMsg: "Внимание! Переход на эту фальшивую страницу опасен. Хотите продолжить?"
  }
};

let currentLang = 'az';

async function initBlockedPage() {
  try {
    const stored = await chrome.storage.local.get(['phishguard_lang']);
    if (stored.phishguard_lang) {
      currentLang = stored.phishguard_lang;
    }
    const switcher = document.getElementById('lang-switcher');
    if (switcher) {
      switcher.value = currentLang;
      switcher.onchange = async (e) => {
        currentLang = e.target.value;
        await chrome.storage.local.set({ phishguard_lang: currentLang });
        updateBlockedTexts();
      };
    }
    updateBlockedTexts();
  } catch (e) {
    console.error("Blocked init error:", e);
  }
}

function updateBlockedTexts() {
  const t = Object.hasOwn(blockedTexts, currentLang) ? blockedTexts[currentLang] : blockedTexts.az;
  const el = (id) => document.getElementById(id);

  if (el('txt-alert-title')) el('txt-alert-title').textContent = t.title;
  if (el('txt-alert-desc')) el('txt-alert-desc').textContent = t.desc;
  if (el('txt-advice-val')) el('txt-advice-val').textContent = t.adviceVal;
  if (el('go-back')) el('go-back').textContent = t.btnBack;
  if (el('proceed')) el('proceed').textContent = t.btnProceed;
}


const reasonText = {
  az: {
    expired: "Keçid artıq mövcud deyil.",
    labels: { embeddedRoot: "Saxta alt domen", lookalike: "Oxşar domen", combo: "Brend və giriş açar sözü",
      brand: "Brend təqlidi", typo: "Brend adında fərq", credentials: "Ünvanda istifadəçi məlumatı",
      mixedScript: "Qarışıq əlifbalar", ip: "IP ünvanı", suffix: "Riskli sonluq",
      depth: "Çoxsəviyyəli domen", hostAction: "Domendə açar söz", pathAction: "Yolda açar söz", blocklist: "Blok siyahısı",
      visualTypo: "Brend adında oxşar simvollar", missingDot: "Domen adında çatışmayan nöqtə",
      bankImpersonation: "Qeyri-rəsmi domendə bank adı", bankLookalike: "Bank domeninə bənzər ünvan" },
  },
  en: {
    expired: "The original address is no longer available.",
    labels: { embeddedRoot: "Official domain embedded in another hostname", lookalike: "Lookalike domain",
      combo: "Brand with a phishing keyword", brand: "Brand impersonation", typo: "Brand spelling change",
      credentials: "Credentials in the address", mixedScript: "Mixed scripts", ip: "IP address",
      suffix: "Risky suffix", depth: "Deeply nested hostname", hostAction: "Keyword in hostname",
      pathAction: "Keyword in path", blocklist: "Blocklist match",
      visualTypo: "Lookalike character sequence in brand", missingDot: "Missing dot in brand domain",
      bankImpersonation: "Bank name on an unofficial domain", bankLookalike: "Bank domain lookalike" },
  },
  ru: {
    expired: "Исходный адрес больше недоступен.",
    labels: { embeddedRoot: "Официальный домен внутри чужого имени", lookalike: "Домен-двойник",
      combo: "Бренд с фишинговым ключевым словом", brand: "Имитация бренда", typo: "Изменение в названии бренда",
      credentials: "Учётные данные в адресе", mixedScript: "Смешение алфавитов", ip: "IP-адрес",
      suffix: "Рискованная доменная зона", depth: "Глубокая вложенность", hostAction: "Ключевое слово в домене",
      pathAction: "Ключевое слово в пути", blocklist: "Совпадение с блоклистом",
      visualTypo: "Похожее сочетание символов в названии", missingDot: "Пропущенная точка в домене бренда",
      bankImpersonation: "Название банка на неофициальном домене", bankLookalike: "Адрес похож на домен банка" },
  },
};
const params = new URLSearchParams(location.search);
document.getElementById("go-back").addEventListener("click", async () => {
  const back = params.get("back");
  if (back === "close") {
    const tab = await chrome.tabs.getCurrent();
    await chrome.tabs.remove(tab.id);
    return;
  }
  // A warning shown after navigation has the intercepted entry immediately behind it.
  const steps = back === "previous" ? 1 : 2;
  if (history.length > steps) history.go(-steps);
  else location.replace("about:blank");
});
const proceed = document.getElementById("proceed");
proceed.disabled = !params.has("id");
proceed.addEventListener("click", async () => {
  const lang = Object.hasOwn(blockedTexts, currentLang) ? currentLang : "az";
  if (!window.confirm(blockedTexts[lang].confirmMsg)) return;
  proceed.disabled = true;
  try {
    const result = await chrome.runtime.sendMessage({ action: "proceed", id: params.get("id") });
    if (result?.ok) return;
  } catch {
    // The service worker may have suspended while the warning was open.
  }
  window.alert(reasonText[lang].expired);
});
void initBlockedPage();
