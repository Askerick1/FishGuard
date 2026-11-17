# FishGuard

FishGuard is a Manifest V3 extension for Chromium 120+ with an optional FastAPI service on loopback. The extension evaluates HTTP and HTTPS addresses locally. FastAPI provides a verified domain feed and accepts user reports for review.

## Run locally

1. Open `chrome://extensions/` or `edge://extensions/`, enable Developer mode and load the `extension` directory as an unpacked extension.
2. To enable reports and feed updates, install the service dependencies with `python -m pip install -r requirements.txt` and start it with `python -m uvicorn main:app --host 127.0.0.1 --port 8000`.
3. Reload the extension after changing its files. Open the popup for the current tab verdict. The report button sends the hostname of the current site.

## Optional OpenPhish feed

The [OpenPhish Community Feed](https://github.com/openphish/public_feed) is enabled in the current configuration and is for non-commercial use. Review the [OpenPhish terms](https://openphish.com/terms.html) before using it. No API key or Python server is required for this feed. To disable it, set `OPENPHISH_ENABLED` to `false` in `extension/openphish.js` and reload the extension; the cached feed is removed. Set it to `true` to enable it again.

The extension downloads the feed at installation/startup and every 12 hours from OpenPhish's public GitHub repository. GitHub receives the feed download request; visited URLs are not sent to GitHub or OpenPhish. The last successful snapshot remains available when an update fails. Matching uses the full browser-normalized HTTP(S) URL including path and query, but excluding the fragment; unrelated pages on the same host are not blocked by this feed. The check runs on committed top-level navigations and History API changes, so the request may already have reached the site; subframes and scripted data transfers are not covered. No list catches every phishing URL.

When a user hovers over a link, a small red indicator appears next to it if the local detector or the downloaded OpenPhish snapshot identifies it as dangerous. Normal clicks and middle clicks open the existing warning page without first visiting the link. Middle clicks and links targeting a new tab open the warning in a new tab. The feed must be enabled and loaded first; this does not cover every way of opening a link, including context menus and scripts.

## Phishing.Database

The extension also downloads the active URL list from [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) on installation/startup and every 12 hours. It requires neither an API key nor the Python server. The list can be tens of megabytes and is stored in the extension's IndexedDB; the `unlimitedStorage` permission allows the database to grow. Updates are staged separately and become active only after a successful download and import. The previous snapshot remains available after an error. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the source's license.

The URL list is matched locally by exact browser-normalized URL, including path and query but excluding fragment. URLs visited by the user are not sent to GitHub. Hover checks are asynchronous; an immediate click before the lookup finishes may begin navigation, after which the top-level navigation check can still show the warning. The database only covers URLs in the source's active link list and can have false positives or omissions; it does not apply the separate domain or IP lists.

## CERT Polska Warning List

The extension downloads the [CERT Polska active domain list](https://cert.pl/en/warning-list/) at startup and checks for updates every five minutes. It requires no API key or Python server. The snapshot is stored locally in IndexedDB and is replaced after a successful import, including removing domains no longer listed. When an update fails, the previous snapshot is retained and can become stale. A listed domain and its subdomains match, but its parent domain does not. Local hover and committed-navigation checks use the same warning flow described above; an immediate click can reach the destination before the asynchronous check completes. GitHub does not receive browsing URLs, and CERT Polska receives only the periodic feed request, not visited addresses.

## MetaMask phishing list

The extension downloads the [MetaMask eth-phishing-detect](https://github.com/MetaMask/eth-phishing-detect) domain blocklist and exceptions on startup and every 12 hours. It requires no API key or Python server. Matching is local and includes subdomains. MetaMask exceptions apply only to this source; they do not override other threat feeds. The upstream fuzzy list is not used. A failed update keeps the previous snapshot, which may become stale. A click before an asynchronous lookup finishes may begin navigation before the warning. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for attribution and the upstream license.

## How the extension works

- Chromium applies bundled and verified `declarativeNetRequest` domain rules to top-level and iframe requests, including network redirect destinations. If a blocked main-frame attempt leaves an error document, the service worker replaces it with the FishGuard warning. This also works for high-risk addresses that fail DNS resolution. Ordinary network errors keep Chromium's error page.
- The isolated content script checks links on hover and click, stops high-risk iframe documents when it can run, and intercepts browser submit events for password forms when the page or destination is already risky. Form checks use the presence of a password field and never read its value. The service worker checks committed main-frame navigations, including the final URL after a redirect, and History API changes. Heuristic checks at these stages can run after a request has reached the destination.
- Password form submissions are also stopped when an HTTPS page submits to HTTP, or when a suspicious address combines a login-related title with a known brand. These checks run locally and inspect the title and form destination, not field values. They cover browser submit events; scripts can send credentials by other means and are not fully covered.
- The same checks cover card number, card security code and one-time code fields identified by selected autocomplete tokens and field metadata. A sensitive field or a cross-domain payment destination alone does not cause a block; custom controls, other labels and scripted transfers can be missed. No field values are read.
- Trust uses exact DNS label boundaries around curated roots. The heuristic score considers embedded official domains, brand lookalikes, single edits and transpositions, brand-plus-keyword combinations, mixed scripts, IP literals and URL structure. Scores of 45–64 show a caution in the popup and badge. Scores of 65 or more trigger the extension warning on a committed navigation. Scores represent relative risk signals.
- Additional local lookalike checks detect selected multi-character visual substitutions (`rn` for `m`, `vv` for `w`, and `cl` for `d`) and certain missing dots in known brand domains. These weak signals require other risk indicators before blocking. They are inspired by domain-permutation techniques; the extension does not run dnstwist, perform DNS discovery, or verify domain ownership.
- The local bank impersonation check uses a curated list of official roots from the [Central Bank of Azerbaijan register](https://www.cbar.az/page-195/banks?language=en) and official bank sites. It checks labels for distinctive bank names, visual substitutions and common typos. Short initials require Azerbaijani or banking context. Recheck official roots when banks change their websites or licenses.
- The official AMTSO desktop phishing test is a bundled URL-specific rule. The launch page remains accessible. This checks that blocking is active.
- The warning lets the user go back or explicitly confirm a single retry of the original URL in the same tab. The temporary network exception applies only to the exact address and top-level requests in that tab. It is removed when navigation completes or fails, or after a short timeout. The original URL stays in the worker's memory for one minute at most. Worker suspension can make the retry unavailable.
- Browsing URLs are never sent automatically. The browser periodically downloads a snapshot from `GET /api/v1/threat-feed`, scoped to rows with source `verified`. Chrome stores the snapshot as dynamic rules and retains the last snapshot when the local service is unavailable. To publish a verified entry, an operator records a canonical lowercase ASCII hostname in `blocked_domains` with source `verified`. A report only creates a pending review entry. Existing `user_report` rows are excluded from active blocks.

## Release and maintenance

Review the bundled domain list before distributing the extension. It originated as demonstration data. Maintain a labeled corpus of legitimate and phishing URLs, review false positives and missed threats and tune the thresholds against a held-out set. The bundled IDN confusable map and compound suffix hints cover selected cases. For broader coverage, use a maintained UTS #39 skeleton dataset and a local PSL snapshot including private suffixes.

For an external provider, ingest and verify feed updates server-side without sending browsing history. Preserve URL-level specificity for malicious pages on shared hosting. Publish domain-wide rules only when the entire hostname and its descendants are considered malicious. Replace the loopback architecture with an authenticated HTTPS deployment if the API is to be exposed to other machines.

Older SQLite rows may still contain full URLs recorded by earlier versions. New checks and reports store canonical hostnames in their URL columns. Review retention of old rows and backups before distributing or sharing any database.

For an offline measurement of the extension's URL heuristics, run `node benchmark_detector.cjs benchmark_example.json`. The example contains synthetic phishing cases and is only a format demonstration, not evidence of real-world accuracy. Replace it with independently labeled, representative phishing and legitimate URLs, separate from the cases used to tune the detector. The script reports blocked and suspicious results separately; it does not evaluate live feeds, page forms, or browser behavior and makes no network requests. Handle potentially sensitive URLs in the dataset appropriately.

## Tests

```sh
node --test test_detector.cjs
node --test test_links.cjs
node --test test_warning.cjs
node --test test_phishing_database.cjs
node --test test_cert_polska.cjs
node --test test_metamask_feed.cjs
python -m pytest -q
```

After reloading the extension, enter `https://google.com.security-check.test/` in the address bar to verify the warning screen with a reserved test domain. The expected score is 100/100.

The backend check endpoint remains available for legacy clients. The extension uses the detector in `extension/detector.js` for browsing decisions.
