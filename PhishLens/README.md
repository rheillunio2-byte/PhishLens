# PhishLens

**See Beyond the Link.** An explainable, local-only URL inspection workbench.

## What changed in the redesign
- New original identity: shield + lens + eye mark, monoline vector wordmark (`assets/logo/`: `phishlens-logo.svg`, `-icon`, `-light` (for dark backgrounds), `-dark` (for light backgrounds), `favicon.svg`).
- Custom SVG illustrations (`assets/illustrations/`): animated hero scanner and empty-archive state.
- Redesigned inspect, results dashboard, history archive and methodology pages; hash routing (`#inspect`, `#history`, `#method`), sliding nav indicator, mobile menu.
- Scan sequence now shows the real parsed protocol, host and path while four stages run; animated risk gauge with count-up; severity-coded signal cards and a score-composition bar.
- Inline validation replaces `alert()`; a dialog confirms clearing history.
- `prefers-reduced-motion` is respected everywhere.
- A Content-Security-Policy (`connect-src 'none'`) makes the no-network promise enforceable by the browser.

## Scoring (unchanged)
The weights, rules and bands are the original ones, copied verbatim. Bands: 0–11 Few flags, 12–29 Low concern, 30–59 Caution, 60–100 High risk.

**One bug fix:** reopening a report from History used to save it into history again (duplicates). It now opens without re-saving.

## Run
Open `index.html`, or use VS Code Live Server / `python -m http.server 8000`. No build step.

## Privacy and limits
Submitted URLs are analyzed in the browser and never fetched or sent anywhere. History is stored in `localStorage`. The only third-party request is the Google Fonts stylesheet (Sora, IBM Plex Mono); remove the `<link>` and the CSP font entries to go fully offline — system fonts are used as fallback. Heuristics are not a reputation check: a low score is not proof of safety.

## v2.0 — engine upgrade (Phase 1)
- Analyzer moved to `engine.js` (pure, no DOM, no network) so it can be unit-tested: `npm test` (Node 18+, zero dependencies).
- Five bands: Safe-looking 0–11, Low 12–29, Medium 30–59, High 60–79, Critical 80–100. Original rule weights are kept.
- New signals: brand look-alikes (digit/`rn` substitution, 1-edit), brand name only in path, embedded redirect parameters, IPv6 literals.
- Fixes: brand check now matches whole hostname tokens against the registered domain (no more `pineapple.com` or `accounts.google.com` false positives); `co.uk`-style suffixes no longer inflate subdomain depth; the non-ASCII rule was unreachable (the URL parser pre-converts to punycode) and now inspects the typed hostname; IPv6 hosts are recognised.
- Related signals share a family: strongest counts in full, others at 50%, so one cue is not penalised repeatedly.
- Every signal carries evidence, severity, contribution and a suggested action; each report lists the checks that were **not** performed.
- Privacy: history and exported reports store only scheme, host and path. Credentials, query strings and fragments are removed.
- History: search, risk filter, CSV export (spreadsheet-formula-safe).

## v2.1 — detection, reports and tools
**Engine (`engine.js`)**
- Punycode is decoded (RFC 3492) so the real characters are inspected. New signals: mixed alphabets in one label, IDN look-alikes of a brand (confusable-character skeleton), obfuscated IPs (hex/octal/decimal), a domain name hidden in the subdomain, double encoding, encoded and path-embedded redirect targets.
- False-positive guards: sign-in wording is not penalised on a brand's own registered domain; `%XX` needs 3+ sequences; `binance`/`finance`-style near-words are not typosquats.
- Independent indicator families add a visible **corroboration** bonus (+10 for 3+ families); related cues are halved. Input over 2048 characters, spaces or control characters are rejected with a clear message.
- Reports add category grouping, hostname breakdown, next steps, and four check states: performed, not applicable, unavailable, not performed.

**Interface**
- Compare two history entries, copy a privacy-redacted report, print / save as PDF (print stylesheet), delete single entries, sort and filter history, and eight annotated sample URLs (all use reserved or fictional domains).
- Stored history is re-validated on load: malformed or tampered records are dropped or clamped, and everything is HTML-escaped.

## v2.3 — motion layer (`fx.js`)
Vanilla JS/CSS adaptations of effects from the React Bits catalog (no React, no dependencies, no network): Blur Text (hero words), Decrypted Text (verdict label; always resolves to the real verdict), Magnet (Analyze button), Spotlight Card and Glare Hover (cards follow the pointer), Fade Content (scroll reveals), Count Up (history statistics), plus a light Aurora and floating motes in the background. Results get a one-shot animation matched to their risk band. Effects are transform/opacity based, background loops pause when the tab is hidden, motes are disabled on small screens, and everything is switched off under `prefers-reduced-motion`. Animations never represent scan progress or alter any score.

## v2.4 — Magnet, swarm and Star on GitHub
- **Magnet** (`fx.js`): a vanilla port of the React Bits Magnet logic — spring physics (stiffness 170, damping 16), a 100 px pull zone with smoothstep falloff, nearest-magnet-wins, 14 px max offset. Applied to the Analyze button and the Star buttons via `data-magnet`.
- **Swarm** (`swarm.js`): a lean vanilla port of SwarmCursor — instanced WebGL2 particles that orbit the cursor, stream behind fast movement, burst on click and roam when the pointer is away. It is decorative, confined to the hero, paused when off-screen or when the tab is hidden, disabled under `prefers-reduced-motion`, and silently skipped if WebGL2 is unavailable. Not ported: the original's grid fluid solver and pour-around-buttons targeting.
- **Star on GitHub**: links to https://github.com/rheillunio2-byte/PhishLens (opens in a new tab with `noopener noreferrer`). It is a plain link: nothing is requested until you click it, and no star count is fetched, so the local-only guarantee holds.

## v2.5 — local threat list, logo, polish
- **Local threat list** (`engine.js`, `threats.js`): a static list of domains reported by third parties. A match is its own signal (labelled "threat list", not "heuristic"), shows a banner with the source, and floors the score at 85 (Critical). It matches the domain and its subdomains only, never look-alikes. It is a snapshot, not a live feed, and a match is a report, not proof the site is malicious today. The built-in entry is `aladel.net`, with its sources shown in the report. You can add, import (`.txt`/`.csv`: plain domains, `domain, category`, hosts files, URL lists or CSV rows incl. IPv4; 5 MB file and 20,000 entry limits; entries on big shared platforms such as Google Drive or GitHub are skipped to prevent false alarms), export and clear your own entries in Methodology. They live only in this browser's localStorage and are validated on load. Lists such as URLhaus or PhishTank exports can be imported this way.
- Structural heuristics alone cannot know that a normal-looking domain is bad: without a list entry, `aladel.net` scores 0.
- **Logo**: new gradient shield with a glass lens, fish-hook glyph and slow scan arc (CSS-animated inside the SVG, still under reduced motion). Variants: `phishlens-logo.svg`, `-dark`, `-light`, `phishlens-icon.svg`, `favicon.svg`.
- **Polish**: a light beam sweeps the input only while a real analysis is running; the hero shield drifts against the pointer.

## Scoring methodology and limits
Weights are hand-chosen, not learned from data. The 0–100 score is a priority indicator, **not a probability**; "Safe-looking" means only that none of these structural checks fired. Phishing hosted on a trusted platform (or on a brand's own subdomain) will not be caught. The brand list is small and local. Domain age, DNS, certificates, reputation feeds and page content are never consulted.

## Privacy
No URL is ever opened, fetched or sent anywhere. Credentials, query strings and fragments are stripped before storage, copy, CSV or export. The CSP forbids network connections from scripts. Note: the page still loads Google Fonts (a v1 choice), which tells Google that the page was opened but never includes the analysed URL; self-hosting the fonts would remove even that.

## Testing
`npm test` runs 42 Node tests (no dependencies): legitimate URLs, phishing patterns, typosquats, Unicode/Punycode, IPv4/IPv6, obfuscated IPs, redirects, encoding, malformed input, score determinism, a 300-case fuzz run, redaction, CSV formula safety and stored-record sanitising. `npm start` serves the app at http://localhost:8000.

## Out of scope by design
Accounts, backend, databases, threat-intelligence APIs and community reporting would break the local-only guarantee and are not part of this architecture.
