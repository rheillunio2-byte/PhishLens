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
