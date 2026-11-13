<div align="center">

<img src="assets/readme/banner-contributing.svg" alt="Contributing to PhishLens" width="100%">

</div>

Thanks for helping improve PhishLens. This guide covers setup, how to add or change a detection rule, and what a good pull request looks like.

## 🧭 Ground rules

1. **Stay local.** Submitted URLs must never be opened, fetched or transmitted. Do not add `fetch`, `XMLHttpRequest`, beacons or third-party scripts. The CSP enforces this.
2. **Stay honest.** No fabricated intelligence. Heuristics are not a malware or reputation scan, and the UI must never imply they are.
3. **Stay explainable.** Every signal needs a title, a weight and a plain-language reason.
4. **Stay light.** No frameworks or build systems. It must run from `index.html` or a static server.

## 🛠️ Setup

```bash
git clone https://github.com/<your-username>/PhishLens.git
cd PhishLens
python -m http.server 8000   # or use VS Code Live Server
```

No install step is needed.

## 🌿 Workflow

1. Fork the repo and create a branch: `git checkout -b feat/short-description`
2. Make focused changes. One idea per pull request.
3. Test manually (checklist below).
4. Open a pull request describing what changed and why. Add screenshots for UI changes.

Commit messages follow a simple convention: `feat:`, `fix:`, `docs:`, `style:`, `refactor:`, for example `feat: flag excessive path depth`.

## 🧩 Adding a detection rule

Three places change, all in `app.js`:

1. **Weight:** add a key to the `weights` object.
2. **Logic:** add a check in `analyze()` using `add(key, title, reason)`.
3. **Label:** add a short name to `RULE_LABELS` so the Methodology table lists it.

```js
// 1. weights
const weights = { /* ... */ manyParams: 5 };

// 2. inside analyze()
if ([...url.searchParams].length > 12)
  add("manyParams", "Many query parameters",
      "The URL carries an unusually large number of parameters, which can hide tracking or redirect targets.");

// 3. RULE_LABELS
const RULE_LABELS = { /* ... */ manyParams: "Many query parameters" };
```

Also keep in mind:

- Explain **why** the pattern matters and that it is not proof of malice.
- Severity is derived from weight (18+ high, 10+ medium, otherwise low), so choose weights accordingly.
- Changing existing weights or score bands needs justification in the PR, and the README table must be updated.
- Document false-positive risks.

## 🎨 Design guidelines

- Use the existing CSS variables in `:root` (midnight navy surfaces, cyan/indigo accents, green/amber/red for risk only).
- Every animation must be disabled under `prefers-reduced-motion`.
- Keep layouts responsive down to 360px with no horizontal scroll.
- Keep visible focus states, semantic HTML and accessible labels on SVGs.
- New SVGs: clean vector paths, a proper `viewBox`, a `<title>`, no embedded raster images.

## ✅ Pull request checklist

- [ ] Analyze works for the sample URLs and for invalid input (inline error appears)
- [ ] Score and signals match the weights; no duplicate history entries when reopening reports
- [ ] History saves, reopens and clears; export downloads a `.txt` report
- [ ] Navigation works on desktop and mobile; keyboard-only use works
- [ ] No console errors and no network requests to external hosts for analysis
- [ ] Reduced motion tested; no horizontal overflow at mobile width
- [ ] README or docs updated if behaviour changed

## 🐞 Reporting issues

Include the URL pattern (use `example.com` style placeholders, never real victim links), the score you expected, the score you got, browser and OS, and a screenshot if it is visual.

## 🔐 Security

If you find a vulnerability (for example an XSS path in rendering), please report it privately to the maintainer instead of opening a public issue.

<div align="center">

<img src="assets/readme/divider.svg" alt="" width="100%">

*Thank you for making links easier to understand.* 🔍

</div>
