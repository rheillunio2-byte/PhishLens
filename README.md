<div align="center">

<img src="assets/readme/banner.svg" alt="PhishLens — See Beyond the Link" width="100%">

<img src="assets/readme/typing.svg" alt="Parse the URL. Examine signals. Calculate a score. Explain findings." width="100%">

![HTML5](https://img.shields.io/badge/HTML5-0D1424?style=for-the-badge&logo=html5&logoColor=38BDF8)
![CSS3](https://img.shields.io/badge/CSS3-0D1424?style=for-the-badge&logo=css3&logoColor=818CF8)
![JavaScript](https://img.shields.io/badge/JavaScript-0D1424?style=for-the-badge&logo=javascript&logoColor=A78BFA)
![Local only](https://img.shields.io/badge/Analysis-100%25_local-34D399?style=for-the-badge)
![No build](https://img.shields.io/badge/Build_step-none-38BDF8?style=for-the-badge)

**Uncover suspicious URL patterns, understand hidden warning signs, and make smarter decisions before you click.**

</div>

<img src="assets/readme/divider.svg" alt="" width="100%">

## ✨ What is PhishLens?

PhishLens is an **explainable URL intelligence workbench**. Paste a link and it breaks the address into its parts, runs a set of transparent heuristic rules, and shows exactly *why* each signal matters, instead of an unexplained "safe / unsafe" label.

- 🔒 **Privacy-first:** URLs are analyzed in your browser. Nothing is opened, fetched or sent anywhere.
- 🔍 **Explainable:** every triggered rule shows its weight, severity and reasoning.
- ⚡ **Zero dependencies:** plain HTML, CSS and JavaScript. Open `index.html` and go.

## 🖼️ Screenshots

### Inspect
<img src="images/Inspect.PNG" alt="PhishLens inspect page with the URL scanner and results dashboard" width="100%">

### History
<img src="images/History.PNG" alt="PhishLens investigation history archive" width="100%">

### Methodology
<img src="images/Methodology.PNG" alt="PhishLens methodology page showing the four-step process and rule weights" width="100%">

<img src="assets/readme/divider.svg" alt="" width="100%">

## 🧭 Features

| | Feature | Details |
|---|---|---|
| 🎯 | **Risk gauge** | Animated 0–100 score with a clear classification |
| 🧩 | **Signal breakdown** | Severity-coded cards with weight and a plain-language reason |
| 🌐 | **Destination profile** | Hostname, protocol, TLD, subdomain depth, URL length, HTTPS |
| 🎞️ | **Scan sequence** | Shows the real parsed protocol, host and path across four stages |
| 🗂️ | **Investigation archive** | Saved in `localStorage`, reopen any report, clear anytime |
| 📄 | **Report export** | Download a plain-text report with every signal |
| 📖 | **Methodology** | Rule weights are generated from the live scoring table |
| ♿ | **Accessible** | Keyboard navigation, visible focus, reduced-motion support |

## 🚀 Quick start

```bash
git clone https://github.com/<your-username>/PhishLens.git
cd PhishLens
# Option A: just open index.html in your browser
# Option B: serve it locally
python -m http.server 8000
```

Then visit `http://localhost:8000`, paste a URL and press **Analyze**. Try the sample chips to see the signals in action.

## 🧮 How scoring works

Each triggered rule adds a fixed weight. The total is capped at 100.

| Score | Classification |
| ---: | --- |
| 0–11 | 🟢 Few flags |
| 12–29 | 🟢 Low concern |
| 30–59 | 🟡 Caution |
| 60–100 | 🔴 High risk |

These are heuristic bands, **not** calibrated probabilities. A score of 0 does not mean a URL is safe.

## 🛡️ Privacy and limitations

- Submitted URLs never leave the browser. A Content-Security-Policy (`connect-src 'none'`) blocks outbound requests.
- The only third-party request is the Google Fonts stylesheet. Remove the `<link>` in `index.html` to go fully offline.
- PhishLens does **not** visit sites, follow redirects, query DNS/WHOIS/certificates, or check live threat feeds.
- Rules can produce false positives and false negatives. Never use the score as the sole basis for a security decision.

## 📁 Project structure

```text
PhishLens/
├── index.html
├── styles.css
├── app.js
├── images/          # README screenshots
├── assets/
│   ├── logo/        # logo, icon, light/dark variants, favicon
│   ├── illustrations/
│   └── readme/      # animated README banners
├── README.md
└── CONTRIBUTING.md
```

## 🤝 Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

<div align="center">

<img src="assets/readme/divider.svg" alt="" width="100%">

*Built for curiosity. Designed for caution.*

</div>
