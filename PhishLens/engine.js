/* PhishLens analysis engine v2 — pure, passive, no network. Works in browsers (window.PhishLensEngine) and Node (require). */
(function (root) {
  "use strict";
  const WEIGHTS = { threatList:70, rawIp:18, obfuscatedIp:10, mixedScript:20, idnBrand:28, domainInSubdomain:16, doubleEncoding:8, punycode:22, unicode:12, userInfo:22, shortener:10, brandBait:18, typosquat:20, brandPath:8, redirectParam:8,
    credential:10, urgency:7, oddPort:9, deepSubdomain:7, longHost:6, hyphens:5, riskyTld:8, doubleExtension:10, encoded:4, longUrl:4, http:4 };
  // Signals in one family describe the same underlying cue; only the strongest counts in full, the rest at 50%.
  const FAMILY = { punycode:"idn", unicode:"idn", mixedScript:"idn", brandBait:"brand", typosquat:"brand", idnBrand:"brand", brandPath:"brand", credential:"lure", urgency:"lure", rawIp:"ip", obfuscatedIp:"ip", encoded:"enc", doubleEncoding:"enc" };
  const BANDS = [[80,"critical","Critical risk"],[60,"high","High risk"],[30,"medium","Medium risk"],[12,"low","Low risk"],[0,"safe","Safe-looking"]];
  const TWO_LEVEL = new Set(["co.uk","org.uk","ac.uk","gov.uk","com.au","net.au","org.au","co.jp","co.nz","co.in","com.br","com.ph","com.sg","co.za","com.mx","com.cn","com.hk","com.tr"]);
  const BRANDS = {
    paypal:["paypal.com","paypal.me"], microsoft:["microsoft.com","live.com","office.com","microsoftonline.com","windows.com","outlook.com","bing.com","xbox.com"],
    apple:["apple.com","icloud.com"], google:["google.com","gmail.com","youtube.com","googleapis.com","gstatic.com","googleusercontent.com","google.com.ph","google.co.uk"],
    amazon:["amazon.com","amazon.co.uk","amazon.de","amazon.in","amazon.com.au","amazon.co.jp","amazonaws.com"], netflix:["netflix.com","nflxvideo.net"],
    facebook:["facebook.com","fb.com","fb.me","messenger.com"], instagram:["instagram.com"], steam:["steampowered.com","steamcommunity.com"],
    discord:["discord.com","discord.gg","discordapp.com"], bank:[],
    dhl:["dhl.com"], fedex:["fedex.com"], linkedin:["linkedin.com"], dropbox:["dropbox.com"], adobe:["adobe.com"], coinbase:["coinbase.com"],
    binance:["binance.com"], chase:["chase.com"], wellsfargo:["wellsfargo.com"], gcash:["gcash.com"], github:["github.com","githubusercontent.com"], whatsapp:["whatsapp.com","whatsapp.net"]
  };
  const NO_LEV = new Set(["binance"]); // "finance" is one edit away; exact/confusable matching only
  const CONF = {"а":"a","е":"e","о":"o","р":"p","с":"c","у":"y","х":"x","і":"i","ј":"j","ѕ":"s","ԁ":"d","һ":"h","ɡ":"g","ӏ":"l","ο":"o","α":"a","ν":"v","ι":"i","ρ":"p","κ":"k","τ":"t","υ":"u","ѵ":"v","ɑ":"a","օ":"o","ս":"u"};
  const SCRIPTS = ["Latin","Cyrillic","Greek","Armenian","Hebrew","Arabic","Han","Hiragana","Katakana","Hangul","Thai","Devanagari"].map(n => [n === "Hiragana" || n === "Katakana" ? "Han" : n, new RegExp("\\p{Script=" + n + "}", "u")]);
  const COMMON_TLD = new Set(["com","net","org","gov","edu"]);
  const CAT = { threatList:"Threat intelligence", rawIp:"Identity", obfuscatedIp:"Identity", punycode:"Identity", unicode:"Identity", mixedScript:"Identity", idnBrand:"Identity", userInfo:"Identity", brandBait:"Identity", typosquat:"Identity", brandPath:"Identity", domainInSubdomain:"Identity",
    shortener:"Structure", oddPort:"Structure", deepSubdomain:"Structure", longHost:"Structure", hyphens:"Structure", riskyTld:"Structure", http:"Structure",
    redirectParam:"Redirect & encoding", encoded:"Redirect & encoding", doubleEncoding:"Redirect & encoding", longUrl:"Redirect & encoding", doubleExtension:"Redirect & encoding", credential:"Lure wording", urgency:"Lure wording" };
  const SHORTENERS = ["bit.ly","tinyurl.com","t.co","is.gd","cutt.ly","rebrand.ly","shorturl.at","ow.ly","buff.ly","rb.gy"];
  const RISKY_TLDS = ["zip","mov","top","click","country","gq","tk","work"];
  const REDIRECT_KEYS = /^(url|redirect|redirect_uri|redirect_url|next|continue|return|returnto|dest|destination|goto|target|link|u)$/i;

  function lev(a, b) {
    const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
    for (let j = 1; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++)
      d[i][j] = Math.min(d[i-1][j] + 1, d[i][j-1] + 1, d[i-1][j-1] + (a[i-1] === b[j-1] ? 0 : 1));
    return d[a.length][b.length];
  }
  const deconfuse = s => s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s");
  const isOfficial = (brand, reg) => BRANDS[brand].includes(reg);
  function registrable(labels) {
    if (labels.length >= 3 && TWO_LEVEL.has(labels.slice(-2).join("."))) return labels.slice(-3).join(".");
    return labels.slice(-2).join(".");
  }

  // RFC 3492 Punycode decoder (used to inspect the real characters behind xn-- labels).
  function puny(s) {
    const out = []; let i = 0, n = 128, bias = 72, idx = 0; const b = s.lastIndexOf("-");
    if (b > 0) { for (let j = 0; j < b; j++) out.push(s.charCodeAt(j)); idx = b + 1; }
    while (idx < s.length) {
      const oldi = i; let w = 1;
      for (let k = 36; ; k += 36) {
        if (idx >= s.length) throw new Error("bad punycode");
        const c = s.charCodeAt(idx++), dg = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : 36;
        if (dg >= 36) throw new Error("bad punycode");
        i += dg * w; const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
        if (dg < t) break; w *= 36 - t;
      }
      const len = out.length + 1; let d = oldi === 0 ? Math.floor((i - oldi) / 700) : (i - oldi) >> 1; d += Math.floor(d / len);
      let k2 = 0; while (d > 455) { d = Math.floor(d / 35); k2 += 36; } bias = k2 + Math.floor(36 * d / (d + 38));
      n += Math.floor(i / len); i %= len; out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  }
  const skeleton = t => [...t].map(c => CONF[c] || c).join("");
  const scriptsOf = l => { const set = new Set(); for (const ch of l) for (const [n, re] of SCRIPTS) if (re.test(ch)) { set.add(n); break; } return set; };
  function csvCell(v) { let s = String(v == null ? "" : v).replace(/[\r\n]+/g, " "); if (/^[=+\-@\t|%]/.test(s.trimStart())) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; }

  /** Validate a record read from localStorage; returns a safe, re-derived record or null. */
  function sanitizeRecord(o) {
    if (!o || typeof o !== "object" || typeof o.host !== "string" || !o.host || o.host.length > 253) return null;
    const sc = Number(o.score), t = Date.parse(o.date); if (!Number.isFinite(sc) || isNaN(t)) return null;
    const score = Math.max(0, Math.min(100, Math.round(sc))), b = bandOf(score), str = (v, n) => String(v == null ? "" : v).slice(0, n), num = v => Math.max(0, Math.min(100, Number(v) || 0));
    const signals = (Array.isArray(o.signals) ? o.signals : []).slice(0, 40).filter(x => x && typeof x === "object" && typeof x.title === "string").map(x => ({
      key: str(x.key, 30), category: str(x.category, 30) || "Structure", title: str(x.title, 80), reason: str(x.reason, 400), evidence: str(x.evidence, 200), action: str(x.action, 300),
      weight: num(x.weight), contribution: num(x.contribution != null ? x.contribution : x.weight), severity: ["low", "medium", "high"].includes(x.severity) ? x.severity : "low", source: x.source === "threat-list" ? "threat-list" : "heuristic" }));
    const red = typeof o.normalized === "string" ? redact(o.normalized) : "(unparseable)";
    const bd = o.hostBreakdown && typeof o.hostBreakdown === "object" ? o.hostBreakdown : {};
    return { id: /^[A-Za-z0-9-]{1,16}$/.test(String(o.id)) ? String(o.id) : "PL-" + Math.random().toString(36).slice(2, 7).toUpperCase(),
      host: str(o.host, 253), normalized: red === "(unparseable)" ? str(o.host, 253) : red, safeUrl: red === "(unparseable)" ? str(o.host, 253) : red,
      registrable: str(o.registrable || o.host, 253), protocol: str(o.protocol, 8), tld: str(o.tld, 30), subdomains: num(o.subdomains), length: Math.max(0, Number(o.length) || 0),
      score, risk: b.risk, verdict: b.label, signals, date: new Date(t).toISOString(), engine: str(o.engine, 8), decodedHost: str(o.decodedHost, 253),
      threatMatch: o.threatMatch && typeof o.threatMatch === "object" ? { domain: str(o.threatMatch.domain, 253), category: str(o.threatMatch.category, 80), source: str(o.threatMatch.source, 200) } : null,
      hostBreakdown: { subdomain: str(bd.subdomain, 253), registrable: str(bd.registrable, 253), tld: str(bd.tld, 30), port: str(bd.port, 6) },
      recommendations: (Array.isArray(o.recommendations) ? o.recommendations : []).slice(0, 8).map(x => str(x, 300)),
      checks: o.checks && Array.isArray(o.checks.notPerformed) ? { performed: (o.checks.performed || []).slice(0, 12).map(x => str(x, 80)), notApplicable: (o.checks.notApplicable || []).slice(0, 12).map(x => str(x, 120)), unavailable: (o.checks.unavailable || []).slice(0, 12).map(x => str(x, 120)), notPerformed: o.checks.notPerformed.slice(0, 12).map(x => str(x, 80)) } : null };
  }

  /** Privacy-safe plain-text report: only scheme, host and path of the URL are ever included. */
  function reportText(r) {
    const L = ["PHISHLENS — URL INSPECTION REPORT", "==================================", `Report: ${r.id}`, `Date: ${new Date(r.date).toLocaleString()}`,
      `URL (credentials, query and fragment removed): ${r.safeUrl}`, r.decodedHost && r.decodedHost !== r.host ? `Decoded hostname: ${r.decodedHost}` : null,
      `Risk score: ${r.score}/100 (heuristic priority score, not a probability)`, `Assessment: ${r.verdict}`];
    if (r.hostBreakdown) L.push("", `Host breakdown: subdomain=${r.hostBreakdown.subdomain || "—"} | registered domain=${r.hostBreakdown.registrable} | TLD=${r.hostBreakdown.tld} | port=${r.hostBreakdown.port || "default"}`);
    L.push("", "SIGNALS");
    if (!r.signals.length) L.push("No suspicious indicators detected in the checks performed.");
    for (const s of r.signals) L.push(`[+${s.contribution != null ? s.contribution : s.weight}] ${s.title} (${s.severity} severity, ${s.source === "threat-list" ? "threat list" : "heuristic"})`, `   Why: ${s.reason}`, s.evidence ? `   Evidence: ${s.evidence}` : null, s.action ? `   Action: ${s.action}` : null);
    if (r.recommendations && r.recommendations.length) L.push("", "RECOMMENDATIONS", ...r.recommendations.map(x => "- " + x));
    if (r.checks) L.push("", "CHECKS", `Performed: ${r.checks.performed.join("; ")}`, `Not applicable to this URL: ${(r.checks.notApplicable || []).join("; ") || "none"}`, `Unavailable: ${(r.checks.unavailable || []).join("; ") || "none"}`, `Not performed (local-only by design): ${r.checks.notPerformed.join("; ")}`);
    L.push("", "LIMITATIONS", "This tool never opens, fetches or contacts the URL. It scores structure only and cannot confirm a site is safe or malicious.");
    return L.filter(x => x !== null).join("\n");
  }

  /** Compare two reports by signal key. */
  function compare(a, b) {
    const ka = new Map(a.signals.map(s => [s.key, s])), kb = new Map(b.signals.map(s => [s.key, s]));
    return { scoreA: a.score, scoreB: b.score, delta: b.score - a.score, higher: a.score === b.score ? "equal" : a.score > b.score ? "a" : "b",
      shared: [...ka.keys()].filter(k => kb.has(k)).map(k => ka.get(k).title), onlyA: [...ka.keys()].filter(k => !kb.has(k)).map(k => ka.get(k).title), onlyB: [...kb.keys()].filter(k => !ka.has(k)).map(k => kb.get(k).title) };
  }
  // Local threat list: static, third-party-reported domains (built-in, with sources) plus lists the user imports. Never fetched live.
  const SEED_THREATS = [{ domain: "aladel.net", category: "malware distribution and phishing reports", source: "Symantec 'dirtiest sites' list (via Help Net Security); flagged as phishing / high risk by MalwareTips and Gridinsoft URL checks" }];
  const DOMAIN_RE = /^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
  const cleanDomain = d => String(d == null ? "" : d).trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, "").replace(/[\/?#:].*$/, "").replace(/^\*?\./, "").replace(/\.$/, "");
  const IPV4 = /^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$/;
  // Shared platforms are never imported as threats: feeds such as URLhaus list abused services (e.g. drive.google.com), and flagging a whole service would cause false alarms.
  const SHARED = ["google.com", "github.com", "github.io", "githubusercontent.com", "gitlab.com", "dropbox.com", "dropboxusercontent.com", "sharepoint.com", "1drv.ms", "amazonaws.com", "cloudfront.net", "azurewebsites.net", "windows.net", "cloudflare.com", "pages.dev", "workers.dev", "netlify.app", "vercel.app", "herokuapp.com", "firebaseapp.com", "web.app", "appspot.com", "telegram.org", "t.me", "mega.nz", "pastebin.com", "wetransfer.com", "wikipedia.org", "youtube.com", "twitter.com", "x.com", "reddit.com", "medium.com", "wordpress.com", "blogspot.com", "sourceforge.net", "archive.org"];
  const PROTECTED = new Set([...Object.values(BRANDS).flat(), ...SHARED]);
  const isProtected = d => { const p = d.split("."); for (let i = 0; i < p.length - 1; i++) if (PROTECTED.has(p.slice(i).join("."))) return true; return false; };
  let threatIdx = new Map();
  function setThreatList(list) {
    threatIdx = new Map();
    for (const x of [...SEED_THREATS, ...(Array.isArray(list) ? list.slice(0, 20000) : [])]) {
      const d = cleanDomain(x && x.domain); const builtin = SEED_THREATS.includes(x); if (!(DOMAIN_RE.test(d) || IPV4.test(d)) || threatIdx.has(d) || (!builtin && isProtected(d))) continue;
      threatIdx.set(d, { domain: d, category: String(x.category || "reported by a list you imported").slice(0, 80), source: String(x.source || "your list").slice(0, 200), builtin });
    }
  }
  function threatMatch(host) { const p = host.split("."); for (let i = 0; i < p.length - 1; i++) { const m = threatIdx.get(p.slice(i).join(".")); if (m) return m; } return null; }
  /** Parses a pasted/imported list: plain domains, "domain, category", hosts files (0.0.0.0 domain), or URL lists/CSV rows (the first URL on a line). */
  function parseThreatList(text, source) {
    const out = [], seen = new Set();
    for (const raw of String(text).split(/\r?\n/).slice(0, 200000)) {
      const l = raw.trim(); if (!l || l[0] === "#" || l[0] === ";") continue;
      let d, cat; const u = l.match(/https?:\/\/[^\s",;]+/i);
      if (u) d = u[0]; else if (/^(127\.0\.0\.1|0\.0\.0\.0)\s/.test(l)) d = l.split(/\s+/)[1]; else { const p = l.split(/[,\t]/); d = p[0]; if (p.length > 1) cat = p.slice(1).map(s => s.trim()).join(", "); }
      d = cleanDomain(d); if (!(DOMAIN_RE.test(d) || IPV4.test(d)) || seen.has(d)) continue; seen.add(d);
      out.push({ domain: d, category: (cat || "reported in an imported list").slice(0, 80), source: String(source || "your list").slice(0, 200) });
    }
    return out;
  }
  setThreatList([]);
  function bandOf(score) { const b = BANDS.find(x => score >= x[0]); return { risk: b[1], label: b[2] }; }

  /** Strip credentials, query and fragment so history/exports never store secrets. */
  function redact(href) {
    try {
      const u = new URL(href);
      return u.protocol + "//" + u.host + u.pathname + (u.search ? "?…" : "") + (u.hash ? "#…" : "");
    } catch { return "(unparseable)"; }
  }

  const RULES = [
    ["rawIp", "Direct IP address", c => c.isIp && c.host,
      "The destination is a raw IP address rather than a named domain, removing a familiar identity cue. This can be legitimate (routers, test servers).", "Ask the sender for the official domain instead of using the IP."],
    ["punycode", "Punycode hostname", c => c.host.includes("xn--") && c.host,
      "An IDN-encoded label is present. Homograph attacks use look-alike characters to imitate trusted domains.", "Type the brand's address yourself instead of following this link."],
    ["unicode", "Non-ASCII characters in the typed hostname", c => c.nonAscii && c.authority,
      "The typed address contains non-Latin or accented characters that can resemble familiar letters.", "Compare the domain character by character with the official one."],
    ["userInfo", "Credentials embedded before host", c => (c.url.username || c.url.password) && "text before @ in the address",
      "Text before the @ can display a trusted-looking name while the real host comes after it.", "Read the address after the @ — that is where the link actually goes."],
    ["shortener", "URL shortener", c => SHORTENERS.some(d => c.host === d || c.host.endsWith("." + d)) && c.host,
      "A shortening service hides the final destination until it is expanded.", "Use a link-expander or preview feature before opening."],
    ["brandBait", "Brand name on an unrelated domain", c => c.brandHost && `"${c.brandHost}" appears in ${c.host}; registered domain is ${c.reg}`,
      "The hostname uses a well-known brand name but the registered domain is not one the brand is known to use.", "Go to the brand's site by typing its address or using its app."],
    ["typosquat", "Look-alike of a known brand", c => c.typo && `"${c.typo.label}" resembles "${c.typo.brand}"`,
      "A hostname label differs from a well-known brand by a swapped or substituted character (e.g. 1 for l, rn for m).", "Do not sign in. Navigate to the real site manually."],
    ["brandPath", "Brand name only in the path", c => c.brandPath && `"${c.brandPath}" in path, domain is ${c.reg}`,
      "A brand name appears in the path of an unrelated domain, a common way to make a page look official.", "Judge the link by its domain, not by the words after it."],
    ["redirectParam", "Embedded redirect target", c => c.redirectKey,
      "The query contains a full URL in a redirect-style parameter, which can bounce you to a different site.", "Check where the link finally lands before entering any data."],
    ["credential", "Account or credential language", c => c.cred && `matched "${c.cred}"`,
      "Sign-in, verification or password wording appears. Common on real sites, but also in credential lures.", "Only enter credentials on a domain you have verified."],
    ["urgency", "Urgency or pressure wording", c => c.urg && `matched "${c.urg}"`,
      "The address contains wording meant to create urgency or fear of account loss.", "Pause: real providers rarely require action through a link."],
    ["oddPort", "Unusual destination port", c => c.url.port && !["80","443"].includes(c.url.port) && "port " + c.url.port,
      "A non-standard port is less common for ordinary public websites.", "Be cautious unless you know why this port is used."],
    ["deepSubdomain", "Deep subdomain chain", c => c.sub >= 3 && `${c.sub} subdomain levels`,
      "Long subdomain chains can bury the real registered domain behind a trusted-looking name.", "Find the last two labels before the first slash — that is the real domain."],
    ["longHost", "Unusually long hostname", c => c.host.length > 45 && `${c.host.length} characters`,
      "A very long hostname is hard to verify at a glance.", "Verify the registered domain carefully."],
    ["hyphens", "Hyphen-heavy hostname", c => (c.host.match(/-/g) || []).length >= 3 && `${(c.host.match(/-/g) || []).length} hyphens`,
      "Many hyphens are not malicious alone but are often used to build brand-like look-alikes.", "Compare with the brand's official domain."],
    ["riskyTld", "TLD often seen in abuse reports", c => RISKY_TLDS.includes(c.tld) && "." + c.tld,
      "This top-level domain appears frequently in abuse reports; TLD alone cannot establish malicious intent.", "Treat as one weak signal among others."],
    ["doubleExtension", "Double file extension", c => /\.(?:pdf|doc|docx|jpg|png|zip|exe)\.(?:php|html?|asp)$/i.test(c.url.pathname) && c.url.pathname,
      "The path looks like a document with a second web/executable extension, a way to disguise downloads.", "Do not download or open the file."],
    ["encoded", "Percent-encoded characters", c => (c.full.match(/%[0-9a-f]{2}/gi) || []).length >= 3 && `${(c.full.match(/%[0-9a-f]{2}/gi) || []).length} %XX sequences`,
      "Encoding is normal on the web but can make a destination harder to read.", "Decode the URL before trusting it."],
    ["longUrl", "Long URL", c => c.url.href.length > 120 && `${c.url.href.length} characters`,
      "Very long addresses can hide confusing parameters.", "Look at the domain, ignore the length."],
    ["http", "Unencrypted HTTP", c => c.url.protocol === "http:" && "http://",
      "Data sent to the site may not be encrypted in transit.", "Avoid entering personal data over HTTP."]
  ];


  RULES.push(
    ["obfuscatedIp", "Obfuscated IP address", c => c.obfIp, "The address was typed in a disguised numeric form (hex, octal or a single decimal number) that browsers convert to a normal IP.", "Do not open it; legitimate sites do not use disguised IPs."],
    ["mixedScript", "Mixed alphabets in one hostname label", c => c.mixed, "A label mixes writing systems (e.g. Latin with Cyrillic), the classic homograph technique.", "Do not sign in. Type the brand address yourself."],
    ["idnBrand", "International characters imitating a brand", c => c.idnBrand, "After decoding, look-alike characters from another alphabet spell a well-known brand name.", "Treat as impersonation unless you can verify the domain independently."],
    ["domainInSubdomain", "Domain name inside the subdomain", c => c.domInSub, "A familiar domain-like name (e.g. paypal.com) sits in the subdomain, so the real registered domain comes later.", "Read the address from the right: the last two labels decide the owner."],
    ["doubleEncoding", "Double URL encoding", c => /%25[0-9a-f]{2}/i.test(c.full) && "contains %25XX", "Encoded percent signs are used to slip characters past filters and hide the real target.", "Decode carefully and verify the final destination."]
  );
  function analyze(raw) {
    let input = String(raw == null ? "" : raw).trim();
    if (!input) throw new Error("Enter a URL to inspect.");
    if (input.length > 2048) throw new Error("That input is too long to inspect (limit 2048 characters).");
    if (/[\u0000-\u001f\u007f\s]/.test(input)) throw new Error("The address contains spaces or control characters.");
    if (!/^[a-zA-Z][a-zA-Z\d+.-]*:\/\//.test(input)) input = "https://" + input;
    let url;
    try { url = new URL(input); } catch { throw new Error("That address could not be parsed. Check for missing characters or spaces and try again."); }
    if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP and HTTPS addresses can be inspected.");

    const host = url.hostname.toLowerCase(), labels = host.split(".").filter(Boolean);
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.startsWith("[");
    const reg = isIp ? host : registrable(labels), tld = labels.at(-1) || "—";
    const sub = isIp ? 0 : Math.max(0, labels.length - reg.split(".").length);
    const path = (url.pathname + " " + url.search).toLowerCase(), full = url.href.toLowerCase();
    const authority = input.replace(/^[a-zA-Z][a-zA-Z\d+.-]*:\/\//, "").split(/[\/?#]/)[0].split("@").pop();
    const tokens = isIp ? [] : host.split(/[.\-_]/).filter(Boolean);
    const ctx = { url, host, labels, reg, tld, sub, isIp, full, authority, nonAscii: /[^\x00-\x7F]/.test(authority) };

    for (const b of Object.keys(BRANDS)) if (!ctx.brandHost && tokens.includes(b) && !isOfficial(b, reg)) ctx.brandHost = b;
    outer: for (const b of Object.keys(BRANDS)) {
      if (b === "bank" || isOfficial(b, reg)) continue;
      for (const label of tokens) {
        if (label === b || label.length < 5) continue;
        if (deconfuse(label) === b || (b.length >= 6 && !NO_LEV.has(b) && lev(label, b) === 1)) { ctx.typo = { label, brand: b }; break outer; }
      }
    }
    for (const b of Object.keys(BRANDS)) if (b !== "bank" && !ctx.brandPath && path.includes(b) && !isOfficial(b, reg) && !tokens.includes(b)) ctx.brandPath = b;
    for (const [k, v] of url.searchParams) if (!ctx.redirectKey && REDIRECT_KEYS.test(k) && /^https?(:|%3a)(\/\/|%2f%2f)/i.test(v)) ctx.redirectKey = 'parameter "' + k + '" holds another URL';
    if (!ctx.redirectKey && /\/https?(:\/\/|%3a%2f%2f)/i.test(url.pathname)) ctx.redirectKey = "another URL is embedded in the path";
    ctx.cred = (path + " " + host).match(/(login|signin|verify|account|password|secure|wallet|auth|update)/)?.[1];
    ctx.urg = full.match(/(urgent|immediately|suspend|limited-time|expire|locked|action-required)/)?.[1];

    const unavailable = [], regLen = reg.split(".").length, subLabels = isIp ? [] : labels.slice(0, Math.max(0, labels.length - regLen));
    const decoded = labels.map(l => { if (!l.startsWith("xn--")) return l; try { return puny(l.slice(4)); } catch { unavailable.push("Punycode decoding of " + l.slice(0, 30)); return l; } });
    ctx.decoded = decoded.join(".");
    const idnLabels = decoded.filter((l, i) => l !== labels[i]);
    for (const l of idnLabels) { const sc = scriptsOf(l); if (!ctx.mixed && sc.size > 1) ctx.mixed = `"${l}" mixes ${[...sc].join(" + ")}`;
      for (const tk of l.split("-")) { const sk = skeleton(tk); if (!ctx.idnBrand && sk !== tk && BRANDS[sk] && !isOfficial(sk, reg)) ctx.idnBrand = `"${tk}" renders like "${sk}"`; } }
    for (let i = 0; i + 1 < subLabels.length; i++) if (COMMON_TLD.has(subLabels[i + 1]) && subLabels[i].length > 1) { ctx.domInSub = `"${subLabels[i]}.${subLabels[i + 1]}" appears in the subdomain`; break; }
    const authHost = authority.replace(/:\d*$/, "").toLowerCase();
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host) && authHost !== host) ctx.obfIp = `typed as ${authHost}, resolves to ${host}`;
    if (Object.keys(BRANDS).some(b => isOfficial(b, reg))) ctx.cred = undefined; // sign-in wording on a brand's own domain is expected
    const hits = [];
    for (const [key, title, test, reason, action] of RULES) {
      const ev = test(ctx);
      if (ev) hits.push({ key, title, reason, action, weight: WEIGHTS[key], evidence: String(ev === true ? "" : ev), source: "heuristic" });
    }
    const tm = isIp ? (host[0] === "[" ? null : threatIdx.get(host) || null) : threatMatch(host);
    if (tm) hits.push({ key: "threatList", title: "Listed in local threat list", reason: `This domain is in PhishLens' local threat list (${tm.category}). The list is a static snapshot of third-party reports, not a live feed, and does not prove the site is malicious today.`,
      action: "Do not open it or enter any data. If you must investigate, use an isolated environment.", weight: WEIGHTS.threatList, evidence: `${tm.domain} — ${tm.source}`, source: "threat-list" });
    hits.sort((a, b) => b.weight - a.weight);
    for (const h of hits) h.category = CAT[h.key] || "Structure";
    const seen = {};
    for (const s of hits) {
      const fam = FAMILY[s.key] || s.key;
      s.contribution = seen[fam] ? Math.round(s.weight / 2) : s.weight;
      s.family = fam; seen[fam] = true;
      s.severity = s.weight >= 18 ? "high" : s.weight >= 10 ? "medium" : "low";
    }
    const strong = [...new Set(hits.filter(s => s.weight >= 8).map(s => s.family))];
    if (strong.length >= 3) hits.push({ key: "corroboration", title: "Multiple independent indicators", reason: "Several unrelated cue types appear together, which is more telling than any one cue alone.", action: "Treat this link as untrusted until verified through an official channel.",
      weight: 10, contribution: 10, evidence: strong.length + " independent indicator types", source: "heuristic", family: "corroboration", category: "Structure", severity: "medium" });
    const score = Math.max(tm ? 85 : 0, Math.min(100, hits.reduce((n, s) => n + s.contribution, 0)));  // a list match floors the score at 85
    const band = bandOf(score);
    return {
      id: "PL-" + Math.random().toString(36).slice(2, 7).toUpperCase(), raw: String(raw).trim(), normalized: url.href, safeUrl: redact(url.href),
      host, registrable: reg, protocol: url.protocol, tld, subdomains: sub, length: url.href.length, score, risk: band.risk, verdict: band.label,
      signals: hits, engine: "2.5", threatMatch: tm ? { domain: tm.domain, category: tm.category, source: tm.source } : null, decodedHost: ctx.decoded,
      hostBreakdown: { subdomain: subLabels.join("."), registrable: reg, tld, port: url.port },
      groups: hits.reduce((g, s) => ((g[s.category] = g[s.category] || []).push(s.key), g), {}),
      recommendations: (() => { const out = [...new Set(hits.filter(s => s.contribution > 0).slice(0, 3).map(s => s.action))];
        if (score >= 30) out.push("Do not open this link from an unsolicited message. Reach the service by typing its address or using its official app.", "If you already entered a password, change it immediately and enable multi-factor authentication.");
        else out.push("No strong structural warning signs, but verify unexpected links through a channel you trust."); return out; })(),
      checks: { performed: ["URL structure", "Hostname patterns", "Brand look-alike comparison (local list)", "Local threat list (" + threatIdx.size + " domains)"].concat(idnLabels.length || ctx.nonAscii ? ["Punycode decoding and alphabet mixing"] : []),
                notApplicable: [].concat(idnLabels.length || ctx.nonAscii ? [] : ["Alphabet mixing: no international characters present"], isIp ? ["Brand and subdomain checks: host is an IP address"] : []),
                unavailable, notPerformed: ["Domain age / WHOIS", "DNS and certificate lookup", "Live threat-intelligence feeds", "Page content"] },
      date: new Date().toISOString()
    };
  }
  const api = { parseThreatList, isProtectedDomain: isProtected, setThreatList, threatList: () => [...threatIdx.values()], cleanDomain, DOMAIN_RE, analyze, redact, bandOf, reportText, compare, csvCell, sanitizeRecord, puny, WEIGHTS, FAMILY, BANDS };
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.PhishLensEngine = api;
})(typeof window !== "undefined" ? window : globalThis);
