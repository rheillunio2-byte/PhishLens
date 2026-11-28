const test = require("node:test"), assert = require("node:assert/strict");
const { analyze, redact } = require("../engine.js");
const keys = r => r.signals.map(s => s.key);

test("plain well-known site has no signals", () => { const r = analyze("https://www.wikipedia.org/"); assert.equal(r.score, 0); assert.equal(r.risk, "safe"); });
test("legit accounts.google.com is not brand-flagged", () => { const r = analyze("https://accounts.google.com/signin"); assert.ok(!keys(r).includes("brandBait")); assert.ok(r.score < 12); });
test("pineapple.com is not 'apple'", () => assert.ok(!keys(analyze("https://pineapple.com")).includes("brandBait")));
test("brand on unrelated domain", () => assert.ok(keys(analyze("http://paypal.account-verify.example.com/login")).includes("brandBait")));
test("typosquats: digit and rn substitution", () => { assert.ok(keys(analyze("https://paypa1.com")).includes("typosquat")); assert.ok(keys(analyze("https://rnicrosoft.com")).includes("typosquat")); });
test("two-level suffix does not inflate subdomain depth", () => assert.equal(analyze("https://www.bbc.co.uk").subdomains, 1));
test("deep subdomain chain", () => assert.ok(keys(analyze("https://a.b.c.d.example.co.uk")).includes("deepSubdomain")));
test("IPv4 + port", () => { const k = keys(analyze("http://203.0.113.45:8080/verify-account")); assert.ok(k.includes("rawIp") && k.includes("oddPort")); });
test("obfuscated decimal IP is normalised and flagged", () => assert.ok(keys(analyze("http://3232235777/")).includes("rawIp")));
test("IPv6 literal flagged", () => assert.ok(keys(analyze("http://[2001:db8::1]/")).includes("rawIp")));
test("punycode flagged", () => assert.ok(keys(analyze("https://xn--pple-43d.com")).includes("punycode")));
test("Cyrillic homograph triggers unicode rule (previously dead code)", () => assert.ok(keys(analyze("https://аpple.com")).includes("unicode")));
test("idn family is de-duplicated", () => { const r = analyze("https://аpple.com"); const idn = r.signals.filter(s => s.family === "idn"); assert.ok(idn.length >= 2); assert.ok(idn.slice(1).every(s => s.contribution < s.weight)); });
test("userinfo trick", () => assert.ok(keys(analyze("https://paypal.com@evil.example/")).includes("userInfo")));
test("redirect parameter", () => assert.ok(keys(analyze("https://example.com/r?url=https://evil.example")).includes("redirectParam")));
test("encoded + long URL", () => { const k = keys(analyze("https://example.com/" + "a%20b".repeat(40))); assert.ok(k.includes("encoded") && k.includes("longUrl")); });
test("score is capped at 100 and bands are consistent", () => { const r = analyze("http://paypal-secure-login-verify.xn--pple-43d.tk:8081/urgent/login?url=http://x.y"); assert.ok(r.score <= 100); assert.ok(["high", "critical"].includes(r.risk)); });
test("every signal carries explanation fields", () => { for (const s of analyze("http://203.0.113.45:8080/login").signals) for (const f of ["title", "reason", "action", "severity", "evidence", "contribution"]) assert.ok(s[f] !== undefined, f); });
test("deterministic", () => { const u = "http://paypal.login-x.example.com/a"; assert.equal(analyze(u).score, analyze(u).score); });
test("invalid inputs throw", () => { for (const bad of ["", "   ", "javascript:alert(1)", "ftp://x.com", "http://", "ht tp://bad host"]) assert.throws(() => analyze(bad), bad); });
test("redact removes credentials, query and fragment", () => { const s = redact("https://user:pw@a.com/x?token=SECRET#frag"); assert.ok(!/pw|SECRET|frag|user/.test(s)); assert.match(s, /a\.com\/x/); });
test("report exposes safeUrl without secrets and lists unperformed checks", () => { const r = analyze("https://a.com/x?session=ABC123"); assert.ok(!r.safeUrl.includes("ABC123")); assert.ok(r.checks.notPerformed.length > 0); });

// ---- v2.1 ----
const E = require("../engine.js");
test("punycode decoder", () => { assert.equal(E.puny("pple-43d"), "\u0430pple"); assert.equal(E.puny("mnchen-3ya"), "münchen"); });
test("Cyrillic а + Latin = mixed-script and brand imitation", () => { const r = analyze("https://аpple.com"); assert.ok(keys(r).includes("mixedScript") && keys(r).includes("idnBrand")); assert.equal(r.decodedHost, "аpple.com"); });
test("all-Cyrillic 'apple' look-alike is caught by skeleton matching", () => assert.ok(keys(analyze("https://аррӏе.com")).includes("idnBrand")));
test("legitimate IDN (münchen.de, Japanese) is not treated as homograph", () => { for (const u of ["https://münchen.de", "https://例え.jp"]) { const k = keys(analyze(u)); assert.ok(!k.includes("mixedScript") && !k.includes("idnBrand"), u); } });
test("obfuscated IPs: hex, octal, decimal", () => { for (const u of ["http://0x7f000001/", "http://0177.0.0.1/", "http://2130706433/"]) assert.ok(keys(analyze(u)).includes("obfuscatedIp"), u); assert.ok(!keys(analyze("http://127.0.0.1/")).includes("obfuscatedIp")); });
test("domain inside subdomain", () => { assert.ok(keys(analyze("https://paypal.com.secure-login.example/")).includes("domainInSubdomain")); assert.ok(!keys(analyze("https://www.bbc.co.uk")).includes("domainInSubdomain")); });
test("double encoding and encoded redirect targets", () => { assert.ok(keys(analyze("https://example.com/%252e%252e/")).includes("doubleEncoding")); assert.ok(keys(analyze("https://example.com/go?next=https%253A%252F%252Fevil.example")).includes("redirectParam")); assert.ok(keys(analyze("https://example.com/redirect/https://evil.example/")).includes("redirectParam")); });
test("single %20 is not flagged as encoding abuse", () => assert.ok(!keys(analyze("https://example.com/my%20file")).includes("encoded")));
test("sign-in wording on a brand's own domain is not penalised", () => { for (const u of ["https://github.com/login", "https://login.microsoftonline.com/common/oauth2/authorize", "https://www.paypal.com/signin"]) assert.equal(analyze(u).score, 0, u); });
test("brand-adjacent real words are not typosquats", () => { for (const u of ["https://finance.example.com", "https://stream.example.com", "https://applesauce.example"]) assert.ok(!keys(analyze(u)).includes("typosquat"), u); });
test("common phishing patterns reach at least High", () => { for (const u of ["http://paypal.com.secure-login.example.tk/verify", "http://203.0.113.9:8080/paypal/login?url=http://x.example", "http://xn--pple-43d.com@bit.ly/urgent-login"]) assert.ok(["high", "critical"].includes(analyze(u).risk), u); });
test("oversized and control-character input fail gracefully", () => { assert.throws(() => analyze("https://a.com/" + "a".repeat(3000)), /too long/); assert.throws(() => analyze("https://a.com/\u0000x"), /control/); assert.throws(() => analyze("https://a.com/ x"), /spaces/); assert.throws(() => analyze(null)); assert.throws(() => analyze(undefined)); });
test("2000-character URL is handled", () => assert.ok(analyze("https://a.com/" + "a".repeat(1980)).signals.some(s => s.key === "longUrl")));
test("host breakdown and groups", () => { const r = analyze("https://www.bbc.co.uk:8443/x"); assert.deepEqual(r.hostBreakdown, { subdomain: "www", registrable: "bbc.co.uk", tld: "uk", port: "8443" }); const g = analyze("http://203.0.113.9:8080/login").groups; assert.ok(g.Identity && g.Structure); });
test("reports separate performed, not-applicable and not-performed checks", () => { const c = analyze("https://example.com").checks; assert.ok(c.performed.length && c.notApplicable.length && c.notPerformed.length && Array.isArray(c.unavailable)); });
test("reportText never leaks credentials, query or fragment", () => { const t = E.reportText(analyze("https://bob:hunter2@evil.example/p?token=SECRETX&session=S3SS#frag9")); for (const bad of ["hunter2", "bob", "SECRETX", "S3SS", "frag9"]) assert.ok(!t.includes(bad), bad); assert.match(t, /LIMITATIONS/); assert.match(t, /Not performed/); });
test("compare reports", () => { const c = E.compare(analyze("https://wikipedia.org"), analyze("http://203.0.113.9:8080/login")); assert.equal(c.higher, "b"); assert.ok(c.onlyB.length > 0 && c.delta > 0); });
test("csvCell blocks formula injection", () => { assert.equal(E.csvCell("=cmd|' /C calc'!A0"), `"'=cmd|' /C calc'!A0"`); for (const v of ["+1", "-1", "@SUM(A1)", "\t=1"]) assert.ok(E.csvCell(v).startsWith(`"'`), v); assert.equal(E.csvCell('a"b'), '"a""b"'); assert.equal(E.csvCell("x\ny"), '"x y"'); });
test("sanitizeRecord rejects garbage and clamps values", () => {
  for (const bad of [null, 5, "x", {}, { host: "a.com", score: "NaN", date: "2026-01-01" }, { host: "a.com", score: 5, date: "nope" }, { host: "x".repeat(300), score: 5, date: "2026-01-01" }]) assert.equal(E.sanitizeRecord(bad), null);
  const r = E.sanitizeRecord({ host: "a.com", score: 9999, date: "2026-01-01", normalized: "https://u:p@a.com/x?k=SECRET", signals: [{ title: "t", weight: -5 }, 7, null], risk: "<img onerror=1>" });
  assert.equal(r.score, 100); assert.equal(r.risk, "critical"); assert.ok(!r.normalized.includes("SECRET") && !r.normalized.includes("p@")); assert.equal(r.signals.length, 1); assert.equal(r.signals[0].weight, 0);
});
test("scoring is bounded across a fuzz of inputs and stays deterministic", () => { const parts = ["http://", "https://", "xn--", "paypal", "-", ".", "login", "@", ":99", "%25", "tk", "203.0.113.9", "/?url=http://a.b"]; let seed = 7; const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff; for (let i = 0; i < 300; i++) { const u = Array.from({ length: 1 + Math.floor(rnd() * 6) }, () => parts[Math.floor(rnd() * parts.length)]).join(""); try { const a = analyze(u), b = analyze(u); assert.ok(a.score >= 0 && a.score <= 100 && a.score === b.score, u); } catch (e) { assert.ok(e instanceof Error && !(e instanceof TypeError), u + " " + e); } } });

// ---- v2.5: local threat list ----
test("aladel.net is flagged Critical via the sourced local threat list, not heuristics", () => {
  const r = analyze("http://aladel.net/"); assert.equal(r.risk, "critical"); assert.ok(r.score >= 85);
  const s = r.signals.find(x => x.key === "threatList"); assert.ok(s && s.source === "threat-list" && /Symantec/.test(s.evidence)); assert.equal(r.threatMatch.domain, "aladel.net");
  assert.ok(r.checks.performed.some(c => /threat list/i.test(c)));
});
test("threat-list matching covers subdomains but not look-alike or longer names", () => {
  assert.ok(keys(analyze("https://www.aladel.net/x")).includes("threatList")); assert.ok(keys(analyze("https://sub.www.aladel.net")).includes("threatList"));
  for (const u of ["https://notaladel.net", "https://aladel.net.example.org", "https://aladel.com"]) assert.ok(!keys(analyze(u)).includes("threatList"), u);
});
test("user-supplied threat entries work, are sanitised, and built-ins survive a reset", () => {
  E.setThreatList([{ domain: "https://Evil-Test.example/path?x=1", category: "phishing" }, { domain: "not a domain" }, { domain: "<script>.com" }, null, 5]);
  assert.ok(keys(analyze("https://evil-test.example")).includes("threatList")); assert.equal(E.threatList().filter(x => !x.builtin).length, 1);
  E.setThreatList([]); assert.ok(!keys(analyze("https://evil-test.example")).includes("threatList")); assert.ok(keys(analyze("https://aladel.net")).includes("threatList"));
});
test("threat match is labelled as a static report in the exported text and survives record sanitising", () => {
  const r = analyze("https://aladel.net"), t = E.reportText(r); assert.match(t, /threat list/); assert.ok(E.sanitizeRecord(r).threatMatch.domain === "aladel.net");
  assert.ok(!E.reportText(analyze("https://aladel.net/p?token=SECRETX#f")).includes("SECRETX"));
});
test("a list match never lowers a high heuristic score", () => { E.setThreatList([{ domain: "paypa1-login.example.tk" }]); assert.ok(analyze("http://paypa1-login.example.tk:8080/verify?url=http://x.y").score >= 85); E.setThreatList([]); });

// ---- v2.6: importable feeds ----
test("parseThreatList understands plain, category, hosts-file, URL-list and CSV rows", () => {
  const text = ["# comment", "plain-one.example", "cat-two.example, phishing, kit", "0.0.0.0 hosts-three.example", "http://url-four.example/a/b.exe?x=1", '"123","2026-01-01","http://csv-five.example/p","online"', "203.0.113.9", "garbage line", "plain-one.example"].join("\n");
  const r = E.parseThreatList(text, "unit"), d = r.map(x => x.domain);
  assert.deepEqual(d, ["plain-one.example", "cat-two.example", "hosts-three.example", "url-four.example", "csv-five.example", "203.0.113.9"]);
  assert.equal(r[1].category, "phishing, kit"); assert.equal(r[0].source, "unit");
});
test("imported IPv4 hosts match, including obfuscated spellings", () => {
  E.setThreatList(E.parseThreatList("203.0.113.9\n198.51.100.7", "unit"));
  assert.ok(keys(analyze("http://203.0.113.9:8080/x")).includes("threatList")); assert.ok(keys(analyze("http://0xCB007109/")).includes("threatList")); assert.ok(!keys(analyze("http://203.0.113.10/")).includes("threatList"));
  E.setThreatList([]);
});
test("shared platforms in a feed are skipped, so drive.google.com is not flagged", () => {
  E.setThreatList(E.parseThreatList("https://drive.google.com/uc?id=1\nhttps://raw.githubusercontent.com/x/y\nreal-bad.example", "urlhaus"));
  assert.ok(E.isProtectedDomain("drive.google.com") && E.isProtectedDomain("a.b.amazonaws.com") && !E.isProtectedDomain("real-bad.example"));
  assert.equal(analyze("https://drive.google.com/file").score, 0); assert.ok(keys(analyze("https://real-bad.example")).includes("threatList")); assert.equal(E.threatList().filter(x => !x.builtin).length, 1);
  E.setThreatList([]);
});
test("large imports are bounded and fast", () => {
  const big = Array.from({ length: 30000 }, (_, i) => `bulk${i}.example`).join("\n"), t0 = Date.now();
  E.setThreatList(E.parseThreatList(big, "bulk")); assert.equal(E.threatList().filter(x => !x.builtin).length, 20000);
  assert.ok(keys(analyze("https://bulk5.example")).includes("threatList")); assert.ok(Date.now() - t0 < 2000); E.setThreatList([]);
});
