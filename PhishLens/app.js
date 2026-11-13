const $ = (s, root=document) => root.querySelector(s);
const $$ = (s, root=document) => [...root.querySelectorAll(s)];
const STORAGE_KEY = "phishlens.history.v1";
let latestReport = null;

function getHistory(){ try{return JSON.parse(localStorage.getItem(STORAGE_KEY)||"[]")}catch{return[]} }
function saveHistory(items){localStorage.setItem(STORAGE_KEY,JSON.stringify(items.slice(0,30)));updateHistoryCount()}
function updateHistoryCount(){$("#history-count").textContent=getHistory().length}
const weights = {
  rawIp:18, punycode:22, unicode:12, userInfo:22, shortener:10, brandBait:18,
  credential:10, urgency:7, oddPort:9, deepSubdomain:7, longHost:6, hyphens:5,
  riskyTld:8, doubleExtension:10, encoded:4, longUrl:4, http:4
};
function analyze(raw){
  let input=raw.trim();
  if(!/^[a-zA-Z][a-zA-Z\d+.-]*:\/\//.test(input)) input="https://"+input;
  let url;
  try{url=new URL(input)}catch{throw new Error("That address could not be parsed. Check for missing characters or spaces and try again.")}
  if(!["http:","https:"].includes(url.protocol)) throw new Error("Only HTTP and HTTPS addresses can be inspected.");
  const host=url.hostname.toLowerCase(), path=(url.pathname+" "+url.search).toLowerCase(), full=url.href.toLowerCase();
  const parts=host.split(".").filter(Boolean), tld=parts.at(-1)||"—", subdomains=Math.max(0,parts.length-2);
  const signals=[];
  const add=(key,title,reason)=>signals.push({key,title,reason,weight:weights[key]||0});
  if(/^(\d{1,3}\.){3}\d{1,3}$/.test(host))add("rawIp","Direct IP address","The destination uses an IPv4 address instead of a recognizable domain name. This can be legitimate, but it removes a familiar domain identity cue.");
  if(host.includes("xn--"))add("punycode","Punycode hostname","The hostname contains an IDN-encoded label. Homograph attacks can use visually similar characters to imitate trusted domains.");
  if(/[^\x00-\x7F]/.test(host))add("unicode","Non-ASCII hostname","The hostname contains non-ASCII characters. Some internationalized domains can resemble familiar Latin-script brands.");
  if(url.username||url.password)add("userInfo","Credentials embedded before host","The URL includes user-info before the @ symbol. Attackers can exploit this to make a misleading brand-like string appear in the address.");
  const shorteners=["bit.ly","tinyurl.com","t.co","is.gd","cutt.ly","rebrand.ly","shorturl.at","ow.ly","buff.ly","rb.gy"];
  if(shorteners.some(d=>host===d||host.endsWith("."+d)))add("shortener","URL shortener","The address uses a known shortening service, so the final destination is obscured until expanded.");
  const brands=["paypal","microsoft","apple","google","amazon","netflix","facebook","instagram","bank","steam","discord"];
  const brandWords=brands.filter(b=>host.includes(b));
  if(brandWords.length && !brandWords.some(b=>host===b+".com"||host.endsWith("."+b+".com")||host===b+".net"))add("brandBait","Brand-like wording in hostname",`The hostname contains "${brandWords[0]}" but is not an obvious canonical ${brandWords[0]} domain. Treat brand references in unrelated domains with caution.`);
  if(/(login|signin|verify|account|password|secure|wallet|auth|update)/.test(path+" "+host))add("credential","Account or credential language","The URL includes sign-in, verification, password, or account-related wording. This is common on legitimate sites too, but is frequently used in credential lures.");
  if(/(urgent|immediately|suspend|limited-time|expire|locked|action-required)/.test(full))add("urgency","Urgency or pressure wording","The address contains language designed to create urgency or fear of account loss.");
  if(url.port && !["80","443"].includes(url.port))add("oddPort","Unusual destination port",`The URL specifies port ${url.port}, which is less common for ordinary public websites.`);
  if(subdomains>=3)add("deepSubdomain","Deep subdomain chain",`The hostname has ${subdomains} subdomain levels. Long chains can bury the actual registered domain and imitate a trusted name.`);
  if(host.length>45)add("longHost","Unusually long hostname",`The hostname is ${host.length} characters long, making it harder to read and verify at a glance.`);
  if((host.match(/-/g)||[]).length>=3)add("hyphens","Hyphen-heavy hostname","Several hyphens appear in the hostname. This is not malicious by itself, but can be used to construct brand-like lookalikes.");
  if(["zip","mov","top","click","country","gq","tk","work"].includes(tld))add("riskyTld","TLD often seen in abuse reports",`The .${tld} top-level domain has appeared in abuse patterns. TLD choice alone cannot establish maliciousness.`);
  if(/\.(?:pdf|doc|docx|jpg|png|zip|exe)\.(?:php|html?|asp)$/i.test(url.pathname))add("doubleExtension","Double file extension","The path resembles a file with a second executable or web extension, a pattern sometimes used to disguise downloads.");
  if(/%[0-9a-f]{2}/i.test(full))add("encoded","Percent-encoded characters","The URL contains encoded characters. Encoding is normal on the web, but can make a destination harder to read.");
  if(url.href.length>120)add("longUrl","Long URL","The complete address is unusually long. Long query strings and paths can conceal tracking or confusing parameters.");
  if(url.protocol==="http:")add("http","Unencrypted HTTP","The URL uses HTTP rather than HTTPS. Data exchanged with the site may not be encrypted in transit.");
  const score=Math.min(100,signals.reduce((sum,s)=>sum+s.weight,0));
  const verdict=score>=60?"HIGH RISK":score>=30?"CAUTION":score>=12?"LOW CONCERN":"FEW FLAGS";
  const risk=score>=60?"high":score>=30?"medium":score>=12?"low":"safe";
  return {id:"PL-"+Math.random().toString(36).slice(2,7).toUpperCase(),raw:raw.trim(),normalized:url.href,host,protocol:url.protocol,tld,subdomains,length:url.href.length,score,verdict,risk,signals,date:new Date().toISOString()};
}

/* ---------- PhishLens UI layer (scoring logic above is unchanged from v1) ---------- */
const RULE_LABELS={rawIp:"Direct IP address",punycode:"Punycode hostname",unicode:"Non-ASCII hostname",userInfo:"Credentials before host",shortener:"URL shortener",brandBait:"Brand-like wording",credential:"Credential language",urgency:"Urgency wording",oddPort:"Unusual port",deepSubdomain:"Deep subdomain chain",longHost:"Long hostname",hyphens:"Hyphen-heavy host",riskyTld:"Abuse-prone TLD",doubleExtension:"Double file extension",encoded:"Percent-encoding",longUrl:"Long URL",http:"Unencrypted HTTP"};
const reduceMotion=matchMedia("(prefers-reduced-motion: reduce)").matches;
const sev=w=>w>=18?"high":w>=10?"medium":"low";
const riskOf=s=>s>=60?"high":s>=30?"medium":s>=12?"low":"safe";
const title=s=>s.charAt(0)+s.slice(1).toLowerCase();
let busy=false;

function moveIndicator(){const a=$(".nav-link.active"),n=$("#nav");if(!a)return;n.style.setProperty("--x",a.offsetLeft+"px");n.style.setProperty("--w",a.offsetWidth+"px")}
function switchView(name,push=true){
  if(!$(`#view-${name}`))name="inspect";
  $$(".view").forEach(v=>v.classList.toggle("active",v.id===`view-${name}`));
  $$(".nav-link").forEach(b=>{const on=b.dataset.view===name;b.classList.toggle("active",on);on?b.setAttribute("aria-current","page"):b.removeAttribute("aria-current")});
  $("#nav").classList.remove("open");$("#mobile-menu").setAttribute("aria-expanded","false");
  if(push&&location.hash!=="#"+name)history.pushState(null,"","#"+name);
  if(name==="history")renderHistory();
  moveIndicator();window.scrollTo({top:0});
}
$$(".nav-link").forEach(b=>b.addEventListener("click",()=>switchView(b.dataset.view)));
addEventListener("popstate",()=>switchView(location.hash.slice(1)||"inspect",false));
addEventListener("resize",moveIndicator);
$("#mobile-menu").addEventListener("click",()=>{const o=$("#nav").classList.toggle("open");$("#mobile-menu").setAttribute("aria-expanded",o)});

function setMsg(text,cls=""){const m=$("#input-msg");m.textContent=text;m.className="input-msg "+cls;$("#input-wrap").classList.toggle("bad",cls==="bad");$("#url-input").toggleAttribute("aria-invalid",cls==="bad")}
const IDLE="Analysis runs locally. No page is opened, fetched or contacted.";
$("#url-input").addEventListener("input",e=>{
  const v=e.target.value.trim();if(!v)return setMsg(IDLE);
  try{analyze(v);setMsg("Looks like a valid address. Press Analyze to inspect it.","good")}catch{setMsg("Keep typing — this address can't be parsed yet.")}
});

function countUp(el,to){if(reduceMotion){el.textContent=to;return}const t0=performance.now();(function f(t){const k=Math.min(1,(t-t0)/1100);el.textContent=Math.round(to*(1-Math.pow(1-k,3)));if(k<1)requestAnimationFrame(f)})(t0)}

function runScan(raw){
  if(busy)return;
  if(!raw.trim())return setMsg("Enter a URL to inspect.","bad"),$("#url-input").focus();
  let report;try{report=analyze(raw)}catch(err){setMsg(err.message,"bad");return $("#url-input").focus()}
  setMsg(IDLE);busy=true;$("#scan-btn").disabled=true;$("#scanner").classList.add("scanning");
  const u=new URL(report.normalized),parts=[u.protocol+"//",u.host,u.pathname+u.search+u.hash];
  $("#tokens").innerHTML=parts.map(p=>`<span>${escapeHtml(p)}</span>`).join("");
  const progress=$("#scan-progress");progress.classList.remove("hidden");$("#results").classList.add("hidden");
  const bar=$("#progress-bar"),pct=$("#progress-percent"),steps=[1,2,3,4].map(i=>$("#step-"+i)),toks=$$("#tokens span"),dur=reduceMotion?60:1800,t0=performance.now();
  (function tick(now){
    const p=Math.min(1,(now-t0)/dur),n=Math.round(p*100);
    bar.style.width=n+"%";pct.textContent=n+"%";
    steps.forEach((s,i)=>s.classList.toggle("done",p>=i*.25));
    toks.forEach((t,i)=>t.classList.toggle("on",p>=i*.25&&p<(i+1)*.25+.25));
    if(p<1)return requestAnimationFrame(tick);
    progress.classList.add("hidden");$("#scanner").classList.remove("scanning");busy=false;$("#scan-btn").disabled=false;
    renderReport(report);showResults();
  })(t0);
}
function showResults(){const r=$("#results");r.classList.remove("hidden");r.scrollIntoView({behavior:reduceMotion?"auto":"smooth",block:"start"})}

function renderReport(r,save=true){
  latestReport=r;const risk=r.risk||riskOf(r.score);
  $("#verdict-card").className="card verdict risk-"+risk;
  $("#report-id").textContent=r.id;$("#report-url").textContent=r.normalized;$("#report-date").textContent=new Date(r.date).toLocaleString();
  const g=$("#gauge-value");g.style.strokeDashoffset=283;requestAnimationFrame(()=>requestAnimationFrame(()=>{g.style.strokeDashoffset=283-283*r.score/100}));
  countUp($("#score"),r.score);$("#verdict").textContent=title(r.verdict);
  $("#verdict-copy").textContent=r.score>=60?"Multiple strong warning signs were detected. Avoid entering credentials or downloading files from this destination.":r.score>=30?"Several indicators deserve a closer look. Verify the domain independently before sharing information.":r.score>=12?"A few cautionary patterns were detected. Check the exact hostname and context before proceeding.":"No major patterns from this rule set were detected. This is not proof that the destination is safe.";
  $("#host-value").textContent=r.host;$("#protocol").textContent=r.protocol.replace(":","").toUpperCase();$("#tld-value").textContent="."+r.tld;$("#sub-value").textContent=r.subdomains;$("#length-value").textContent=r.length+" chars";$("#https-value").textContent=r.protocol==="https:"?"Yes":"No";
  $("#domain-name").textContent=r.signals.length?"Score composition: each segment is one triggered rule.":"No rules contributed to the score.";
  $("#compose").innerHTML=r.signals.map(s=>`<i class="sev-${sev(s.weight)}" style="flex:${s.weight}" title="${escapeHtml(s.title)} +${s.weight}"></i>`).join("");
  $("#signal-count").textContent=`${r.signals.length} signal${r.signals.length===1?"":"s"}`;
  $("#signal-summary").textContent=r.signals.length?`${r.signals.length} indicator${r.signals.length===1?"":"s"} worth reviewing. Each one explains why it matters.`:"No notable patterns detected";
  $("#signal-list").innerHTML=r.signals.length?r.signals.map((s,i)=>`<article class="sig sev-${sev(s.weight)}" style="--i:${i}"><div class="sig-top"><strong>${escapeHtml(s.title)}</strong><span class="w">+${s.weight}</span></div><span class="sev">${sev(s.weight)} severity</span><p>${escapeHtml(s.reason)}</p><div class="sig-bar"><i style="width:${Math.round(s.weight/22*100)}%"></i></div></article>`).join(""):`<div class="empty-sig">No rules were triggered. Remember: unknown threats may not match these patterns.</div>`;
  if(save){const h=getHistory();h.unshift(r);saveHistory(h)}
}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
$("#scan-form").addEventListener("submit",e=>{e.preventDefault();runScan($("#url-input").value)});
$$(".sample").forEach(b=>b.addEventListener("click",()=>{$("#url-input").value=b.dataset.url;runScan(b.dataset.url)}));
$("#new-scan").addEventListener("click",()=>{$("#scanner").scrollIntoView({behavior:"smooth"});$("#url-input").select()});

function renderHistory(){
  const items=getHistory(),flagged=items.filter(r=>r.score>=30).length;
  $("#hist-stats").innerHTML=`<span class="chip">${items.length} investigation${items.length===1?"":"s"}</span><span class="chip">${flagged} flagged</span>`;
  $("#clear-history").hidden=!items.length;
  const host=$("#history-list");
  if(!items.length){host.innerHTML=`<div class="empty"><img src="assets/illustrations/empty-history.svg" alt="" width="220" height="165"><h3>No investigations yet</h3><p>URLs you inspect will appear here.</p><button class="btn" id="go-inspect">Start an inspection</button></div>`;$("#go-inspect").addEventListener("click",()=>switchView("inspect"));return}
  host.innerHTML=items.map((r,i)=>`<div class="entry risk-${r.risk||riskOf(r.score)}"><div class="ring" style="--p:${r.score}"><b>${r.score}</b></div><div class="h"><strong>${escapeHtml(r.host)}</strong><small>${escapeHtml(r.normalized)}</small></div><span class="v">${title(r.verdict)}</span><span class="d">${new Date(r.date).toLocaleDateString()}<br>${new Date(r.date).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"})}</span><button class="btn ghost" data-index="${i}" aria-label="Open report for ${escapeHtml(r.host)}">View report</button></div>`).join("");
  $$("[data-index]",host).forEach(b=>b.addEventListener("click",()=>{renderReport(items[Number(b.dataset.index)],false);switchView("inspect");showResults()}));
}
$("#clear-history").addEventListener("click",()=>$("#confirm").showModal());
$("#confirm").addEventListener("close",e=>{if(e.target.returnValue==="yes"){saveHistory([]);renderHistory()}});

$("#export-report").addEventListener("click",()=>{
  if(!latestReport)return;const r=latestReport;
  const lines=["PHISHLENS — URL INSPECTION REPORT","==================================",`Report: ${r.id}`,`Date: ${new Date(r.date).toLocaleString()}`,`Submitted URL: ${r.raw}`,`Normalized URL: ${r.normalized}`,`Risk score: ${r.score}/100`,`Assessment: ${r.verdict}`,"","SIGNALS","-------",...(r.signals.length?r.signals.map(s=>`[+${s.weight}] ${s.title}\n${s.reason}`):["No configured heuristic rules were triggered."]),"","LIMITATION","This report is based on local URL heuristics only. It is not a live reputation check and does not prove a URL is safe or malicious."];
  const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([lines.join("\n")],{type:"text/plain"}));a.download=`PhishLens-${r.id}.txt`;a.click();URL.revokeObjectURL(a.href);
});

$("#rules").innerHTML=Object.entries(weights).sort((a,b)=>b[1]-a[1]).map(([k,w])=>`<div class="rule sev-${sev(w)}"><span>${RULE_LABELS[k]}</span><i style="--w:${Math.round(w/22*100)}%"></i><span>+${w}</span></div>`).join("");
updateHistoryCount();
switchView(location.hash.slice(1)||"inspect",false);
document.fonts?.ready.then(moveIndicator);
