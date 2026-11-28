const $ = (s, root=document) => root.querySelector(s);
const $$ = (s, root=document) => [...root.querySelectorAll(s)];
const STORAGE_KEY = "phishlens.history.v1";
let latestReport = null;

function getHistory(){ try{const a=JSON.parse(localStorage.getItem(STORAGE_KEY)||"[]");return Array.isArray(a)?a.slice(0,100).map(sanitizeRecord).filter(Boolean):[]}catch{return[]} }
const toStored=r=>{const{raw,...rest}=r;return{...rest,normalized:r.safeUrl||redact(r.normalized)}};
function saveHistory(items){localStorage.setItem(STORAGE_KEY,JSON.stringify(items.slice(0,100).map(toStored)));updateHistoryCount()}
const picked=new Set();
function toast(m){const t=$("#toast");t.textContent=m;clearTimeout(toast.t);toast.t=setTimeout(()=>t.textContent="",2500)}
function updateHistoryCount(){$("#history-count").textContent=getHistory().length}
const { analyze, redact, bandOf, reportText, compare, csvCell, sanitizeRecord, WEIGHTS: weights } = PhishLensEngine;

/* ---------- PhishLens UI layer (scoring logic above is unchanged from v1) ---------- */
const RULE_LABELS={rawIp:"Direct IP address",punycode:"Punycode hostname",unicode:"Non-ASCII hostname",userInfo:"Credentials before host",shortener:"URL shortener",brandBait:"Brand-like wording",credential:"Credential language",urgency:"Urgency wording",oddPort:"Unusual port",deepSubdomain:"Deep subdomain chain",longHost:"Long hostname",hyphens:"Hyphen-heavy host",riskyTld:"Abuse-prone TLD",doubleExtension:"Double file extension",encoded:"Percent-encoding",longUrl:"Long URL",http:"Unencrypted HTTP",typosquat:"Brand look-alike",brandPath:"Brand in path",redirectParam:"Embedded redirect",obfuscatedIp:"Obfuscated IP",mixedScript:"Mixed alphabets",idnBrand:"IDN brand imitation",domainInSubdomain:"Domain in subdomain",doubleEncoding:"Double encoding",threatList:"Local threat list match"};
const reduceMotion=matchMedia("(prefers-reduced-motion: reduce)").matches;
const sev=w=>w>=18?"high":w>=10?"medium":"low";
const riskOf=s=>bandOf(s).risk;
const css=k=>k==="critical"?"high":k;
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
  latestReport=r;const risk=css(r.risk||riskOf(r.score));
  $("#verdict-card").className="card verdict risk-"+risk;
  $("#report-id").textContent=r.id;$("#report-url").textContent=r.normalized;$("#report-date").textContent=new Date(r.date).toLocaleString();
  const g=$("#gauge-value");g.style.strokeDashoffset=283;requestAnimationFrame(()=>requestAnimationFrame(()=>{g.style.strokeDashoffset=283-283*r.score/100}));
  countUp($("#score"),r.score);$("#verdict").textContent=r.verdict.charAt(0)+r.verdict.slice(1).toLowerCase();
  $("#verdict-copy").textContent=r.score>=80?"Critical: several strong warning signs were found. Do not enter credentials or open files from this destination.":r.score>=60?"Multiple strong warning signs were detected. Avoid entering credentials or downloading files from this destination.":r.score>=30?"Several indicators deserve a closer look. Verify the domain independently before sharing information.":r.score>=12?"A few cautionary patterns were detected. Check the exact hostname and context before proceeding.":"No suspicious indicators detected in the checks performed. This is not proof that the destination is safe.";
  $("#host-value").textContent=r.host;$("#protocol").textContent=r.protocol.replace(":","").toUpperCase();$("#tld-value").textContent="."+r.tld;$("#sub-value").textContent=r.subdomains;$("#length-value").textContent=r.length+" chars";$("#https-value").textContent=r.protocol==="https:"?"Yes":"No";
  $("#domain-name").textContent=(r.signals.length?"Score composition: each segment is one triggered rule. ":"No rules contributed to the score. ")+(r.checks?"Not checked: "+r.checks.notPerformed.join(", ")+".":"");
  $("#compose").innerHTML=r.signals.map(s=>`<i class="sev-${sev(s.weight)}" style="flex:${s.contribution??s.weight}" title="${escapeHtml(s.title)} +${s.contribution??s.weight}"></i>`).join("");
  $("#signal-count").textContent=`${r.signals.length} signal${r.signals.length===1?"":"s"}`;
  $("#signal-summary").textContent=r.signals.length?`${r.signals.length} indicator${r.signals.length===1?"":"s"} worth reviewing. Each one explains why it matters.`:"No notable patterns detected";
  const ordered=[...r.signals].sort((a,b)=>(a.category||"").localeCompare(b.category||"")||b.contribution-a.contribution);
  $("#signal-list").innerHTML=r.signals.length?ordered.map((s,i)=>`<article class="sig sev-${sev(s.weight)}" style="--i:${i}"><div class="sig-top"><strong>${escapeHtml(s.title)}</strong><span class="w">+${s.contribution??s.weight}</span></div><span class="sev">${sev(s.weight)} severity · ${s.source==="threat-list"?"threat list":"heuristic"}</span><p>${escapeHtml(s.reason)}</p>${s.evidence?`<p class="mono small">Evidence: ${escapeHtml(s.evidence)}</p>`:""}${s.action?`<p class="small"><b>Suggested action:</b> ${escapeHtml(s.action)}</p>`:""}<div class="sig-bar"><i style="width:${Math.round(s.weight/22*100)}%"></i></div></article>`).join(""):`<div class="empty-sig">No rules were triggered. Remember: unknown threats may not match these patterns.</div>`;
  $("#confidence").textContent=r.threatMatch?"Basis: local threat list (static third-party reports), plus heuristics":"Confidence: heuristic, explainable";
  if(r.threatMatch)$("#verdict-copy").textContent="This domain is in the local threat list of third-party reports. Do not open it, enter credentials, or download files from it.";
  const ib=$("#intel-banner");if(ib){ib.hidden=!r.threatMatch;ib.innerHTML=r.threatMatch?`<span class="pulse" aria-hidden="true"></span><div><b>Matched the local threat list</b><br><span>${escapeHtml(r.threatMatch.domain)} — ${escapeHtml(r.threatMatch.category)}. Source: ${escapeHtml(r.threatMatch.source)}. This is a static third-party snapshot, not a live verdict.</span></div>`:""}
  let last="";$$("#signal-list .sig").forEach((el,i)=>{const c=ordered[i].category||"Structure";if(c!==last){el.insertAdjacentHTML("beforebegin",`<h4 class="cat">${escapeHtml(c)}</h4>`);last=c}});
  if(r.decodedHost&&r.decodedHost!==r.host)$("#host-value").textContent=r.host+" (decoded: "+r.decodedHost+")";
  const hb=r.hostBreakdown,li=a=>(a&&a.length?a.map(x=>`<li>${escapeHtml(x)}</li>`).join(""):"<li>None</li>");
  $("#report-extras").innerHTML=`<h3>Next steps</h3><ul class="list">${li(r.recommendations)}</ul>`+(hb?`<h3>Hostname breakdown</h3><dl class="kv"><div><dt>Subdomain</dt><dd class="mono">${escapeHtml(hb.subdomain||"—")}</dd></div><div><dt>Registered domain</dt><dd class="mono">${escapeHtml(hb.registrable)}</dd></div><div><dt>TLD</dt><dd class="mono">.${escapeHtml(hb.tld)}</dd></div><div><dt>Port</dt><dd class="mono">${escapeHtml(hb.port||"default")}</dd></div></dl>`:"")+(r.checks?`<h3>Checks</h3><p class="small"><b>Performed:</b></p><ul class="list">${li(r.checks.performed)}</ul><p class="small"><b>Not applicable to this URL:</b></p><ul class="list">${li(r.checks.notApplicable)}</ul><p class="small"><b>Unavailable:</b></p><ul class="list">${li(r.checks.unavailable)}</ul><p class="small"><b>Not performed (local-only by design):</b></p><ul class="list">${li(r.checks.notPerformed)}</ul>`:"");
  if(save){const h=getHistory();h.unshift(r);saveHistory(h)}
}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
$("#scan-form").addEventListener("submit",e=>{e.preventDefault();runScan($("#url-input").value)});
$$(".sample").forEach(b=>b.addEventListener("click",()=>{$("#url-input").value=b.dataset.url;runScan(b.dataset.url)}));
$("#new-scan").addEventListener("click",()=>{$("#scanner").scrollIntoView({behavior:"smooth"});$("#url-input").select()});

function renderHistory(){
  const all=getHistory(),q=($("#hist-search").value||"").trim().toLowerCase(),f=$("#hist-filter").value;
  const items=all.filter(r=>(!q||(r.host+" "+r.normalized).toLowerCase().includes(q))&&(!f||(r.risk||riskOf(r.score))===f));
  const SORTS={new:(a,b)=>Date.parse(b.date)-Date.parse(a.date),old:(a,b)=>Date.parse(a.date)-Date.parse(b.date),hi:(a,b)=>b.score-a.score,lo:(a,b)=>a.score-b.score};items.sort(SORTS[$("#hist-sort").value]||SORTS.new);
  const flagged=items.filter(r=>r.score>=30).length;
  $("#hist-stats").innerHTML=`<span class="chip">${items.length} investigation${items.length===1?"":"s"}</span><span class="chip">${flagged} flagged</span>`;
  $("#clear-history").hidden=!all.length;$("#export-csv").hidden=!all.length;
  const host=$("#history-list");
  if(!items.length){host.innerHTML=`<div class="empty"><img src="assets/illustrations/empty-history.svg" alt="" width="220" height="165"><h3>No investigations yet</h3><p>URLs you inspect will appear here.</p><button class="btn" id="go-inspect">Start an inspection</button></div>`;$("#go-inspect").addEventListener("click",()=>switchView("inspect"));return}
  host.innerHTML=items.map(r=>{const k=css(r.risk||riskOf(r.score)),id=escapeHtml(r.id),d=new Date(r.date);return `<div class="entry risk-${k}"><label class="pick"><input type="checkbox" data-pick="${id}" ${picked.has(r.id)?"checked":""} aria-label="Select ${escapeHtml(r.host)} for comparison"></label><div class="ring" style="--p:${r.score}"><b>${r.score}</b></div><div class="h"><strong>${escapeHtml(r.host)}</strong><small>${escapeHtml(r.normalized)}</small></div><span class="v">${escapeHtml(r.verdict)}</span><span class="d">${d.toLocaleDateString()}<br>${d.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"})}</span><button class="btn ghost" data-open="${id}" aria-label="Open report for ${escapeHtml(r.host)}">View report</button><button class="btn ghost danger" data-del="${id}" aria-label="Delete ${escapeHtml(r.host)} from history">Delete</button></div>`}).join("");
  $$("[data-open]",host).forEach(b=>b.addEventListener("click",()=>{const r=getHistory().find(x=>x.id===b.dataset.open);if(r){renderReport(r,false);switchView("inspect");showResults()}}));
  $$("[data-del]",host).forEach(b=>b.addEventListener("click",()=>{picked.delete(b.dataset.del);saveHistory(getHistory().filter(x=>x.id!==b.dataset.del));renderHistory();toast("Entry deleted")}));
  $$("[data-pick]",host).forEach(b=>b.addEventListener("change",()=>{if(b.checked){picked.add(b.dataset.pick);if(picked.size>2)picked.delete(picked.values().next().value)}else picked.delete(b.dataset.pick);renderHistory()}));
  $("#compare-btn").disabled=picked.size!==2;$("#compare-btn").textContent=`Compare (${picked.size}/2)`;
}
["input","change"].forEach(ev=>{["#hist-search","#hist-filter","#hist-sort"].forEach(s=>$(s).addEventListener(ev,renderHistory))});
$("#export-csv").addEventListener("click",()=>{const rows=[["date","host","url_redacted","score","risk","signals"],...getHistory().map(r=>[r.date,r.host,r.normalized,r.score,r.verdict,r.signals.map(s=>s.title).join("; ")])];
  const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([rows.map(x=>x.map(csvCell).join(",")).join("\n")],{type:"text/csv"}));a.download="phishlens-history.csv";a.click();URL.revokeObjectURL(a.href)});
$("#clear-history").addEventListener("click",()=>$("#confirm").showModal());
$("#confirm").addEventListener("close",e=>{if(e.target.returnValue==="yes"){saveHistory([]);renderHistory()}});

$("#export-report").addEventListener("click",()=>{if(!latestReport)return;const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([reportText(latestReport)],{type:"text/plain"}));a.download=`PhishLens-${latestReport.id}.txt`;a.click();URL.revokeObjectURL(a.href)});
$("#copy-report").addEventListener("click",async()=>{if(!latestReport)return;try{await navigator.clipboard.writeText(reportText(latestReport));toast("Redacted report copied")}catch{toast("Copy blocked by the browser; use Export instead")}});
$("#print-report").addEventListener("click",()=>window.print());
$("#compare-btn").addEventListener("click",()=>{const [a,b]=[...picked].map(id=>getHistory().find(x=>x.id===id));if(!a||!b)return;const c=compare(a,b),li=x=>x.length?x.map(t=>`<li>${escapeHtml(t)}</li>`).join(""):"<li>None</li>";
  const col=(r,n)=>`<div class="cmp-col risk-${css(r.risk)}"><h4>${n}: ${escapeHtml(r.host)}</h4><p class="mono small">${escapeHtml(r.normalized)}</p><p><b>${r.score}</b>/100 · ${escapeHtml(r.verdict)}</p></div>`;
  $("#compare-body").innerHTML=`<div class="cmp">${col(a,"A")}${col(b,"B")}</div><p>${c.higher==="equal"?"Both reports have the same score.":`Report ${c.higher.toUpperCase()} scores ${Math.abs(c.delta)} points higher. Scores are heuristic priorities, not probabilities.`}</p><h4>Only in A</h4><ul class="list">${li(c.onlyA)}</ul><h4>Only in B</h4><ul class="list">${li(c.onlyB)}</ul><h4>In both</h4><ul class="list">${li(c.shared)}</ul>`;$("#compare-dialog").showModal()});
$$(".sample").forEach(b=>b.addEventListener("click",()=>{$("#sample-note").textContent="What this shows: "+(b.dataset.note||"")}));
document.addEventListener("keydown",e=>{if(e.key==="Escape"&&$("#nav").classList.contains("open")){$("#nav").classList.remove("open");$("#mobile-menu").setAttribute("aria-expanded","false");$("#mobile-menu").focus()}});

$("#rules").innerHTML=Object.entries(weights).sort((a,b)=>b[1]-a[1]).map(([k,w])=>`<div class="rule sev-${sev(w)}"><span>${RULE_LABELS[k]}</span><i style="--w:${Math.round(w/22*100)}%"></i><span>+${w}</span></div>`).join("");
updateHistoryCount();
switchView(location.hash.slice(1)||"inspect",false);
document.fonts?.ready.then(moveIndicator);

/* ---- v2.2 polish: tooltips, scanner focus state, button ripple ---- */
(()=>{const tips={"Hostname":"The full host the link points to","Subdomain depth":"Labels before the registered domain","HTTPS":"Whether the connection would be encrypted","Top-level domain":"The final label of the hostname"};
$$(".dest dt, #view-inspect dl dt").forEach(d=>{const t=tips[d.textContent.trim()];if(t){d.dataset.tip=t;d.tabIndex=0}});
const w=$("#input-wrap");$("#url-input").addEventListener("focus",()=>w.classList.add("focus"));$("#url-input").addEventListener("blur",()=>w.classList.remove("focus"));
document.addEventListener("pointerdown",e=>{const b=e.target.closest(".btn");if(!b||matchMedia("(prefers-reduced-motion:reduce)").matches)return;const r=b.getBoundingClientRect();b.style.setProperty("--rx",e.clientX-r.left+"px");b.style.setProperty("--ry",e.clientY-r.top+"px");b.classList.remove("rip");void b.offsetWidth;b.classList.add("rip")});
const t=$("#toast");new MutationObserver(()=>t.classList.toggle("ok",/copied|deleted/i.test(t.textContent))).observe(t,{childList:true});})();
