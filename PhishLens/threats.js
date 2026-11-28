/* Local threat list manager: add/import/export/clear domains. Stored only in this browser (localStorage); nothing is uploaded. */
(() => {
  "use strict";
  const E = window.PhishLensEngine, $ = s => document.querySelector(s), KEY = "phishlens.threats.v1";
  if (!E || !$("#threat-card")) return;
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const msg = t => { $("#threat-msg").textContent = t; };
  let mine = []; try { const a = JSON.parse(localStorage.getItem(KEY) || "[]"); if (Array.isArray(a)) mine = a.filter(x => x && typeof x.domain === "string").slice(0, 20000); } catch { mine = []; }
  const save = () => { try { localStorage.setItem(KEY, JSON.stringify(mine)); } catch { msg("Could not save (storage is full or blocked)."); } };
  function apply() {
    E.setThreatList(mine); const all = E.threatList(), yours = all.filter(x => !x.builtin).length;
    $("#threat-builtin").innerHTML = all.filter(x => x.builtin).map(x => `<li><b class="mono">${esc(x.domain)}</b> — ${esc(x.category)} <span class="muted small">(built-in. Source: ${esc(x.source)})</span></li>`).join("") + `<li class="muted small">${yours} domain${yours === 1 ? "" : "s"} from your own lists.</li>`;
  }
  const parse = (text, src) => E.parseThreatList(text, src);
  function add(items) {
    const prot = items.filter(it => E.isProtectedDomain(it.domain)).length; items = items.filter(it => !E.isProtectedDomain(it.domain));
    const have = new Set(mine.map(x => x.domain)); let n = 0;
    for (const it of items) if (!have.has(it.domain) && mine.length < 20000) { mine.push(it); have.add(it.domain); n++; }
    save(); apply(); msg((n ? `Added ${n} entr${n === 1 ? "y" : "ies"}. New scans will use them.` : "Nothing new added: entries were invalid, duplicates, or already built in.") + (prot ? ` ${prot} shared-platform entr${prot === 1 ? "y was" : "ies were"} skipped (flagging a whole service such as Google Drive would cause false alarms).` : ""));
  }
  $("#threat-add").addEventListener("click", () => { add(parse($("#threat-input").value, "added by you")); $("#threat-input").value = ""; });
  $("#threat-file").addEventListener("change", e => {
    const f = e.target.files[0]; e.target.value = ""; if (!f) return;
    if (f.size > 5e6) return msg("That file is larger than 5 MB; split it and import in parts.");
    const r = new FileReader(); r.onload = () => add(parse(r.result, "imported: " + f.name.slice(0, 60))); r.onerror = () => msg("The file could not be read."); r.readAsText(f);
  });
  $("#threat-export").addEventListener("click", () => {
    const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([E.threatList().map(x => `${x.domain}, ${x.category}`).join("\n")], { type: "text/plain" }));
    a.download = "phishlens-threat-list.txt"; a.click(); URL.revokeObjectURL(a.href);
  });
  $("#threat-clear").addEventListener("click", () => { if (!mine.length) return msg("Your list is already empty."); if (confirm("Remove all domains you added? Built-in entries stay.")) { mine = []; save(); apply(); msg("Your list was cleared."); } });
  apply();
})();
