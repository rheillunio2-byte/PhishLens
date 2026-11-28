/* PhishLens motion layer — vanilla adaptations of React Bits-style effects (BlurText, DecryptedText, Magnet, SpotlightCard,
   GlareHover, FadeContent, CountUp, Aurora/Particles). No dependencies, no network; all effects respect prefers-reduced-motion. */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const RM = matchMedia("(prefers-reduced-motion: reduce)"), fine = matchMedia("(hover:hover) and (pointer:fine)"), motion = () => !RM.matches;

  // BlurText: hero words resolve from blur one by one (the gradient line animates as a whole to keep its text gradient intact).
  const h1 = $(".hero h1");
  if (h1 && motion()) {
    h1.setAttribute("aria-label", $$("span", h1).map(x => x.textContent.trim()).filter(Boolean).join(" "));
    let n = 0;
    $$("span:not(.grad)", h1).forEach(sp => { const t = sp.textContent; sp.textContent = "";
      t.split(/(\s+)/).forEach(p => { if (!p.trim()) return sp.append(" ");
        const w = document.createElement("span"); w.className = "bw"; w.setAttribute("aria-hidden", "true"); w.style.setProperty("--i", n++); w.textContent = p; sp.append(w); }); });
  }

  // DecryptedText on the verdict + a one-shot risk-specific animation on its card. The final text is always the real verdict.
  const v = $("#verdict");
  if (v) {
    let busy = false;
    new MutationObserver(() => {
      const card = v.closest(".verdict") || v.closest(".card");
      if (card) { card.classList.remove("play"); void card.offsetWidth; card.classList.add("play"); }
      if (busy || !motion() || !v.textContent) return;
      busy = true; const fin = v.textContent, g = "01<>/#$%"; let f = 0;
      const id = setInterval(() => { f++;
        v.textContent = [...fin].map((c, i) => c === " " || i < fin.length * f / 14 ? c : g[Math.random() * g.length | 0]).join("");
        if (f >= 14) { clearInterval(id); v.textContent = fin; setTimeout(() => busy = false, 0); } }, 32);
    }).observe(v, { childList: true, characterData: true, subtree: true });
  }

  // Magnet (port of React Bits Magnet): spring-driven pull toward the pointer inside `padding` px; the nearest magnet wins.
  const mags = []; let ptr = null, raf = 0, last = 0;
  const smooth = (a, b, x) => { const t = Math.min(1, Math.max(0, (x - a) / (b - a))); return t * t * (3 - 2 * t); };
  const reach = (r, p) => { const dx = p.x - (r.left + r.width / 2), dy = p.y - (r.top + r.height / 2);
    return { dx, dy, out: Math.hypot(Math.max(0, Math.abs(dx) - r.width / 2), Math.max(0, Math.abs(dy) - r.height / 2)) }; };
  function tick(now) {
    raf = 0; const dt = last ? Math.min((now - last) / 1000, 1 / 30) : 1 / 60; last = now;
    let best = null, bo = 1e9;
    if (ptr && motion()) for (const m of mags) { const r = m.el.getBoundingClientRect(); if (!r.width) continue; m.n = reach(r, ptr); if (m.n.out <= m.pad && m.n.out < bo) { bo = m.n.out; best = m; } }
    let busy = false;
    for (const m of mags) {
      let tx = 0, ty = 0;
      if (m === best) { const pull = 1 - smooth(m.pad * .5, m.pad, m.n.out); tx = m.n.dx / m.k * pull; ty = m.n.dy / m.k * pull;
        const L = Math.hypot(tx, ty); if (L > m.max) { tx *= m.max / L; ty *= m.max / L; } }
      const steps = Math.ceil(dt * 120);
      for (let i = 0; i < steps; i++) { const h = dt / steps; m.vx += (170 * (tx - m.x) - 16 * m.vx) * h; m.vy += (170 * (ty - m.y) - 16 * m.vy) * h; m.x += m.vx * h; m.y += m.vy * h; }
      if (Math.abs(tx - m.x) < .05 && Math.abs(ty - m.y) < .05 && Math.abs(m.vx) < .05 && Math.abs(m.vy) < .05) { m.x = tx; m.y = ty; m.vx = m.vy = 0; } else busy = true;
      m.el.style.translate = m.x || m.y ? `${m.x.toFixed(2)}px ${m.y.toFixed(2)}px` : "";
      m.el.toggleAttribute("data-magnet-active", m === best);
    }
    if (busy) raf = requestAnimationFrame(tick); else last = 0;
  }
  const wake = () => { if (!raf) raf = requestAnimationFrame(tick); };
  if (fine.matches) {
    $$("[data-magnet]").forEach(el => mags.push({ el, pad: 100, k: +el.dataset.magnet || 2, max: 14, x: 0, y: 0, vx: 0, vy: 0 }));
    addEventListener("pointermove", e => { if (e.pointerType !== "touch") { ptr = { x: e.clientX, y: e.clientY }; wake(); } }, { passive: true });
    addEventListener("scroll", wake, { passive: true, capture: true });
    document.documentElement.addEventListener("pointerleave", () => { ptr = null; wake(); });
  }

  // SpotlightCard: a soft light follows the pointer across cards (CSS draws it from --sx/--sy).
  document.addEventListener("pointermove", e => {
    if (!fine.matches || !motion()) return;
    const el = e.target.closest && e.target.closest(".card,.entry,.sig"); if (!el) return;
    const r = el.getBoundingClientRect(); el.style.setProperty("--sx", e.clientX - r.left + "px"); el.style.setProperty("--sy", e.clientY - r.top + "px");
  }, { passive: true });

  // FadeContent: methodology cards, empty states and footer fade in as they scroll into view.
  if ("IntersectionObserver" in window && motion()) {
    const io = new IntersectionObserver(es => es.forEach(x => { if (x.isIntersecting) { x.target.classList.add("in"); io.unobserve(x.target); } }), { threshold: .1 });
    const add = () => $$("#view-method .card,#view-history .empty,footer").forEach(el => { if (!el.dataset.rv) { el.dataset.rv = 1; el.classList.add("rv"); io.observe(el); } });
    add(); new MutationObserver(add).observe($("main"), { childList: true, subtree: true });
  }

  // CountUp for the history statistics (real counts only).
  const hs = $("#hist-stats");
  if (hs) {
    let b = false;
    new MutationObserver(() => {
      if (b || !motion()) return; b = true;
      $$(".chip", hs).forEach(c => { const m = c.textContent.match(/^(\d+)(.*)$/); if (!m || +m[1] === 0) return; const n = +m[1], t0 = performance.now();
        (function f(t) { const p = Math.min(1, (t - t0) / 600); c.textContent = Math.round(n * (1 - Math.pow(1 - p, 3))) + m[2]; if (p < 1) requestAnimationFrame(f); })(t0); });
      setTimeout(() => b = false, 700);
    }).observe(hs, { childList: true });
  }

  // Scan beam: a light sweeps the input only while a real analysis is running (tied to the .scanning state set by app.js).
  const iw = $(".input-wrap"); if (iw) iw.insertAdjacentHTML("beforeend", '<span class="beam" aria-hidden="true"></span>');
  // Hero art parallax: the shield drifts slightly against the pointer.
  const art = $(".hero-art");
  if (art && fine.matches) addEventListener("pointermove", e => { if (!motion()) return; const x = e.clientX / innerWidth - .5, y = e.clientY / innerHeight - .5;
    art.style.translate = `${(-x * 16).toFixed(1)}px ${(-y * 10).toFixed(1)}px`; art.style.rotate = `${(x * 2).toFixed(2)}deg`; }, { passive: true });

  // Aurora + a few floating motes (CSS-only animation, paused when the tab is hidden).
  const bg = $(".bg");
  if (bg && motion()) {
    bg.insertAdjacentHTML("beforeend", '<div class="aurora"><i></i><i></i></div><div class="motes">' +
      Array.from({ length: 14 }, (_, i) => `<i style="left:${(i * 37 + 11) % 100}%;--d:${16 + (i * 5) % 14}s;--w:${-(i * 3)}s;--s:${2 + i % 3}px"></i>`).join("") + "</div>");
    document.addEventListener("visibilitychange", () => document.documentElement.classList.toggle("paused", document.hidden));
  }
})();
