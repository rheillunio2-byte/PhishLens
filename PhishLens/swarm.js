/* PhishLens hero swarm — a lean vanilla port of React Bits SwarmCursor: instanced WebGL2 particles that orbit the cursor,
   stream behind fast movement, burst on click, and roam when the pointer is away. Decorative only; no network, no fluid solver. */
(() => {
  "use strict";
  const hero = document.querySelector(".hero");
  if (!hero || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const cv = document.createElement("canvas"); cv.className = "swarm"; cv.setAttribute("aria-hidden", "true"); hero.prepend(cv);
  const gl = cv.getContext("webgl2", { alpha: true, premultipliedAlpha: true, antialias: false, depth: false, stencil: false });
  if (!gl) { cv.remove(); return; }
  const sh = (t, src) => { const s = gl.createShader(t); gl.shaderSource(s, src); gl.compileShader(s); return gl.getShaderParameter(s, gl.COMPILE_STATUS) ? s : null; };
  const vs = sh(gl.VERTEX_SHADER, `#version 300 es
layout(location=0) in vec2 aC; layout(location=1) in vec4 aP; layout(location=2) in float aT;
uniform vec2 uV; out vec2 vC; out float vA; out float vT;
void main(){ float r=aP.z*1.6; vec2 p=aP.xy+aC*r; vC=aC*1.6; vA=aP.w; vT=aT; gl_Position=vec4(p.x/uV.x*2.0-1.0, 1.0-p.y/uV.y*2.0, 0.0, 1.0); }`);
  const fs = sh(gl.FRAGMENT_SHADER, `#version 300 es
precision mediump float; uniform vec3 uA; uniform vec3 uB; in vec2 vC; in float vA; in float vT; out vec4 o;
void main(){ float c=1.0-smoothstep(0.55,1.0,length(vC)); float a=c*vA; o=vec4(mix(uA,uB,vT)*a,a); }`);
  const pg = gl.createProgram(); if (!vs || !fs) { cv.remove(); return; }
  gl.attachShader(pg, vs); gl.attachShader(pg, fs); gl.linkProgram(pg);
  if (!gl.getProgramParameter(pg, gl.LINK_STATUS)) { cv.remove(); return; }
  const uV = gl.getUniformLocation(pg, "uV"), uA = gl.getUniformLocation(pg, "uA"), uB = gl.getUniformLocation(pg, "uB");
  const N = innerWidth < 700 ? 220 : 480, SIZE = 2.4, SPREAD = 90, SWIRL = .6, TAIL = .5, WANDER = .5, DEPTH = .7;
  const vao = gl.createVertexArray(); gl.bindVertexArray(vao);
  const corner = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, corner); gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
  gl.enableVertexAttribArray(0); gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
  const inst = new Float32Array(N * 4), tint = new Float32Array(N);
  const inBuf = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, inBuf); gl.bufferData(gl.ARRAY_BUFFER, inst.byteLength, gl.DYNAMIC_DRAW);
  gl.enableVertexAttribArray(1); gl.vertexAttribPointer(1, 4, gl.FLOAT, false, 0, 0); gl.vertexAttribDivisor(1, 1);
  const tBuf = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, tBuf); gl.bufferData(gl.ARRAY_BUFFER, tint.byteLength, gl.DYNAMIC_DRAW);
  gl.enableVertexAttribArray(2); gl.vertexAttribPointer(2, 1, gl.FLOAT, false, 0, 0); gl.vertexAttribDivisor(2, 1);
  gl.bindVertexArray(null);

  let seed = 7; const rnd = () => ((seed ^= seed << 13, seed ^= seed >>> 17, seed ^= seed << 5) >>> 0) / 4294967296;
  const px = new Float32Array(N), py = new Float32Array(N), vx = new Float32Array(N), vy = new Float32Array(N),
    home = new Float32Array(N), ph = new Float32Array(N), grain = new Float32Array(N), rate = new Float32Array(N);
  for (let i = 0; i < N; i++) { home[i] = .1 + .9 * Math.sqrt(rnd()); ph[i] = rnd() * 6.283; grain[i] = .55 + rnd() * .9; rate[i] = .5 + rnd() * 1.1; }
  let W = 1, H = 1, ratio = 1, t = 0, intro = 0, flash = 9, raf = 0, last = 0, visible = true, ax = 0, ay = 0, pax = 0, pay = 0, amx = 0, amy = 0, presence = 0;
  const ptr = { x: 0, y: 0, in: false };
  const clamp = (v, a, b) => Math.min(b, Math.max(a, v));

  function resize() {
    W = Math.max(1, hero.clientWidth); H = Math.max(1, hero.clientHeight); ratio = Math.min(devicePixelRatio || 1, 1.5);
    cv.width = Math.round(W * ratio); cv.height = Math.round(H * ratio);
    if (!t) for (let i = 0; i < N; i++) { px[i] = rnd() * W; py[i] = rnd() * H; }
    ax = pax = W * .6; ay = pay = H * .5; wake();
  }
  function frame(now) {
    raf = 0; if (!visible || document.hidden) return;
    const dt = last ? clamp((now - last) / 1000, .001, 1 / 30) : 1 / 60; last = now; t += dt; flash += dt; intro = Math.min(1, intro + dt / 1.4);
    const e = intro * intro * (3 - 2 * intro), live = ptr.in;
    const gx = live ? ptr.x : W * (.62 + .2 * Math.sin(t * .21) + .05 * Math.sin(t * .53 + 1.7)), gy = live ? ptr.y : H * (.5 + .22 * Math.sin(t * .29 + .8));
    presence += (1 - presence) * (1 - Math.exp(-dt / .4));
    ax += (gx - ax) * (1 - Math.exp(-dt * 12)); ay += (gy - ay) * (1 - Math.exp(-dt * 12));
    const bl = 1 - Math.exp(-dt * 20); amx += ((ax - pax) / dt - amx) * bl; amy += ((ay - pay) / dt - amy) * bl; pax = ax; pay = ay;
    const k = 14 * (1 - .6 * TAIL) * (.2 + .8 * e), sw = SWIRL * 300 * (.3 + .7 * e), damp = Math.exp(-dt * 2.6), zr = SPREAD * .55;
    const flashK = flash < 1.2 ? Math.exp(-flash / .3) : 0;
    for (let i = 0; i < N; i++) {
      const dx = px[i] - ax, dy = py[i] - ay, d = Math.hypot(dx, dy) + .001, ux = dx / d, uy = dy / d, off = d - home[i] * SPREAD, edge = Math.min(1, d / (SPREAD * .5));
      let fx = -ux * off * k - uy * sw * edge + amx * TAIL * .9 * (1 - home[i] * .5);
      let fy = -uy * off * k + ux * sw * edge + amy * TAIL * .9 * (1 - home[i] * .5);
      fx += Math.sin(t * .9 + ph[i] * 3 + py[i] * .02) * WANDER * 70; fy += Math.cos(t * .8 + ph[i] * 2 + px[i] * .02) * WANDER * 70;
      vx[i] = (vx[i] + fx * dt) * damp; vy[i] = (vy[i] + fy * dt) * damp; px[i] += vx[i] * dt; py[i] += vy[i] * dt;
      const sp = Math.hypot(vx[i], vy[i]), near = clamp(Math.sin(t * rate[i] + ph[i]), -1, 1);
      const o = i * 4; inst[o] = px[i]; inst[o + 1] = py[i]; inst[o + 2] = SIZE * grain[i] * (1 + DEPTH * .6 * near);
      inst[o + 3] = clamp(.8 * (1 - DEPTH * .45 * Math.max(0, -near)) * (.86 + .14 * Math.sin(t * 3.1 + ph[i] * 9)), 0, 1) * e * presence * .75;
      tint[i] = Math.max(clamp((sp - 380) / 900, 0, 1), flashK);
    }
    gl.viewport(0, 0, cv.width, cv.height); gl.clearColor(0, 0, 0, 0); gl.clear(gl.COLOR_BUFFER_BIT);
    gl.useProgram(pg); gl.enable(gl.BLEND); gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA); gl.bindVertexArray(vao);
    gl.bindBuffer(gl.ARRAY_BUFFER, inBuf); gl.bufferSubData(gl.ARRAY_BUFFER, 0, inst);
    gl.bindBuffer(gl.ARRAY_BUFFER, tBuf); gl.bufferSubData(gl.ARRAY_BUFFER, 0, tint);
    gl.uniform2f(uV, W, H); gl.uniform3f(uA, .22, .74, .97); gl.uniform3f(uB, .65, .55, .98);   // cyan -> violet when particles rush
    gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, N); gl.bindVertexArray(null);
    raf = requestAnimationFrame(frame);
  }
  function wake() { if (!raf && visible && !document.hidden) { last = 0; raf = requestAnimationFrame(frame); } }

  const locate = ev => { const r = hero.getBoundingClientRect(), x = ev.clientX - r.left, y = ev.clientY - r.top; return { x, y, in: x >= 0 && y >= 0 && x <= r.width && y <= r.height }; };
  if (matchMedia("(hover:hover) and (pointer:fine)").matches) {
    addEventListener("pointermove", e => { Object.assign(ptr, locate(e)); }, { passive: true });
    document.documentElement.addEventListener("pointerleave", () => { ptr.in = false; });
  }
  addEventListener("pointerdown", e => {            // click burst: splash outward in a curl
    const p = locate(e); if (!p.in || e.target.closest("a,button,input,select,textarea")) return;
    flash = 0; const reachOut = SPREAD * 2.2;
    for (let i = 0; i < N; i++) { const dx = px[i] - p.x, dy = py[i] - p.y, d = Math.hypot(dx, dy) || 1; if (d > reachOut) continue;
      const kk = (1 - d / reachOut) * 780 * (.6 + .4 * grain[i]); vx[i] += dx / d * kk - dy / d * kk * .35; vy[i] += dy / d * kk + dx / d * kk * .35; }
  }, { passive: true });
  new ResizeObserver(resize).observe(hero);
  new IntersectionObserver(en => { visible = en.some(x => x.isIntersecting); if (visible) wake(); }).observe(hero);
  document.addEventListener("visibilitychange", wake);
  resize();
})();
