"use strict";
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const H = { "X-DepGate": "1" };
  let st = null, current = decodeURIComponent(location.hash.slice(1)) || "", pollT = null;
  const state = { q: "", sev: "", dev: true };

  // ---------- tiny DOM helper (text only: never innerHTML with data) ----------
  function el(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === "class") e.className = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? "" : v);
    }
    for (const k of kids.flat(Infinity)) {
      if (k == null || k === false) continue;
      e.append(k instanceof Node ? k : document.createTextNode(String(k)));
    }
    return e;
  }
  const safeURL = (u) => /^https:\/\//.test(u || "") ? u : null;

  function toast(msg) {
    const t = $("#toast"); t.textContent = msg; t.classList.add("on");
    clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove("on"), 1600);
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); toast("Kopyalandı"); }
    catch { const ta = el("textarea", null, text); document.body.append(ta); ta.select(); document.execCommand("copy"); ta.remove(); toast("Kopyalandı"); }
  }
  const copyBtn = (text, label = "Kopyala") => el("button", { class: "small", onclick: () => copy(text) }, label);

  // ---------- theme ----------
  const root = document.documentElement;
  try { const t = localStorage.getItem("depgate-theme"); if (t) root.dataset.theme = t; } catch {}
  $("#theme").addEventListener("click", () => {
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("depgate-theme", root.dataset.theme); } catch {}
  });

  // ---------- labels ----------
  const NEED = {
    now: ["DƏRHAL", "bad"], soon: ["Bəli, növbəti baxımda", "warn"], plan: ["Təcili deyil, planla", ""],
    optional: ["İstəyə görə", "good"], none: ["Lazım deyil", "good"],
  };
  const NEED_VULN_NOW = "Bəli, təcili";
  const IMPACT = { no: ["Xeyr", "good"], maybe: ["Ola bilər", "warn"], yes: ["Bəli", "bad"], unknown: ["Bilinmir", "warn"] };
  const GROUPS = [
    ["now_easy", "İndi et — kod dəyişmir", true],
    ["now_code", "İndi et — kod dəyişir", true],
    ["plan", "Planla", false],
    ["optional", "İstəyə görə", false],
    ["ok", "Lazım deyil", false],
  ];
  const STRAT = { upgrade: "Yenilə", relock: "Yalnız lockfile-ı yenilə", parent: "Valideyn paketi yenilə", override: "Override (müvəqqəti)", remove: "Sil" };
  const pad = (n) => String(n).padStart(2, "0");
  const fmtTime = (s) => { const d = new Date(s); return isNaN(d) ? s : `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`; };

  // ---------- data ----------
  async function api(method, path, body) {
    const r = await fetch(path, { method, headers: body ? { ...H, "Content-Type": "application/json" } : H, body: body ? JSON.stringify(body) : undefined });
    let data = null; try { data = await r.json(); } catch {}
    if (!r.ok) throw new Error((data && data.error) || "HTTP " + r.status);
    return data;
  }
  async function load() {
    setState(await api("GET", "api/state"));
  }
  function setState(s) {
    st = s;
    if (!st.projects.some((p) => p.dir === current)) current = st.projects.length ? st.projects[0].dir : "";
    render();
    clearTimeout(pollT);
    if (st.busy) pollT = setTimeout(() => load().catch(() => {}), 1200);
  }
  async function scan(dirs) {
    try { setState(await api("POST", "api/scan", { dirs })); toast(dirs.length ? "Skan başladı" : "Bütün layihələr skan olunur"); }
    catch (e) { toast("Xəta: " + e.message); }
  }
  async function removeProject(p) {
    if (!confirm(`«${p.name}» siyahıdan silinsin? (layihə fayllarına toxunulmur)`)) return;
    try { setState(await api("POST", "api/projects/remove", { dir: p.dir })); toast("Silindi"); }
    catch (e) { toast("Xəta: " + e.message); }
  }
  function select(dir) { current = dir; history.replaceState(null, "", "#" + encodeURIComponent(dir)); render(); window.scrollTo(0, 0); }

  $("#scanall").addEventListener("click", () => scan([]));
  $("#addproj").addEventListener("click", () => openPicker(""));

  // ---------- render ----------
  function counts(r) {
    const s = (r && r.summary) || {};
    return { urgent: (s.now_easy || 0) + (s.now_code || 0), plan: s.plan || 0, mal: s.malware || 0 };
  }
  function render() {
    const ps = st.projects || [];
    $("#meta").textContent = [st.tool, st.lastScan ? "son skan " + fmtTime(st.lastScan) : null, st.offline ? "offline (keşdən)" : null, st.readOnly ? "yalnız baxış" : null].filter(Boolean).join(" · ");
    $("#scanall").hidden = st.readOnly || ps.length === 0;
    $("#addproj").hidden = st.readOnly;
    $("#scanall").disabled = st.busy;
    $("#scanall").textContent = st.busy ? "Skan olunur…" : "Hamısını skan et";

    const nav = $("#projects");
    nav.hidden = ps.length === 0;
    nav.replaceChildren(el("h2", null, `Layihələr (${ps.length})`), ...ps.map((p) => {
      const c = counts(p.report);
      const busy = p.scanning || p.queued;
      return el("button", { class: "proj" + (p.dir === current ? " active" : ""), title: p.dir, onclick: () => select(p.dir) },
        el("span", { class: "nm" }, p.name),
        busy ? el("span", { class: "spin", "aria-label": "skan olunur" }) :
          !p.report ? el("span", { class: "cnt" }, "—") :
          el("span", { class: "cnt" }, c.mal ? el("b", null, "!" + c.mal + " ") : null, c.urgent ? el("b", null, c.urgent) : "0", " · ", c.plan));
    }));

    const mal = ps.reduce((n, p) => n + counts(p.report).mal, 0);
    const ban = $("#banner");
    if (mal) { ban.hidden = false; ban.className = "banner"; ban.textContent = `Zərərli paket tapıldı (${mal}) — qırmızı kartdakı təlimata indi əməl et.`; }
    else if (st.errors && st.errors.length) { ban.hidden = false; ban.className = "banner warn"; ban.textContent = "Bəzi mənbələr yüklənmədi: " + st.errors.join(" · "); }
    else ban.hidden = true;

    const main = $("#main");
    if (!ps.length) { main.replaceChildren(welcome()); return; }
    const p = ps.find((x) => x.dir === current) || ps[0];
    main.replaceChildren(projectView(p));
  }

  function welcome() {
    return el("div", { class: "welcome" },
      el("h1", null, "DepGate-ə xoş gəldin"),
      el("p", null, "Node.js layihələrini əlavə et: DepGate hər paket üçün iki suala cavab verəcək — yeniləmək lazımdır? koda təsir edir?"),
      el("p", { class: "quiet" }, "Layihə siyahısı və son hesabatlar yadda saxlanır; növbəti dəfə açanda hamısı yerində olacaq."),
      st.readOnly ? null : el("button", { class: "primary big", onclick: () => openPicker("") }, "+ Layihə əlavə et"),
      st.container ? el("p", { class: "quiet" }, "Docker-də işləyir: yalnız konteynerə bağlanmış qovluqlar görünür (" + (st.roots || []).join(", ") + "). Başqa qovluq lazımdırsa, docker-compose.yml-də volume əlavə et.") : null);
  }

  function projectView(p) {
    const bar = el("div", { class: "pbar" },
      el("div", { class: "pdir", title: p.dir }, p.dir),
      p.scanning ? el("span", { class: "chip busy" }, el("span", { class: "spin" }), " skan olunur…") : p.queued ? el("span", { class: "chip busy" }, "növbədə…") : null,
      st.readOnly ? null : el("button", { class: "small", disabled: p.scanning || p.queued || undefined, onclick: () => scan([p.dir]) }, "Skan et"),
      st.readOnly ? null : el("button", { class: "small ghost danger", onclick: () => removeProject(p) }, "Siyahıdan sil"));
    if (!p.report) {
      return el("div", null, bar, el("div", { class: "empty" }, el("h1", null, p.name), p.scanning || p.queued ? "İlk skan gedir — bir neçə saniyə…" : "Hələ skan olunmayıb."));
    }
    return el("div", null, bar, project(p.report));
  }

  // ---------- folder picker ----------
  let picker = null;
  function closePicker() { if (picker) { picker.remove(); picker = null; document.removeEventListener("keydown", escClose); } }
  function escClose(e) { if (e.key === "Escape") closePicker(); }
  async function openPicker(path) {
    let l;
    try { l = await api("GET", "api/browse?path=" + encodeURIComponent(path)); }
    catch (e) { toast("Xəta: " + e.message); return; }
    const add = async (dir, btn) => {
      if (btn) { btn.disabled = true; btn.textContent = "Əlavə olunur…"; }
      try {
        const r = await api("POST", "api/projects", { path: dir });
        closePicker();
        const first = (r.added || [])[0];
        if (first) current = first;
        setState(r.state);
        toast((r.added || []).length > 1 ? `${r.added.length} layihə əlavə olundu, skan gedir` : "Əlavə olundu, skan gedir");
      } catch (e) { toast("Xəta: " + e.message); if (btn) { btn.disabled = false; btn.textContent = "Əlavə et"; } }
    };
    const crumbs = el("div", { class: "crumbs" },
      (st.roots || []).length > 1 ? el("button", { class: "link", onclick: () => openPicker("") }, "Köklər") : null,
      (l.crumbs || []).map((c, i) => [i || (st.roots || []).length > 1 ? el("span", { class: "sep" }, "/") : null,
        el("button", { class: "link", onclick: () => openPicker(c.path) }, c.name)]));
    const list = el("div", { class: "flist" },
      l.parent ? el("div", { class: "frow" }, el("button", { class: "fname", onclick: () => openPicker(l.parent) }, "↩ ..")) : null,
      (l.entries || []).length ? l.entries.map((e) => el("div", { class: "frow" },
        el("button", { class: "fname", onclick: () => openPicker(e.path), title: e.path }, el("span", { class: "ficon" + (e.isProject ? " proj" : "") }), e.name),
        e.isProject ? el("span", { class: "chip" }, "layihə") : null,
        e.isProject && !e.lockfile ? el("span", { class: "chip warn" }, "lockfile yoxdur") : null,
        e.added ? el("span", { class: "chip ok" }, "əlavə olunub") : null,
        e.isProject ? el("button", { class: "small", onclick: (ev) => add(e.path, ev.currentTarget) }, e.added ? "Yenidən skan" : "Əlavə et") : null))
        : el("div", { class: "quiet pad" }, "Bu qovluqda alt qovluq yoxdur."));
    const foot = el("div", { class: "pfoot" },
      el("div", { class: "quiet" }, l.path ? "Seçilmiş qovluq: " + l.path : "Kök qovluqlardan birini seç"),
      el("span", { class: "grow" }),
      el("button", { onclick: closePicker }, "Bağla"),
      l.path ? el("button", { class: "primary", onclick: (ev) => add(l.path, ev.currentTarget), title: "Bu qovluğu və altındakı bütün layihələri əlavə et" }, l.project ? "Bu layihəni əlavə et" : "Bu qovluqdakı layihələri əlavə et") : null);
    const dlg = el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": "Layihə əlavə et" },
      el("div", { class: "mhead" }, el("div", { class: "h3" }, "Layihə əlavə et"), el("div", { class: "quiet" }, "Qovluqları gəz; package.json olanlar «layihə» kimi işarələnib. Monorepo seçsən, alt layihələrin hamısı əlavə olunur.")),
      crumbs, list, foot);
    const ov = el("div", { class: "overlay", onclick: (e) => { if (e.target === ov) closePicker(); } }, dlg);
    closePicker();
    picker = ov;
    document.body.append(ov);
    document.addEventListener("keydown", escClose);
    const firstBtn = ov.querySelector(".fname"); if (firstBtn) firstBtn.focus();
  }

  function project(p) {
    const s = p.summary || {};
    const tile = (n, l, cls, grp) => el("div", { class: "tile " + cls + (n ? "" : " zero"), onclick: () => { const d = document.getElementById("g-" + grp); if (d) { d.open = true; d.scrollIntoView({ behavior: "smooth" }); } } },
      el("div", { class: "n" }, n || 0), el("div", { class: "l" }, l));
    const sub = [p.node && p.node.version ? "Node " + p.node.version : p.node && p.node.line ? "Node " + p.node.line : null,
      p.manager, (p.packages || 0) + " paket", p.lockfile || "lockfile yoxdur", p.repo].filter(Boolean).join(" · ");
    const head = el("div", { class: "phead" },
      el("div", null, el("h1", null, p.name), el("div", { class: "sub" }, sub),
        p.approximate ? el("div", { class: "sub warntext" }, "Təxmini rejim: lockfile yoxdur, versiyalar aralığın minimumudur, dolayı paketlər yoxlanmayıb.") : null),
      el("div", { class: "tiles" },
        tile(s.now_easy, "Kod dəyişmir", "easy", "now_easy"), tile(s.now_code, "Kod dəyişir", "code", "now_code"),
        tile(s.plan, "Planla", "", "plan"), tile(s.optional, "İstəyə görə", "", "optional"), tile(s.ok, "Lazım deyil", "", "ok")));

    const toolbar = el("div", { class: "toolbar" },
      el("input", { type: "search", placeholder: "Paket axtar…", value: state.q, oninput: (e) => { state.q = e.target.value; rerenderGroups(); } }),
      el("select", { onchange: (e) => { state.sev = e.target.value; rerenderGroups(); } },
        ...[["", "Bütün severity"], ["critical", "critical"], ["high", "high+"], ["moderate", "moderate+"]].map(([v, l]) => el("option", { value: v, selected: state.sev === v }, l))),
      el("label", null, el("input", { type: "checkbox", checked: state.dev, onchange: (e) => { state.dev = e.target.checked; rerenderGroups(); } }), "devDependencies"));

    const groups = el("div");
    function rerenderGroups() { groups.replaceChildren(...renderGroups(p)); }
    rerenderGroups();

    return el("div", null, head,
      el("div", { class: "side" }, nodeCard(p), hygieneCard(p)),
      toolbar, groups,
      p.errors && p.errors.length ? el("details", { class: "errs" }, el("summary", null, `Xəbərdarlıqlar (${p.errors.length})`), el("ul", null, p.errors.map((e) => el("li", null, e)))) : null);
  }

  const SEVR = { critical: 4, high: 3, moderate: 2, low: 1 };
  function visible(f) {
    if (!state.dev && f.dev) return false;
    if (state.q && !f.pkg.toLowerCase().includes(state.q.toLowerCase())) return false;
    if (state.sev && (f.kind !== "vuln" && f.kind !== "malware" || (SEVR[f.severity] || 0) < SEVR[state.sev])) return false;
    return true;
  }

  function renderGroups(p) {
    const out = [];
    for (const [g, title, open] of GROUPS) {
      const fs = (p.findings || []).filter((f) => f.group === g && visible(f));
      if (!fs.length) continue;
      const body = [];
      if (g === "now_easy") {
        const cmd = bulkCommand(fs, p.manager);
        if (cmd) body.push(el("div", { class: "bulk" }, el("code", null, cmd), copyBtn(cmd)));
      }
      if (g === "ok") body.push(el("div", { class: "oklist" }, fs.map((f) => el("div", null, `${f.pkg}@${f.current}`))));
      else body.push(fs.map((f) => card(f, p)));
      out.push(el("details", { class: "grp", id: "g-" + g, open: open || undefined },
        el("summary", null, title, el("span", { class: "c" }, `(${fs.length})`)), body));
    }
    if (!out.length) out.push(el("div", { class: "empty" }, "Süzgəcə uyğun paket yoxdur."));
    return out;
  }

  // one command for all simple upgrades of the group
  function bulkCommand(fs, mgr) {
    const specs = [], other = [];
    for (const f of fs) {
      if (f.fix && f.fix.strategy === "upgrade" && f.target && !f.dev) specs.push(`${f.pkg}@${f.target}`);
      else if (f.fix && f.fix.command && f.fix.strategy !== "override") other.push(f.fix.command);
    }
    if (!specs.length) return other.length > 1 ? other.join(" && ") : "";
    const base = { pnpm: "pnpm up", yarn: "yarn up", yarn1: "yarn upgrade", bun: "bun add", npm: "npm install" }[mgr] || "npm install";
    return [base + " " + specs.join(" "), ...other].join(" && ");
  }

  function card(f, p) {
    const vuln = f.kind === "vuln" || f.kind === "malware";
    let needTxt = (NEED[f.needUpdate] || NEED.none)[0];
    if (f.kind === "vuln" && f.needUpdate === "now") needTxt = NEED_VULN_NOW;
    const needCls = (NEED[f.needUpdate] || NEED.none)[1];
    const [impTxt, impCls] = IMPACT[f.codeImpact] || IMPACT.unknown;
    const cls = "card" + (f.kind === "malware" ? " mal bad" : "");
    const title = el("div", { class: "ctitle" },
      el("span", { class: "pkg" }, f.pkg),
      el("span", { class: "ver" }, f.current, f.target ? [el("span", { class: "arr" }, "→"), f.target] : null),
      f.severity ? el("span", { class: "chip sev-" + f.severity }, f.kind === "malware" ? "ZƏRƏRLİ" : f.severity) : null,
      el("span", { class: "chip" }, f.direct ? "birbaşa" : "dolayı"),
      f.dev ? el("span", { class: "chip" }, "dev") : null,
      vuln ? el("span", { class: "chip prio", title: "Prioritet balı (0–100)" }, "P" + f.priority) : null,
      f.latest && f.latest !== f.target && f.latest !== f.current ? el("span", { class: "chip", title: "Ən son versiya" }, "son: " + f.latest) : null);

    const kids = [title];
    if (f.title) kids.push(el("div", { class: "ctext" }, f.title));
    if (f.chain && f.chain.length > 1) kids.push(el("div", { class: "chain" }, f.chain.join(" → ")));
    kids.push(el("div", { class: "q" }, el("span", { class: "dot " + needCls }), el("span", { class: "lbl" }, "① Yeniləmək lazımdır?"), el("span", { class: "ans" }, needTxt)));
    if (f.why && f.why.length) kids.push(el("ul", { class: "why" }, f.why.map((w) => el("li", null, w))));
    kids.push(el("div", { class: "q" }, el("span", { class: "dot " + impCls }), el("span", { class: "lbl" }, "② Koda təsir edir?"), el("span", { class: "ans" }, impTxt)));
    if (f.impactWhy && f.impactWhy.length) kids.push(el("ul", { class: "why" }, f.impactWhy.map((w) => el("li", null, w))));
    if (f.warnings && f.warnings.length) kids.push(el("div", { class: "warnbox" }, f.warnings.map((w) => el("div", null, "⚠ " + w))));
    if (f.fix) {
      const fx = f.fix;
      kids.push(el("div", { class: "fix" },
        el("div", { class: "row" }, el("span", { class: "chip" }, STRAT[fx.strategy] || fx.strategy), fx.command ? el("code", null, fx.command) : el("span", { class: "grow" }), fx.command && !/\s«/.test(fx.command) ? copyBtn(fx.command) : null),
        fx.snippet ? el("pre", null, (fx.file ? "// " + fx.file + "\n" : "") + fx.snippet) : null,
        fx.note ? el("div", { class: "note" }, fx.note) : null));
    }
    const foot = el("div", { class: "cfoot" });
    if (f.advisories && f.advisories.length) {
      foot.append(el("div", { class: "advs" }, f.advisories.slice(0, 6).map((a) => {
        const u = safeURL(a.url);
        const label = a.id + (a.kev ? " · KEV" : "") + (a.fixed ? " · düzəliş " + a.fixed : "");
        return u ? el("a", { href: u, target: "_blank", rel: "noopener noreferrer" }, label) : el("span", null, label);
      }), f.advisories.length > 6 ? `+${f.advisories.length - 6}` : null));
    }
    foot.append(el("span", { class: "grow" }), copyBtn(agentTask(f, p), "Claude Code üçün tapşırıq"));
    kids.push(foot);
    return el("div", { class: cls }, kids);
  }

  function agentTask(f, p) {
    const L = [];
    L.push(`Layihə: ${p.name} (${p.dir})`);
    L.push(`Paket: ${f.pkg} ${f.current}${f.target ? " → " + f.target : ""} (${f.direct ? "birbaşa" : "dolayı: " + (f.chain || []).join(" → ")}${f.dev ? ", devDependency" : ""})`);
    if (f.advisories && f.advisories.length) L.push("Advisory: " + f.advisories.map((a) => `${a.id}${a.severity ? " (" + a.severity + ")" : ""}${a.url ? " " + a.url : ""}`).join("; "));
    L.push("Niyə: " + (f.why || []).join("; "));
    L.push("Koda təsir: " + (IMPACT[f.codeImpact] || IMPACT.unknown)[0] + ((f.impactWhy || []).length ? " — " + f.impactWhy.join("; ") : ""));
    if (f.fix) {
      L.push(`Həll (${STRAT[f.fix.strategy] || f.fix.strategy}): ${f.fix.command || ""}`);
      if (f.fix.snippet) L.push(`${f.fix.file || ""}:\n${f.fix.snippet}`);
      if (f.fix.note) L.push("Qeyd: " + f.fix.note);
    }
    if (f.warnings && f.warnings.length) L.push("Diqqət: " + f.warnings.join("; "));
    L.push("");
    L.push("Tapşırıq: bu yeniləməni et, lockfile-ı yenilə, build və testləri işlət; kod dəyişikliyi lazımdırsa (major, peer, Node tələbi) miqrasiya bələdçisinə görə düzəlt. Nəticəni qısa yaz.");
    return L.join("\n");
  }

  function nodeCard(p) {
    const n = p.node;
    if (!n) return el("div", { class: "card" }, el("div", { class: "h3" }, "Node.js"), el("div", { class: "sub quiet" }, "Node versiyası heç yerdə göstərilməyib (Dockerfile, .nvmrc, engines, CI)."));
    const [needTxt, needCls] = NEED[n.need] || NEED.none;
    const [impTxt, impCls] = IMPACT[n.impact] || IMPACT.unknown;
    const bad = n.need === "now";
    const target = n.securityFix || n.latestInLine;
    return el("div", { class: "card" + (bad ? " bad" : "") },
      el("div", { class: "ctitle" }, el("span", { class: "pkg" }, "Node " + (n.version || n.line || "?")),
        target && n.version && target !== n.version ? el("span", { class: "ver" }, el("span", { class: "arr" }, "→"), target) : null,
        n.lts ? el("span", { class: "chip" }, "LTS " + n.lts) : null,
        n.eol ? el("span", { class: "chip" + (n.daysToEol != null && n.daysToEol < 90 ? " sev-high" : "") }, "EOL " + n.eol) : null),
      el("div", { class: "q" }, el("span", { class: "dot " + needCls }), el("span", { class: "lbl" }, "① Yeniləmək lazımdır?"), el("span", { class: "ans" }, needTxt)),
      el("div", { class: "q" }, el("span", { class: "dot " + impCls }), el("span", { class: "lbl" }, "② Koda təsir edir?"), el("span", { class: "ans" }, impTxt)),
      n.why && n.why.length ? el("ul", { class: "why" }, n.why.map((w) => el("li", null, w))) : null,
      el("ul", { class: "why" }, (n.sources || []).map((s) => el("li", null, `${s.file}: ${s.value}`))),
      n.command ? el("div", { class: "fix" }, el("div", { class: "row" }, el("code", null, n.command), copyBtn(n.command.split("   #")[0]))) : null);
  }

  function hygieneCard(p) {
    const hs = p.hygiene || [];
    const bad = hs.filter((h) => !h.ok).length;
    return el("div", { class: "card hyg" },
      el("div", { class: "h3" }, "Layihə gigiyenası", el("span", { class: "chip" }, bad ? `${bad} tövsiyə` : "hamısı qaydasındadır")),
      hs.map((h) => el("div", { class: "item " + (h.ok ? "ok" : "no") },
        el("span", { class: "mk" }, h.ok ? "✓" : "!"),
        el("div", null, el("div", null, h.title),
          !h.ok && h.detail ? el("div", { class: "d" }, h.detail) : null,
          !h.ok && h.fix ? el("div", null, h.file ? el("span", { class: "d" }, h.file + ": ") : null, el("code", null, h.fix)) : null))));
  }

  load().catch((e) => { $("#main").replaceChildren(el("div", { class: "empty" }, "Yüklənmədi: " + e.message)); });
})();
