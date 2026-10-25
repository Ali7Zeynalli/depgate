"use strict";
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const H = { "X-DepGate": "1" };
  let st = null, current = decodeURIComponent(location.hash.slice(1)) || "", pollT = null;
  const state = { q: "", sev: "", dev: true };

  // ---------- language ----------
  const D = {
    loading: ["Yüklənir…", "Loading…"],
    copied: ["Kopyalandı", "Copied"],
    copy: ["Kopyala", "Copy"],
    theme: ["Tema", "Theme"],
    scanAll: ["Hamısını skan et", "Scan all"],
    scanning: ["Skan olunur…", "Scanning…"],
    addProject: ["+ Layihə əlavə et", "+ Add project"],
    addProjectTitle: ["Layihə əlavə et", "Add project"],
    lastScan: ["son skan {0}", "last scan {0}"],
    offline: ["offline (keşdən)", "offline (cache)"],
    readOnly: ["yalnız baxış", "read-only"],
    projects: ["Layihələr ({0})", "Projects ({0})"],
    scanningAria: ["skan olunur", "scanning"],
    malwareBanner: ["Zərərli paket tapıldı ({0}) — qırmızı kartdakı təlimata indi əməl et.", "Malicious package found ({0}) — follow the steps on the red card now."],
    sourcesFailed: ["Bəzi mənbələr yüklənmədi: {0}", "Some sources failed: {0}"],
    welcomeTitle: ["DepGate-ə xoş gəldin", "Welcome to DepGate"],
    welcomeText: ["Node.js layihələrini əlavə et: DepGate hər paket üçün iki suala cavab verəcək — yeniləmək lazımdır? koda təsir edir?", "Add your Node.js projects: for every package DepGate answers two questions — do I need to update? will it affect my code?"],
    welcomeMemory: ["Layihə siyahısı və son hesabatlar yadda saxlanır; növbəti dəfə açanda hamısı yerində olacaq.", "Your project list and last reports are remembered; next time everything is already here."],
    welcomeDocker: ["Docker-də işləyir: yalnız konteynerə bağlanmış qovluqlar görünür ({0}). Başqa qovluq lazımdırsa, docker-compose.yml-də volume əlavə et.", "Running in Docker: only folders mounted into the container are visible ({0}). Need another folder? Add a volume in docker-compose.yml."],
    scanStarted: ["Skan başladı", "Scan started"],
    scanAllStarted: ["Bütün layihələr skan olunur", "Scanning all projects"],
    removeConfirm: ["«{0}» siyahıdan silinsin? (layihə fayllarına toxunulmur)", "Remove “{0}” from the list? (project files are not touched)"],
    removed: ["Silindi", "Removed"],
    error: ["Xəta: {0}", "Error: {0}"],
    scanningChip: [" skan olunur…", " scanning…"],
    queued: ["növbədə…", "queued…"],
    scan: ["Skan et", "Scan"],
    remove: ["Siyahıdan sil", "Remove"],
    firstScan: ["İlk skan gedir — bir neçə saniyə…", "First scan running — a few seconds…"],
    notScanned: ["Hələ skan olunmayıb.", "Not scanned yet."],
    adding: ["Əlavə olunur…", "Adding…"],
    addedN: ["{0} layihə əlavə olundu, skan gedir", "{0} projects added, scanning"],
    added1: ["Əlavə olundu, skan gedir", "Added, scanning"],
    add: ["Əlavə et", "Add"],
    rescan: ["Yenidən skan", "Rescan"],
    roots: ["Köklər", "Roots"],
    chipProject: ["layihə", "project"],
    chipNoLock: ["lockfile yoxdur", "no lockfile"],
    chipAdded: ["əlavə olunub", "added"],
    noSubfolders: ["Bu qovluqda alt qovluq yoxdur.", "No sub-folders here."],
    selected: ["Seçilmiş qovluq: {0}", "Selected folder: {0}"],
    pickRoot: ["Kök qovluqlardan birini seç", "Pick one of the roots"],
    close: ["Bağla", "Close"],
    addThisTitle: ["Bu qovluğu və altındakı bütün layihələri əlavə et", "Add this folder and every project below it"],
    addThisProject: ["Bu layihəni əlavə et", "Add this project"],
    addThisFolder: ["Bu qovluqdakı layihələri əlavə et", "Add projects in this folder"],
    pickerHelp: ["Qovluqları gəz; package.json olanlar «layihə» kimi işarələnib. Monorepo seçsən, alt layihələrin hamısı əlavə olunur.", "Browse your folders; folders with a package.json are marked as projects. Pick a monorepo to add all its workspaces."],
    packages: ["{0} paket", "{0} packages"],
    noLockfile: ["lockfile yoxdur", "no lockfile"],
    approx: ["Təxmini rejim: lockfile yoxdur, versiyalar aralığın minimumudur, dolayı paketlər yoxlanmayıb.", "Approximate mode: no lockfile, versions are the lowest in range, transitive packages are not checked."],
    tEasy: ["Kod dəyişmir", "No code change"],
    tCode: ["Kod dəyişir", "Code change"],
    tPlan: ["Planla", "Plan"],
    tOptional: ["İstəyə görə", "Optional"],
    tOk: ["Lazım deyil", "Nothing to do"],
    search: ["Paket axtar…", "Search packages…"],
    allSev: ["Bütün severity", "All severities"],
    warningsN: ["Xəbərdarlıqlar ({0})", "Warnings ({0})"],
    gNowEasy: ["İndi et — kod dəyişmir", "Do now — no code change"],
    gNowCode: ["İndi et — kod dəyişir", "Do now — code change"],
    gPlan: ["Planla", "Plan"],
    gOptional: ["İstəyə görə", "Optional"],
    gOk: ["Lazım deyil", "Nothing to do"],
    noMatch: ["Süzgəcə uyğun paket yoxdur.", "No packages match the filter."],
    needNow: ["DƏRHAL", "NOW"],
    needNowVuln: ["Bəli, təcili", "Yes, urgent"],
    needSoon: ["Bəli, növbəti baxımda", "Yes, at the next maintenance"],
    needPlan: ["Təcili deyil, planla", "Not urgent, plan it"],
    needOptional: ["İstəyə görə", "Optional"],
    needNone: ["Lazım deyil", "Not needed"],
    impNo: ["Xeyr", "No"],
    impMaybe: ["Ola bilər", "Maybe"],
    impYes: ["Bəli", "Yes"],
    impUnknown: ["Bilinmir", "Unknown"],
    sUpgrade: ["Yenilə", "Upgrade"],
    sRelock: ["Yalnız lockfile-ı yenilə", "Relock only"],
    sParent: ["Valideyn paketi yenilə", "Upgrade the parent"],
    sOverride: ["Override (müvəqqəti)", "Override (temporary)"],
    sRemove: ["Sil", "Remove"],
    malicious: ["ZƏRƏRLİ", "MALICIOUS"],
    direct: ["birbaşa", "direct"],
    transitive: ["dolayı", "transitive"],
    prioTitle: ["Prioritet balı (0–100)", "Priority score (0–100)"],
    latestTitle: ["Ən son versiya", "Latest version"],
    latest: ["son: {0}", "latest: {0}"],
    qNeed: ["① Yeniləmək lazımdır?", "① Do I need to update?"],
    qImpact: ["② Koda təsir edir?", "② Will it affect my code?"],
    fixedIn: [" · düzəliş {0}", " · fixed in {0}"],
    agentBtn: ["Claude Code üçün tapşırıq", "Task for Claude Code"],
    aProject: ["Layihə", "Project"],
    aPackage: ["Paket", "Package"],
    aWhy: ["Niyə", "Why"],
    aImpact: ["Koda təsir", "Code impact"],
    aFix: ["Həll", "Fix"],
    aNote: ["Qeyd", "Note"],
    aWarn: ["Diqqət", "Warning"],
    aTask: ["Tapşırıq: bu yeniləməni et, lockfile-ı yenilə, build və testləri işlət; kod dəyişikliyi lazımdırsa (major, peer, Node tələbi) miqrasiya bələdçisinə görə düzəlt. Nəticəni qısa yaz.", "Task: apply this update, refresh the lockfile, run the build and tests; if code changes are needed (major, peer, Node requirement), fix them following the migration guide. Summarise the result briefly."],
    noNode: ["Node versiyası heç yerdə göstərilməyib (Dockerfile, .nvmrc, engines, CI).", "Node.js version is not set anywhere (Dockerfile, .nvmrc, engines, CI)."],
    hygiene: ["Layihə gigiyenası", "Project hygiene"],
    hygBad: ["{0} tövsiyə", "{0} suggestions"],
    hygOk: ["hamısı qaydasındadır", "all good"],
    loadFailed: ["Yüklənmədi: {0}", "Failed to load: {0}"],
    langTitle: ["Dil / Language", "Language / Dil"],
    setupTitle: ["DepGate üçün parol təyin et", "Set a password for DepGate"],
    setupText: ["Bu parol interfeysi qoruyur: başqa saytlar və kompüterdəki başqa proqramlar onsuz layihələrini görə bilməz. Bir dəfə təyin edirsən, sonra brauzer səni 30 gün yadda saxlayır.", "This password protects the UI: other websites and programs on this computer can't see your projects without it. You set it once; the browser then remembers you for 30 days."],
    password: ["Parol", "Password"],
    passwordRepeat: ["Parolu təkrarla", "Repeat password"],
    passwordHint: ["Ən azı 8 simvol", "At least 8 characters"],
    setPassword: ["Parolu təyin et", "Set password"],
    mismatch: ["Parollar eyni deyil", "Passwords don't match"],
    tooShort: ["Parol ən azı 8 simvol olmalıdır", "Password must be at least 8 characters"],
    loginTitle: ["DepGate-ə daxil ol", "Sign in to DepGate"],
    remember: ["Məni 30 gün yadda saxla", "Remember me for 30 days"],
    signIn: ["Daxil ol", "Sign in"],
    forgot: ["Parolu unutmusan? Terminalda: depgate --reset-password", "Forgot it? In a terminal: depgate --reset-password"],
    logout: ["Çıxış", "Sign out"],
    changePw: ["Parolu dəyiş", "Change password"],
    currentPw: ["Cari parol", "Current password"],
    newPw: ["Yeni parol", "New password"],
    save: ["Yadda saxla", "Save"],
    pwChanged: ["Parol dəyişdi; digər cihazlardakı sessiyalar bağlandı", "Password changed; sessions on other devices were signed out"],
    please: ["Gözlə…", "Please wait…"],
  };
  let lang = "en";
  try { lang = localStorage.getItem("depgate-lang") || ""; } catch {}
  if (lang !== "az" && lang !== "en") lang = (navigator.language || "").toLowerCase().startsWith("az") ? "az" : "en";
  const t = (k, ...a) => { const e = D[k]; let s = e ? e[lang === "az" ? 0 : 1] : k; a.forEach((v, i) => { s = s.split("{" + i + "}").join(String(v)); }); return s; };
  // tr picks a bilingual {az, en} value from the report
  const tr = (v) => v == null ? "" : typeof v === "string" ? v : (v[lang] || v.en || v.az || "");

  function applyStatic() {
    document.documentElement.lang = lang;
    $("#theme").title = t("theme"); $("#theme").setAttribute("aria-label", t("theme"));
    $("#lang").textContent = lang === "az" ? "EN" : "AZ";
    $("#lang").title = t("langTitle");
    $("#addproj").textContent = t("addProject");
    $("#logout").textContent = t("logout");
    $("#pwbtn").title = t("changePw"); $("#pwbtn").setAttribute("aria-label", t("changePw"));
  }

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
    const x = $("#toast"); x.textContent = msg; x.classList.add("on");
    clearTimeout(toast.t); toast.t = setTimeout(() => x.classList.remove("on"), 1800);
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); toast(t("copied")); }
    catch { const ta = el("textarea", null, text); document.body.append(ta); ta.select(); document.execCommand("copy"); ta.remove(); toast(t("copied")); }
  }
  const copyBtn = (text, label) => el("button", { class: "small", onclick: () => copy(text) }, label || t("copy"));

  // ---------- theme & language ----------
  const root = document.documentElement;
  try { const th = localStorage.getItem("depgate-theme"); if (th) root.dataset.theme = th; } catch {}
  $("#theme").addEventListener("click", () => {
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("depgate-theme", root.dataset.theme); } catch {}
  });
  $("#lang").addEventListener("click", () => {
    lang = lang === "az" ? "en" : "az";
    try { localStorage.setItem("depgate-lang", lang); } catch {}
    applyStatic();
    if (document.body.classList.contains("locked")) { if (authState && authState.setup) showSetup(); else showLogin(); return; }
    if (st) render();
    if (picker) openPicker(picker.dataset.path || "");
  });
  applyStatic();

  // ---------- labels ----------
  const NEED = { now: ["needNow", "bad"], soon: ["needSoon", "warn"], plan: ["needPlan", ""], optional: ["needOptional", "good"], none: ["needNone", "good"] };
  const IMPACT = { no: ["impNo", "good"], maybe: ["impMaybe", "warn"], yes: ["impYes", "bad"], unknown: ["impUnknown", "warn"] };
  const GROUPS = [["now_easy", "gNowEasy", true], ["now_code", "gNowCode", true], ["plan", "gPlan", false], ["optional", "gOptional", false], ["ok", "gOk", false]];
  const STRAT = { upgrade: "sUpgrade", relock: "sRelock", parent: "sParent", override: "sOverride", remove: "sRemove" };
  const strat = (s) => STRAT[s] ? t(STRAT[s]) : s;
  const pad = (n) => String(n).padStart(2, "0");
  const fmtTime = (s) => { const d = new Date(s); return isNaN(d) ? s : `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`; };

  // ---------- data ----------
  async function api(method, path, body) {
    const r = await fetch(path, { method, headers: body ? { ...H, "Content-Type": "application/json" } : H, body: body ? JSON.stringify(body) : undefined });
    let data = null; try { data = await r.json(); } catch {}
    if (r.status === 401 && !path.startsWith("api/auth")) { showAuth(); throw new Error(t("loginTitle")); }
    if (!r.ok) throw new Error((data && (lang === "az" && data.error_az || data.error)) || "HTTP " + r.status);
    return data;
  }
  async function load() { setState(await api("GET", "api/state")); }
  function setState(s) {
    st = s;
    if (!st.projects.some((p) => p.dir === current)) current = st.projects.length ? st.projects[0].dir : "";
    render();
    clearTimeout(pollT);
    if (st.busy) pollT = setTimeout(() => load().catch(() => {}), 1200);
  }
  async function scan(dirs) {
    try { setState(await api("POST", "api/scan", { dirs })); toast(dirs.length ? t("scanStarted") : t("scanAllStarted")); }
    catch (e) { toast(t("error", e.message)); }
  }
  async function removeProject(p) {
    if (!confirm(t("removeConfirm", p.name))) return;
    try { setState(await api("POST", "api/projects/remove", { dir: p.dir })); toast(t("removed")); }
    catch (e) { toast(t("error", e.message)); }
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
    $("#meta").textContent = [st.tool, st.lastScan ? t("lastScan", fmtTime(st.lastScan)) : null, st.offline ? t("offline") : null, st.readOnly ? t("readOnly") : null].filter(Boolean).join(" · ");
    $("#scanall").hidden = st.readOnly || ps.length === 0;
    $("#addproj").hidden = st.readOnly;
    $("#scanall").disabled = st.busy;
    $("#scanall").textContent = st.busy ? t("scanning") : t("scanAll");

    const nav = $("#projects");
    nav.hidden = ps.length === 0;
    nav.setAttribute("aria-label", t("projects", ps.length));
    nav.replaceChildren(el("h2", null, t("projects", ps.length)), ...ps.map((p) => {
      const c = counts(p.report);
      const busy = p.scanning || p.queued;
      return el("button", { class: "proj" + (p.dir === current ? " active" : ""), title: p.dir, onclick: () => select(p.dir) },
        el("span", { class: "nm" }, p.name),
        busy ? el("span", { class: "spin", "aria-label": t("scanningAria") }) :
          !p.report ? el("span", { class: "cnt" }, "—") :
          el("span", { class: "cnt" }, c.mal ? el("b", null, "!" + c.mal + " ") : null, c.urgent ? el("b", null, c.urgent) : "0", " · ", c.plan));
    }));

    const mal = ps.reduce((n, p) => n + counts(p.report).mal, 0);
    const ban = $("#banner");
    if (mal) { ban.hidden = false; ban.className = "banner"; ban.textContent = t("malwareBanner", mal); }
    else if (st.errors && st.errors.length) { ban.hidden = false; ban.className = "banner warn"; ban.textContent = t("sourcesFailed", st.errors.join(" · ")); }
    else ban.hidden = true;

    const main = $("#main");
    if (!ps.length) { main.replaceChildren(welcome()); return; }
    const p = ps.find((x) => x.dir === current) || ps[0];
    main.replaceChildren(projectView(p));
  }

  function welcome() {
    return el("div", { class: "welcome" },
      el("h1", null, t("welcomeTitle")),
      el("p", null, t("welcomeText")),
      el("p", { class: "quiet" }, t("welcomeMemory")),
      st.readOnly ? null : el("button", { class: "primary big", onclick: () => openPicker("") }, t("addProject")),
      st.container ? el("p", { class: "quiet" }, t("welcomeDocker", (st.roots || []).join(", "))) : null);
  }

  function projectView(p) {
    const bar = el("div", { class: "pbar" },
      el("div", { class: "pdir", title: p.dir }, p.dir),
      p.scanning ? el("span", { class: "chip busy" }, el("span", { class: "spin" }), t("scanningChip")) : p.queued ? el("span", { class: "chip busy" }, t("queued")) : null,
      st.readOnly ? null : el("button", { class: "small", disabled: p.scanning || p.queued || undefined, onclick: () => scan([p.dir]) }, t("scan")),
      st.readOnly ? null : el("button", { class: "small ghost danger", onclick: () => removeProject(p) }, t("remove")));
    if (!p.report) {
      return el("div", null, bar, el("div", { class: "empty" }, el("h1", null, p.name), p.scanning || p.queued ? t("firstScan") : t("notScanned")));
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
    catch (e) { toast(t("error", e.message)); return; }
    const add = async (dir, btn) => {
      if (btn) { btn.disabled = true; btn.textContent = t("adding"); }
      try {
        const r = await api("POST", "api/projects", { path: dir });
        closePicker();
        const first = (r.added || [])[0];
        if (first) current = first;
        setState(r.state);
        toast((r.added || []).length > 1 ? t("addedN", r.added.length) : t("added1"));
      } catch (e) { toast(t("error", e.message)); if (btn) { btn.disabled = false; btn.textContent = t("add"); } }
    };
    const crumbs = el("div", { class: "crumbs" },
      (st.roots || []).length > 1 ? el("button", { class: "link", onclick: () => openPicker("") }, t("roots")) : null,
      (l.crumbs || []).map((c, i) => [i || (st.roots || []).length > 1 ? el("span", { class: "sep" }, "/") : null,
        el("button", { class: "link", onclick: () => openPicker(c.path) }, c.name)]));
    const list = el("div", { class: "flist" },
      l.parent ? el("div", { class: "frow" }, el("button", { class: "fname", onclick: () => openPicker(l.parent) }, "↩ ..")) : null,
      (l.entries || []).length ? l.entries.map((e) => el("div", { class: "frow" },
        el("button", { class: "fname", onclick: () => openPicker(e.path), title: e.path }, el("span", { class: "ficon" + (e.isProject ? " proj" : "") }), e.name),
        e.isProject ? el("span", { class: "chip" }, t("chipProject")) : null,
        e.isProject && !e.lockfile ? el("span", { class: "chip warn" }, t("chipNoLock")) : null,
        e.added ? el("span", { class: "chip ok" }, t("chipAdded")) : null,
        e.isProject ? el("button", { class: "small", onclick: (ev) => add(e.path, ev.currentTarget) }, e.added ? t("rescan") : t("add")) : null))
        : el("div", { class: "quiet pad" }, t("noSubfolders")));
    const foot = el("div", { class: "pfoot" },
      el("div", { class: "quiet" }, l.path ? t("selected", l.path) : t("pickRoot")),
      el("span", { class: "grow" }),
      el("button", { onclick: closePicker }, t("close")),
      l.path ? el("button", { class: "primary", onclick: (ev) => add(l.path, ev.currentTarget), title: t("addThisTitle") }, l.project ? t("addThisProject") : t("addThisFolder")) : null);
    const dlg = el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": t("addProjectTitle") },
      el("div", { class: "mhead" }, el("div", { class: "h3" }, t("addProjectTitle")), el("div", { class: "quiet" }, t("pickerHelp"))),
      crumbs, list, foot);
    const ov = el("div", { class: "overlay", onclick: (e) => { if (e.target === ov) closePicker(); } }, dlg);
    ov.dataset.path = l.path || "";
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
      p.manager, t("packages", p.packages || 0), p.lockfile || t("noLockfile"), p.repo].filter(Boolean).join(" · ");
    const head = el("div", { class: "phead" },
      el("div", null, el("h1", null, p.name), el("div", { class: "sub" }, sub),
        p.approximate ? el("div", { class: "sub warntext" }, t("approx")) : null),
      el("div", { class: "tiles" },
        tile(s.now_easy, t("tEasy"), "easy", "now_easy"), tile(s.now_code, t("tCode"), "code", "now_code"),
        tile(s.plan, t("tPlan"), "", "plan"), tile(s.optional, t("tOptional"), "", "optional"), tile(s.ok, t("tOk"), "", "ok")));

    const toolbar = el("div", { class: "toolbar" },
      el("input", { type: "search", placeholder: t("search"), value: state.q, oninput: (e) => { state.q = e.target.value; rerenderGroups(); } }),
      el("select", { onchange: (e) => { state.sev = e.target.value; rerenderGroups(); } },
        ...[["", t("allSev")], ["critical", "critical"], ["high", "high+"], ["moderate", "moderate+"]].map(([v, l]) => el("option", { value: v, selected: state.sev === v }, l))),
      el("label", null, el("input", { type: "checkbox", checked: state.dev, onchange: (e) => { state.dev = e.target.checked; rerenderGroups(); } }), "devDependencies"));

    const groups = el("div");
    function rerenderGroups() { groups.replaceChildren(...renderGroups(p)); }
    rerenderGroups();

    return el("div", null, head,
      el("div", { class: "side" }, nodeCard(p), hygieneCard(p)),
      toolbar, groups,
      p.errors && p.errors.length ? el("details", { class: "errs" }, el("summary", null, t("warningsN", p.errors.length)), el("ul", null, p.errors.map((e) => el("li", null, e)))) : null);
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
        el("summary", null, t(title), el("span", { class: "c" }, `(${fs.length})`)), body));
    }
    if (!out.length) out.push(el("div", { class: "empty" }, t("noMatch")));
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

  function needText(kind, need) {
    if (kind === "vuln" && need === "now") return t("needNowVuln");
    return t((NEED[need] || NEED.none)[0]);
  }
  const needClass = (need) => (NEED[need] || NEED.none)[1];
  const impText = (i) => t((IMPACT[i] || IMPACT.unknown)[0]);
  const impClass = (i) => (IMPACT[i] || IMPACT.unknown)[1];
  const list = (xs) => (xs || []).filter((x) => tr(x)).map((w) => el("li", null, tr(w)));

  function card(f, p) {
    const vuln = f.kind === "vuln" || f.kind === "malware";
    const cls = "card" + (f.kind === "malware" ? " mal bad" : "");
    const title = el("div", { class: "ctitle" },
      el("span", { class: "pkg" }, f.pkg),
      el("span", { class: "ver" }, f.current, f.target ? [el("span", { class: "arr" }, "→"), f.target] : null),
      f.severity ? el("span", { class: "chip sev-" + f.severity }, f.kind === "malware" ? t("malicious") : f.severity) : null,
      el("span", { class: "chip" }, f.direct ? t("direct") : t("transitive")),
      f.dev ? el("span", { class: "chip" }, "dev") : null,
      vuln ? el("span", { class: "chip prio", title: t("prioTitle") }, "P" + f.priority) : null,
      f.latest && f.latest !== f.target && f.latest !== f.current ? el("span", { class: "chip", title: t("latestTitle") }, t("latest", f.latest)) : null);

    const kids = [title];
    if (f.title) kids.push(el("div", { class: "ctext" }, f.title));
    if (f.chain && f.chain.length > 1) kids.push(el("div", { class: "chain" }, f.chain.join(" → ")));
    kids.push(el("div", { class: "q" }, el("span", { class: "dot " + needClass(f.needUpdate) }), el("span", { class: "lbl" }, t("qNeed")), el("span", { class: "ans" }, needText(f.kind, f.needUpdate))));
    if (f.why && f.why.length) kids.push(el("ul", { class: "why" }, list(f.why)));
    kids.push(el("div", { class: "q" }, el("span", { class: "dot " + impClass(f.codeImpact) }), el("span", { class: "lbl" }, t("qImpact")), el("span", { class: "ans" }, impText(f.codeImpact))));
    if (f.impactWhy && f.impactWhy.length) kids.push(el("ul", { class: "why" }, list(f.impactWhy)));
    if (f.warnings && f.warnings.length) kids.push(el("div", { class: "warnbox" }, f.warnings.map((w) => el("div", null, "⚠ " + tr(w)))));
    if (f.fix) {
      const fx = f.fix;
      const note = tr(fx.note);
      kids.push(el("div", { class: "fix" },
        el("div", { class: "row" }, el("span", { class: "chip" }, strat(fx.strategy)), fx.command ? el("code", null, fx.command) : el("span", { class: "grow" }), fx.command ? copyBtn(fx.command.split("   #")[0]) : null),
        fx.snippet ? el("pre", null, (fx.file ? "// " + fx.file + "\n" : "") + fx.snippet) : null,
        note ? el("div", { class: "note" }, note) : null));
    }
    const foot = el("div", { class: "cfoot" });
    if (f.advisories && f.advisories.length) {
      foot.append(el("div", { class: "advs" }, f.advisories.slice(0, 6).map((a) => {
        const u = safeURL(a.url);
        const label = a.id + (a.kev ? " · KEV" : "") + (a.fixed ? t("fixedIn", a.fixed) : "");
        return u ? el("a", { href: u, target: "_blank", rel: "noopener noreferrer" }, label) : el("span", null, label);
      }), f.advisories.length > 6 ? `+${f.advisories.length - 6}` : null));
    }
    foot.append(el("span", { class: "grow" }), copyBtn(agentTask(f, p), t("agentBtn")));
    kids.push(foot);
    return el("div", { class: cls }, kids);
  }

  function agentTask(f, p) {
    const join = (xs) => (xs || []).map(tr).filter(Boolean).join("; ");
    const L = [];
    L.push(`${t("aProject")}: ${p.name} (${p.dir})`);
    L.push(`${t("aPackage")}: ${f.pkg} ${f.current}${f.target ? " → " + f.target : ""} (${f.direct ? t("direct") : t("transitive") + ": " + (f.chain || []).join(" → ")}${f.dev ? ", devDependency" : ""})`);
    if (f.advisories && f.advisories.length) L.push("Advisory: " + f.advisories.map((a) => `${a.id}${a.severity ? " (" + a.severity + ")" : ""}${a.url ? " " + a.url : ""}`).join("; "));
    L.push(`${t("aWhy")}: ${join(f.why)}`);
    L.push(`${t("aImpact")}: ${impText(f.codeImpact)}${(f.impactWhy || []).length ? " — " + join(f.impactWhy) : ""}`);
    if (f.fix) {
      L.push(`${t("aFix")} (${strat(f.fix.strategy)}): ${f.fix.command || ""}`);
      if (f.fix.snippet) L.push(`${f.fix.file || ""}:\n${f.fix.snippet}`);
      if (tr(f.fix.note)) L.push(`${t("aNote")}: ${tr(f.fix.note)}`);
    }
    if (f.warnings && f.warnings.length) L.push(`${t("aWarn")}: ${join(f.warnings)}`);
    L.push("");
    L.push(t("aTask"));
    return L.join("\n");
  }

  function nodeCard(p) {
    const n = p.node;
    if (!n) return el("div", { class: "card" }, el("div", { class: "h3" }, "Node.js"), el("div", { class: "sub quiet" }, t("noNode")));
    const bad = n.need === "now";
    const target = n.securityFix || n.latestInLine;
    return el("div", { class: "card" + (bad ? " bad" : "") },
      el("div", { class: "ctitle" }, el("span", { class: "pkg" }, "Node " + (n.version || n.line || "?")),
        target && n.version && target !== n.version ? el("span", { class: "ver" }, el("span", { class: "arr" }, "→"), target) : null,
        n.lts ? el("span", { class: "chip" }, "LTS " + n.lts) : null,
        n.eol ? el("span", { class: "chip" + (n.daysToEol != null && n.daysToEol < 90 ? " sev-high" : "") }, "EOL " + n.eol) : null),
      el("div", { class: "q" }, el("span", { class: "dot " + needClass(n.need) }), el("span", { class: "lbl" }, t("qNeed")), el("span", { class: "ans" }, needText("node", n.need))),
      el("div", { class: "q" }, el("span", { class: "dot " + impClass(n.impact) }), el("span", { class: "lbl" }, t("qImpact")), el("span", { class: "ans" }, impText(n.impact))),
      n.why && n.why.length ? el("ul", { class: "why" }, list(n.why)) : null,
      el("ul", { class: "why" }, (n.sources || []).map((s) => el("li", null, `${s.file}: ${s.value}`))),
      n.command ? el("div", { class: "fix" }, el("div", { class: "row" }, el("code", null, n.command), copyBtn(n.command.split("   #")[0]))) : null);
  }

  function hygieneCard(p) {
    const hs = p.hygiene || [];
    const bad = hs.filter((h) => !h.ok).length;
    return el("div", { class: "card hyg" },
      el("div", { class: "h3" }, t("hygiene"), el("span", { class: "chip" }, bad ? t("hygBad", bad) : t("hygOk"))),
      hs.map((h) => el("div", { class: "item " + (h.ok ? "ok" : "no") },
        el("span", { class: "mk" }, h.ok ? "✓" : "!"),
        el("div", null, el("div", null, tr(h.title)),
          !h.ok && tr(h.detail) ? el("div", { class: "d" }, tr(h.detail)) : null,
          !h.ok && h.fix ? el("div", null, h.file ? el("span", { class: "d" }, h.file + ": ") : null, el("code", null, h.fix)) : null))));
  }

  // ---------- authentication ----------
  let authState = null;
  function setAuthed(on) {
    document.body.classList.toggle("locked", !on);
    const canPw = on && authState && !authState.noAuth && !authState.fromEnv;
    $("#logout").hidden = !on || !authState || authState.noAuth;
    $("#pwbtn").hidden = !canPw;
    if (!on) { $("#scanall").hidden = true; $("#addproj").hidden = true; $("#projects").hidden = true; $("#banner").hidden = true; $("#meta").textContent = ""; }
  }
  function field(type, label, ac, hint) {
    const id = "f" + Math.random().toString(36).slice(2);
    const input = el("input", { type, id, autocomplete: ac, required: true, minlength: type === "password" ? 8 : undefined });
    return { input, row: el("div", { class: "frm" }, el("label", { for: id }, label), input, hint ? el("div", { class: "quiet small" }, hint) : null) };
  }
  function authCard(title, text, fields, extra, submitLabel, onSubmit) {
    const err = el("div", { class: "ferr", role: "alert" });
    const btn = el("button", { class: "primary big", type: "submit" }, submitLabel);
    const form = el("form", { class: "authcard", novalidate: true, onsubmit: async (ev) => {
      ev.preventDefault(); err.textContent = ""; btn.disabled = true; const label = btn.textContent; btn.textContent = t("please");
      try { await onSubmit(err); } catch (e) { err.textContent = e.message; }
      finally { btn.disabled = false; btn.textContent = label; }
    } },
      el("div", { class: "brand big" }, el("span", { class: "logo", "aria-hidden": "true" }), "DepGate"),
      el("h1", null, title), text ? el("p", { class: "quiet" }, text) : null,
      fields.map((f) => f.row), extra, err, btn);
    $("#main").replaceChildren(el("div", { class: "authwrap" }, form));
    const first = form.querySelector("input"); if (first) first.focus();
  }
  async function authPost(path, body) { return api("POST", path, body); }
  function showSetup() {
    setAuthed(false);
    const a = field("password", t("password"), "new-password", t("passwordHint"));
    const b = field("password", t("passwordRepeat"), "new-password");
    authCard(t("setupTitle"), t("setupText"), [a, b], null, t("setPassword"), async (err) => {
      if (a.input.value.length < 8) { err.textContent = t("tooShort"); return; }
      if (a.input.value !== b.input.value) { err.textContent = t("mismatch"); return; }
      await authPost("api/auth/setup", { password: a.input.value });
      await start();
    });
  }
  function showLogin() {
    setAuthed(false);
    const a = field("password", t("password"), "current-password");
    const rem = el("input", { type: "checkbox", checked: true, id: "remember" });
    authCard(t("loginTitle"), null, [a], [el("label", { class: "chk", for: "remember" }, rem, t("remember")), el("div", { class: "quiet small" }, t("forgot"))], t("signIn"), async () => {
      await authPost("api/auth/login", { password: a.input.value, remember: rem.checked });
      await start();
    });
  }
  async function showAuth() {
    try { authState = await api("GET", "api/auth"); } catch { authState = null; }
    if (authState && authState.setup) showSetup(); else showLogin();
  }
  $("#logout").addEventListener("click", async () => {
    try { await authPost("api/auth/logout"); } catch {}
    clearTimeout(pollT); st = null; showLogin();
  });
  $("#pwbtn").addEventListener("click", () => {
    const cur = field("password", t("currentPw"), "current-password");
    const nw = field("password", t("newPw"), "new-password", t("passwordHint"));
    const rp = field("password", t("passwordRepeat"), "new-password");
    const err = el("div", { class: "ferr", role: "alert" });
    const close = () => { ov.remove(); document.removeEventListener("keydown", esc); };
    const esc = (e) => { if (e.key === "Escape") close(); };
    const form = el("form", { class: "modal pwmodal", novalidate: true, onsubmit: async (ev) => {
      ev.preventDefault(); err.textContent = "";
      if (nw.input.value.length < 8) { err.textContent = t("tooShort"); return; }
      if (nw.input.value !== rp.input.value) { err.textContent = t("mismatch"); return; }
      try { await authPost("api/auth/password", { current: cur.input.value, next: nw.input.value }); close(); toast(t("pwChanged")); }
      catch (e) { err.textContent = e.message; }
    } },
      el("div", { class: "mhead" }, el("div", { class: "h3" }, t("changePw"))),
      el("div", { class: "pad" }, cur.row, nw.row, rp.row, err),
      el("div", { class: "pfoot" }, el("span", { class: "grow" }), el("button", { type: "button", onclick: () => close() }, t("close")), el("button", { class: "primary", type: "submit" }, t("save"))));
    const ov = el("div", { class: "overlay", onclick: (e) => { if (e.target === ov) close(); } }, form);
    document.body.append(ov); document.addEventListener("keydown", esc); cur.input.focus();
  });

  async function start() {
    try { authState = await api("GET", "api/auth"); }
    catch (e) { $("#main").replaceChildren(el("div", { class: "empty" }, t("loadFailed", e.message))); return; }
    if (authState.setup && !authState.noAuth) return showSetup();
    if (!authState.authed) return showLogin();
    setAuthed(true);
    await load();
  }
  start().catch((e) => { $("#main").replaceChildren(el("div", { class: "empty" }, t("loadFailed", e.message))); });
})();
