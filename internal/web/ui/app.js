"use strict";
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const H = { "X-DepGate": "1" };
  const TABS = ["overview", "packages", "code", "docker", "server", "env", "ai"];
  const TABL = { overview: "tabOverview", packages: "tabPackages", code: "tabCode", docker: "tabDocker", server: "tabServer", env: "tabEnv", ai: "tabAI" };
  // location.hash = encodeURIComponent(project or folder) + "@" + tab ("@" never appears encoded)
  const parseHash = () => {
    const h = location.hash.slice(1), i = h.lastIndexOf("@");
    let dir = i >= 0 ? h.slice(0, i) : h;
    try { dir = decodeURIComponent(dir); } catch { dir = ""; }
    const tab = i >= 0 ? h.slice(i + 1) : "";
    return { dir, tab: TABS.includes(tab) ? tab : "overview" };
  };
  const h0 = parseHash();
  let st = null, current = h0.dir, pollT = null;
  const state = { q: "", sev: "", dev: true, tab: h0.tab, grp: "", open: new Set(), shut: new Set() };

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
    malwareBanner: ["Zərərli paket tapıldı ({0}) — layihəni aç və qırmızı sətirdəki təlimata indi əməl et.", "Malicious package found ({0}) — open the project and follow the steps on the red row now."],
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
    folderRoot: ["qovluğun özü", "folder itself"],
    nProjects: ["{0} layihə", "{0} projects"],
    expand: ["Aç / bağla", "Expand / collapse"],
    scanFolder: ["Qovluğu skan et ({0})", "Scan folder ({0})"],
    removeFolder: ["Qovluğu sil ({0})", "Remove folder ({0})"],
    sources: ["Mənbələr", "Sources"],
    sourcesTitle: ["Skan hansı mənbələrə əsaslanır", "What the scan is based on"],
    sourcesIntro: ["DepGate qərarı bu açıq mənbələrə görə verir. Kodun və faylların heç yerə göndərilmir — mənbələrdən yalnız paket adı və versiyası soruşulur.", "DepGate decides with these public sources. Your code and files are never sent anywhere — only package names and versions are looked up."],
    sourcesLocal: ["Kompüterində oxunanlar", "Read on your computer"],
    sourcesLocalText: ["package.json və lockfile (npm, pnpm, yarn, bun) — quraşdırılmış versiyalar və asılılıq zənciri; layihənin mənbə faylları — yeniləmədə kodunda dəyişəcək yerlər; Dockerfile və compose faylları, .dockerignore — Docker yoxlaması; .nvmrc, .node-version, engines və CI faylları — Node.js versiyası; .npmrc — gigiyena yoxlamaları. Bunlar heç yerə göndərilmir.", "package.json and the lockfile (npm, pnpm, yarn, bun) — installed versions and the dependency chain; the project's source files — the places an update changes in your code; Dockerfiles, compose files and .dockerignore — Docker checks; .nvmrc, .node-version, engines and CI files — the Node.js version; .npmrc — hygiene checks. None of it is sent anywhere."],
    sourcesOnline: ["İnternetdən soruşulanlar", "Looked up online"],
    srcReq: ["{0} sorğu", "{0} requests"],
    srcReq1: ["1 sorğu", "1 request"],
    srcFailed: ["{0} sorğu alınmadı", "{0} requests failed"],
    srcUnused: ["bu skanda lazım olmadı", "not needed in this scan"],
    srcNotYet: ["hələ skan yoxdur", "no scan yet"],
    srcCache: ["keşdən (offline)", "from cache (offline)"],
    srcFoot: ["Mənbələr: {0}", "Sources: {0}"],
    folderSub: ["{0} layihə · {1} paket", "{0} projects · {1} packages"],
    folderProjects: ["Layihələr", "Projects"],
    folderNotScanned: ["Bu qovluqda hələ skan olunmuş layihə yoxdur.", "No project in this folder has been scanned yet."],
    colProject: ["Layihə", "Project"],
    whereN: ["Harada ({0} layihə)", "Where ({0} projects)"],
    whereN1: ["Harada", "Where"],
    whereAll: ["Hamısını kopyala", "Copy all"],
    nodeCves: ["Bu versiyaya aid zəifliklər ({0})", "Vulnerabilities in this version ({0})"],
    removedChip: ["npm-dən silinib", "removed from npm"],
    nodeAll: ["Node.js (layihələr üzrə)", "Node.js (per project)"],
    hygAll: ["Gigiyena (layihələr üzrə)", "Hygiene (per project)"],
    inProjects: ["layihələr: {0}", "projects: {0}"],
    aiBtn: ["AI üçün prompt", "AI prompt"],
    aiTitle: ["AI üçün tapşırıq (prompt)", "Task for an AI agent (prompt)"],
    aiHelp: ["Bunu Claude Code, Cursor və ya başqa AI agentə ver: bütün tapıntılar, harada olduqları, hansı versiyaya və niyə yenilənməli olduqları burada yazılıb.", "Give this to Claude Code, Cursor or another AI agent: every finding, where it is, which version to move to and why."],
    aiStats: ["{0} tapşırıq · {1} layihə", "{0} tasks · {1} projects"],
    download: ["Yüklə ({0})", "Download ({0})"],
    aiNothing: ["Görüləcək iş yoxdur — hər şey qaydasındadır.", "Nothing to do — everything is fine."],
    pH1: ["# Asılılıq yeniləmə tapşırığı (DepGate)", "# Dependency update task (DepGate)"],
    pIntro: ["Sən təcrübəli Node.js mühəndisisən. Aşağıdakı layihələrdə DepGate-in tapdığı npm paket problemlərini düzəlt. Hər bəndə nə, harada, hansı versiyaya və niyə yazılıb.", "You are an experienced Node.js engineer. Fix the npm package problems DepGate found in the projects below. Each item says what, where, which version and why."],
    pScope: ["Əhatə", "Scope"],
    pScanned: ["Skan vaxtı", "Scanned at"],
    pRules: ["## Qaydalar", "## Rules"],
    pRule1: ["Sıra ilə işlə: əvvəl ZƏRƏRLİ paketlər, sonra «İndi et», sonra «Planla». «İstəyə görə» bəndləri yalnız vaxt qalarsa.", "Work in order: MALICIOUS packages first, then “Do now”, then “Plan”. “Optional” items only if time allows."],
    pRule2: ["Göstərilən hədəf versiya «ən təhlükəsiz minimumdur» — lazım olmadan daha yuxarı (xüsusən yeni major) qalxma.", "The given target is the safest minimum — do not go higher (especially to a new major) unless needed."],
    pRule3: ["Hər layihədə öz qovluğunda və öz paket menecerinlə işlə; lockfile-ı da yenilə və commit et.", "Work inside each project's own folder with its own package manager; update and commit the lockfile too."],
    pRule4: ["Hər layihədən sonra install, build və testləri işlət. «Koda təsir: Bəli» olan bəndlərdə changelog/miqrasiya bələdçisinə bax və kodu uyğunlaşdır.", "After each project run install, build and tests. For items with “Code impact: Yes”, read the changelog / migration guide and adapt the code."],
    pRule5: ["Override yalnız müvəqqəti həlldir — valideyn paket düzəlişi tələb edən kimi sil.", "An override is only a temporary fix — remove it once the parent package requires the fixed version."],
    pRule6: ["Zərərli paket varsa: node_modules-u sil, npm/GitHub/bulud token-lərini və .env sirlərini dəyiş, CI loglarını yoxla.", "If a package is malicious: delete node_modules, rotate npm/GitHub/cloud tokens and .env secrets, review CI logs."],
    pProject: ["## Layihə: {0}", "## Project: {0}"],
    pPath: ["Yol", "Path"],
    pMgr: ["Paket meneceri", "Package manager"],
    pProblem: ["Problem", "Problem"],
    pAdv: ["Advisory", "Advisories"],
    pWhy: ["Niyə yenilənməli", "Why update"],
    pImpact: ["Koda təsir", "Code impact"],
    pFix: ["Nə etməli", "What to do"],
    pNote: ["Qeyd", "Note"],
    pWarn: ["Diqqət", "Warning"],
    pChain: ["Zəncir", "Chain"],
    pOptional: ["### İstəyə görə yeniləmələr", "### Optional updates"],
    pNode: ["### Node.js", "### Node.js"],
    pHyg: ["### Layihə gigiyenası", "### Project hygiene"],
    pReport: ["## Sonda hesabat ver", "## Report back"],
    pReportText: ["Cədvəl: layihə | paket | köhnə → yeni versiya | nəticə (edildi / alınmadı + səbəb). Sonra build/test nəticəsi və etdiyin kod dəyişiklikləri.", "A table: project | package | old → new version | result (done / failed + reason). Then the build/test results and any code changes you made."],
    prod: ["prod", "prod"],
    migNow: ["Kodunda dəyişəcək yerlər (→ {0}): {1}", "Places in your code to change (→ {0}): {1}"],
    migPlan: ["Yeni major-a keçsən (→ {0}): kodunda {1} yer", "If you move to the new major (→ {0}): {1} places in your code"],
    migNone: ["uyğun istifadə tapılmadı", "no matching usage found"],
    migCodemod: ["Avtomatik düzəliş (rəsmi codemod)", "Automatic fix (official codemod)"],
    migChecks: ["Əl ilə yoxla", "Check by hand"],
    migNotes: ["Release notes — breaking changes ({0})", "Release notes — breaking changes ({0})"],
    migNotesErr: ["Release notes yüklənmədi: {0}", "Release notes not loaded: {0}"],
    migHint: ["Axtarış mətn nümunələrinə əsaslanır: hər yeri yoxla, sonra build və testləri işlət.", "Matching is text based: review each place, then run the build and tests."],
    pMig: ["Kod dəyişiklikləri", "Code changes"],
    pMigPlan: ["Yeni major {0} mövcuddur: kodunda {1} yer dəyişəcək (DepGate-də bax)", "New major {0} is available: {1} places in your code would change (see DepGate)"],
    bundlesTitle: ["Birlikdə yenilə", "Update together"],
    bundleTo: ["→ {0}", "→ {0}"],
    bundleStays: ["qalır", "stays"],
    docs: ["Sənəd", "Docs"],
    dockerTitle: ["Docker təhlükəsizliyi", "Docker security"],
    dockerNone: ["Dockerfile və ya compose faylı tapılmadı.", "No Dockerfile or compose file found."],
    dockerOk: ["Yoxlanan fayllarda problem tapılmadı: {0}", "No issues in the checked files: {0}"],
    dockerN: ["{0} tövsiyə", "{0} suggestions"],
    readOnlyNote: ["DepGate heç bir faylı dəyişmir — yalnız göstərir və təklif edir.", "DepGate never changes your files — it only shows and suggests."],
    mcpBtn: ["AI agent (MCP)", "AI agent (MCP)"],
    mcpTitle: ["Bu layihəni AI agentə qoş (MCP)", "Connect this project to an AI agent (MCP)"],
    mcpHelp: ["Bir dəfə qoş: sonra Claude Code, Cursor və ya başqa agent bu layihənin tapıntılarını, kod dəyişikliklərini və qaydalarını DepGate-dən özü soruşur, yeni paket əlavə etməzdən əvvəl check_package ilə yoxlayır. Hər layihəyə ayrıca qoşulur.", "Connect once: Claude Code, Cursor or any agent then asks DepGate itself for this project's findings, code changes and rules, and checks every new package with check_package before installing it. Each project is connected on its own."],
    mcpStats: ["9 alət · yalnız oxuyur", "9 tools · read-only"],
    rulesBtn: ["AI qaydaları", "AI rules"],
    rulesTitle: ["AI agentlər üçün versiya qaydaları", "Version rules for AI agents"],
    rulesHelp: ["Bunu layihənin AGENTS.md, CLAUDE.md və ya .cursor/rules faylına əlavə et: AI köhnə versiyalara görə yox, sənin quraşdırdığın versiyalara görə kod yazacaq. DepGate faylı özü yazmır.", "Add this to the project's AGENTS.md, CLAUDE.md or .cursor/rules: the AI will write code for the versions you actually have, not the ones it was trained on. DepGate does not write the file itself."],
    rulesStats: ["{0} qayda · {1} əvəz təklifi", "{0} rules · {1} replacement suggestion(s)"],
    rulesNothing: ["Bu layihə üçün xüsusi qayda yoxdur.", "No specific rules for this project."],
    pBundles: ["### Birlikdə yenilə", "### Update together"],
    pDocker: ["### Docker", "### Docker"],
    pServer: ["### Veb server (nginx / Caddy)", "### Web server (nginx / Caddy)"],
    sections: ["Bölmələr", "Sections"],
    tabOverview: ["Ümumi", "Overview"],
    tabPackages: ["Paketlər", "Packages"],
    tabCode: ["Kod dəyişiklikləri", "Code changes"],
    tabDocker: ["Docker", "Docker"],
    tabEnv: ["Node.js və mühit", "Node.js & setup"],
    tabAI: ["AI və MCP", "AI & MCP"],
    firstTitle: ["Əvvəlcə bunları et", "Do these first"],
    firstHelp: ["Prioritetə görə sıralanıb; hər addım öz bölməsinə aparır.", "Sorted by priority; each step opens its section."],
    firstNone: ["Təcili iş yoxdur.", "Nothing urgent."],
    go: ["Bax →", "Open →"],
    badgeUrgent: ["{0} təcili", "{0} urgent"],
    areaPlaces: ["{0} yer", "{0} places"],
    colPkg: ["Paket", "Package"],
    colVer: ["Versiya", "Version"],
    colWhy: ["Niyə", "Why"],
    colImpact: ["Koda təsir", "Code impact"],
    help_now_easy: ["Təhlükəsizlik üçün indi yenilə. Kod dəyişmir: eyni major daxilində ən təhlükəsiz versiya.", "Update now for security. No code change: the safest version within the same major."],
    help_now_code: ["Təhlükəsizlik üçün indi yenilə, amma düzəliş yeni major-dadır: kodda dəyişiklik lazımdır.", "Update now for security, but the fix is in a new major: your code needs changes."],
    help_plan: ["Təcili deyil, amma dəstəyi bitir və ya köhnəlir — planla.", "Not urgent, but support ends or the package is getting old — plan it."],
    help_optional: ["Problem yoxdur, sadəcə daha yeni versiya var.", "No problem, a newer version is simply available."],
    help_ok: ["Bu paketlərdə görüləcək iş yoxdur.", "Nothing to do for these packages."],
    help_bundles: ["Bu paketlər birlikdə buraxılır: birini yeniləsən, qalanlarını da eyni versiyaya keçir.", "These packages are released together: update one and move the others to the same version."],
    codeHelp: ["Yeniləmədən sonra kodunda dəyişməli olan yerlər.", "The places in your code that change with these updates."],
    codeNone: ["Kod dəyişikliyi tələb edən yeniləmə yoxdur.", "No update needs code changes."],
    toPackage: ["Paketə bax", "View package"],
    seeCode: ["Kodda {0} yer dəyişməlidir → Kod dəyişiklikləri", "{0} places in your code change → Code changes"],
    seeCode0: ["Yeniləmə qeydləri → Kod dəyişiklikləri", "Upgrade notes → Code changes"],
    dockerHelp: ["Dockerfile və compose faylları: təhlükəsizlik, Compose standartı və image-lərin köhnəlməsi.", "Dockerfiles and compose files: security, the Compose Specification and outdated images."],
    dockerFiles: ["Yoxlanan fayllar: {0}", "Checked files: {0}"],
    aiOpen: ["Promptu aç", "Open the prompt"],
    rulesOpen: ["Qaydalara bax", "View the rules"],
    mcpOpen: ["Qoşulma əmri", "Connection command"],
    tabServer: ["Veb server", "Web server"],
    serverHelp: ["nginx və Caddy: konfiqurasiya qaydaları (TLS, başlıqlar, alias, admin API…) və istifadə etdiyin image versiyasının məlum zəiflikləri.", "nginx and Caddy: config rules (TLS, headers, alias, admin API…) and the known vulnerabilities of the image version you run."],
    serverImagesOnly: ["Konfiqurasiya faylı tapılmadı — yalnız image versiyası yoxlanıb", "No config file found — only the image version was checked"],
    removeFolderConfirm: ["«{0}» qovluğundakı {1} layihə siyahıdan silinsin? (fayllara toxunulmur)", "Remove the {1} projects in “{0}” from the list? (files are not touched)"],
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
    $("#srcbtn").textContent = t("sources");
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
  const FOLDER = "folder:";
  const currentGroup = () => current.startsWith(FOLDER) ? groupsOf(st.projects).find((g) => FOLDER + g.dir === current && g.items.length > 1) : null;
  function setState(s) {
    st = s;
    if (!currentGroup() && !st.projects.some((p) => p.dir === current)) current = st.projects.length ? st.projects[0].dir : "";
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
  async function removeGroup(g) {
    if (!confirm(t("removeFolderConfirm", baseName(g.dir), g.items.length))) return;
    try { setState(await api("POST", "api/projects/remove", { dirs: g.items.map((p) => p.dir) })); toast(t("removed")); }
    catch (e) { toast(t("error", e.message)); }
  }
  function setHash() { history.replaceState(null, "", "#" + encodeURIComponent(current) + (state.tab !== "overview" ? "@" + state.tab : "")); }
  function select(dir) { current = dir; setHash(); render(); window.scrollTo(0, 0); }
  // goTab switches the section; o.grp picks a package group, o.open opens (and shows) one package row
  function goTab(tab, o) {
    state.tab = tab;
    if (o && o.grp) state.grp = o.grp;
    if (o && o.open) { state.open.add(o.open); state.shut.delete(o.open); }
    setHash(); render();
    const row = o && o.open && [...document.querySelectorAll("details.prow")].find((d) => d.dataset.key === o.open);
    if (row) row.scrollIntoView({ block: "start" });
    else { const tb = $(".tabs"); if (tb && tb.getBoundingClientRect().top < 60) window.scrollTo(0, 0); }
  }

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
    $("#srcbtn").hidden = false;
    $("#scanall").disabled = st.busy;
    $("#scanall").textContent = st.busy ? t("scanning") : t("scanAll");

    const nav = $("#projects");
    nav.hidden = ps.length === 0;
    nav.setAttribute("aria-label", t("projects", ps.length));
    nav.replaceChildren(el("h2", null, t("projects", ps.length)), ...groupsOf(ps).map(groupNav));

    const mal = ps.reduce((n, p) => n + counts(p.report).mal, 0);
    const ban = $("#banner");
    if (mal) { ban.hidden = false; ban.className = "banner"; ban.textContent = t("malwareBanner", mal); }
    else if (st.errors && st.errors.length) { ban.hidden = false; ban.className = "banner warn"; ban.textContent = t("sourcesFailed", st.errors.join(" · ")); }
    else ban.hidden = true;

    const main = $("#main");
    if (!ps.length) { main.replaceChildren(welcome()); return; }
    const cg = currentGroup();
    if (cg) { main.replaceChildren(folderView(cg)); return; }
    const p = ps.find((x) => x.dir === current) || ps[0];
    main.replaceChildren(projectView(p));
  }

  // ---------- sidebar: projects nested under the folder they were added from ----------
  const baseName = (d) => d.replace(/[\\/]+$/, "").split(/[\\/]/).pop() || d;
  const relTo = (dir, group) => dir === group ? "" : dir.slice(group.length).replace(/^[\\/]+/, "");
  function groupsOf(ps) {
    const out = [], by = {};
    for (const p of ps) {
      const k = p.group || p.dir;
      if (!by[k]) { by[k] = { dir: k, items: [] }; out.push(by[k]); }
      by[k].items.push(p);
    }
    return out;
  }
  let collapsed = {};
  try { collapsed = JSON.parse(localStorage.getItem("depgate-collapsed") || "{}") || {}; } catch {}
  function toggleGroup(dir) {
    collapsed[dir] = !collapsed[dir];
    try { localStorage.setItem("depgate-collapsed", JSON.stringify(collapsed)); } catch {}
    render();
  }
  function countsEl(items) {
    if (items.some((p) => p.scanning || p.queued)) return el("span", { class: "spin", "aria-label": t("scanningAria") });
    if (!items.some((p) => p.report)) return el("span", { class: "cnt" }, "—");
    const c = items.reduce((a, p) => { const x = counts(p.report); return { urgent: a.urgent + x.urgent, plan: a.plan + x.plan, mal: a.mal + x.mal }; }, { urgent: 0, plan: 0, mal: 0 });
    return el("span", { class: "cnt" }, c.mal ? el("b", null, "!" + c.mal + " ") : null, c.urgent ? el("b", null, c.urgent) : "0", " · ", c.plan);
  }
  function projButton(p, label, child) {
    const pkg = p.name && p.name !== baseName(p.dir) ? p.name : "";
    return el("button", { class: "proj" + (child ? " child" : "") + (p.dir === current ? " active" : ""), title: p.dir + (pkg ? "\n" + pkg : ""), onclick: () => select(p.dir) },
      el("span", { class: "nm" }, el("span", { class: "lbl" }, label), pkg && pkg !== label ? el("span", { class: "pkg" }, pkg) : null),
      countsEl([p]));
  }
  function groupNav(g) {
    if (g.items.length === 1 && g.items[0].dir === g.dir) return projButton(g.items[0], baseName(g.dir), false);
    const open = !collapsed[g.dir];
    const head = el("div", { class: "fgrp" + (FOLDER + g.dir === current ? " active" : "") + (g.items.some((p) => p.dir === current) ? " has-active" : "") },
      el("button", { class: "caret", "aria-expanded": String(open), "aria-label": t("expand"), title: t("expand"), onclick: () => toggleGroup(g.dir) }, open ? "▾" : "▸"),
      el("button", { class: "gname", title: g.dir, onclick: () => select(FOLDER + g.dir) },
        el("span", { class: "nm" }, el("span", { class: "lbl" }, baseName(g.dir)), el("span", { class: "pkg" }, t("nProjects", g.items.length))),
        countsEl(g.items)));
    return el("div", { class: "fgroup" }, head,
      open ? el("div", { class: "kids", role: "group" }, g.items.map((p) => projButton(p, relTo(p.dir, g.dir) || t("folderRoot"), true))) : null);
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
      st.readOnly ? null : el("button", { class: "small ghost danger", onclick: () => removeProject(p) }, t("remove")),
      p.report ? el("button", { class: "small primary", onclick: () => openPrompt([p], p.dir) }, t("aiBtn")) : null);
    const g = groupsOf(st.projects).find((x) => x.items.includes(p));
    if (g && g.items.length > 1 && !st.readOnly) {
      bar.append(el("span", { class: "gsep" }),
        el("button", { class: "small", disabled: st.busy || undefined, onclick: () => scan(g.items.map((x) => x.dir)) }, t("scanFolder", g.items.length)),
        el("button", { class: "small ghost danger", onclick: () => removeGroup(g) }, t("removeFolder", g.items.length)));
    }
    if (!p.report) {
      return el("div", null, bar, el("div", { class: "empty" }, el("h1", null, p.name), p.scanning || p.queued ? t("firstScan") : t("notScanned")));
    }
    const r = p.report;
    const srcs = (r.sources || []).filter((x) => x.requests > 0);
    const sub = [r.node && r.node.version ? "Node " + r.node.version : r.node && r.node.line ? "Node " + r.node.line : null,
      r.manager, t("packages", r.packages || 0), r.lockfile || t("noLockfile"), r.repo].filter(Boolean).join(" · ");
    const head = el("div", { class: "phead" },
      el("div", null, el("h1", null, r.name), el("div", { class: "sub" }, sub),
        r.approximate ? el("div", { class: "sub warntext" }, t("approx")) : null));
    return el("div", null, bar, head, tabbed(projectCtx(p)),
      el("div", { class: "srcfoot" }, el("button", { class: "link", onclick: () => openSources(r) },
        t("srcFoot", (srcs.length ? srcs : st.sources || []).map((x) => x.name).join(" · ")))));
  }

  // ---------- sections (tabs) shared by the project and the folder page ----------
  const keyOf = (f) => f.group + "|" + (f.key || f.pkg) + "|" + f.current;
  const grpTitle = (grp) => t((GROUPS.find((x) => x[0] === grp) || [0, "gOk"])[1]);
  function nodeLine(n) {
    const target = n.securityFix || n.latestInLine;
    return "Node " + (n.version || n.line || "?") + (target && n.version && target !== n.version ? " → " + target : "") + " · " + needText("node", n.need);
  }
  function projectCtx(p) {
    const r = p.report;
    return {
      reps: [p], dir: p.dir, g: null,
      entries: (r.findings || []).map((f) => ({ f, where: null, rep: r })),
      card: (e) => card(e.f, r, null, null, true),
      bulk: (es) => { const c = bulkCommand(es.map((e) => e.f), r.manager); return c ? el("div", { class: "bulk" }, el("code", null, c), copyBtn(c)) : null; },
      bundles: (r.bundles || []).map((b) => bundleCard(b)),
      docker: { issues: r.docker || [], files: r.dockerFiles || [], label: null },
      server: { issues: r.server || [], files: r.serverFiles || [], label: null },
      nodes: r.node ? [{ label: "", n: r.node }] : [],
      hygBad: (r.hygiene || []).filter((h) => !h.ok).length,
      env: () => el("div", { class: "side" }, nodeCard(r), hygieneCard(r)),
      migs: (e) => (e.f.migrate || []).map((m) => ({ m, label: "" })),
      errors: r.errors || [],
      extra: null,
    };
  }
  function tabbed(ctx) {
    const es = ctx.entries;
    const n = (grp) => es.filter((e) => e.f.group === grp).length;
    const urgent = n("now_easy") + n("now_code");
    const migs = es.map((e) => ({ e, ms: ctx.migs(e) })).filter((x) => x.ms.length);
    const hits = migs.reduce((a, x) => a + x.ms.reduce((b, y) => b + (y.m.hits || 0), 0), 0);
    const di = ctx.docker.issues;
    const nodeNow = ctx.nodes.some((x) => x.n.need === "now");
    const envN = (nodeNow ? 1 : 0) + ctx.hygBad;
    const info = {
      overview: ["", false],
      packages: [es.filter((e) => e.f.group !== "ok").length, urgent > 0],
      code: [hits, false],
      docker: [di.length, di.some((d) => d.severity === "high")],
      server: [ctx.server.issues.length, ctx.server.issues.some((d) => d.severity === "high")],
      env: [envN, nodeNow],
      ai: ["", false],
    };
    const hasServer = ctx.server.files.length > 0 || ctx.server.issues.length > 0;
    const tabs = TABS.filter((k) => k !== "server" || hasServer);
    const tab = tabs.includes(state.tab) ? state.tab : "overview";
    const bar = el("div", { class: "tabs", role: "tablist", "aria-label": t("sections") }, tabs.map((k) => el("button", {
      role: "tab", "aria-selected": String(k === tab), tabindex: k === tab ? "0" : "-1", onclick: () => goTab(k),
      onkeydown: (ev) => {
        const d = ev.key === "ArrowRight" ? 1 : ev.key === "ArrowLeft" ? -1 : 0;
        if (!d) return;
        ev.preventDefault();
        goTab(tabs[(tabs.indexOf(k) + d + tabs.length) % tabs.length]);
        const b = $(".tabs [aria-selected=true]"); if (b) b.focus();
      },
    }, info[k][1] ? el("span", { class: "alert", "aria-hidden": "true" }) : null, t(TABL[k]), info[k][0] ? el("span", { class: "n" }, info[k][0]) : null)));
    const body = tab === "packages" ? packagesTab(ctx) : tab === "code" ? codeTab(migs) : tab === "docker" ? dockerTab(ctx.docker)
      : tab === "server" ? dockerTab(ctx.server, "server")
      : tab === "env" ? ctx.env() : tab === "ai" ? aiTab(ctx) : overviewTab(ctx, { n, urgent, hits, migs, nodeNow });
    return el("div", null, bar, el("div", { class: "tabbody", role: "tabpanel", "aria-label": t(TABL[tab]) }, body));
  }

  // the few things to do first, across all sections
  function stepsOf(ctx) {
    const S = [];
    for (const e of ctx.entries) {
      const f = e.f;
      if (f.group === "ok" || f.group === "optional") continue;
      const bad = f.kind === "malware" || f.kind === "removed";
      const score = f.kind === "malware" ? 1000 : f.kind === "removed" ? 900 : (f.priority || 0) + (f.group === "plan" ? 0 : 200);
      S.push({
        score, bad: bad || f.severity === "critical",
        title: (f.kind === "malware" ? t("malicious") + ": " : f.kind === "removed" ? t("removedChip") + ": " : "") + f.pkg + " " + f.current + (f.target && f.target !== f.current ? " → " + f.target : ""),
        sub: [f.title, t("qImpact").replace(/^②\s*/, "") + " " + impText(f.codeImpact), e.where && e.where.length > 1 ? t("nProjects", e.where.length) : ""].filter(Boolean).join(" · "),
        tab: "packages", o: { grp: f.group, open: keyOf(f) },
      });
    }
    for (const x of ctx.nodes) if (x.n.need === "now") S.push({ score: 250, bad: true, title: (x.label ? x.label + ": " : "") + nodeLine(x.n), sub: tr((x.n.why || [])[0]), tab: "env" });
    for (const d of ctx.docker.issues) if (d.severity === "high") S.push({ score: 220, bad: false, title: tr(d.title), sub: (ctx.docker.label ? ctx.docker.label(d) : d.file) + (d.line ? ":" + d.line : "") + (d.service ? " · " + d.service : ""), tab: "docker" });
    for (const d of ctx.server.issues) if (d.severity === "high") S.push({ score: 230, bad: false, title: tr(d.title), sub: (ctx.server.label ? ctx.server.label(d) : d.file) + (d.line ? ":" + d.line : "") + (d.service ? " · " + d.service : ""), tab: "server" });
    return S.sort((a, b) => b.score - a.score).slice(0, 6);
  }
  function overviewTab(ctx, x) {
    const steps = stepsOf(ctx);
    const first = el("div", { class: "card steps" },
      el("div", { class: "h3" }, t("firstTitle")),
      el("div", { class: "quiet small" }, steps.length ? t("firstHelp") : t("firstNone")),
      steps.map((s, i) => el("div", { class: "step" + (s.bad ? " bad" : "") },
        el("span", { class: "num" }, i + 1),
        el("div", { class: "st" }, el("div", { class: "stt" }, s.title), s.sub ? el("div", { class: "sub" }, s.sub) : null),
        el("span", { class: "tabname" }, t(TABL[s.tab])),
        el("button", { class: "small", onclick: () => goTab(s.tab, s.o) }, t("go")))));
    const area = (tab, title, badge, bad, l1, l2) => el("button", { class: "card area", onclick: () => goTab(tab) },
      el("span", { class: "ah" }, el("span", null, title), badge ? el("span", { class: "chip" + (bad ? " sev-high" : badge === "✓" ? " ok" : "") }, badge) : null),
      l1 ? el("span", { class: "quiet small" }, l1) : null, l2 ? el("span", { class: "quiet small" }, l2) : null);
    const n = x.n, di = ctx.docker.issues, files = ctx.docker.files;
    const areas = el("div", { class: "areas" },
      area("packages", t("tabPackages"), x.urgent ? t("badgeUrgent", x.urgent) : "✓", x.urgent > 0,
        `${t("tEasy")}: ${n("now_easy")} · ${t("tCode")}: ${n("now_code")}`,
        `${t("tPlan")}: ${n("plan")} · ${t("tOptional")}: ${n("optional")} · ${t("tOk")}: ${n("ok")}`),
      area("code", t("tabCode"), x.hits ? t("areaPlaces", x.hits) : x.migs.length ? "" : "✓", false,
        x.migs.length ? x.migs.slice(0, 3).map((m) => m.e.f.pkg + " → " + m.ms[0].m.to).join(" · ") : t("codeNone"), ""),
      area("docker", "Docker", di.length ? t("dockerN", di.length) : files.length ? "✓" : "", di.some((d) => d.severity === "high"),
        files.length ? files.slice(0, 3).join(" · ") + (files.length > 3 ? " …" : "") : t("dockerNone"), ""),
      ctx.server.files.length || ctx.server.issues.length ? area("server", t("tabServer"), ctx.server.issues.length ? t("dockerN", ctx.server.issues.length) : "✓", ctx.server.issues.some((d) => d.severity === "high"),
        ctx.server.files.length ? ctx.server.files.slice(0, 3).join(" · ") + (ctx.server.files.length > 3 ? " …" : "") : t("serverImagesOnly"), "") : null,
      area("env", t("tabEnv"), x.nodeNow ? t("needNow") : "✓", x.nodeNow,
        ctx.nodes.length === 1 ? (ctx.nodes[0].label ? ctx.nodes[0].label + ": " : "") + nodeLine(ctx.nodes[0].n) : ctx.nodes.length ? t("nodeAll") : t("noNode"),
        t("hygiene") + ": " + (ctx.hygBad ? t("hygBad", ctx.hygBad) : t("hygOk"))));
    return [first, areas, ctx.extra,
      ctx.errors.length ? el("details", { class: "errs" }, el("summary", null, t("warningsN", ctx.errors.length)), el("ul", null, ctx.errors.map((e) => el("li", null, e)))) : null];
  }
  function packagesTab(ctx) {
    const chips = el("div", { class: "fchips", role: "group", "aria-label": t("tabPackages") }), help = el("div", { class: "ghelp" }), list = el("div");
    const toolbar = el("div", { class: "toolbar" },
      el("input", { type: "search", placeholder: t("search"), "aria-label": t("search"), value: state.q, oninput: (e) => { state.q = e.target.value; rerender(); } }),
      el("select", { "aria-label": t("allSev"), onchange: (e) => { state.sev = e.target.value; rerender(); } },
        ...[["", t("allSev")], ["critical", "critical"], ["high", "high+"], ["moderate", "moderate+"]].map(([v, l]) => el("option", { value: v, selected: state.sev === v }, l))),
      el("label", null, el("input", { type: "checkbox", checked: state.dev, onchange: (e) => { state.dev = e.target.checked; rerender(); } }), "devDependencies"));
    function rerender() {
      const vis = ctx.entries.filter((e) => visible(e.f));
      const opts = GROUPS.filter(([g]) => ctx.entries.some((e) => e.f.group === g)).map(([g, l]) => [g, t(l), vis.filter((e) => e.f.group === g).length]);
      if (ctx.bundles.length) opts.push(["bundles", t("bundlesTitle"), ctx.bundles.length]);
      let grp = state.grp;
      if (!opts.some((o) => o[0] === grp)) grp = (opts.find((o) => o[2]) || opts[0] || [""])[0];
      chips.replaceChildren(...opts.map(([g, l, c]) => el("button", { class: "fchip" + (g === grp ? " on" : ""), "aria-pressed": String(g === grp), onclick: () => { state.grp = g; rerender(); } }, l, el("b", null, c))));
      help.textContent = grp ? t("help_" + grp) : "";
      if (!grp) { list.replaceChildren(el("div", { class: "empty" }, t("noMatch"))); return; }
      if (grp === "bundles") { list.replaceChildren(...ctx.bundles); return; }
      const es = vis.filter((e) => e.f.group === grp);
      const out = [];
      if (!es.length) out.push(el("div", { class: "empty" }, t("noMatch")));
      else if (grp === "ok") out.push(el("div", { class: "card" }, el("div", { class: "oklist" }, es.map((e) => el("div", null, `${e.f.pkg}@${e.f.current}`, e.where && e.where.length > 1 ? el("span", { class: "quiet" }, " ×" + e.where.length) : null)))));
      else {
        if (grp === "now_easy") out.push(ctx.bulk(es));
        out.push(el("div", { class: "rlist" },
          el("div", { class: "rhead", "aria-hidden": "true" }, el("span", null, t("colPkg")), el("span", null, t("colVer")), el("span", null, t("colWhy")), el("span", null, t("colImpact")), el("span")),
          es.map((e) => prow(e, ctx))));
      }
      list.replaceChildren(...out.filter(Boolean));
    }
    rerender();
    return [chips, toolbar, help, list];
  }
  // one compact row per package; the full answer opens below it
  function prow(e, ctx) {
    const f = e.f, k = keyOf(f), bad = f.kind === "malware" || f.kind === "removed";
    const open = state.open.has(k) || bad && !state.shut.has(k);
    const sev = f.kind === "malware" ? t("malicious") : f.kind === "removed" ? t("removedChip") : f.severity || "";
    const d = el("details", { class: "prow" + (bad ? " mal" : ""), open: open || undefined },
      el("summary", null,
        el("span", { class: "c1" }, el("code", { class: "pk" }, f.pkg),
          el("span", { class: "quiet small" }, [f.direct ? t("direct") : t("transitive"), f.dev ? "dev" : "", e.where && e.where.length > 1 ? t("nProjects", e.where.length) : ""].filter(Boolean).join(" · "))),
        el("span", { class: "c2" }, f.current, f.target && f.target !== f.current ? [el("span", { class: "arr" }, " → "), el("b", null, f.target)] : null),
        el("span", { class: "c3" }, sev ? el("span", { class: "chip sev-" + (bad ? "critical" : f.severity) }, sev) : null,
          el("span", { class: "t" }, f.title || tr((f.why || [])[0]) || "")),
        el("span", { class: "c4 " + impClass(f.codeImpact) }, impText(f.codeImpact))),
      ctx.card(e));
    d.dataset.key = k;
    d.addEventListener("toggle", () => { if (d.open) { state.open.add(k); state.shut.delete(k); } else { state.open.delete(k); state.shut.add(k); } });
    return d;
  }
  function codeTab(migs) {
    if (!migs.length) return el("div", { class: "empty" }, t("codeNone"));
    const order = { now_code: 0, now_easy: 1, plan: 2, optional: 3, ok: 4 };
    const xs = [...migs].sort((a, b) => ((order[a.e.f.group] ?? 5) - (order[b.e.f.group] ?? 5)) || (b.e.f.priority || 0) - (a.e.f.priority || 0));
    return [el("div", { class: "ghelp" }, t("codeHelp"), " ", t("readOnlyNote")),
      xs.map(({ e, ms }) => el("div", { class: "card" },
        el("div", { class: "ctitle" }, el("span", { class: "pkg" }, e.f.pkg),
          el("span", { class: "ver" }, e.f.current, e.f.target ? [el("span", { class: "arr" }, "→"), e.f.target] : null),
          el("span", { class: "chip" }, grpTitle(e.f.group)),
          el("span", { class: "grow" }),
          el("button", { class: "link small", onclick: () => goTab("packages", { grp: e.f.group, open: keyOf(e.f) }) }, t("toPackage"))),
        ms.map((x) => migBlock(x.m, x.label, true))))];
  }
  const SEVC = { high: "sev-high", medium: "sev-moderate", low: "" };
  function dockerTab(dk, kind) {
    const srv = kind === "server";
    if (!dk.files.length && !dk.issues.length) return el("div", { class: "empty" }, t("dockerNone"));
    const checked = dk.files.length ? el("div", { class: "quiet small" }, t("dockerFiles", dk.files.join(", "))) : null;
    if (!dk.issues.length) return el("div", { class: "card" }, el("div", null, t("dockerOk", dk.files.join(", "))));
    const by = new Map();
    for (const d of dk.issues) { const f = dk.label ? dk.label(d) : d.file; if (!by.has(f)) by.set(f, []); by.get(f).push(d); }
    return [el("div", { class: "ghelp" }, t(srv ? "serverHelp" : "dockerHelp"), " ", t("readOnlyNote")),
      [...by].map(([file, ds]) => el("div", { class: "card dfile" },
        el("div", { class: "dfh" }, el("code", null, file), el("span", { class: "quiet small" }, t("dockerN", ds.length))),
        ds.map((d) => el("div", { class: "ditem" },
          el("div", { class: "drow" }, el("span", { class: "chip " + (SEVC[d.severity] || "") }, d.severity), el("b", null, tr(d.title)),
            el("span", { class: "quiet small" }, (d.line ? file.split("/").pop() + ":" + d.line : "") + (d.service ? " · " + d.service : ""))),
          tr(d.detail) ? el("div", { class: "d" }, tr(d.detail)) : null,
          d.fix ? el("code", { class: "dfix" }, d.fix) : null)))),
      checked];
  }
  function aiTab(ctx) {
    const scanned = ctx.reps.filter((p) => p.report);
    const c = (title, text, btn) => el("div", { class: "card aicard" }, el("div", { class: "h3" }, title), el("div", { class: "quiet small" }, text), btn);
    return el("div", { class: "areas" },
      c(t("aiBtn"), t("aiHelp"), el("button", { class: "primary", onclick: () => openPrompt(scanned, ctx.dir, ctx.g) }, t("aiOpen"))),
      c(t("rulesBtn"), t("rulesHelp"), el("button", { onclick: () => openRules(scanned, ctx.dir, ctx.g) }, t("rulesOpen"))),
      st.readOnly ? null : c(t("mcpBtn"), t("mcpHelp"), el("button", { onclick: () => openMCP(ctx.dir) }, t("mcpOpen"))));
  }

  // ---------- data sources ----------
  function openSources(rep) {
    const list = (rep && rep.sources && rep.sources.length ? rep.sources : st && st.sources) || [];
    const scanned = !!(rep ? rep.sources : st && st.lastScan);
    const close = () => { ov.remove(); document.removeEventListener("keydown", esc); };
    const esc = (e) => { if (e.key === "Escape") close(); };
    const status = (x) => !scanned ? el("span", { class: "chip" }, t("srcNotYet")) :
      x.failed ? el("span", { class: "chip warn" }, t("srcFailed", x.failed)) :
      x.requests ? el("span", { class: "chip ok" }, st && st.offline ? t("srcCache") : (x.requests === 1 ? t("srcReq1") : t("srcReq", x.requests))) :
      el("span", { class: "chip" }, t("srcUnused"));
    const dlg = el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": t("sourcesTitle") },
      el("div", { class: "mhead" }, el("div", { class: "h3" }, t("sourcesTitle")), el("div", { class: "quiet" }, t("sourcesIntro"))),
      el("div", { class: "srclist" },
        el("div", { class: "srcsec" }, t("sourcesOnline")),
        list.map((x) => el("div", { class: "srcrow" },
          el("div", { class: "srcmain" },
            safeURL(x.url) ? el("a", { href: x.url, target: "_blank", rel: "noopener noreferrer" }, x.name) : el("b", null, x.name),
            el("div", { class: "quiet" }, tr(x.use))),
          status(x))),
        el("div", { class: "srcsec" }, t("sourcesLocal")),
        el("div", { class: "srcrow" }, el("div", { class: "srcmain quiet" }, t("sourcesLocalText")))),
      el("div", { class: "pfoot" }, el("span", { class: "grow" }), el("button", { onclick: () => close() }, t("close"))));
    const ov = el("div", { class: "overlay", onclick: (e) => { if (e.target === ov) close(); } }, dlg);
    document.body.append(ov); document.addEventListener("keydown", esc);
    dlg.querySelector("button, a").focus();
  }
  $("#srcbtn").addEventListener("click", () => {
    const p = st && (st.projects || []).find((x) => x.dir === current);
    openSources(p && p.report && p.report.sources ? p.report : null);
  });

  // ---------- folder overview: every project of a folder on one page ----------
  const relName = (p, g) => relTo(p.dir, g.dir) || t("folderRoot");
  const cdPrefix = (p, g) => { const r = relTo(p.dir, g.dir); return r ? "cd " + (/\s/.test(r) ? JSON.stringify(r) : r) + " && " : ""; };
  function mergeFindings(ps) {
    const by = new Map();
    for (const p of ps) for (const f of (p.report && p.report.findings) || []) {
      const k = f.group + "|" + f.key + "|" + f.current + ">" + (f.target || "");
      if (!by.has(k)) by.set(k, { f, where: [] });
      by.get(k).where.push({ p, f });
    }
    return [...by.values()].sort((a, b) => (b.f.priority || 0) - (a.f.priority || 0) || a.f.pkg.localeCompare(b.f.pkg));
  }
  function folderView(g) {
    const ps = g.items, scanned = ps.filter((p) => p.report);
    const busy = ps.some((p) => p.scanning || p.queued);
    const bar = el("div", { class: "pbar" },
      el("div", { class: "pdir", title: g.dir }, g.dir),
      busy ? el("span", { class: "chip busy" }, el("span", { class: "spin" }), t("scanningChip")) : null,
      st.readOnly ? null : el("button", { class: "small", disabled: st.busy || undefined, onclick: () => scan(ps.map((x) => x.dir)) }, t("scanFolder", ps.length)),
      st.readOnly ? null : el("button", { class: "small ghost danger", onclick: () => removeGroup(g) }, t("removeFolder", ps.length)),
      scanned.length ? el("button", { class: "small primary", onclick: () => openPrompt(scanned, g.dir, g) }, t("aiBtn")) : null);
    if (!scanned.length) return el("div", null, bar, el("div", { class: "empty" }, el("h1", null, baseName(g.dir)), busy ? t("firstScan") : t("folderNotScanned")));

    const pkgs = scanned.reduce((a, p) => a + (p.report.packages || 0), 0);
    const head = el("div", { class: "phead" },
      el("div", null, el("h1", null, baseName(g.dir)), el("div", { class: "sub" }, t("folderSub", ps.length, pkgs))));

    const rows = el("div", { class: "card ptable" }, el("div", { class: "h3" }, t("folderProjects")),
      el("table", null,
        el("thead", null, el("tr", null, el("th", null, t("colProject")), el("th", null, t("tEasy")), el("th", null, t("tCode")), el("th", null, t("tPlan")), el("th", null, t("tOptional")), el("th", null, "Node"))),
        el("tbody", null, ps.map((p) => {
          const s = (p.report && p.report.summary) || {};
          const num = (v, bad) => el("td", { class: "num" + (v && bad ? " bad" : "") }, p.report ? v || 0 : "—");
          const nd = p.report && p.report.node;
          return el("tr", { class: "clickable", onclick: () => select(p.dir) },
            el("td", null, el("div", null, s.malware ? el("span", { class: "chip sev-critical" }, t("malicious")) : null, " ", relName(p, g)), p.name !== baseName(p.dir) ? el("div", { class: "quiet small" }, p.name) : null),
            num(s.now_easy, true), num(s.now_code, true), num(s.plan), num(s.optional),
            el("td", { class: nd && nd.need === "now" ? "bad" : "" }, nd ? (nd.version || nd.line || "?") + (nd.securityFix && nd.securityFix !== nd.version ? " → " + nd.securityFix : "") : "—"));
        }))));

    const dk = new Map(), dfiles = new Set();
    for (const p of scanned) {
      for (const f of p.report.dockerFiles || []) dfiles.add(relTo(joinPath(p.dir, f), g.dir) || f);
      for (const d of p.report.docker || []) {
        const abs = joinPath(p.dir, d.file);
        const k = abs + "|" + d.line + "|" + d.rule + "|" + (d.service || "");
        if (!dk.has(k)) dk.set(k, { ...d, abs });
      }
    }
    const merge = (issuesOf, filesOf) => {
      const m = new Map(), fs = new Set();
      for (const p of scanned) {
        for (const f of filesOf(p.report) || []) fs.add(relTo(joinPath(p.dir, f), g.dir) || f);
        for (const d of issuesOf(p.report) || []) {
          const abs = joinPath(p.dir, d.file);
          const k = abs + "|" + d.line + "|" + d.rule + "|" + (d.service || "");
          if (!m.has(k)) m.set(k, { ...d, abs });
        }
      }
      const sev = { high: 0, medium: 1, low: 2 };
      return { issues: [...m.values()].sort((a, b) => sev[a.severity] - sev[b.severity] || a.abs.localeCompare(b.abs) || a.line - b.line), files: [...fs], label: (d) => relTo(d.abs, g.dir) || d.abs };
    };
    const dIssues = [...dk.values()].sort((a, b) => ({ high: 0, medium: 1, low: 2 }[a.severity] - { high: 0, medium: 1, low: 2 }[b.severity]) || a.abs.localeCompare(b.abs) || a.line - b.line);
    const ctx = {
      reps: scanned, dir: g.dir, g,
      entries: mergeFindings(scanned).map((e) => ({ f: e.f, where: e.where, rep: e.where[0].p.report })),
      card: (e) => card(e.f, e.rep, e.where, g, true),
      bulk: (es) => {
        const lines = [];
        for (const p of g.items) {
          const fs = es.flatMap((e) => e.where.filter((w) => w.p === p).map((w) => w.f));
          const cmd = fs.length ? bulkCommand(fs, p.report.manager) : "";
          if (cmd) lines.push(cdPrefix(p, g) + cmd);
        }
        return lines.length ? el("div", { class: "bulk multi" }, el("pre", null, lines.join("\n")), copyBtn(lines.join("\n"))) : null;
      },
      bundles: scanned.flatMap((p) => (p.report.bundles || []).map((b) => bundleCard({ ...b, command: b.command ? cdPrefix(p, g) + b.command : "" }, relName(p, g)))),
      docker: { issues: dIssues, files: [...dfiles], label: (d) => relTo(d.abs, g.dir) || d.abs },
      server: merge((r) => r.server, (r) => r.serverFiles),
      nodes: scanned.filter((p) => p.report.node).map((p) => ({ label: relName(p, g), n: p.report.node })),
      hygBad: scanned.reduce((a, p) => a + (p.report.hygiene || []).filter((h) => !h.ok).length, 0),
      env: () => el("div", { class: "side" }, folderNodeCard(g, scanned), folderHygieneCard(g, scanned)),
      migs: (e) => e.where.flatMap((w) => (w.f.migrate || []).map((m) => ({ m, label: e.where.length > 1 ? relName(w.p, g) : "" }))),
      errors: scanned.flatMap((p) => (p.report.errors || []).map((x) => relName(p, g) + ": " + x)),
      extra: rows,
    };
    return el("div", null, bar, head, tabbed(ctx));
  }
  function folderNodeCard(g, ps) {
    const withNode = ps.filter((p) => p.report.node);
    if (!withNode.length) return el("div", { class: "card" }, el("div", { class: "h3" }, "Node.js"), el("div", { class: "sub quiet" }, t("noNode")));
    const bad = withNode.some((p) => p.report.node.need === "now");
    return el("div", { class: "card" + (bad ? " bad" : "") }, el("div", { class: "h3" }, t("nodeAll")),
      withNode.map((p) => {
        const nd = p.report.node, target = nd.securityFix || nd.latestInLine;
        return el("div", { class: "q nrow" }, el("span", { class: "dot " + needClass(nd.need) }),
          el("span", { class: "lbl" }, relName(p, g)),
          el("span", { class: "ans" }, "Node " + (nd.version || nd.line || "?") + (target && nd.version && target !== nd.version ? " → " + target : "")),
          el("span", { class: "quiet small" }, needText("node", nd.need) + (nd.vulns && nd.vulns.length ? " · " + nd.vulns.length + " CVE" : "")));
      }));
  }
  function folderHygieneCard(g, ps) {
    const by = new Map();
    for (const p of ps) for (const h of p.report.hygiene || []) {
      if (!by.has(h.id)) by.set(h.id, { h, bad: [], all: 0 });
      const e = by.get(h.id); e.all++; if (!h.ok) e.bad.push(p);
    }
    const es = [...by.values()];
    const nbad = es.filter((e) => e.bad.length).length;
    return el("div", { class: "card hyg" },
      el("div", { class: "h3" }, t("hygAll"), el("span", { class: "chip" }, nbad ? t("hygBad", nbad) : t("hygOk"))),
      es.map(({ h, bad }) => el("div", { class: "item " + (bad.length ? "no" : "ok") },
        el("span", { class: "mk" }, bad.length ? "!" : "✓"),
        el("div", null, el("div", null, tr(h.title)),
          bad.length ? el("div", { class: "d" }, t("inProjects", bad.map((p) => relName(p, g)).join(", "))) : null,
          bad.length && h.fix ? el("div", null, h.file ? el("span", { class: "d" }, h.file + ": ") : null, el("code", null, h.fix)) : null))));
  }

  // ---------- AI prompt: everything to fix, where, to which version and why ----------
  function promptFor(ps, rootDir, g) {
    const L = [], join = (xs) => (xs || []).map(tr).filter(Boolean).join("; ");
    const label = (p) => g ? relName(p, g) + (p.name !== baseName(p.dir) ? " (" + p.name + ")" : "") : p.name;
    let tasks = 0, nproj = 0;
    const hygAll = new Map();
    const code = (x) => x.includes("\n") ? ["", "```", x, "```"] : ["`" + x + "`"];
    L.push(t("pH1"), "", t("pIntro"), "");
    L.push(`- ${t("pScope")}: ${rootDir}${g ? " — " + t("nProjects", ps.length) : ""}`);
    const when = ps.map((p) => p.report.scannedAt).filter(Boolean).sort().pop() || st.lastScan;
    if (when) L.push(`- ${t("pScanned")}: ${fmtTime(when)} (${st.tool || "depgate"})`);
    L.push("", t("pRules"), ...["pRule1", "pRule2", "pRule3", "pRule4", "pRule5", "pRule6"].map((k, i) => `${i + 1}. ${t(k)}`), "");
    const order = { malware: 0 };
    for (const p of ps) {
      const r = p.report, fs = (r.findings || []).filter((f) => ["now_easy", "now_code", "plan"].includes(f.group));
      fs.sort((a, b) => (order[a.kind] ?? 1) - (order[b.kind] ?? 1) || (b.priority || 0) - (a.priority || 0));
      const opt = (r.findings || []).filter((f) => f.group === "optional");
      const nd = r.node && r.node.need && r.node.need !== "none" ? r.node : null;
      const bundles = r.bundles || [];
      const dock = (r.docker || []).filter((d) => d.severity !== "low");
      const srvI = (r.server || []).filter((d) => d.severity !== "low");
      for (const h of (r.hygiene || []).filter((h) => !h.ok)) {
        const k = h.id + "|" + (h.file || "") + "|" + (h.fix || "");
        if (!hygAll.has(k)) hygAll.set(k, { h, where: [] });
        hygAll.get(k).where.push(label(p));
      }
      if (!fs.length && !opt.length && !nd && !bundles.length && !dock.length && !srvI.length) continue;
      nproj++;
      L.push(t("pProject", label(p)), "");
      L.push(`- ${t("pPath")}: ${p.dir}`);
      L.push(`- ${t("pMgr")}: ${r.manager || "npm"}${r.lockfile ? " · " + r.lockfile : " · " + t("noLockfile")}${r.node && r.node.version ? " · Node " + r.node.version : ""}`);
      if (r.approximate) L.push(`- ${t("pWarn")}: ${t("approx")}`);
      L.push("");
      fs.forEach((f, i) => {
        tasks++;
        const tags = [f.kind === "malware" ? t("malicious") : needText(f.kind, f.needUpdate), f.severity, f.kind === "vuln" || f.kind === "malware" ? "P" + f.priority : null, f.direct ? t("direct") : t("transitive"), f.dev ? "dev" : t("prod")].filter(Boolean);
        L.push(`### ${i + 1}. ${f.pkg} ${f.current}${f.target ? " → " + f.target : ""}  [${tags.join(" · ")}]`);
        if (f.title) L.push(`- ${t("pProblem")}: ${f.title}`);
        if (!f.direct && f.chain && f.chain.length > 1) L.push(`- ${t("pChain")}: ${f.chain.join(" → ")}`);
        if (f.advisories && f.advisories.length) L.push(`- ${t("pAdv")}: ` + f.advisories.map((a) => [a.id, (a.aliases || []).filter((x) => x.startsWith("CVE-")).join(", "), a.severity, a.cvss ? "CVSS " + a.cvss : "", a.epss ? "EPSS " + Math.round(a.epss * 100) + "%" : "", a.kev ? "CISA KEV" : "", a.fixed ? t("fixedIn", a.fixed).replace(/^ · /, "") : "", a.url].filter(Boolean).join(" · ")).join("; "));
        L.push(`- ${t("pWhy")}: ${join(f.why)}`);
        L.push(`- ${t("pImpact")}: ${impText(f.codeImpact)}${(f.impactWhy || []).length ? " — " + join(f.impactWhy) : ""}`);
        if (f.fix) {
          L.push(`- ${t("pFix")} (${strat(f.fix.strategy)}):${f.fix.command ? " `" + f.fix.command.split("   #")[0] + "`" : ""}`);
          if (f.fix.snippet) L.push("", "```json" + (f.fix.file ? "  // " + f.fix.file : ""), f.fix.snippet, "```");
          if (tr(f.fix.note)) L.push(`- ${t("pNote")}: ${tr(f.fix.note)}`);
        }
        if (f.warnings && f.warnings.length) L.push(`- ${t("pWarn")}: ${join(f.warnings)}`);
        for (const m of f.migrate || []) {
          if (m.plan) { L.push(`- ${t("pMigPlan", m.to, m.hits)}`); continue; }
          L.push(`- ${t("pMig")} (→ ${m.to}):`);
          for (const st of m.steps || []) {
            L.push(`  - ${st.topic} — ${st.docs}`);
            if (st.codemod) L.push(`    - codemod: \`${st.codemod}\``);
            for (const h of st.hits || []) L.push(`    - ${h.file}:${h.line} — ${tr(h.msg)}${h.fix ? " → `" + h.fix.split("\n")[0] + "`" : ""}`);
            for (const c of st.checks || []) L.push(`    - ${t("migChecks")}: ${tr(c)}`);
          }
          for (const n of m.notes || []) L.push(`  - release ${n.version}${n.url ? " (" + n.url + ")" : ""}: ${n.breaking.replace(/\s+/g, " ").slice(0, 400)}`);
        }
        L.push("");
      });
      if (bundles.length) {
        L.push(t("pBundles"));
        for (const b of bundles) {
          tasks++;
          L.push(`- ${b.name}${b.target ? " → " + b.target : ""} — ${join(b.why)}`);
          for (const it of b.items || []) L.push(`  - ${it.pkg} ${it.current}${it.target ? " → " + it.target : " (" + t("bundleStays") + ")"}${tr(it.note) ? " — " + tr(it.note) : ""}`);
          if (b.command) L.push(`  - ${t("pFix")}: \`${b.command}\``);
          if (b.docs) L.push(`  - ${t("docs")}: ${b.docs}`);
        }
        L.push("");
      }
      if (dock.length) {
        L.push(t("pDocker"));
        for (const d of dock) {
          tasks++;
          L.push(`- [${d.severity}] ${d.file}${d.line ? ":" + d.line : ""}${d.service ? " (" + d.service + ")" : ""} — ${tr(d.title)}${tr(d.detail) ? ": " + tr(d.detail) : ""}${d.fix ? " — `" + d.fix + "`" : ""}`);
        }
        L.push("");
      }
      if (srvI.length) {
        L.push(t("pServer"));
        for (const d of srvI) {
          tasks++;
          L.push(`- [${d.severity}] ${d.file}${d.line ? ":" + d.line : ""}${d.service ? " (" + d.service + ")" : ""} — ${tr(d.title)}${tr(d.detail) ? ": " + tr(d.detail) : ""}${d.fix ? " — `" + d.fix + "`" : ""}`);
        }
        L.push("");
      }
      if (nd) {
        tasks++;
        const target = nd.securityFix || nd.latestInLine;
        L.push(t("pNode"), `- Node ${nd.version || nd.line || "?"}${target && target !== nd.version ? " → " + target : ""} [${needText("node", nd.need)}] — ${t("pImpact")}: ${impText(nd.impact)}`);
        if (nd.why && nd.why.length) L.push(`- ${t("pWhy")}: ${join(nd.why)}`);
        if (nd.sources && nd.sources.length) L.push(`- ${t("pPath")}: ` + nd.sources.map((x) => `${x.file}: ${x.value}`).join("; "));
        if (nd.vulns && nd.vulns.length) L.push(`- ${t("pAdv")}: ` + nd.vulns.map((v) => [(v.cve || []).join(", ") || v.id, v.severity, v.title, v.url].filter(Boolean).join(" · ")).join("; "));
        if (nd.command) L.push(`- ${t("pFix")}: \`${nd.command.split("   #")[0]}\``);
        L.push("");
      }
      if (opt.length) { L.push(t("pOptional"), ...opt.map((f) => `- ${f.pkg} ${f.current} → ${f.target || f.latest || "?"}${f.dev ? " (dev)" : ""}${f.fix && f.fix.command ? " — `" + f.fix.command.split("   #")[0] + "`" : ""}`), ""); }
    }
    if (hygAll.size) {
      L.push("## " + t("pHyg").replace(/^#+\s*/, ""));
      for (const { h, where } of hygAll.values()) {
        L.push(`- ${tr(h.title)}${tr(h.detail) ? " — " + tr(h.detail) : ""}${ps.length > 1 ? " (" + t("inProjects", where.join(", ")) + ")" : ""}`);
        if (h.fix) { const c = code(h.fix); L.push(`  ${h.file ? h.file + ": " : ""}${c[0]}`, ...c.slice(1)); }
      }
      L.push("");
    }
    if (!nproj && !hygAll.size) return { text: t("aiNothing"), tasks: 0, projects: 0 };
    L.push(t("pReport"), t("pReportText"));
    return { text: L.join("\n"), tasks, projects: nproj };
  }
  function textModal(title, help, text, stats, filename) {
    const close = () => { ov.remove(); document.removeEventListener("keydown", esc); };
    const esc = (e) => { if (e.key === "Escape") close(); };
    const ta = el("textarea", { class: "prompt", readonly: true, spellcheck: "false" }, text);
    const dl = () => {
      const a = el("a", { href: URL.createObjectURL(new Blob([text], { type: "text/markdown" })), download: filename });
      document.body.append(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
    };
    const dlg = el("div", { class: "modal wide", role: "dialog", "aria-modal": "true", "aria-label": title },
      el("div", { class: "mhead" }, el("div", { class: "h3" }, title), el("div", { class: "quiet" }, help), el("div", { class: "quiet small" }, t("readOnlyNote"))),
      el("div", { class: "pad" }, ta),
      el("div", { class: "pfoot" }, el("div", { class: "quiet" }, stats), el("span", { class: "grow" }),
        el("button", { onclick: dl }, t("download", filename.slice(filename.lastIndexOf(".")))), el("button", { onclick: () => close() }, t("close")),
        el("button", { class: "primary", onclick: () => copy(text) }, t("copy"))));
    const ov = el("div", { class: "overlay", onclick: (e) => { if (e.target === ov) close(); } }, dlg);
    document.body.append(ov); document.addEventListener("keydown", esc); ta.focus(); ta.setSelectionRange(0, 0);
  }
  function openPrompt(ps, rootDir, g) {
    const pr = promptFor(ps, rootDir, g);
    textModal(t("aiTitle"), t("aiHelp"), pr.text, t("aiStats", pr.tasks, pr.projects), "depgate-" + baseName(rootDir) + ".md");
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

  function bundleCard(b, where) {
    return el("div", { class: "card bundle" },
      el("div", { class: "ctitle" }, el("span", { class: "pkg" }, b.name), b.target ? el("span", { class: "ver" }, el("span", { class: "arr" }, "→"), b.target) : null,
        el("span", { class: "chip " + impClass(b.impact) }, t("qImpact").replace(/^②\s*/, "") + " " + impText(b.impact)),
        where ? el("span", { class: "chip" }, where) : null),
      el("ul", { class: "why" }, list(b.why)),
      el("table", { class: "btable" }, el("tbody", null, (b.items || []).map((it) => el("tr", null,
        el("td", null, el("code", null, it.pkg), it.dev ? el("span", { class: "chip" }, "dev") : null),
        el("td", null, it.current),
        el("td", { class: it.target ? "good" : "quiet" }, it.target ? "→ " + it.target : t("bundleStays")),
        el("td", { class: "quiet small" }, tr(it.note)))))),
      b.command ? el("div", { class: "fix" }, el("div", { class: "row" }, el("code", null, b.command), copyBtn(b.command))) : null,
      safeURL(b.docs) ? el("div", { class: "cfoot" }, el("a", { href: b.docs, target: "_blank", rel: "noopener noreferrer" }, t("docs") + ": " + b.docs)) : null);
  }
  // normalise "a/b/../c" so the same compose file seen from two projects is one entry
  function joinPath(dir, rel) {
    const out = [];
    for (const part of (dir + "/" + rel).split("/")) {
      if (part === "" || part === ".") continue;
      if (part === "..") out.pop(); else out.push(part);
    }
    return "/" + out.join("/");
  }
  function rulesFor(ps, g) {
    const L = [], day = new Date().toISOString().slice(0, 10);
    let nr = 0, nx = 0;
    for (const p of ps) {
      const r = p.report && p.report.aiRules;
      if (!r) continue;
      if (ps.length > 1) L.push(`### ${g ? relName(p, g) : p.report.name}${g && p.name !== baseName(p.dir) ? " (" + p.name + ")" : ""}`, "");
      if (r.stack && r.stack.length) {
        L.push("Stack (exact versions from the lockfile):");
        for (const x of r.stack) L.push(`- ${x.pkg} ${x.version}${x.docs ? " — " + x.docs : ""}`);
        L.push("", "Write code for these exact versions. Do not use APIs from other major versions; when unsure, check the linked docs or the package's own docs in node_modules.", "");
      }
      let topic = "";
      for (const x of r.rules || []) {
        nr++;
        if (x.topic !== topic) { topic = x.topic; L.push(`${topic}${x.docs ? " (" + x.docs + ")" : ""}:`); }
        L.push(`- ${x.text}`);
      }
      if ((r.rules || []).length) L.push("");
      if (r.replace && r.replace.length) {
        L.push("Prefer built-in or maintained alternatives (suggest, ask before replacing existing code):");
        for (const x of r.replace) { nx++; L.push(`- \`${x.pkg}\` → ${x.use} — ${x.why}${x.docs ? " (" + x.docs + ")" : ""}`); }
        L.push("");
      }
    }
    if (!L.length) return { text: t("rulesNothing"), rules: 0, repl: 0 };
    const text = [`<!-- depgate:ai-rules — generated by DepGate on ${day} from the installed versions; regenerate after upgrades -->`, "## Dependency versions and rules", "", ...L, "<!-- /depgate:ai-rules -->"].join("\n");
    return { text, rules: nr, repl: nx };
  }
  async function openMCP(dir) {
    let info = { enabled: false, token: "" };
    try { info = await api("GET", "api/mcp"); } catch {}
    const q = (x) => /^[\w@%+=:,./-]+$/.test(x) ? x : "'" + x.replace(/'/g, "'\\''") + "'";
    const url = location.origin + "/mcp?project=" + encodeURIComponent(dir);
    const L = [];
    if (info.enabled && info.token) {
      L.push("# 1) Recommended — over HTTP to this DepGate server: same projects and reports as this page, works with Docker too.",
        "#    The command contains your DepGate token: -s local keeps it out of the project files.",
        `cd ${q(dir)} && claude mcp add --transport http depgate -s local ${q(url)} --header ${q("Authorization: Bearer " + info.token)}`,
        "",
        "# Cursor (.cursor/mcp.json), VS Code, Windsurf… — keep this file out of git (it holds the token)",
        JSON.stringify({ mcpServers: { depgate: { url, headers: { Authorization: "Bearer " + info.token } } } }, null, 2),
        "");
    }
    const cmdline = st.container ? ["docker", "exec", "-i", "depgate", "depgate", "mcp", "--project", dir] : ["depgate", "mcp", "--project", dir];
    L.push(`# ${info.enabled ? "2" : "1"}) Over stdio — the agent starts DepGate itself (${st.container ? "inside the DepGate container" : "uses the local data folder"})`,
      `cd ${q(dir)} && claude mcp add depgate -s local -- ${cmdline.map(q).join(" ")}`,
      "",
      "# Tools: project_status · get_findings · get_fix_plan · get_code_changes · get_docker_issues · get_ai_rules · check_package · scan_project · list_projects",
      "# Ask the agent e.g.: \"fix this project's dependencies with DepGate\" or \"check with DepGate before adding a package\"");
    textModal(t("mcpTitle"), t("mcpHelp"), L.join("\n"), t("mcpStats"), "depgate-mcp.txt");
  }
  function openRules(ps, rootDir, g) {
    const r = rulesFor(ps, g);
    textModal(t("rulesTitle"), t("rulesHelp"), r.text, t("rulesStats", r.rules, r.repl), "AGENTS-depgate-" + baseName(rootDir) + ".md");
  }

  const SEVR = { critical: 4, high: 3, moderate: 2, low: 1 };
  function visible(f) {
    if (!state.dev && f.dev) return false;
    if (state.q && !f.pkg.toLowerCase().includes(state.q.toLowerCase())) return false;
    if (state.sev && (f.kind !== "vuln" && f.kind !== "malware" || (SEVR[f.severity] || 0) < SEVR[state.sev])) return false;
    return true;
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

  function migBlock(m, label, openAll) {
    const steps = m.steps || [];
    const head = m.plan ? t("migPlan", m.to, m.hits) : t("migNow", m.to, m.hits || t("migNone"));
    return el("details", { class: "mig" + (m.plan ? " plan" : ""), open: (openAll ? m.hits > 0 : !m.plan && m.hits > 0) || undefined },
      el("summary", null, label ? el("span", { class: "chip" }, label) : null, head),
      el("div", { class: "quiet small" }, t("migHint"), " ", t("readOnlyNote")),
      steps.map((st) => el("div", { class: "mstep" },
        el("div", { class: "mtopic" }, el("b", null, st.topic), safeURL(st.docs) ? el("a", { href: st.docs, target: "_blank", rel: "noopener noreferrer" }, t("docs")) : null),
        st.codemod ? el("div", { class: "row codemod" }, el("span", { class: "quiet small" }, t("migCodemod")), el("code", null, st.codemod), copyBtn(st.codemod)) : null,
        (st.hits || []).length ? el("ul", { class: "hits" }, st.hits.map((h) => el("li", null,
          el("div", null, el("code", { class: "loc" }, h.file + ":" + h.line), " ", el("span", null, tr(h.msg))),
          h.code && h.code !== h.file ? el("pre", { class: "snip" }, h.code) : null,
          h.fix ? el("div", { class: "quiet small" }, "→ ", el("code", null, h.fix)) : null))) : null,
        (st.checks || []).length ? el("div", { class: "checks" }, el("span", { class: "quiet small" }, t("migChecks")), el("ul", { class: "why" }, list(st.checks))) : null)),
      (m.notes || []).length ? el("details", { class: "notes" }, el("summary", null, t("migNotes", m.notes.length)),
        m.notes.map((n) => el("div", { class: "note" },
          safeURL(n.url) ? el("a", { href: n.url, target: "_blank", rel: "noopener noreferrer" }, n.version) : el("b", null, n.version),
          el("pre", { class: "snip" }, n.breaking)))) : null,
      m.notesErr ? el("div", { class: "quiet small" }, t("migNotesErr", m.notesErr)) : null);
  }

  // bare: the card's body inside a package row (the row already shows name, version and chips)
  function card(f, p, where, g, bare) {
    const vuln = f.kind === "vuln" || f.kind === "malware";
    const cls = bare ? "rbody" : "card" + (f.kind === "malware" ? " mal bad" : f.kind === "removed" ? " bad" : "");
    const title = el("div", { class: "ctitle" },
      el("span", { class: "pkg" }, f.pkg),
      el("span", { class: "ver" }, f.current, f.target ? [el("span", { class: "arr" }, "→"), f.target] : null),
      f.severity ? el("span", { class: "chip sev-" + f.severity }, f.kind === "malware" ? t("malicious") : f.kind === "removed" ? t("removedChip") : f.severity) : null,
      el("span", { class: "chip" }, f.direct ? t("direct") : t("transitive")),
      f.dev ? el("span", { class: "chip" }, "dev") : null,
      vuln ? el("span", { class: "chip prio", title: t("prioTitle") }, "P" + f.priority) : null,
      f.latest && f.latest !== f.target && f.latest !== f.current ? el("span", { class: "chip", title: t("latestTitle") }, t("latest", f.latest)) : null);

    const kids = bare ? [el("div", { class: "rchips" }, [...title.querySelectorAll(".chip[title]")])] : [title];
    if (f.title && !bare) kids.push(el("div", { class: "ctext" }, f.title));
    if (f.chain && f.chain.length > 1) kids.push(el("div", { class: "chain" }, f.chain.join(" → ")));
    kids.push(el("div", { class: "q" }, el("span", { class: "dot " + needClass(f.needUpdate) }), el("span", { class: "lbl" }, t("qNeed")), el("span", { class: "ans" }, needText(f.kind, f.needUpdate))));
    if (f.why && f.why.length) kids.push(el("ul", { class: "why" }, list(f.why)));
    kids.push(el("div", { class: "q" }, el("span", { class: "dot " + impClass(f.codeImpact) }), el("span", { class: "lbl" }, t("qImpact")), el("span", { class: "ans" }, impText(f.codeImpact))));
    if (f.impactWhy && f.impactWhy.length) kids.push(el("ul", { class: "why" }, list(f.impactWhy)));
    const migs = where ? where.flatMap((w) => (w.f.migrate || []).map((m) => [m, where.length > 1 ? relName(w.p, g) : ""])) : (f.migrate || []).map((m) => [m, ""]);
    if (bare && migs.length) {
      const hits = migs.reduce((a, [m]) => a + (m.hits || 0), 0);
      kids.push(el("button", { class: "tocode" + (migs.some(([m]) => !m.plan) ? " now" : ""), onclick: () => goTab("code") }, hits ? t("seeCode", hits) : t("seeCode0")));
    } else for (const [m, l] of migs) kids.push(migBlock(m, l));
    if (f.warnings && f.warnings.length) kids.push(el("div", { class: "warnbox" }, f.warnings.map((w) => el("div", null, "⚠ " + tr(w)))));
    if (where) {
      const lines = where.map((w) => w.f.fix && w.f.fix.command ? cdPrefix(w.p, g) + w.f.fix.command.split("   #")[0] : "").filter(Boolean);
      kids.push(el("div", { class: "where" },
        el("div", { class: "row" }, el("b", null, where.length === 1 ? t("whereN1") : t("whereN", where.length)), el("span", { class: "grow" }), lines.length > 1 ? copyBtn(lines.join("\n"), t("whereAll")) : null),
        where.map((w) => el("div", { class: "row" },
          el("button", { class: "link", onclick: () => select(w.p.dir), title: w.p.dir }, relName(w.p, g)),
          w.f.fix && w.f.fix.command ? [el("code", null, cdPrefix(w.p, g) + w.f.fix.command.split("   #")[0]), copyBtn(cdPrefix(w.p, g) + w.f.fix.command.split("   #")[0])] : null))));
    }
    if (f.fix) {
      const fx = f.fix;
      const note = tr(fx.note);
      const cmd = where ? "" : fx.command;
      kids.push(el("div", { class: "fix" },
        el("div", { class: "row" }, el("span", { class: "chip" }, strat(fx.strategy)), cmd ? el("code", null, cmd) : el("span", { class: "grow" }), cmd ? copyBtn(cmd.split("   #")[0]) : null),
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
    foot.append(el("span", { class: "grow" }), copyBtn(where ? where.map((w) => agentTask(w.f, w.p.report)).join("\n\n---\n\n") : agentTask(f, p), t("agentBtn")));
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
      n.vulns && n.vulns.length ? el("details", { class: "nvulns" }, el("summary", null, t("nodeCves", n.vulns.length)),
        el("ul", { class: "why" }, n.vulns.map((v) => el("li", null,
          safeURL(v.url) ? el("a", { href: v.url, target: "_blank", rel: "noopener noreferrer" }, (v.cve && v.cve[0]) || v.id) : (v.cve && v.cve[0]) || v.id,
          v.severity ? " · " + v.severity : "", " — ", v.title, v.env && v.env.length ? " (" + v.env.join(", ") + ")" : "")))) : null,
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
    if (!on) { $("#srcbtn").hidden = true; $("#scanall").hidden = true; $("#addproj").hidden = true; $("#projects").hidden = true; $("#banner").hidden = true; $("#meta").textContent = ""; }
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
