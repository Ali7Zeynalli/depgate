"use strict";
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const H = { "X-DepGate": "1" };
  const TABS = ["overview", "packages", "code", "docker", "server", "env", "ai", "history"];
  const TABL = { overview: "tabOverview", packages: "tabPackages", code: "tabCode", docker: "tabDocker", server: "tabServer", env: "tabEnv", ai: "tabAI", history: "tabHistory" };
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
  let envPick = "all";
  try { envPick = localStorage.getItem("depgate-env") || "all"; } catch {}
  const state = { q: "", sev: "", env: ["all", "prod", "dev"].includes(envPick) ? envPick : "all", flt: new Set(), tab: h0.tab, grp: "", open: new Set(), shut: new Set() };

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
    allSev: ["Bütün risk dərəcələri", "All severities"],
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
    tileCodeNone: ["indi yox", "none now"],
    tileCodeZero: ["{0} paket major dəyişir, yer tapılmadı — qeydlərə bax", "{0} packages change major, no places found — see the notes"],
    tileCodeZero1: ["1 paket major dəyişir, yer tapılmadı — qeydlərə bax", "1 package changes major, no places found — see the notes"],
    tileCodeMore: ["+{0} növbəti major-da", "+{0} at the next major"],
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
    migHint: ["Təxminidir: yerlər mətn nümunələri ilə tapılır, səhv və ya əskik ola bilər — öz kodunu analiz et, sonra build və testləri işlət.", "Approximate: places are found by text patterns and may be wrong or missing — analyse your own code, then run the build and tests."],
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
    mcpHelp: ["Qoş: sonra Claude Code, Cursor və ya başqa agent bu layihənin tapıntılarını, kod dəyişikliklərini və qaydalarını DepGate-dən özü soruşur, yeni paket əlavə etməzdən əvvəl check_package ilə yoxlayır. Bir dəfə qoşmaq bütün layihələr üçün kifayətdir.", "Connect it: Claude Code, Cursor or any agent then asks DepGate itself for this project's findings, code changes and rules, and checks every new package with check_package before installing it. Connecting once is enough for every project."],
    mcpStats: ["10 alət · yalnız oxuyur", "10 tools · read-only"],
    mcpAgent: ["Hansı AI agenti istifadə edirsən?", "Which AI agent do you use?"],
    mcpOther: ["Digər (stdio)", "Other (stdio)"],
    shBash: ["Terminal (bash/zsh, Git Bash)", "Terminal (bash/zsh, Git Bash)"],
    mcpRunIn: ["Terminal aç (layihə qovluğunda olmaq lazım deyil — əmr özü keçir).", "Open a terminal (any folder — the command changes into the project)."],
    mcpRun: ["Bu əmri işlət:", "Run this command:"],
    mcpCheck: ["Yoxla — siyahıda depgate «connected» görünməlidir:", "Check — depgate should show as connected:"],
    mcpClaudeNote: ["-s local: qoşulma yalnız səndə və yalnız bu layihədə saxlanır, layihə fayllarına yazılmır.", "-s local: the connection is stored only for you and only for this project, not in the project files."],
    mcpFile: ["Bu faylı yarat (varsa, depgate hissəsini içinə əlavə et):", "Create this file (if it exists, add the depgate entry to it):"],
    mcpGlobalFile: ["Bu faylı aç və depgate hissəsini əlavə et (fayl yoxdursa, yarat). Bir dəfə kifayətdir — bütün layihələr üçün işləyir, agent hansı qovluqda olduğunu özü bildirir:", "Open this file and add the depgate entry (create it if missing). Once is enough — it works for every project; the agent tells DepGate which folder it is in:"],
    mcpRunInAll: ["Terminal aç (istənilən qovluqda).", "Open a terminal (any folder)."],
    mcpAll: ["Bütün layihələr (bir dəfə)", "All projects (once)"],
    mcpOne: ["Yalnız bu layihə", "This project only"],
    mcpAllNote: ["-s user: bir dəfə qoşulursan, Claude Code hansı layihədə açılsa, DepGate-dən o layihəni soruşur. Layihə fayllarına heç nə yazılmır.", "-s user: connect once; whichever project Claude Code is opened in, it asks DepGate about that one. Nothing is written into your projects."],
    mcpPrompts: ["Claude Code-da hazır əmrlər:", "Ready commands in Claude Code:"],
    mcpGitignore: ["Faylda token var — .gitignore-a əlavə et:", "The file holds the token — add it to .gitignore:"],
    mcpCursorCheck: ["Cursor → Settings → MCP: depgate yaşıl olmalıdır (lazım olsa, yenilə).", "Cursor → Settings → MCP: depgate should be green (refresh if needed)."],
    mcpVsToken: ["Faylı saxla, server üzərində «Start» bas; token soruşulanda bunu yapışdır (VS Code onu təhlükəsiz saxlayır, fayla yazılmır):", "Save the file and click “Start” above the server; when asked for the token paste this (VS Code stores it securely, not in the file):"],
    mcpVsCheck: ["Copilot Chat → Agent rejimi → alətlər düyməsi: depgate alətləri görünməlidir.", "Copilot Chat → Agent mode → tools button: the depgate tools should be listed."],
    mcpWindsurfCheck: ["Cascade → MCP ikonu → Refresh: depgate görünməlidir.", "Cascade → MCPs icon → Refresh: depgate should appear."],
    mcpGeminiCheck: ["Gemini CLI-ı yenidən aç və yaz — depgate «Ready» olmalıdır:", "Restart Gemini CLI and type — depgate should be ready:"],
    mcpStdioHelp: ["Agent DepGate-i özü işə salır (server lazım deyil). MCP dəstəkləyən istənilən agent üçün.", "The agent starts DepGate itself (no server needed). For any agent that supports MCP."],
    mcpStdioClaude: ["Claude Code:", "Claude Code:"],
    mcpStdioJson: ["Digər agentlər (mcpServers JSON):", "Other agents (mcpServers JSON):"],
    mcpNoHttp: ["Bu rejimdə HTTP qoşulma yoxdur — yalnız stdio.", "No HTTP connection in this mode — stdio only."],
    mcpTokenNote: ["Əmrdə/faylda sənin DepGate tokenin var: onu paylaşma və git-ə əlavə etmə.", "The command/file contains your DepGate token: don't share it or commit it."],
    mcpTokenVs: ["Faylda token yoxdur, ona görə .vscode/mcp.json-u git-ə əlavə etmək olar.", "The file has no token, so .vscode/mcp.json can be committed."],
    mcpVerify: ["Qoşulduqdan sonra agent bu səhifənin «Tarixçə» bölməsində yaşıl nöqtə ilə görünəcək.", "Once connected, the agent shows up with a green dot in this page's History tab."],
    mcpAsk: ["Agentə yaz, məsələn: «DepGate ilə bu layihənin asılılıqlarını düzəlt» və ya «paket əlavə etməzdən əvvəl DepGate ilə yoxla».", "Then ask the agent e.g. “fix this project's dependencies with DepGate” or “check with DepGate before adding a package”."],
    mcpTools: ["Agentin alacağı alətlər ({0})", "Tools the agent gets ({0})"],
    toolCheck: ["paketi quraşdırmadan əvvəl yoxlayır: təhlükəsizdirmi, hansı versiya", "checks a package before install: is it safe, which version"],
    toolPlan: ["bütün düzəlişlər birdən — oxumaq üçün", "every fix at once — to read"],
    toolOverview: ["BURADAN BAŞLA: kateqoriyalara görə yoxlama siyahısı, səndən soruşmaq üçün", "START HERE: the checklist by category, to ask you"],
    toolStart: ["sənin seçdiyin tapşırıqlarla iş sessiyası (UI-də görünür)", "a work session with the tasks you chose (shown in the UI)"],
    toolTask: ["yalnız bir tapşırığın addımları", "the steps of one task only"],
    toolComplete: ["tapşırıqdan sonra DepGate özü yenidən skan edib yoxlayır", "after a task DepGate scans again and checks it itself"],
    toolFindings: ["tapıntılar: hədəf versiya, səbəb, əmr", "findings: target version, why, command"],
    toolCode: ["bir paket üçün dəyişməli kod yerləri (fayl:sətir)", "code places to change for one package (file:line)"],
    toolDocker: ["Docker, compose, nginx və Caddy tapıntıları", "Docker, compose, nginx and Caddy findings"],
    toolRules: ["layihənin versiyalarına görə kod yazma qaydaları", "coding rules for the project's versions"],
    toolHistory: ["son skanlar arasında nə dəyişib", "what changed between recent scans"],
    toolStatus: ["layihənin qısa xülasəsi", "short project summary"],
    toolScan: ["layihəni yenidən skan edir", "scans the project again"],
    toolList: ["DepGate-in bildiyi bütün layihələr", "all projects DepGate knows"],
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
    tabHistory: ["Tarixçə", "History"],
    colRisk: ["Risk", "Risk"],
    colWhat: ["Nədir və nə tapılıb", "What it is and what was found"],
    colDo: ["Nə et", "What to do"],
    tagMal: ["Zərərli", "Malicious"],
    tagRemoved: ["Silinib", "Removed"],
    tagDeprecated: ["Köhnəlib", "Deprecated"],
    tagUpdate: ["Yeniləmə", "Update"],
    tagKev: ["real hücumlarda", "exploited"],
    tagServer: ["Server", "Server"],
    sevCritical: ["Kritik", "Critical"],
    sevHigh: ["Yüksək", "High"],
    sevModerate: ["Orta", "Medium"],
    sevLow: ["Aşağı", "Low"],
    impPlaces: ["{0} yer", "{0} places"],
    todoCmd: ["Əmri işlət (yuxarıda, kopyala düyməsi ilə)", "Run the command above"],
    todoSnippet: ["Yuxarıdakı dəyişikliyi fayla əlavə et", "Add the change above to the file"],
    todoCode: ["Koddakı yerləri dəyiş — «Kod dəyişiklikləri» bölməsi (yerlər təxminidir: öz kodunu yoxla)", "Change the places in your code — the Code changes section (the places are approximate: check your code)"],
    todoOverride: ["Əmri işlət — override-ı package.json-a yazır və lockfile-ı yeniləyir (və ya aşağıdakı dəyişikliyi əl ilə əlavə et)", "Run the command — it writes the override into package.json and updates the lockfile (or add the change below by hand)"],
    cmdsBtn: ["Əmrlər", "Commands"],
    cmdsTitle: ["package.json və lockfile üçün əmrlər", "Commands for package.json and the lockfile"],
    cmdsHelp: ["Təklifdir: DepGate bunları özü işlətmir. Əvvəlcə commit et ki, geri qayıda biləsən; sonra build və testləri işlət. Kod dəyişikliyi tələb edənlər üçün əvvəlcə «Kod dəyişiklikləri» bölməsinə bax.", "Suggestions: DepGate does not run them. Commit first so you can go back; then run the build and the tests. For the ones that need code changes, look at the Code changes section first."],
    cmdsStats: ["{0} əmr", "{0} commands"],
    cmdsNone: ["İndi işlədiləcək əmr yoxdur.", "Nothing to run now."],
    cmdsHead: ["DepGate — package.json və lockfile üçün TƏKLİF olunan əmrlər", "DepGate — SUGGESTED commands for package.json and the lockfile"],
    cmdsCommit: ["Əvvəlcə: git add -A && git commit -m \"before dependency updates\"  (geri qayıtmaq üçün)", "First: git add -A && git commit -m \"before dependency updates\"  (so you can go back)"],
    cmdsAfter: ["Sonra: build və testləri işlət, DepGate-də yenidən skan et.", "Then: run the build and the tests, and scan again in DepGate."],
    cmdsMal: ["ZƏRƏRLİ paket — birinci bunu et", "MALWARE — do this first"],
    cmdsEasy: ["İndi et — kod dəyişmir", "Do now — no code change"],
    cmdsCode: ["İndi et — kod DƏYİŞİR (əvvəlcə «Kod dəyişiklikləri»-nə bax, yerlər təxminidir)", "Do now — code CHANGES (look at Code changes first; the places are approximate)"],
    cmdsOverride: ["Override (keçid paketlər) — valideyn paket düzəlişi götürəndə sil; workspace/monorepo-da kök qovluqda işlət", "Overrides (transitive packages) — remove once the parent package takes the fix; in a workspace/monorepo run it in the root folder"],
    cmdsOptional: ["İstəyə görə — təcili deyil (şərhdən çıxar)", "Optional — not urgent (uncomment)"],
    cmdsBundle: ["Birlikdə yenilənməli paketlər", "Packages that must update together"],
    cmdsPlan: ["Planla — hazır olanda (şərhdən çıxar)", "Plan — when you are ready (uncomment)"],
    codeNote: ["Diqqət: kod yerləri mətn nümunələri ilə tapılır və TƏXMİNİDİR — səhv və ya əskik ola bilər. Öz kodunu analiz et (və ya «AI üçün prompt» ilə agentə tapşır), sonra build və testləri işlət. DepGate faylı dəyişmir.", "Note: code places are found by text patterns and are APPROXIMATE — some may be wrong or missing. Analyse your own code (or hand it to your agent with «AI prompt»), then run the build and the tests. DepGate never changes your files."],
    updCheck: ["Yeniləməni yoxla", "Check for updates"],
    updNone: ["Ən son versiyadasan ({0})", "You have the latest version ({0})"],
    todoBuild: ["Build və testləri işlət", "Run the build and the tests"],
    todoRescan: ["DepGate-də yenidən skan et", "Scan again in DepGate"],
    hMal: ["Dərhal müdaxilə", "Act now"],
    hUrgent: ["Təcili diqqət", "Needs attention"],
    hPlan: ["Planlaşdır", "Plan ahead"],
    hOk: ["Qaydasındadır", "All good"],
    hTasks: ["{0} vacib iş", "{0} important tasks"],
    hNoTasks: ["təcili iş yoxdur", "nothing urgent"],
    hClean: ["{0}/{1} paket təmiz", "{0}/{1} packages clean"],
    tileMal: ["Zərərli", "Malicious"],
    tileNone: ["yoxdur", "none"],
    tileNow: ["İndi et", "Do now"],
    tileNowSub: ["{0} sadə · {1} kod dəyişir", "{0} simple · {1} code change"],
    tileCode: ["Kodda dəyişiklik", "Code changes"],
    tileCodeLater: ["növbəti major-da {0} paket", "{0} packages at the next major"],
    tileCodeLater1: ["növbəti major-da 1 paket", "1 package at the next major"],
    tileCodeSub: ["yer · {0} paket", "places · {0} packages"],
    tileCodeSub1: ["yer · 1 paket", "places · 1 package"],
    inProjects: ["layihələrdə {0}", "{0} in projects"],
    tileDs: ["Docker və server", "Docker & server"],
    tileDsSub: ["{0} yüksək · {1} orta · {2} aşağı", "{0} high · {1} medium · {2} low"],
    tileHist: ["Son dəyişiklik", "Last change"],
    tileHistNone: ["hələ müqayisə yoxdur", "nothing to compare yet"],
    tileAdv: ["yeni advisory", "new advisories"],
    pkgAllOk: ["Paketlərdə iş yoxdur", "Nothing to do in packages"],
    nodeN: ["{0} layihə · {1} yenilənməli", "{0} projects · {1} to update"],
    kTitle: ["Göstəricilər", "Indicators"],
    kOpen: ["Açıq vacib işlər", "Open important"],
    kOpenSub: ["zərərli, kritik/yüksək, «indi et», Node.js", "malware, critical/high, do now, Node.js"],
    kMttr: ["Orta düzəltmə müddəti", "Mean time to fix"],
    kMttrSub: ["son 90 gündə düzəliş: {0}", "fixes in 90 days: {0}"],
    kMttrNone: ["hələ düzəliş yoxdur", "nothing fixed yet"],
    kOldest: ["Ən köhnə açıq iş", "Oldest open"],
    kNothingOpen: ["açıq vacib iş yoxdur", "nothing important open"],
    kWeek: ["Bu həftə", "Last 7 days"],
    kWeekSub: ["yeni / həll olunub", "new / fixed"],
    kAccSoon: ["Qəbul edilmiş risk bitir", "Accepted risks ending"],
    kAccSoonSub: ["14 gün ərzində", "within 14 days"],
    kLast: ["Son skan", "Last scan"],
    kLastSub: ["avto-skan «⋯» menyusunda", "auto scan in the ⋯ menu"],
    kWeeks: ["Həftəlik: yeni və həll olunan", "Per week: new and fixed"],
    kNew: ["yeni", "new"],
    kFixed: ["həll olunub", "fixed"],
    kDays: ["{0} gün", "{0} days"],
    kHours: ["{0} saat", "{0} h"],
    kLessHour: ["< 1 saat", "< 1 h"],
    colTrend: ["Son skanlar", "Recent scans"],
    colOldest: ["Ən köhnə açıq", "Oldest open"],
    histN: ["Son {0} skan", "Last {0} scans"],
    histMove: ["Təcili işlər: {0} → {1}", "Urgent: {0} → {1}"],
    gAccepted: ["Risk qəbul edilib", "Risk accepted"],
    help_accepted: ["Sənin bilərəkdən qəbul etdiyin risklər. Təcili sayğaca daxil deyil; müddət bitəndə və ya paketin versiyası dəyişəndə öz qrupuna qayıdır.", "Risks you chose to accept. They don't count as urgent; each goes back to its group when the period ends or the package version changes."],
    tAccepted: ["Qəbul edilib", "Accepted"],
    hByAuto: ["avtomatik", "automatic"],
    accBtn: ["Riski qəbul et…", "Accept the risk…"],
    accTitle: ["Riski qəbul et: {0}", "Accept the risk: {0}"],
    accHelp: ["Bu tapıntı «Risk qəbul edilib» qrupuna keçəcək və təcili sayğaca daxil olmayacaq. Silinmir: müddət bitəndə və ya {0} başqa versiyaya keçəndə yenidən görünəcək. AI agent də bunu görür və toxunmur.", "The finding moves to “Risk accepted” and stops counting as urgent. It is not deleted: it comes back when the period ends or {0} changes version. AI agents see it too and leave it alone."],
    accReason: ["Səbəb (məcburi)", "Reason (required)"],
    accReasonPh: ["məs.: express 5-ə keçid aprelə planlaşdırılıb; açıq redirect istifadə olunmur", "e.g. the move to express 5 is planned for April; open redirects are not used"],
    accFor: ["Müddət", "For"],
    accDays: ["{0} gün", "{0} days"],
    accWhere: ["{0} layihədə tətbiq olunacaq", "Applies in {0} projects"],
    accSave: ["Qəbul et", "Accept"],
    accDone: ["Risk qəbul edildi", "Risk accepted"],
    accUndo: ["Geri al", "Undo"],
    accUndone: ["Tapıntı öz qrupuna qaytarıldı", "The finding is back in its group"],
    accInfo: ["Risk qəbul edilib — {0} tarixinədək. Səbəb: ", "Risk accepted until {0}. Reason: "],
    accFrom: ["Əvvəlki qrup: {0} · qəbul tarixi {1}", "Was: {0} · accepted on {1}"],
    accChip: ["qəbul edilib", "accepted"],
    accFromFile: ["Komandanın faylından — dəyişmək üçün faylı redaktə et:", "From the team file — edit it to change:"],
    accExpTitle: ["CI və komanda üçün", "For CI and your team"],
    accExpHelp: ["depgate-accept.json-u yüklə və layihənin (və ya repo-nun) kök qovluğuna qoy: depgate --ci və komandandakı hər DepGate bu riskləri eyni cür qəbul edəcək. DepGate faylı özü yazmır.", "Download depgate-accept.json and put it in the project (or repository) root: depgate --ci and every DepGate on your team treat these risks the same way. DepGate never writes the file itself."],
    accExpBtn: ["depgate-accept.json yüklə", "Download depgate-accept.json"],
    accNoMal: ["Zərərli paketin riski qəbul edilmir — onu dərhal sil.", "A malicious package's risk cannot be accepted — remove it now."],
    rescanLbl: ["Avto-skan", "Auto scan"],
    rescanOpt: ["hər {0} saat", "every {0} h"],
    rescanOffOpt: ["söndürülüb", "off"],
    metaAuto: ["avto-skan hər {0} saat", "auto scan every {0} h"],
    metaAutoOff: ["avto-skan söndürülüb", "auto scan off"],
    more: ["Daha çox", "More"],
    refresh: ["Yenilə (yeni nəticələri göstər)", "Refresh (show the latest results)"],
    refreshed: ["Yeniləndi", "Refreshed"],
    filters: ["Süzgəc", "Filter"],
    fKev: ["Real hücumda (KEV)", "Exploited (KEV)"],
    fEpss: ["EPSS ≥ 10%", "EPSS ≥ 10%"],
    fNoFix: ["Düzəlişi yoxdur", "No fix"],
    nAdv: ["{0} zəiflik", "{0} advisories"],
    ladderTitle: ["Hansı versiya nəyi düzəldir", "Which version fixes what"],
    ladderFixes: ["{0} zəifliyi düzəldir", "fixes {0}"],
    ladderSum: ["cəmi {0}/{1}", "{0}/{1} in total"],
    ladderTarget: ["tövsiyə olunan", "suggested"],
    ladderNone: ["{0} zəifliyin düzəlişi yoxdur", "{0} without a fix"],
    ladderNoneHelp: ["heç bir versiyada düzəlməyib — paketi əvəz etməyi və ya riski qəbul etməyi düşün", "no version fixes it — consider another package or accepting the risk"],
    addSkipped: ["{0} package.json asılılığı olmadığı üçün keçildi: {1}", "{0} package.json without dependencies left out: {1}"],
    rescanOff: ["Avto-skan: söndürülüb", "Auto scan: off"],
    rescanEvery: ["Avto-skan: hər {0} saat", "Auto scan: every {0} h"],
    rescanSaved: ["Avto-skan yadda saxlandı", "Auto scan saved"],
    updText: ["Yeni versiya var: DepGate {0} (səndə {1}).", "A new version is out: DepGate {0} (you have {1})."],
    updHow: ["Necə yeniləmək", "How to update"],
    updNotes: ["Nə dəyişib", "What's new"],
    updLater: ["Sonra", "Later"],
    updTitle: ["DepGate-i yenilə", "Update DepGate"],
    updDocker: ["Docker ilə işləyirsən. depgate qovluğunda:", "You run it in Docker. In the depgate folder:"],
    updBinary: ["Tək fayl: Releases səhifəsindən yeni faylı yüklə və köhnəsinin yerinə qoy (məlumatın qalır). Go ilə quraşdırmısansa:", "Single binary: download the new file from Releases and replace the old one (your data stays). Installed with Go:"],
    updData: ["Layihə siyahın, hesabatlar, tarixçə və parol yerində qalır.", "Your project list, reports, history and password stay."],
    hChart: ["Təcili işlər — son skanlar", "Urgent items — recent scans"],
    hScans: ["Skanlar ({0})", "Scans ({0})"],
    hNone: ["Hələ tarixçə yoxdur — növbəti skandan sonra burada görünəcək.", "No history yet — it starts with the next scan."],
    hFirst: ["ilk skan", "first scan"],
    hSame: ["dəyişiklik yoxdur", "no change"],
    hNew: ["+{0} yeni", "+{0} new"],
    hFixed: ["{0} aradan qalxıb", "{0} gone"],
    hChanged: ["{0} dəyişib", "{0} changed"],
    hLock: ["lockfile dəyişib", "lockfile changed"],
    hAdv: ["lockfile eynidir — yeni advisory çıxıb", "lockfile unchanged — new advisories"],
    hByUI: ["interfeys", "UI"],
    hByCLI: ["əmr sətri", "command line"],
    hByMCP: ["AI agent", "AI agent"],
    hCounts: ["təcili {0} · planla {1} · zərərli {2} · Docker/server {3}", "urgent {0} · plan {1} · malware {2} · Docker/server {3}"],
    hNewL: ["Yeni", "New"],
    envLbl: ["Mühit:", "Environment:"],
    envAll: ["Hamısı", "All"],
    envProd: ["Production", "Production"],
    envDev: ["Dev", "Dev"],
    envAllT: ["Production və dev birlikdə", "Production and dev together"],
    envProdT: ["Yalnız production-a çatanlar: dependencies, dev olmayan Docker/server faylları", "Only what reaches production: dependencies, Docker/server files that are not dev"],
    envDevT: ["Yalnız inkişaf: devDependencies, dev Docker/compose faylları və mərhələləri", "Only development: devDependencies, dev Docker/compose files and stages"],
    ofDev: ["{0}-i dev", "{0} dev"],
    envChip: ["dev", "dev"],
    envProdChip: ["prod", "prod"],
    envMark: ["Bu fayl:", "This file:"],
    envAuto: ["Avtomatik", "Automatic"],
    envAutoAs: ["Avtomatik ({0})", "Automatic ({0})"],
    envSaved: ["Saxlandı — yalnız DepGate-in data qovluğunda", "Saved — in DepGate's data folder only"],
    envFolder: ["Qovluq", "Folder"],
    wTitle: ["AI işləri", "AI work"],
    wHelp: ["Agent əvvəl yoxlama siyahısını göstərir, sən seçirsən, o bir-bir edir. «Təsdiqləndi» — DepGate yeni skanla özü yoxlayıb, agentin sözünə görə yox.", "The agent shows the checklist first, you choose, it does them one by one. «Verified» means DepGate checked it with a new scan itself — not the agent's word."],
    wNone: ["Hələ yoxdur. Agentə de: «DepGate ilə asılılıqları düzəlt» və ya /mcp__depgate__fix — əvvəl yoxlama siyahısını göstərəcək.", "Nothing yet. Tell your agent \"fix the dependencies with DepGate\" or use /mcp__depgate__fix — it shows the checklist first."],
    wOpen: ["işləyir · {0}/{1} təsdiqləndi", "working · {0}/{1} verified"],
    wFin: ["bitib · {0}/{1} təsdiqləndi", "finished · {0}/{1} verified"],
    wItems: ["{0}/{1} düzəlib", "{0}/{1} fixed"],
    wItemsN: ["{0} element", "{0} items"],
    wItemsN1: ["1 element", "1 item"],
    wChecked: ["yoxlandı {0}", "checked {0}"],
    wNote: ["Agentin qeydi:", "Agent's note:"],
    wMore: ["… daha {0} sessiya", "… {0} more sessions"],
    wTodo: ["gözləyir", "to do"],
    wDoing: ["icrada", "in progress"],
    wDone: ["✓ təsdiqləndi", "✓ verified"],
    wPartial: ["qismən", "partly done"],
    wNotDone: ["edilməyib", "not done"],
    wSkipped: ["ötürüldü", "skipped"],
    w_malware: ["Zərərli paketlər", "Malicious packages"],
    w_now: ["npm — indi et, kod dəyişmir", "npm — update now, no code change"],
    w_node: ["Node.js", "Node.js"],
    w_code: ["npm — indi et, kod dəyişir", "npm — update now, code changes"],
    w_docker: ["Docker və Compose", "Docker and Compose"],
    w_server: ["Veb server (nginx/Caddy)", "Web server (nginx/Caddy)"],
    w_setup: ["Layihə qurulumu", "Project setup"],
    w_plan: ["Planla — yeni major", "Plan — new majors"],
    pkTitle: ["Paket versiyaları dəyişib ({0})", "Package versions changed ({0})"],
    pkTrans: ["dolayı paketlər: {0}", "transitive packages: {0}"],
    pkMore: ["… və daha {0} (saxlanmayıb)", "… and {0} more (not stored)"],
    pkN: ["{0} paket dəyişib", "{0} packages changed"],
    pkDownN: ["{0} köhnə versiyaya qayıdıb", "{0} back to an older version"],
    pkUp: ["yeniləndi", "updated"],
    pkDown: ["köhnəyə qayıdıb", "older version"],
    pkAdd: ["yeni", "added"],
    pkRemove: ["silindi", "removed"],
    hFixedL: ["Aradan qalxıb", "Gone"],
    hChangedL: ["Dəyişib", "Changed"],
    hSameN: ["{0} skan dəyişikliksiz", "{0} scans without changes"],
    hClear: ["Tarixçəni təmizlə", "Clear history"],
    hClearConfirm: ["«{0}» üçün skan tarixçəsi və agent fəaliyyəti silinsin? Hesabatlar qalır.", "Delete the scan history and agent activity of “{0}”? Reports stay."],
    hCleared: ["Tarixçə təmizləndi", "History cleared"],
    hLocal: ["Tarixçə yalnız bu kompüterdə saxlanır: hər layihə üçün son 200 skan (90 gün) və agentlərin son 500 əməliyyatı.", "History stays on this computer: the last 200 scans per project (90 days) and the last 500 agent actions."],
    agTitle: ["Qoşulan AI agentlər", "Connected AI agents"],
    agNone: ["Hələ heç bir agent qoşulmayıb. Qoşmaq üçün: AI və MCP → Qoşulma əmri.", "No agent has connected yet. To connect one: AI & MCP → Connection command."],
    agActive: ["aktiv", "active"],
    agSeen: ["son dəfə {0}", "last seen {0}"],
    agCalls: ["sorğu: {0}", "calls: {0}"],
    agChecks: ["paket yoxlaması: {0}", "package checks: {0}"],
    agWarned: ["xəbərdarlıq: {0}", "flagged: {0}"],
    agScans: ["skan: {0}", "scans: {0}"],
    actTitle: ["Agent fəaliyyəti", "Agent activity"],
    actNone: ["Agent fəaliyyəti yoxdur.", "No agent activity yet."],
    vOk: ["təhlükəsiz", "ok"],
    vCaution: ["ehtiyatla", "caution"],
    vBlock: ["quraşdırma", "do not install"],
    evConnect: ["qoşuldu", "connected"],
    sinceTitle: ["Son dəyişiklik", "Last change"],
    hOpen: ["Tarixçə →", "History →"],
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
    seeCodePlan: ["Növbəti major-a keçəndə kodda {0} yer dəyişəcək → Kod dəyişiklikləri", "Moving to the next major later changes {0} places → Code changes"],
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
    aboutWhat: ["Bu paket nədir:", "What this package is:"],
    aboutNone: ["npm-də təsviri yoxdur", "no description on npm"],
    aboutHome: ["sayt", "homepage"],
    aboutHow: ["Layihəyə necə düşüb:", "How it got into the project:"],
    aboutDirect: ["birbaşa — package.json, {0}", "directly — package.json, {0}"],
    aboutVia: ["dolayı — {0}", "through other packages — {0}"],
    advFound: ["Nə tapılıb ({0})", "What was found ({0})"],
    advMore: ["Daha {0} advisory", "{0} more advisories"],
    advType: ["Zəiflik növü:", "Weakness type:"],
    advText: ["Advisory mətni (ingiliscə)", "Advisory text"],
    advKev: ["real hücumlarda istifadə olunur (CISA KEV)", "exploited in the wild (CISA KEV)"],
    advMeans: ["Bu zəiflik nə deməkdir", "What this weakness means"],
    advWhat: ["Nədir:", "What it is:"],
    advRisk: ["Nə açıq yaradır:", "What it opens up:"],
    issueWhy: ["Niyə risklidir:", "Why it matters:"],
    issueFix: ["Təklif:", "Suggested:"],
    malOne: ["Zərərli paket: {0}", "Malicious package: {0}"],
    malMany: ["Zərərli paketlər: {0}", "Malicious packages: {0}"],
    malWhere: ["layihə: {0}", "project: {0}"],
    malDo: ["Dərhal təhlükəsiz versiyaya keç, node_modules-u sil və tokenləri dəyiş.", "Move to the safe version now, delete node_modules and rotate your tokens."],
    malOpen: ["Təlimata bax →", "See the steps →"],
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
    $("#themelbl").textContent = t("theme");
    $("#refresh").title = t("refresh"); $("#refresh").setAttribute("aria-label", t("refresh"));
    $("#more").setAttribute("aria-label", t("more")); $("#more").title = t("more");
    $("#rescanlbl").textContent = t("rescanLbl");
    $("#lang").textContent = lang === "az" ? "EN" : "AZ";
    $("#lang").title = t("langTitle");
    $("#addproj").replaceChildren(el("span", { class: "plus", "aria-hidden": "true" }, "+"), el("span", { class: "full" }, t("addProject").replace(/^\+\s*/, "")));
    $("#addproj").setAttribute("aria-label", t("addProjectTitle"));
    $("#srcbtn").textContent = t("sources");
    $("#updbtn").textContent = t("updCheck");
    $("#logout").textContent = t("logout");
    $("#pwbtn").textContent = t("changePw");
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
    clearTimeout(toast.t); toast.t = setTimeout(() => x.classList.remove("on"), Math.min(6000, 1800 + Math.max(0, String(msg).length - 40) * 40));
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
  const GROUPS = [["now_easy", "gNowEasy", true], ["now_code", "gNowCode", true], ["plan", "gPlan", false], ["optional", "gOptional", false], ["accepted", "gAccepted", false], ["ok", "gOk", false]];
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
  // the page follows the server by itself: automatic scans, scans an AI agent ran,
  // another tab — it only redraws when something really changed
  let lastRaw = "";
  async function load(force) {
    const s = await api("GET", "api/state");
    if (!force && JSON.stringify(s) === lastRaw) { if (s.busy) { clearTimeout(pollT); pollT = setTimeout(() => load().catch(() => {}), 1200); } return; }
    setState(s);
  }
  const typing = () => { const a = document.activeElement; return a && (a.tagName === "INPUT" || a.tagName === "TEXTAREA" || a.tagName === "SELECT") && !a.closest(".menu"); };
  const quietRefresh = () => {
    if (!st || document.visibilityState !== "visible" || document.body.classList.contains("locked") || typing() || document.querySelector(".overlay")) return;
    load().catch(() => {});
  };
  setInterval(quietRefresh, 20000);
  window.addEventListener("focus", quietRefresh);
  document.addEventListener("visibilitychange", quietRefresh);
  const FOLDER = "folder:";
  const currentGroup = () => current.startsWith(FOLDER) ? groupsOf(st.projects).find((g) => FOLDER + g.dir === current && g.items.length > 1) : null;
  function setState(s) {
    st = s; lastRaw = JSON.stringify(s);
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
  $("#refresh").addEventListener("click", async () => {
    hcache.clear();
    try { await load(true); toast(t("refreshed")); } catch (e) { toast(t("error", e.message)); }
  });
  $("#addproj").addEventListener("click", () => openPicker(""));

  // "⋯" menu: the less used actions
  const menu = $("#moremenu"), moreBtn = $("#more");
  const closeMenu = () => { menu.hidden = true; moreBtn.setAttribute("aria-expanded", "false"); };
  moreBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    menu.hidden = !menu.hidden; moreBtn.setAttribute("aria-expanded", String(!menu.hidden));
    if (!menu.hidden) { const f = menu.querySelector("button:not([hidden]), select"); if (f) f.focus(); }
  });
  document.addEventListener("click", (e) => { if (!menu.hidden && !menu.contains(e.target)) closeMenu(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !menu.hidden) { closeMenu(); moreBtn.focus(); } });
  menu.addEventListener("click", (e) => { if (e.target.closest("button.mitem")) closeMenu(); });

  // ---------- render ----------
  function counts(r) {
    const s = (r && r.summary) || {};
    return { urgent: (s.now_easy || 0) + (s.now_code || 0), plan: s.plan || 0, mal: s.malware || 0 };
  }
  function render() {
    const ps = st.projects || [];
    $("#meta").textContent = [st.tool, st.lastScan ? t("lastScan", fmtTime(st.lastScan)) : null,
      !st.readOnly && ps.length ? (st.rescanHours ? t("metaAuto", st.rescanHours) : t("metaAutoOff")) : null,
      st.offline ? t("offline") : null, st.readOnly ? t("readOnly") : null].filter(Boolean).join(" · ");
    $("#scanall").hidden = st.readOnly || ps.length === 0;
    $("#refresh").hidden = st.readOnly;
    $("#addproj").hidden = st.readOnly;
    $("#srcbtn").hidden = false;
    $("#updbtn").hidden = !!st.readOnly;
    $("#scanall").disabled = st.busy;
    $("#scanall").textContent = st.busy ? t("scanning") : t("scanAll");
    renderRescan(ps.length);
    renderUpdate();

    const nav = $("#projects");
    nav.hidden = ps.length === 0;
    nav.setAttribute("aria-label", t("projects", ps.length));
    nav.replaceChildren(el("h2", null, t("projects", ps.length)), ...groupsOf(ps).map(groupNav));

    const mals = ps.flatMap((p) => ((p.report && p.report.findings) || []).filter((f) => f.kind === "malware").map((f) => ({ p, f })));
    const ban = $("#banner");
    if (mals.length) {
      ban.hidden = false; ban.className = "banner";
      const first = mals[0], names = [...new Set(mals.map((m) => m.f.pkg + " " + m.f.current))];
      const open = () => { current = first.p.dir; state.grp = first.f.group; goTab("packages", { grp: first.f.group, open: keyOf(first.f) }); };
      ban.replaceChildren(
        el("span", { class: "bicon", "aria-hidden": "true" }, "!"),
        el("b", null, t(names.length === 1 ? "malOne" : "malMany", names.slice(0, 3).join(", ") + (names.length > 3 ? " …" : ""))),
        el("span", { class: "bsub" }, ps.length > 1 ? t("malWhere", [...new Set(mals.map((m) => m.p.name))].join(", ")) + " · " : "", t("malDo")),
        el("span", { class: "grow" }),
        el("button", { class: "small binv", onclick: open }, t("malOpen")));
    }
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

  // on a phone the sidebar becomes one select
  function projSwitch() {
    const groups = groupsOf(st.projects || []);
    if ((st.projects || []).length < 2) return null;
    const opts = [];
    for (const g of groups) {
      if (g.items.length > 1) opts.push(el("option", { value: FOLDER + g.dir, selected: current === FOLDER + g.dir || undefined }, baseName(g.dir) + " — " + t("nProjects", g.items.length)));
      for (const p of g.items) {
        const c = counts(p.report);
        opts.push(el("option", { value: p.dir, selected: current === p.dir || undefined }, (g.items.length > 1 ? "  " + (relTo(p.dir, g.dir) || t("folderRoot")) : baseName(p.dir)) + (c.mal ? " · !" + c.mal : c.urgent ? " · " + c.urgent : "")));
      }
    }
    return el("select", { class: "pswitch", "aria-label": t("projects", st.projects.length), onchange: (e) => select(e.target.value) }, opts);
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
      projSwitch(),
      el("div", { class: "pdir", title: p.dir }, p.dir),
      p.scanning ? el("span", { class: "chip busy" }, el("span", { class: "spin" }), t("scanningChip")) : p.queued ? el("span", { class: "chip busy" }, t("queued")) : null,
      st.readOnly ? null : el("button", { class: "small", disabled: p.scanning || p.queued || undefined, onclick: () => scan([p.dir]) }, t("scan")),
      st.readOnly ? null : el("button", { class: "small ghost danger", onclick: () => removeProject(p) }, t("remove")),
      p.report ? el("button", { class: "small", onclick: () => openCommands([p], p.dir) }, t("cmdsBtn")) : null,
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
    const ctx = envView(projectCtx(p));
    const nd = r.node;
    const head = el("div", { class: "phead" },
      el("div", null, el("h1", null, r.name),
        el("div", { class: "pchips" },
          r.manager ? el("span", { class: "pc" }, r.manager) : null,
          el("span", { class: "pc" }, t("packages", r.packages || 0)),
          el("span", { class: "pc" + (r.lockfile ? "" : " warn") }, r.lockfile || t("noLockfile")),
          nd ? el("span", { class: "pc" + (nd.need === "now" ? " hi" : "") }, "Node " + (nd.version || nd.line || "?")) : null,
          r.repo ? el("span", { class: "pc" }, r.repo) : null),
        r.approximate ? el("div", { class: "sub warntext" }, t("approx")) : null),
      healthCard(ctx));
    return el("div", null, bar, head, tabbed(ctx),
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
  // production / dev: what runs in production, what only on a developer's machine.
  // A package in devDependencies is dev; a Docker or server file is dev when its
  // name, stage or compose profile says so, or when the user marked it.
  const isDevIssue = (d) => d.env === "dev";
  function envView(ctx) {
    const e = state.env;
    if (e === "all") return ctx;
    const keep = (dev) => (e === "dev") === dev;
    // malware stays in every view: in devDependencies it runs on your machine and in CI
    return { ...ctx, entries: ctx.entries.filter((x) => x.f.kind === "malware" || keep(!!x.f.dev)),
      docker: { ...ctx.docker, issues: ctx.docker.issues.filter((d) => keep(isDevIssue(d))) },
      server: { ...ctx.server, issues: ctx.server.issues.filter((d) => keep(isDevIssue(d))) } };
  }
  function envSwitch() {
    const set = (v) => { state.env = v; try { localStorage.setItem("depgate-env", v); } catch {} render(); };
    return el("div", { class: "envsw", role: "group", "aria-label": t("envLbl") },
      el("span", { class: "quiet small" }, t("envLbl")),
      [["all", "envAll"], ["prod", "envProd"], ["dev", "envDev"]].map(([v, k]) =>
        el("button", { class: "fchip" + (state.env === v ? " on" : ""), "aria-pressed": String(state.env === v), title: t(k + "T"), onclick: () => set(v) }, t(k))));
  }
  // what the environment selector of a Docker/server file needs: whose file it is and its state
  const fileRef = (p, f, label) => ({ dir: p.dir, file: f, label, auto: (p.report.fileEnv || {})[f] || "", mark: (p.report.envMarks || {})[f] || "" });
  function projectCtx(p) {
    const r = p.report;
    return {
      reps: [p], dir: p.dir, g: null, hkey: "only:" + p.dir,
      entries: (r.findings || []).map((f) => ({ f, where: null, rep: r })),
      card: (e) => card(e.f, r, null, null, true),
      bulk: (es) => { const c = bulkCommand(es.map((e) => e.f), r.manager); return c ? el("div", { class: "bulk" }, el("code", null, c), copyBtn(c)) : null; },
      bundles: (r.bundles || []).map((b) => bundleCard(b)),
      docker: { issues: r.docker || [], files: r.dockerFiles || [], label: null, ref: (f) => fileRef(p, f, f) },
      server: { issues: r.server || [], files: r.serverFiles || [], label: null, ref: (f) => fileRef(p, f, f) },
      nodes: r.node ? [{ label: "", n: r.node }] : [],
      hygBad: (r.hygiene || []).filter((h) => !h.ok).length,
      env: () => el("div", { class: "side" }, nodeCard(r), hygieneCard(r)),
      migs: (e) => (e.f.migrate || []).map((m) => ({ m, label: "" })),
      errors: r.errors || [],
      extra: null,
    };
  }
  // inline SVG (charts, rings): built with DOM calls, never innerHTML
  const SVGNS = "http://www.w3.org/2000/svg";
  const sv = (tag, a, ...kids) => { const e = document.createElementNS(SVGNS, tag); for (const [k, v] of Object.entries(a || {})) e.setAttribute(k, v); e.append(...kids); return e; };
  const SEVN = { critical: "sevCritical", high: "sevHigh", moderate: "sevModerate", medium: "sevModerate", low: "sevLow" };
  const sevName = (s) => SEVN[s] ? t(SEVN[s]) : s || "";
  // an override's command is only useful when it also writes package.json (npm pkg set …)
  const realCmd = (fx) => fx && fx.command && (fx.strategy !== "override" || fx.command.includes("npm pkg set ")) ? fx.command.split("   #")[0] : "";
  const cmdOf = (f) => realCmd(f.fix);

  // singular wording when there is one ("1 package"), when the text has a "…1" variant
  const tn = (k, n) => (n === 1 && D[k + "1"] ? t(k + "1") : t(k, n));
  // the numbers every section starts from
  function factsOf(ctx) {
    const es = ctx.entries;
    const n = (grp) => es.filter((e) => e.f.group === grp).length;
    const migs = es.map((e) => ({ e, ms: ctx.migs(e) })).filter((x) => x.ms.length);
    // "now" = the upgrade this scan suggests; "plan" = a later major — counted apart
    const sumHits = (plan) => migs.reduce((a, x) => a + x.ms.filter((y) => !!y.m.plan === plan).reduce((b, y) => b + (y.m.hits || 0), 0), 0);
    const hits = sumHits(false), hitsLater = sumHits(true);
    const pkgsNow = migs.filter((x) => x.ms.some((y) => !y.m.plan && y.m.hits)).length;
    const pkgsNowZero = migs.filter((x) => x.ms.some((y) => !y.m.plan) && !x.ms.some((y) => !y.m.plan && y.m.hits)).length;
    const pkgsLater = migs.filter((x) => x.ms.some((y) => y.m.plan)).length;
    const ds = [...ctx.docker.issues, ...ctx.server.issues];
    const sev = (s) => ds.filter((d) => d.severity === s).length;
    const mal = es.filter((e) => e.f.kind === "malware");
    const nodeNow = ctx.nodes.some((x) => x.n.need === "now");
    // a folder shows a finding once; "in projects" counts every project that has it (like the side list and History)
    const occ = (e) => (e.where ? e.where.length : 1);
    const inProj = (grp) => es.filter((e) => e.f.group === grp).reduce((a, e) => a + occ(e), 0);
    const total = ctx.reps.reduce((a, p) => a + ((p.report && p.report.packages) || 0), 0);
    const flagged = new Set(es.filter((e) => !["ok", "optional", "accepted"].includes(e.f.group))
      .flatMap((e) => (e.where || [{ p: { dir: "" } }]).map((w) => w.p.dir + "|" + e.f.pkg))).size;
    // the same rule as History's "Open important": malware, removed, critical/high, do now; a Node.js security release; high Docker/server findings
    const important = es.filter((e) => e.f.group !== "accepted" && e.f.group !== "ok" &&
      (e.f.kind === "malware" || e.f.kind === "removed" || e.f.severity === "critical" || e.f.severity === "high" || e.f.group === "now_easy" || e.f.group === "now_code"))
      .reduce((a, e) => a + occ(e), 0);
    const nodeTasks = ctx.nodes.filter((x) => x.n.need === "now").length;
    return { n, inProj, migs, hits, hitsLater, pkgsNow, pkgsNowZero, pkgsLater, ds, high: sev("high"), medium: sev("medium"), low: sev("low"), mal, nodeNow,
      malProj: mal.reduce((a, e) => a + occ(e), 0),
      urgent: n("now_easy") + n("now_code"), urgentProj: inProj("now_easy") + inProj("now_code"),
      tasks: important + nodeTasks + sev("high"), total, clean: Math.max(0, total - flagged),
      devUrgent: es.filter((e) => e.f.dev && (e.f.group === "now_easy" || e.f.group === "now_code")).length, dsDev: ds.filter(isDevIssue).length };
  }

  // the state of a project (or folder) at a glance: a ring of clean packages and one word
  function healthCard(ctx) {
    const x = factsOf(ctx);
    const tasks = x.tasks;
    const lvl = x.mal.length ? "bad" : x.urgent || x.nodeNow ? "hi" : x.n("plan") || x.high ? "warn" : "good";
    const label = { bad: "hMal", hi: "hUrgent", warn: "hPlan", good: "hOk" }[lvl];
    const share = x.total ? x.clean / x.total : 1, C = 2 * Math.PI * 18;
    const ring = sv("svg", { viewBox: "0 0 44 44", class: "ring " + lvl, role: "img", "aria-label": t("hClean", x.clean, x.total) },
      sv("circle", { cx: 22, cy: 22, r: 18, class: "track" }),
      sv("circle", { cx: 22, cy: 22, r: 18, class: "arc", "stroke-dasharray": (C * share).toFixed(1) + " " + C.toFixed(1), transform: "rotate(-90 22 22)" }));
    return el("div", { class: "health " + lvl }, ring,
      el("div", null, el("div", { class: "hl" }, t(label)),
        el("div", { class: "quiet small" }, [tasks ? t("hTasks", tasks) : t("hNoTasks"), t("hClean", x.clean, x.total)].join(" · "))));
  }

  // five numbers under the title; each opens its section
  function tilesOf(ctx, x) {
    const tile = (cls, label, value, sub, tab, o) => el("button", { class: "stile " + cls, onclick: () => goTab(tab, o) },
      el("span", { class: "sl" }, el("span", { class: "sdot", "aria-hidden": "true" }), label),
      el("span", { class: "sv" }, value), el("span", { class: "ss" }, sub));
    const malNames = [...new Set(x.mal.map((e) => e.f.pkg + " " + e.f.current))];
    const tiles = [
      tile(x.mal.length ? "bad" : "zero", t("tileMal"), x.mal.length, x.mal.length ? malNames.slice(0, 2).join(", ") + (x.malProj > x.mal.length ? " · " + t("inProjects", x.malProj) : "") : t("tileNone"), "packages", x.mal.length ? { grp: x.mal[0].f.group, open: keyOf(x.mal[0].f) } : null),
      tile(x.urgent ? "hi" : "zero", t("tileNow"), x.urgent, t("tileNowSub", x.n("now_easy"), x.n("now_code")) + (x.urgentProj > x.urgent ? " · " + t("inProjects", x.urgentProj) : "") + (state.env === "all" && x.devUrgent ? " · " + t("ofDev", x.devUrgent) : ""), "packages", { grp: x.n("now_easy") ? "now_easy" : "now_code" }),
      tile(x.hits ? "code" : "zero", t("tileCode"), x.hits,
        [x.hits ? tn("tileCodeSub", x.pkgsNow) : x.pkgsNowZero ? tn("tileCodeZero", x.pkgsNowZero) : x.pkgsLater ? t("tileCodeNone") : t("tileNone"),
          x.hitsLater ? t("tileCodeMore", x.hitsLater) : x.pkgsLater && !x.hits ? tn("tileCodeLater", x.pkgsLater) : ""].filter(Boolean).join(" · "), "code"),
      tile(x.high ? "warn" : x.ds.length ? "warn" : "zero", t("tileDs"), x.ds.length, x.ds.length ? t("tileDsSub", x.high, x.medium, x.low) + (state.env === "all" && x.dsDev ? " · " + t("ofDev", x.dsDev) : "") : t("tileNone"), ctx.docker.issues.length || !ctx.server.issues.length ? "docker" : "server"),
    ];
    if (!st.readOnly) tiles.push(slot(ctx.hkey, (h) => {
      const ds = h.projects.map((p) => p.scans.find((s) => !s.diff.first && (s.diff.new.length || s.diff.fixed.length || s.diff.changed.length))).filter(Boolean);
      if (!ds.length) return h.projects.some((p) => p.scans.length > 1) ? tile("zero", t("tileHist"), "0", t("hSame"), "history") : tile("zero", t("tileHist"), "—", t("tileHistNone"), "history");
      const nw = ds.reduce((a, s) => a + s.diff.new.length, 0), fx = ds.reduce((a, s) => a + s.diff.fixed.length, 0);
      const d = nw - fx, lock = ds.some((s) => s.diff.lockChanged);
      return tile(d > 0 ? "hi" : d < 0 ? "good" : "zero", t("tileHist"), (d > 0 ? "+" : d < 0 ? "−" : "") + Math.abs(d),
        [nw ? t("hNew", nw) : "", fx ? t("hFixed", fx) : "", lock ? t("hLock") : nw ? t("tileAdv") : ""].filter(Boolean).join(" · ") || t("hSame"), "history");
    }));
    return el("div", { class: "stiles" }, tiles);
  }

  function tabbed(ctx) {
    const x = factsOf(ctx);
    const es = ctx.entries, di = ctx.docker.issues, si = ctx.server.issues;
    const lvl = (is) => is.some((d) => d.severity === "high") ? "bad" : is.length ? "warn" : "";
    const info = {
      overview: ["", ""],
      packages: [es.filter((e) => e.f.group !== "ok" && e.f.group !== "accepted").length, x.mal.length || x.urgent ? "bad" : ""],
      code: [x.hits, ""],
      docker: [di.length, lvl(di)],
      server: [si.length, lvl(si)],
      env: [(x.nodeNow ? 1 : 0) + ctx.hygBad, x.nodeNow ? "bad" : ctx.hygBad ? "warn" : ""],
      ai: ["", ""],
      history: ["", ""],
    };
    const hasServer = ctx.server.files.length > 0 || si.length > 0;
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
    }, t(TABL[k]), info[k][0] ? el("span", { class: "n " + info[k][1] }, info[k][0]) : null)));
    const body = tab === "packages" ? packagesTab(ctx) : tab === "code" ? codeTab(x.migs) : tab === "docker" ? dockerTab(ctx.docker)
      : tab === "server" ? dockerTab(ctx.server, "server")
      : tab === "env" ? ctx.env() : tab === "ai" ? aiTab(ctx) : tab === "history" ? historyTab(ctx) : overviewTab(ctx, x);
    const out = el("div", null, envSwitch(), tilesOf(ctx, x), bar, el("div", { class: "tabbody", role: "tabpanel", "aria-label": t(TABL[tab]) }, body));
    requestAnimationFrame(() => { const b = out.querySelector(".tabs [aria-selected=true]"); if (b && b.scrollIntoView && b.parentNode.scrollWidth > b.parentNode.clientWidth) b.scrollIntoView({ block: "nearest", inline: "nearest" }); });
    return out;
  }

  // the few things to do first, across all sections
  function stepsOf(ctx) {
    const S = [];
    for (const e of ctx.entries) {
      const f = e.f;
      if (f.group === "ok" || f.group === "optional" || f.group === "accepted") continue;
      const score = f.kind === "malware" ? 1000 : f.kind === "removed" ? 900 : (f.priority || 0) + (f.group === "plan" ? 0 : 200);
      const lvl = f.kind === "malware" || f.kind === "removed" || f.severity === "critical" ? "bad" : f.group === "now_code" ? "code" : f.severity === "high" ? "hi" : "warn";
      const tag = f.kind === "malware" ? t("tagMal") : f.kind === "removed" ? t("removedChip") : f.group === "now_code" ? t("tCode") : f.severity ? sevName(f.severity) : f.group === "plan" ? t("tPlan") : t("tagUpdate");
      const one = !e.where || e.where.length === 1;
      const cmd = one && cmdOf(f) ? (e.where ? cdPrefix(e.where[0].p, ctx.g) : "") + cmdOf(f) : "";
      S.push({
        score, lvl, tag, kev: (f.advisories || []).some((a) => a.kev),
        title: f.pkg + " " + f.current + (f.target && f.target !== f.current ? " → " + f.target : ""),
        sub: [f.title, t("qImpact").replace(/^②\s*/, "") + " " + impText(f.codeImpact), e.where && e.where.length > 1 ? t("nProjects", e.where.length) : ""].filter(Boolean).join(" · "),
        cmd, tab: "packages", o: { grp: f.group, open: keyOf(f) },
      });
    }
    for (const x of ctx.nodes) if (x.n.need === "now") S.push({ score: 250, lvl: "hi", tag: "Node", title: (x.label ? x.label + ": " : "") + nodeLine(x.n), sub: tr((x.n.why || [])[0]), cmd: x.n.command && ctx.nodes.length === 1 ? x.n.command.split("   #")[0] : "", tab: "env" });
    for (const [is, tab, tag, score] of [[ctx.docker.issues, "docker", "Docker", 220], [ctx.server.issues, "server", t("tagServer"), 230]]) {
      const lab = tab === "docker" ? ctx.docker.label : ctx.server.label;
      for (const d of is) if (d.severity === "high") S.push({ score, lvl: "warn", tag, title: tr(d.title), sub: (lab ? lab(d) : d.file) + (d.line ? ":" + d.line : "") + (d.service ? " · " + d.service : ""), tab });
    }
    return S.sort((a, b) => b.score - a.score).slice(0, 6);
  }
  function overviewTab(ctx, x) {
    const steps = stepsOf(ctx);
    const first = el("section", { class: "card steps" },
      el("div", { class: "sh" }, el("h2", { class: "h3" }, t("firstTitle")), el("span", { class: "quiet small" }, steps.length ? t("firstHelp") : t("firstNone"))),
      steps.map((s) => el("div", { class: "step " + s.lvl },
        el("span", { class: "rail", "aria-hidden": "true" }),
        el("div", { class: "st" },
          el("div", { class: "stt" }, el("span", { class: "stag" }, s.tag), el("b", null, s.title), s.kev ? el("span", { class: "chip sev-critical" }, t("tagKev")) : null),
          s.sub ? el("div", { class: "sub" }, s.sub) : null),
        el("div", { class: "sact" },
          s.cmd ? [el("code", { class: "scmd", title: s.cmd }, s.cmd), copyBtn(s.cmd)] : null,
          el("button", { class: "small", onclick: () => goTab(s.tab, s.o) }, t("go"))))));

    // packages by group: one bar
    const segs = [["now_easy", "hi", t("tEasy")], ["now_code", "code", t("tCode")], ["plan", "warn", t("tPlan")], ["optional", "muted", t("tOptional")], ["accepted", "good", t("tAccepted")]]
      .map(([g, c, l]) => ({ g, c, l, v: x.n(g) })).filter((z) => z.v);
    const pk = el("button", { class: "card ocard", onclick: () => goTab("packages") },
      el("span", { class: "oh" }, el("span", { class: "h3" }, t("tabPackages")), el("span", { class: "quiet small" }, t("hClean", x.clean, x.total))),
      segs.length ? el("span", { class: "sbar", role: "img", "aria-label": segs.map((z) => z.l + " " + z.v).join(", ") }, segs.map((z) => { const x = el("span", { class: z.c }); x.style.flexGrow = String(z.v); return x; })) : el("span", { class: "quiet small" }, t("pkgAllOk")),
      el("span", { class: "lg" }, segs.map((z) => el("span", null, el("i", { class: z.c }), z.l + " " + z.v))));
    // docker and web server by severity
    const files = [...ctx.docker.files, ...ctx.server.files];
    const ds = el("button", { class: "card ocard", onclick: () => goTab(ctx.docker.issues.length || !ctx.server.issues.length ? "docker" : "server") },
      el("span", { class: "oh" }, el("span", { class: "h3" }, t("tileDs")), el("span", { class: "quiet small" }, x.ds.length ? t("dockerN", x.ds.length) : files.length ? "✓" : "")),
      files.length || x.ds.length ? el("span", { class: "sev3" },
        el("span", { class: "s hi" }, el("b", null, x.high), t("sevHigh")),
        el("span", { class: "s warn" }, el("b", null, x.medium), t("sevModerate")),
        el("span", { class: "s" }, el("b", null, x.low), t("sevLow"))) : null,
      el("span", { class: "quiet small" }, files.length ? files.slice(0, 3).join(" · ") + (files.length > 3 ? " …" : "") : t("dockerNone")));
    // Node.js
    const nd = ctx.nodes.length === 1 ? ctx.nodes[0].n : null, target = nd && (nd.securityFix || nd.latestInLine);
    const node = el("button", { class: "card ocard", onclick: () => goTab("env") },
      el("span", { class: "oh" }, el("span", { class: "h3" }, "Node.js"), x.nodeNow ? el("span", { class: "chip sev-high" }, t("needNow")) : ctx.nodes.length ? el("span", { class: "chip ok" }, "✓") : null),
      nd ? el("span", { class: "nver" }, nd.version || nd.line || "?", target && nd.version && target !== nd.version ? [el("span", { class: "arr" }, " → "), el("b", null, target)] : null) : null,
      el("span", { class: "quiet small" }, nd ? [nd.lts ? "LTS " + nd.lts : "", nd.eol ? "EOL " + nd.eol : "", needText("node", nd.need)].filter(Boolean).join(" · ")
        : ctx.nodes.length ? t("nodeN", ctx.nodes.length, ctx.nodes.filter((z) => z.n.need === "now").length) : t("noNode")),
      el("span", { class: "quiet small" }, t("hygiene") + ": " + (ctx.hygBad ? t("hygBad", ctx.hygBad) : t("hygOk"))));
    // last scans
    const hist = !st.readOnly ? slot(ctx.hkey, (h) => {
      const k = h.kpi;
      const scans = ctx.reps.length === 1 ? (h.projects[0] || { scans: [] }).scans.slice(0, 10).reverse() : [];
      if (!k || !k.lastScan) return null;
      let spark = null;
      if (scans.length >= 2) {
        const W = 300, H = 56, P = 6, max = Math.max(1, ...scans.map(urgentOf));
        const X = (i) => P + i * (W - 2 * P) / (scans.length - 1), Y = (v) => H - P - v * (H - 2 * P - 8) / max;
        const last = scans[scans.length - 1];
        spark = sv("svg", { viewBox: `0 0 ${W} ${H}`, class: "spark", role: "img", "aria-label": t("hChart") + ": " + scans.map(urgentOf).join(", ") },
          sv("line", { x1: P, x2: W - P, y1: Y(0), y2: Y(0), class: "base" }),
          sv("polyline", { points: scans.map((s, i) => X(i) + "," + Y(urgentOf(s))).join(" "), class: "ln" }),
          sv("circle", { cx: X(scans.length - 1), cy: Y(urgentOf(last)), r: 4, class: "pt" }));
      }
      const line = (l, v) => el("span", { class: "kl" }, el("span", { class: "quiet" }, l), el("b", null, v));
      return el("button", { class: "card ocard", onclick: () => goTab("history") },
        el("span", { class: "oh" }, el("span", { class: "h3" }, t("kTitle")), el("span", { class: "quiet small" }, t("hOpen"))),
        spark,
        line(t("kMttr"), k.fixedN ? fmtDur(k.mttrHours) : "—"),
        line(t("kOldest"), k.oldestPkg ? t("kDays", k.oldestDays) + " · " + k.oldestPkg : "—"),
        line(t("kWeek"), "+" + k.weekNew + " / −" + k.weekFixed));
    }) : null;
    return [el("div", { class: "ovgrid" }, first, el("div", { class: "ovside" }, pk, ds, node, hist)), ctx.extra,
      ctx.errors.length ? el("details", { class: "errs" }, el("summary", null, t("warningsN", ctx.errors.length)), el("ul", null, ctx.errors.map((e) => el("li", null, e)))) : null];
  }
  function packagesTab(ctx) {
    const chips = el("div", { class: "fchips seg", role: "group", "aria-label": t("tabPackages") }), help = el("div", { class: "ghelp" }), list = el("div");
    const toolbar = el("div", { class: "toolbar" },
      el("input", { type: "search", placeholder: t("search"), "aria-label": t("search"), value: state.q, oninput: (e) => { state.q = e.target.value; rerender(); } }),
      el("select", { "aria-label": t("allSev"), onchange: (e) => { state.sev = e.target.value; rerender(); } },
        ...[["", t("allSev")], ["critical", sevName("critical")], ["high", sevName("high") + "+"], ["moderate", sevName("moderate") + "+"]].map(([v, l]) => el("option", { value: v, selected: state.sev === v }, l))),
      null);
    const flts = el("div", { class: "fltrow", role: "group", "aria-label": t("filters") });
    const drawFlts = () => flts.replaceChildren(el("span", { class: "quiet small" }, t("filters") + ":"),
      ...[["kev", t("fKev")], ["epss", t("fEpss")], ["nofix", t("fNoFix")], ["direct", t("direct")], ["transitive", t("transitive")]].map(([k, l]) =>
        el("button", { class: "flt" + (state.flt.has(k) ? " on" : ""), "aria-pressed": String(state.flt.has(k)), onclick: () => { state.flt.has(k) ? state.flt.delete(k) : state.flt.add(k); drawFlts(); rerender(); } }, l)));
    drawFlts();
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
      const accBar = grp === "accepted" && !st.readOnly ? acceptExport(ctx) : null;
      const es = vis.filter((e) => e.f.group === grp);
      const out = [];
      if (!es.length) out.push(el("div", { class: "empty" }, t("noMatch")));
      else if (grp === "ok") out.push(el("div", { class: "card" }, el("div", { class: "oklist" }, es.map((e) => el("div", null, `${e.f.pkg}@${e.f.current}`, e.where && e.where.length > 1 ? el("span", { class: "quiet" }, " ×" + e.where.length) : null)))));
      else {
        if (grp === "now_easy") out.push(ctx.bulk(es));
        out.push(el("div", { class: "rlist" },
          el("div", { class: "rhead", "aria-hidden": "true" }, el("span", null, t("colRisk")), el("span", null, t("colPkg")), el("span", null, t("colVer")), el("span", null, t("colWhy")), el("span", null, t("colImpact")), el("span")),
          es.map((e) => prow(e, ctx))), legend());
      }
      list.replaceChildren(...[accBar, ...out].filter(Boolean));
    }
    rerender();
    return [chips, toolbar, flts, help, list];
  }
  // risk of a finding, as a word and a colour
  function riskOf(f) {
    if (f.kind === "malware") return ["mal", t("tagMal")];
    if (f.kind === "removed") return ["bad", t("tagRemoved")];
    if (f.severity === "critical") return ["bad", sevName("critical")];
    if (f.severity === "high") return ["hi", sevName("high")];
    if (f.severity === "moderate") return ["warn", sevName("moderate")];
    if (f.severity === "low") return ["low", sevName("low")];
    if (f.kind === "deprecated") return ["low", t("tagDeprecated")];
    return ["muted", t("tagUpdate")];
  }
  // what the update does to the code: no · maybe · N places
  function impactPill(f, e, ctx) {
    const ms = ctx ? ctx.migs(e) : (f.migrate || []).map((m) => ({ m }));
    const hits = ms.filter((x) => !x.m.plan).reduce((a, x) => a + (x.m.hits || 0), 0);
    if (f.codeImpact === "yes" && hits) return el("span", { class: "imp bad" }, t("impPlaces", hits));
    return el("span", { class: "imp " + impClass(f.codeImpact) }, impText(f.codeImpact));
  }
  function legend() {
    const r = (c, l) => el("span", { class: "risk " + c }, l);
    return el("div", { class: "legend" },
      el("b", null, t("colRisk") + ":"), r("mal", t("tagMal")), r("bad", sevName("critical")), r("hi", sevName("high")), r("warn", sevName("moderate")), r("low", sevName("low")),
      el("b", null, t("colImpact") + ":"), el("span", { class: "imp good" }, t("impNo")), el("span", { class: "imp warn" }, t("impMaybe")), el("span", { class: "imp bad" }, t("impPlaces", "N")));
  }
  // one compact row per package; the full answer opens below it
  function prow(e, ctx) {
    const f = e.f, k = keyOf(f), bad = f.kind === "malware" || f.kind === "removed";
    const open = state.open.has(k) || bad && !state.shut.has(k);
    const [rc, rl] = riskOf(f);
    const kev = (f.advisories || []).some((a) => a.kev);
    const d = el("details", { class: "prow" + (bad ? " mal" : ""), open: open || undefined },
      el("summary", null,
        el("span", { class: "c0" }, el("span", { class: "risk " + rc }, rl)),
        el("span", { class: "c1" }, el("code", { class: "pk" }, f.pkg),
          el("span", { class: "quiet small" }, [f.direct ? t("direct") : t("transitive"), f.dev ? "dev" : "", e.where && e.where.length > 1 ? t("nProjects", e.where.length) : "", (f.advisories || []).length > 1 ? t("nAdv", f.advisories.length) : "", f.priority && (f.kind === "vuln" || f.kind === "malware") ? "P" + f.priority : ""].filter(Boolean).join(" · "))),
        el("span", { class: "c2" }, f.current, f.target && f.target !== f.current ? [el("span", { class: "arr" }, " → "), el("b", null, f.target)] : null),
        el("span", { class: "c3" }, f.accepted ? el("span", { class: "chip accepted" }, t("accChip")) : null,
          el("span", { class: "t" }, f.title || tr((f.why || [])[0]) || ""), kev ? el("span", { class: "chip sev-critical" }, t("tagKev")) : null),
        el("span", { class: "c4" }, impactPill(f, e, ctx))),
      ctx.card(e));
    d.dataset.key = k;
    d.addEventListener("toggle", () => { if (d.open) { state.open.add(k); state.shut.delete(k); } else { state.open.delete(k); state.shut.add(k); } });
    return d;
  }
  function codeTab(migs) {
    if (!migs.length) return el("div", { class: "empty" }, t("codeNone"));
    const order = { now_code: 0, now_easy: 1, plan: 2, optional: 3, ok: 4 };
    const xs = [...migs].sort((a, b) => ((order[a.e.f.group] ?? 5) - (order[b.e.f.group] ?? 5)) || (b.e.f.priority || 0) - (a.e.f.priority || 0));
    return [el("div", { class: "ghelp" }, t("codeHelp")), el("div", { class: "codenote" }, t("codeNote")),
      xs.map(({ e, ms }) => el("div", { class: "card" },
        el("div", { class: "ctitle" }, el("span", { class: "pkg" }, e.f.pkg),
          el("span", { class: "ver" }, e.f.current, e.f.target ? [el("span", { class: "arr" }, "→"), e.f.target] : null),
          el("span", { class: "chip" }, grpTitle(e.f.group)),
          el("span", { class: "grow" }),
          el("button", { class: "link small", onclick: () => goTab("packages", { grp: e.f.group, open: keyOf(e.f) }) }, t("toPackage"))),
        ms.map((x) => migBlock(x.m, x.label, true))))];
  }
  const SEVC = { high: "sev-high", medium: "sev-moderate", low: "" };
  function envSelect(ref) {
    if (!ref || st.readOnly) return null;
    const auto = t(ref.auto === "dev" ? "envChip" : "envProdChip"); // unknown counts as production
    const sel = el("select", { class: "envsel", "aria-label": t("envMark") + " " + ref.label, onchange: async (e) => {
      try { setState(await api("POST", "api/envmark", { dir: ref.dir, file: ref.file, env: e.target.value })); toast(t("envSaved")); }
      catch (er) { toast(t("error", er.message)); }
    } }, [["", t("envAutoAs", auto)], ["prod", t("envProd")], ["dev", t("envDev")]].map(([v, l]) => el("option", { value: v, selected: ref.mark === v || undefined }, l)));
    return el("label", { class: "envmark quiet small" }, t("envMark"), " ", sel);
  }
  const dirOf = (f) => { const i = f.lastIndexOf("/"); return i < 0 ? "" : f.slice(0, i + 1); };
  function dockerTab(dk, kind) {
    const srv = kind === "server";
    if (!dk.files.length && !dk.issues.length) return el("div", { class: "empty" }, t("dockerNone"));
    const checked = dk.files.length ? el("div", { class: "quiet small" }, t("dockerFiles", dk.files.join(", "))) : null;
    if (!dk.issues.length) return el("div", { class: "card" }, el("div", null, t("dockerOk", dk.files.join(", "))));
    const by = new Map();
    for (const d of dk.issues) { const f = dk.label ? dk.label(d) : d.file; if (!by.has(f)) by.set(f, []); by.get(f).push(d); }
    // grouped by the folder the files are in, so it is clear where each one lives
    const folders = new Map();
    for (const [file, ds] of by) { const d = dirOf(file); if (!folders.has(d)) folders.set(d, []); folders.get(d).push([file, ds]); }
    const fileCard = ([file, ds]) => {
      const ref = dk.ref ? dk.ref(file) : null;
      const devFile = ds.every(isDevIssue);
      return el("div", { class: "card dfile" + (devFile ? " devfile" : "") },
        el("div", { class: "dfh" },
          el("span", { class: "dpath" }, el("span", { class: "quiet" }, dirOf(file)), el("code", null, file.slice(dirOf(file).length))),
          devFile ? el("span", { class: "chip envc", title: tr(ds[0].envWhy) || "" }, t("envChip")) : null,
          el("span", { class: "quiet small" }, t("dockerN", ds.length)),
          el("span", { class: "grow" }), envSelect(ref)),
        ds.map((d) => el("div", { class: "ditem" },
          el("div", { class: "drow" }, el("span", { class: "chip " + (SEVC[d.severity] || "") }, d.severity),
            !devFile && isDevIssue(d) ? el("span", { class: "chip envc", title: tr(d.envWhy) || "" }, t("envChip")) : null,
            el("b", null, tr(d.title)),
            el("span", { class: "quiet small" }, (d.line ? file.split("/").pop() + ":" + d.line : "") + (d.service ? " · " + d.service : "") + (d.envWhy && isDevIssue(d) ? " · " + tr(d.envWhy) : ""))),
          tr(d.detail) ? el("div", { class: "d" }, el("span", { class: "lbl" }, t("issueWhy")), " ", tr(d.detail)) : null,
          d.fix ? el("div", { class: "d" }, el("span", { class: "lbl" }, t("issueFix")), " ", el("code", { class: "dfix" }, d.fix)) : null)));
    };
    return [el("div", { class: "ghelp" }, t(srv ? "serverHelp" : "dockerHelp"), " ", t("readOnlyNote")),
      [...folders].map(([d, files]) => folders.size > 1 ? el("div", { class: "dfolder" }, el("div", { class: "h3 dfname" }, "📁 ", d || "./"), files.map(fileCard)) : files.map(fileCard)),
      checked];
  }
  function aiTab(ctx) {
    const scanned = ctx.reps.filter((p) => p.report);
    const c = (title, text, btn) => el("div", { class: "card aicard" }, el("div", { class: "h3" }, title), el("div", { class: "quiet small" }, text), btn);
    return el("div", { class: "areas" },
      c(t("aiBtn"), t("aiHelp"), el("button", { class: "primary", onclick: () => openPrompt(scanned, ctx.dir, ctx.g) }, t("aiOpen"))),
      c(t("rulesBtn"), t("rulesHelp"), el("button", { onclick: () => openRules(scanned, ctx.dir, ctx.g) }, t("rulesOpen"))),
      st.readOnly ? null : c(t("mcpBtn"), t("mcpHelp"), el("button", { onclick: () => openMCP(ctx.dir) }, t("mcpOpen"))),
      st.readOnly ? null : slot(ctx.hkey, (h) => [el("div", { class: "card aicard" }, el("div", { class: "h3" }, t("agTitle")),
        agentList(h.agents.slice(0, 3)),
        el("button", { onclick: () => goTab("history") }, t("hOpen"))),
        workPanel(h.work, ctx.dir, 2) || el("div", { class: "card aicard workcard" }, el("div", { class: "h3" }, t("wTitle")), el("div", { class: "quiet small" }, t("wNone")))]));
  }

  // ---------- accepted risk ----------
  function acceptBlock(f, dirs) {
    if (st.readOnly) return null;
    const a = f.accepted;
    if (a) {
      return el("div", { class: "accbox" },
        el("div", null, el("b", null, t("accInfo", String(a.until).slice(0, 10))), a.reason),
        el("div", { class: "quiet small" }, t("accFrom", grpTitle(a.group), a.at && !a.at.startsWith("0001") ? String(a.at).slice(0, 10) : "—")),
        a.file ? el("div", { class: "quiet small" }, t("accFromFile"), " ", el("code", null, a.file)) : el("button", { class: "small", onclick: async () => {
          try { setState(await api("POST", "api/accept", { dirs, key: f.key, remove: true })); toast(t("accUndone")); }
          catch (e) { toast(t("error", e.message)); }
        } }, t("accUndo")));
    }
    if (f.group === "ok") return null;
    if (f.kind === "malware") return null;
    return el("div", { class: "accrow" }, el("button", { class: "small ghost acc", onclick: () => openAccept(f, dirs) }, t("accBtn")));
  }
  // depgate-accept.json: the same accepted risks for the team and for depgate --ci
  function acceptExport(ctx) {
    const seen = new Set(), list = [];
    for (const e of ctx.entries) {
      const f = e.f, a = f.accepted;
      if (!a || seen.has(f.key)) continue;
      seen.add(f.key);
      list.push({ key: f.key, pkg: f.pkg, reason: a.reason, until: String(a.until).slice(0, 10), at: a.at && !a.at.startsWith("0001") ? String(a.at).slice(0, 10) : undefined });
    }
    if (!list.length) return null;
    const text = JSON.stringify({ schema: "depgate/accept@1", accepted: list }, null, 2) + "\n";
    const dl = () => {
      const a = el("a", { href: URL.createObjectURL(new Blob([text], { type: "application/json" })), download: "depgate-accept.json" });
      document.body.append(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
    };
    return el("div", { class: "card accexport" },
      el("div", null, el("b", null, t("accExpTitle")), el("div", { class: "quiet small" }, t("accExpHelp"))),
      el("span", { class: "grow" }),
      el("button", { class: "small", onclick: dl }, t("accExpBtn")));
  }
  function openAccept(f, dirs) {
    const close = () => { ov.remove(); document.removeEventListener("keydown", esc); };
    const esc = (e) => { if (e.key === "Escape") close(); };
    const reason = el("textarea", { class: "accreason", rows: "3", maxlength: "500", placeholder: t("accReasonPh") });
    const days = el("select", null, [30, 90, 180, 365].map((d) => el("option", { value: String(d), selected: d === 90 || undefined }, t("accDays", d))));
    const save = el("button", { class: "primary", onclick: async () => {
      if (!reason.value.trim()) { reason.focus(); return; }
      save.disabled = true;
      try { const s2 = await api("POST", "api/accept", { dirs, key: f.key, reason: reason.value, days: +days.value }); close(); setState(s2); toast(t("accDone")); }
      catch (e) { save.disabled = false; toast(t("error", e.message)); }
    } }, t("accSave"));
    const dlg = el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": t("accTitle", f.pkg) },
      el("div", { class: "mhead" }, el("div", { class: "h3" }, t("accTitle", f.pkg + " " + f.current)), el("div", { class: "quiet" }, t("accHelp", f.pkg))),
      el("div", { class: "pad accform" },
        f.title ? el("div", { class: "quiet small" }, f.title) : null,
        el("label", null, t("accReason"), reason),
        el("label", { class: "inl" }, t("accFor"), days),
        dirs.length > 1 ? el("div", { class: "quiet small" }, t("accWhere", dirs.length)) : null),
      el("div", { class: "pfoot" }, el("span", { class: "grow" }), el("button", { onclick: close }, t("close")), save));
    const ov = el("div", { class: "overlay", onclick: (e) => { if (e.target === ov) close(); } }, dlg);
    document.body.append(ov); document.addEventListener("keydown", esc); reason.focus();
  }

  // ---------- automatic scan & new version ----------
  function renderRescan(n) {
    const sel = $("#rescan");
    $("#rescanrow").hidden = st.readOnly || !n;
    if (st.readOnly || !n) return;
    const cur = st.rescanHours || 0;
    const opts = [0, 6, 12, 24, 48];
    if (!opts.includes(cur)) opts.push(cur);
    sel.setAttribute("aria-label", t("rescanLbl")); sel.title = t("rescanLbl");
    sel.replaceChildren(...opts.map((h) => el("option", { value: String(h), selected: h === cur || undefined }, h ? t("rescanOpt", h) : t("rescanOffOpt"))));
  }
  $("#rescan").addEventListener("change", async (e) => {
    try { setState(await api("POST", "api/settings", { rescanHours: +e.target.value })); toast(t("rescanSaved")); }
    catch (er) { toast(t("error", er.message)); }
  });
  function renderUpdate() {
    const bar = $("#update"), u = st.update;
    let later = ""; try { later = localStorage.getItem("depgate-upd-later") || ""; } catch {}
    bar.hidden = !u || later === u.latest;
    if (bar.hidden) return;
    bar.replaceChildren(el("span", null, t("updText", u.latest, st.version)),
      el("button", { class: "small", onclick: openUpdate }, t("updHow")),
      safeURL(u.url) ? el("a", { href: u.url, target: "_blank", rel: "noopener noreferrer" }, t("updNotes")) : null,
      el("span", { class: "grow" }),
      el("button", { class: "small ghost", onclick: () => { try { localStorage.setItem("depgate-upd-later", u.latest); } catch {} renderUpdate(); } }, t("updLater")));
  }
  function openUpdate() {
    const close = () => { ov.remove(); document.removeEventListener("keydown", esc); };
    const esc = (e) => { if (e.key === "Escape") close(); };
    const box = (c) => el("div", { class: "codebox" }, el("pre", null, c), copyBtn(c));
    const dlg = el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": t("updTitle") },
      el("div", { class: "mhead" }, el("div", { class: "h3" }, t("updTitle")), el("div", { class: "quiet" }, t("updText", st.update.latest, st.version))),
      el("div", { class: "pad accform" },
        st.container ? [el("div", null, t("updDocker")), box("git pull && docker compose pull && docker compose up -d")]
          : [el("div", null, t("updBinary")), box("go install github.com/Ali7Zeynalli/depgate@latest"),
            safeURL(st.update.url) ? el("a", { href: st.update.url, target: "_blank", rel: "noopener noreferrer" }, "GitHub Releases →") : null],
        el("div", { class: "quiet small" }, t("updData"))),
      el("div", { class: "pfoot" }, el("span", { class: "grow" }), el("button", { class: "primary", onclick: close }, t("close"))));
    const ov = el("div", { class: "overlay", onclick: (e) => { if (e.target === ov) close(); } }, dlg);
    document.body.append(ov); document.addEventListener("keydown", esc);
  }

  // ---------- history: scans compared, and what AI agents did ----------
  const hcache = new Map();
  function getHistory(dir) {
    const key = (st.lastScan || "") + "|" + st.busy + "|" + (st.workAt || "");
    const c = hcache.get(dir);
    if (c && c.key === key && Date.now() - c.at < 10000) return c.p;
    const only = dir.startsWith("only:");
    const p = api("GET", "api/history?dir=" + encodeURIComponent(only ? dir.slice(5) : dir) + (only ? "&only=1" : ""));
    hcache.set(dir, { key, at: Date.now(), p });
    p.catch(() => hcache.delete(dir));
    return p;
  }
  // slot shows what build(history) returns once the history has loaded
  function slot(dir, build, loading) {
    const box = el("div", { class: "hslot" }, loading ? el("div", { class: "quiet small" }, t("loading")) : null);
    if (st.readOnly) return null;
    getHistory(dir).then((h) => { const x = build(h); box.replaceChildren(...[x].flat(Infinity).filter(Boolean)); if (!box.childNodes.length) box.remove(); })
      .catch((e) => { if (loading) box.replaceChildren(el("div", { class: "empty" }, t("error", e.message))); else box.remove(); });
    return box;
  }
  const isActive = (a) => Date.now() - new Date(a.last) < 10 * 60 * 1000;
  function agentList(as) {
    if (!as.length) return el("div", { class: "quiet small" }, t("agNone"));
    return el("div", { class: "agents" }, as.map((a) => el("div", { class: "agent" },
      el("span", { class: "dot" + (isActive(a) ? " on" : ""), "aria-hidden": "true" }),
      el("div", { class: "grow" },
        el("div", null, el("b", null, a.name), " ", el("span", { class: "quiet small" }, a.via === "stdio" ? "stdio" : "HTTP"),
          isActive(a) ? el("span", { class: "chip ok" }, t("agActive")) : null),
        el("div", { class: "quiet small" }, [t("agSeen", fmtTime(a.last)), a.calls ? t("agCalls", a.calls) : "", a.checks ? t("agChecks", a.checks) : "", a.blocked ? t("agWarned", a.blocked) : "", a.scans ? t("agScans", a.scans) : ""].filter(Boolean).join(" · "))))));
  }
  const byText = (s) => s.by === "mcp" ? (s.agent || t("hByMCP")) : s.by === "cli" ? t("hByCLI") : s.by === "auto" ? t("hByAuto") : t("hByUI");
  const urgentOf = (s) => (s.sum.now_easy || 0) + (s.sum.now_code || 0);
  function diffChips(d) {
    if (d.first) return [el("span", { class: "chip" }, t("hFirst"))];
    if (!d.new.length && !d.fixed.length && !d.changed.length) return [el("span", { class: "quiet small" }, t("hSame"))];
    return [d.new.length ? el("span", { class: "chip sev-high" }, t("hNew", d.new.length)) : null,
      d.fixed.length ? el("span", { class: "chip ok" }, t("hFixed", d.fixed.length)) : null,
      d.changed.length ? el("span", { class: "chip warn" }, t("hChanged", d.changed.length)) : null,
      d.lockChanged ? el("span", { class: "quiet small" }, t("hLock")) : d.new.length ? el("span", { class: "quiet small" }, t("hAdv")) : null];
  }
  const itemText = (it) => (it.t === "docker" || it.t === "server" ? it.p : it.p + (it.v ? "@" + it.v : "")) +
    (it.to ? " → " + it.to : "") + (it.n ? " — " + it.n : "");
  function itemList(label, cls, its) {
    if (!its.length) return null;
    return el("div", { class: "hitems" }, el("div", { class: "lbl " + cls }, label + " (" + its.length + ")"),
      its.map((it) => el("div", { class: "hit" }, it.s ? el("span", { class: "chip " + (SEVC[it.s] || "sev-" + it.s) }, it.s) : el("span", { class: "chip" }, it.t), " ", itemText(it))));
  }
  // package versions that changed in a scan: updated, back to an older version, added, removed
  const PKK = { down: ["pkDown", "warn", "↓"], add: ["pkAdd", "sev-high", "+"], remove: ["pkRemove", "", "−"], up: ["pkUp", "ok", "↑"] };
  function pkgChips(p) {
    const cs = (p && p.c) || [];
    if (!cs.length) return null;
    const down = cs.filter((c) => c.k === "down").length;
    return [el("span", { class: "chip" }, t("pkN", cs.length + (p.more || 0))), down ? el("span", { class: "chip warn" }, t("pkDownN", down)) : null];
  }
  function pkgList(p) {
    const cs = (p && p.c) || [];
    if (!cs.length) return null;
    const line = (c) => el("div", { class: "hit" },
      el("span", { class: "chip " + PKK[c.k][1] }, PKK[c.k][2] + " " + t(PKK[c.k][0])), " ",
      el("b", null, c.n), " ",
      el("span", { class: "mono" }, c.k === "add" ? c.t : c.k === "remove" ? c.f : c.f + " → " + c.t),
      c.dev ? el("span", { class: "quiet small" }, " dev") : null);
    const direct = cs.filter((c) => c.d), trans = cs.filter((c) => !c.d), more = p.more || 0;
    return el("div", { class: "hitems" }, el("div", { class: "lbl" }, t("pkTitle", cs.length + more)),
      direct.map(line),
      trans.length ? el("details", { class: "pktrans", open: !direct.length && trans.length <= 10 || undefined },
        el("summary", { class: "quiet small" }, t("pkTrans", trans.length + more)), trans.map(line),
        more ? el("div", { class: "quiet small" }, t("pkMore", more)) : null) : null);
  }
  function chart(scans) {
    const xs = scans.slice(0, 30).reverse(); // oldest → newest
    if (xs.length < 2) return null;
    const W = 900, Hh = 120, P = 14, max = Math.max(1, ...xs.map(urgentOf));
    const X = (i) => P + i * (W - 2 * P) / (xs.length - 1), Y = (v) => Hh - P - v * (Hh - 2 * P) / max;
    const NS = "http://www.w3.org/2000/svg";
    const sv = (tag, a, ...kids) => { const e = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(a)) e.setAttribute(k, v); e.append(...kids); return e; };
    const svg = sv("svg", { viewBox: `0 0 ${W} ${Hh}`, class: "hchart", role: "img", "aria-label": t("hChart") + ": " + xs.map(urgentOf).join(", ") });
    svg.append(sv("line", { x1: P, x2: W - P, y1: Y(0), y2: Y(0), class: "base" }));
    svg.append(sv("polyline", { points: xs.map((s, i) => X(i) + "," + Y(urgentOf(s))).join(" "), class: "ln" }));
    xs.forEach((s, i) => {
      const g = sv("g", { class: "pt" + (s.sum.malware ? " bad" : "") });
      g.append(sv("rect", { x: X(i) - 9, y: 0, width: 18, height: Hh, class: "hit" }), sv("circle", { cx: X(i), cy: Y(urgentOf(s)), r: 4 }),
        sv("title", {}, fmtTime(s.at) + " · " + t("hCounts", urgentOf(s), s.sum.plan || 0, s.sum.malware || 0, (s.docker || 0) + (s.server || 0))));
      svg.append(g);
    });
    const last = xs[xs.length - 1];
    svg.append(sv("text", { x: W - P, y: Math.max(12, Y(urgentOf(last)) - 8), "text-anchor": "end", class: "lab" }, String(urgentOf(last))));
    return el("div", { class: "card" }, el("div", { class: "h3" }, t("hChart")), svg);
  }
  function timeline(ph) {
    const out = [];
    let same = 0;
    const flush = () => { if (same) out.push(el("div", { class: "hrow same quiet small" }, t("hSameN", same))); same = 0; };
    ph.scans.forEach((s, i) => {
      const d = s.diff, pk = (s.pkgs && s.pkgs.c) || [], changed = d.first || d.new.length || d.fixed.length || d.changed.length || pk.length;
      if (!changed && i > 0) { same++; return; }
      flush();
      const head = el("summary", null,
        el("span", { class: "ht" }, fmtTime(s.at)),
        el("span", { class: "chip" + (s.by === "mcp" ? " ai" : "") }, byText(s)),
        el("span", { class: "hc quiet small" }, t("hCounts", urgentOf(s), s.sum.plan || 0, s.sum.malware || 0, (s.docker || 0) + (s.server || 0))),
        el("span", { class: "hd" }, diffChips(d), pkgChips(s.pkgs)));
      const body = [itemList(t("hNewL"), "bad", d.new), itemList(t("hFixedL"), "good", d.fixed), itemList(t("hChangedL"), "warn", d.changed), pkgList(s.pkgs)].filter(Boolean);
      out.push(body.length ? el("details", { class: "hrow", open: i === 0 || undefined }, head, el("div", { class: "hbody" }, body))
        : el("div", { class: "hrow flat" }, [...head.childNodes]));
    });
    flush();
    return out;
  }
  const VERD = { ok: ["vOk", "ok"], caution: ["vCaution", "warn"], block: ["vBlock", "sev-critical"] };
  function activity(evs, dir) {
    if (!evs.length) return el("div", { class: "quiet small" }, t("actNone"));
    return el("div", { class: "acts" }, evs.slice(0, 60).map((e) => el("div", { class: "act" + (e.error ? " err" : "") },
      el("span", { class: "ht" }, fmtTime(e.at)),
      el("b", null, e.agent),
      el("code", null, e.tool === "connect" ? t("evConnect") : e.tool),
      e.target ? el("span", { class: "mono" }, e.target) : null,
      e.verdict && VERD[e.verdict] ? el("span", { class: "chip " + VERD[e.verdict][1] }, t(VERD[e.verdict][0])) : null,
      e.project && e.project !== dir ? el("span", { class: "quiet small" }, relTo(e.project, dir) || baseName(e.project)) : null)));
  }
  const fmtDur = (h) => h < 1 ? t("kLessHour") : h < 48 ? t("kHours", Math.round(h)) : t("kDays", Math.round(h / 24));
  function kpiStrip(k, dir) {
    const card = (cls, l, v, sub) => el("div", { class: "stile kpi " + cls }, el("span", { class: "sl" }, el("span", { class: "sdot", "aria-hidden": "true" }), l), el("span", { class: "sv" }, v), el("span", { class: "ss" }, sub));
    return el("div", { class: "stiles" },
      card(k.openUrgent ? "hi" : "good", t("kOpen"), k.openUrgent, t("kOpenSub")),
      card(k.fixedN ? "code" : "zero", t("kMttr"), k.fixedN ? fmtDur(k.mttrHours) : "—", k.fixedN ? t("kMttrSub", k.fixedN) : t("kMttrNone")),
      card(k.oldestDays >= 14 ? "bad" : k.oldestPkg ? "warn" : "good", t("kOldest"), k.oldestPkg ? t("kDays", k.oldestDays) : "—",
        k.oldestPkg ? k.oldestPkg + (k.oldestSev ? " · " + (k.oldestSev === "malware" ? t("tagMal") : sevName(k.oldestSev)) : "") + (k.oldestDir && k.oldestDir !== dir ? " · " + (relTo(k.oldestDir, dir) || baseName(k.oldestDir)) : "") : t("kNothingOpen")),
      card(k.weekNew > k.weekFixed ? "hi" : "good", t("kWeek"), "+" + k.weekNew + " / −" + k.weekFixed, t("kWeekSub")),
      k.acceptedSoon ? card("warn", t("kAccSoon"), k.acceptedSoon, t("kAccSoonSub")) : card("zero", t("kLast"), k.lastScan ? fmtTime(k.lastScan).slice(11) : "—", k.lastScan ? fmtTime(k.lastScan).slice(0, 10) : t("kLastSub")));
  }
  // new and fixed per week, two bars each, one axis
  function weekChart(weeks) {
    if (!weeks || !weeks.length || !weeks.some((w) => w.new || w.fixed)) return null;
    const W = 640, H = 150, P = 22, B = 14, max = Math.max(1, ...weeks.flatMap((w) => [w.new, w.fixed]));
    const step = (W - 2 * P) / weeks.length, Y = (v) => H - P - v * (H - 2 * P - 8) / max;
    const lab = (d) => { const x = new Date(d); return pad(x.getDate()) + "." + pad(x.getMonth() + 1); };
    const svg = sv("svg", { viewBox: `0 0 ${W} ${H}`, class: "wchart", role: "img", "aria-label": t("kWeeks") + ": " + weeks.map((w) => lab(w.start) + " +" + w.new + "/−" + w.fixed).join(", ") },
      sv("line", { x1: P, x2: W - P, y1: Y(0), y2: Y(0), class: "base" }));
    weeks.forEach((w, i) => {
      const x = P + i * step + step / 2;
      for (const [v, cls, dx] of [[w.new, "nb", -B - 1], [w.fixed, "fb", 1]]) {
        const g = sv("g", { class: "bar " + cls });
        g.append(sv("rect", { x: x + dx, y: Y(v), width: B, height: Math.max(0, Y(0) - Y(v)), rx: 3 }), sv("title", {}, lab(w.start) + ": " + (cls === "nb" ? t("kNew") : t("kFixed")) + " " + v));
        svg.append(g);
        if (v) svg.append(sv("text", { x: x + dx + B / 2, y: Y(v) - 4, "text-anchor": "middle", class: "bl" }, String(v)));
      }
      svg.append(sv("text", { x, y: H - 6, "text-anchor": "middle", class: "wl" }, lab(w.start)));
    });
    return el("div", { class: "card" }, el("div", { class: "oh wh" }, el("span", { class: "h3" }, t("kWeeks")),
      el("span", { class: "lg" }, el("span", null, el("i", { class: "hi" }), t("kNew")), el("span", null, el("i", { class: "good" }), t("kFixed")))), svg);
  }
  // ---------- AI work: the tasks an agent took on over MCP and what DepGate verified ----------
  const WST = { todo: ["wTodo", ""], doing: ["wDoing", "ai"], done: ["wDone", "ok"], partial: ["wPartial", "warn"], not_done: ["wNotDone", "sev-high"], skipped: ["wSkipped", ""] };
  function workPanel(ws, dir, max) {
    if (!ws || !ws.length) return null;
    const shown = ws.slice(0, max || 5);
    const sess = (w, i) => {
      const fin = w.tasks.filter((x) => x.status === "done").length, open = w.tasks.some((x) => x.status === "todo" || x.status === "doing");
      const proj = relTo(w.project, dir);
      return el("details", { class: "work", open: i === 0 || undefined },
        el("summary", null,
          el("span", { class: "dot" + (open ? " on" : ""), "aria-hidden": "true" }),
          el("b", null, w.agent),
          proj ? el("span", { class: "chip" }, proj) : null,
          el("span", { class: "quiet small" }, fmtTime(w.started)),
          el("span", { class: "grow" }),
          el("span", { class: "chip " + (open ? "ai" : fin === w.tasks.length ? "ok" : "warn") }, open ? t("wOpen", fin, w.tasks.length) : t("wFin", fin, w.tasks.length))),
        el("div", { class: "wtasks" }, w.tasks.map((x) => {
          const done = (x.items || []).filter((it) => it.done).length;
          return el("details", { class: "wtask" },
            el("summary", null,
              el("span", { class: "chip " + WST[x.status][1] }, t(WST[x.status][0])),
              el("span", { class: "chip" }, x.cat),
              el("span", null, t("w_" + x.id)),
              el("span", { class: "quiet small" }, x.checked ? t("wItems", done, x.items.length) + " · " + t("wChecked", fmtTime(x.checked)) : tn("wItemsN", x.items.length))),
            el("div", { class: "witems" },
              (x.items || []).map((it) => el("div", { class: it.done ? "wdone" : "" }, (it.done ? "✓ " : x.checked ? "✗ " : "• ") + it.label)),
              x.note ? el("div", { class: "quiet small" }, t("wNote"), " ", x.note) : null));
        })));
    };
    return el("div", { class: "card workcard" }, el("div", { class: "h3" }, t("wTitle")), el("div", { class: "quiet small" }, t("wHelp")),
      shown.map(sess), ws.length > shown.length ? el("div", { class: "quiet small" }, t("wMore", ws.length - shown.length)) : null);
  }
  function historyTab(ctx) {
    if (st.readOnly) return el("div", { class: "empty" }, t("readOnly"));
    return slot(ctx.hkey, (h) => {
      const multi = h.projects.length > 1;
      const any = h.projects.some((p) => p.scans.length);
      const projs = h.projects.filter((p) => p.scans.length).map((p) => {
        const name = multi ? relTo(p.dir, ctx.dir) || t("folderRoot") : null;
        return el("div", null, name ? el("div", { class: "h3 hproj" }, name) : null, chart(p.scans),
          el("div", { class: "card hlist" }, el("div", { class: "h3" }, t("hScans", p.scans.length)), timeline(p)));
      });
      return [el("div", { class: "ghelp" }, t("hLocal")),
        any ? kpiStrip(h.kpi, ctx.dir) : null,
        workPanel(h.work, ctx.dir, 8),
        any ? weekChart(h.kpi.weeks) : null,
        el("div", { class: "areas two" },
          el("div", { class: "card" }, el("div", { class: "h3" }, t("agTitle")), agentList(h.agents)),
          el("div", { class: "card" }, el("div", { class: "h3" }, t("actTitle")), activity(h.events, ctx.dir))),
        any ? projs : el("div", { class: "empty" }, t("hNone")),
        any || h.events.length ? el("div", { class: "hfoot" }, el("button", { class: "small ghost danger", onclick: async () => {
          if (!confirm(t("hClearConfirm", baseName(ctx.dir)))) return;
          try { await api("POST", "api/history/clear", { dir: ctx.dir }); hcache.clear(); toast(t("hCleared")); render(); }
          catch (e) { toast(t("error", e.message)); }
        } }, t("hClear"))) : null];
    }, true);
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
  $("#updbtn").addEventListener("click", async () => {
    $("#moremenu").hidden = true; $("#more").setAttribute("aria-expanded", "false");
    try {
      const res = await api("POST", "api/update/check");
      if (res.update) { try { localStorage.removeItem("depgate-upd-later"); } catch {} }
      setState(res.state);
      if (res.update) openUpdate(); else toast(t("updNone", st.version || "dev"));
    } catch (er) { toast(t("error", er.message)); }
  });
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
      projSwitch(),
      el("div", { class: "pdir", title: g.dir }, g.dir),
      busy ? el("span", { class: "chip busy" }, el("span", { class: "spin" }), t("scanningChip")) : null,
      st.readOnly ? null : el("button", { class: "small", disabled: st.busy || undefined, onclick: () => scan(ps.map((x) => x.dir)) }, t("scanFolder", ps.length)),
      st.readOnly ? null : el("button", { class: "small ghost danger", onclick: () => removeGroup(g) }, t("removeFolder", ps.length)),
      scanned.length ? el("button", { class: "small", onclick: () => openCommands(scanned, g.dir, g) }, t("cmdsBtn")) : null,
      scanned.length ? el("button", { class: "small primary", onclick: () => openPrompt(scanned, g.dir, g) }, t("aiBtn")) : null);
    if (!scanned.length) return el("div", null, bar, el("div", { class: "empty" }, el("h1", null, baseName(g.dir)), busy ? t("firstScan") : t("folderNotScanned")));

    const pkgs = scanned.reduce((a, p) => a + (p.report.packages || 0), 0);
    const head = el("div", { class: "phead" },
      el("div", null, el("h1", null, baseName(g.dir)), el("div", { class: "pchips" }, el("span", { class: "pc" }, t("nProjects", ps.length)), el("span", { class: "pc" }, t("packages", pkgs)))));

    const rows = el("div", { class: "card ptable" }, el("div", { class: "h3" }, t("folderProjects")),
      el("table", null,
        el("thead", null, el("tr", null, el("th", null, t("colProject")), el("th", null, t("tEasy")), el("th", null, t("tCode")), el("th", null, t("tPlan")), el("th", null, t("tOptional")), el("th", null, "Node"),
          st.readOnly ? null : [el("th", null, t("colTrend")), el("th", null, t("colOldest")), el("th", null, t("kMttr"))])),
        el("tbody", null, ps.map((p) => {
          const s = (p.report && p.report.summary) || {};
          const num = (v, bad) => el("td", { class: "num" + (v && bad ? " bad" : "") }, p.report ? v || 0 : "—");
          const nd = p.report && p.report.node;
          return el("tr", { class: "clickable", onclick: () => select(p.dir) },
            el("td", null, el("div", null, s.malware ? el("span", { class: "chip sev-critical" }, t("malicious")) : null, " ", relName(p, g)), p.name !== baseName(p.dir) ? el("div", { class: "quiet small" }, p.name) : null),
            num(s.now_easy, true), num(s.now_code, true), num(s.plan), num(s.optional),
            el("td", { class: nd && nd.need === "now" ? "bad" : "" }, nd ? (nd.version || nd.line || "?") + (nd.securityFix && nd.securityFix !== nd.version ? " → " + nd.securityFix : "") : "—"),
            st.readOnly ? null : [el("td", { class: "kt", "data-dir": p.dir }, "…"), el("td", { class: "ko", "data-dir": p.dir }, "…"), el("td", { class: "km", "data-dir": p.dir }, "…")]);
        }))));
    // trend, oldest open and time to fix per project, from the history
    if (!st.readOnly) getHistory(g.dir).then((h) => {
      for (const ph of h.projects) {
        const cell = (c) => [...rows.querySelectorAll("td." + c)].find((x) => x.dataset.dir === ph.dir);
        const k = ph.kpi, tr = (k.trend || []).slice(-12);
        const kt = cell("kt"), ko = cell("ko"), km = cell("km");
        if (kt) {
          if (tr.length >= 2) {
            const W = 90, H = 24, max = Math.max(1, ...tr.map((x) => x.urgent));
            const X = (i) => 2 + i * (W - 4) / (tr.length - 1), Y = (v) => H - 3 - v * (H - 6) / max;
            kt.replaceChildren(sv("svg", { viewBox: `0 0 ${W} ${H}`, class: "tspark", role: "img", "aria-label": t("hChart") + ": " + tr.map((x) => x.urgent).join(", ") },
              sv("polyline", { points: tr.map((x, i) => X(i) + "," + Y(x.urgent)).join(" ") })));
          } else kt.textContent = "—";
        }
        if (ko) { ko.textContent = k.oldestPkg ? t("kDays", k.oldestDays) + " · " + k.oldestPkg : "—"; ko.className = "ko" + (k.oldestDays >= 14 ? " bad" : ""); }
        if (km) km.textContent = k.fixedN ? fmtDur(k.mttrHours) : "—";
      }
    }).catch(() => {});

    const dk = new Map(), dfiles = new Set(), refs = new Map();
    for (const p of scanned) {
      for (const f of [...(p.report.dockerFiles || []), ...(p.report.serverFiles || [])]) {
        const l = relTo(joinPath(p.dir, f), g.dir) || f;
        if (!refs.has(l)) refs.set(l, fileRef(p, f, l));
      }
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
      return { issues: [...m.values()].sort((a, b) => sev[a.severity] - sev[b.severity] || a.abs.localeCompare(b.abs) || a.line - b.line), files: [...fs], label: (d) => relTo(d.abs, g.dir) || d.abs, ref: (l) => refs.get(l) };
    };
    const dIssues = [...dk.values()].sort((a, b) => ({ high: 0, medium: 1, low: 2 }[a.severity] - { high: 0, medium: 1, low: 2 }[b.severity]) || a.abs.localeCompare(b.abs) || a.line - b.line);
    const ctx = {
      reps: scanned, dir: g.dir, g, hkey: g.dir,
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
      docker: { issues: dIssues, files: [...dfiles], label: (d) => relTo(d.abs, g.dir) || d.abs, ref: (l) => refs.get(l) },
      server: merge((r) => r.server, (r) => r.serverFiles),
      nodes: scanned.filter((p) => p.report.node).map((p) => ({ label: relName(p, g), n: p.report.node })),
      hygBad: scanned.reduce((a, p) => a + (p.report.hygiene || []).filter((h) => !h.ok).length, 0),
      env: () => el("div", { class: "side" }, folderNodeCard(g, scanned), folderHygieneCard(g, scanned)),
      migs: (e) => e.where.flatMap((w) => (w.f.migrate || []).map((m) => ({ m, label: e.where.length > 1 ? relName(w.p, g) : "" }))),
      errors: scanned.flatMap((p) => (p.report.errors || []).map((x) => relName(p, g) + ": " + x)),
      extra: rows,
    };
    const vctx = envView(ctx);
    head.append(healthCard(vctx));
    return el("div", null, bar, head, tabbed(vctx));
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
        if (f.advisories && f.advisories.length) L.push(`- ${t("pAdv")}: ` + f.advisories.map((a) => [a.id, (a.aliases || []).filter((x) => x.startsWith("CVE-")).join(", "), a.severity, a.cvss ? "CVSS " + a.cvss : "", a.epss ? "EPSS " + Math.round(a.epss * 100) + "%" : "", a.kev ? "CISA KEV" : "", a.fixed ? t("fixedIn", a.fixed).replace(/^ · /, "") : "", (a.weakness || []).map((w) => w.id + (tr(w.name) ? " " + tr(w.name) : "")).join(", "), a.url].filter(Boolean).join(" · ")).join("; "));
        if (f.about) L.push(`- ${t("aboutWhat").replace(/:$/, "")}: ${f.about}`);
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
  // every package.json / lockfile command of a project or folder as one script — a suggestion to read, not run blindly
  function commandScript(ps, g) {
    const L = ["# " + t("cmdsHead"), "# " + t("readOnlyNote"), "# " + t("cmdsCommit"), ""];
    let n = 0;
    for (const p of ps) {
      const r = p.report;
      if (!r) continue;
      const pre = g ? cdPrefix(p, g) : "", fs = r.findings || [];
      const mal = fs.filter((f) => f.kind === "malware" && f.group !== "accepted");
      const by = (grp) => fs.filter((f) => f.group === grp && f.kind !== "malware");
      const easy = by("now_easy"), code = by("now_code"), plan = by("plan");
      const ovr = [...easy, ...code].filter((f) => f.fix && f.fix.strategy === "override");
      const sec = [];
      const addMal = () => add(t("cmdsMal"), mal.map(cmdOf));
      const add = (head, cmds, comment) => {
        const u = [...new Set(cmds.filter(Boolean))];
        if (!u.length) return;
        sec.push("# --- " + head);
        // each line in its own subshell, so a "cd" does not carry over to the next line
        for (const c of u) { sec.push((comment ? "# " : "") + (pre || c.startsWith("cd ") ? "(" + pre + c + ")" : c)); if (!comment) n++; }
        sec.push("");
      };
      addMal();
      // simple production upgrades in one install, everything else one by one
      const plain = easy.filter((f) => !f.fix || f.fix.strategy !== "override");
      const one = (f) => f.fix && f.fix.strategy === "upgrade" && f.target && !f.dev;
      add(t("cmdsEasy"), [plain.some(one) ? bulkCommand(plain.filter(one), r.manager) : "", ...plain.filter((f) => !one(f)).map(cmdOf)]);
      add(t("cmdsCode"), code.filter((f) => !f.fix || f.fix.strategy !== "override").map(cmdOf));
      add(t("cmdsOverride"), ovr.map(cmdOf));
      add(t("cmdsBundle"), (r.bundles || []).map((b) => b.command || ""));
      add(t("cmdsPlan"), plan.map(cmdOf), true);
      add(t("cmdsOptional"), by("optional").map(cmdOf), true);
      if (!sec.length) continue;
      if (ps.length > 1 || g) L.push("# ===== " + (g ? relName(p, g) : baseName(p.dir)) + "  (" + p.dir + ")", "");
      L.push(...sec);
    }
    if (!n) L.push("# " + t("cmdsNone"), "");
    L.push("# " + t("cmdsAfter"));
    return { text: L.join("\n"), n };
  }
  function openCommands(ps, rootDir, g) {
    const s = commandScript(ps, g);
    textModal(t("cmdsTitle"), t("cmdsHelp"), s.text, t("cmdsStats", s.n), "depgate-" + baseName(rootDir) + ".sh");
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
        const sk = r.skipped || [];
        toast(((r.added || []).length > 1 ? t("addedN", r.added.length) : t("added1")) + (sk.length ? " · " + t("addSkipped", sk.length, sk.slice(0, 3).map((d) => relTo(d, dir) || baseName(d)).join(", ")) : ""));
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
        : el("div", { class: "pad" }, el("div", { class: "quiet" }, t("noSubfolders")), l.hint ? el("div", { class: "warnbox" }, tr(l.hint)) : null));
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
  // ---------- MCP: one tab per agent, each with only what that agent needs ----------
  const AGENTS = [["claude", "Claude Code"], ["cursor", "Cursor"], ["vscode", "VS Code (Copilot)"], ["windsurf", "Windsurf"], ["codex", "Codex CLI"], ["gemini", "Gemini CLI"], ["stdio", "stdio"]];
  const MCP_TOOLS = [["get_overview", "toolOverview"], ["start_tasks", "toolStart"], ["get_task", "toolTask"], ["complete_task", "toolComplete"], ["check_package", "toolCheck"], ["get_fix_plan", "toolPlan"], ["get_findings", "toolFindings"], ["get_code_changes", "toolCode"], ["get_docker_issues", "toolDocker"],
    ["get_ai_rules", "toolRules"], ["get_history", "toolHistory"], ["project_status", "toolStatus"], ["scan_project", "toolScan"], ["list_projects", "toolList"]];
  let mcpPick = { agent: "claude", shell: "" };
  try { Object.assign(mcpPick, JSON.parse(localStorage.getItem("depgate-mcp") || "{}")); } catch {}
  async function openMCP(dir) {
    let info = { enabled: false, token: "" };
    try { info = await api("GET", "api/mcp"); } catch {}
    // in Docker the page sees /host/…; the agent runs on the computer itself and needs the real folder
    let hp = dir;
    if (info.home && info.hostHome && (dir === info.home || dir.startsWith(info.home + "/"))) {
      hp = info.hostHome + dir.slice(info.home.length);
      if (/^[A-Za-z]:\\/.test(info.hostHome)) hp = hp.replace(/\//g, "\\");
    }
    const win = /^[A-Za-z]:\\/.test(hp) || /Win/i.test(navigator.platform || "");
    const sep = /^[A-Za-z]:\\/.test(hp) ? "\\" : "/";
    const inDir = (f) => hp + sep + f.split("/").join(sep);
    const home = (f) => (win ? "%USERPROFILE%\\" + f.split("/").join("\\") : "~/" + f);
    if (!mcpPick.shell) mcpPick.shell = win ? "ps" : "sh";
    const base = location.origin + "/mcp";
    const url = base + "?project=" + encodeURIComponent(dir).replace(/%2F/gi, "/");
    const tok = info.token, auth = "Bearer " + tok, http = info.enabled && !!tok;
    const sh = (x) => /^[\w@%+=:,./-]+$/.test(x) ? x : "'" + x.replace(/'/g, "'\\''") + "'";
    const ps = (x) => /^[\w@%+=:,./\\-]+$/.test(x) ? x : "'" + x.replace(/'/g, "''") + "'";
    const json = (o) => JSON.stringify(o, null, 2);
    const stdio = st.container ? ["docker", "exec", "-i", "depgate", "depgate", "mcp", "--project", dir] : ["depgate", "mcp", "--project", dir];

    const body = el("div", { class: "mcpbody" });
    const step = (n, text, code, file) => el("div", { class: "mstep2" },
      el("span", { class: "num" }, n),
      el("div", { class: "grow" }, el("div", null, text, file ? [" ", el("code", { class: "file" }, file)] : null),
        code ? el("div", { class: "codebox" }, el("pre", null, code), copyBtn(code)) : null));
    function guide() {
      if (!http) mcpPick.agent = "stdio";
      const a = mcpPick.agent, out = [];
      if (!http) out.push(el("div", { class: "warnbox" }, t("mcpNoHttp")));
      if (a === "claude") {
        const q = mcpPick.shell === "ps" ? ps : sh, join = mcpPick.shell === "ps" ? "; " : " && ";
        out.push(el("div", { class: "fchips small" }, [["sh", t("shBash")], ["ps", "PowerShell"]].map(([k, l]) =>
          el("button", { class: "fchip" + (mcpPick.shell === k ? " on" : ""), "aria-pressed": String(mcpPick.shell === k), onclick: () => { mcpPick.shell = k; save(); draw(); } }, l))));
        const all = mcpPick.scope !== "one";
        out.push(el("div", { class: "fchips small" }, [["all", t("mcpAll")], ["one", t("mcpOne")]].map(([k, l]) =>
          el("button", { class: "fchip" + ((k === "all") === all ? " on" : ""), "aria-pressed": String((k === "all") === all), onclick: () => { mcpPick.scope = k; save(); draw(); } }, l))));
        out.push(step(1, t(all ? "mcpRunInAll" : "mcpRunIn")), step(2, t("mcpRun"), all
          ? `claude mcp add --transport http depgate -s user ${q(base)} --header ${q("Authorization: " + auth)}`
          : `cd ${q(hp)}${join}claude mcp add --transport http depgate -s local ${q(url)} --header ${q("Authorization: " + auth)}`),
          step(3, t("mcpCheck"), "claude mcp list"));
        out.push(el("div", { class: "quiet small" }, t(all ? "mcpAllNote" : "mcpClaudeNote")));
        out.push(el("div", { class: "mok" }, t("mcpPrompts"), " ", ["fix", "status", "check", "docker", "changes"].map((n, i) => [i ? " · " : "", el("code", null, "/mcp__depgate__" + n)])));
      } else if (a === "cursor") {
        out.push(step(1, t("mcpFile"), json({ mcpServers: { depgate: { url, headers: { Authorization: auth } } } }), inDir(".cursor/mcp.json")),
          step(2, t("mcpGitignore"), ".cursor/mcp.json"),
          step(3, t("mcpCursorCheck")));
      } else if (a === "vscode") {
        out.push(step(1, t("mcpFile"), json({ inputs: [{ type: "promptString", id: "depgate-token", description: "DepGate token", password: true }],
          servers: { depgate: { type: "http", url, headers: { Authorization: "Bearer ${input:depgate-token}" } } } }), inDir(".vscode/mcp.json")),
          step(2, t("mcpVsToken"), tok),
          step(3, t("mcpVsCheck")));
      } else if (a === "windsurf") {
        out.push(step(1, t("mcpGlobalFile"), json({ mcpServers: { depgate: { serverUrl: base, headers: { Authorization: auth } } } }), home(".codeium/windsurf/mcp_config.json")),
          step(2, t("mcpWindsurfCheck")));
      } else if (a === "codex") {
        out.push(step(1, t("mcpGlobalFile"), `[mcp_servers.depgate]\nurl = ${JSON.stringify(base)}\nhttp_headers = { "Authorization" = ${JSON.stringify(auth)} }`, home(".codex/config.toml")),
          step(2, t("mcpCheck"), "codex mcp list"));
      } else if (a === "gemini") {
        out.push(step(1, t("mcpGlobalFile"), json({ mcpServers: { depgate: { httpUrl: base, headers: { Authorization: auth } } } }), home(".gemini/settings.json")),
          step(2, t("mcpGeminiCheck"), "/mcp"));
      } else {
        out.push(el("div", { class: "quiet small" }, t("mcpStdioHelp")),
          step(1, t("mcpStdioClaude"), `cd ${(mcpPick.shell === "ps" ? ps : sh)(hp)}${mcpPick.shell === "ps" ? "; " : " && "}claude mcp add depgate -s local -- ${stdio.map(sh).join(" ")}`),
          step(2, t("mcpStdioJson"), json({ mcpServers: { depgate: { command: stdio[0], args: stdio.slice(1) } } })));
      }
      if (a !== "stdio") out.push(el("div", { class: "quiet small" }, t(a === "vscode" ? "mcpTokenVs" : "mcpTokenNote")));
      out.push(el("div", { class: "mok" }, t("mcpVerify")),
        el("div", { class: "quiet small" }, t("mcpAsk")));
      return out;
    }
    const tabs = el("div", { class: "fchips", role: "tablist", "aria-label": t("mcpAgent") });
    const save = () => { try { localStorage.setItem("depgate-mcp", JSON.stringify(mcpPick)); } catch {} };
    function draw() {
      tabs.replaceChildren(...AGENTS.filter(([k]) => http || k === "stdio").map(([k, l]) => el("button", {
        role: "tab", class: "fchip" + (mcpPick.agent === k ? " on" : ""), "aria-selected": String(mcpPick.agent === k),
        onclick: () => { mcpPick.agent = k; save(); draw(); } }, k === "stdio" ? t("mcpOther") : l)));
      body.replaceChildren(...guide());
    }
    draw();
    const toolsBox = el("details", { class: "mtools" }, el("summary", null, t("mcpTools", MCP_TOOLS.length)),
      el("div", { class: "tl" }, MCP_TOOLS.map(([n, k]) => el("div", null, el("code", null, n), el("span", { class: "quiet small" }, t(k))))));
    const close = () => { ov.remove(); document.removeEventListener("keydown", esc); };
    const esc = (e) => { if (e.key === "Escape") close(); };
    const dlg = el("div", { class: "modal wide", role: "dialog", "aria-modal": "true", "aria-label": t("mcpTitle") },
      el("div", { class: "mhead" }, el("div", { class: "h3" }, t("mcpTitle")), el("div", { class: "quiet" }, t("mcpHelp")),
        el("div", { class: "quiet small mono" }, hp)),
      el("div", { class: "pad mcpscroll" }, el("div", { class: "quiet small" }, t("mcpAgent")), tabs, body, toolsBox),
      el("div", { class: "pfoot" }, el("div", { class: "quiet" }, t("mcpStats")), el("span", { class: "grow" }), el("button", { class: "primary", onclick: () => close() }, t("close"))));
    const ov = el("div", { class: "overlay", onclick: (e) => { if (e.target === ov) close(); } }, dlg);
    document.body.append(ov); document.addEventListener("keydown", esc);
    const sel = tabs.querySelector(".on"); if (sel) sel.focus();
  }
  function openRules(ps, rootDir, g) {
    const r = rulesFor(ps, g);
    textModal(t("rulesTitle"), t("rulesHelp"), r.text, t("rulesStats", r.rules, r.repl), "AGENTS-depgate-" + baseName(rootDir) + ".md");
  }

  const SEVR = { critical: 4, high: 3, moderate: 2, low: 1 };
  function visible(f) {
    if (state.q && !f.pkg.toLowerCase().includes(state.q.toLowerCase())) return false;
    if (state.sev && (f.kind !== "vuln" && f.kind !== "malware" || (SEVR[f.severity] || 0) < SEVR[state.sev])) return false;
    const advs = f.advisories || [];
    if (state.flt.has("kev") && !advs.some((a) => a.kev)) return false;
    if (state.flt.has("epss") && !advs.some((a) => (a.epss || 0) >= 0.1)) return false;
    if (state.flt.has("nofix") && !(f.kind === "vuln" && (!f.target || f.target === f.current || advs.some((a) => !a.fixed)))) return false;
    if (state.flt.has("direct") !== state.flt.has("transitive") && f.direct !== state.flt.has("direct")) return false;
    return true;
  }

  // one command for all simple upgrades of the group
  function bulkCommand(fs, mgr) {
    const specs = [], other = [];
    for (const f of fs) {
      if (f.fix && f.fix.strategy === "upgrade" && f.target && !f.dev) specs.push(`${f.pkg}@${f.target}`);
      else if (realCmd(f.fix)) other.push(realCmd(f.fix));
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

    const kids = bare ? [el("div", { class: "rchips" }, [...title.querySelectorAll(".chip[title]:not(.prio)")])] : [title];
    if (f.title && !bare) kids.push(el("div", { class: "ctext" }, f.title));
    const dirs = where ? where.map((w) => w.p.dir) : [p.dir];
    if (f.accepted) kids.push(acceptBlock(f, dirs));
    // left: what it is and what was found · right: what to do
    const L = [aboutBlock(f)], R = [];
    if (f.advisories && f.advisories.length) L.push(advBlock(f));
    L.push(el("div", { class: "q" }, el("span", { class: "dot " + needClass(f.needUpdate) }), el("span", { class: "lbl" }, t("qNeed")), el("span", { class: "ans" }, needText(f.kind, f.needUpdate))));
    if (f.why && f.why.length) L.push(el("ul", { class: "why" }, list(f.why)));
    R.push(el("div", { class: "q" }, el("span", { class: "dot " + impClass(f.codeImpact) }), el("span", { class: "lbl" }, t("qImpact")), el("span", { class: "ans" }, impText(f.codeImpact))));
    if (f.impactWhy && f.impactWhy.length) R.push(el("ul", { class: "why" }, list(f.impactWhy)));
    const lad = ladder(f);
    if (lad) R.push(lad);
    const migs = where ? where.flatMap((w) => (w.f.migrate || []).map((m) => [m, where.length > 1 ? relName(w.p, g) : ""])) : (f.migrate || []).map((m) => [m, ""]);
    if (bare && migs.length) {
      const now = migs.filter(([m]) => !m.plan), hits = now.reduce((a, [m]) => a + (m.hits || 0), 0);
      const later = migs.filter(([m]) => m.plan).reduce((a, [m]) => a + (m.hits || 0), 0);
      R.push(el("button", { class: "tocode" + (now.length ? " now" : ""), onclick: () => goTab("code") },
        hits ? t("seeCode", hits) : !now.length && later ? t("seeCodePlan", later) : t("seeCode0")));
    } else for (const [m, l] of migs) R.push(migBlock(m, l));
    if (f.warnings && f.warnings.length) R.push(el("div", { class: "warnbox" }, f.warnings.map((w) => el("div", null, "⚠ " + tr(w)))));
    if (where) {
      const lines = where.map((w) => w.f.fix && w.f.fix.command ? cdPrefix(w.p, g) + w.f.fix.command.split("   #")[0] : "").filter(Boolean);
      R.push(el("div", { class: "where" },
        el("div", { class: "row" }, el("b", null, where.length === 1 ? t("whereN1") : t("whereN", where.length)), el("span", { class: "grow" }), lines.length > 1 ? copyBtn(lines.join("\n"), t("whereAll")) : null),
        where.map((w) => el("div", { class: "row" },
          el("button", { class: "link", onclick: () => select(w.p.dir), title: w.p.dir }, relName(w.p, g)),
          w.f.fix && w.f.fix.command ? [el("code", null, cdPrefix(w.p, g) + w.f.fix.command.split("   #")[0]), copyBtn(cdPrefix(w.p, g) + w.f.fix.command.split("   #")[0])] : null))));
    }
    if (f.fix) {
      const fx = f.fix;
      const note = tr(fx.note);
      const cmd = where ? "" : fx.command;
      R.push(el("div", { class: "fix" },
        el("div", { class: "row" }, el("span", { class: "chip" }, strat(fx.strategy)), cmd ? el("code", null, cmd) : el("span", { class: "grow" }), cmd ? copyBtn(cmd.split("   #")[0]) : null),
        fx.snippet ? el("pre", null, (fx.file ? "// " + fx.file + "\n" : "") + fx.snippet) : null,
        note ? el("div", { class: "note" }, note) : null));
      if (f.group !== "ok" && f.group !== "accepted") R.push(el("ol", { class: "todo" },
        el("li", null, t(fx.snippet ? (realCmd(fx) ? "todoOverride" : "todoSnippet") : "todoCmd")),
        f.codeImpact === "yes" || f.codeImpact === "maybe" ? el("li", null, t("todoCode")) : null,
        el("li", null, t("todoBuild")),
        el("li", null, t("todoRescan"))));
    }
    const foot = el("div", { class: "cfoot" });
    foot.append(copyBtn(where ? where.map((w) => agentTask(w.f, w.p.report)).join("\n\n---\n\n") : agentTask(f, p), t("agentBtn")));
    if (!f.accepted) { const ab = acceptBlock(f, dirs); if (ab) foot.append(...ab.childNodes); }
    R.push(foot);
    kids.push(el("div", { class: "cgrid" },
      el("div", { class: "ccol" }, el("div", { class: "clbl" }, t("colWhat")), L),
      el("div", { class: "ccol do" }, el("div", { class: "clbl" }, t("colDo")), R)));
    return el("div", { class: cls }, kids);
  }

  // which version fixes what: "16.3.3 fixes 2, 16.3.8 fixes 9 …" and where the suggested target lands
  function cmpVer(a, b) {
    const sp = (v) => { const [m, pre] = String(v).replace(/^v/, "").split("-", 2); return [m.split(".").map((x) => parseInt(x, 10) || 0), pre]; };
    const [ma, pa] = sp(a), [mb, pb] = sp(b);
    for (let i = 0; i < 3; i++) if ((ma[i] || 0) !== (mb[i] || 0)) return (ma[i] || 0) - (mb[i] || 0);
    return pa === pb ? 0 : pa === undefined ? 1 : pb === undefined ? -1 : pa < pb ? -1 : 1;
  }
  function ladder(f) {
    const advs = f.advisories || [];
    if (advs.length < 2) return null;
    const by = new Map(), none = [];
    for (const a of advs) { if (a.fixed) { if (!by.has(a.fixed)) by.set(a.fixed, []); by.get(a.fixed).push(a); } else none.push(a); }
    const steps = [...by.keys()].sort(cmpVer);
    if (steps.length < 2 && !none.length) return null;
    let sum = 0;
    const SEVK = { critical: "bad", high: "hi", moderate: "warn", medium: "warn", low: "low" };
    const rows = steps.map((v) => {
      const as = by.get(v); sum += as.length;
      const sev = {};
      for (const a of as) sev[a.severity] = (sev[a.severity] || 0) + 1;
      const isT = f.target && cmpVer(f.target, v) === 0;
      return el("div", { class: "lrow" + (isT ? " target" : "") },
        el("code", null, f.pkg + "@" + v),
        el("span", null, t("ladderFixes", as.length)),
        el("span", { class: "lsev" }, Object.entries(sev).map(([k, n]) => el("span", { class: "risk " + (SEVK[k] || "low") }, n + " " + sevName(k)))),
        el("span", { class: "quiet small" }, t("ladderSum", sum, advs.length)),
        isT ? el("span", { class: "chip ok" }, t("ladderTarget")) : null);
    });
    return el("div", { class: "ladder" }, el("div", { class: "h4" }, t("ladderTitle")), rows,
      none.length ? el("div", { class: "lrow none" }, el("span", { class: "risk bad" }, t("ladderNone", none.length)), el("span", { class: "quiet small" }, t("ladderNoneHelp"))) : null);
  }

  // what the package is and how it got into the project
  function aboutBlock(f) {
    const how = f.direct ? t("aboutDirect", f.dev ? "devDependencies" : "dependencies")
      : f.chain && f.chain.length > 1 ? t("aboutVia", f.chain.join(" → ")) : t("transitive");
    return el("div", { class: "about" },
      el("div", null, el("span", { class: "lbl" }, t("aboutWhat")), " ",
        f.about ? el("span", null, f.about) : el("span", { class: "quiet" }, t("aboutNone")),
        safeURL(f.homepage) ? [" ", el("a", { href: f.homepage, target: "_blank", rel: "noopener noreferrer" }, t("aboutHome"))] : null),
      el("div", null, el("span", { class: "lbl" }, t("aboutHow")), " ", el("span", { class: f.direct ? "" : "mono" }, how)));
  }
  // what was found: every advisory, its weakness type, and what that weakness lets an attacker do
  function advBlock(f) {
    const advs = f.advisories, byCWE = new Map();
    for (const a of advs) for (const w of a.weakness || []) if (!byCWE.has(w.id)) byCWE.set(w.id, w);
    const item = (a) => {
      const u = safeURL(a.url);
      const cves = (a.aliases || []).filter((x) => x.startsWith("CVE-"));
      const meta = [a.severity, a.cvss ? "CVSS " + a.cvss : "", a.epss ? "EPSS " + Math.round(a.epss * 100) + "%" : "", a.kev ? t("advKev") : "", a.fixed ? t("fixedIn", a.fixed).replace(/^ · /, "") : ""].filter(Boolean).join(" · ");
      return el("div", { class: "adv" },
        el("div", { class: "advh" }, u ? el("a", { href: u, target: "_blank", rel: "noopener noreferrer" }, a.id) : el("b", null, a.id),
          cves.length ? el("span", { class: "quiet small" }, cves.join(", ")) : null, el("span", { class: "quiet small" }, meta)),
        a.summary ? el("div", { class: "advs1" }, a.summary) : null,
        (a.weakness || []).length ? el("div", { class: "small" }, el("span", { class: "lbl" }, t("advType")), " ",
          a.weakness.map((w, i) => [i ? ", " : "", tr(w.name) || w.id, tr(w.name) ? el("span", { class: "quiet" }, " (" + w.id + ")") : null])) : null,
        a.details ? el("details", { class: "advd" }, el("summary", null, t("advText")), el("div", { class: "quiet small" }, a.details)) : null);
    };
    const shown = advs.slice(0, 4), rest = advs.slice(4);
    const known = [...byCWE.values()].filter((w) => tr(w.what));
    return el("div", { class: "found" },
      el("div", { class: "h4" }, t("advFound", advs.length)),
      shown.map(item),
      rest.length ? el("details", { class: "advd" }, el("summary", null, t("advMore", rest.length)), rest.map(item)) : null,
      known.length ? el("div", { class: "weak" }, el("div", { class: "h4" }, t("advMeans")),
        known.map((w) => el("div", { class: "wk" },
          el("div", null, el("b", null, tr(w.name)), " ", safeURL(w.url) ? el("a", { class: "small", href: w.url, target: "_blank", rel: "noopener noreferrer" }, w.id) : null),
          el("div", { class: "small" }, el("span", { class: "lbl" }, t("advWhat")), " ", tr(w.what)),
          el("div", { class: "small" }, el("span", { class: "lbl" }, t("advRisk")), " ", tr(w.risk))))) : null);
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
    if (!on) { $("#srcbtn").hidden = true; $("#scanall").hidden = true; $("#refresh").hidden = true; $("#addproj").hidden = true; $("#projects").hidden = true; $("#banner").hidden = true; $("#meta").textContent = ""; }
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
