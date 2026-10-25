<p align="center"><img src="docs/social-preview.png" alt="DepGate" width="820"></p>

<h1 align="center">DepGate</h1>

<p align="center"><b>npm asılılıqların bir ekranda: nəyi indi yeniləmək lazımdır, nə gözləyə bilər və yeniləmə kodunu sındırırmı.</b><br>
Lokal veb interfeys · Docker · sıfır asılılıq · Azərbaycan və ingilis dili</p>

<p align="center"><a href="README.md">English</a></p>

---

`npm audit` nəyinsə boşluqlu olduğunu deyir. DepGate isə **nə etməli olduğunu** deyir:

| Hər paket üçün | DepGate-in cavabı |
|---|---|
| ① **Yeniləmək lazımdır?** | Zərərli paket və critical/high CVE üçün **DƏRHAL** (CISA KEV + EPSS ilə çəkilir) · növbəti baxımda · planla · istəyə görə · lazım deyil |
| ② **Koda təsir edir?** | **Xeyr** — patch/minor, bir əmr · **Ola bilər** — peer/engines münaqişəsi · **Bəli** — major, miqrasiya bələdçisi ilə |
| 🎯 **Hansı versiya?** | «Ən təhlükəsiz minimum»: cari major-da boşluğu düzəldən ən kiçik versiya, «latest» yox |
| 🔗 **Dolayı paketdirsə?** | Lockfile yeniləməsi → birbaşa valideynin yenilənməsi → hazır `overrides` bloku |
| 🕵️ **Yeni versiyanın özü təhlükəsizdirmi?** | 3 gündən cavan versiyaları keçir; yeni install skriptini, itən provenance-ı, dəyişən dərc edəni və ya repo-nu işarələyir |

Hər şey sənin kompüterində işləyir. Kənara yalnız paket adları, versiyalar və CVE nömrələri gedir, kod heç vaxt getmir.

![DepGate dashboard](docs/screenshot-az.png)

## Niyə indi

2026-cı il npm təchizat zənciri üçün ən ağır il oldu: martda 100 milyondan çox həftəlik yüklənməsi olan [Axios ələ keçirildi](https://unit42.paloaltonetworks.com/axios-supply-chain-attack/), mayda [Mini Shai-Hulud](https://braindetox.kr/en/posts/npm_supply_chain_attack_2026.html) 22 dəqiqədə 314 paketi zərərli versiyalarla əvəz etdi, iyunda `binding.gyp` vasitəsilə [57 paket](https://threatcluster.io/cluster/large-scale-supply-chain-attack-targets-npm-packages-via-bin-4588b024) götürüldü, oktyabrda isə Node.js-in özündə Brotli RCE (CVE-2026-111497) daxil olmaqla [10 boşluq düzəldildi](https://securityonline.info/nodejs-security-release-october-2026/).

Faydalı olsa, ⭐ başqa developerlərin onu tapmasına kömək edir.

## Quraşdırma

```bash
go install github.com/Ali7Zeynalli/depgate@latest
# və ya Releases-dən hazır binary (linux, macOS, Windows; amd64, arm64)
```

## İstifadə

### Veb interfeys (əsas rejim)

```bash
depgate
```

`http://127.0.0.1:7777` açılır; ilk dəfə parol təyin edirsən. Interfeys iki dillidir: brauzerin dili Azərbaycan dilidirsə, özü AZ açılır; yuxarıdakı **AZ / EN** düyməsi ilə yenidən skan etmədən dəyişir. **+ Layihə əlavə et** düyməsini bas, qovluqları gəz (`package.json` olanlar «layihə» kimi işarələnib) və layihəni seç. Bütöv qovluq da seçmək olar: altındakı bütün layihələr, monorepo üzvləri daxil, əlavə olunur və arxa planda skan edilir.

Layihə siyahısı və son hesabatlar yadda qalır (`~/.config/depgate`), növbəti dəfə hamısı yerindədir. Hər layihə üçün **Skan et** və **Siyahıdan sil**, hamısı üçün **Hamısını skan et**. Layihə qovluğunda `depgate` (və ya `depgate ~/projects`) yazsan, dərhal əlavə olunur.

Qovluq seçici yalnız icazə verilən kökləri göstərir (standart: ev qovluğu; `--root` ilə dəyişir).

![Layihə əlavə etmək](docs/add-project.png)

### Docker

```bash
git clone https://github.com/Ali7Zeynalli/depgate.git && cd depgate
DEPGATE_UID=$(id -u) DEPGATE_GID=$(id -g) docker compose up -d
```

`http://127.0.0.1:7777` aç, parol təyin et və ev qovluğunun istənilən yerindən layihə əlavə et.

- **Ev qovluğun eyni yolla, yalnız oxuma rejimində bağlanır** — interfeysdə real yollar (`/home/sən/...`) görünür, heç nəyi köçürmək lazım deyil. DepGate ora heç nə yazmır.
- Konteyner **sənin istifadəçinlə** işləyir (`DEPGATE_UID`/`DEPGATE_GID`, standart 1000) ki, fayllarını oxuya bilsin; əvvəlcə qısa `depgate-init` addımı data volume-unu həmin istifadəçiyə verir (köhnə versiyaların yaratdığı volume-ları da düzəldir).
- Siyahı, hesabatlar və parol hash-ı **`depgate-data` Docker volume-unda** saxlanır (yenidən başlatma və yeniləmədə itmir). Docker-siz `depgate` ilə ortaq istifadə etmək istəsən, volume-u `${HOME}/.config/depgate:/data` ilə əvəz et (`docker-compose.yml`-dəki şərhə bax).
- Port yalnız `127.0.0.1`-də açılır. `DEPGATE_PASSWORD=…` parolu brauzer əvəzinə əvvəlcədən təyin edir.

### Bir dəfəlik rejimlər

```bash
depgate --json > report.json # skan et, JSON yaz (schema depgate/report@1)
depgate --view report.json   # saxlanmış hesabatı interfeysdə aç
depgate --ci --fail-on high  # CI: high/critical və ya zərərli paket varsa çıxış kodu 1
depgate --push URL --token T # skan et və hesabatı göndər
depgate --offline            # şəbəkəsiz, yalnız keşdən
```

| Bayraq | Nə edir | Standart |
|---|---|---|
| `--port` | Veb interfeysin portu (məşğuldursa növbəti) | 7777 |
| `--addr` | Dinlənilən ünvan | 127.0.0.1 (Docker-də 0.0.0.0) |
| `--root` | Gəzilə bilən qovluq (təkrarlana bilər; `DEPGATE_ROOTS`) | ev qovluğu |
| `--data` | Siyahı, hesabatlar, token (`DEPGATE_DATA`) | `~/.config/depgate` |
| `--allow-host` | Əlavə icazəli `Host` adı (təkrarlana bilər) | — |
| `--reset-password` | Parolu unut; növbəti açılışda yenisi istənir | — |
| `--no-auth` | Parolu söndür (yalnız 127.0.0.1; tövsiyə olunmur) | söndürülüb |
| `--no-open` | Brauzeri avtomatik açmır | açır |
| `--depth` | Layihə axtarışının dərinliyi | 3 |

Terminal mesajları standart olaraq ingiliscədir; `DEPGATE_LANG=az` ilə Azərbaycan dilinə keçir.
| `--cooldown` | Bundan cavan versiyaları (gün) hədəf seçmir | 3 |

## Nə yoxlayır

- **Paketlər:** `package-lock.json` (v1–v3), `pnpm-lock.yaml` (v5–v9), `yarn.lock` (v1 və berry), `bun.lock`. Dolayı paketlər daxil. Lockfile yoxdursa `node_modules`-dan oxuyur, o da yoxdursa «təxmini» rejimə keçir.
- **Boşluqlar və zərərli paketlər:** [OSV.dev](https://osv.dev) (GitHub Advisory və OpenSSF Malicious Packages daxil).
- **Prioritet:** severity + [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) + [EPSS](https://www.first.org/epss/).
- **Hədəf versiya — «ən təhlükəsiz minimum»:** eyni major xəttində boşluğu düzəldən ən kiçik versiya; 3 gündən cavan versiyalar keçilir.
- **Dolayı paket:** relock → birbaşa valideynin yenilənməsi → override bloku.
- **Koda təsir:** semver fərqi, hədəf versiyanın `engines.node` və `peerDependencies` tələbləri.
- **Təchizat zənciri siqnalları:** yeni install skripti, itən provenance, dərc edən hesabın dəyişməsi, repo linkinin dəyişməsi.
- **Node.js runtime:** Dockerfile, `.nvmrc`, `.node-version`, `.tool-versions`, `engines`, GitHub Actions; təhlükəsizlik relizləri və EOL tarixləri.
- **Layihə gigiyenası:** lockfile, install skriptləri, cooldown ayarı, Node versiyasının uyğunluğu.

## Qovluqlar və AI prompt

Qovluq əlavə edəndə (monorepo və ya bir neçə layihənin olduğu qovluq) sol paneldə bir başlıq kimi görünür, layihələri isə onun altında sıralanır. Qovluğun adına klikləyəndə bütün layihələrin ümumi səhifəsi açılır: əvvəl layihələr cədvəli, sonra bütün tapıntılar kateqoriyalar üzrə. Eyni tapıntı bir neçə layihədə varsa, bir dəfə göstərilir: altında hansı layihələrdə olduğu və hər biri üçün işlədiləcək əmr yazılır.

**AI üçün prompt** (qovluqda və ya tək layihədə) Claude Code, Cursor və ya başqa agent üçün bir tapşırıq yazır. Orada hər paket üçün harada olduğu, hansı versiyaya və niyə yenilənməli olduğu, advisory-lər, koda təsiri və dəqiq əmr göstərilir. Qaydalar da var: əvvəl zərərli paketlər, ən təhlükəsiz minimum versiya, build və testləri işlətmək. Sonda agentin nəyi hesabat verməli olduğu yazılır. Promptu kopyalaya və ya `.md` kimi yükləyə bilərsən.

![Qovluq səhifəsi](docs/folder-overview.png)
![AI prompt](docs/ai-prompt.png)

## Birlikdə yenilə, Docker, AI qaydaları

DepGate heç bir faylı dəyişmir. Aşağıdakıların hamısını yalnız göstərir və təklif edir; tətbiq etmək sənin (və ya AI agentinin) işidir.

- **Birlikdə yenilə.** Bəzi paketlər həmişə birlikdə buraxılır: `react` + `react-dom` (+ uyğun `@types/react`), `next` + `eslint-config-next`, əsas `@nestjs/*` paketləri, `@angular/*`, Vue, Storybook, Nx, Prisma, typescript-eslint, Tiptap. Onlardan biri yeni versiyaya keçməlidirsə və ya versiyaları bir-birindən ayrılıbsa, DepGate bir kart göstərir: hər paket, onun hədəf versiyası və hamısı üçün bir əmr. Öz versiya xətti olan paketlər (məsələn `@nestjs/config`) qrupa salınmır.
- **Docker təhlükəsizliyi.** Layihədəki və repo kökündəki Dockerfile və compose faylları yoxlanır: konteynerin root ilə işləməsi, `latest` teqləri, `ENV`/`ARG`/`environment` içində sirlər, `npm ci` əvəzinə `npm install`, `curl | sh`, `.dockerignore`-un olmaması (bu halda `.env` image-ə düşə bilər), `privileged`, Docker socket-in konteynerə bağlanması, bütün interfeyslərə açılmış verilənlər bazası, host şəbəkəsi və PID, söndürülmüş seccomp/AppArmor və s. Hər tapıntıda fayl, sətir, servis və təklif olunan sətir göstərilir.
- **AI qaydaları.** AI modelləri köhnə versiyalarla öyrədilib: Next.js 16 layihəsində `getServerSideProps`, ESLint 9-da `.eslintrc` yazırlar. **AI qaydaları** lockfile-dakı versiyalardan `AGENTS.md` / `CLAUDE.md` / `.cursor/rules` üçün blok hazırlayır. Blokda dəqiq stack, versiyaya uyğun qaydalar (Next.js, React, Tailwind, ESLint, Express, NestJS, Prisma, Zod, TanStack Query, React Router, TypeScript, Node.js; hər biri rəsmi upgrade bələdçisinin linki ilə) və köhnəlmiş paketlərin daxili və ya dəstəklənən əvəzləri (`request`, `moment`, `node-fetch`, `dotenv`, `rimraf` və s.) olur. Bloku kopyalaya və ya `.md` kimi yükləyə bilərsən.

## Mənbələr

Hər qərar açıq və pulsuz mənbələrə əsaslanır. İnterfeysdəki **Mənbələr** düyməsi onları göstərir: hər mənbə nə üçün istifadə olunur və son skanda neçə sorğuya cavab verib (və ya alınmayıb). Eyni siyahının linki hər layihənin altında da var.

| Mənbə | Nə üçün |
|---|---|
| [OSV.dev](https://osv.dev) | zəifliklər (CVE/GHSA) və zərərli paketlər — GitHub Advisory Database və OpenSSF Malicious Packages daxil |
| [npm advisories](https://docs.npmjs.com/cli/commands/npm-audit) | `npm audit`-in mənbəyi: GitHub Advisory Database birbaşa, zərərli paketlər daxil — OSV-nin hələ almadığı qeydləri tutur |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | real hücumlarda istifadə olunan zəifliklər (prioriteti qaldırır) |
| [FIRST EPSS](https://www.first.org/epss/) | yaxın 30 gündə istismar ehtimalı (prioritetə təsir edir) |
| [deps.dev](https://deps.dev) | paketin bütün versiyaları və buraxılış tarixləri (hədəf versiya, gözləmə müddəti) |
| [npm registry](https://www.npmjs.com) | hədəf versiyanın `engines`, peer asılılıqları, install skriptləri, provenance, deprecated qeydi |
| [Node.js releases](https://nodejs.org/en/about/previous-releases) + [Node.js Security WG](https://github.com/nodejs/security-wg) | Node.js versiyaları, təhlükəsizlik relizləri, EOL tarixləri və dəqiq versiyana aid CVE-lər |

Əlavə mənbə tələb etməyən iki yoxlama:

- **Silinmiş versiyalar.** Lockfile-dakı versiya npm registry-də artıq yoxdursa, DepGate bunu göstərir: təmiz quraşdırma alınmayacaq, npm isə zərərli versiyaları silir. npm bütün paketi `0.0.1-security` ilə əvəz edibsə, bu zərərli paket kimi göstərilir. Workspace və özəl paketlər yoxlanmır.
- **Prerelease versiyalar.** `npm audit` `2.0.0-beta.1` kimi versiyaları advisory aralıqları ilə müqayisə etmir, DepGate isə edir.

**Dəqiqlik.** `TestCompareNpmAudit` testi məlum zəif asılılıqları olan bir layihəni skan edir və `npm audit`-in tapdığı hər advisory-nin DepGate hesabatında da olduğunu yoxlayır (yazılan vaxt 71/71). Test GitHub Actions-da hər həftə işləyir (`accuracy` workflow). Lokal işlətmək üçün: `DEPGATE_LIVE=1 go test -run TestCompareNpmAudit -v ./internal/scan`.

Kompüterində oxunanlar: `package.json`, lockfile, Dockerfile / `.nvmrc` / `.node-version` / `engines` / CI faylları, `.npmrc`.

![Mənbələr](docs/sources.png)

## Kənara nə gedir

Yalnız paket adları və versiyalar (OSV, deps.dev, npm registry və onun advisory endpoint-i), CVE nömrələri (EPSS). Kod, fayl yolları, layihə adları, `.env` heç vaxt getmir. Cavablar `~/.cache/depgate/` qovluğunda keşlənir.

Veb interfeys `127.0.0.1`-də işləyir (Docker-də host-un `127.0.0.1`-inə açılır), parolla qorunur, `Host` başlığını yoxlayır, CSP aktivdir. Qovluq gəzmə icazəli köklərlə məhdudlaşır və DepGate layihələri yalnız oxuyur.

## Parol niyə lazımdır?

DepGate kompüterində `127.0.0.1:7777` ünvanında kiçik veb server işlədir. Qorunmasa, o ünvana çata bilən hər şey ondan istifadə edə bilər:

- **açdığın başqa saytlar** — zərərli səhifə və ya reklam brauzerin üzərindən `127.0.0.1`-ə sorğu göndərib (CSRF, DNS rebinding) qovluqlarını, layihə adlarını və hesabatları oxumağa cəhd edə bilər;
- **eyni kompüterdəki başqa proqramlar və istifadəçilər** — localhost portu hamısına açıqdır;
- **şəbəkə** — Docker portu səhvən `0.0.0.0`-a açılsa, eyni Wi-Fi-dakı hər kəs interfeysi görə bilər.

DepGate qovluqlarını gəzə bilir və layihələrinin zəif yerlərini göstərir — hücumçunun axtardığı məhz budur. Ona görə interfeys parolla qorunur:

- **ilk açılış:** parolu özün seçirsən (ən azı 8 simvol) — heç bir token, kopyalanacaq link yoxdur;
- **sonra:** adi giriş səhifəsi, «məni yadda saxla» (30 gün); yuxarıda **Çıxış** və **Parolu dəyiş** düymələri var (parol dəyişəndə digər brauzerlərdəki sessiyalar bağlanır);
- **unutmusan?** `depgate --reset-password` (Docker-də: `docker exec depgate depgate --reset-password`), sonra yenisini təyin et;
- **Docker / avtomatlaşdırma:** `DEPGATE_PASSWORD=…` parolu əvvəlcədən təyin edir; skriptlər API-ni `Authorization: Bearer <token>` ilə çağırır (token `~/.config/depgate/token` faylındadır; Docker-də onu `DEPGATE_TOKEN` ilə özün təyin et).

Parol yalnız PBKDF2-SHA256 hash kimi saxlanır (600 000 iterasiya, təsadüfi salt); ardıcıl yanlış cəhdlər yavaşladılır. Bundan əlavə DepGate `Host` başlığını yoxlayır, hər API sorğusunda xüsusi başlıq tələb edir və sərt Content Security Policy göndərir.

## İnkişaf

```bash
go test ./...
go vet ./...
go run . ./testdata/lockfiles/npm-v3
```

## Lisenziya

MIT
