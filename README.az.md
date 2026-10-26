<p align="center">
  <img src="docs/social-preview.png" alt="DepGate — yeniləmək lazımdır və kodumu sındıracaqmı?" width="820">
</p>

<h1 align="center">DepGate</h1>

<p align="center">
  <b>npm asılılıqların bir ekranda: nəyi indi yeniləmək lazımdır, nə gözləyə bilər, yeniləmə kodunu sındırırmı və dəqiq harada.</b><br>
  Linux · macOS · Windows · Docker və ya tək fayl · sıfır asılılıq · Azərbaycan və ingilis dili
</p>

<p align="center">
  <a href="https://github.com/Ali7Zeynalli/depgate/actions/workflows/ci.yml"><img src="https://github.com/Ali7Zeynalli/depgate/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="https://github.com/Ali7Zeynalli/depgate/releases"><img src="https://img.shields.io/github/v/release/Ali7Zeynalli/depgate?include_prereleases&amp;sort=semver" alt="release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT"></a>
  <img src="https://img.shields.io/badge/third--party%20deps-0-brightgreen" alt="sıfır asılılıq">
</p>

<p align="center">
  <a href="#quraşdırma">Quraşdırma</a> · <a href="#nə-edir">Nə edir</a> · <a href="#mcp">AI agentlər (MCP)</a> · <a href="#mənbələr">Mənbələr</a> · <a href="#əmr-sətri">Əmr sətri</a> · <a href="#təhlükəsizlik">Təhlükəsizlik</a> · <a href="README.md">English</a>
</p>

---

`npm audit` nəyinsə zəif olduğunu deyir. DepGate isə **nə etməli olduğunu** deyir — hər layihədə, hər paket üçün:

| Sual | DepGate-in cavabı |
|---|---|
| ① **Yeniləmək lazımdır?** | **indi** (zərərli paket, kritik/yüksək CVE — CISA KEV və EPSS-ə görə) · tezliklə · planla · istəyə görə · lazım deyil |
| ② **Koduma təsir edir?** | **xeyr** (patch/minor, bir əmr) · **ola bilər** (peer/engines ziddiyyəti) · **bəli** (breaking reliz) |
| 📍 **Kodumda harada?** | dəyişməli hər yer — `fayl:sətir`, niyə, əvəzinə nə yazmalı — və rəsmi codemod |
| 🎯 **Hansı versiyaya?** | *ən təhlükəsiz minimum*: cari major-da zəifliyi olmayan ən kiçik versiya, «latest» yox |
| 🤖 **AI agentim edə bilər?** | hazır prompt, `AGENTS.md` üçün versiya qaydaları və agentin özünün soruşduğu MCP server |

Dockerfile və compose fayllarını, nginx və Caddy-ni, Node.js runtime-ı da yoxlayır. Hər şey sənin kompüterində işləyir və DepGate **heç bir faylı dəyişmir** — göstərir və təklif edir.

![Ümumi](docs/overview.png)

<a id="quraşdırma"></a>
## Quraşdırma

Üç yol var, nəticə eynidir: `http://127.0.0.1:7777` ünvanında veb interfeys.

### Docker (Linux, macOS, Windows)

```bash
git clone https://github.com/Ali7Zeynalli/depgate.git
cd depgate
docker compose up -d
```

Heç nə ayarlamaq lazım deyil. Ev qovluğun **yalnız oxuma** rejimində bağlanır; konteyner onun sahibini özü tapır, həmin istifadəçi kimi işləyir və bütün hüquqlarını buraxır (SELinux da daxil). DepGate-in nəyi gördüyü onu haradan işə saldığından asılıdır:

| Haradan işə salınıb | DepGate nəyi görür |
|---|---|
| Linux / macOS terminalı | ev qovluğunu öz yolu ilə (`/home/sən`, `/Users/sən`) |
| Windows PowerShell və ya cmd | `C:\Users\sən`, `/host` kimi |
| Windows Git Bash | `C:\Users\sən`, `/c/Users/sən` kimi |
| Windows WSL terminalı | WSL ev qovluğunu — layihələr Windows tərəfindədirsə, PowerShell-dən işə sal |

Yeniləmə: `git pull && docker compose up -d --build`. Layihələr, hesabatlar və parol `depgate-data` volume-unda saxlanır.

### Tək fayl (Docker-siz)

[Releases](https://github.com/Ali7Zeynalli/depgate/releases)-dən arxivini yüklə — Linux, macOS (Intel, Apple Silicon) və ya Windows, amd64 və ya arm64 — aç və `./depgate` işlət (Windows: `depgate.exe`). Yollar real görünür, AI agentlər üçün də ən rahatı budur.

- macOS, ilk dəfə: `xattr -d com.apple.quarantine ./depgate` (fayl notarizasiya olunmayıb).
- Windows SmartScreen: *More info → Run anyway*.
- Yoxlama: `checksums.txt` (SHA-256) və `gh attestation verify <fayl> -R Ali7Zeynalli/depgate`.

### Go

```bash
go install github.com/Ali7Zeynalli/depgate@latest
depgate
```

### İlk addımlar

1. `http://127.0.0.1:7777` aç və parol seç.
2. **+ Layihə əlavə et** → layihəni və ya bütöv qovluğu seç (monorepo-lar da). Skan başlayır.
3. Əvvəlcə **Ümumi** bölməsini oxu: görüləcək bir neçə iş sıra ilə yazılıb.
4. İstəsən, AI agentini qoş — **AI və MCP → Qoşulma əmri** yolu və tokeni doldurulmuş əmri verir.

<a id="nə-edir"></a>
## Nə edir

Hər layihə və qovluq bölmələrə ayrılıb: **Ümumi** · **Paketlər** · **Kod dəyişiklikləri** · **Docker** · **Veb server** (olanda) · **Node.js və mühit** · **AI və MCP**.

### Paketlər

![Paketlər](docs/screenshot-az.png)

- Hər paket bir sətirdir; açanda tam cavab görünür: paket nədir, layihəyə necə düşüb, nə tapılıb və həlli.
- **Zəifliklər və zərərli paketlər** OSV.dev və npm advisory bazasından (`npm audit`-in məlumatı) birləşdirilir; prerelease versiyalar da yoxlanır.
- **Hər advisory izah olunur:** zəiflik növü (CWE) sadə dildə — nədir və hücumçuya nə imkan verir — 70-ə yaxın geniş yayılmış növ üçün, Azərbaycan və ingilis dilində.
- **Silinmiş versiyalar:** npm-in artıq vermədiyi versiya və ya `0.0.1-security` yer tutanı ilə əvəz olunmuş paket.
- **Dolayı paketlər:** valideyn düzəlişə icazə verirsə lockfile yenilənir, yoxsa valideyn yenilənir, o da olmasa hazır `overrides` bloku verilir.
- **Birlikdə yenilə:** `react` + `react-dom`, `next` + `eslint-config-next`, `@nestjs/*`, `@angular/*`, Vue, Storybook, Nx, Prisma… bir kartda, bir əmrlə.
- **Yeni versiya təhlükəsizdirmi?** 3 gündən yeni versiyalar keçilir; yeni install skriptləri, itən provenance, dəyişən dərc edən hesab və repo xəbərdarlıqla göstərilir.

### Kod dəyişiklikləri

Yeniləmə breaking relizdən keçirsə, DepGate mənbə fayllarını oxuyur (kompüterində) və dəyişməli hər yeri göstərir: `fayl:sətir`, sətrin özü, niyə, əvəzinə nə yazmalı və rəsmi codemod. Dəqiq qaydalar: **Next.js 15/16, React 18/19, TanStack Query 5, ESLint 9, Tailwind 4, Express 5, NestJS 11, Zod 4, Prisma 7, React Router 6/7**; Angular, Nx, Storybook və Expo üçün rəsmi yeniləmə alətləri; başqa paketlərin major yeniləməsində GitHub reliz qeydlərinin *breaking changes* hissəsi. Axtarış mətn nümunələri ilə aparılır — hər yeri yoxla, sonra build və testləri işlət.

![Kod dəyişiklikləri](docs/code-changes.png)

### Docker və veb server

- **Docker** — 25 təhlükəsizlik qaydası (root istifadəçi, `ENV`/`environment`-də sirlər, `latest` teqləri, `npm ci` əvəzinə `npm install`, `.dockerignore`-un olmaması, `docker.sock`, bütün interfeyslərə açıq verilənlər bazası…), Compose Specification xətaları (səhv yazılmış açarlar, elan olunmamış volume/şəbəkə, qırıq `depends_on`) və endoflife.date-ə görə dəstəyi bitmiş və ya köhnəlmiş image-lər.
- **nginx və Caddy** — işlətdiyin versiyanın məlum zəiflikləri (nginx-in öz siyahısı, Caddy üçün OSV) və konfiqurasiya yoxlamaları: köhnə TLS, zəif şifrlər, HSTS və təhlükəsizlik başlıqlarının olmaması, `alias` ilə yol keçidi, `autoindex`/`browse`, `$uri` ilə CRLF, `proxy_pass` ilə SSRF, açıq Caddy admin API. Qaydalar gixy, Mozilla SSL, OWASP Secure Headers və rəsmi sənədlərə əsaslanır.

![Veb server](docs/webserver.png)

### Node.js və layihə mühiti

Node.js versiyası Dockerfile, `.nvmrc`, `.node-version`, `engines` və CI fayllarından oxunur: təhlükəsizlik relizləri, dəstəyin bitməsi və dəqiq versiyana aid CVE-lər. Üstəlik gigiyena: lockfile var, install skriptləri söndürülüb, yeni versiyalar üçün gözləmə müddəti, hər yerdə eyni Node.js versiyası.

### Qovluqlar və monorepo-lar

Qovluq əlavə edəndə layihələri sol paneldə onun altında görünür. Qovluq səhifəsi hamısını birləşdirir: bir neçə layihədə olan tapıntı bir dəfə göstərilir, hər layihə üçün `cd … &&` əmri ilə.

<a id="mcp"></a>
### AI prompt, AI qaydaları və MCP

- **AI prompt** — Claude Code, Cursor və ya istənilən agent üçün bir tapşırıq: nəyi, harada, hansı versiyaya, niyə dəyişmək və nəyi hesabat vermək lazımdır.
- **AI qaydaları** — dəqiq versiyalarınla `AGENTS.md` / `CLAUDE.md` bloku: agent öyrəndiyi köhnə versiyalara görə kod yazmır.
- **MCP** — agent DepGate-dən özü soruşur, hər layihə üçün ayrıca:

```bash
# Linux / macOS — işləyən DepGate-ə HTTP ilə (Docker ilə də işləyir)
cd ~/projects/shop && claude mcp add --transport http depgate -s local \
  "http://127.0.0.1:7777/mcp?project=$PWD" --header "Authorization: Bearer $(depgate --print-token)"
```

```powershell
# Windows PowerShell
cd $HOME\projects\shop; claude mcp add --transport http depgate -s local `
  "http://127.0.0.1:7777/mcp?project=$PWD" --header "Authorization: Bearer $(depgate --print-token)"
```

Docker-də tokeni `docker exec depgate depgate --print-token` verir. Server işləmirsə: `claude mcp add depgate -s local -- depgate mcp --project "$PWD"` (stdio).

| Alət | Agent nə alır |
|---|---|
| `check_package` | **hər quraşdırmadan əvvəl** — `ad@versiya` təhlükəsizdirmi, yoxsa hansı versiya |
| `get_fix_plan` | layihə (və ya monorepo-nun bütün layihələri) üçün sıralı tam tapşırıq |
| `get_findings` · `get_code_changes` | hədəf, səbəb və əmrlə tapıntılar · bir paket üçün `fayl:sətir` yerləri |
| `get_docker_issues` | Docker, compose, image, nginx və Caddy tapıntıları |
| `get_ai_rules` · `project_status` · `scan_project` · `list_projects` | versiya qaydaları · xülasə · yenidən skan · bütün layihələr |

HTTP ilə MCP DepGate tokenini tələb edir, yad origin-ləri rədd edir və yalnız DepGate-in oxuya bildiyi qovluqlara baxır. Advisory mətnləri təlimat kimi yox, məlumat kimi verilir.

<a id="mənbələr"></a>
## Mənbələr

Açıq və pulsuzdur. **Mənbələr** düyməsi hər mənbəni və son skanda necə cavab verdiyini göstərir.

| Mənbə | Nə üçün |
|---|---|
| [OSV.dev](https://osv.dev) | zəifliklər (CVE/GHSA), zərərli paketlər, Caddy versiyaları |
| [npm advisories](https://docs.npmjs.com/cli/commands/npm-audit) | `npm audit`-in məlumatı, OSV-nin hələ almadığı qeydlər də |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [FIRST EPSS](https://www.first.org/epss/) | real hücumlarda istifadə · istismar ehtimalı (prioritet) |
| [deps.dev](https://deps.dev) · [npm registry](https://www.npmjs.com) | versiyalar və tarixlər · engines, peer, install skriptləri, provenance |
| [GitHub releases](https://docs.github.com/en/rest/releases/releases) | versiyan ilə hədəf arasındakı breaking changes |
| [nginx advisories](https://nginx.org/en/security_advisories.html) · [endoflife.date](https://endoflife.date) | nginx zəiflikləri · image-lərin dəstək müddəti |
| [Node.js releases](https://nodejs.org/en/about/previous-releases) · [Node.js Security WG](https://github.com/nodejs/security-wg) | runtime versiyaları, dəstəyin bitməsi, CVE-lər |

**Dəqiqlik:** həftəlik test zəifliyi bilinən layihədə DepGate-i `npm audit` ilə müqayisə edir — `npm audit`-in tapdığı hər advisory DepGate-in hesabatında da olmalıdır (yazılan vaxt 71-dən 71-i). Özün yoxla: `DEPGATE_LIVE=1 go test -run TestCompareNpmAudit -v ./internal/scan`.

<a id="əmr-sətri"></a>
## Əmr sətri

```bash
depgate                      # veb interfeys (əsas)
depgate ~/projects           # qovluğu əlavə et və interfeysi aç
depgate --json > report.json # bir dəfə skan et, JSON ver (sxem depgate/report@1)
depgate --view report.json   # saxlanmış hesabatı interfeysdə aç
depgate --ci --fail-on high  # yüksək/kritik zəiflik və ya zərərli paket olsa exit 1
depgate mcp --project DIR    # stdio ilə MCP server
depgate --reset-password     # parolu unut (Docker: docker exec depgate depgate --reset-password)
```

| Flag · env | Nə edir | Standart |
|---|---|---|
| `--port` | interfeysin portu (məşğuldursa, növbəti boş port) | 7777 |
| `--root` · `DEPGATE_ROOTS` | interfeysin gəzə biləcəyi qovluqlar | ev qovluğu |
| `--data` · `DEPGATE_DATA` | layihə siyahısı, hesabatlar, parol hash-ı | `~/.config/depgate` (macOS `~/Library/Application Support/depgate`, Windows `%AppData%\depgate`) |
| `--offline` | şəbəkəsiz, yalnız keş | söndürülüb |
| `--cooldown` | N gündən yeni versiyaları hədəf seçmə | 3 |
| `--depth` | layihə axtarışının dərinliyi | 3 |
| `--print-token` · `DEPGATE_TOKEN` | API / MCP tokeni | avtomatik |
| `DEPGATE_PASSWORD` | parolu əvvəlcədən təyin et (ən azı 8 simvol) | — |
| `DEPGATE_GITHUB_TOKEN` | reliz qeydləri üçün daha çox GitHub sorğusu (icazə lazım deyil) | — |
| `DEPGATE_LANG=az` | terminal mesajları Azərbaycan dilində | ingilis |

Bundan başqa: `--addr`, `--allow-host`, `--no-open`, `--no-auth`, `--push URL --token T` — `depgate --help`-ə bax.

<a id="təhlükəsizlik"></a>
## Təhlükəsizlik və məxfilik

- **Kompüterindən yalnız açıq paket məlumatı çıxır:** paket adları və versiyaları, CVE nömrələri, GitHub repo adları (reliz qeydləri üçün) və image adları (endoflife.date). Kodun, fayl yolların, layihə adların və `.env` faylların heç vaxt getmir.
- **Yalnız oxuyur:** DepGate layihələrinə heç nə yazmır; Docker-də ev qovluğun yalnız oxuma rejimində bağlanır və proses root olmadan işləyir.
- **Parolla qorunan interfeys**, yalnız `127.0.0.1`-də — başqa saytlar və kompüterindəki başqa proqramlar ondan istifadə edə bilməz. Parol PBKDF2-SHA256 hash kimi saxlanır (600 000 iterasiya); səhv cəhdlər yavaşladılır. Hər API sorğusu xüsusi başlıq tələb edir, `Host` başlığı yoxlanır və sərt Content Security Policy göndərilir.

## Hədlər

- Yalnız npm (npm, pnpm, yarn, bun lockfile-ları); PyPI, Go, Maven hələ yoxdur.
- Kod dəyişiklikləri mətn nümunələri ilə tapılır — hər yeri yoxla, sonra build və testləri işlət.
- Container image-lərin *içindəki* CVE-lər skan olunmur; bunun üçün Trivy və ya Docker Scout istifadə et. Dəstəyi bitmiş base image DepGate-in verdiyi ən güclü xəbərdarlıqdır.
- Lokal alətdir: işlədiyi kompüterin qovluqlarını oxuyur.

## İnkişaf

```bash
go test ./... && go vet ./...
go run . ./testdata/lockfiles/npm-v3
```

Yalnız standart kitabxana. [CONTRIBUTING.md](CONTRIBUTING.md)-ə bax; təhlükəsizlik bildirişləri: [SECURITY.md](SECURITY.md).

Faydalı olsa, ⭐ başqalarının onu tapmasına kömək edir.

## Lisenziya

[MIT](LICENSE)
