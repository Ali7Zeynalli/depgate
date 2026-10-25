# DepGate

[English](README.md)

Node.js layihələri üçün lokal paket təhlükəsizliyi və yeniləmə aləti. Hər paket üçün iki suala cavab verir:

1. **Yeniləmək lazımdır?** Boşluq, zərərli paket, köhnəlmiş Node xətti, deprecated paket və ya sadəcə yeni versiya.
2. **Koda təsir edir?** Versiyanı qaldırmaq kifayətdir, yoxsa kodda nəyisə dəyişmək lazımdır.

Bir binary-dir, Go ilə yazılıb və xarici asılılığı yoxdur. Layihənin kodunu heç yerə göndərmir və heç nəyi dəyişmir: yalnız göstərir və hazır əmr verir.

## Quraşdırma

```bash
go install github.com/Ali7Zeynalli/depgate@latest
# və ya Releases-dən hazır binary (linux, macOS, Windows; amd64, arm64)
```

## İstifadə

```bash
cd ~/projects/kraton-web
depgate                      # skan edir, brauzerdə http://127.0.0.1:7777 açır
depgate ~/projects           # alt qovluqlardakı bütün layihələr (package.json olan hər qovluq)
depgate --json > report.json # interfeyssiz, maşın üçün (schema depgate/report@1)
depgate --ci --fail-on high  # CI: high/critical və ya zərərli paket varsa çıxış kodu 1
depgate --offline            # şəbəkəsiz, yalnız keşdən
```

| Bayraq | Nə edir | Standart |
|---|---|---|
| `--port` | Veb interfeysin portu (məşğuldursa növbəti) | 7777 |
| `--no-open` | Brauzeri avtomatik açmır | açır |
| `--offline` | Şəbəkəyə çıxmır | yox |
| `--depth` | Layihə axtarışının dərinliyi | 3 |
| `--cooldown` | Bundan cavan versiyaları (gün) hədəf seçmir | 3 |
| `--json` | JSON hesabat stdout-a | yox |
| `--ci`, `--fail-on` | CI rejimi və hədd | high |
| `--push`, `--token` | Hesabatı URL-ə POST edir (Bearer token) | — |

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

## Kənara nə gedir

Yalnız paket adları və versiyalar (OSV, deps.dev, npm registry), CVE nömrələri (EPSS). Kod, fayl yolları, layihə adları, `.env` heç vaxt getmir. Cavablar `~/.cache/depgate/` qovluğunda keşlənir.

Veb interfeys yalnız `127.0.0.1`-də işləyir; hər işə salmada təsadüfi token yaranır, `Host` başlığı yoxlanır, CSP aktivdir.

## İnkişaf

```bash
go test ./...
go vet ./...
go run . ./testdata/lockfiles/npm-v3
```

## Lisenziya

MIT
