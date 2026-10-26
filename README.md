<p align="center">
  <img src="docs/social-preview.png" alt="DepGate — do I need to update, and will it break my code?" width="820">
</p>

<h1 align="center">DepGate</h1>

<p align="center">
  <b>Your npm dependencies in one screen: what to update now, what can wait, whether it breaks your code — and exactly where.</b><br>
  Linux · macOS · Windows · Docker or a single binary · zero dependencies · English &amp; Azerbaijani
</p>

<p align="center">
  <a href="https://github.com/Ali7Zeynalli/depgate/actions/workflows/ci.yml"><img src="https://github.com/Ali7Zeynalli/depgate/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="https://github.com/Ali7Zeynalli/depgate/releases"><img src="https://img.shields.io/github/v/release/Ali7Zeynalli/depgate?include_prereleases&amp;sort=semver" alt="release"></a>
  <a href="https://goreportcard.com/report/github.com/Ali7Zeynalli/depgate"><img src="https://goreportcard.com/badge/github.com/Ali7Zeynalli/depgate" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT"></a>
  <img src="https://img.shields.io/badge/third--party%20deps-0-brightgreen" alt="zero dependencies">
</p>

<p align="center">
  <a href="#install">Install</a> · <a href="#what-it-does">What it does</a> · <a href="#mcp">AI agents (MCP)</a> · <a href="#data-sources">Data sources</a> · <a href="#command-line">Command line</a> · <a href="#security-and-privacy">Security</a> · <a href="README.az.md">Azərbaycan dilində</a>
</p>

---

`npm audit` tells you *something* is vulnerable. DepGate tells you **what to do about it** — for every package, in every project:

| Question | DepGate's answer |
|---|---|
| ① **Do I need to update?** | **now** (malware, critical/high CVEs, weighted by CISA KEV and EPSS) · soon · plan · optional · not needed |
| ② **Will it affect my code?** | **no** (patch/minor, one command) · **maybe** (peer/engines conflict) · **yes** (breaking release) |
| 📍 **Where in my code?** | every place to change — `file:line`, why, what to write instead — plus the official codemod |
| 🎯 **To which version?** | the *safest minimum*: the lowest clean version in your current major, not "latest" |
| 🤖 **Can my AI agent do it?** | a ready prompt, version rules for `AGENTS.md`, and an MCP server the agent asks itself |

It also checks Dockerfiles and compose files, nginx and Caddy, and your Node.js runtime. Everything runs on your computer, and DepGate **never changes your files** — it shows and suggests.

![Overview](docs/overview.png)

<a id="install"></a>
## Install

Three ways, the same result: a web UI at `http://127.0.0.1:7777`.

### Docker (Linux, macOS, Windows)

```bash
git clone https://github.com/Ali7Zeynalli/depgate.git
cd depgate
docker compose up -d
```

Nothing to configure. Your home folder is mounted **read-only**; the container works out who owns it, runs as that user and drops every privilege (SELinux included). What DepGate sees depends on where you start it:

| Started from | DepGate sees |
|---|---|
| Linux / macOS terminal | your home at its real path (`/home/you`, `/Users/you`) |
| Windows PowerShell or cmd | `C:\Users\you`, shown as `/host` |
| Windows Git Bash | `C:\Users\you`, shown as `/c/Users/you` |
| Windows WSL terminal | your WSL home — projects on the Windows side? start it from PowerShell |

Update with `git pull && docker compose up -d --build`. Projects, reports and the password live in the `depgate-data` volume.

### Single binary (no Docker)

Download your archive from [Releases](https://github.com/Ali7Zeynalli/depgate/releases) — Linux, macOS (Intel, Apple Silicon) or Windows, amd64 or arm64 — unpack and run `./depgate` (Windows: `depgate.exe`). Paths are your real ones, which AI agents like best.

- macOS, first run: `xattr -d com.apple.quarantine ./depgate` (the binary is not notarized).
- Windows SmartScreen: *More info → Run anyway*.
- Verify: `checksums.txt` (SHA-256) and `gh attestation verify <file> -R Ali7Zeynalli/depgate`.

### Go

```bash
go install github.com/Ali7Zeynalli/depgate@latest
depgate
```

### First steps

1. Open `http://127.0.0.1:7777` and choose a password.
2. **+ Add project** → pick a project or a whole folder (monorepos included). The scan starts.
3. Read **Overview** first: it lists the few things to do, in order.
4. Optional: connect your AI agent — **AI & MCP → Connection command** gives you the command with path and token filled in.

<a id="what-it-does"></a>
## What it does

Each project and folder is split into sections: **Overview** · **Packages** · **Code changes** · **Docker** · **Web server** (when present) · **Node.js & setup** · **AI & MCP**.

### Packages

![Packages](docs/screenshot.png)

- One compact row per package; open it for the full answer: what the package is, how it got into the project, what was found and the fix.
- **Vulnerabilities and malware** from OSV.dev and the npm advisory database (the data behind `npm audit`), merged; prerelease versions are matched too.
- **Every advisory explained:** its weakness type (CWE) in plain words — what it is and what it lets an attacker do — for about 70 common types, in English and Azerbaijani.
- **Removed versions:** a locked version npm no longer serves, or a package replaced by a `0.0.1-security` placeholder.
- **Transitive packages:** relock if the parent already allows the fix, else upgrade the parent, else a ready `overrides` block.
- **Update together:** `react` + `react-dom`, `next` + `eslint-config-next`, `@nestjs/*`, `@angular/*`, Vue, Storybook, Nx, Prisma… in one card, one command.
- **Is the new version safe?** Versions younger than 3 days are skipped; new install scripts, lost provenance and a changed publisher or repository are flagged.

### Code changes

When an update crosses a breaking release, DepGate reads your source files (locally) and lists each place to change: `file:line`, the line, why, what to write instead, and the official codemod. Exact rules for **Next.js 15/16, React 18/19, TanStack Query 5, ESLint 9, Tailwind 4, Express 5, NestJS 11, Zod 4, Prisma 7, React Router 6/7**; Angular, Nx, Storybook and Expo get their upgrade tools; any other major shows the *breaking changes* from its GitHub releases. Matching is text based — review each place, then build and test.

![Code changes](docs/code-changes.png)

### Docker and web server

- **Docker** — 25 security rules (root user, secrets in `ENV`/`environment`, `latest` tags, `npm install` instead of `npm ci`, a missing `.dockerignore`, `docker.sock`, databases open on all interfaces…), Compose Specification errors (misspelled keys, undeclared volumes/networks, broken `depends_on`), and end-of-life or outdated images via endoflife.date.
- **nginx and Caddy** — known vulnerabilities of the version you run (nginx's own advisories, OSV for Caddy) and config checks: old TLS, weak ciphers, missing HSTS and security headers, `alias` path traversal, `autoindex`/`browse`, CRLF via `$uri`, SSRF via `proxy_pass`, an exposed Caddy admin API. Rules follow gixy, Mozilla SSL, OWASP Secure Headers and the official docs.

![Web server](docs/webserver.png)

### Node.js and project setup

The Node.js version from Dockerfile, `.nvmrc`, `.node-version`, `engines` and CI: security releases, end of life and the CVEs that affect your exact version. Plus hygiene: lockfile present, install scripts disabled, release cooldown, one Node.js version everywhere.

### Folders and monorepos

Add a folder and its projects appear nested in the sidebar. The folder page merges everything: a finding that appears in several projects is shown once, with a `cd … &&` command for each.

<a id="mcp"></a>
### AI prompt, AI rules and MCP

- **AI prompt** — one task for Claude Code, Cursor or any agent: what to change, where, to which version, why, and what to report back.
- **AI rules** — an `AGENTS.md` / `CLAUDE.md` block with your exact versions, so the agent stops writing code for versions it was trained on.
- **MCP** — the agent asks DepGate itself, per project:

```bash
# Linux / macOS — over HTTP to the running DepGate (works with Docker too)
cd ~/projects/shop && claude mcp add --transport http depgate -s local \
  "http://127.0.0.1:7777/mcp?project=$PWD" --header "Authorization: Bearer $(depgate --print-token)"
```

```powershell
# Windows PowerShell
cd $HOME\projects\shop; claude mcp add --transport http depgate -s local `
  "http://127.0.0.1:7777/mcp?project=$PWD" --header "Authorization: Bearer $(depgate --print-token)"
```

In Docker the token comes from `docker exec depgate depgate --print-token`. Without a running server: `claude mcp add depgate -s local -- depgate mcp --project "$PWD"` (stdio).

| Tool | What the agent gets |
|---|---|
| `check_package` | **before every install** — is `name@version` safe, and which version to use instead |
| `get_fix_plan` | the whole ordered task for the project (or every project of a monorepo) |
| `get_findings` · `get_code_changes` | findings with target, reason and command · the `file:line` places for one package |
| `get_docker_issues` | Docker, compose, image, nginx and Caddy findings |
| `get_ai_rules` · `project_status` · `scan_project` · `list_projects` | version rules · summary · rescan · all projects |

MCP over HTTP needs the DepGate token, rejects foreign origins and only reads folders DepGate may read. Text from advisories is quoted as data, never as instructions.

<a id="data-sources"></a>
## Data sources

Public and free. The **Sources** button shows each source and how it answered in the last scan.

| Source | Used for |
|---|---|
| [OSV.dev](https://osv.dev) | vulnerabilities (CVE/GHSA), malicious packages, Caddy versions |
| [npm advisories](https://docs.npmjs.com/cli/commands/npm-audit) | the `npm audit` data, including records OSV has not imported yet |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [FIRST EPSS](https://www.first.org/epss/) | exploited in the wild · probability of exploitation (priority) |
| [deps.dev](https://deps.dev) · [npm registry](https://www.npmjs.com) | versions and dates · engines, peers, install scripts, provenance |
| [GitHub releases](https://docs.github.com/en/rest/releases/releases) | breaking changes between your version and the target |
| [nginx advisories](https://nginx.org/en/security_advisories.html) · [endoflife.date](https://endoflife.date) | nginx vulnerabilities · image support dates |
| [Node.js releases](https://nodejs.org/en/about/previous-releases) · [Node.js Security WG](https://github.com/nodejs/security-wg) | runtime versions, end of life, CVEs |

**Accuracy:** a weekly test compares DepGate with `npm audit` on a project with known-vulnerable dependencies — every advisory `npm audit` reports must also be in DepGate's report (71 of 71 at the time of writing). Run it yourself: `DEPGATE_LIVE=1 go test -run TestCompareNpmAudit -v ./internal/scan`.

<a id="command-line"></a>
## Command line

```bash
depgate                      # web UI (default)
depgate ~/projects           # add a folder and open the UI
depgate --json > report.json # scan once, print JSON (schema depgate/report@1)
depgate --view report.json   # open a saved report in the UI
depgate --ci --fail-on high  # exit 1 on high/critical vulnerabilities or malware
depgate mcp --project DIR    # MCP server over stdio
depgate --reset-password     # forget the password (Docker: docker exec depgate depgate --reset-password)
```

| Flag · env | What it does | Default |
|---|---|---|
| `--port` | UI port (next free one if busy) | 7777 |
| `--root` · `DEPGATE_ROOTS` | folders the UI may browse | your home |
| `--data` · `DEPGATE_DATA` | project list, reports, password hash | `~/.config/depgate` (macOS `~/Library/Application Support/depgate`, Windows `%AppData%\depgate`) |
| `--offline` | no network, cache only | off |
| `--cooldown` | skip target versions younger than N days | 3 |
| `--depth` | project discovery depth | 3 |
| `--print-token` · `DEPGATE_TOKEN` | API / MCP token | generated |
| `DEPGATE_PASSWORD` | set the password up front (min. 8 characters) | — |
| `DEPGATE_GITHUB_TOKEN` | more GitHub requests for release notes (no scopes needed) | — |
| `DEPGATE_LANG=az` | terminal messages in Azerbaijani | English |

Also: `--addr`, `--allow-host`, `--no-open`, `--no-auth`, `--push URL --token T` — see `depgate --help`.

<a id="security-and-privacy"></a>
## Security and privacy

- **Only public package data leaves your computer:** package names and versions, CVE ids, GitHub repository names (release notes) and image names (endoflife.date). Never your code, file paths, project names or `.env` files.
- **Read-only:** DepGate never writes into your projects; in Docker your home is mounted read-only and the process runs without root.
- **Password-protected UI** on `127.0.0.1` only — other websites and programs on your computer cannot use it. The password is stored as a PBKDF2-SHA256 hash (600 000 iterations); wrong attempts are slowed down. Every API call needs a custom header, the `Host` header is checked and a strict Content Security Policy is sent.

## Limits

- npm only (npm, pnpm, yarn, bun lockfiles); no PyPI, Go or Maven yet.
- Code changes are found by text patterns — check each place, then build and test.
- No CVE scan *inside* container images; use Trivy or Docker Scout for that. An end-of-life base image is the strongest warning DepGate gives.
- A local tool: it reads the folders of the computer it runs on.

## Development

```bash
go test ./... && go vet ./...
go run . ./testdata/lockfiles/npm-v3
```

Standard library only. See [CONTRIBUTING.md](CONTRIBUTING.md); security reports: [SECURITY.md](SECURITY.md).

If DepGate saves you a bad afternoon, a ⭐ helps others find it.

## License

[MIT](LICENSE)
