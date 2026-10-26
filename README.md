<p align="center">
  <img src="docs/social-preview.png" alt="DepGate — do I need to update, and will it break my code?" width="820">
</p>

<h1 align="center">DepGate</h1>

<p align="center">
  <b>Your npm dependencies in one screen: what to update now, whether it breaks your code — and exactly where.</b><br>
  Linux · macOS · Windows · Docker or a single binary · zero dependencies · English &amp; Azerbaijani
</p>

<p align="center">
  <a href="https://github.com/Ali7Zeynalli/depgate/actions/workflows/ci.yml"><img src="https://github.com/Ali7Zeynalli/depgate/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="https://github.com/Ali7Zeynalli/depgate/releases"><img src="https://img.shields.io/github/v/release/Ali7Zeynalli/depgate?include_prereleases&amp;sort=semver" alt="release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT"></a>
  <img src="https://img.shields.io/badge/third--party%20deps-0-brightgreen" alt="zero dependencies">
  · <a href="README.az.md">Azərbaycan dilində</a>
</p>

---

`npm audit` tells you *something* is vulnerable. DepGate tells you **what to do** — for every package:

- ① **Do I need to update?** now · soon · plan · optional · not needed — malware and exploited CVEs first
- ② **Will it affect my code?** no · maybe · yes — and if yes, **every place to change** (`file:line`) plus the codemod
- 🎯 **To which version?** the *safest minimum*, not "latest"
- 🤖 **Can my AI agent do it?** a ready prompt, version rules and an MCP server

It also checks Dockerfiles, docker-compose, nginx, Caddy and your Node.js runtime. It runs on your computer and **never changes your files**.

![DepGate](docs/screenshot.png)

## Install

**Docker** — Linux, macOS, Windows; nothing to configure:

```bash
git clone https://github.com/Ali7Zeynalli/depgate.git && cd depgate
docker compose up -d
```

**Single binary** — from [Releases](https://github.com/Ali7Zeynalli/depgate/releases), run `./depgate` (Windows: `depgate.exe`). **Go** — `go install github.com/Ali7Zeynalli/depgate@latest`.

Then open `http://127.0.0.1:7777`, choose a password and **+ Add project** (a project or a whole folder).

<details>
<summary>Docker on Windows, updates, binary notes</summary>

| Docker started from | DepGate sees |
|---|---|
| Linux / macOS terminal | your home at its real path |
| Windows PowerShell or cmd | `C:\Users\you` as `/host` |
| Windows Git Bash | `C:\Users\you` as `/c/Users/you` |
| Windows WSL | your WSL home — projects on the Windows side? start it from PowerShell |

- Your home is mounted read-only; the container runs as its owner and drops root. Data lives in the `depgate-data` volume.
- Update: `git pull && docker compose up -d` (it always fetches the newest image; the version is shown at the top of the page).
- macOS binary, first run: `xattr -d com.apple.quarantine ./depgate`. Windows SmartScreen: *More info → Run anyway*.
- Verify downloads: `checksums.txt` and `gh attestation verify <file> -R Ali7Zeynalli/depgate`.
</details>

## What you get

| Section | What it shows |
|---|---|
| **Overview** | the few things to do first, in order |
| **Packages** | one row per package: what it is, what was found, the weakness explained in plain words (CWE), the safest version and the command; malware, removed versions, packages that must update together; **accept a risk** with a reason until a date (it comes back by itself) |
| **Code changes** | `file:line` places for Next.js, React, Express, NestJS, Prisma, Zod, Tailwind, ESLint, TanStack Query, React Router; codemods; breaking changes from release notes |
| **Docker** | 25 security rules, Compose Specification errors, end-of-life and outdated images |
| **Web server** | nginx / Caddy: known vulnerabilities of your version, TLS, headers, path traversal, exposed admin API |
| **Node.js & setup** | runtime security releases and end of life; lockfile, install scripts, release cooldown |
| **AI & MCP** | a ready prompt, `AGENTS.md` version rules, the MCP connection command, which agents are connected |
| **History** | projects are scanned again automatically (every 12 h by default, changeable at the top); every scan compared with the one before: what is new, what is gone, whether the lockfile changed or a new advisory appeared; who ran it (UI, CLI or an AI agent) and what each agent checked over MCP |

Folders and monorepos get one merged page; a finding in several projects is shown once.

![Code changes](docs/code-changes.png)

## AI agents (MCP)

The agent asks DepGate itself — and checks every package **before** it installs it (`check_package`). The **AI & MCP → Connection command** button shows the setup for your agent — Claude Code, Cursor, VS Code, Windsurf, Codex CLI, Gemini CLI or any stdio client — with path and token filled in:

```bash
cd ~/projects/shop && claude mcp add --transport http depgate -s local \
  "http://127.0.0.1:7777/mcp?project=$PWD" --header "Authorization: Bearer $(depgate --print-token)"
```

<details>
<summary>Tools, Windows, stdio</summary>

| Tool | What the agent gets |
|---|---|
| `check_package` | is `name@version` safe to install, and which version to use instead |
| `get_fix_plan` | the whole ordered task (also for every project of a monorepo) |
| `get_findings` · `get_code_changes` | findings with target and command · `file:line` places for one package |
| `get_docker_issues` | Docker, compose, image, nginx and Caddy findings |
| `get_ai_rules` · `project_status` · `scan_project` · `list_projects` | version rules · summary · rescan · all projects |
| `get_history` | what changed between recent scans — to confirm a fix worked |

- Windows PowerShell: `cd $HOME\projects\shop; claude mcp add --transport http depgate -s local "http://127.0.0.1:7777/mcp?project=$PWD" --header "Authorization: Bearer $(depgate --print-token)"`
- Token in Docker: `docker exec depgate depgate --print-token`.
- Without a running server (stdio): `claude mcp add depgate -s local -- depgate mcp --project "$PWD"`.
- `/mcp` needs the token, rejects foreign origins and reads only allowed folders; advisory text is passed as data, not instructions.
</details>

## Data sources

Public and free: [OSV.dev](https://osv.dev), [npm advisories](https://docs.npmjs.com/cli/commands/npm-audit), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS](https://www.first.org/epss/), [deps.dev](https://deps.dev), [npm registry](https://www.npmjs.com), [GitHub releases](https://docs.github.com/en/rest/releases/releases), [nginx advisories](https://nginx.org/en/security_advisories.html), [endoflife.date](https://endoflife.date), [Node.js releases](https://nodejs.org/en/about/previous-releases). The **Sources** button shows how each one answered in the last scan.

A weekly test checks that every advisory `npm audit` reports is also in DepGate's report (71 of 71 at the time of writing).

## Command line

```bash
depgate --ci --fail-on high   # exit 1 on high/critical vulnerabilities or malware
depgate --json > report.json  # scan once, print JSON
depgate --view report.json    # open a saved report
depgate --reset-password      # Docker: docker exec depgate depgate --reset-password
```

<details>
<summary>Flags and environment variables</summary>

| Flag · env | What it does | Default |
|---|---|---|
| `--port` | UI port | 7777 |
| `--root` · `DEPGATE_ROOTS` | folders the UI may browse | your home |
| `--data` · `DEPGATE_DATA` | project list, reports, scan history, password hash | `~/.config/depgate` · macOS `~/Library/Application Support/depgate` · Windows `%AppData%\depgate` |
| `--offline` | no network, cache only | off |
| `--cooldown` | skip target versions younger than N days | 3 |
| `--rescan` · `DEPGATE_RESCAN_HOURS` | scan projects again when the last scan is older than N hours (0 = off; also in the UI) | 12 |
| `DEPGATE_NO_UPDATE_CHECK=1` | don't check GitHub once a day for a newer DepGate | — |
| `--print-token` · `DEPGATE_TOKEN` | API / MCP token | generated |
| `DEPGATE_PASSWORD` | set the password up front | — |
| `DEPGATE_GITHUB_TOKEN` | more GitHub requests for release notes | — |
| `DEPGATE_LANG=az` | terminal messages in Azerbaijani | English |

More: `depgate --help`.
</details>

## Security and privacy

- Only package names, versions, CVE ids and image names leave your computer — never code, paths or `.env` files. Once a day DepGate asks GitHub for the newest release number and shows a notice if there is one.
- Read-only: nothing is written into your projects; in Docker your home is mounted read-only and DepGate runs without root.
- The UI listens on `127.0.0.1` only and is password-protected (PBKDF2-SHA256); API calls need a custom header, the `Host` header is checked, a strict CSP is sent.

**Limits:** npm only (npm, pnpm, yarn, bun) · code places are found by text patterns, so review them · no CVE scan inside container images (use Trivy) · it reads the folders of the computer it runs on.

## Development

`go test ./... && go vet ./...` — standard library only. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

If DepGate saves you a bad afternoon, a ⭐ helps others find it. — [MIT](LICENSE)
