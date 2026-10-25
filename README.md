# DepGate

[![ci](https://github.com/Ali7Zeynalli/depgate/actions/workflows/ci.yml/badge.svg)](https://github.com/Ali7Zeynalli/depgate/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Ali7Zeynalli/depgate.svg)](https://pkg.go.dev/github.com/Ali7Zeynalli/depgate)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Local npm dependency security and update advisor for Node.js projects.** For every package DepGate answers two questions:

1. **Do I need to update?** Vulnerability, malicious package, end-of-life Node.js, deprecated package, or just a newer version.
2. **Will the update affect my code?** Is bumping the version enough, or does code have to change?

One static Go binary, zero third-party dependencies. It never uploads your code and never changes anything: it shows what to do and gives you the exact command.

![DepGate report](docs/screenshot.png)

[Azərbaycan dilində](README.az.md)

## Install

```bash
go install github.com/Ali7Zeynalli/depgate@latest
```

Or download a prebuilt binary (Linux, macOS, Windows; amd64, arm64) from [Releases](https://github.com/Ali7Zeynalli/depgate/releases). Every release ships SHA-256 checksums and build provenance attestations.

## Usage

```bash
cd ~/projects/my-app
depgate                      # scan and open the report at http://127.0.0.1:7777
depgate ~/projects           # every project below (each folder with a package.json)
depgate --json > report.json # machine-readable (schema depgate/report@1)
depgate --view report.json   # open a saved report in the UI
depgate --ci --fail-on high  # exit 1 on high/critical vulnerabilities or malware
depgate --offline            # no network, cache only
```

| Flag | What it does | Default |
|---|---|---|
| `--port` | UI port (next free port if busy) | 7777 |
| `--no-open` | Don't open the browser | opens |
| `--offline` | Never touch the network | off |
| `--depth` | Project discovery depth | 3 |
| `--cooldown` | Skip versions younger than N days as targets | 3 |
| `--json` | Write the JSON report to stdout | off |
| `--view` | Serve a saved JSON report | — |
| `--ci`, `--fail-on` | CI mode and threshold | high |
| `--push`, `--token` | POST the report to a URL (Bearer token) | — |

## What it checks

- **Lockfiles:** `package-lock.json` (v1–v3), `pnpm-lock.yaml` (v5–v9), `yarn.lock` (v1 and Berry), `bun.lock`, workspaces included. Transitive packages are checked. Without a lockfile it reads `node_modules`, and otherwise falls back to a clearly marked approximate mode.
- **Vulnerabilities and malware:** [OSV.dev](https://osv.dev), including GitHub Security Advisories and OpenSSF Malicious Packages.
- **Priority (0–100):** severity plus [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [EPSS](https://www.first.org/epss/).
- **Safest minimum target:** the lowest clean version in the same major line, skipping versions younger than the cooldown.
- **Transitive fixes:** relock when the parent's range already allows the fix, otherwise upgrade the direct parent, otherwise an `overrides` / `resolutions` block.
- **Code impact:** semver distance, the target's `engines.node` and `peerDependencies` against your project.
- **Supply-chain signals on the target version:** new install scripts, lost npm provenance, a different publisher, a changed repository URL.
- **Node.js runtime:** Dockerfile, `.nvmrc`, `.node-version`, `.tool-versions`, `engines`, GitHub Actions; security releases and end-of-life dates.
- **Project hygiene:** lockfile committed, install scripts disabled, release cooldown configured, consistent Node.js version.

## Privacy

Only package names and versions (OSV, deps.dev, npm registry) and CVE IDs (EPSS) leave your machine. Source code, file paths, project names and `.env` files never do. Responses are cached in `~/.cache/depgate/`.

The UI binds to `127.0.0.1` only, uses a random per-run token, checks the `Host` header and sends a strict Content Security Policy.

## Development

```bash
go test ./...
go vet ./...
go run . ./testdata/lockfiles/npm-v3
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
