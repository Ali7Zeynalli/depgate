# Contributing

Thanks for helping. A few rules keep DepGate small and trustworthy:

- **Standard library only.** No third-party Go modules. A security tool must not be a supply-chain risk itself.
- **Read-only.** DepGate never modifies a project, installs packages or runs package scripts.
- **No code leaves the machine.** Only package names, versions and CVE IDs may be sent to public APIs.
- **Tests without network.** Use `internal/sources/sourcestest` and fixtures under `testdata/`.

## Workflow

```bash
gofmt -l .        # must print nothing
go vet ./...
go test -race ./...
```

Open a pull request against `main` with a short description of the change and how you tested it. New lockfile formats or decision rules need a fixture and a test.
