# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems in DepGate itself. Use GitHub's private reporting instead: **Security → Report a vulnerability** on this repository.

Include the DepGate version (`depgate --version`), your OS, and steps to reproduce. You will get a reply within 7 days.

## Supported versions

Only the latest release receives fixes.

## Scope

In scope: the local web UI (token, Host check, CSP), command execution, handling of untrusted data from lockfiles and public APIs, the release pipeline.

Out of scope: vulnerabilities in the npm packages DepGate reports on — report those to the package maintainers or the [GitHub Advisory Database](https://github.com/advisories).
