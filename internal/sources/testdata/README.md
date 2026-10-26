Fixtures for the `sources` tests: what each public data source answers.

Copied from the real service (October 2026): `osv-GHSA-f82v-jwr5-mffw.json`
(GitHub Advisory Database, OSV format), `npm-bulk.json` (npm bulk advisories
for express 4.19.2, next 14.2.3, flatmap-stream 0.1.1), `npm-*.json` (npm
registry), `node-schedule.json` and `node-core-index.json` (last 3 entries) from
the nodejs GitHub repositories.

Written by hand in the documented format, with real values: `osv-querybatch.json`,
`osv-query.json`, `depsdev-left-pad.json`, `eol-v1-nodejs.json`,
`eol-v0-postgresql.json`, `node-dist-index.json`, `epss.json`, `kev.json`.

If a source changes its format, refresh the file and the test shows what broke.
