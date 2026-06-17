# vuln-api fixtures

Committed JSON bodies matching the authoritative server serialization
(vuln-api repo: `cve_worker/src/worker.js`). Deserialization tests live in
`src/vuln_api/mod.rs`; full-HTTP-path contract tests in
`tests/vuln_api_contract.rs`.

| Fixture | Verdict |
|---|---|
| `check_clean.json` | known package, no advisories |
| `check_vulnerable.json` | one advisory with `fixed_version` remediation |
| `check_malware.json` | `MAL-*` advisory, no version range, no fix |
| `check_unknown.json` | unknown package — `/check` answers 200 clean, not 404 |

## Deterministic staging targets

The staging worker (`https://cve-worker-staging.corgea.workers.dev`) serves
stable verdicts for these targets; the `#[ignore]`d tests in
`tests/vuln_api_contract.rs` assert them:

| Target | Ecosystem | Verdict |
|---|---|---|
| `axios@0.21.0` | npm | vulnerable (CVE-2021-3749, fixed in 0.21.2) |
| `minimist@0.0.8` | npm | vulnerable |
| `node-fetch@2.6.0` | npm | vulnerable |
| `mezzanine==6.0.0` | pypi | vulnerable (CVE-2025-29573) |

Run the staging contract tests with:

```sh
cargo test --test vuln_api_contract -- --ignored
```
