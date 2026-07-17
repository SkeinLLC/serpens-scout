# Security audit: 17 July 2026

## Result

The audit found no committed secret and no known vulnerable locked dependency. It did find
code and repository controls that needed correction before wider use. The working branch fixes
the production-code findings; Bandit, Ruff, Zizmor, pip-audit, Gitleaks, GitCred's Bandit pass,
22 tests, and a live bounded collection now pass.

No sample ran during this audit. Network activity stayed within the collector's named public
services.

## Scope

The review covered Python source, tests, detection rules, dependency files, both GitHub Actions
workflows, four commits of Git history, repository security settings, and one live collection.
It tested the scanner against hostile XML, oversized inputs, archive member floods, symlinks,
redirects, malformed JSON, and source-page drift.

## Findings and corrections

| Area | Finding | Correction |
|---|---|---|
| HTTP collection | The original client accepted any port on an allowed host, followed redirects without rechecking the destination, and read responses without a cap. A redirected GitHub request could carry its authorization header outside the intended trust boundary. | Require HTTPS on port 443, reject URL credentials, revalidate redirects, prohibit cross-host redirects, and cap each response at 10 MiB. |
| XML and archives | `xml.etree.ElementTree` accepted attacker-controlled config files, while archive reads trusted member metadata and could allocate more than intended. Directory scans followed filesystem symlinks. | Parse with `defusedxml`; cap archive bytes, members, nesting, expansion ratio, and each streamed member read; skip encrypted members and symlinks. |
| Report integrity | A vendor-page redesign could leave a short or wrong section that still produced an authoritative-looking delta. | Stop collection when the IOC marker is absent or extraction falls below source-specific domain and hash floors. Preserve source-content hashes in each receipt. |
| Runtime checks | Several internal type checks used `assert`, which disappears under `python -O`. | Replace production assertions with explicit exceptions. |
| API records | JSON array responses, invalid GitHub result records, and malformed base64 content could reach code that assumed valid objects. | Validate response shapes and base64 before parsing sampled configs. Collection records an error instead of aborting or accepting damaged data. |
| Build and CI | Dependencies floated, Actions used mutable tags, checkout credentials persisted, and CI lacked source, dependency, and workflow audits. | Add hash-locked build/runtime/CI files; pin Actions to commit SHAs; disable persisted checkout credentials; add timeouts, concurrency, Bandit, pip-audit, Ruff security rules, Zizmor, YARA validation, and tests. |
| Repository settings | Dependency alerts, automated security updates, private vulnerability reporting, CodeQL setup, branch cleanup, and Action-source restrictions were absent. | Enable those controls. Actions now accept GitHub-owned actions only. Existing secret scanning and push protection remain enabled. |

## Tool receipts

| Check | Version or revision | Final result |
|---|---|---|
| GitCred | upstream commit `d09516bb409656a98bbb005207801f7a58dcc51a` | 0 production Bandit findings; 37 low-severity `B101` records came from test assertions. Its Flake8 pass reported 106 style differences against a 79-character line limit; the project uses Ruff with a 100-character limit. |
| Bandit | 1.9.4 | 0 findings under `src/`. |
| Ruff | 0.15.22 | Pass with the `S` security rule family enabled. |
| pip-audit | 2.10.1 | No known vulnerability in the hash-locked CI or runtime sets. |
| Zizmor | 1.27.0 | No finding in the online auditor profile. |
| Gitleaks | 8.30.1, release checksum verified | No leak in four commits or the working tree. |
| Pytest | 9.1.1 | 22 passed. |
| Live collection | Serpens Scout hardened branch | Exit 0; 10 delta domains, 15 delta SHA-256 values, five GitHub samples, and no DNS or GitHub collection error. |

The pre-fix Zizmor run reported 11 workflow issues, including five high-severity mutable-action
references. The pre-fix production Bandit run reported 13 records: two medium and 11 low. Those
production findings are now zero.

## GitCred cautions

GitCred's current command-line entry point imports `simple-term-menu`, which imports Unix-only
`termios`; the CLI therefore can't start on native Windows. This audit called GitCred's own
`process_local_repo()` function from an isolated checkout and removed `GITHUB_TOKEN` first.

There is a second trap: GitCred catches missing `flake8` or `bandit` executables and can return a
zero count. The final run placed its isolated virtual-environment `Scripts` directory on `PATH`
before invoking the analyzer. GitCred also writes commit-author metadata to CSV, so its output
stayed in a temporary directory and wasn't added to this repository.

GitCred doesn't replace a credential scanner. Gitleaks supplied the history and working-tree
secret check in this audit.

## Remaining work

The pull request must pass hosted Python 3.12 CI before merge. The lock files were generated and
tested locally with Python 3.12.13. After merge, require immutable Action SHAs in repository
settings and turn on the new protected-branch check. GitHub currently leaves non-provider secret
patterns and secret-validity checks disabled for this repository.

Later research should add parser fuzzing and run the config detector across an approved
known-good .NET corpus. Those tasks affect assurance and false-positive measurement; they don't
leave a known production-code hole in this branch.
