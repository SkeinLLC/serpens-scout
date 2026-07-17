# Serpens Scout

Serpens Scout turns the public Unit 42 Screening Serpens report into a repeatable
research pipeline. It does four jobs:

1. Fetches the Unit 42 report and a primary-source Check Point report covering the
   same 2026 activity.
2. Normalizes domains and SHA-256 hashes, then reports indicators present in the
   second source but absent from Unit 42.
3. Uses passive DNS and optional GitHub Code Search to enrich the result and test
   the false-positive assumptions behind AppDomainManager config detection.
4. Scans local files and archives for the value-aware `.config` combination, then
   exports JSON, defanged Markdown, and STIX 2.1.

The tool never connects to suspected command-and-control systems, submits URLs for
scanning, downloads malware, or executes samples. Network access is restricted in
code to known research and vendor services.

## Why this exists

The first Project Meridian prototype emitted queries but intentionally made no
network calls. It could not discover anything. Serpens Scout performs bounded,
passive collection and preserves the difference between:

- an indicator confirmed by Unit 42;
- an indicator added by another primary source;
- a DNS observation about shared hosting; and
- a candidate requiring analyst review.

"New" in the generated report means **new relative to the Unit 42 IOC list**. It
does not mean newly registered, previously unknown, or independently attributed by
Skein LLC.

## Install

```powershell
git clone https://github.com/SkeinLLC/serpens-scout.git
Set-Location .\serpens-scout
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Run the research pipeline

```powershell
serpens-scout hunt --out research\latest
```

To add a sampled GitHub config baseline, expose a token with public-code read
access. The token is never written to output.

```powershell
$env:GITHUB_TOKEN = gh auth token
serpens-scout hunt --out research\latest --github-limit 40
Remove-Item Env:\GITHUB_TOKEN
```

Outputs:

- `findings.md`: human report with network indicators defanged.
- `findings.json`: machine-readable evidence with operational values.
- `serpens.stix.json`: STIX 2.1 indicators for TIP import.
- `github-baseline.json`: sampled public config results when a token is available.

## Scan a directory or archive

```powershell
serpens-scout scan C:\path\to\software --out scan.json
serpens-scout scan C:\path\to\delivery.zip --out archive-scan.json
```

The archive reader caps nesting, member count, extracted size, and compression ratio. It does
not follow symbolic links or write archive members to disk. XML parsing blocks DTDs and entity
expansion.

## Security controls

- Network requests permit HTTPS on port 443 to four named services. Cross-host redirects fail.
- Response, file, archive, nesting, and member-count limits bound untrusted input processing.
- CI dependencies use hash-locked requirement files; GitHub Actions use immutable commit SHAs.
- Bandit, pip-audit, Ruff security rules, Zizmor, YARA fixtures, and unit tests run on every push
  and pull request.
- GitHub secret scanning, push protection, dependency alerts, private reporting, and CodeQL
  setup are enabled in the repository settings. Actions are limited to GitHub-owned sources.

The dated [security audit](docs/security-audit-2026-07-17.md) records the threat boundaries,
tool receipts, corrections, and remaining repository-control work.

## Detection model

AppDomainManager is legitimate .NET functionality. Matching the tag name alone is
noisy. Serpens Scout evaluates the values that matter:

- a custom `appDomainManagerType` and assembly;
- local probing through `privatePath`;
- `etwEnable enabled="false"`;
- `bypassTrustedAppStrongNames enabled="true"`;
- `publisherPolicy apply="no"`; and
- `requiredRuntime safemode="true"`.

The YARA rule in `rules/yara/` follows the same value-aware logic. Public GitHub
searches show legitimate configs containing several tag names with safe values,
which is why the original presence-only rule was not suitable for deployment.

## Repository map

```text
src/serpens_scout/       collector, scanner, STIX, and CLI
rules/                   YARA, Sigma, and Defender XDR KQL
tests/                   offline tests and safe fixtures
docs/methodology.md      evidence model and research limits
docs/skein-tip.md        STIX import notes
research/                dated, reproducible run receipts
```

## Sources and handling

- [Unit 42: Tracking Iranian APT Screening Serpens' 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [Check Point Research: Fast and Furious - Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)

Both sources are public. Narrative output is TLP:CLEAR and defanged. Machine files
retain public operational indicators so detections and STIX patterns remain usable.

## Status

The dated [17 July 2026 research receipt](research/2026-07-17/findings.md) found nine
unambiguous domain additions, one probable correction to a malformed Unit 42 domain, and
15 SHA-256 additions in Check Point's IOC set. Eight of the ten valid delta domains returned
passive DNS answers. A 40-file public GitHub sample produced no suspicious value combinations,
although three files contained legitimate AppDomainManager context and one was not valid XML.

Treat every cross-source delta as an analytic lead until its provenance and scope are reviewed.
Shared Azure addresses are observations, not standalone malicious IP indicators.
