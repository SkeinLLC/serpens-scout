# Methodology

## Research question

Can the Screening Serpens AppDomainManager tradecraft support a deployable pre-execution
detection, and does cross-source collection add indicators beyond Unit 42's published set?

## Evidence model

Serpens Scout keeps four evidence classes separate:

| Class | Meaning | Allowed use |
|---|---|---|
| Unit 42 baseline | Indicator listed in the report's IOC section | Source-attributed detection and enrichment |
| Cross-source delta | Check Point IOC absent from the fetched Unit 42 IOC section | Analytic lead; validate before blocking |
| DNS observation | Exact-name DNS answer for a reported domain | Hosting context only |
| Config candidate | Value-aware local scanner match | Triage the file, signer, host, and provenance |

“New” is a set relationship: `Check Point IOC set - Unit 42 IOC set`. It does not claim global
novelty, first discovery, live command and control, or independent attribution.

## Collection boundary

The HTTP client permits HTTPS connections only to the two report publishers, Google DNS-over-
HTTPS, and GitHub's API. It never requests a reported domain. DNS queries are exact-name lookups;
the returned shared-hosting addresses remain observations. The tool does not download malware,
detonate content, or submit indicators to public scanning services.

Each report fetch records its retrieval time and SHA-256 content digest. Extraction is constrained
to the report's IOC section. A change in source layout should be treated as a failed or suspicious
run, not silently accepted as a campaign change.

The report fetch is mandatory. DNS and GitHub enrichment are optional: bounded retry handles
HTTP 429 responses, after which the collector writes an explicit partial-result error and keeps
the report-diff output. A failed enrichment call never becomes a negative finding.

## Configuration test

AppDomainManager is legitimate .NET functionality. Element-name presence alone is inadequate.
The scanner requires the values that change security behavior and combines them with a custom
manager and local assembly probing. Scoring is transparent:

| Signal | Score |
|---|---:|
| Custom manager type | 15 |
| Custom manager assembly | 10 |
| Local private path | 15 |
| ETW disabled | 25 |
| Strong-name bypass enabled | 20 |
| Publisher policy disabled | 10 |
| Runtime safe mode enabled | 5 |

A highly suspicious verdict requires at least 65 points, a custom manager type, and two
security-weakening values. The included legitimate fixture has manager elements but safe values;
it must remain context-only. Archive handling is in-memory and bounded by member size, cumulative
size, compression ratio, and nesting depth.

## False-positive program

GitHub Code Search supplies a convenience sample, not a known-good population. Use the resulting
counts to reject naive presence-only logic. Before prevention, scan an approved corpus of signed
enterprise software, record publisher and product, review every suspicious result, and calculate
the observed false-positive rate with confidence intervals appropriate to the sample size.

## Analytic confidence

The cross-source set difference is reproducible from two public primary reports. Actor-level
confidence remains inherited from those publishers. VirusTotal upload location, timing against a
regional conflict, shared techniques, and domain themes are supporting context rather than proof
of victim location or operator identity.
