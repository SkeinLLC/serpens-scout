# Screening Serpens research findings

Run time: `2026-07-17T06:37:51.585390+00:00`

## Executive finding

The two primary reports do not expose the same IOC set. Check Point Research supplies
**9 unambiguous domain additions**, **1 probable source
correction**, and **15 SHA-256 additions** relative to Unit 42's IOC section.
These are set differences, not claims of previously unknown infrastructure or independent Skein
LLC attribution.

The value-aware configuration test also matters: public code can contain the
AppDomainManager-related element names without the malicious values. In the sampled GitHub
baseline, verdicts were `{'no-match': 36, 'context-only': 3, 'invalid-xml': 1}`. A presence-only signature would therefore overstate
risk.

## Collection receipt

| Source | Domains | SHA-256 | Content receipt |
|---|---:|---:|---|
| Unit 42 | 22 | 12 | `a9d7a5f243394ae42fb86fd8ae5b6412e81ed1a605a7584c3eae1484ef2efce5` |
| Check Point Research | 25 | 27 | `b4a2b50d0dffee32f09f72fc797fad144f1fd354cd48493cff782bc901c4eb31` |

Cross-source overlap: 15 domains and 12 SHA-256
hashes.

## Cross-source domain delta

- `getsqldeveloper[.]com`
- `global-check-business-it[.]azurewebsites[.]net`
- `global-check-itbusiness[.]azurewebsites[.]net`
- `global-it-checkbusiness[.]azurewebsites[.]net`
- `global-it-checkers[.]azurewebsites[.]net`
- `global-it-consultants[.]azurewebsites[.]net`
- `globalbusiness-checkers-it[.]azurewebsites[.]net`
- `globalit-consultants[.]azurewebsites[.]net`
- `globalitconsultants[.]azurewebsites[.]net`
- `ramiltonsfinance[.]azurewebsites[.]net`

## Cross-source SHA-256 delta

- `0291ef318576953f7f3fe287e7775ed1d7c3206119dc7b9cd6d85c02779e6e40`
- `10fd541674adadfbba99b54280f7e59732746faf2b10ce68521866f737f1e46d`
- `2c214494fd0bad31473ca8adce78a4f50847876584571e66aadeae70827ec2dc`
- `485f182f7b74ea4013b2539275a95d21e3a9bf0082c331937af9353a324b36f3`
- `5c3362d20229597d11380f56d1f2eb39647fb6afad7be8392a7abcd18dff12f8`
- `63d0d3c4a7f71bdbca720903d6a99b832089cc093c64d2938e7e001e56c17ab4`
- `64530d7e6ee30e4a66d9eeed6b8595c33fd72f5f73409133ca40539e5695df4c`
- `781605ce9d4a9869e846f6c9657d71437cb6240ab27ffbc4cd550c0e06996690`
- `a13ba3c5aff46e9daf2d23df4b3e3d49dc7236c207c56f0a1433051f3450d441`
- `a57ffb819fe8d98ff925c5d7b239598fe302acf5a13193d7a535040a71298fdf`
- `dfa1e3137a032ee8561a1cd5e1a0f71a10bebb36aef7c336c878638a9c1239ee`
- `ecaf493c320d201d285ef5f61d75744216e47cf1115b4af528f9a78883cc446e`
- `eee657ffdb2af8ed6412221e7d5fbf4f5742f2ac2c88f43f12db46af0697de71`
- `f08b17856616d66492a24dced27f788e235f35f42fa7cd10f315000d3a2f4c03`
- `f54cd38632ac9da3af3533ae93e92625cbcb04df521dbf1b6acfaa81218f9e8c`

## Probable source corrections

- `ramiltonsfinance[.]azurewebsites[.]net` likely corrects Unit 42's `ramiltonsfinance[.]azurewebsites[.]neti`.

## Passive DNS observations

Exact-name DNS-over-HTTPS queries returned an answer for **8 of 10** delta
domains. IP addresses in `findings.json` are hosting observations only. They are not promoted
to IOCs because Azure hosting addresses are shared infrastructure.

## Public-code prevalence check

- `appDomainManagerType extension:config`: **82** results
- `"etwEnable" "enabled=\"false\"" extension:config`: **21** results
- `bypassTrustedAppStrongNames extension:config`: **247** results
- `"publisherPolicy" "apply=\"no\"" extension:config`: **1338** results
- `"appDomainManagerType" "etwEnable" "bypassTrustedAppStrongNames" extension:config`: **9** results

Sampled verdict counts: `{'no-match': 36, 'context-only': 3, 'invalid-xml': 1}`. GitHub Code Search is a convenience sample, not a
statistically representative known-good corpus. It supports the narrow conclusion that values,
not element-name presence, must drive the config signature.

## Assessment and limits

- Confidence is high that the listed delta accurately reflects the two fetched IOC sections;
  both source documents are hashed above.
- Confidence is moderate that the delta belongs in the broader actor cluster because Check
  Point maps Nimbus Manticore to UNC1549, while Unit 42 maps Screening Serpens to UNC1549.
- The collection does not prove live C2, victimization, or actor control. DNS resolution is not
  evidence of malicious traffic.
- The pipeline made no connection to a suspected domain, downloaded no sample, and submitted
  no indicator to a third-party scanner.

## Analyst next actions

1. Load `serpens.stix.json` into the TIP as source-attributed indicators.
2. Deploy the value-aware YARA and endpoint queries in audit mode.
3. Compare local telemetry against the cross-source delta, preserving source and first-seen
   timestamps.
4. Build the false-positive baseline from an approved enterprise software corpus before
   enabling prevention.
