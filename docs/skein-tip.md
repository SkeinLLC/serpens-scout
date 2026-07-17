# Skein TIP handoff

`serpens.stix.json` is a STIX 2.1 bundle with two explicit roles:

- `unit42-baseline`: directly present in Unit 42's IOC section.
- `cross-source-delta`: present in Check Point Research and absent from that Unit 42 section.

Import the bundle into a staging collection first. Preserve `external_references`, labels,
confidence, and the source-defined attribution. Do not convert DNS answer IPs from `findings.json`
into indicators; Azure addresses are shared hosting.

Recommended automation:

1. Run the scheduled workflow weekly or on demand.
2. Compare the new JSON artifact to the prior successful run.
3. Route added or removed source indicators to analyst review.
4. Promote reviewed indicators into the operational collection with an internal decision record.
5. Expire infrastructure according to local source and sightings policy rather than treating the
   public report date as a permanent block decision.
