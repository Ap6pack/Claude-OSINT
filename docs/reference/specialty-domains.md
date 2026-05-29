# Specialty OSINT Domains

> Encyclopedic reference for domain-specific OSINT techniques.
> Extracted from skill files for clean separation.

---

## Specialty OSINT Techniques

**Cryptocurrency** — track flows with Cielo, TRM, Arkham, MetaSleuth. L2/rollup: start at L1 bridge events; use L2 explorers for in-rollup activity. Caution: bridges mint/burn (avoid 1:1 flow assumptions); MEV paths create false direct trails.

**Image / Video / Chronolocation** — reverse image search (Google Lens, Yandex, TinEye); EXIF via ExifTool; forensics via Forensically/FotoForensics; geolocation via foreground+background landmark analysis, Street View, Overpass Turbo, PeakVisor. Shadow analysis: SunCalc, ShadeMap. Satellite: Google Earth Pro historical, Sentinel Hub.

**Threat Actor Investigation** — scoping: actor hypothesis from CERT/vendor reports → IOC harvest → infra mapping via CT log pivots, shared hosting, NS reuse, HTML fingerprints → artifact profiling (PDB paths, Rich headers, SSDEEP/YARA) → social pivots (handles, code snippets, job posts). Attribution discipline: rule of three; separate capability from intent; prefer durable pivots (code-signing certs, build path idioms) over ephemeral (resolving IPs). Russia pivots: EGRUL, Rusprofile, hh.ru, VKontakte. China pivots: gsxt.gov.cn, Tianyancha, ICP filings, Weibo, Zhihu.

**People & Social Media** — username enumeration: WhatsMyName, Sherlock, Maigret. Face search: PimEyes, Exposing.ai. Social graph: Maltego, SocialBlade. Bluesky: DID resolution via `bsky.social/xrpc/`, firehose via Firesky. Mastodon: WebFinger discovery; FediSearch cross-instance.

---

## Sector-Specific Recon Notes

### Healthcare
- **DICOM** (medical imaging) — port 11112, sometimes 4242.
- **HL7 FHIR** — `/fhir/R4/<resource>` paths; OAuth / SMART-on-FHIR posture varies widely.
- **PACS/EHR vendors:** Epic (`*.epic.com`), Cerner/Oracle Health, Meditech.

### Finance
- **SWIFT terminals** — internal-only; if external-facing → CRITICAL.
- **FIX protocol** (electronic trading) — port 9876; cleartext.
- **Banking middleware:** Temenos T24, Finacle, FIS, Jack Henry, Fiserv.

### ICS / SCADA / OT

> **Caution:** even passive scanning can disrupt ICS. Do NOT actively probe without explicit RoE + OT team coordination.

- **Modbus** — port 502 (TCP). **BACnet** — port 47808 (UDP). **Siemens S7** — port 102.
- Sources: Shodan ICS-specific filters (`port:502`, `tag:ics`), Censys, Onyphe.

### IoT / Consumer / SOHO
- **MQTT** — port 1883 (cleartext), 8883 (TLS). Topics often readable without auth.
- **Camera DVRs/NVRs** — Hikvision, Dahua, Axis. Multiple CVEs.

### Government
- **FedRAMP / FISMA / DoD CMMC** — defensive posture generally above baseline.
- **OSINT sources:** USAspending.gov, SAM.gov (procurement).
- Severity: as high or higher than commercial; political sensitivity on top.

---

