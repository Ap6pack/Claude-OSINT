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
- **HL7 v2** — port 2575 (TCP, often plaintext). Legacy but still widespread; carries ADT, ORM, ORU messages with patient demographics in the clear.
- **HL7 FHIR** — `/fhir/R4/<resource>` paths; OAuth / SMART-on-FHIR posture varies widely.
- **PACS/RIS/EHR vendors:** Epic (`*.epic.com`), Cerner/Oracle Health, Allscripts/Veradigm, Athenahealth, NextGen, Meditech, eClinicalWorks.
- **Searches:** `site:{domain} ("EHR" OR "PACS" OR "PHI" OR "HIPAA")`, `intitle:"Epic Systems" "{target}"`.
- **Severity:** any PHI exposure → **CRITICAL**; HL7/DICOM open without auth → **CRITICAL**.

### Finance
- **SWIFT terminals** — internal-only; if external-facing → **CRITICAL**.
- **FIX protocol** (electronic trading) — port 9876; cleartext.
- **Bloomberg terminals** — typically VDI-delivered; check for `bloomberg.com`-related auth surfaces exposed on the target's perimeter.
- **Trading platform vendors:** Fidessa, Charles River, Eze Software, Aladdin (BlackRock).
- **Banking middleware:** Temenos T24, Finacle (Infosys), FIS, Jack Henry, Fiserv. Each has known CVE history; version-fingerprint when possible.
- **Searches:** `site:{domain} ("PCI" OR "SOX" OR "GLBA" OR "MAS")`, `intitle:"Temenos" "{target}"`.
- **Severity:** any account/balance data exposure → **CRITICAL**; SWIFT → **CRITICAL**; trade-execution surface → **CRITICAL**.

### ICS / SCADA / OT

> **Caution:** even passive scanning can disrupt ICS. Do NOT actively probe without explicit RoE + OT team coordination.

- **Modbus** — port 502 (TCP). **BACnet** — port 47808 (UDP). **Siemens S7** — port 102.
- **DNP3** — port 20000 (TCP).
- **EtherNet/IP** — port 44818 (TCP).
- **Niagara Framework** — ports 1911, 4911, 5011, 502.
- **Honeywell EBI / Tridium** — port assignments vary by deployment.
- **GE Proficy / iFIX** — port assignments vary by deployment.
- **Common findings:** unauthenticated read access (BACnet point list, Modbus register read), default creds on HMI panels, public-facing engineering workstations.
- **Detectability:** medium-to-high; ICS networks often have low background traffic and are heavily monitored.
- Sources: Shodan ICS-specific filters (`port:502`, `tag:ics`), Censys, Onyphe.

### IoT / Consumer / SOHO
- **MQTT** — port 1883 (cleartext), 8883 (TLS). Topics often readable without auth.
- **CoAP** — port 5683 (UDP). Lightweight IoT protocol; may expose device resources without authentication.
- **UPnP / SSDP** — port 1900 (UDP); often discloses internal device map and service endpoints.
- **Common router admin patterns:** `/cgi-bin/`, `/setup.cgi`, `/admin/index.html`. Default creds are the norm.
- **Camera DVRs/NVRs** — Hikvision, Dahua, Axis. Multiple CVEs; frequently internet-facing with factory defaults.
- **Smart-home hubs** — exposed APIs sometimes leak auth tokens or device inventories.

### Government
- **FedRAMP / FISMA / DoD CMMC** — defensive posture generally above baseline.
- `.gov` and `.mil` domains require special engagement-scope discipline; verify authorization explicitly before any active interaction.
- **OSINT data sources:** USAspending.gov, SAM.gov (System for Award Management), FBO.gov / sam.gov (procurement).
- **Common findings:** vendor of record disclosed in public contracts → adjacent-vendor pivot for supply-chain attack surface.
- Severity: as high or higher than commercial; political sensitivity on top.

### Maritime / Aviation / Automotive
- **Maritime:** AIS (Automatic Identification System) broadcasts vessel positions; tools: MarineTraffic, VesselFinder. Engine telemetry sometimes exposed via VSAT terminals.
- **Aviation:** ADS-B (Automatic Dependent Surveillance-Broadcast) — see flight OSINT tools (FlightRadar24, ADS-B Exchange). Operator/airline-specific OPS data sometimes exposed on misconfigured portals.
- **Automotive:** OEM telematics backends (Tesla, GM OnStar, etc.) — typically authenticated, but APIs leak via mobile-app reverse engineering. Connected-vehicle platforms may expose VIN-linked telemetry or remote-command endpoints.

---

### Universal Sector Caveat

> Most external recon techniques apply universally. Sector-specific protocols add attack surface; sector-specific compliance regimes add reporting requirements. Don't assume "healthcare/finance/etc. has different OSINT" — the OSINT is the same; the targeted services differ.

---

