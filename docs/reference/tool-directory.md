# Tool Directory

> Consolidated tool recommendations organized by category.
> Extracted from skill files for clean separation.

---

## AI-Assisted OSINT

> **Warning:** Never paste PII, sensitive IOCs, or unique pivots into cloud LLMs.

| Tool | Strength |
|------|---------|
| [ChatGPT](https://chat.openai.com/) (paid) | Log parsing, dataset analysis, Code Interpreter for CSV/JSON |
| [Claude](https://claude.ai/) (paid) | 200K-token context for large doc dumps + report synthesis |
| [Gemini](https://gemini.google.com/) | Long-context; Deep Research mode with citations |
| [Perplexity Pro](https://www.perplexity.ai/) | Real-time web search + reasoning |

**Local / privacy-preserving:** [Ollama](https://ollama.com/), [LM Studio](https://lmstudio.ai/).

---

## Username & Email Investigation

| Tool | Purpose |
|------|---------|
| [Sherlock](https://github.com/sherlock-project/sherlock) | Username search across social networks |
| [Maigret](https://github.com/soxoj/maigret) | Profile collector by username |
| [What's My Name](https://whatsmyname.app/) | Username search |
| [Holehe](https://github.com/megadose/holehe) | Email registration check |
| [Epieos](https://epieos.com/) | Email pivots and metadata |
| [OSINT Industries](https://osint.industries/) | Email/username/phone lookups |
| [Hunter.io](https://hunter.io/) | Domain → emails |
| [EmailRep](https://emailrep.io/) | Email reputation |
| [RocketReach](https://rocketreach.co/) / [Apollo](https://www.apollo.io/) | Email enrichment + pattern guessing |

---

## People Search

- [TruePeopleSearch](https://www.truepeoplesearch.com/) — free U.S. people search.
- [WhitePages](https://www.whitepages.com/), [Spokeo](https://www.spokeo.com/), [Webmii](https://webmii.com/), [Pipl](https://pipl.com/) (paid).
- [FaceCheck](https://facecheck.id/) / [FaceSeek](https://faceseek.online/) — reverse face search.

---

## Phone Number OSINT

- [TrueCaller](https://www.truecaller.com/) — caller ID + spam blocking.
- [ThatsThem](https://thatsthem.com/) — reverse phone search.
- [Infobel](https://infobel.com/) — non-USA phone search.
- [FreeCarrierLookup](https://freecarrierlookup.com/) — carrier/type (US).

---

## Social Media

| Platform | Tool |
|----------|------|
| Instagram | [Picuki](https://www.picuki.com/) — profile view without account |
| X/Twitter | [snscrape](https://github.com/snscrape/snscrape) — preferred CLI scraper |
| Facebook | [Graph Search](https://inteltechniques.com/tools/Facebook.html), [sowsearch.info](https://sowsearch.info/) |
| YouTube/Twitch | [Social Blade](https://socialblade.com/) — analytics |
| TikTok | [Tokboard](https://tokboard.com/) — trends + profile analytics |
| Reddit | [Reveddit](https://www.reveddit.com/) — removed content |
| Bluesky | [Firesky](https://firesky.tv/) — real-time firehose |
| Mastodon | [FediSearch](https://fedisearch.skorpil.cz/) — cross-instance |
| Faces | [Search4Faces](https://search4faces.com/) |

---

## Threat Intel & IOCs

- CERT advisories: CISA/NSA/CSA, CERT-EU, NCSC-UK, JPCERT/CC, CERT-UA.
- [MISP Project](https://www.misp-project.org/) and public MISP feeds.
- [ThreatFox](https://threatfox.abuse.ch/), [URLHaus](https://urlhaus.abuse.ch/), [SSLBL](https://sslbl.abuse.ch/).
- [MalwareBazaar](https://bazaar.abuse.ch/), [PhishTank](https://www.phishtank.com/).

### Vulnerability Prioritization Sources

| Source | What it tells you |
|---|---|
| [NVD](https://nvd.nist.gov/vuln/search) | Base CVE catalog with CVSS v2/v3 |
| [EPSS](https://www.first.org/epss/) | 0.0–1.0 probability of exploit in next 30 days |
| [CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | CVEs proven exploited in the wild |
| [ExploitDB](https://www.exploit-db.com/) / `searchsploit` | POC code presence |
| [Trickest CVE](https://github.com/trickest/cve) | Auto-generated CVE → public POC repo links |
| [OSV.dev](https://osv.dev/) | Open-source vulnerability DB; JSON API |

---

## Cryptocurrency OSINT

- [Blockchain.com](https://www.blockchain.com/explorer), [Etherscan](https://etherscan.io/), [Solscan](https://solscan.io/).
- [Arkham](https://www.arkhamintelligence.com/) — multichain, entity labels, graphs.
- [MetaSleuth](https://metasleuth.io/) — visual flow.
- [Breadcrumbs](https://www.breadcrumbs.app/) — visual graphing + labels (freemium).
- [Chainalysis](https://www.chainalysis.com/) / [Crystal Blockchain](https://crystalblockchain.com/) — pro analytics.
- [L2Beat](https://l2beat.com/) — risk framework + TVL for L2s.

---

## Telegram & Messaging Intelligence

- [TGStat](https://tgstat.com/) — channel analytics + search.
- [Telemetr](https://telemetr.io/) — channel growth, overlaps, forwards.
- View public Telegram channels: `https://t.me/s/<channel>`.
- Google: `site:t.me "{target}"`.

---

## Job Posting Tech-Stack Analysis

**ATS Platforms:**

| Platform | URL |
|---|---|
| Lever | `jobs.lever.co/{company}` |
| Greenhouse | `boards.greenhouse.io/{company}` |
| AshbyHQ | `jobs.ashbyhq.com/{company}` |
| Workable | `apply.workable.com/{company}` |
| Company careers | `{domain}/careers`, `{domain}/jobs` |

**What to extract:** Required technologies → confirmed in-use; vendor names (Workday, Salesforce, Snowflake) → SaaS tenants; compliance frameworks (SOC2, FedRAMP, HIPAA, PCI) → defensive priorities; cloud + on-prem ratio hints.

---

## Sat Imagery for Physical Recon

| Source | URL | Notes |
|---|---|---|
| **Google Earth Pro** | desktop app | Historical timeline; sub-meter for major cities |
| **Google Maps** | maps.google.com | Street view inside building lobbies sometimes |
| **Bing Maps Bird's Eye** | bing.com/maps | Oblique 45-degree; shows facades better |
| **NearMap** (paid) | nearmap.com | Highest-resolution; frequent updates (US/AU/NZ/CA) |
| **Sentinel Hub EO Browser** | apps.sentinel-hub.com | Free Sentinel-2 (10m); change detection |
| **Wayback ArcGIS** | livingatlas.arcgis.com/wayback/ | Historical satellite |

**What to extract:** entrance count/locations, parking lot ingress, fence lines, HVAC/utility access, adjacent occupants, smoking area locations (social-engineering staging), vehicle types.

**OSINT beyond satellites:** LinkedIn employee photos (badge templates visible), Glassdoor office tour photos, Instagram geotagged photos at office address, press release "ribbon cutting" photos.

**Discipline:** document imagery is public-source; note imagery date (buildings change).

---

## General OSINT References

- [OSINT Framework](https://osintframework.com/) — categorized tree of OSINT tools.
- [IntelTechniques](https://inteltechniques.com/tools/) — Bazzell's tool collection.
- [Bellingcat Online Investigations Toolkit](https://www.bellingcat.com/resources/2024/09/24/bellingcat-online-investigations-toolkit/) — investigative toolkit.
- [CyberSudo OSINT Lists](https://github.com/CyberSudo) — curated lists.
- [DDoSecrets](https://ddosecrets.com/) — leaked dataset reference.
- [DigitalDigging](https://digitaldigging.org/) — OSINT training resources.

---

## Search Engines

| Tool | URL | Notes |
|------|-----|-------|
| Carrot2 | carrot2.org | Clustering search results |
| etools | etools.ch | Metasearch |
| Kagi | kagi.com | Premium; programmable lenses |
| Brave Search | search.brave.com | Independent index; AI answer |
| PDF Search | pdf-search-engine.com | Specifically for PDF documents |

---

## Infrastructure & Attack-Surface OSINT

| Tool | URL | Notes |
|------|-----|-------|
| [Shodan](https://www.shodan.io/) | shodan.io | Banner search, InternetDB |
| [Censys](https://search.censys.io/) | censys.io | Certificate + host search |
| [GreyNoise](https://www.greynoise.io/) | greynoise.io | Internet background noise |
| [SecurityTrails](https://securitytrails.com/) | securitytrails.com | DNS history + IP WHOIS |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | GitHub | Open-source OSINT automation |
| [BuiltWith](https://builtwith.com/) | builtwith.com | Technology profiling |
| [Netlas](https://netlas.io/) | netlas.io | Attack surface search |
| [BinaryEdge](https://www.binaryedge.io/) | binaryedge.io | Internet scan |
| [ZoomEye](https://www.zoomeye.org/) | zoomeye.org | Chinese search engine for devices |

---

## WHOIS Historical & Reverse Lookup

| Source | Notes |
|---|---|
| [DomainTools](https://www.domaintools.com/) | Gold-standard for historical WHOIS + reverse WHOIS |
| [SecurityTrails](https://securitytrails.com/) | Free historical DNS; limited historical WHOIS |
| [viewdns.info](https://viewdns.info/) | Basic reverse WHOIS |

**Reverse-WHOIS example (DomainTools API):**
```
https://reverse-whois-api.domaintools.com/v1?terms={"registrant_org":"Acme%20Corp"}&mode=purchase
```

---

## Geospatial Intelligence

### Satellite & Mapping
- Google Maps / Google Earth Pro (historical timeline, sub-meter for major cities).
- Bing Maps Bird's Eye (oblique 45-degree views).
- [Sentinel Hub EO Browser](https://apps.sentinel-hub.com/) — Free Sentinel-2 (10m); change detection.
- [NASA Worldview](https://worldview.earthdata.nasa.gov/) — near-real-time satellite.
- [Wayback ArcGIS](https://livingatlas.arcgis.com/wayback/) — historical satellite.

### Geolocation Tools
- [Mapillary](https://www.mapillary.com/) — crowd-sourced street imagery.
- [KartaView](https://kartaview.org/) — open street imagery.
- [Overpass Turbo](https://overpass-turbo.eu/) — OpenStreetMap query engine.
- [SunCalc](https://www.suncalc.org/) — shadow analysis for chronolocation.

### Flight OSINT
- [FlightRadar24](https://www.flightradar24.com/), [ADSBExchange](https://globe.adsbexchange.com/) — unfiltered.

### Maritime OSINT
- [MarineTraffic](https://www.marinetraffic.com/), [VesselFinder](https://www.vesselfinder.com/), [Global Fishing Watch](https://globalfishingwatch.org/).

---

## Regional Search Engines

### Russia / CIS
- Yandex (yandex.ru), Mail.ru, VK (vk.com), OK.ru (Odnoklassniki).

### China
- Baidu (baidu.com), Sogou (sogou.com), 360 Search (so.com), Weibo (weibo.com), Zhihu (zhihu.com).

---

## Public Records & Company Information

### General
- [OpenCorporates](https://opencorporates.com/) — global company registry search.
- [SEC EDGAR](https://www.sec.gov/cgi-bin/browse-edgar) — US public company filings.
- [OpenOwnership](https://register.openownership.org/) — beneficial ownership.
- [MuckRock](https://www.muckrock.com/) — FOIA request platform.
- [UK Companies House](https://find-and-update.company-information.service.gov.uk/) — UK company registry.

### Russia
- [Rusprofile](https://www.rusprofile.ru/) — company + director search.
- [Kontur.Focus](https://focus.kontur.ru/) — Russian company analytics.
- [zakupki.gov.ru](https://zakupki.gov.ru/) — Russian procurement.

### China
- [GSXT](https://www.gsxt.gov.cn/) — national enterprise credit system.
- [USCC](https://www.uscc.gov/) — US-China Economic and Security Review Commission.
- ICP Beian (beian.miit.gov.cn) — domain registration records.

### Sanctions & Compliance
- [OFAC](https://sanctionssearch.ofac.treas.gov/) — US sanctions list.
- [OpenSanctions](https://www.opensanctions.org/) — aggregated sanctions data.
- [OCCRP Aleph](https://aleph.occrp.org/) — investigative data.

---

## LinkedIn Employee Enumeration Tools

- [theHarvester](https://github.com/laramies/theHarvester) — email + subdomain harvester.
- [CrossLinked](https://github.com/m8sec/CrossLinked) — LinkedIn scraper → employee list.

---

