---
name: recon-asset-discovery
description: "Subdomain enumeration, ASN/BGP pivots, CT logs, DNS record catalog, WHOIS/RDAP, geospatial, and regional search engines for authorized external recon."
version: 1.0.0
triggers:
  - subdomain enumeration
  - asset discovery
  - certificate transparency
  - crt.sh
  - ASN lookup
  - BGP pivot
  - WHOIS lookup
  - RDAP
  - DNS record catalog
  - passive recon
  - footprinting
  - geospatial intelligence
  - regional search engines
  - company information
  - public records
---

# Recon — Asset Discovery

> Sub-skill of `offensive-osint`. Load `osint-methodology` for pipeline and triage context.
> Authorized targets only.

---

## 1. General OSINT References

- [OSINT Framework](https://osintframework.com/) — tool/resource directory.
- [IntelTechniques Tools](https://inteltechniques.com/tools/) — investigative suite.
- [Bellingcat Toolkit](https://www.bellingcat.com/resources/2024/09/24/bellingcat-online-investigations-toolkit/)
- [CyberSudo OSINT Toolkit](https://docs.google.com/spreadsheets/d/1EC0sKA_W9znzsxUt0wye9UYtyATXw5m8) — OSINT websites list.
- [Distributed Denial of Secrets](https://ddosecrets.com/) — leaked datasets.
- [Country-Specific Resources](https://digitaldigging.org/osint/) — country-targeted OSINT.

---

## 2. Search Engines

| Tool | Notes |
|------|-------|
| [Carrot2](https://search.carrot2.org/#/search/web) | Clusters results by topic |
| [etools](https://www.etools.ch/) | Metasearch |
| [Kagi](https://kagi.com/) | Privacy-first, non-personalized |
| [Brave Search](https://search.brave.com/) | Independent index; Goggles for custom ranking |
| [PDF Search](https://www.pdfsearch.io/) | PDF + table of contents |

---

## 3. Public Records & Company Information

- [OpenCorporates](https://opencorporates.com/) — world's largest open company DB.
- [SEC EDGAR](https://www.sec.gov/edgar.shtml) — U.S. company filings.
- [OpenOwnership Register](https://register.openownership.org/) — beneficial ownership.
- [MuckRock](https://www.muckrock.com/) — FOIA repository + request tracking.
- [UK Companies House](https://find-and-update.company-information.service.gov.uk/)

### 3.1 RU Registries

[Rusprofile](https://www.rusprofile.ru/), [Kontur.Focus](https://focus.kontur.ru/) (freemium), [zakupki.gov.ru](https://zakupki.gov.ru/) (procurement).

### 3.2 CN Registries + USCC + ICP

- **GSXT** — [gsxt.gov.cn](https://www.gsxt.gov.cn/) National Enterprise Credit Info; cross-check with Tianyancha / Qichacha.
- **USCC** — 18-character entity ID. Workflow: `target.cn` domain → ICP lookup → USCC → GSXT → entity name + officers.
- **ICP Beian** — [beian.miit.gov.cn](https://beian.miit.gov.cn/) — every domain serving mainland CN traffic must register.

### 3.3 Sanctions & Compliance

- [OFAC SDN List](https://sanctionssearch.ofac.treas.gov/), [EU Sanctions Map](https://www.sanctionsmap.eu/).
- [OpenSanctions](https://www.opensanctions.org/) — aggregated.
- [OCCRP Aleph](https://aleph.occrp.org/) — investigative documents, leaks, company records.

---

## 4. Subdomain-Source Stack (Passive)

| Source | Tier | Notes |
|---|---|---|
| crt.sh | Free | Best single source; **frequently 502s — see fallback chain** |
| VirusTotal | Freemium | Domain → passive DNS history |
| AlienVault OTX | Free | Passive DNS + URL data |
| Shodan | Paid (low tier) | Subdomain enum via `domain:` filter |
| SecurityTrails | Paid | Passive DNS + asset discovery |
| RapidDNS | Free | Public passive DNS |
| Subfinder | Free | Aggregates 30+ free sources |
| Amass | Free | Thorough, slower |
| Recon-ng | Free | Modular framework |

**DNS AXFR opportunism:**
```
dig @<ns-host> <target-domain> AXFR
```
Most NSs reject; those that don't = full zone disclosure (CRITICAL).

**Brute-force tier:** puredns against [assetnote.io](https://wordlists.assetnote.io/) wordlists.

### 4.1 crt.sh Down? Fallback Chain

```bash
D="target.example"

# 1. Censys cert search (free 250/month with key)
censys search "names: ${D}" --index-type certificates --fields names | jq -r '.names[]' | sort -u

# 2. Cert Spotter API (sslmate) — free w/ rate limits
curl -sk "https://api.certspotter.com/v1/issuances?domain=${D}&include_subdomains=true&expand=dns_names" | \
  jq -r '.[].dns_names[]' | sort -u

# 3. Subfinder bundled aggregator
subfinder -d ${D} -all -recursive -silent

# 4. AlienVault OTX — free, no key
curl -sk "https://otx.alienvault.com/api/v1/indicators/domain/${D}/passive_dns" | \
  jq -r '.passive_dns[].hostname' | sort -u

# 5. URLScan — passive DNS via past scans
curl -sk "https://urlscan.io/api/v1/search/?q=domain:${D}" | \
  jq -r '.results[].page.domain' | sort -u
```

### 4.2 Common-Prefix Active Sweep

Passive enum misses 20–40% of high-value subdomains. Always pair with active prefix probe (detectability: low — single A-record query per host).

```bash
D="target.example"
for p in www mail webmail owa autodiscover ftp vpn sslvpn gateway api app portal login sso idp iam identity accounts oauth auth adfs admin intranet hr sap erp crm support help status grafana kibana docs wiki jira jenkins gitlab dev test staging stg qa uat sandbox preprod preview careers jobs eapps old legacy beta tender suppliers procurement; do
  IP=$(dig +short A "$p.$D" | head -1)
  [ -n "$IP" ] && echo "$p.$D -> $IP"
done
```

PowerShell equivalent:
```powershell
$D = "target.example"
$prefixes = @("www","mail","webmail","owa","autodiscover","ftp","vpn","sslvpn","gateway","api","app","portal","login","sso","idp","iam","identity","accounts","oauth","auth","adfs","admin","intranet","hr","sap","erp","crm","support","help","status","grafana","kibana","docs","wiki","jira","jenkins","gitlab","dev","test","staging","stg","qa","uat","sandbox","preprod","preview","careers","jobs","eapps","old","legacy","beta","tender","suppliers","procurement")
foreach ($p in $prefixes) {
  $r = Resolve-DnsName "$p.$D" -Type A -ErrorAction SilentlyContinue
  if ($r) { $ips = ($r | ? {$_.IPAddress}).IPAddress -join ","; "$p.$D -> $ips" }
}
```

**Wordlist sources:**

| Source | URL |
|---|---|
| **Assetnote** | `https://wordlists.assetnote.io/` — best-curated; per-CMS/framework |
| **SecLists** | `https://github.com/danielmiessler/SecLists` — `Discovery/DNS/subdomains-top1million-110000.txt` |
| **jhaddix all.txt** | `https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056` |

---

## 5. Infrastructure & Attack-Surface OSINT

- [Shodan](https://www.shodan.io/), [Censys](https://search.censys.io/) — internet device + cert search.
- [GreyNoise](https://viz.greynoise.io/) — distinguish background noise from targeted scans.
- [SecurityTrails](https://securitytrails.com/) — passive DNS + asset discovery.
- [SpiderFoot](https://www.spiderfoot.net/) — automated recon + correlation.
- [BuiltWith](https://builtwith.com/) — tech stack enumeration.
- [Netlas](https://netlas.io/), [BinaryEdge](https://www.binaryedge.io/), [FOFA](https://fofa.so/), [ZoomEye](https://www.zoomeye.org/).
- [RiskIQ PassiveTotal](https://community.riskiq.com/) — passive DNS/cert/host pivots.

### 5.1 ASN/BGP & Internet Measurement

- [Hurricane Electric BGP Toolkit](https://bgp.he.net/), [RIPEstat](https://stat.ripe.net/), [BGPView](https://bgpview.io/), [PeeringDB](https://www.peeringdb.com/).

**Bulk IP → ASN recipes:**
```bash
# Cymru bulk WHOIS (fastest; no rate-limit; no key)
echo -e "begin\nverbose\n8.8.8.8\n1.1.1.1\nend" | nc whois.cymru.com 43

# RIPEstat (free; ~1 req/sec polite)
curl -sk "https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8" | jq '.data'

# bgp.tools (free; light rate-limit)
curl -sk -A "osint-recon/1.0 (contact@example.com)" "https://bgp.tools/api/ip/8.8.8.8" | jq .
```

**Note:** `bgpview.io` API has aggressive undocumented rate limits (~1 req/min/IP); not suitable for bulk.

### 5.2 Certificates & CT Monitoring

- [crt.sh](https://crt.sh/), [Censys Certificates](https://search.censys.io/certificates), [CertStream](https://certstream.calidog.io/) (real-time CT WebSocket), [Cert Spotter](https://sslmate.com/certspotter).
- **Favicon mmh3 hash:** cluster infrastructure; pair with Shodan/Censys favicon search for shared-infra discovery.

---

## 6. WHOIS / RDAP / Historical

```bash
whois target.example
curl -sk "https://rdap.org/domain/${D}" | jq .
```

What to extract: registrant org/email, registrar (pivot for related domains), created/updated dates (bulk registration patterns), nameservers (NS reuse pivot), status flags.

**Historical WHOIS sources:**
| Source | Notes |
|---|---|
| [DomainTools](https://domaintools.com/) | Paid; gold-standard; full WHOIS history |
| [SecurityTrails](https://securitytrails.com/) | Paid; WHOIS + DNS history |
| [viewdns.info](https://viewdns.info/) | Free (limited) |

**Reverse-WHOIS:** given a registrant email, find all domains they registered:
```bash
# DomainTools (paid)
curl -sk -H "X-API-Username: ..." -H "X-API-Key: ..." \
  "https://api.domaintools.com/v1/reverse-whois/?terms=admin@target.example"
```

---

## 7. DNS Record Catalog

```bash
D="target.example"
for rtype in A AAAA MX TXT NS SOA CAA SRV CNAME PTR; do
  echo "=== ${rtype} ===" && dig +short "${D}" "${rtype}"
done
```

**TXT verification tokens → SaaS tenancy inference (selected):**

| TXT pattern | SaaS / service |
|---|---|
| `google-site-verification=<token>` | Google Workspace |
| `MS=ms<digits>` | Microsoft 365 |
| `atlassian-domain-verification=<token>` | Atlassian Cloud |
| `slack-domain-verification=<token>` | Slack Enterprise Grid |
| `zscaler-verification-<id>-<date>-<random>` | Zscaler (ZIA/ZPA/ZDX) |
| `salesforce-domain-verification=<token>` | Salesforce |
| `workday-domain-verification=<token>` | Workday (HR + Finance) |
| `hubspot-domain-verification=<token>` | HubSpot CRM |
| `zoom_verify_<id>` | Zoom |
| `_amazonses=<token>` | AWS SES |
| `docusign=<token>` | DocuSign |
| `intercom-verification=<token>` | Intercom |
| `gitlab-domain-verification=<token>` | GitLab |

Each discovered tenancy is a separate attack surface (own credentials, own MFA posture).

**Autodiscover-as-M365-confirmation:**
```bash
dig +short A "autodiscover.target.example"
```
If IP lands in `40.96.0.0/13`, `52.96.0.0/14`, `13.107.0.0/16` → `M365_CONFIRMED` even when MX is wrapped by Mimecast/Proofpoint.

**CAA records (cert issuance control):**
```bash
dig +short CAA "${D}"
```
Absence = LOW (any CA can mis-issue). Presence + restrictive list = good posture.

---

## 8. Geospatial Intelligence

### 8.1 Satellite & Mapping

- [Google Maps](https://www.google.com/maps), [Bing Maps](https://www.bing.com/maps/).
- [Sentinel Hub EO Browser](https://apps.sentinel-hub.com/eo-browser/), [NASA Worldview](https://worldview.earthdata.nasa.gov/).
- [Wayback Imagery (ArcGIS)](https://livingatlas.arcgis.com/wayback/) — historical satellite.

### 8.2 Geolocation Tools

- [Mapillary](https://www.mapillary.com/app), [KartaView](https://kartaview.org/), [Overpass Turbo](https://overpass-turbo.eu/), [SunCalc](https://www.suncalc.org/).

### 8.3 Flight OSINT

- [FlightRadar24](https://www.flightradar24.com/), [ADSBExchange](https://www.adsbexchange.com/) (unfiltered).

### 8.4 Maritime OSINT

- [MarineTraffic](https://www.marinetraffic.com/), [VesselFinder](https://www.vesselfinder.com/).
- [Global Fishing Watch](https://globalfishingwatch.org/map/) — vessel behavior + AIS gap analysis.

---

## 9. Regional Search Engines

- **Russia / CIS:** [Yandex](https://yandex.com/), [Mail.ru Search](https://go.mail.ru/), [VK](https://vk.com/), [OK.ru](https://ok.ru/).
- **China:** [Baidu](https://www.baidu.com/), [Sogou](https://www.sogou.com/), [360 Search](https://www.so.com/), [Weibo](https://weibo.com/), [Zhihu](https://www.zhihu.com/).
