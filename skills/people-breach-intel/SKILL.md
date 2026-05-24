---
name: people-breach-intel
description: "Username/email investigation, breach data lookup, HudsonRock infostealer intel, people search, phone OSINT, email-pattern inference, email harvest, social media, threat intel, crypto OSINT, Telegram, job postings, Slack/Discord discovery, and package registry leaks."
version: 1.0.0
triggers:
  - breach lookup
  - have I been pwned
  - HudsonRock cavalier
  - infostealer
  - dehashed
  - intelx
  - username investigation
  - email investigation
  - people search
  - phone OSINT
  - email pattern inference
  - email harvest
  - social media OSINT
  - threat intelligence
  - cryptocurrency OSINT
  - Telegram intelligence
  - job posting tech stack
  - Slack workspace discovery
  - Discord server discovery
  - npm token leak
  - package registry leaks
  - sat imagery
---

# People, Breach & Intelligence

> Sub-skill of `offensive-osint`. Load `osint-methodology` for pipeline and triage context.
> Authorized targets only. Never paste PII or credentials into cloud LLMs.

---

## 1. Breach & Leak Data — Highest ROI Sources

- [Have I Been Pwned](https://haveibeenpwned.com/) — breach lookup; Pwned Passwords API (k-anonymity).
- [Dehashed](https://dehashed.com/) — credential search (paid).
- [IntelX](https://intelx.io/) — data intelligence.
- [LeakCheck](https://leakcheck.io/), [Snusbase](https://snusbase.com/), [BreachDirectory](https://breachdirectory.org/).
- **[Cavalier (Hudson Rock)](https://cavalier.hudsonrock.com/) — infostealer log lookups; FREE; highest single-source ROI for compromised employee credentials.**

### 1.1 HudsonRock Cavalier — Direct API

```bash
# By domain (canonical first call)
curl -sk -m 30 "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=target.com" | jq .

# By email (single-account check)
curl -sk -m 30 "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=alice@target.com" | jq .

# By URL (when target's app is the breach victim)
curl -sk -m 30 "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-url?url=https://app.target.com" | jq .
```

**Top-level JSON fields:**
- `total` — total stealer entries.
- `employees` — count of `<*>@<domain>` accounts found.
- `users` — count of customer accounts where domain appeared as visited URL.
- `data.employees_urls[]` — `{occurrence, type, url}` — **internal apps where employees were logging in when stolen. Subdomain hits here = recon gold.**
- `data.clients_urls[]` — user-facing apps (reveals undocumented portals).
- `data.stealer_families[]` — which stealer (RedLine / Lumma / StealC / Vidar / Raccoon).

**Free-tier caveats:**
- Subdomains past the first few are **redacted with asterisks**. Pivot to paid tier for unredacted.
- Cleartext passwords + emails are **never** in the free response.
- Rate limit ~1 req/sec/IP.

### 1.2 Domain-Level Breach Severity Mapping

| Stat | Severity |
|---|---|
| ≥ 10 employees compromised | **CRITICAL** |
| 1–9 employees compromised | **HIGH** |
| ≥ 1 end-user (non-employee) compromised | **MEDIUM** |
| Domain in breach with 0 named accounts | **INFO** |

### 1.3 SSO_EXPOSURE Finding

When a discovered SSO tenant intersects with the breach corpus → `SSO_EXPOSURE` finding, severity **CRITICAL**.

**Legacy-mail-decommissioned pattern (high-value):**

All three together → CRITICAL `SSO_EXPOSURE`:
1. `Resolve-DnsName mail.<domain> -Type A` → NXDOMAIN (legacy gone)
2. HudsonRock corpus has employee URLs against the old host (e.g., `mail.<domain>/owa/`, `/zimbra/`)
3. Current MX → M365 / Google Workspace (DNS confirms migration)

Evidence pack: tenant GUID + breach count + 3+ legacy URLs + autodiscover Microsoft IPs + current MX. Recommend forced password rotation + MFA audit.

---

## 2. Username & Email Investigation

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

## 3. Email-Pattern Inference (TENTATIVE)

Generate 8 candidate addresses for `(first_name, last_name, domain)`:
```
{first}.{last}@{domain}        # john.doe@example.com
{first}{last}@{domain}         # johndoe@example.com
{first}@{domain}               # john@example.com
{first[0]}{last}@{domain}      # jdoe@example.com
{first}.{last[0]}@{domain}     # john.d@example.com
{last}@{domain}                # doe@example.com
{first}_{last}@{domain}        # john_doe@example.com
{first}-{last}@{domain}        # john-doe@example.com
```

Lowercase before lookup. Strip diacritics. If Hunter.io shows a dominant pattern, mark FIRM.

---

## 4. Email-Harvest Source Stack

Six parallel sources — dedup at the end:

1. **IntelX phonebook API** — 2-step search + poll. Largest single source for breach-era addresses.
2. **Hunter.io** — domain-search endpoint. ~25 free/month. Returns verified emails + roles.
3. **crt.sh** — extract X.509 SAN extensions. Many certs include admin/contact emails.
4. **DuckDuckGo SERP scrape** — HTML scrape of `"@{target-domain}"` results.
5. **Bing SERP scrape** — same query, complementary index.
6. **Wayback CDX** — historic snapshots often contain emails removed from the live site.

**Email regex:**
```regex
\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b
```

---

## 5. People Search

- [TruePeopleSearch](https://www.truepeoplesearch.com/) — free U.S. people search.
- [WhitePages](https://www.whitepages.com/), [Spokeo](https://www.spokeo.com/), [Webmii](https://webmii.com/), [Pipl](https://pipl.com/) (paid).
- [FaceCheck](https://facecheck.id/) / [FaceSeek](https://faceseek.online/) — reverse face search.

---

## 6. Phone Number OSINT

- [TrueCaller](https://www.truecaller.com/) — caller ID + spam blocking.
- [ThatsThem](https://thatsthem.com/) — reverse phone search.
- [Infobel](https://infobel.com/) — non-USA phone search.
- [FreeCarrierLookup](https://freecarrierlookup.com/) — carrier/type (US).

---

## 7. Social Media

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

## 8. Threat Intel & IOCs

- CERT advisories: CISA/NSA/CSA, CERT-EU, NCSC-UK, JPCERT/CC, CERT-UA.
- [MISP Project](https://www.misp-project.org/) and public MISP feeds.
- [ThreatFox](https://threatfox.abuse.ch/), [URLHaus](https://urlhaus.abuse.ch/), [SSLBL](https://sslbl.abuse.ch/).
- [MalwareBazaar](https://bazaar.abuse.ch/), [PhishTank](https://www.phishtank.com/).

### 8.1 Vulnerability Prioritization

| Source | What it tells you |
|---|---|
| [NVD](https://nvd.nist.gov/vuln/search) | Base CVE catalog with CVSS v2/v3 |
| [EPSS](https://www.first.org/epss/) | 0.0–1.0 probability of exploit in next 30 days |
| [CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | CVEs proven exploited in the wild |
| [ExploitDB](https://www.exploit-db.com/) / `searchsploit` | POC code presence |
| [Trickest CVE](https://github.com/trickest/cve) | Auto-generated CVE → public POC repo links |
| [OSV.dev](https://osv.dev/) | Open-source vulnerability DB; JSON API |

```bash
# EPSS score for a CVE
curl -sk "https://api.first.org/data/v1/epss?cve=CVE-2024-3400" | jq '.data[0]'

# Check if in CISA KEV
curl -sk https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | \
  jq '.vulnerabilities[] | select(.cveID == "CVE-2024-3400")'
```

---

## 9. Cryptocurrency OSINT

- [Blockchain.com](https://www.blockchain.com/explorer), [Etherscan](https://etherscan.io/), [Solscan](https://solscan.io/).
- [Arkham](https://www.arkhamintelligence.com/) — multichain, entity labels, graphs.
- [MetaSleuth](https://metasleuth.io/) — visual flow.
- [Breadcrumbs](https://www.breadcrumbs.app/) — visual graphing + labels (freemium).
- [Chainalysis](https://www.chainalysis.com/) / [Crystal Blockchain](https://crystalblockchain.com/) — pro analytics.
- [L2Beat](https://l2beat.com/) — risk framework + TVL for L2s.

---

## 10. Telegram & Messaging Intelligence

- [TGStat](https://tgstat.com/) — channel analytics + search.
- [Telemetr](https://telemetr.io/) — channel growth, overlaps, forwards.
- View public Telegram channels: `https://t.me/s/<channel>`.
- Google: `site:t.me "{target}"`.

---

## 11. Job Posting Tech-Stack Analysis

**Sources:**
| Platform | URL |
|---|---|
| Lever (ATS) | `https://jobs.lever.co/<company>` |
| Greenhouse (ATS) | `https://boards.greenhouse.io/<company>` |
| AshbyHQ (ATS) | `https://jobs.ashbyhq.com/<company>` |
| Company careers page | `https://careers.<target>.com` |

**What to extract:** Required technologies → confirmed in-use; vendor names (Workday, Salesforce, Snowflake) → SaaS tenants; compliance frameworks (SOC2, FedRAMP, HIPAA, PCI) → defensive priorities; cloud + on-prem ratio hints.

---

## 12. Slack / Discord / Telegram Workspace Discovery

**Slack invite-link discovery:**
```
site:join.slack.com "{target}"
inurl:slack.com inurl:shared_invite "{target}"
```
Open invite link = anyone joins without approval → HIGH finding.

**Discord server check:**
```bash
curl -sk "https://discord.com/api/v9/invites/<token>?with_counts=true"
```
Returns server name, ID, member count.

---

## 13. Package Registry Leak Hunting

### 13.1 npm
```bash
npm search "<target-keyword>"
npm pack <package>@<version>
tar -xzf package-version.tgz
# Run secret catalog over extracted files
```

### 13.2 PyPI
```bash
# Per-package history
curl -sk "https://pypi.org/pypi/<package>/json" | jq '.releases | keys'
pip download <package>==<version> --no-deps -d /tmp/pkg
```

### 13.3 Workflow

For each candidate package owned by target:
1. List all historical versions (old versions often had leaked keys).
2. Download each version's archive.
3. Extract; run secret catalog.
4. For Docker images: scan each layer with `dive` or `skopeo`.

### 13.4 Typosquat Surveillance

For every published package the target owns, generate typosquat candidates:
```bash
# Example: target package "acme-utils"
for candidate in acme-util acmeutils acme_utils; do
  npm view $candidate 2>&1 | head -3
done
```
Unregistered candidate near target's published package → MEDIUM finding (typosquat / supply-chain risk).

---

## 14. Sat Imagery for Physical Recon

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
