---
name: recon-asset-discovery
description: "Subdomain enumeration, CT logs, DNS record catalog, WHOIS/RDAP, and passive reconnaissance for authorized external recon."
version: 1.0.0
triggers:
  - subdomain enumeration
  - asset discovery
  - certificate transparency
  - crt.sh
  - WHOIS lookup
  - RDAP
  - DNS record catalog
  - passive recon
  - footprinting
---

# Recon — Asset Discovery

> Sub-skill of `offensive-osint`. Load `osint-methodology` for pipeline and triage context.
> Authorized targets only.

---

## BEHAVIORAL CONTRACT

**When triggered:** Subdomain enumeration, asset discovery, DNS records, CT logs, WHOIS/RDAP, or passive reconnaissance is needed.

**Execute:**
1. Run the passive subdomain-source stack (§1) in parallel across all listed sources. If crt.sh is down, follow the fallback chain.
2. Complement passive results with common-prefix candidates from the prefix wordlist (§2).
3. Run WHOIS/RDAP (§3) on the root domain. Extract registrant org/email for pivoting.
4. Catalog DNS records (§4) for every discovered domain/subdomain. Parse TXT records for SaaS tenancy inference using the verification token table.
5. Check autodiscover for M365 confirmation (§4).
6. Deduplicate all discovered assets by typed key. Tag each with confidence level per `osint-methodology` §2.

**Output:** Asset list with typed keys (subdomain, ip, domain) per `osint-methodology` §8 taxonomy.

**Severity rules:** DNS AXFR success = CRITICAL. Missing CAA = LOW.

**Gating rules:** Passive first. Active prefix sweep only when authorized. Brute-force (puredns) only with explicit operator approval.

**Chain to:** Feed discovered subdomains to `web-surface` for probing. Feed discovered emails to `people-breach-intel` for breach lookup. Feed discovered IPs to `cloud-and-infra` for infrastructure analysis.

---

## 1. Subdomain-Source Stack (Passive)

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

### 1.1 crt.sh Down? Fallback Chain

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

---

## 2. Common-Prefix Wordlist

Passive enum misses 20–40% of high-value subdomains. Pair with active prefix probe when authorized (detectability: low — single A-record query per host).

```
www mail webmail owa autodiscover ftp vpn sslvpn gateway api app portal
login sso idp iam identity accounts oauth auth adfs admin intranet hr
sap erp crm support help status grafana kibana docs wiki jira jenkins
gitlab dev test staging stg qa uat sandbox preprod preview careers jobs
eapps old legacy beta tender suppliers procurement
```

---

## 3. WHOIS / RDAP

```bash
whois target.example
curl -sk "https://rdap.org/domain/${D}" | jq .
```

What to extract: registrant org/email, registrar (pivot for related domains), created/updated dates (bulk registration patterns), nameservers (NS reuse pivot), status flags.

---

## 4. DNS Record Catalog

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
