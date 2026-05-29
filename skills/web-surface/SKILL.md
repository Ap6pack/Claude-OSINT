---
name: web-surface
description: "Probe paths, endpoint scoring, email security analysis, vendor fingerprints, documentation leak hunting, and API endpoint references for authorized web-surface enumeration."
version: 1.0.0
triggers:
  - swagger discovery
  - openapi discovery
  - graphql introspection
  - endpoint enumeration
  - email security analysis
  - SPF DMARC DKIM
  - vendor product fingerprints
  - Citrix Netscaler
  - F5 BIG-IP
  - Pulse Secure
  - FortiGate
  - PaloAlto GlobalProtect
  - Cisco AnyConnect
  - VMware vCenter
  - Wayback CDX
  - postman workspace
  - stack exchange OSINT
  - subdomain takeover
  - documentation leak
---

# Web Surface Enumeration

> Sub-skill of `offensive-osint`. Load `osint-methodology` for pipeline and triage context.
> Authorized targets only.

---

## BEHAVIORAL CONTRACT

**When triggered:** Web surface enumeration, Swagger/OpenAPI/GraphQL discovery, endpoint probing, email security analysis, vendor fingerprinting, documentation leak hunting, or subdomain takeover assessment is needed.

**Execute:**
1. For each alive webapp, probe the Swagger/OpenAPI paths (§1) and GraphQL paths (§2).
2. Check high-risk ports (§3) against Shodan/naabu results.
3. Audit security headers (§4) — escalate per sensitive-path rules.
4. Run always-on HTTP checks (§5) with listed match logic.
5. Audit email security posture (§6): parse SPF/DMARC/DKIM, map severity, infer SaaS tenants from TXT records.
6. Fingerprint vendor products (§7) — cross-reference with CISA KEV for severity escalation.
7. Check documentation/wiki leak paths (§8).
8. Query API endpoints (§9) for Wayback CDX, Postman workspace search, and Stack Exchange OSINT.
9. For each finding, assign severity per the inline tables and emit per `osint-methodology` §3 schema.

**Output:** Per-finding results using `osint-methodology` §3 schema.

**Severity rules:** Swagger/OpenAPI without auth = HIGH. GraphQL introspection without auth = HIGH. Vendor product matching KEV CVE = CRITICAL. Missing HSTS on login page = HIGH (escalated from MEDIUM).

**Gating rules:** Authorized targets only. Detection-aware: if 429s or WAF blocks appear during probing, follow `osint-methodology` §6.4 back-off ladder.

**Chain to:** Load `secrets-and-dorks` for secret scanning of discovered JS/API specs. Load `analysis-and-reporting` for endpoint interest scoring (score >= 70 gets attack-path hint). Feed discovered email security gaps to `people-breach-intel`.

---

## 1. Swagger / OpenAPI Discovery — 28 Paths

Probe each on every alive webapp. GET (or HEAD if rate-limited).

```
swagger.json           swagger.yaml
swagger/v1/swagger.json    swagger/v2/swagger.json
swagger-ui.html        swagger-ui/
swagger-resources      api-docs
api-docs.json          api/swagger
api/swagger.json       api/swagger-ui.html
api/v1/swagger.json    api/v2/swagger.json
api/v3/api-docs        v2/api-docs
v3/api-docs            openapi.json
openapi.yaml           openapi/v1
openapi/v3             docs
redoc                  rapidoc
api/docs               api/documentation
.well-known/openapi
```

Reachable Swagger/OpenAPI spec without auth → **HIGH** `LEAKY_API_SPEC`.

---

## 2. GraphQL Discovery — 13 Paths

```
graphql    graphiql    api/graphql    v1/graphql    v2/graphql
query      api/query   gql            altair
playground subscriptions graphql/console api/v1/graphql
```

**Standard introspection POST body:**
```json
{"operationName":"IntrospectionQuery","query":"query IntrospectionQuery { __schema { types { name kind fields { name type { name kind } } } queryType { name } mutationType { name } subscriptionType { name } } }"}
```

- Introspection without auth → **HIGH** `OPEN_GRAPHQL_API`.
- Field-suggestion enumeration (server "did you mean" on typo'd fields) → MEDIUM (re-derive partial schema even when introspection is disabled).
- Batched queries (`[...]` request body) → MEDIUM (rate-limit bypass).

---

## 3. High-Risk Ports — Selected (35 total)

| Port | Service | Severity | Why it matters |
|---|---|---|---|
| 445 | SMB | **CRITICAL** | EternalBlue, SMB relay |
| 2375 | Docker API (unencrypted) | **CRITICAL** | Unauthenticated container takeover |
| 3389 | RDP | **CRITICAL** | BlueKeep / DejaBlue |
| 6379 | Redis | **CRITICAL** | No auth default; write authorized_keys |
| 9200 | Elasticsearch | **CRITICAL** | Typically no auth |
| 27017 | MongoDB | **CRITICAL** | No auth by default |
| 22 | SSH | LOW | Banner; brute-force surface |
| 161 | SNMP | HIGH | Community strings; full device enum |
| 389 | LDAP | HIGH | Anonymous bind = full directory dump |
| 1433 | MSSQL | HIGH | Brute-force; xp_cmdshell |
| 2049 | NFS | HIGH | World-readable exports |
| 5432 | PostgreSQL | HIGH | Brute-force; default postgres:postgres |
| 5601 | Kibana | HIGH | Often unauthenticated |
| 8888 | Jupyter | HIGH | Interactive shell |

---

## 4. Missing Security Headers — 6 Findings

| Header | Severity (default) | Severity (sensitive path) |
|---|---|---|
| `Strict-Transport-Security` | MEDIUM | **HIGH** (for /login, /admin, /sso) |
| `Content-Security-Policy` | MEDIUM | MEDIUM |
| `X-Frame-Options` | LOW | LOW |
| `X-Content-Type-Options` | LOW | LOW |
| `Referrer-Policy` | INFO | INFO |
| `Permissions-Policy` | INFO | INFO |

---

## 5. Always-On HTTP Checks — 15 Paths

| Path | Finding | Severity | Match logic |
|---|---|---|---|
| `/.git/config` | Exposed `.git` | **CRITICAL** | Body contains `[core]`, `repositoryformatversion` |
| `/.env` | Exposed `.env` | **CRITICAL** | `^\s*[A-Z_][A-Z0-9_]*\s*=` |
| `/actuator/env` | Spring Boot env | **CRITICAL** | `"propertySources"` |
| `/actuator/heapdump` | Spring Boot heap | **CRITICAL** | HPROF bytes / large binary |
| `/_cat/indices` | Elasticsearch open | HIGH | Returns index list |
| `/phpinfo.php` | phpinfo() leak | HIGH | `phpinfo()`, `PHP Version` |
| `/console` | Jenkins console | HIGH | `Jenkins`/`Script Console` |
| `/manager/html` | Tomcat Manager | HIGH | `Tomcat Web Application Manager` |
| `/.git/HEAD` | Exposed HEAD | HIGH | Body matches `^ref:\s` |
| `/server-status` | Apache status | MEDIUM | `Apache Server Status` |
| `/server-info` | Apache info | MEDIUM | `Apache Server Information` |
| `/info.php` | phpinfo (alt) | HIGH | Same as phpinfo.php |
| `/.DS_Store` | DS_Store | LOW | Byte signature `\x00\x00\x00\x01Bud1` |
| `/wp-admin/install.php` | WP orphan install | LOW | `WordPress Installation` |
| `/.well-known/security.txt` | Disclosure policy | INFO | Parse contact + policy |

Also parse `/robots.txt` `Disallow:` paths as next-tier wordlist.

---

## 6. Email Security Analysis (SPF/DMARC/DKIM/BIMI/MTA-STS)

```bash
D="target.example"
dig +short TXT "$D" | grep -i 'v=spf1'
dig +short TXT "_dmarc.${D}"
dig +short MX "${D}"
```

**SPF parsing:** `-all` = strict; `~all` = softfail (spoofs land in spam); `?all` = permissive.
SPF `include:` reveals SaaS tenants: `_spf.google.com` → Google Workspace; `spf.protection.outlook.com` → M365; `sendgrid.net` → SendGrid; `_spf.atlassian.net` → Atlassian Cloud.

**DMARC severity:** `p=none` → MEDIUM; `p=quarantine pct<100` → LOW; `p=reject` + strict alignment → no finding.

**DKIM common selectors:**
```bash
for selector in default google selector1 selector2 mail email k1 dkim s1 s2 amazonses 20240101 mailchimp sendgrid mxvault; do
  dig +short TXT "${selector}._domainkey.${D}"
done
```

**PowerShell parallel:**
```powershell
$D = "target.example"
"=== SPF ==="; (Resolve-DnsName $D -Type TXT -EA SilentlyContinue | ? { $_.Strings -match 'v=spf1' }).Strings
"=== DMARC ==="; (Resolve-DnsName "_dmarc.$D" -Type TXT -EA SilentlyContinue).Strings
"=== MX ==="; Resolve-DnsName $D -Type MX -EA SilentlyContinue | Select NameExchange,Preference
```

---

## 7. Vendor Product Fingerprints

| Product | Fingerprint paths | KEV CVEs |
|---|---|---|
| **Citrix Netscaler** | `/vpn/index.html`, `/logon/LogonPoint/tmindex.html` | CVE-2023-3519, CVE-2019-19781 |
| **F5 BIG-IP TMUI** | `/tmui/login.jsp`, `/mgmt/tm/sys/` | CVE-2022-1388, CVE-2023-46747 |
| **Cisco AnyConnect** | `/+CSCOE+/`, `/CSCOE/index.html`, `/webvpn.html` | CVE-2020-3452 |
| **Pulse Secure / Ivanti** | `/dana-na/auth/url_default/welcome.cgi` | CVE-2024-21887, CVE-2023-46805 |
| **FortiGate** | `/remote/login`, `/remote/info`, `/api/v2/` | CVE-2022-42475, CVE-2024-21762 |
| **PaloAlto GlobalProtect** | `/global-protect/`, `/api/?type=keygen` | CVE-2024-3400 |
| **VMware vCenter** | `/sdk`, `/vsphere-client/`, `/websso/SAML2/` | CVE-2021-21972, CVE-2021-22005 |
| **MS Exchange OWA** | `/owa/`, `/ews/exchange.asmx`, `/ecp/` | ProxyShell, ProxyLogon, ProxyNotShell |
| **Atlassian Confluence** | `/confluence/`, `/login.action` | CVE-2022-26134, CVE-2023-22515 |
| **GitLab self-hosted** | `/users/sign_in`, `/help` | CVE-2021-22205 |
| **TeamCity** | `/login.html` | CVE-2024-27198 |
| **ConnectWise ScreenConnect** | `/SetupWizard.aspx` | CVE-2024-1709 |

**Nuclei fingerprint:**
```bash
nuclei -u $T -t http/technologies/ -severity info,low,medium,high,critical
nuclei -u $T -t http/cves/ -severity high,critical -etags fuzz
```

---

## 8. Documentation / Wiki Leak Paths

| Platform | URL pattern |
|---|---|
| Notion | `*.notion.site/<slug>` |
| Confluence Cloud | `<target>.atlassian.net/wiki/spaces/` |
| Trello | `https://trello.com/b/<id>/<slug>` |
| Miro | `https://miro.com/app/board/<id>/` |
| GitBook | `<workspace>.gitbook.io/<book>/` |
| ReadTheDocs | `<project>.readthedocs.io` |

**Dorks:**
```
site:notion.site "{target}"
site:trello.com "{target}"
site:miro.com "{target}"
site:atlassian.net "{target}"
```

---

## 9. API Endpoints

| Service | Endpoint | Method |
|---|---|---|
| Wayback CDX | `https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=timestamp,original` | GET |
| Postman search | `https://www.postman.com/_api/ws/proxy` | POST (body: `{"service":"search","method":"POST","path":"/search-all","body":{"queryIndices":["collaboration.workspace"],"queryText":"{domain}","size":100}}`) |
| StackExchange | `https://api.stackexchange.com/2.3/search/advanced?site=stackoverflow.com&q={domain}&filter=withbody` | GET |
