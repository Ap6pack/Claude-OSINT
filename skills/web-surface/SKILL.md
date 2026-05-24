---
name: web-surface
description: "Probe paths, curl one-liners, endpoint scoring, email security analysis, CDN bypass, vendor fingerprints, Postman search, Stack Exchange sweep, SaaS dorks, and Wayback CDX for authorized web-surface enumeration."
version: 1.0.0
triggers:
  - swagger discovery
  - openapi discovery
  - graphql introspection
  - endpoint enumeration
  - copy paste probes
  - curl one-liner
  - email security analysis
  - SPF DMARC DKIM
  - origin discovery
  - CDN bypass
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
  - JS endpoint extraction
---

# Web Surface Enumeration

> Sub-skill of `offensive-osint`. Load `osint-methodology` for pipeline and triage context.
> Authorized targets only.

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

## 6. Copy-Paste Probes (curl one-liners)

```bash
T="https://target.example"

# .git/config (CRITICAL)
curl -sk -m 10 "$T/.git/config" | grep -E '\[core\]|\[remote|repositoryformatversion'

# .env (CRITICAL)
curl -sk -m 10 "$T/.env" | grep -E '^[[:space:]]*[A-Z_][A-Z0-9_]*[[:space:]]*='

# Spring Boot actuator/env (CRITICAL)
curl -sk -m 10 "$T/actuator/env" | grep -E '"propertySources"|systemProperties|systemEnvironment'

# Spring Boot heapdump (CRITICAL)
curl -sk -m 30 "$T/actuator/heapdump" -o /tmp/heap && file /tmp/heap | grep -i 'HPROF\|data'

# Elasticsearch (HIGH)
curl -sk -m 10 "$T/_cat/indices?v"

# Jenkins console (HIGH)
curl -sk -m 10 "$T/script" | grep -iE 'Jenkins|Script Console'

# Tomcat manager — 401 = present+auth-gated; 200 = no auth
curl -sk -m 10 "$T/manager/html" -w '%{http_code}\n' | tail -1

# security.txt (INFO)
curl -sk -m 10 "$T/.well-known/security.txt"
```

**GraphQL introspection:**
```bash
curl -sk -m 15 -X POST "https://target.example/graphql" \
  -H 'Content-Type: application/json' \
  -d '{"operationName":"IntrospectionQuery","query":"query IntrospectionQuery { __schema { types { name kind } queryType { name } mutationType { name } } }"}' | jq '.data.__schema.types | length'
```

**SSO subdomain prefixes:**
```bash
D="target.example"
for prefix in auth login sso idp iam identity accounts oauth; do
  echo "=== ${prefix}.${D} ===" && \
  curl -sk -m 10 "https://${prefix}.${D}/.well-known/openid-configuration" -o /dev/null -w '%{http_code}\n'
done
```

**Cloud bucket probes:**
```bash
B="candidate-bucket-name"
curl -sk -m 10 -I "https://${B}.s3.amazonaws.com/" -w 'STATUS:%{http_code}\n' | head -20
curl -sk -m 10 "https://${B}.s3.amazonaws.com/?list-type=2" | head -50
curl -sk -m 10 -I "https://${B}.storage.googleapis.com/"
curl -sk -m 10 -I "https://${B}.blob.core.windows.net/"
```

**Bulk probe with httpx:**
```bash
cat subdomains.txt | httpx -sc -title -tech-detect -path /actuator/env,/.git/config,/.env -mc 200,301,403
```

---

## 7. Email Security Analysis (SPF/DMARC/DKIM/BIMI/MTA-STS)

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

## 8. Origin Discovery / CDN Bypass

**DNS history:**
```bash
# Validin (free)
curl -sk "https://app.validin.com/api/axon/${D}/dns" | jq .
```

**Favicon hash (Shodan):**
```bash
python3 -c "
import urllib.request, codecs, mmh3
data = urllib.request.urlopen('https://target.example/favicon.ico').read()
print(mmh3.hash(codecs.encode(data, 'base64')))"
shodan search "http.favicon.hash:<hash>" --fields ip_str,port,org
```

**Host-header probe (validate candidate):**
```bash
CANDIDATE_IP="203.0.113.42"
curl -sk -m 10 -H "Host: target.example.com" "https://${CANDIDATE_IP}/" -o /tmp/candidate.html
diff <(curl -sk -m 10 https://target.example.com/) /tmp/candidate.html | head -50
```

**Auxiliary subdomains that often skip CDN:**
```bash
for sub in mail smtp ftp direct origin origin-www old-www noproxy dev staging stg uat; do
  dig +short A "${sub}.${D}"
done
```

---

## 9. Vendor Product Fingerprints

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

## 10. Documentation / Wiki Leak Paths

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

## 11. Wayback CDX Deep Usage

```bash
D="target.example"
# All URLs
curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*&output=json&fl=timestamp,original&limit=10000"

# JS bundles only (with secret scan)
curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*.js&output=json&fl=timestamp,original&filter=statuscode:200" | \
  jq -r '.[1:][] | "\(.[0]) \(.[1])"'

# Legacy app pivot (when *.js empty for brochure-ware sites)
for ext in asp aspx php jsp cfm; do
  curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*.${ext}&output=json&fl=timestamp,original&filter=statuscode:200&collapse=urlkey&limit=500"
done
```

---

## 12. Postman Public Workspace Search

```bash
curl -sk -m 15 \
  "https://www.postman.com/_api/ws/proxy" \
  -H 'Content-Type: application/json' \
  -H 'X-Entity-Team-Id: 0' \
  -d '{"service":"search","method":"POST","path":"/search-all","body":{"queryIndices":["collaboration.workspace","runtime.collection","runtime.request"],"queryText":"acme.com","size":100,"from":0,"clientTraceId":"","queryAllIndices":false,"domain":"public"}}' | jq '.data[]'
```

Pagination via `from` (0, 100, 200...). Run secret catalog over every env var, pre-request script, and request body extracted.

---

## 13. Stack Exchange OSINT Sweep

```bash
curl -sk "https://api.stackexchange.com/2.3/search/advanced?site=stackoverflow.com&q=target.example&filter=withbody&pagesize=100"
```

Extract code blocks with `<pre><code>([\s\S]*?)</code></pre>`, run secret catalog. Also check: `serverfault.com`, `dba.stackexchange.com`, `devops.stackexchange.com`.

---

## 14. Public SaaS Collaboration Surfaces

```
site:trello.com "{target}"
site:notion.so "{target}"
site:miro.com "{target}"
site:*.atlassian.net "{target}"
site:airtable.com "{target}"
```
