---
name: analysis-and-reporting
description: "Endpoint interest scoring (0–100), mobile app ownership confidence, attack-path hint patterns (27 templates), severity decision matrix (80+ examples), AI-assisted OSINT, archiving/evidence, automation, sidecar coordination, tooling quick-install, and sector-specific notes."
version: 1.0.0
triggers:
  - endpoint interest score
  - finding severity
  - severity decision matrix
  - attack path hint
  - mobile app ownership
  - mobile recon
  - AI-assisted OSINT
  - evidence preservation
  - archiving
  - automation workflow
  - cross module sidecar
  - tooling install
  - sector specific recon
  - healthcare DICOM
  - finance SWIFT
  - ICS SCADA
  - CVE prioritization
  - EPSS scoring
  - vulnerability prioritization
  - reporting
---

# Analysis & Reporting

> Sub-skill of `offensive-osint`. Load `osint-methodology` for pipeline and triage context.
> Authorized targets only.

---

## 1. Endpoint Interest Score — 0–100 Rubric

For every classified API endpoint, apply this rubric:

| Signal | Points | Conditions |
|---|---|---|
| **Unauth write** | +40 | POST/PUT/DELETE/PATCH returns 200/201/202/204 anonymously |
| **Open GraphQL introspection** | +35 | `__schema` returns full type list anonymously |
| **Verb tampering bypass** | +30 | OPTIONS reveals method not documented; accessible |
| **Reflected CORS + credentials** | +25 | `Access-Control-Allow-Origin` reflects Origin AND `Access-Control-Allow-Credentials: true` |
| **Sensitive keyword in path** | +20 | `admin`, `internal`, `debug`, `user`, `password`, `token`, `key`, `export`, `upload`, `backup`, `config`, `secret`, `private`, `delete`, `purge`, `wipe` |
| **Schema leak in error** | +20 | Stack trace, ORM error class, framework signature in response |
| **API key in URL** | +15 | `api_key=`, `apikey=`, `token=`, `access_token=` in query string |
| **Wildcard CORS** | +10 | `Access-Control-Allow-Origin: *` |
| **Missing rate-limit headers** | +10 | No `RateLimit-*` / `X-RateLimit-*` after rapid requests |

**Thresholds:**

| Score | Severity |
|---|---|
| ≥ 90 | **CRITICAL** |
| 70–89 | **HIGH** |
| 50–69 | MEDIUM |
| 25–49 | LOW |
| < 25 | INFO |

For score ≥ 70, attach an `attack_path_hint` in evidence (see §3).

---

## 2. Mobile App Ownership Confidence — 0–100 Rubric

Before deep APK static analysis, score whether the app belongs to the target. **Threshold: ≥70 = accept.**

| Signal | Points |
|---|---|
| Package reverse-DNS matches target domain (`com.acme.android` ↔ `acme.com`) | +40 |
| Developer email is `<anything>@<target-domain>` | +25 |
| Developer website URL is the target domain | +20 |
| App name contains a brand keyword from operator brand list | +10 |
| App has ≥ 20 reviews | +5 |

Apps below threshold: tag `mobile_review_pending`. Operator can lower threshold with `--mobile-ownership-threshold 50`.

---

## 3. Attack-Path Hint Patterns — 27 Templates

When emitting a HIGH/CRITICAL finding (score ≥ 70), include a one-sentence `attack_path_hint`:

| Trigger | Attack-path hint |
|---|---|
| Unauth POST / PUT / DELETE | *"Unauthenticated {method} {path} — try IDOR + privilege escalation; check whether numeric IDs are sequential or guessable."* |
| Open GraphQL introspection | *"Open GraphQL introspection on {path} — enumerate mutations, look for `createUser`, `setRole`, `transferFunds`-shaped names; pivot to broken-auth or business-logic flaws."* |
| Reflected CORS + creds | *"Reflected CORS with credentials on {path} — host CSRF page on attacker-controlled origin; victim's browser will leak {sensitive-data-hint}."* |
| Wildcard CORS + sensitive | *"Wildcard CORS on {path} returning user-tied data — exfiltrate via cross-origin fetch from any page victim visits."* |
| API key in URL | *"API key in URL `?{param}=...` — token leaks to access logs, browser history, Referer headers, third-party CDNs. Check Wayback / Google for cached copies."* |
| Schema leak in error | *"Schema leak in error response — framework signature `{framework}` exposed; map to known {framework} vulns and craft targeted payloads."* |
| Sensitive keyword | *"Path contains '{keyword}' — review for direct object reference, mass-assignment, or hidden admin functionality."* |
| Open RTDB Firebase | *"Open Firebase RTDB at https://{project}.firebaseio.com/.json — read everything, then test write at `/<random-key>.json` with PUT to gauge ACL scope."* |
| Listable cloud bucket | *"Listable {provider} bucket `{bucket}` — recursive object listing + content-type analysis; look for backups, logs, customer data, AWS keys in JSON configs."* |
| .git exposed | *"Exposed .git/config on {host} — reconstruct repository with git-dumper or githacker; full source history."* |
| .env exposed | *"Exposed .env on {host} — grep for `_KEY`, `_SECRET`, `_TOKEN`, `_PASSWORD`; validate all credentials read-only."* |
| /actuator/env | *"Spring Boot /actuator/env exposed — dump environment variables; look for `spring.datasource.password`, JWT secrets, cloud creds."* |
| /actuator/heapdump | *"Spring Boot /actuator/heapdump exposed — download HPROF, run `jhat` or VisualVM, search for cleartext secrets in heap strings."* |
| Open Elasticsearch | *"Open Elasticsearch on {host}:9200 — `/_cat/indices?v` for index list; sample documents from each high-value index."* |
| Open Redis | *"Open Redis on {host}:6379 — `INFO`, `KEYS *`, sample reads; check write access via `CONFIG SET` then `BGSAVE` to write `authorized_keys`."* |
| Open MongoDB | *"Open MongoDB on {host}:27017 — `show dbs`, `show collections`, sample find queries; check user collection for password hashes."* |
| Subdomain takeover | *"CNAME for {host} points to unclaimed {provider} resource → register `{takeover-target}` on {provider} to serve content from {host}."* |
| Open kubelet | *"Open kubelet on {host}:10250 — `GET /pods` to list; `POST /run/<ns>/<pod>/<container>` for in-container exec without K8s API auth."* |
| Open etcd | *"Open etcd on {host}:2379 — `etcdctl get / --prefix --keys-only` for full cluster state; secrets stored under `/registry/secrets/`."* |
| K8s API anonymous | *"Kubernetes API on {host}:6443 with anonymous-auth — `kubectl --server=https://{host}:6443 --insecure-skip-tls-verify get pods --all-namespaces`."* |
| Cloud function URL unauth | *"AWS Lambda Function URL at {url} accessible anonymously — review IAM auth configuration; audit input validation aggressively."* |
| npm typosquat candidate | *"Package name `{candidate}` is unregistered + similar to target's `{official}` — typosquat takeover risk; advise client to defensively register."* |
| DMARC missing/permissive | *"DMARC `p=none` on {domain} — spoof of `{anything}@{domain}` deliverable; recommend enforcement to `p=quarantine` or `p=reject`."* |
| Live AI API key | *"Validated `sk-{provider}-...` key with model access — quota cost can be exfiltrated; rotate immediately + audit usage logs in provider console."* |
| Public Slack invite link | *"Slack workspace invite link discoverable via search engine — anyone can join the workspace without approval."* |
| Open Docker registry | *"Public Docker registry at {host} — `GET /v2/_catalog` lists images; pull and scan layers for embedded secrets."* |
| Sourcemap with sourcesContent[] | *"Sourcemap on {host} includes embedded original sources — full frontend code reconstructable; grep for inline secrets and internal hostnames."* |

---

## 4. Severity Decision Matrix — Worked Examples (selected)

| Finding | Severity | Why |
|---|---|---|
| `/.git/config` reachable on prod | **CRITICAL** | Full source-code + secret history |
| `/.env` reachable on prod | **CRITICAL** | Plaintext creds (DB, cloud, API) |
| Open Firebase RTDB returning data | **CRITICAL** | All app data readable; often writable |
| Listable S3 bucket containing PII | **CRITICAL** | Direct data exfil |
| Spring Boot `/actuator/env` exposed | **CRITICAL** | DB creds, JWT secrets, cloud keys in env |
| Open Elasticsearch | **CRITICAL** | Full data reads; often writable |
| Open MongoDB (no auth) | **CRITICAL** | Full data + password hashes |
| Open Redis (no AUTH) | **CRITICAL** | Write `authorized_keys` → SSH foothold |
| Open Docker API (port 2375) | **CRITICAL** | Container/host takeover |
| Public PMAK validated live (broad scope) | **CRITICAL** | Full Postman + all team workspaces |
| Open kubelet on 10250 | **CRITICAL** | Pod exec without K8s API auth |
| Open etcd on 2379 | **CRITICAL** | Cluster state + secrets |
| Live Anthropic / OpenAI API key | **CRITICAL** | Quota cost + potential PII in past responses |
| Live npm token with `publish` scope | **CRITICAL** | Supply-chain compromise of all maintained packages |
| `android:debuggable=true` on prod app | **CRITICAL** | Production debug-build → full client compromise |
| Decommissioned legacy mail + breach + cloud migration | **CRITICAL** | SSO_EXPOSURE; stolen passwords survived migration via reuse |
| Heartbleed (CVE-2014-0160) detected | **CRITICAL** | Memory disclosure including session tokens |
| Live AWS root access key | **CRITICAL** | Full account compromise |
| Citrix Netscaler with KEV CVE | **CRITICAL** | Patch immediately; actively exploited |
| FortiGate with CVE-2024-21762 | **CRITICAL** | KEV; auth bypass + RCE |
| PaloAlto GlobalProtect with CVE-2024-3400 | **CRITICAL** | KEV; pre-auth RCE |
| GitLab self-hosted with CVE-2021-22205 | **CRITICAL** | KEV; ExifTool RCE |
| Live GitHub PAT found in JS bundle | HIGH | Repo write access (depends on scope) |
| Live Slack token in pastebin | HIGH | Workspace data + history |
| Open GraphQL introspection on prod | HIGH | Full schema → mutations |
| Subdomain takeover possible | HIGH | Trusted-domain phishing surface |
| Reflected CORS with credentials | HIGH | CSRF-via-CORS |
| phpinfo.php reachable on prod | HIGH | Discloses paths, env vars, modules |
| Jenkins script console accessible | HIGH | Groovy script execution = RCE |
| K8s API on 6443 with anonymous-auth | HIGH | Cluster recon; sometimes pod exec |
| F5 BIG-IP TMUI accessible | HIGH | TMUI = admin panel |
| Missing HSTS on `/login` | HIGH (escalated from MED) | Login pages must enforce HSTS |
| Public Slack invite link discoverable | HIGH | Anyone joins workspace |
| Sourcemap (`.js.map`) on prod | HIGH | Frontend source disclosure |
| Missing HSTS on standard pages | MEDIUM | Hardening gap |
| Missing CSP | MEDIUM | XSS impact mitigation gone |
| Internal IP / K8s service DNS in JS | MEDIUM | Internal topology disclosure |
| Apache `/server-status` reachable | MEDIUM | Live request visibility |
| Public-facing intranet without VPN | MEDIUM | Staff portal exposed |
| Staging / preprod publicly resolvable | MEDIUM | Often weaker auth + debug endpoints |
| DMARC `p=none` on production | MEDIUM | Spoof feasible |
| TLS 1.0/1.1 supported on prod | MEDIUM | PCI-DSS compliance gap |
| Slack webhook URL leaked | MEDIUM | Send to channel; social-eng vector |
| `android:allowBackup=true` (no whitelist) | MEDIUM | App data exfil via `adb backup` |
| Missing `X-Frame-Options` | LOW | Clickjacking |
| `.DS_Store` exposed | LOW | Directory listing of dev's machine |
| Cert about to expire (<30 days) | LOW | Operational risk |
| `vpn.<domain>` resolves + vendor unknown | INFO | Escalate to HIGH-CRIT after KEV CVE match |
| Domain in breach with 0 named accounts | INFO | Contextual only |

---

## 5. AI-Assisted OSINT

> **Warning:** Never paste PII, sensitive IOCs, or unique pivots into cloud LLMs.

| Tool | Strength |
|------|---------|
| [ChatGPT](https://chat.openai.com/) (paid) | Log parsing, dataset analysis, Code Interpreter for CSV/JSON |
| [Claude](https://claude.ai/) (paid) | 200K-token context for large doc dumps + report synthesis |
| [Gemini](https://gemini.google.com/) | Long-context; Deep Research mode with citations |
| [Perplexity Pro](https://www.perplexity.ai/) | Real-time web search + reasoning |

**Local / privacy-preserving:** [Ollama](https://ollama.com/), [LM Studio](https://lmstudio.ai/).

---

## 6. Archiving & Evidence Preservation

- [archive.today](https://archive.today/) — one-page archiver + screenshot.
- [URLScan.io](https://urlscan.io/) — webpage scan + resource map.
- [ArchiveBox](https://archivebox.io/) — self-hosted (HTML, PDF, screenshots).
- Wayback SavePageNow API v3 — on-demand archiving with job IDs.

**Evidence handling:** URL + UTC timestamp + PNG + WARC/SingleFileZ archive, SHA-256 hash all downloads, separate work profiles per case, store evidence read-only, JSONL run logs with `run_id` + tool versions.

```bash
mkdir -p evidence/$(date -u +%Y%m%d)
T="https://target.example"; P="/actuator/env"; TS=$(date -u +%Y%m%dT%H%M%SZ)
SAFE_NAME=$(echo "${T}${P}" | tr '/:' '_')
curl -sk -m 10 "$T$P" -o "evidence/$(date -u +%Y%m%d)/${TS}_${SAFE_NAME}.body" \
  -D "evidence/$(date -u +%Y%m%d)/${TS}_${SAFE_NAME}.headers"
sha256sum "evidence/$(date -u +%Y%m%d)/${TS}_${SAFE_NAME}".* > "evidence/$(date -u +%Y%m%d)/${TS}_${SAFE_NAME}.sha256"
```

---

## 7. Cross-Module Sidecar Coordination

Each module writes a sidecar JSON when it finishes:
- `<scan>/mobile_endpoints.json` — endpoints + hostnames from APK static analysis.
- `<scan>/secrets_sidecar.json` — hostnames + endpoints + Firebase project IDs.
- `<scan>/sso_tenants.json` — discovered IdP tenants for breach correlation.

Downstream modules check for sidecars on start; if present, ingest.

**Sidecar shape:**
```json
{
  "endpoints": [{"method": "GET", "url": "https://api.acme.com/v1/users", "source": "apk:com.acme.android"}],
  "hostnames": ["api.acme.com"],
  "firebase_project_ids": ["acme-prod-12345"]
}
```

---

## 8. Tooling Quick-Install

```bash
# Subdomain enumeration
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/d3mondev/puredns/v2@latest

# HTTP probing & enrichment
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/sensepost/gowitness@latest

# Vulnerability scanning
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -ut
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Content discovery
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest

# JS / endpoint extraction
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/subjs@latest

# Secret scanners
go install github.com/trufflesecurity/trufflehog@latest
go install github.com/zricethezav/gitleaks/v8@latest

# Wayback
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

# Cloud
pip install awscli s3scanner sslyze

# Mobile
pip install apkleaks androguard

# Misc utilities
go install github.com/tomnomnom/anew@latest
sudo apt install jq
```

**Full PD toolkit:** `go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest && pdtm -install-all`

---

## 9. Sector-Specific Recon Notes

### 9.1 Healthcare
- **DICOM** (medical imaging) — port 11112, sometimes 4242.
- **HL7 FHIR** — `/fhir/R4/<resource>` paths; OAuth / SMART-on-FHIR posture varies widely.
- **PACS/EHR vendors:** Epic (`*.epic.com`), Cerner/Oracle Health, Meditech.
- Severity escalation: any PHI exposure → CRITICAL; HL7/DICOM open without auth → CRITICAL.

### 9.2 Finance
- **SWIFT terminals** — internal-only; if external-facing → CRITICAL.
- **FIX protocol** (electronic trading) — port 9876; cleartext.
- **Banking middleware:** Temenos T24, Finacle, FIS, Jack Henry, Fiserv.
- Severity escalation: account/balance data exposure → CRITICAL; SWIFT exposure → CRITICAL.

### 9.3 ICS / SCADA / OT

> **Caution:** even passive scanning can disrupt ICS. Do NOT actively probe without explicit RoE + OT team coordination.

- **Modbus** — port 502 (TCP). **BACnet** — port 47808 (UDP). **Siemens S7** — port 102.
- Sources: Shodan ICS-specific filters (`port:502`, `tag:ics`), Censys, Onyphe.

### 9.4 IoT / Consumer / SOHO
- **MQTT** — port 1883 (cleartext), 8883 (TLS). Topics often readable without auth.
- **Camera DVRs/NVRs** — Hikvision, Dahua, Axis. Multiple CVEs.

### 9.5 Government
- **FedRAMP / FISMA / DoD CMMC** — defensive posture generally above baseline.
- **OSINT sources:** USAspending.gov, SAM.gov (procurement).
- Severity: as high or higher than commercial; political sensitivity on top.
