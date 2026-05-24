---
name: cloud-and-infra
description: "Cloud-native service fingerprints, Kubernetes/container exposure, CI/CD platform exposure, TLS deep audit, ASN/BGP, CT monitoring, and reverse DNS sweep for authorized infrastructure recon."
version: 1.0.0
triggers:
  - cloud native fingerprint
  - Lambda function URL
  - Cloud Run
  - kubernetes exposure
  - kubelet
  - etcd
  - CI CD exposure
  - Jenkins recon
  - GitLab self-hosted
  - GitHub Actions secrets
  - TLS deep audit
  - JA3 JA4
  - reverse DNS sweep
  - IPv6 enumeration
  - certificate transparency
  - ASN BGP
  - container registry
  - Docker API
  - Argo CD
---

# Cloud & Infrastructure OSINT

> Sub-skill of `offensive-osint`. Load `osint-methodology` for pipeline and triage context.
> Authorized targets only.

---

## 1. Cloud-Native Service Fingerprints

| Provider | URL pattern | Notes |
|---|---|---|
| **AWS Lambda Function URL** | `*.lambda-url.<region>.on.aws` | Direct invocation; check IAM auth posture |
| **AWS App Runner** | `*.<region>.awsapprunner.com` | Managed container |
| **AWS API Gateway** | `*.execute-api.<region>.amazonaws.com` | REST/HTTP/WebSocket; check authorizer |
| **AWS CloudFront** | `d{14}\.cloudfront\.net` | Distribution; find origin via §16.15 |
| **AWS ALB / ELB** | `*.elb.<region>.amazonaws.com` | Behind = EC2 / ECS |
| **AWS Amplify** | `*.amplifyapp.com` | Static + Lambda backend |
| **Google Cloud Run** | `*.run.app` (and `*.<region>.run.app`) | Check public-vs-IAM auth |
| **Google Cloud Functions** | `*.cloudfunctions.net` | Serverless |
| **Google App Engine** | `*.appspot.com` | Older serverless |
| **Azure Functions** | `*.azurewebsites.net` | Function App; also App Service |
| **Azure Container Apps** | `*.azurecontainerapps.io` | Containers |
| **Vercel** | `*.vercel.app`, `*.now.sh` (legacy) | Frontend + serverless |
| **Netlify** | `*.netlify.app`, `*.netlify.com` | Frontend + functions |
| **Cloudflare Workers** | `*.workers.dev` | Edge functions |
| **Cloudflare Pages** | `*.pages.dev` | Static + functions |
| **Heroku** | `*.herokuapp.com` | Dynos |
| **Render** | `*.onrender.com` | Container/static |
| **Railway** | `*.railway.app` | App platform |
| **DigitalOcean App Platform** | `*.ondigitalocean.app` | Static + container |

**Per-platform checks:**
- Confirm public vs auth-required (HEAD / GET).
- Check CORS posture.
- Lambda Function URLs / Cloud Run / Cloud Functions: anonymous invocation = HIGH finding.
- Static + functions hybrids (Vercel/Netlify): function paths usually `/api/*`; enumerate via JS extraction.

---

## 2. Container & Kubernetes Exposure

| Target | Port | Probe | Severity |
|---|---|---|---|
| **Docker API (unencrypted)** | 2375 | `curl -sk -m 5 http://${IP}:2375/v1.40/info` | CRITICAL |
| **Docker API (TLS)** | 2376 | `curl -sk -m 5 https://${IP}:2376/v1.40/info` | HIGH |
| **Kubernetes API server** | 6443 / 8443 | `curl -sk -m 5 https://${IP}:6443/api` | HIGH if anonymous non-403 |
| **kubelet** | 10250 (HTTPS) | `curl -sk -m 5 https://${IP}:10250/pods` | CRITICAL (no auth = pod exec) |
| **etcd** | 2379 (client) | `curl -sk -m 5 https://${IP}:2379/v2/keys/` | CRITICAL (cluster state + secrets) |
| **Kubernetes Dashboard** | 8001 / 9090 / 30000+ | `curl -sk -m 5 http://${IP}:8001/api/v1/namespaces/kube-system/services/kubernetes-dashboard` | HIGH |
| **kube-controller-manager** | 10257 | `curl https://${IP}:10257/metrics` | MEDIUM |
| **kube-scheduler** | 10259 | `curl https://${IP}:10259/metrics` | MEDIUM |
| **Helm Tiller** (Helm 2, deprecated but found) | 44134 | `helm --host ${IP}:44134 list` | HIGH |

**Container registries to check for leaks:**

| Registry | Search pattern |
|---|---|
| Docker Hub | `https://hub.docker.com/search?q=<target-keyword>&type=image` |
| Quay (Red Hat) | `https://quay.io/search?q=<target-keyword>` |
| GitHub Container Registry | `https://api.github.com/orgs/<org>/packages?package_type=container` |
| Amazon ECR Public | `https://gallery.ecr.aws/?searchTerm=<keyword>` |

**Per-image scan workflow:**
```bash
docker pull <registry>/<image>:<tag>
docker save <image> -o /tmp/img.tar
# Extract layers; run secret catalog over files
docker history <image>   # inspect build args + COPY of secrets
```

---

## 3. CI/CD Platform Exposure

| Platform | Common exposure | Probe |
|---|---|---|
| **Jenkins** | `/script` (Groovy console = RCE if no auth), `/asynchPeople/` | `curl -sk -m 10 "${T}/script"` |
| **GitLab self-hosted** | Version in HTML; `/api/v4/version` | `curl -sk -m 10 "${T}/api/v4/version"` |
| **TeamCity** | `/login.html`; CVE-2024-27198 (KEV) | `curl -sk -m 10 "${T}/login.html" \| grep -i TeamCity` |
| **Argo CD** | `/api/version`; anonymous-auth posture | `curl -sk -m 10 "${T}/api/version"` |
| **Bamboo** | `/rest/api/latest/info` | `curl -sk -m 10 "${T}/rest/api/latest/info"` |
| **Drone CI** | `/api/info` | `curl -sk -m 10 "${T}/api/info"` |
| **Spinnaker** | `/gate/info`, `/applications` | `curl -sk -m 10 "${T}/gate/info"` |

**GitHub Actions secret-leak anti-patterns:**
```yaml
# Anti-pattern: secret echoed to log
run: echo "${{ secrets.MY_API_KEY }}"

# Anti-pattern: pull_request_target with fork code checkout (CVE class)
on: pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # checks out fork code with secrets in env
```

---

## 4. ASN / BGP & Internet Measurement

- [Hurricane Electric BGP Toolkit](https://bgp.he.net/), [RIPEstat](https://stat.ripe.net/), [BGPView](https://bgpview.io/), [PeeringDB](https://www.peeringdb.com/).

**Bulk IP → ASN (fastest options):**
```bash
# Cymru bulk WHOIS (fastest; no key required)
echo -e "begin\nverbose\n8.8.8.8\n1.1.1.1\nend" | nc whois.cymru.com 43

# RIPEstat (free; ~1 req/sec polite)
curl -sk "https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8" | jq '.data'

# bgp.tools (free; light rate-limit)
curl -sk -A "osint-recon/1.0 (contact@example.com)" "https://bgp.tools/api/ip/8.8.8.8" | jq .
```

**Note:** `bgpview.io` API has aggressive rate limits (~1 req/min/IP); not suitable for bulk. Use Cymru for >50 IPs.

---

## 5. Certificates & CT Monitoring

- [crt.sh](https://crt.sh/), [Censys Certificates](https://search.censys.io/certificates), [CertStream](https://certstream.calidog.io/) (real-time CT WebSocket), [Cert Spotter](https://sslmate.com/certspotter).

**Favicon mmh3 hash pivot:**
```bash
python3 -c "
import urllib.request, codecs, mmh3
data = urllib.request.urlopen('https://target.example/favicon.ico').read()
print(mmh3.hash(codecs.encode(data, 'base64')))"
shodan search "http.favicon.hash:<hash>" --fields ip_str,port,org
```

---

## 6. TLS Deep Audit

Beyond cert SAN + JARM — inspect cipher suites, protocols, and config quality.

```bash
# sslyze (most thorough)
pip install sslyze
sslyze --regular target.example:443
sslyze --json_out=tls.json target.example:443

# testssl.sh (thorough + readable)
docker run --rm -ti drwetter/testssl.sh https://target.example
testssl.sh --jsonfile-pretty=tls-report.json target.example:443

# nmap (lighter)
nmap --script ssl-enum-ciphers,ssl-cert -p 443 target.example
```

**Issues to check:**

| Issue | Severity |
|---|---|
| TLS 1.0 / 1.1 supported | MEDIUM (PCI-DSS forbids TLS 1.0) |
| SSL 3.0 / 2.0 supported | HIGH |
| Weak ciphers (RC4, 3DES, CBC modes) | MEDIUM |
| Anonymous DH | HIGH |
| Weak key size (<2048 RSA, <256 ECDSA) | HIGH |
| Heartbleed (CVE-2014-0160) | CRITICAL |
| ROBOT (CVE-2017-13099) | HIGH |
| Ticketbleed (CVE-2016-9244) | HIGH (F5-specific) |
| HSTS not present on /login | HIGH |
| Self-signed cert on production | MEDIUM |
| Expired cert | MEDIUM |

**JA3/JA4 reference databases:**
- [ja3er.com](https://ja3er.com) — JA3 → client-software mapping.
- Shodan `ssl.jarm:<hash>` to find shared infrastructure / origin candidates.

---

## 7. Reverse DNS Sweep & IPv6 Enumeration

```bash
# Single /24
for i in $(seq 1 254); do
  IP="203.0.113.$i"
  PTR=$(dig +short -x $IP)
  [ -n "$PTR" ] && echo "$IP -> $PTR"
done

# Larger range with parallelism
prips 203.0.113.0/22 | xargs -I {} -P 50 sh -c 'PTR=$(dig +short -x {}); [ -n "$PTR" ] && echo "{} -> $PTR"'

# zdns (faster for large ranges)
prips 203.0.113.0/22 | zdns PTR

# masscan + banner-grab
sudo masscan -p80,443 203.0.113.0/22 --rate=1000 --banners -oX masscan.xml
```

**IPv6 enumeration:**
```bash
# AAAA records for every discovered subdomain
for sub in $(cat all-subs.txt); do
  AAAA=$(dig +short AAAA $sub)
  [ -n "$AAAA" ] && echo "$sub -> $AAAA"
done
# IPv6 brute-force is infeasible (2^64 host bits); instead: extract prefixes from ASN allocation
whois -h whois.cymru.com " -v target.example.com"
```

**BGP route observation:**
- [RouteViews](http://archive.routeviews.org/) — historical BGP routing table snapshots.
- [RIPE RIS](https://ris.ripe.net/) — route collectors.
