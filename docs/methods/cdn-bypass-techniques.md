# CDN Bypass & Origin Discovery Techniques

> Human-operator reference. Origin discovery techniques for bypassing CDN/WAF layers.
> Extracted from skill files for clean separation.

---

## DNS History

```bash
# Validin (free)
curl -sk "https://app.validin.com/api/axon/${D}/dns" | jq .
```

---

## Favicon Hash (Shodan)

```bash
python3 -c "
import urllib.request, codecs, mmh3
data = urllib.request.urlopen('https://target.example/favicon.ico').read()
print(mmh3.hash(codecs.encode(data, 'base64')))"
shodan search "http.favicon.hash:<hash>" --fields ip_str,port,org
```

---

## Host-Header Probe (validate candidate)

```bash
CANDIDATE_IP="203.0.113.42"
curl -sk -m 10 -H "Host: target.example.com" "https://${CANDIDATE_IP}/" -o /tmp/candidate.html
diff <(curl -sk -m 10 https://target.example.com/) /tmp/candidate.html | head -50
```

---

## Auxiliary Subdomains That Often Skip CDN

```bash
for sub in mail smtp ftp direct origin origin-www old-www noproxy dev staging stg uat; do
  dig +short A "${sub}.${D}"
done
```

---

