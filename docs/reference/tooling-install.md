# Tooling Quick-Install

> Installation commands for all recommended tools, organized by category.
> Extracted from skill files for clean separation.

---

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

# GraphQL
pip install clairvoyance graphql-cop

# Mobile
pip install apkleaks androguard

# Misc utilities
go install github.com/tomnomnom/anew@latest
sudo apt install jq
```

**Full PD toolkit:** `go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest && pdtm -install-all`

---

