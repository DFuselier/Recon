# asm_recon.py -- Light-Active Attack Surface Reconnaissance

**Script tier:** Light-Active Recon  
**Based on:** Enterprise Financial Services ASM SOP v1.0  
**Companion scripts:** `asm_active.py` (future -- port scanning, CVE testing, exploit templates)

> **Written authorization required.** Even though every action here simulates normal internet
> traffic, you are still directing reconnaissance at assets belonging to another party.
> Ensure written authorization from an appropriate executive before use.

---

## Philosophy

Every action in this script is indistinguishable from normal internet activity:

- HTTP/S requests are identical to a browser visiting a page
- DNS queries go through public resolvers, not the target's nameservers directly
- No packets are crafted or sent directly to target ports
- No credentials are tested, no vulnerabilities are exploited
- External APIs (Shodan, Censys, crt.sh) are queried, not the target itself

This makes the script appropriate for:
- Pre-authorization reconnaissance and OSINT during deal due diligence
- Continuous monitoring programs where a low-noise footprint matters
- M&A day-zero assessments where authorization scope is still being defined
- Any situation where you want actionable intelligence without generating scanner signatures in the target's logs

---

## What Was Removed (vs asm_enterprise.py) and Why

These tools are intentionally excluded and saved for `asm_active.py`:

| Removed | Reason |
|---|---|
| **masscan** | Raw TCP SYN port scanner. Generates crafted packets with no equivalent in normal user traffic. Immediately detectable by any IDS/firewall. |
| **nmap (all variants)** | Port scanner with service version probing and NSE scripts. Service fingerprinting sends probes specifically designed to elicit version disclosures -- not normal browser behavior. |
| **puredns bruteforce** | Mass DNS brute-force generates thousands of queries to subdomain permutations. Produces an anomalous query volume that any DNS monitoring tool would flag. |
| **massdns PTR bulk sweep** | Sweeps entire IP ranges with reverse-DNS queries. The volume and pattern are characteristic of a scanner, not a user. |
| **nuclei cves/** | Actively tests target services for CVE exploitability. These templates send specific payloads that only make sense if you are trying to exploit a vulnerability. |
| **nuclei default-logins/** | Credential brute-forcing. No interpretation as normal traffic exists. |
| **nuclei misconfiguration/** | Many templates send intrusive probes beyond what a browser would issue -- targeted path guessing at volume. |
| **nuclei exposed-panels/** | Enumerates admin interfaces with volume path probing. |
| **nuclei cloud/** | Mixed -- several templates test for authenticated cloud misconfigurations. |

---

## What Was Kept and Why

| Kept | Reason |
|---|---|
| **crt.sh, Shodan, Censys, ARIN, ipinfo.io, RADB, Wayback, HIBP, CISA KEV** | Pure passive read-only queries to trusted third-party services. Zero contact with target infrastructure. |
| **subfinder, amass (passive)** | Query third-party DNS aggregators and certificate databases -- no direct contact with target nameservers. |
| **AXFR zone transfer** | Standard DNS protocol request. Any DNS client can attempt this; refusal is the expected response from properly configured servers. The attempt itself is a valid DNS message. |
| **puredns resolve** | Resolves a list of known subdomains via public resolvers. Unlike bruteforce, this does not generate novel query names -- it simply resolves subdomains you already discovered from CT logs. |
| **dnsx** | DNS record lookups (A, CNAME, MX, TXT, NS) via public resolvers. Identical to `dig`. |
| **httpx** | HTTP GET requests to discovered hosts. A browser visiting a website is functionally identical. |
| **tlsx** | TLS handshakes to HTTPS hosts. Every browser connecting to HTTPS does this. |
| **whatweb** | HTTP requests that read response headers and body. Equivalent to curl with various User-Agent strings. |
| **nuclei takeovers/** | Reads server response bodies to fingerprint dangling CNAME indicators. Equivalent to `curl <url>` and reading the response. |
| **nuclei technologies/** | Fingerprints technology stack from response headers and body content. Equivalent to visiting the page and inspecting the source. |
| **nuclei exposures/configs/** | Checks if publicly accessible config files (`.env`, `.git/config`, `phpinfo.php`) exist by making HTTP GET requests to known paths. Equivalent to `curl https://target/.env`. These files should never be publicly accessible -- their presence is the finding. |
| **nuclei exposures/tokens/** | Reads server responses and JavaScript files for accidentally embedded secrets. Reads what the server serves to anyone. |
| **subjack** | Makes HTTP requests to discovered subdomains to fingerprint takeover-eligible responses. Equivalent to `curl` on each subdomain. |
| **gau** | Queries Wayback Machine, CommonCrawl, and URLScan archives for historically known URLs. These are third-party archives, not the target. |
| **trufflehog** | Scans GitHub repos (github.com) for verified secrets. Does not contact target infrastructure. |
| **gitleaks** | Scans GitHub repos (github.com) for secrets. Does not contact target infrastructure. |
| **CertStream** | WebSocket connection to certstream.calidog.io (third-party). Does not contact target infrastructure. |
| **cloud_enum / S3 HEAD checks** | HTTP HEAD/GET requests to cloud storage endpoints. These are standard web requests any internet user can make. If the bucket is publicly accessible, the HEAD request is identical to a browser loading a URL. |
| **SPF/DMARC/DKIM analysis** | Standard DNS TXT/MX queries via public resolvers. Identical to what email servers perform on every incoming message. |
| **robots.txt / sitemap.xml** | Standard HTTP GET requests to well-known paths. This is literally what Googlebot does. |
| **CAA record checks** | Standard DNS query via public resolvers. |

---

## What Was Added (vs asm_enterprise.py)

| Added | Phase | What it does |
|---|---|---|
| **theHarvester** | 2 | OSINT aggregator: collects emails, subdomains, and hosts from search engines, LinkedIn, and DNS aggregators. Pure passive. |
| **assetfinder** | 2 | Lightweight passive subdomain finder from certificate logs and DNS aggregators. Complements subfinder. |
| **Google / search engine dork file** | 2 | Generates ~20+ targeted search queries per domain for manual investigation. No network requests -- offline generation. |
| **uncover** | 5 | Aggregates Shodan, Censys, FOFA, Hunter.io, and ZoomEye simultaneously in a single query. Passive API only. |
| **SPF / DMARC / DKIM analysis** | 3 | Checks MX records, SPF TXT records, DMARC policies, and probes common DKIM selectors. Missing DMARC or p=none is a direct spoofing enablement finding. |
| **robots.txt + sitemap.xml fetching** | 6 | Fetches standard web files and extracts disallowed paths (often revealing hidden endpoints and admin areas) and sitemap references. |
| **Security header analysis (inline)** | 6 | Moved from a Phase 8 dependency into Phase 6 httpx post-processing. Now runs immediately alongside liveness checks. Reports missing HSTS, CSP, X-Frame-Options, wildcard CORS. |
| **Expiring-soon TLS cert tracking** | 6 | tlsx output now flags certs expiring within 30 days, not just expired certs. |
| **waybackurls** | 8 | Dedicated Wayback Machine URL extractor (complements gau). |
| **JS endpoint extraction** | 8 | Fetches publicly served JavaScript files and extracts API paths, auth endpoints, and internal service names via regex. These are paths the application itself sends to any browser. |
| **Favicon hash + Shodan** | 8 | Computes MurmurHash3 of the target's favicon, then queries Shodan for all servers serving the identical icon. Reveals related infrastructure, acquired companies, and servers behind CDNs sharing the same codebase. |
| **Extended CNAME targets** | 7 | Added readthedocs.io, statuspage.io, bitbucket.io, uservoice.com, feedpress.me to the dangling CNAME detection list. |
| **Extended Shodan queries** | 5 | Added Jenkins, Jupyter Notebooks, Grafana, Prometheus, PostgreSQL, MSSQL, MySQL to the high-risk service query list. |
| **GitHub dork file (expanded)** | 10 | Added DATABASE_URL, BEGIN OPENSSH PRIVATE KEY, and Authorization header patterns. |

---

## Full Installation (Kali Linux)

### Step 1 -- System packages

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y \
    python3 python3-pip git curl wget \
    whois amass dnsrecon whatweb gitleaks jq
```

### Step 2 -- Go (required for ProjectDiscovery tools)

```bash
go version || (
    wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz &&
    sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz &&
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc &&
    source ~/.bashrc
)
```

### Step 3 -- ProjectDiscovery + recon tools

```bash
# Core subdomain / DNS tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/projectdiscovery/uncover/cmd/uncover@latest

# Resolution + brute-force
go install github.com/d3mondev/puredns/v2@latest

# Takeover detection
go install github.com/haccer/subjack@latest

# URL / JS collection
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

# Lightweight passive subdomain finder
go install github.com/tomnomnom/assetfinder@latest

# Update Nuclei templates immediately after install
nuclei -update-templates

# Verify all tools
for tool in subfinder httpx dnsx nuclei tlsx uncover puredns subjack gau waybackurls assetfinder; do
    which $tool && echo "OK: $tool" || echo "MISSING: $tool"
done
```

### Step 4 -- theHarvester

```bash
pip3 install theHarvester
# or for latest:
git clone https://github.com/laramies/theHarvester /opt/theHarvester
cd /opt/theHarvester && pip3 install -r requirements/base.txt
ln -s /opt/theHarvester/theHarvester.py /usr/local/bin/theHarvester
```

### Step 5 -- cloud_enum

```bash
git clone https://github.com/initstring/cloud_enum /opt/cloud_enum
pip3 install -r /opt/cloud_enum/requirements.txt
ln -s /opt/cloud_enum/cloud_enum.py /usr/local/bin/cloud_enum
chmod +x /opt/cloud_enum/cloud_enum.py
```

### Step 6 -- trufflehog

```bash
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
  | sudo sh -s -- -b /usr/local/bin
trufflehog --version
```

### Step 7 -- Python dependencies

```bash
pip3 install -r requirements.txt

# Verify key imports
python3 -c "import requests, dns, rich, shodan, censys, certstream, mmh3; print('All OK')"
```

---

## API Key Setup

```bash
# Add to ~/.bashrc or ~/.zshrc
export SHODAN_API_KEY="your_key_here"
export CENSYS_API_ID="your_id_here"
export CENSYS_API_SECRET="your_secret_here"

source ~/.bashrc
```

| API | URL | Notes |
|---|---|---|
| Shodan | https://account.shodan.io | Free tier usable; paid plan for full org/ASN data |
| Censys | https://search.censys.io/account | Free research API available |

---

## Usage

```bash
python3 asm_recon.py
```

At startup you will confirm authorization, then enter:

- **Root domains** -- e.g. `target.com,subsidiary.com`
- **IP/CIDR ranges** -- e.g. `203.0.113.0/24` (or ENTER to skip)
- **Organization name** -- exact string as in WHOIS/certs
- **ASN** -- e.g. `AS12345`
- **GitHub org handle** -- for trufflehog/gitleaks secret scanning
- **API keys** -- Shodan, Censys (or pre-set via env vars)

Phase menu options:
- `all` -- run every phase
- `1,2,7` -- run specific phases
- `info` -- show what cannot be automated
- `removed` -- show what was removed (saved for asm_active.py)
- `added` -- show what was added vs asm_enterprise.py

### M&A Day-Zero Passive-Only Run

For pre-authorization recon (before active scanning is approved):

```
Select phases: 1,2,3,5,10,11
```

Phases 1, 2, 5, 10, and 11 are entirely passive third-party API queries.
Phase 3 includes AXFR and puredns resolve -- if you want to skip those, just
run `1,2,5,10,11` for pure passive.

---

## Phase Reference

| # | Phase | Primary Tools | Key Output Files |
|---|---|---|---|
| 1 | Seed Data | whois, ARIN API, ipinfo.io, RADB, Wayback | `seed_data.json`, `asn_prefixes.txt` |
| 2 | CT & OSINT | crt.sh, Censys, Shodan, theHarvester, assetfinder | `ct_subdomains.txt`, `search_engine_dorks.txt` |
| 3 | DNS | subfinder, amass, AXFR, puredns, dnsx, SPF/DMARC | `resolved_subdomains.txt`, `email_security_analysis.json` |
| 4 | IP & ASN | ipinfo.io, Shodan, PTR lookups | `all_ips.txt`, `ptr_results.txt` |
| 5 | Passive Intel | Shodan, Censys, uncover | `shodan_*.json`, `uncover_*.txt` |
| 6 | Validation | httpx, tlsx, robots.txt, CAA, security headers | `httpx_results.json`, `cert_findings.json`, `header_analysis.json` |
| 7 | Takeovers | nuclei takeovers/, subjack, CNAME analysis | `nuclei_takeovers.txt`, `dangling_cnames.json` |
| 8 | Fingerprint | whatweb, nuclei tech/configs, gau, waybackurls, JS, favicon | `nuclei_exposed_configs.txt`, `js_endpoints_*.txt`, `favicon_hash_findings.json` |
| 9 | Cloud | cloud_enum, S3 HEAD, Shodan cloud | `s3_findings.json`, `cloud_enum_results.txt` |
| 10 | Leaks | trufflehog, gitleaks, HIBP, CISA KEV, nuclei tokens | `trufflehog_*.json`, `hibp_*.json`, `cisa_kev.json` |
| 11 | CertStream | certstream.calidog.io WebSocket | `cert_alerts.jsonl` |

---

## What asm_active.py Will Add

The following capabilities are intentionally excluded from this script and will be implemented in `asm_active.py` (future). They require explicit written authorization and should be disclosed in your scope of work agreement:

- **masscan** -- full-range TCP SYN port sweeps
- **nmap** -- service version detection, NSE scripts, TLS cipher analysis, SMB vuln checks
- **puredns bruteforce** -- mass DNS subdomain brute-force
- **massdns PTR** -- bulk reverse-DNS sweeps across owned IP ranges
- **nuclei cves/** -- CVE-specific exploit testing
- **nuclei default-logins/** -- credential brute-forcing on discovered services
- **nuclei misconfiguration/** -- targeted misconfiguration testing templates
- **nuclei exposed-panels/** -- admin panel enumeration at volume
- **Authenticated cloud posture** -- ScoutSuite, Prowler (requires cloud credentials)

---

## Legal Reminder

Use only against assets you own or have explicit written authorization to test.
Unauthorized reconnaissance may violate the CFAA and equivalent laws in your jurisdiction.
