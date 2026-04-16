# ASM Enterprise v2.0

**Attack Surface Management -- Enterprise Financial Services**

Python-based external recon and ASM automation for large financial services organizations with active M&A programs. All phases produce output indistinguishable from normal internet activity. No port scanning, no exploit testing, no credential brute forcing.

**Platform:** Kali Linux (recommended) / Ubuntu 22.04+  
**Python:** 3.9+  
**License:** For authorized security assessment use only.

---

## Quick Start

```bash
# Install dependencies
sudo apt install python3-tk whois amass gitleaks theharvester golang
pip3 install -r requirements.txt --break-system-packages

# Install Go tools (requires golang)
export PATH=$PATH:$(go env GOPATH)/bin
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.zshrc

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/lc/gau/v2/cmd/gau@latest

# TruffleHog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
  | sudo sh -s -- -b /usr/local/bin

# cloud_enum
git clone https://github.com/initstring/cloud_enum ~/tools/cloud_enum
pip3 install -r ~/tools/cloud_enum/requirements.txt --break-system-packages
sudo ln -s ~/tools/cloud_enum/cloud_enum.py /usr/local/bin/cloud_enum

# Launch GUI
python3 asm_gui.py

# Or run CLI interactively
python3 asm_enterprise.py
```

---

## Files

| File | Purpose |
|---|---|
| `asm_enterprise.py` | Core scan engine -- 19 phases, CLI + GUI subprocess mode |
| `asm_gui.py` | Tkinter GUI -- phase selection, live log, progress bar, API key management |
| `requirements.txt` | Python dependencies |

Both files must be in the same directory.

---

## API Keys

| Service | Where to get | Required for |
|---|---|---|
| Shodan | account.shodan.io | Phases 2, 7, 12, 19 |
| Censys | search.censys.io/account | Phase 2 |
| SecurityTrails | securitytrails.com/app/account | Phase 14 |

Keys can be set via environment variables or entered in the GUI. The GUI saves keys to `~/.asm_config.json` (chmod 600).

```bash
export SHODAN_API_KEY="your_key"
export CENSYS_API_ID="your_id"
export CENSYS_API_SECRET="your_secret"
export SECURITYTRAILS_API_KEY="your_key"
```

**Shodan plan note:** Free/dev tier keys cannot run `org:` or `http.html:` search queries -- these return 403. SSL cert and host lookups work on free tier. Phases 7, 12, and 19 require a paid plan for full functionality. Use the "Test Keys" button in the GUI to check your plan level.

---

## Phases

All phases produce output that is indistinguishable from normal internet traffic. No packets are crafted, no services are fingerprinted with scanner signatures, no credentials are tested.

| # | Phase | Mode | Key Tools |
|---|---|---|---|
| 1 | Seed Data Collection | mixed | whois, ARIN, ipinfo.io, RADB, Wayback CDX |
| 2 | CT & Passive Recon | mixed | crt.sh, Censys API, Shodan SSL/org |
| 3 | Active DNS Enumeration | mixed | subfinder, amass, assetfinder, waybackurls, AXFR, puredns, dnsx |
| 4 | IP & ASN Mapping | mixed | CIDR expansion, A record resolution, RADB, Shodan org IPs |
| 5 | Web Validation & TLS | mixed | httpx, tlsx, robots.txt, sitemap, CORS, server version analysis |
| 6 | CNAME Dangling Analysis | **PASSIVE** | Python dnspython -- public resolvers only |
| 7 | Cloud Asset Enumeration | mixed | cloud_enum, S3 HEAD probes, Shodan cloud queries |
| 8 | JS Collection, Endpoints & Secret Scanning | mixed | gau, inline regex, Shannon entropy, JS dump for Phase 17 |
| 9 | Certificate Monitoring | mixed | CertStream real-time CT WebSocket |
| 10 | Reverse PTR Sweeps | **PASSIVE** | dnsx -ptr |
| 11 | DNS Permutation | **PASSIVE** | alterx, puredns |
| 12 | Favicon Hash Pivoting | **PASSIVE** | httpx -favicon, Shodan http.favicon.hash |
| 13 | DMARC / SPF / DKIM | **PASSIVE** | dnspython -- pure DNS queries |
| 14 | Historical DNS | **PASSIVE** | SecurityTrails API |
| 15 | Email Harvesting | **PASSIVE** | theHarvester (15 passive sources) |
| 16 | Paste Site Monitoring | **PASSIVE** | GitHub code search, LeakIX, Pastebin dork |
| 17 | Credential & Leak Monitoring | mixed | trufflehog (GitHub + JS dump), gitleaks, HIBP, dork file |
| 18 | Reverse Whois | **PASSIVE** | viewdns.info, reversewhois.io, amass intel -whois |
| 19 | Digital Footprint & Shadow Assets | **PASSIVE** | Tracker ID pivoting, Shodan copyright/html search |

### Phase selection shortcuts

| Input | Runs |
|---|---|
| `all` | All 19 phases |
| `passive` | Phases 1, 2, 4, 6, 10-16, 18, 19 -- safe for M&A pre-authorization |
| `1,3,8` | Specific phases (comma-separated) |
| `info` | Show what cannot be automated and why |

### Phase dependencies

For best results, run phases in order. Key dependencies:

- Phase 6 (CNAME) needs Phase 3 subdomain output
- Phase 8 (JS) should run before Phase 17 (leaks) -- Phase 17 scans Phase 8's JS dump with trufflehog/gitleaks filesystem mode
- Phase 10 (PTR) needs Phase 4 IP output
- Phase 11 (permutation) needs Phase 3 subdomain output
- Phase 12 (favicon) uses Phase 5 httpx output if available
- Phase 17 (leaks) checks for Phase 8 JS dump and runs filesystem secret scan if present

---

## Output Structure

All output is written to a timestamped directory: `output/<domain>_<YYYYMMDD_HHMMSS>/`

```
output/target.com_20260416_120000/
  SUMMARY_REPORT.json          # High-level findings summary
  resolvers.txt                # Trusted DNS resolvers used
  phase1_seed/
    seed_data.json
    whois_*.txt
    arin_search.json
    asn_*_ipinfo.json
    wayback_subdomains_*.txt
  phase2_ct/
    crtsh_*.json
    ct_subdomains.txt          # KEY: all unique subdomains from CT logs
    censys_hosts_*.json
    shodan_ssl_*.json
  phase3_dns/
    AXFR_SUCCESS_*.txt         # P0: zone transfer succeeded
    subfinder_*.txt
    amass_*.txt
    assetfinder_*.txt
    waybackurls_*.txt
    all_subdomains_raw.txt
    resolved_subdomains.txt    # KEY: live subdomains after puredns resolution
    dnsx_resolved.json
  phase4_ip/
    all_ips.txt
    shodan_org_ips.txt
  phase5_validation/
    httpx_results.json         # KEY: all live web hosts + metadata
    live_hosts.txt
    auth_interfaces.txt
    cors_wildcard.txt          # CRITICAL if populated: wildcard CORS
    server_version_disclosure.json
    tlsx_results.json
    cert_findings.json         # Expired/expiring/self-signed/LE certs
    robots_sitemap_findings.json
  phase6_cname/
    dangling_cnames.json       # P0 if NXDOMAIN entries present
    dangling_cnames_summary.txt
  phase7_cloud/
    bucket_permutations.txt
    cloud_enum_results.txt
    s3_findings.json           # CRITICAL if public:true entries present
    shodan_docker_api.json
    shodan_kubernetes.json
  phase8_js/
    gau_js_*.txt
    js_endpoints.txt           # Extracted API paths
    js_endpoints_high_value.txt
    js_secrets.json            # KEY: pattern + entropy secret hits in JS
    dump/                      # Raw JS files -- scanned by Phase 17
  phase9_certstream/
    cert_alerts.jsonl          # Append-only CT event log
  phase10_ptr/
    ptr_results.json
    ptr_new_hosts.txt
  phase11_permutation/
    alterx_permutations.txt
    permutation_new_hosts.txt
  phase12_favicon/
    favicon_hashes.json
    favicon_pivot_results.json
    favicon_novel_ips.txt      # IPs outside scope sharing your favicon
  phase13_email_security/
    email_security_findings.json
  phase14_historical_dns/
    st_full_*.json
    st_new_subdomains_*.txt
    historical_ips_*.txt       # Review for CDN/Cloudflare origin IP bypass
  phase15_email_harvest/
    harvested_emails.txt
    external_domain_emails.txt
  phase16_pastes/
    paste_hits_summary.json
    pastebin_urls_*.txt
    leakix_*.json
    dehashed_manual_links.txt
  phase17_leaks/
    trufflehog_*.json          # Verified secrets in GitHub repos
    trufflehog_js_dump.json    # Secrets found in Phase 8 JS files
    gitleaks_report.json
    gitleaks_js_dump.json
    hibp_*.json
    search_dorks.txt           # Manual Google/GitHub dork queries
  phase18_reverse_whois/
    reverse_whois_domains.txt
    reverse_whois_summary.json
  phase19_digital_footprint/
    tracker_ids_found.json
    shodan_copyright_*.json
    digital_footprint_findings.json
    novel_ips_from_footprint.txt
  debug.log                    # Present only when --debug flag is used
```

---

## Escalation Priorities

### P0 -- Remediate within 24 hours

| Finding | Location |
|---|---|
| `AXFR_SUCCESS_*.txt` exists | `phase3_dns/` -- DNS zone transfer allowed |
| `dangling_cnames.json` contains NXDOMAIN entries | `phase6_cname/` -- active subdomain takeover risk |
| `s3_findings.json` contains `"public": true` | `phase7_cloud/` -- public S3 bucket |
| `js_secrets.json` contains pattern-matched credentials | `phase8_js/` -- live keys in public JS |
| `trufflehog_*.json` contains verified secrets | `phase17_leaks/` -- confirmed live secrets in GitHub |

### P1 -- Remediate within 7 days

| Finding | Location |
|---|---|
| `cors_wildcard.txt` populated | `phase5_validation/` -- wildcard CORS on financial API |
| `cert_findings.json` contains expired certs | `phase5_validation/` |
| `hibp_*.json` shows recent breach | `phase17_leaks/` |
| `historical_ips_*.txt` shows CDN origin IP | `phase14_historical_dns/` -- Cloudflare bypass risk |

### P2 -- Include in next sprint

| Finding | Location |
|---|---|
| `email_security_findings.json` -- DMARC p=none or missing | `phase13_email_security/` |
| `server_version_disclosure.json` populated | `phase5_validation/` |
| `reverse_whois_domains.txt` has unknown domains | `phase18_reverse_whois/` |
| `novel_ips_from_footprint.txt` populated | `phase19_digital_footprint/` -- shadow IT |

---

## M&A Pre-Acquisition Workflow

Before acquiring a company, run passive phases only. No active requests reach the target.

```
Select phases: passive
```

This runs phases: 1, 2, 4, 6, 10, 11, 12, 13, 14, 15, 16, 18, 19

Do **not** run phases 3, 5, 7, 8, 9, 17 against an acquisition target without explicit CISO authorization from the target organization. The deal does not grant you that right automatically.

After deal close and CISO authorization, run the full suite:

```
Select phases: all
```

---

## CLI Mode

The script can be run without the GUI:

```bash
# Interactive mode -- prompts for all inputs
python3 asm_enterprise.py

# Non-interactive mode -- used by the GUI, also useful for scripting
python3 asm_enterprise.py \
  --config /path/to/config.json \
  --phases 1,2,3,6,8 \
  --non-interactive \
  --no-color

# With debug logging
python3 asm_enterprise.py --debug
```

### Config JSON format (for --config)

```json
{
  "domains":            ["target.com", "subsidiary.com"],
  "ip_ranges":          ["203.0.113.0/24"],
  "org_name":           "Target Corporation",
  "asn":                "AS12345",
  "github_org":         "targetcorp",
  "shodan_key":         "your_key",
  "censys_id":          "your_id",
  "censys_secret":      "your_secret",
  "securitytrails_key": "your_key",
  "output_dir":         ""
}
```

Leave `output_dir` blank to auto-name the output directory.

---

## Not Automated

The following capabilities are intentionally excluded:

| Capability | Reason |
|---|---|
| Port scanning (masscan, nmap) | Generates crafted packets -- reserved for `asm_active.py` |
| CVE / default-login testing (nuclei) | Exploit-adjacent probing -- reserved for `asm_active.py` |
| Third-party / supply chain assessment | Requires internal vendor lists not externally discoverable |
| M&A pre-acquisition active phases | Requires explicit CISO authorization from target |
| Dark web / Flashpoint monitoring | Enterprise license required |
| Authenticated cloud posture (ScoutSuite/Prowler) | Requires provisioned cloud credentials |

---

## Regulatory Alignment

Findings from this tool map directly to requirements under:

| Regulation | Relevant Phases |
|---|---|
| NY DFS Part 500 | 5 (TLS), 6 (takeover), 13 (DMARC/SPF), 17 (credential leaks) |
| FFIEC CAT | 2, 3, 5, 6, 7, 8, 17 |
| PCI-DSS 12.3 | 3, 5, 6, 7 |
| GLBA Safeguards Rule | 2, 13, 17, 18 |
| DORA (EU) | 2, 5, 6, 7, 14, 18 |

---

## Legal

This tool is for authorized security assessments only. Unauthorized use against systems you do not own or do not have explicit written authorization to test may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, GDPR Article 32, and equivalent laws in your jurisdiction.

Written authorization from an appropriate executive (CISO, CTO, or legal counsel) is required before running any phase against any target.
