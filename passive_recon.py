#!/usr/bin/env python3
"""
asm_recon.py -- Light-Active Attack Surface Reconnaissance
Based on: Enterprise Financial Services ASM SOP v1.0

Philosophy: Every action this script takes is indistinguishable from normal
internet activity. Every HTTP request could be a browser visiting a page.
Every DNS query goes through public resolvers. No packets are crafted, no
services are fingerprinted with scanner signatures, no credentials are tested.

FOR AUTHORIZED USE ONLY. Written authorization required before use.
"""

import os
import sys
import json
import re
import subprocess
import datetime
import ipaddress
import hashlib
import base64
from pathlib import Path
from typing import List, Optional, Set, Dict, Any, Tuple

# ── Core dependencies ──────────────────────────────────────────────────────────
try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] 'requests' not found. Run: pip3 install requests")
    sys.exit(1)

try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.reversename
    import dns.exception
except ImportError:
    print("[!] 'dnspython' not found. Run: pip3 install dnspython")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn
except ImportError:
    print("[!] 'rich' not found. Run: pip3 install rich")
    sys.exit(1)

# ── Optional dependencies (handled gracefully) ─────────────────────────────────
SHODAN_AVAILABLE = False
CENSYS_AVAILABLE = False
CERTSTREAM_AVAILABLE = False
MMH3_AVAILABLE = False

try:
    import shodan as shodan_lib
    SHODAN_AVAILABLE = True
except ImportError:
    pass

try:
    from censys.search import CensysHosts
    CENSYS_AVAILABLE = True
except ImportError:
    pass

try:
    import certstream
    CERTSTREAM_AVAILABLE = True
except ImportError:
    pass

try:
    import mmh3
    MMH3_AVAILABLE = True
except ImportError:
    pass

console = Console()


# =============================================================================
# CONSTANTS & REFERENCE DATA
# =============================================================================

BANNER = r"""
   ___   ____  __  __   ____
  / _ \ / ___||  \/  | |  _ \ ___  ___ ___  _ __
 | | | |\___ \| |\/| | | |_) / _ \/ __/ _ \| '_ \
 | |_| | ___) | |  | | |  _ <  __/ (_| (_) | | | |
  \___/ |____/|_|  |_| |_| \_\___|\___\___/|_| |_|

  Light-Active Attack Surface Reconnaissance
  Enterprise Financial Services SOP v1.0
  *** FOR AUTHORIZED USE ONLY ***
"""

PHASES: Dict[int, str] = {
    1:  "Seed Data Collection         (WHOIS, ARIN, ipinfo.io, RADB, Wayback)",
    2:  "CT & OSINT                   (crt.sh, Censys, Shodan, theHarvester, dorks)",
    3:  "DNS Enumeration              (subfinder, amass, AXFR, dnsx, SPF/DMARC)",
    4:  "IP & ASN Enumeration         (ipinfo.io, Shodan, PTR lookups)",
    5:  "Passive Service Intelligence (Shodan, Censys, uncover)",
    6:  "Asset Validation & Liveness  (httpx, tlsx, robots.txt, sitemap, headers)",
    7:  "Takeover Detection           (nuclei, subjack, CNAME analysis)",
    8:  "Web Fingerprinting           (whatweb, nuclei, gau, waybackurls, JS, favicon)",
    9:  "Cloud Discovery              (cloud_enum, S3, Shodan cloud)",
    10: "Credential & Leak Monitoring (trufflehog, gitleaks, HIBP, CISA KEV)",
    11: "Certificate Monitoring       (CertStream real-time WebSocket)",
}

NOT_AUTOMATABLE: List[Tuple[str, str]] = [
    (
        "Third-Party / Supply Chain Exposure",
        "Requires vendor and SaaS lists from target IT team.\n"
        "Manual: request procurement records, OAuth consent logs, SSO audit logs.",
    ),
    (
        "M&A Pre-Acquisition Assessment",
        "Run all phases passively against the acquisition target.\n"
        "Do not run active tools against assets you do not own.",
    ),
    (
        "Dark Web / Flashpoint Monitoring",
        "Requires enterprise license. Configure keyword Collections\n"
        "in your Flashpoint portal within 24 hours of each deal close.",
    ),
    (
        "Authenticated Cloud Posture (ScoutSuite / Prowler)",
        "Requires provisioned cloud credentials:\n"
        "  AWS:   prowler aws -g cis_level2 -M json,csv\n"
        "  Azure: python3 scout.py azure\n"
        "  GCP:   python3 scout.py gcp",
    ),
    (
        "Port Scanning / Service Version Detection",
        "Intentionally excluded from this script. Use asm_active.py\n"
        "(future) for masscan + nmap service fingerprinting.",
    ),
    (
        "CVE / Default-Login / Exploit Testing",
        "Intentionally excluded. Use asm_active.py (future)\n"
        "for nuclei cves/, default-logins/, and exploit templates.",
    ),
]

# Tools / capabilities removed from asm_enterprise.py and saved for asm_active.py
REMOVED_FOR_ACTIVE_SCRIPT: List[Tuple[str, str]] = [
    ("masscan",
     "Raw TCP SYN port scanner. Generates crafted packets not resembling normal traffic."),
    ("nmap (all variants)",
     "Port scanner + NSE scripts. Service version probing is invasive fingerprinting."),
    ("puredns bruteforce",
     "Mass DNS brute-force. Generates anomalous query volume toward target nameservers."),
    ("massdns PTR bulk sweep",
     "Bulk reverse-DNS across target IP ranges. Anomalous query volume."),
    ("nuclei cves/",
     "Actively tests target services for CVE exploitability. Not regular traffic."),
    ("nuclei default-logins/",
     "Brute-force credential testing. Explicitly invasive."),
    ("nuclei misconfiguration/",
     "Many templates send probes beyond what a browser would normally issue."),
    ("nuclei exposed-panels/",
     "Enumerates admin interfaces with targeted path probing at volume."),
    ("nuclei cloud/",
     "Mixed templates; several test for authenticated cloud misconfigs."),
]

# Tools added in this script that were not in asm_enterprise.py
ADDED_TOOLS: List[Tuple[str, str]] = [
    ("theHarvester",
     "OSINT aggregator -- emails, subdomains, hosts from search engines and LinkedIn."),
    ("uncover",
     "Aggregates Shodan, Censys, FOFA, Hunter.io, ZoomEye in a single passive query."),
    ("assetfinder",
     "Lightweight passive subdomain finder from certificate and DNS aggregators."),
    ("waybackurls",
     "Fetches historically known URLs from Wayback Machine for a domain."),
    ("SPF / DMARC / DKIM analysis",
     "MX + TXT record queries via public resolvers. Reveals email security posture."),
    ("robots.txt + sitemap.xml",
     "Standard web file fetching -- identical to Googlebot crawling. Reveals endpoints."),
    ("Favicon hash Shodan search",
     "Computes favicon MurmurHash3 then queries Shodan for servers serving identical icon. "
     "Reveals related/acquired infrastructure behind CDNs."),
    ("JS endpoint extraction",
     "Fetches publicly served JavaScript files and extracts API paths via regex."),
    ("Google / search engine dork file",
     "Generates passive investigation queries for manual search engine reconnaissance."),
    ("Security header analysis (inline)",
     "Moved from Phase 8 dependency chain into Phase 6 httpx post-processing."),
]

TAKEOVER_FINGERPRINTS: Dict[str, str] = {
    "GitHub Pages":  "There isn't a GitHub Pages site here",
    "Heroku":        "No such app",
    "Netlify":       "Not found - Request ID:",
    "Azure Web App": "Error 404 - Web app not found",
    "Azure Blob":    "The specified resource does not exist",
    "AWS S3":        "NoSuchBucket",
    "AWS CloudFront":"The request could not be satisfied",
    "Fastly":        "Fastly error: unknown domain",
    "Firebase":      "Firebase Hosting Site Not Found",
    "Google Cloud":  "NoSuchBucket",
    "Shopify":       "Sorry, this shop is currently unavailable",
    "Ghost":         "Used internally by Ghost",
    "WordPress.com": "Do you want to register",
    "Tumblr":        "Whatever you were looking for doesn't currently exist",
    "Zendesk":       "Help Center Closed",
    "HubSpot":       "This page isn't available",
    "Pingdom":       "This public status page does not seem to exist",
    "Mailchimp":     "Oops, that page doesn't exist",
    "Cargo":         "If you're moving your domain away from Cargo",
}

DANGEROUS_CNAME_TARGETS: List[str] = [
    "herokuapp.com", "github.io", "azurewebsites.net", "netlify.app",
    "netlify.com", "s3.amazonaws.com", "cloudfront.net", "fastly.net",
    "web.app", "firebaseapp.com", "myshopify.com", "zendesk.com",
    "hubspot.com", "ghost.io", "pingdom.com", "wordpress.com",
    "tumblr.com", "mailchimpsites.com", "helpscoutdocs.com",
    "desk.com", "campaignmonitor.com", "cargo.site", "readthedocs.io",
    "statuspage.io", "bitbucket.io", "uservoice.com", "feedpress.me",
]

BUCKET_SUFFIXES: List[str] = [
    "-prod", "-staging", "-dev", "-backup", "-logs", "-data",
    "-archive", "-reports", "-assets", "-static", "-media",
    "-files", "-uploads", "-images", "-cdn", "-api", "-db",
    "-database", "-config", "-deploy", "-release", "-builds",
]

GOOGLE_DORK_TEMPLATES: List[str] = [
    "site:{domain} filetype:env",
    "site:{domain} filetype:sql",
    "site:{domain} filetype:log",
    "site:{domain} filetype:bak",
    "site:{domain} inurl:admin",
    "site:{domain} inurl:login",
    "site:{domain} inurl:api",
    "site:{domain} inurl:swagger",
    "site:{domain} inurl:phpinfo",
    "site:{domain} intext:\"Index of /\"",
    "site:{domain} intext:\"password\"",
    "\"{domain}\" \"api_key\"",
    "\"{domain}\" \"aws_access_key\"",
    "\"{domain}\" \"BEGIN PRIVATE KEY\"",
    "\"{domain}\" \"internal\" site:pastebin.com",
    "\"{domain}\" site:github.com",
    "\"{domain}\" site:trello.com",
    "\"{domain}\" site:jira.atlassian.com",
]

DKIM_SELECTORS: List[str] = [
    "default", "google", "mail", "dkim", "k1", "k2",
    "selector1", "selector2", "s1", "s2", "email",
    "protonmail", "mailchimp", "sendgrid", "mimecast",
]

RESOLVERS_URL = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"


# =============================================================================
# DISPLAY HELPERS
# =============================================================================

def section(title: str) -> None:
    console.rule(f"[bold yellow]{title}[/bold yellow]")

def info(msg: str) -> None:
    console.print(f"  [bold blue][*][/] {msg}")

def success(msg: str) -> None:
    console.print(f"  [bold green][+][/] {msg}")

def warn(msg: str) -> None:
    console.print(f"  [bold yellow][!][/] {msg}")

def error(msg: str) -> None:
    console.print(f"  [bold red][x][/] {msg}")

def critical(msg: str) -> None:
    console.print(f"  [bold red on white][CRITICAL][/] {msg}")

def finding(category: str, msg: str) -> None:
    console.print(f"  [bold magenta][FINDING][/] [{category}] {msg}")


# =============================================================================
# FILE / SUBPROCESS UTILITIES
# =============================================================================

def make_dir(base: Path, name: str) -> Path:
    p = base / name
    p.mkdir(parents=True, exist_ok=True)
    return p

def run_tool(
    cmd: List[str],
    output_file: Optional[Path] = None,
    timeout: int = 600,
    env: Optional[Dict] = None,
) -> Optional[str]:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, env={**os.environ, **(env or {})},
        )
        stdout = result.stdout.strip()
        if output_file and stdout:
            output_file.write_text(stdout, encoding="utf-8")
        if result.returncode != 0 and result.stderr:
            warn(f"[{cmd[0]}] stderr: {result.stderr[:300]}")
        return stdout
    except FileNotFoundError:
        error(f"Tool not found: [bold]{cmd[0]}[/bold] -- skipping.")
        return None
    except subprocess.TimeoutExpired:
        warn(f"Timeout (>{timeout}s) for {cmd[0]}. Partial results may exist.")
        return None
    except Exception as exc:
        error(f"Error running {cmd[0]}: {exc}")
        return None

def tool_available(name: str) -> bool:
    return subprocess.run(["which", name], capture_output=True).returncode == 0

def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

def read_lines(path: Path) -> List[str]:
    if path.exists():
        return [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    return []

def save_lines(path: Path, lines: List[str]) -> None:
    path.write_text("\n".join(sorted(set(l for l in lines if l))), encoding="utf-8")

def append_line(path: Path, line: str) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def safe_get(url: str, timeout: int = 10, **kwargs) -> Optional[requests.Response]:
    """HTTP GET that never raises -- returns None on any error."""
    try:
        return requests.get(url, timeout=timeout, verify=False, **kwargs)
    except Exception:
        return None

def get_resolvers(output_dir: Path) -> Path:
    rf = output_dir / "resolvers.txt"
    if rf.exists() and len(read_lines(rf)) > 10:
        return rf
    try:
        r = requests.get(RESOLVERS_URL, timeout=30)
        rf.write_text(r.text, encoding="utf-8")
        info(f"Downloaded {len(r.text.splitlines())} public resolvers.")
    except Exception:
        rf.write_text("8.8.8.8\n1.1.1.1\n9.9.9.9\n8.8.4.4\n", encoding="utf-8")
        warn("Could not download resolvers list -- using fallback.")
    return rf


# =============================================================================
# SCOPE
# =============================================================================

class Scope:
    def __init__(self) -> None:
        self.domains: List[str] = []
        self.ip_ranges: List[str] = []
        self.org_name: str = ""
        self.asn: str = ""
        self.github_org: str = ""
        self.shodan_key: str = ""
        self.censys_id: str = ""
        self.censys_secret: str = ""
        self.output_dir: Path = Path("output") / "default"

    def prompt(self) -> None:
        section("Scope Definition")
        warn("Provide ONLY assets you have written authorization to assess.")

        raw = Prompt.ask("\n  [cyan]Root domain(s)[/cyan]  (comma-separated)")
        self.domains = [d.strip().lower() for d in raw.split(",") if d.strip()]

        raw = Prompt.ask(
            "  [cyan]IP / CIDR range(s)[/cyan]  (comma-separated, or ENTER to skip)",
            default="",
        )
        if raw.strip():
            self.ip_ranges = [r.strip() for r in raw.split(",") if r.strip()]

        self.org_name = Prompt.ask(
            "  [cyan]Organization name[/cyan]  (as in WHOIS/certs, or ENTER to skip)",
            default="",
        )
        self.asn = Prompt.ask(
            "  [cyan]ASN[/cyan]  (e.g. AS12345, or ENTER to skip)",
            default="",
        )
        self.github_org = Prompt.ask(
            "  [cyan]GitHub org handle[/cyan]  (for secret scanning, or ENTER to skip)",
            default="",
        )
        self.shodan_key = os.environ.get("SHODAN_API_KEY") or Prompt.ask(
            "  [cyan]Shodan API key[/cyan]  (or SHODAN_API_KEY env var, ENTER to skip)",
            default="", password=True,
        )
        self.censys_id = os.environ.get("CENSYS_API_ID") or Prompt.ask(
            "  [cyan]Censys API ID[/cyan]  (or CENSYS_API_ID env var, ENTER to skip)",
            default="", password=True,
        )
        self.censys_secret = os.environ.get("CENSYS_API_SECRET") or Prompt.ask(
            "  [cyan]Censys API Secret[/cyan]  (or CENSYS_API_SECRET env var, ENTER to skip)",
            default="", password=True,
        )

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^\w.-]", "_", self.domains[0] if self.domains else "unknown")
        self.output_dir = Path("output") / f"{safe}_{ts}"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        success(f"Output directory: {self.output_dir}")

    @property
    def primary_domain(self) -> str:
        return self.domains[0] if self.domains else ""

    def best_subdomain_file(self) -> Path:
        for candidate in [
            self.output_dir / "phase3_dns" / "resolved_subdomains.txt",
            self.output_dir / "phase3_dns" / "all_subdomains_raw.txt",
            self.output_dir / "phase2_osint" / "ct_subdomains.txt",
        ]:
            if candidate.exists() and read_lines(candidate):
                return candidate
        fallback = self.output_dir / "scope_domains.txt"
        save_lines(fallback, self.domains)
        return fallback


# =============================================================================
# PHASE 1 -- SEED DATA COLLECTION
# Technique: passive third-party registry / API queries only.
# Tools: whois (registrar), ARIN REST API, ipinfo.io, RADB whois, Wayback Machine
# =============================================================================

def phase1_seed(scope: Scope) -> None:
    section("Phase 1 -- Seed Data Collection")
    out = make_dir(scope.output_dir, "phase1_seed")

    write_json(out / "seed_data.json", {
        "domains": scope.domains,
        "ip_ranges": scope.ip_ranges,
        "org_name": scope.org_name,
        "asn": scope.asn,
        "timestamp": datetime.datetime.utcnow().isoformat(),
    })

    for domain in scope.domains:
        info(f"WHOIS: {domain}")
        run_tool(["whois", domain], out / f"whois_{domain}.txt", timeout=30)

    if scope.org_name:
        info(f"ARIN REST search: {scope.org_name}")
        try:
            r = requests.get(
                "https://search.arin.net/rest/search",
                params={"q": scope.org_name},
                headers={"Accept": "application/json"},
                timeout=15,
            )
            if r.ok:
                write_json(out / "arin_search.json", r.json())
                success("ARIN search saved.")
        except Exception as exc:
            warn(f"ARIN search failed: {exc}")

    if scope.asn:
        asn_digits = re.sub(r"[^0-9]", "", scope.asn)
        info(f"ipinfo.io ASN lookup: AS{asn_digits}")
        try:
            r = requests.get(f"https://ipinfo.io/AS{asn_digits}/json", timeout=15)
            if r.ok:
                data = r.json()
                write_json(out / f"asn_{asn_digits}_ipinfo.json", data)
                prefixes = [p.get("netblock", "") for p in data.get("prefixes", []) if p.get("netblock")]
                if prefixes:
                    save_lines(out / "asn_prefixes.txt", prefixes)
                    success(f"AS{asn_digits}: {len(prefixes)} prefixes")
                console.print(f"    Org:     [cyan]{data.get('org', 'N/A')}[/]")
                console.print(f"    Country: [cyan]{data.get('country', 'N/A')}[/]")
        except Exception as exc:
            warn(f"ipinfo.io ASN lookup failed: {exc}")

        asn_tag = scope.asn.upper()
        if not asn_tag.startswith("AS"):
            asn_tag = "AS" + asn_tag
        info(f"RADB route lookup: {asn_tag}")
        radb_raw = run_tool(
            ["whois", "-h", "whois.radb.net", "--", f"-i origin {asn_tag}"],
            out / f"radb_{asn_tag}.txt", timeout=30,
        )
        if radb_raw:
            routes = re.findall(r"route(?:6)?:\s+(\S+)", radb_raw)
            if routes:
                save_lines(out / "radb_routes.txt", routes)
                success(f"RADB: {len(routes)} route entries")

    for domain in scope.domains[:3]:
        r = safe_get(f"https://archive.org/wayback/available?url={domain}")
        if r and r.ok:
            wb = r.json()
            write_json(out / f"wayback_{domain}.json", wb)
            snap = wb.get("archived_snapshots", {}).get("closest", {})
            if snap:
                info(f"Wayback: earliest snapshot for {domain} at {snap.get('timestamp', '?')}")

    success("Phase 1 complete.")


# =============================================================================
# PHASE 2 -- CT & OSINT
# Technique: passive third-party API queries + OSINT aggregation.
# Tools: crt.sh, Censys API, Shodan API, theHarvester, assetfinder,
#        Google dork file generation (no network)
# =============================================================================

def phase2_osint(scope: Scope) -> None:
    section("Phase 2 -- Certificate Transparency & OSINT")
    out = make_dir(scope.output_dir, "phase2_osint")
    all_subdomains: Set[str] = set()

    # crt.sh wildcard + org queries
    for domain in scope.domains:
        for query in [f"%.{domain}", domain]:
            info(f"crt.sh: {query}")
            try:
                r = requests.get(
                    f"https://crt.sh/?q={requests.utils.quote(query)}&output=json",
                    timeout=60, headers={"Accept": "application/json"}, verify=False,
                )
                if r.ok:
                    certs = r.json()
                    write_json(out / f"crtsh_{domain}_{query[0]}.json", certs)
                    for cert in certs:
                        for name in cert.get("name_value", "").split("\n"):
                            name = name.strip().lstrip("*.")
                            if name.endswith(f".{domain}") or name == domain:
                                all_subdomains.add(name)
                    success(f"crt.sh [{query}]: {len(certs)} certificates")
            except Exception as exc:
                warn(f"crt.sh query failed: {exc}")

    if scope.org_name:
        info(f"crt.sh org query: {scope.org_name}")
        try:
            r = requests.get(
                f"https://crt.sh/?O={requests.utils.quote(scope.org_name)}&output=json",
                timeout=60, verify=False,
            )
            if r.ok:
                certs = r.json()
                write_json(out / "crtsh_by_org.json", certs)
                for cert in certs:
                    for name in cert.get("name_value", "").split("\n"):
                        name = name.strip().lstrip("*.")
                        for domain in scope.domains:
                            if name.endswith(f".{domain}") or name == domain:
                                all_subdomains.add(name)
                success(f"crt.sh org [{scope.org_name}]: {len(certs)} certificates")
        except Exception as exc:
            warn(f"crt.sh org query failed: {exc}")

    # Censys API
    if scope.censys_id and scope.censys_secret and CENSYS_AVAILABLE:
        info("Querying Censys API")
        try:
            os.environ["CENSYS_API_ID"] = scope.censys_id
            os.environ["CENSYS_API_SECRET"] = scope.censys_secret
            h = CensysHosts()
            for domain in scope.domains:
                results = []
                for page in h.search(f"parsed.names: {domain}", per_page=100, pages=5):
                    results.extend(page)
                write_json(out / f"censys_hosts_{domain}.json", results)
                success(f"Censys [{domain}]: {len(results)} hosts")
        except Exception as exc:
            warn(f"Censys API failed: {exc}")
    elif scope.censys_id:
        warn("Censys library not installed. (pip3 install censys)")

    # Shodan SSL cert + org queries
    if scope.shodan_key and SHODAN_AVAILABLE:
        info("Shodan SSL certificate and org queries")
        try:
            api = shodan_lib.Shodan(scope.shodan_key)
            for domain in scope.domains:
                results = api.search(f"ssl.cert.subject.cn:{domain}")
                write_json(out / f"shodan_ssl_{domain}.json", results)
                success(f"Shodan SSL [{domain}]: {results.get('total', 0)} results")
            if scope.org_name:
                results = api.search(f'org:"{scope.org_name}"')
                write_json(out / "shodan_org.json", results)
                success(f"Shodan org [{scope.org_name}]: {results.get('total', 0)} results")
        except Exception as exc:
            warn(f"Shodan API failed: {exc}")
    elif scope.shodan_key:
        warn("Shodan library not installed. (pip3 install shodan)")

    # theHarvester -- OSINT aggregator
    if tool_available("theHarvester"):
        info("Running theHarvester (emails, hosts, subdomains from search engines)")
        for domain in scope.domains:
            th_out = out / f"theharvester_{domain}.json"
            run_tool(
                ["theHarvester", "-d", domain, "-b", "all", "-f", str(th_out)],
                timeout=300,
            )
            if th_out.exists():
                success(f"theHarvester results saved for {domain}")
    else:
        warn("theHarvester not found. Install: pip3 install theHarvester")

    # assetfinder -- lightweight passive subdomain finder
    if tool_available("assetfinder"):
        info("Running assetfinder (lightweight passive subdomain finder)")
        for domain in scope.domains:
            af_out = run_tool(["assetfinder", "--subs-only", domain], timeout=120)
            if af_out:
                results = [l for l in af_out.splitlines() if l.endswith(f".{domain}") or l == domain]
                all_subdomains.update(results)
                save_lines(out / f"assetfinder_{domain}.txt", results)
                success(f"assetfinder [{domain}]: {len(results)} subdomains")
    else:
        warn("assetfinder not found. Install: go install github.com/tomnomnom/assetfinder@latest")

    # Save CT subdomain list
    if all_subdomains:
        save_lines(out / "ct_subdomains.txt", list(all_subdomains))
        success(f"Total unique subdomains from CT/OSINT: {len(all_subdomains)}")

    # Google dork file generation -- no network, offline generation
    info("Generating Google / search engine dork query file")
    dorks: List[str] = []
    for domain in scope.domains:
        for template in GOOGLE_DORK_TEMPLATES:
            dorks.append(template.format(domain=domain))
        if scope.org_name:
            dorks.append(f'"{scope.org_name}" filetype:pdf')
            dorks.append(f'"{scope.org_name}" "confidential"')
            dorks.append(f'"{scope.org_name}" site:linkedin.com')
    save_lines(out / "search_engine_dorks.txt", dorks)
    info(f"Dork queries saved -> {out / 'search_engine_dorks.txt'}")
    info("Use manually at: google.com, bing.com, or via Google Dorking API")

    success("Phase 2 complete.")


# =============================================================================
# PHASE 3 -- DNS ENUMERATION
# Technique: passive subdomain aggregation + standard DNS protocol queries.
# All DNS queries go through public resolvers, not target nameservers directly
# (except AXFR which is a standard protocol request any client can make).
# Tools: subfinder, amass, AXFR, puredns resolve, dnsx, SPF/DMARC/MX analysis
# =============================================================================

def phase3_dns(scope: Scope) -> None:
    section("Phase 3 -- DNS Enumeration")
    out = make_dir(scope.output_dir, "phase3_dns")
    all_subdomains: Set[str] = set()

    # Seed from Phase 2 CT data
    ct_file = scope.output_dir / "phase2_osint" / "ct_subdomains.txt"
    if ct_file.exists():
        all_subdomains.update(read_lines(ct_file))
        info(f"Seeded {len(all_subdomains)} subdomains from Phase 2 CT data")

    for domain in scope.domains:
        info(f"--- Enumerating: {domain} ---")

        if tool_available("subfinder"):
            sf_out = out / f"subfinder_{domain}.txt"
            info("Subfinder (50+ passive sources)")
            run_tool(["subfinder", "-d", domain, "-all", "-silent", "-o", str(sf_out)], timeout=300)
            results = read_lines(sf_out)
            all_subdomains.update(results)
            success(f"Subfinder: {len(results)} results")
        else:
            warn("subfinder not found. Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")

        if tool_available("amass"):
            am_out = out / f"amass_{domain}.txt"
            info("Amass passive enumeration")
            run_tool(["amass", "enum", "-passive", "-d", domain, "-o", str(am_out)], timeout=600)
            results = read_lines(am_out)
            all_subdomains.update(results)
            success(f"Amass: {len(results)} results")
        else:
            warn("amass not found. Install: apt install amass")

        # AXFR zone transfer -- standard DNS protocol request
        info(f"AXFR zone transfer attempts for {domain}")
        try:
            ns_answers = dns.resolver.resolve(domain, "NS")
            nameservers = [str(r).rstrip(".") for r in ns_answers]
            for ns in nameservers:
                info(f"  AXFR -> {ns}")
                try:
                    xfr = dns.query.xfr(ns, domain, timeout=10, lifetime=15)
                    zone = dns.zone.from_xfr(xfr)
                    zone_names = [str(n) for n in zone.nodes.keys()]
                    axfr_file = out / f"AXFR_SUCCESS_{domain}_{ns}.txt"
                    axfr_file.write_text("\n".join(zone_names), encoding="utf-8")
                    critical(f"AXFR SUCCEEDED against {ns}! Zone dump saved.")
                    for n in zone_names:
                        if n not in ("@", ""):
                            all_subdomains.add(f"{n}.{domain}")
                except Exception as axfr_err:
                    info(f"    AXFR blocked at {ns}: {type(axfr_err).__name__}")
        except Exception as exc:
            warn(f"NS lookup failed for {domain}: {exc}")

    # Write merged raw subdomain list
    all_subs_file = out / "all_subdomains_raw.txt"
    save_lines(all_subs_file, list(all_subdomains))
    info(f"Raw subdomain list: {len(all_subdomains)} entries")

    # puredns resolve -- resolves known subdomains via public resolvers (not bruteforce)
    resolvers_file = get_resolvers(out)
    if tool_available("puredns"):
        info("puredns: resolving known subdomains via public resolvers")
        resolved_file = out / "resolved_subdomains.txt"
        run_tool(
            [
                "puredns", "resolve", str(all_subs_file),
                "-r", str(resolvers_file),
                "--write", str(resolved_file),
                "--write-wildcards", str(out / "wildcards.txt"),
                "--rate-limit", "500",
            ],
            timeout=1200,
        )
        success(f"puredns: {len(read_lines(resolved_file))} subdomains resolved")
    else:
        warn("puredns not found. Install: go install github.com/d3mondev/puredns/v2@latest")
        resolved_file = all_subs_file

    # dnsx -- A, CNAME, MX, TXT record breakdown
    if tool_available("dnsx"):
        info("dnsx: full record breakdown (A, CNAME, MX, TXT, NS)")
        dnsx_out = out / "dnsx_resolved.txt"
        run_tool(
            ["dnsx", "-l", str(resolved_file),
             "-a", "-cname", "-mx", "-txt", "-ns",
             "-resp", "-o", str(dnsx_out), "-silent"],
            timeout=600,
        )
        success(f"dnsx records saved -> {dnsx_out}")
    else:
        warn("dnsx not found. Install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest")

    # SPF / DMARC / DKIM / MX analysis -- standard DNS queries via public resolvers
    info("Analyzing email security records (SPF, DMARC, DKIM, MX)")
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    email_findings: List[Dict] = []

    for domain in scope.domains:
        domain_findings: Dict[str, Any] = {"domain": domain}

        # MX records
        try:
            mx_records = resolver.resolve(domain, "MX")
            domain_findings["mx"] = [str(r.exchange).rstrip(".") for r in mx_records]
        except Exception:
            domain_findings["mx"] = []

        # SPF (TXT on root domain)
        try:
            txt_records = resolver.resolve(domain, "TXT")
            spf = [str(r) for r in txt_records if "v=spf1" in str(r).lower()]
            domain_findings["spf"] = spf
            if not spf:
                warn(f"No SPF record for {domain} -- email spoofing may be possible")
                finding("EMAIL-SEC", f"Missing SPF: {domain}")
        except Exception:
            domain_findings["spf"] = []

        # DMARC (_dmarc.domain.com TXT)
        try:
            dmarc_records = resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc = [str(r) for r in dmarc_records if "v=dmarc1" in str(r).lower()]
            domain_findings["dmarc"] = dmarc
            if dmarc:
                dmarc_str = dmarc[0].lower()
                if "p=none" in dmarc_str:
                    warn(f"DMARC policy=none for {domain} -- no enforcement")
                    finding("EMAIL-SEC", f"DMARC p=none (monitor only): {domain}")
                elif "p=quarantine" in dmarc_str or "p=reject" in dmarc_str:
                    success(f"DMARC enforced for {domain}")
            else:
                warn(f"No DMARC record for {domain}")
                finding("EMAIL-SEC", f"Missing DMARC: {domain}")
        except Exception:
            domain_findings["dmarc"] = []
            warn(f"No DMARC record for {domain}")

        # DKIM (probe common selectors)
        found_dkim: List[str] = []
        for selector in DKIM_SELECTORS:
            try:
                dkim_records = resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                for r in dkim_records:
                    if "v=dkim1" in str(r).lower() or "p=" in str(r).lower():
                        found_dkim.append(f"{selector}: {str(r)[:80]}")
            except Exception:
                pass
        domain_findings["dkim_selectors_found"] = found_dkim

        email_findings.append(domain_findings)

    write_json(out / "email_security_analysis.json", email_findings)
    success("Email security record analysis saved")

    success("Phase 3 complete.")


# =============================================================================
# PHASE 4 -- IP & ASN ENUMERATION
# Technique: passive API queries + standard PTR DNS queries via public resolvers.
# Tools: ipinfo.io, Shodan ASN, Python PTR via public resolvers
# =============================================================================

def phase4_asn(scope: Scope) -> None:
    section("Phase 4 -- IP & ASN Enumeration")
    out = make_dir(scope.output_dir, "phase4_asn")
    all_ips: List[str] = []

    for cidr in scope.ip_ranges:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = [str(ip) for ip in net.hosts()]
            all_ips.extend(hosts)
            info(f"Expanded {cidr} -> {len(hosts)} host IPs")
        except ValueError as exc:
            warn(f"Invalid CIDR {cidr}: {exc}")

    if all_ips:
        save_lines(out / "all_ips.txt", all_ips)
        success(f"Total IPs in scope: {len(all_ips)}")

    if scope.asn:
        asn_digits = re.sub(r"[^0-9]", "", scope.asn)
        info(f"ipinfo.io full ASN data: AS{asn_digits}")
        try:
            r = requests.get(f"https://ipinfo.io/AS{asn_digits}/json", timeout=15)
            if r.ok:
                data = r.json()
                write_json(out / f"asn_AS{asn_digits}_full.json", data)
                prefixes = data.get("prefixes", [])
                if prefixes:
                    save_lines(out / "asn_cidrs.txt",
                               [p.get("netblock", "") for p in prefixes if p.get("netblock")])
                    success(f"AS{asn_digits}: {len(prefixes)} prefixes")
                console.print(f"    Org: [cyan]{data.get('org', 'N/A')}[/]  "
                              f"Country: [cyan]{data.get('country', 'N/A')}[/]")
        except Exception as exc:
            warn(f"ipinfo.io ASN lookup failed: {exc}")

    if scope.shodan_key and SHODAN_AVAILABLE and scope.asn:
        asn_tag = scope.asn.upper()
        if not asn_tag.startswith("AS"):
            asn_tag = "AS" + asn_tag
        info(f"Shodan ASN query: {asn_tag}")
        try:
            api = shodan_lib.Shodan(scope.shodan_key)
            results = api.search(f"asn:{asn_tag}")
            write_json(out / f"shodan_asn_{asn_tag}.json", results)
            success(f"Shodan ASN: {results.get('total', 0)} results")
        except Exception as exc:
            warn(f"Shodan ASN query failed: {exc}")

    # PTR lookups via public resolvers -- standard DNS, capped at 500 IPs
    if all_ips:
        info("PTR (reverse DNS) lookups via public resolvers (capped at 500 IPs)")
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        ptr_results: List[str] = []
        for ip in all_ips[:500]:
            try:
                rev = dns.reversename.from_address(ip)
                ans = resolver.resolve(rev, "PTR")
                for rr in ans:
                    ptr_results.append(f"{ip} -> {str(rr).rstrip('.')}")
            except Exception:
                pass
        if ptr_results:
            (out / "ptr_results.txt").write_text("\n".join(ptr_results), encoding="utf-8")
            success(f"PTR: {len(ptr_results)} hostnames resolved")
        info("For full IP-range PTR coverage, add massdns to asm_active.py")

    success("Phase 4 complete.")


# =============================================================================
# PHASE 5 -- PASSIVE SERVICE INTELLIGENCE
# Technique: read-only queries to third-party scanning platforms.
# Zero packets sent to target infrastructure.
# Tools: Shodan API, Censys API, uncover
# =============================================================================

def phase5_passive_intel(scope: Scope) -> None:
    section("Phase 5 -- Passive Service Intelligence")
    out = make_dir(scope.output_dir, "phase5_passive_intel")

    if scope.shodan_key and SHODAN_AVAILABLE:
        info("Shodan queries (IP ranges, org, high-risk service fingerprints)")
        try:
            api = shodan_lib.Shodan(scope.shodan_key)
            for cidr in scope.ip_ranges:
                results = api.search(f"net:{cidr}")
                write_json(out / f"shodan_net_{cidr.replace('/', '_')}.json", results)
                success(f"Shodan net:{cidr} -> {results.get('total', 0)} results")
            if scope.org_name:
                for query, label in [
                    (f'org:"{scope.org_name}" http.title:"admin"', "admin_panels"),
                    (f'org:"{scope.org_name}" port:3389',          "rdp_exposed"),
                    (f'org:"{scope.org_name}" port:22',            "ssh_exposed"),
                    (f'org:"{scope.org_name}" port:9200',          "elasticsearch"),
                    (f'org:"{scope.org_name}" port:6379',          "redis"),
                    (f'org:"{scope.org_name}" port:27017',         "mongodb"),
                    (f'org:"{scope.org_name}" port:2375',          "docker_api"),
                    (f'org:"{scope.org_name}" port:445',           "smb_exposed"),
                    (f'org:"{scope.org_name}" port:5432',          "postgres_exposed"),
                    (f'org:"{scope.org_name}" port:1433',          "mssql_exposed"),
                    (f'org:"{scope.org_name}" port:3306',          "mysql_exposed"),
                    (f'org:"{scope.org_name}" "X-Jenkins"',        "jenkins_exposed"),
                    (f'org:"{scope.org_name}" title:"Jupyter"',    "jupyter_exposed"),
                ]:
                    results = api.search(query)
                    total = results.get("total", 0)
                    if total > 0:
                        write_json(out / f"shodan_{label}.json", results)
                        sev = "bold red" if label in (
                            "rdp_exposed", "elasticsearch", "docker_api",
                            "smb_exposed", "jupyter_exposed", "jenkins_exposed",
                        ) else "bold yellow"
                        finding(sev.upper(), f"{label.replace('_', ' ')}: {total} Shodan results")
        except Exception as exc:
            warn(f"Shodan queries failed: {exc}")

    if scope.censys_id and scope.censys_secret and CENSYS_AVAILABLE:
        info("Censys queries (IP ranges)")
        try:
            os.environ["CENSYS_API_ID"] = scope.censys_id
            os.environ["CENSYS_API_SECRET"] = scope.censys_secret
            h = CensysHosts()
            for cidr in scope.ip_ranges:
                results = []
                for page in h.search(f"ip: {cidr}", per_page=100, pages=3):
                    results.extend(page)
                write_json(out / f"censys_net_{cidr.replace('/', '_')}.json", results)
                success(f"Censys net:{cidr} -> {len(results)} results")
        except Exception as exc:
            warn(f"Censys queries failed: {exc}")

    # uncover -- aggregates Shodan, Censys, FOFA, Hunter, ZoomEye simultaneously
    if tool_available("uncover"):
        info("uncover: aggregating multiple passive scanners")
        for domain in scope.domains:
            uncover_out = out / f"uncover_{domain}.txt"
            run_tool(
                ["uncover", "-q", domain, "-e", "shodan,censys,fofa,hunter,zoomeye",
                 "-o", str(uncover_out), "-silent"],
                timeout=120,
            )
            results = read_lines(uncover_out)
            if results:
                success(f"uncover [{domain}]: {len(results)} results across passive sources")
        if scope.org_name:
            uncover_org = out / "uncover_org.txt"
            run_tool(
                ["uncover", "-q", f'org:"{scope.org_name}"',
                 "-e", "shodan,censys", "-o", str(uncover_org), "-silent"],
                timeout=120,
            )
    else:
        warn("uncover not found. Install: go install github.com/projectdiscovery/uncover/cmd/uncover@latest")

    success("Phase 5 complete.")


# =============================================================================
# PHASE 6 -- ASSET VALIDATION & LIVENESS
# Technique: HTTP/S requests indistinguishable from a browser visiting a page.
#            TLS handshakes identical to any browser connection.
#            robots.txt + sitemap.xml fetching identical to Googlebot.
#            CAA + standard DNS queries via public resolvers.
# Tools: httpx, tlsx, robots.txt/sitemap.xml, CAA checks, security header analysis
# =============================================================================

def phase6_validation(scope: Scope) -> None:
    section("Phase 6 -- Asset Validation & Liveness")
    out = make_dir(scope.output_dir, "phase6_validation")
    subs_file = scope.best_subdomain_file()
    subs = read_lines(subs_file)
    info(f"Validating {len(subs)} targets from: {subs_file}")

    # httpx -- HTTP probing identical to a browser GET request
    if tool_available("httpx"):
        info("httpx: HTTP/S probing (status, title, server, tech detection)")
        httpx_json = out / "httpx_results.json"
        run_tool(
            [
                "httpx", "-l", str(subs_file),
                "-status-code", "-title", "-server", "-tech-detect",
                "-follow-redirects", "-content-length", "-response-time",
                "-o", str(httpx_json), "-json", "-silent",
            ],
            timeout=900,
        )
        if httpx_json.exists():
            takeover_hits: List[Dict] = []
            auth_interfaces: List[str] = []
            live_hosts: List[str] = []
            missing_headers: Dict[str, List[str]] = {
                "strict-transport-security": [],
                "content-security-policy": [],
                "x-frame-options": [],
                "x-content-type-options": [],
                "permissions-policy": [],
            }
            cors_wildcard: List[str] = []
            server_versions: List[Dict] = []

            for line in read_lines(httpx_json):
                try:
                    h = json.loads(line)
                    url = h.get("url", "")
                    status = h.get("status_code", 0)
                    body = h.get("body", "") or ""
                    headers = {k.lower(): v for k, v in (h.get("headers") or {}).items()}

                    if status:
                        live_hosts.append(url)
                    if status in (401, 403):
                        auth_interfaces.append(url)

                    # Takeover fingerprinting from response body
                    for platform, fp in TAKEOVER_FINGERPRINTS.items():
                        if fp.lower() in body.lower():
                            takeover_hits.append({"url": url, "platform": platform})

                    # Security header analysis
                    for hdr in missing_headers:
                        if hdr not in headers:
                            missing_headers[hdr].append(url)
                    if headers.get("access-control-allow-origin", "") == "*":
                        cors_wildcard.append(url)
                    server = headers.get("server", "")
                    if any(v in server for v in ("Apache/", "nginx/", "IIS/", "PHP/")):
                        server_versions.append({"url": url, "server": server})
                except Exception:
                    pass

            save_lines(out / "live_hosts.txt", live_hosts)
            if auth_interfaces:
                save_lines(out / "auth_interfaces.txt", auth_interfaces)
                warn(f"{len(auth_interfaces)} auth-required interfaces (review for public exposure)")
            if takeover_hits:
                write_json(out / "httpx_takeover_candidates.json", takeover_hits)
                critical(f"{len(takeover_hits)} TAKEOVER CANDIDATES from body fingerprinting!")
            if cors_wildcard:
                save_lines(out / "cors_wildcard.txt", cors_wildcard)
                critical(f"{len(cors_wildcard)} hosts with wildcard CORS -- financial API risk")
            if server_versions:
                write_json(out / "server_version_disclosure.json", server_versions[:100])
                warn(f"{len(server_versions)} hosts disclosing server version strings")

            write_json(out / "header_analysis.json", {
                "missing_hsts":  missing_headers["strict-transport-security"][:50],
                "missing_csp":   missing_headers["content-security-policy"][:50],
                "missing_xframe":missing_headers["x-frame-options"][:50],
                "missing_xcto":  missing_headers["x-content-type-options"][:50],
                "cors_wildcard": cors_wildcard,
                "server_versions": server_versions[:50],
            })
            success(f"httpx: {len(live_hosts)} live hosts | {len(takeover_hits)} takeover candidates")
    else:
        warn("httpx not found. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")

    # tlsx -- TLS certificate analysis (identical to a browser TLS handshake)
    if tool_available("tlsx"):
        info("tlsx: bulk TLS certificate analysis")
        tlsx_json = out / "tlsx_results.json"
        run_tool(
            ["tlsx", "-l", str(subs_file), "-san", "-cn", "-serial",
             "-not-after", "-expired", "-o", str(tlsx_json), "-json", "-silent"],
            timeout=900,
        )
        if tlsx_json.exists():
            expired: List[str] = []
            lets_encrypt: List[str] = []
            self_signed: List[str] = []
            expiring_soon: List[Dict] = []
            for line in read_lines(tlsx_json):
                try:
                    t = json.loads(line)
                    host = t.get("host", "")
                    issuer = (t.get("issuer_cn") or t.get("issuer_org") or "").lower()
                    if t.get("expired"):
                        expired.append(host)
                    if "let's encrypt" in issuer or "letsencrypt" in issuer:
                        lets_encrypt.append(host)
                    if not issuer or "self" in issuer or issuer == host.lower():
                        self_signed.append(host)
                    # Check certs expiring within 30 days
                    not_after = t.get("not_after", "")
                    if not_after:
                        try:
                            expiry = datetime.datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%SZ")
                            days_left = (expiry - datetime.datetime.utcnow()).days
                            if 0 < days_left <= 30:
                                expiring_soon.append({"host": host, "days_left": days_left, "expires": not_after})
                        except Exception:
                            pass
                except Exception:
                    pass

            cert_findings: Dict[str, Any] = {}
            if expired:
                cert_findings["expired_certs"] = expired
                critical(f"{len(expired)} EXPIRED TLS certificates")
            if expiring_soon:
                cert_findings["expiring_within_30_days"] = expiring_soon
                warn(f"{len(expiring_soon)} certs expiring within 30 days")
            if lets_encrypt:
                cert_findings["letsencrypt_certs"] = lets_encrypt
                info(f"{len(lets_encrypt)} Let's Encrypt certs (verify issuer expectation)")
            if self_signed:
                cert_findings["self_signed_certs"] = self_signed
                warn(f"{len(self_signed)} self-signed certificates")
            if cert_findings:
                write_json(out / "cert_findings.json", cert_findings)
            success("tlsx certificate analysis complete")
    else:
        warn("tlsx not found. Install: go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest")

    # robots.txt + sitemap.xml -- standard web crawling (identical to Googlebot)
    info("Fetching robots.txt and sitemap.xml for all live hosts")
    robots_findings: List[Dict] = []
    live_hosts_file = out / "live_hosts.txt"
    hosts_to_probe = read_lines(live_hosts_file)[:200] if live_hosts_file.exists() else [
        f"https://{d}" for d in scope.domains
    ]
    for host in hosts_to_probe:
        for path, label in [("/robots.txt", "robots"), ("/sitemap.xml", "sitemap")]:
            r = safe_get(f"{host.rstrip('/')}{path}", timeout=8)
            if r and r.status_code == 200 and len(r.text) > 20:
                entry = {"host": host, "path": path, "length": len(r.text)}
                # Extract disallowed paths from robots.txt
                if label == "robots":
                    disallowed = re.findall(r"(?i)Disallow:\s*(\S+)", r.text)
                    sitemaps = re.findall(r"(?i)Sitemap:\s*(\S+)", r.text)
                    entry["disallowed_paths"] = disallowed[:50]
                    entry["sitemaps_referenced"] = sitemaps
                    if disallowed:
                        info(f"  robots.txt [{host}]: {len(disallowed)} disallowed paths")
                robots_findings.append(entry)
    if robots_findings:
        write_json(out / "robots_sitemap_findings.json", robots_findings)
        success(f"robots.txt / sitemap.xml: {len(robots_findings)} files found")

    # CAA record check via public resolvers
    info("CAA record check for all root domains")
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    missing_caa: List[str] = []
    for domain in scope.domains:
        try:
            resolver.resolve(domain, "CAA")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            missing_caa.append(domain)
            warn(f"No CAA record for {domain} -- any CA can issue certificates")
        except Exception:
            pass
    if missing_caa:
        save_lines(out / "missing_caa.txt", missing_caa)

    success("Phase 6 complete.")


# =============================================================================
# PHASE 7 -- SUBDOMAIN TAKEOVER DETECTION
# Technique: HTTP requests to discovered subdomains to read their responses.
#            DNS queries via public resolvers to trace CNAME chains.
#            nuclei takeover templates = curl-equivalent reads of server responses.
# Tools: nuclei (takeovers/ only), subjack, Python CNAME chain analysis
# =============================================================================

def phase7_takeover(scope: Scope) -> None:
    section("Phase 7 -- Subdomain Takeover Detection")
    out = make_dir(scope.output_dir, "phase7_takeover")
    subs_file = scope.best_subdomain_file()

    if tool_available("nuclei"):
        info("Updating Nuclei templates")
        run_tool(["nuclei", "-update-templates", "-silent"], timeout=120)
        info("nuclei: takeover fingerprint templates (reads server responses)")
        nuclei_out = out / "nuclei_takeovers.txt"
        run_tool(
            ["nuclei", "-l", str(subs_file), "-t", "takeovers/",
             "-o", str(nuclei_out), "-silent"],
            timeout=900,
        )
        hits = read_lines(nuclei_out)
        if hits:
            critical(f"nuclei: {len(hits)} potential takeovers detected!")
            for h in hits[:20]:
                console.print(f"    [red]{h}[/]")
    else:
        warn("nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

    if tool_available("subjack"):
        info("subjack: CNAME takeover detection via HTTP fingerprinting")
        subjack_out = out / "subjack_results.txt"
        run_tool(
            ["subjack", "-w", str(subs_file), "-t", "100",
             "-timeout", "30", "-ssl", "-o", str(subjack_out), "-v"],
            timeout=900,
        )
        hits = read_lines(subjack_out)
        if hits:
            warn(f"subjack: {len(hits)} potential takeovers -- review {subjack_out}")
    else:
        warn("subjack not found. Install: go install github.com/haccer/subjack@latest")

    # Python CNAME chain analysis via public resolvers
    info("Python CNAME dangling-record analysis via public resolvers")
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    dangling: List[Dict] = []
    subs = read_lines(subs_file)
    info(f"Checking {min(len(subs), 3000)} subdomains for dangling CNAMEs")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as progress:
        task = progress.add_task("Checking CNAME chains...", total=min(len(subs), 3000))
        for sub in subs[:3000]:
            progress.advance(task)
            try:
                cname_answers = resolver.resolve(sub, "CNAME")
                for rdata in cname_answers:
                    target = str(rdata.target).rstrip(".")
                    for dangerous in DANGEROUS_CNAME_TARGETS:
                        if target.endswith(dangerous):
                            try:
                                resolver.resolve(target, "A")
                            except dns.resolver.NXDOMAIN:
                                dangling.append({
                                    "subdomain": sub,
                                    "cname_target": target,
                                    "platform": dangerous,
                                    "status": "NXDOMAIN -- DANGLING CNAME",
                                })
                                critical(f"DANGLING CNAME: {sub} -> {target}")
                            except Exception:
                                pass
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            except Exception:
                pass

    if dangling:
        write_json(out / "dangling_cnames.json", dangling)
        critical(f"{len(dangling)} dangling CNAMEs confirmed -- remediate immediately!")
    else:
        success("No dangling CNAMEs detected")

    success("Phase 7 complete.")


# =============================================================================
# PHASE 8 -- WEB FINGERPRINTING
# Technique: HTTP requests to read publicly served content.
#            Identical to what a browser, curl, or Googlebot would fetch.
#            Favicon hash uses public data to query Shodan (passive).
# Tools: whatweb, nuclei (technologies/ + exposures/configs/), gau,
#        waybackurls, JS endpoint extraction, favicon hash
# =============================================================================

def phase8_fingerprint(scope: Scope) -> None:
    section("Phase 8 -- Web Fingerprinting")
    out = make_dir(scope.output_dir, "phase8_fingerprint")
    subs_file = scope.best_subdomain_file()

    # whatweb -- HTTP fingerprinting (reads response headers and body)
    if tool_available("whatweb"):
        info("whatweb: technology fingerprinting from HTTP responses")
        run_tool(
            ["whatweb", "-i", str(subs_file),
             "--log-json", str(out / "whatweb_results.json"), "-a", "3"],
            timeout=900,
        )
        success("whatweb complete")
    else:
        warn("whatweb not found. Install: apt install whatweb")

    # nuclei technology + exposure/config detection
    if tool_available("nuclei"):
        info("nuclei: technology fingerprinting templates")
        run_tool(
            ["nuclei", "-l", str(subs_file), "-t", "technologies/",
             "-o", str(out / "nuclei_technologies.txt"), "-silent"],
            timeout=900,
        )
        info("nuclei: exposed config file checks (reads publicly served files)")
        run_tool(
            ["nuclei", "-l", str(subs_file), "-t", "exposures/configs/",
             "-o", str(out / "nuclei_exposed_configs.txt"), "-silent"],
            timeout=900,
        )
        info("nuclei: exposed API documentation checks (Swagger, OpenAPI, GraphQL)")
        run_tool(
            ["nuclei", "-l", str(subs_file), "-t", "exposures/apis/",
             "-o", str(out / "nuclei_api_exposure.txt"), "-silent"],
            timeout=600,
        )
        # Surface high-value config exposures immediately
        config_hits = read_lines(out / "nuclei_exposed_configs.txt")
        if config_hits:
            critical(f"{len(config_hits)} exposed configuration files detected!")
            for h in config_hits[:10]:
                console.print(f"    [red]{h}[/]")
    else:
        warn("nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

    # gau -- historical URL collection from Wayback, CommonCrawl, URLScan (passive APIs)
    if tool_available("gau"):
        info("gau: collecting historical URLs from Wayback Machine, CommonCrawl, URLScan")
        for domain in scope.domains:
            gau_out = run_tool(
                ["gau", "--blacklist", "png,jpg,gif,svg,woff,woff2,ttf,eot,ico,css", domain],
                timeout=180,
            )
            if gau_out:
                all_urls = gau_out.splitlines()
                js_urls = [u for u in all_urls if u.strip().endswith(".js")]
                save_lines(out / f"gau_all_{domain}.txt", all_urls)
                save_lines(out / f"gau_js_{domain}.txt", js_urls)
                success(f"gau [{domain}]: {len(all_urls)} URLs ({len(js_urls)} JS files)")
    else:
        warn("gau not found. Install: go install github.com/lc/gau/v2/cmd/gau@latest")

    # waybackurls -- dedicated Wayback Machine URL extractor (complementary to gau)
    if tool_available("waybackurls"):
        info("waybackurls: Wayback Machine historical URL discovery")
        for domain in scope.domains:
            wbu_out = run_tool(
                ["waybackurls", domain], timeout=120,
            )
            if wbu_out:
                urls = wbu_out.splitlines()
                save_lines(out / f"waybackurls_{domain}.txt", urls)
                success(f"waybackurls [{domain}]: {len(urls)} historical URLs")
    else:
        warn("waybackurls not found. Install: go install github.com/tomnomnom/waybackurls@latest")

    # JS endpoint extraction -- fetch publicly served JS files, extract API paths
    info("JS endpoint extraction from publicly served JavaScript files")
    js_files_found: List[str] = []
    for domain in scope.domains:
        gau_js = out / f"gau_js_{domain}.txt"
        if not gau_js.exists():
            continue
        js_urls = read_lines(gau_js)[:100]  # Cap to avoid excessive requests
        endpoints: Set[str] = set()
        api_patterns = [
            r'["\']\/[a-zA-Z0-9_\-\/\.]{4,80}["\']',   # path strings
            r'(?:api|v\d)[a-zA-Z0-9_\-\/\.]{2,60}',     # api/v1/v2 patterns
            r'https?:\/\/[a-zA-Z0-9\-\.]+\/[a-zA-Z0-9_\-\/\.]{4,80}', # full URLs
        ]
        for js_url in js_urls:
            r = safe_get(js_url, timeout=6)
            if r and r.status_code == 200:
                js_files_found.append(js_url)
                for pattern in api_patterns:
                    matches = re.findall(pattern, r.text)
                    for match in matches:
                        match = match.strip("\"'")
                        if any(kw in match.lower() for kw in
                               ["/api/", "/v1/", "/v2/", "/auth/", "/user", "/account",
                                "/admin", "/internal", "/graphql", "/rest", "/token"]):
                            endpoints.add(match)
        if endpoints:
            save_lines(out / f"js_endpoints_{domain}.txt", list(endpoints))
            success(f"JS extraction [{domain}]: {len(endpoints)} API endpoints from {len(js_files_found)} files")

    # Favicon hash -- fetch favicon, compute MurmurHash3, query Shodan for related infra
    if scope.shodan_key and SHODAN_AVAILABLE:
        info("Favicon hash: computing hash then querying Shodan for related infrastructure")
        live_file = scope.output_dir / "phase6_validation" / "live_hosts.txt"
        hosts_to_check = read_lines(live_file)[:50] if live_file.exists() else [
            f"https://{d}" for d in scope.domains
        ]
        favicon_findings: List[Dict] = []
        for host in hosts_to_check:
            favicon_url = f"{host.rstrip('/')}/favicon.ico"
            r = safe_get(favicon_url, timeout=6)
            if r and r.status_code == 200 and len(r.content) > 100:
                if MMH3_AVAILABLE:
                    fav_hash = mmh3.hash(base64.encodebytes(r.content))
                else:
                    # Fallback: MD5-based hash if mmh3 not available (less accurate for Shodan)
                    fav_hash = int(hashlib.md5(r.content).hexdigest(), 16) % (2**32)
                    warn("mmh3 not installed -- favicon hash may not match Shodan exactly. (pip3 install mmh3)")
                try:
                    api = shodan_lib.Shodan(scope.shodan_key)
                    shodan_results = api.search(f"http.favicon.hash:{fav_hash}")
                    total = shodan_results.get("total", 0)
                    if total > 0:
                        favicon_findings.append({
                            "host": host,
                            "favicon_hash": fav_hash,
                            "shodan_matches": total,
                        })
                        info(f"  Favicon hash {fav_hash} [{host}]: {total} Shodan matches -- review for related/CDN-bypassed infra")
                except Exception:
                    pass
        if favicon_findings:
            write_json(out / "favicon_hash_findings.json", favicon_findings)
            success(f"Favicon hash analysis: {len(favicon_findings)} hashes with Shodan matches")

    success("Phase 8 complete.")


# =============================================================================
# PHASE 9 -- CLOUD ASSET DISCOVERY
# Technique: HTTP HEAD/GET requests to cloud storage endpoints.
#            These are standard web requests any internet user can make.
#            Shodan queries are passive API calls.
# Tools: cloud_enum, S3 HEAD checks, Shodan cloud queries
# =============================================================================

def phase9_cloud(scope: Scope) -> None:
    section("Phase 9 -- Cloud Asset Discovery (Unauthenticated)")
    out = make_dir(scope.output_dir, "phase9_cloud")

    # Build permutation list
    base_keywords: Set[str] = set()
    for domain in scope.domains:
        base = domain.split(".")[0]
        base_keywords.update([base, base.replace("-", ""), base.replace(".", "-")])
    if scope.org_name:
        org_base = scope.org_name.lower().replace(" ", "-").replace("_", "-")
        base_keywords.update([org_base, org_base.replace("-", ""), org_base.replace("-", "_")])

    permutations: Set[str] = set(base_keywords)
    for kw in list(base_keywords):
        for suffix in BUCKET_SUFFIXES:
            permutations.add(kw + suffix)
            permutations.add(kw + suffix.replace("-", ""))

    save_lines(out / "bucket_permutations.txt", list(permutations))
    info(f"Generated {len(permutations)} bucket name permutations")

    # cloud_enum -- HTTP requests to cloud storage endpoints
    if tool_available("cloud_enum"):
        info("cloud_enum: enumerating S3, Azure Blob, GCP Storage")
        cmd = ["cloud_enum"] + [item for kw in list(base_keywords)[:6] for item in ["-k", kw]]
        cmd += ["-l", str(out / "cloud_enum_results.txt")]
        run_tool(cmd, timeout=900)
        success("cloud_enum complete")
    else:
        warn("cloud_enum not found. Install:")
        warn("  git clone https://github.com/initstring/cloud_enum && cd cloud_enum")
        warn("  pip3 install -r requirements.txt")
        warn("  ln -s $(pwd)/cloud_enum.py /usr/local/bin/cloud_enum")

        # Python S3 HEAD fallback -- standard HTTP HEAD requests
        info("Falling back to Python S3 HEAD checks (standard HTTP requests)")
        public_buckets: List[Dict] = []
        for name in list(permutations)[:200]:
            try:
                r = requests.head(
                    f"https://{name}.s3.amazonaws.com",
                    timeout=4, allow_redirects=False, verify=False,
                )
                if r.status_code == 200:
                    public_buckets.append({"bucket": name, "access": "PUBLIC",
                                           "url": f"https://{name}.s3.amazonaws.com"})
                    critical(f"PUBLIC S3 BUCKET: https://{name}.s3.amazonaws.com")
                elif r.status_code == 403:
                    public_buckets.append({"bucket": name, "access": "EXISTS_PRIVATE",
                                           "url": f"https://{name}.s3.amazonaws.com"})
                    info(f"  Bucket exists (private): {name}.s3.amazonaws.com")
            except requests.exceptions.ConnectionError:
                pass
            except Exception:
                pass
        if public_buckets:
            write_json(out / "s3_findings.json", public_buckets)
            public = [b for b in public_buckets if b["access"] == "PUBLIC"]
            if public:
                critical(f"{len(public)} PUBLIC S3 BUCKETS -- review immediately")

    # Shodan cloud-focused passive queries
    if scope.shodan_key and SHODAN_AVAILABLE:
        info("Shodan cloud-specific queries (passive)")
        try:
            api = shodan_lib.Shodan(scope.shodan_key)
            cloud_queries = []
            if scope.org_name:
                cloud_queries = [
                    (f'org:"{scope.org_name}" product:"Kubernetes"',              "kubernetes"),
                    (f'org:"{scope.org_name}" port:2375',                         "docker_api"),
                    (f'org:"{scope.org_name}" port:9200 product:"Elasticsearch"', "elasticsearch"),
                    (f'org:"{scope.org_name}" port:6379',                         "redis"),
                    (f'org:"{scope.org_name}" port:9090 product:"Prometheus"',    "prometheus"),
                    (f'org:"{scope.org_name}" title:"Grafana"',                   "grafana"),
                ]
            for domain in scope.domains:
                cloud_queries.append((f'ssl.cert.subject.cn:{domain} port:9200', f"es_{domain}"))
            for query, label in cloud_queries:
                results = api.search(query)
                total = results.get("total", 0)
                if total > 0:
                    write_json(out / f"shodan_{label}.json", results)
                    sev = "bold red" if label in ("docker_api", "kubernetes", "elasticsearch") else "bold yellow"
                    console.print(f"  [{sev}][!] {label.upper()}:[/] {total} Shodan results")
        except Exception as exc:
            warn(f"Shodan cloud queries failed: {exc}")

    console.print(
        "\n  [bold yellow]NOTE:[/] Authenticated cloud posture assessment (ScoutSuite/Prowler)\n"
        "  requires provisioned credentials and is not in scope for this script.\n"
    )
    success("Phase 9 complete.")


# =============================================================================
# PHASE 10 -- CREDENTIAL & LEAK MONITORING
# Technique: third-party API queries + reading publicly served web content.
#            trufflehog/gitleaks query github.com, not target infrastructure.
#            nuclei exposures/tokens reads server responses (curl-equivalent).
# Tools: trufflehog, gitleaks, HIBP API, CISA KEV, nuclei exposures/tokens/,
#        GitHub dork file
# =============================================================================

def phase10_leaks(scope: Scope) -> None:
    section("Phase 10 -- Credential & Data Leak Monitoring")
    out = make_dir(scope.output_dir, "phase10_leaks")
    subs_file = scope.best_subdomain_file()

    # trufflehog -- scans github.com repos (not target infrastructure)
    if scope.github_org:
        if tool_available("trufflehog"):
            info(f"trufflehog: scanning GitHub org {scope.github_org} for verified secrets")
            truff_out = out / f"trufflehog_{scope.github_org}.json"
            run_tool(
                ["trufflehog", "github", f"--org={scope.github_org}",
                 "--only-verified", "--json"],
                truff_out, timeout=2400,
            )
            hits = [l for l in read_lines(truff_out) if l and "{" in l]
            if hits:
                critical(f"trufflehog: {len(hits)} VERIFIED secrets in {scope.github_org}!")
            else:
                success(f"trufflehog: No verified secrets in {scope.github_org}")
        else:
            warn("trufflehog not found. Install:")
            warn("  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin")

    # gitleaks -- scans github.com repos (not target infrastructure)
    if scope.github_org:
        if tool_available("gitleaks"):
            info(f"gitleaks: scanning GitHub org {scope.github_org}")
            run_tool(
                ["gitleaks", "detect",
                 "--source", f"https://github.com/{scope.github_org}",
                 "-v", "--report-format", "json",
                 "--report-path", str(out / "gitleaks_report.json")],
                timeout=900,
            )
        else:
            warn("gitleaks not found. Install: apt install gitleaks")

    # HIBP public breach list -- queries haveibeenpwned.com (third-party)
    info("HIBP: checking public breach data for domain exposure")
    try:
        r = requests.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            headers={"User-Agent": "ASM-Enterprise-Script/1.0"},
            timeout=15,
        )
        if r.ok:
            all_breaches = r.json()
            for domain in scope.domains:
                matches = [b for b in all_breaches if domain.lower() in b.get("Domain", "").lower()]
                if matches:
                    write_json(out / f"hibp_{domain}.json", matches)
                    warn(f"HIBP: {len(matches)} breach(es) for {domain}")
                    for b in matches[:5]:
                        console.print(f"    [yellow]{b.get('Name', '?')}[/] "
                                      f"({b.get('BreachDate', '?')}): {b.get('DataClasses', [])}")
                else:
                    success(f"HIBP: No direct breach records for {domain}")
    except Exception as exc:
        warn(f"HIBP API failed: {exc}")

    # CISA KEV -- passive download from cisa.gov (not target infrastructure)
    info("CISA KEV: downloading Known Exploited Vulnerabilities catalog")
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=30,
        )
        if r.ok:
            kev_data = r.json()
            (out / "cisa_kev.json").write_text(r.text, encoding="utf-8")
            kev_count = len(kev_data.get("vulnerabilities", []))
            success(f"CISA KEV: {kev_count} known-exploited CVEs saved")
            info("Cross-reference this catalog against service versions found in Phases 5-8")
    except Exception as exc:
        warn(f"CISA KEV download failed: {exc}")

    # nuclei exposures/tokens -- reads server responses for accidentally exposed secrets
    if tool_available("nuclei"):
        info("nuclei: scanning for exposed tokens/secrets in server responses")
        run_tool(
            ["nuclei", "-l", str(subs_file), "-t", "exposures/tokens/",
             "-o", str(out / "nuclei_exposed_tokens.txt"), "-silent"],
            timeout=600,
        )
        token_hits = read_lines(out / "nuclei_exposed_tokens.txt")
        if token_hits:
            critical(f"nuclei: {len(token_hits)} exposed tokens/secrets found in HTTP responses!")
            for h in token_hits[:10]:
                console.print(f"    [red]{h}[/]")

    # GitHub dork file -- no network, offline generation
    info("Generating GitHub code search dork file")
    dorks: List[str] = []
    for domain in scope.domains:
        org_handle = scope.github_org or domain.split(".")[0]
        dorks += [
            f"org:{org_handle} api_key",
            f"org:{org_handle} aws_secret_access_key",
            f"org:{org_handle} BEGIN RSA PRIVATE KEY",
            f"org:{org_handle} BEGIN OPENSSH PRIVATE KEY",
            f"org:{org_handle} internal.{domain}",
            f"org:{org_handle} password",
            f"org:{org_handle} token",
            f"org:{org_handle} secret",
            f"org:{org_handle} db_password",
            f"org:{org_handle} DATABASE_URL",
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" .env',
            f'"{domain}" "Authorization:"',
        ]
    save_lines(out / "github_dorks.txt", dorks)
    info(f"GitHub dorks saved -> {out / 'github_dorks.txt'}")
    info("Run at: https://github.com/search?q=<dork>&type=code (requires login)")

    success("Phase 10 complete.")


# =============================================================================
# PHASE 11 -- CERTIFICATE MONITORING (CertStream)
# Technique: WebSocket connection to certstream.calidog.io (third-party CT
#            aggregator). Does not connect to target infrastructure.
# =============================================================================

def phase11_certstream(scope: Scope) -> None:
    section("Phase 11 -- Continuous Certificate Monitoring (CertStream)")
    out = make_dir(scope.output_dir, "phase11_certstream")

    if not CERTSTREAM_AVAILABLE:
        error("certstream library not installed.")
        warn("Install: pip3 install certstream")
        return

    alerts_file = out / "cert_alerts.jsonl"
    monitored = scope.domains[:]

    console.print(f"\n  Monitoring for: [cyan]{', '.join(monitored)}[/cyan]")
    console.print("  New certificates appear within seconds of issuance.")
    console.print("  [yellow]Let's Encrypt certs on your domains may indicate active takeovers.[/yellow]")
    console.print("  Press Ctrl+C to stop.\n")

    alert_count = 0

    def callback(message: Dict, context: Any) -> None:
        nonlocal alert_count
        if message.get("message_type") != "certificate_update":
            return
        try:
            leaf = message["data"]["leaf_cert"]
            cert_domains = leaf.get("all_domains", [])
            issuer_org = leaf.get("issuer", {}).get("O", "Unknown")
            for cert_domain in cert_domains:
                for watched in monitored:
                    if cert_domain.endswith(f".{watched}") or cert_domain == watched:
                        alert_count += 1
                        le_flag = ""
                        if "Let's Encrypt" in issuer_org:
                            le_flag = " [bold red]<-- LET'S ENCRYPT -- CHECK FOR TAKEOVER[/bold red]"
                        append_line(alerts_file, json.dumps({
                            "ts": datetime.datetime.utcnow().isoformat(),
                            "cert_domain": cert_domain,
                            "issuer_org": issuer_org,
                            "all_domains_on_cert": cert_domains[:15],
                        }))
                        console.print(
                            f"  [green][CERT][/green] {cert_domain} | "
                            f"Issuer: {issuer_org}{le_flag}"
                        )
        except Exception:
            pass

    try:
        certstream.listen_for_events(callback, url="wss://certstream.calidog.io/")
    except KeyboardInterrupt:
        console.print(f"\n  [yellow]CertStream stopped. {alert_count} events.[/yellow]")
        success(f"Alerts saved -> {alerts_file}")


# =============================================================================
# SUMMARY REPORT
# =============================================================================

def generate_summary(scope: Scope) -> Path:
    summary = {
        "engagement": {
            "domains": scope.domains,
            "ip_ranges": scope.ip_ranges,
            "org_name": scope.org_name,
            "asn": scope.asn,
            "github_org": scope.github_org,
            "script": "asm_recon.py (light-active tier)",
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "output_dir": str(scope.output_dir),
        },
        "finding_highlights": {},
    }

    checks = [
        ("ct_subdomain_count",        "phase2_osint/ct_subdomains.txt",                          "count"),
        ("resolved_subdomain_count",  "phase3_dns/resolved_subdomains.txt",                      "count"),
        ("email_security_issues",     "phase3_dns/email_security_analysis.json",                 "json"),
        ("dangling_cnames",           "phase7_takeover/dangling_cnames.json",                    "json"),
        ("nuclei_takeovers",          "phase7_takeover/nuclei_takeovers.txt",                    "lines"),
        ("httpx_takeover_hits",       "phase6_validation/httpx_takeover_candidates.json",        "json"),
        ("expired_certs",             "phase6_validation/cert_findings.json",                    "json"),
        ("cors_wildcard",             "phase6_validation/cors_wildcard.txt",                     "count"),
        ("nuclei_exposed_configs",    "phase8_fingerprint/nuclei_exposed_configs.txt",           "count"),
        ("nuclei_exposed_tokens",     "phase10_leaks/nuclei_exposed_tokens.txt",                 "count"),
        ("trufflehog_secrets",        f"phase10_leaks/trufflehog_{scope.github_org}.json",       "count"),
        ("hibp_matches",              f"phase10_leaks/hibp_{scope.primary_domain}.json",         "json"),
        ("s3_public_buckets",         "phase9_cloud/s3_findings.json",                           "json"),
        ("js_endpoints_found",        f"phase8_fingerprint/js_endpoints_{scope.primary_domain}.txt", "count"),
        ("cisa_kev_count",            "phase10_leaks/cisa_kev.json",                             "kev"),
    ]

    for key, rel_path, fmt in checks:
        full = scope.output_dir / rel_path
        if not full.exists():
            continue
        try:
            if fmt == "json":
                summary["finding_highlights"][key] = json.loads(full.read_text())
            elif fmt == "lines":
                summary["finding_highlights"][key] = read_lines(full)[:50]
            elif fmt == "count":
                summary["finding_highlights"][key] = len(read_lines(full))
            elif fmt == "kev":
                summary["finding_highlights"][key] = len(
                    json.loads(full.read_text()).get("vulnerabilities", [])
                )
        except Exception:
            pass

    path = scope.output_dir / "SUMMARY_REPORT.json"
    path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    return path


# =============================================================================
# PHASE MENU
# =============================================================================

PHASE_FUNCTIONS = {
    1:  phase1_seed,
    2:  phase2_osint,
    3:  phase3_dns,
    4:  phase4_asn,
    5:  phase5_passive_intel,
    6:  phase6_validation,
    7:  phase7_takeover,
    8:  phase8_fingerprint,
    9:  phase9_cloud,
    10: phase10_leaks,
    11: phase11_certstream,
}


def show_not_automatable() -> None:
    console.print("\n  [bold red]Not automated in this script:[/bold red]\n")
    for name, reason in NOT_AUTOMATABLE:
        console.print(f"  [bold yellow]{name}[/bold yellow]")
        for line in reason.splitlines():
            console.print(f"    {line}")
        console.print()


def show_removed_tools() -> None:
    console.print("\n  [bold red]Removed (saved for asm_active.py):[/bold red]\n")
    t = Table(show_header=True, header_style="bold red")
    t.add_column("Tool / Template", style="yellow", width=30)
    t.add_column("Reason removed", style="white")
    for tool, reason in REMOVED_FOR_ACTIVE_SCRIPT:
        t.add_row(tool, reason)
    console.print(t)


def show_added_tools() -> None:
    console.print("\n  [bold green]Added in this script:[/bold green]\n")
    t = Table(show_header=True, header_style="bold green")
    t.add_column("Tool / Feature", style="cyan", width=30)
    t.add_column("What it does", style="white")
    for tool, desc in ADDED_TOOLS:
        t.add_row(tool, desc)
    console.print(t)


def phase_menu() -> List[int]:
    console.print("\n  [bold cyan]Available Phases:[/bold cyan]\n")
    t = Table(show_header=True, header_style="bold magenta")
    t.add_column("#", style="cyan", width=4)
    t.add_column("Phase", style="white")
    for num, desc in PHASES.items():
        t.add_row(str(num), desc)
    console.print(t)

    console.print(
        "\n  [cyan]all[/]      -- Run all phases\n"
        "  [cyan]1,3,7[/]    -- Run specific phases\n"
        "  [cyan]info[/]     -- Show what cannot be automated\n"
        "  [cyan]removed[/]  -- Show what was removed (for asm_active.py)\n"
        "  [cyan]added[/]    -- Show what was added vs asm_enterprise.py\n"
    )

    choice = Prompt.ask("  Select phases").strip().lower()

    if choice == "info":
        show_not_automatable()
        return phase_menu()
    if choice == "removed":
        show_removed_tools()
        return phase_menu()
    if choice == "added":
        show_added_tools()
        return phase_menu()
    if choice == "all":
        return sorted(PHASE_FUNCTIONS.keys())

    selected: List[int] = []
    for part in choice.split(","):
        part = part.strip()
        try:
            n = int(part)
            if n in PHASE_FUNCTIONS:
                selected.append(n)
            else:
                warn(f"Phase {n} not available here (see 'removed' or 'info').")
        except ValueError:
            if part:
                warn(f"'{part}' is not a valid phase number.")
    return selected


# =============================================================================
# ENTRY POINT
# =============================================================================

def main() -> None:
    console.print(BANNER, style="bold cyan")

    console.print(
        Panel(
            "[bold green]LIGHT-ACTIVE RECON TIER[/bold green]\n\n"
            "All actions in this script simulate normal internet activity:\n"
            "  - HTTP/S requests are identical to a browser visiting a page\n"
            "  - DNS queries go through public resolvers\n"
            "  - No packets are crafted or sent directly to target ports\n"
            "  - No credentials are tested, no CVEs are exploited\n\n"
            "For port scanning, CVE testing, and default-login checks,\n"
            "use [bold]asm_active.py[/bold] (future script) with written authorization.\n\n"
            "[bold red]Written authorization from an appropriate executive is still\n"
            "required before running any reconnaissance against a target.[/bold red]",
            title="[bold white]asm_recon.py[/bold white]",
            border_style="green",
        )
    )

    if not Confirm.ask("\n  I confirm I have written authorization to assess all assets in my defined scope"):
        console.print("  Exiting.")
        sys.exit(0)

    scope = Scope()
    scope.prompt()

    selected = phase_menu()
    if not selected:
        error("No valid phases selected.")
        sys.exit(1)

    console.print(f"\n  Phases queued: [cyan]{sorted(selected)}[/cyan]\n")
    start_time = datetime.datetime.now()

    for phase_num in sorted(selected):
        try:
            PHASE_FUNCTIONS[phase_num](scope)
        except KeyboardInterrupt:
            warn(f"Phase {phase_num} interrupted -- continuing.")
        except Exception as exc:
            error(f"Phase {phase_num} unhandled exception: {exc}")
            import traceback
            traceback.print_exc()

    elapsed = datetime.datetime.now() - start_time
    console.rule("[bold green]Complete[/bold green]")

    summary_path = generate_summary(scope)
    console.print(f"\n  [bold green]Summary report:[/bold green]  {summary_path}")
    console.print(f"  [bold green]All outputs:[/bold green]      {scope.output_dir}/")
    console.print(f"  [bold green]Elapsed:[/bold green]          {str(elapsed).split('.')[0]}\n")


if __name__ == "__main__":
    main()
