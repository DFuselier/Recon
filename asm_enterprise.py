#!/usr/bin/env python3
"""
ASM Enterprise - Attack Surface Management Automation Script
Based on: Enterprise Financial Services ASM SOP v1.0
FOR AUTHORIZED PENTESTING / SECURITY ASSESSMENT USE ONLY.
Ensure written authorization before running active phases.
"""

import os
import sys
import json
import subprocess
import datetime
import ipaddress
import re
import time
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
    import dns.name
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
    from rich import print as rprint
except ImportError:
    print("[!] 'rich' not found. Run: pip3 install rich")
    sys.exit(1)

SHODAN_AVAILABLE = False
CENSYS_AVAILABLE = False
CERTSTREAM_AVAILABLE = False

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

console = Console()


# =============================================================================
# CONSTANTS & REFERENCE DATA
# =============================================================================

BANNER = r"""
   ___   ____  __  __   _____       _                       _
  / _ \ / ___||  \/  | | ____|_ __ | |_ ___ _ __ _ __  _ __(_)___  ___
 | | | |\___ \| |\/| | |  _| | '_ \| __/ _ \ '__| '_ \| '__| / __|/ _ \
 | |_| | ___) | |  | | | |___| | | | ||  __/ |  | |_) | |  | \__ \  __/
  \___/ |____/|_|  |_| |_____|_| |_|\__\___|_|  | .__/|_|  |_|___/\___|
                                                  |_|
     Attack Surface Management -- Enterprise Financial Services SOP v1.0
     *** FOR AUTHORIZED USE ONLY ***
"""

PHASES: Dict[int, str] = {
    1:  "Seed Data Collection & Asset Universe Definition",
    2:  "Certificate Transparency & Passive Recon  (crt.sh + Censys + Shodan)",
    3:  "DNS Enumeration  (Subfinder, Amass, PureDNS, dnsx, AXFR)",
    4:  "IP Space & ASN Enumeration  (WHOIS, ipinfo.io, PTR reversal)",
    5:  "Internet-Wide Scanning  (Shodan/Censys passive  +  masscan/nmap active)",
    6:  "Asset Validation & Liveness  (httpx, tlsx, certificate analysis)",
    7:  "Subdomain Takeover Detection  (nuclei, subjack, CNAME chain analysis)",
    8:  "Web Application Fingerprinting  (whatweb, nuclei, JS endpoint analysis)",
    9:  "Cloud Asset Discovery  (S3Scanner, cloud_enum -- no credentials needed)",
    10: "Vulnerability Analysis  (nuclei CVE/exposure/default-logins + CISA KEV)",
    11: "Credential & Data Leak Monitoring  (trufflehog, gitleaks, HIBP)",
    14: "Continuous Certificate Monitoring  (CertStream real-time WebSocket)",
}

NOT_AUTOMATABLE: List[Tuple[str, str]] = [
    (
        "Phase 12 -- Third-Party & Supply Chain Exposure",
        "Requires a manually obtained vendor/SaaS list from the target IT team.\n"
        "Manual action: request procurement records, SSO audit logs, and OAuth\n"
        "consent lists from the target organization.",
    ),
    (
        "Phase 13 -- M&A Pre-Acquisition ASM Assessment",
        "This is a COMPOSITE of Phases 2, 3, 6, 7, 9, 10, and 11 run in passive-only\n"
        "mode. Select those phases individually and answer NO to active scanning.",
    ),
    (
        "Phase 15 -- Dark Web & Flashpoint Monitoring",
        "Requires a Flashpoint, Recorded Future, or IntelX enterprise license.\n"
        "Configure keyword alert Collections in your Flashpoint portal manually\n"
        "within 24 hours of each deal close.",
    ),
    (
        "Phase 16 -- Authenticated Cloud Posture (ScoutSuite / Prowler)",
        "Requires provisioned cloud credentials. Once you have them:\n"
        "  AWS:   prowler aws -g cis_level2 -M json,csv\n"
        "  Azure: python3 scout.py azure\n"
        "  GCP:   python3 scout.py gcp",
    ),
    (
        "Phase 17 -- SOAR / Ticketing Alert Integration",
        "Requires platform-specific API tokens and webhook config.\n"
        "  go install github.com/projectdiscovery/notify/cmd/notify@latest\n"
        "  cat findings.txt | notify -provider slack",
    ),
    (
        "Phase 18 -- HaveIBeenPwned Enterprise / DeHashed / IntelX",
        "Public HIBP breach list is checked automatically. Enterprise domain-level\n"
        "API, DeHashed, and IntelX all require paid API keys.",
    ),
    (
        "IMDSv2 Remediation",
        "Detection via Shodan is included. Remediation requires AWS credentials:\n"
        "  aws ec2 modify-instance-metadata-options --instance-id i-xxx\n"
        "  --http-tokens required --http-put-response-hop-limit 1",
    ),
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
}

DANGEROUS_CNAME_TARGETS: List[str] = [
    "herokuapp.com", "github.io", "azurewebsites.net", "netlify.app",
    "netlify.com", "s3.amazonaws.com", "cloudfront.net", "fastly.net",
    "web.app", "firebaseapp.com", "myshopify.com", "zendesk.com",
    "hubspot.com", "ghost.io", "pingdom.com", "wordpress.com",
    "tumblr.com", "mailchimpsites.com", "helpscoutdocs.com",
    "desk.com", "campaignmonitor.com", "cargo.site",
]

FINANCIAL_RISK_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    1433, 1521, 2375, 2376, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 9090, 9200, 9300, 27017,
]

BUCKET_SUFFIXES: List[str] = [
    "-prod", "-staging", "-dev", "-backup", "-logs", "-data",
    "-archive", "-reports", "-assets", "-static", "-media",
    "-files", "-uploads", "-images", "-cdn", "-api", "-db",
    "-database", "-config", "-deploy", "-release", "-builds",
]

RESOLVERS_URL = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"


# =============================================================================
# PASSIVE-ONLY MODE DEFINITION
#
# MAXIMUM passive mode -- only the following sources run:
#   crt.sh API, Shodan API, Censys API, ARIN API, ipinfo.io API, RADB whois,
#   Wayback Machine API, HIBP API, CISA KEV download (cisa.gov),
#   CertStream WebSocket (certstream.calidog.io -- third-party CT aggregator),
#   trufflehog on GitHub repos (github.com -- not target),
#   gitleaks on GitHub repos (github.com -- not target)
#
# Everything else generates DNS queries, TCP connections, or HTTP requests
# that reach the target's own infrastructure or nameservers and is SKIPPED.
# =============================================================================

# (phase_number, tool_name, reason_skipped)
PASSIVE_SKIPS: Dict[int, List[Tuple[str, str]]] = {
    3: [
        ("subfinder",
         "aggregates from sources that ultimately resolve via target nameservers"),
        ("amass (passive)",
         "same -- feeds through sources that probe target DNS"),
        ("AXFR zone transfer",
         "direct TCP/UDP query to target's authoritative nameservers"),
        ("dnsrecon AXFR",
         "direct TCP/UDP query to target's authoritative nameservers"),
        ("puredns",
         "mass DNS resolution -- queries route through target nameservers"),
        ("dnsx",
         "DNS A/CNAME lookups -- queries route through target nameservers"),
        ("massdns PTR",
         "bulk reverse-DNS across target IP ranges"),
    ],
    4: [
        ("massdns PTR",
         "bulk reverse-DNS across target IP ranges"),
        ("Python PTR fallback",
         "reverse-DNS queries across target IP ranges"),
    ],
    5: [
        ("masscan",
         "TCP SYN packets sent directly to target IP ranges"),
        ("nmap (web ports)",
         "TCP connections and HTTP requests to target ports"),
        ("nmap (TLS)",
         "TLS handshakes to target port 443"),
        ("nmap (SMB / MS17-010)",
         "TCP connections to target port 445"),
    ],
    6: [
        ("httpx",
         "HTTP/S connections to every discovered target host"),
        ("tlsx",
         "TLS handshakes to every discovered HTTPS host"),
        ("CAA record check",
         "DNS queries that route through target nameservers"),
    ],
    7: [
        ("nuclei (takeovers/)",
         "HTTP requests to target hosts to fingerprint responses"),
        ("subjack",
         "HTTP requests to target hosts for takeover detection"),
        ("Python CNAME analysis",
         "DNS queries that ultimately reach target nameservers"),
    ],
    8: [
        ("whatweb",
         "direct HTTP requests to every target host"),
        ("nuclei (technologies/)",
         "HTTP requests to target hosts for fingerprinting"),
        ("nuclei (exposures/apis/)",
         "HTTP requests probing target hosts for exposed API docs"),
        ("HTTP header analysis",
         "depends on httpx output which is also skipped"),
        ("gau",
         "URL archive lookups that involve resolving the target domain"),
    ],
    9: [
        ("cloud_enum",
         "HTTP requests to AWS/Azure/GCP endpoints for bucket enumeration"),
        ("S3 HEAD checks",
         "direct HTTP requests to AWS S3 endpoints using target-derived names"),
    ],
    10: [
        ("nuclei (cves/)",
         "HTTP requests to target hosts testing for CVE exploitability"),
        ("nuclei (exposures/)",
         "HTTP requests probing target hosts for exposed files/configs"),
        ("nuclei (default-logins/)",
         "HTTP requests testing default credentials on target services"),
        ("nuclei (misconfiguration/)",
         "HTTP requests checking target hosts for misconfigurations"),
        ("nuclei (exposed-panels/)",
         "HTTP requests probing target hosts for admin interfaces"),
        ("nuclei (cloud/)",
         "HTTP requests checking cloud exposure on target hosts"),
    ],
    11: [
        ("nuclei (exposures/tokens/)",
         "HTTP requests to target hosts scanning for exposed tokens"),
    ],
}

# What DOES run per phase in passive-only mode
PASSIVE_RETAINED: Dict[int, List[str]] = {
    1:  ["whois (queries registrar, not target)",
         "ARIN REST API", "ipinfo.io ASN API", "RADB whois", "Wayback Machine API"],
    2:  ["crt.sh API", "Censys API", "Shodan API"],
    3:  ["CT subdomain data from Phase 2 carried forward as the subdomain list (no new queries)"],
    4:  ["ipinfo.io ASN API", "Shodan ASN API"],
    5:  ["Shodan API queries (IP/org)", "Censys API queries (IP ranges)"],
    6:  ["(entire phase skipped)"],
    7:  ["(entire phase skipped)"],
    8:  ["(entire phase skipped)"],
    9:  ["Shodan cloud-focused API queries",
         "Bucket permutation list saved (no requests sent)"],
    10: ["CISA KEV catalog download (cisa.gov -- not target infrastructure)"],
    11: ["trufflehog on GitHub org repos (github.com -- not target)",
         "gitleaks on GitHub org repos (github.com -- not target)",
         "HIBP API (haveibeenpwned.com -- not target)",
         "GitHub dork query file generated (no network requests)"],
    14: ["CertStream WebSocket (certstream.calidog.io -- third-party CT aggregator)"],
}


def show_passive_only_notice() -> None:
    """Print the full skips table and retained actions table."""
    console.print()
    console.print(
        Panel(
            "[bold yellow]PASSIVE-ONLY MODE ACTIVE[/bold yellow]\n\n"
            "Only direct read-only API calls to trusted third-party services run.\n"
            "Every tool that generates DNS queries, TCP connections, or HTTP requests\n"
            "directed at or routing through the target's own infrastructure is SKIPPED.",
            title="[bold yellow]Passive-Only Mode[/bold yellow]",
            border_style="yellow",
        )
    )

    console.print("\n  [bold red]SKIPPED in passive-only mode:[/bold red]")
    t_skip = Table(show_header=True, header_style="bold red", show_lines=True)
    t_skip.add_column("Phase", style="cyan", width=7, no_wrap=True)
    t_skip.add_column("Tool / Step Skipped", style="yellow", width=30)
    t_skip.add_column("Reason", style="white")
    for phase_num, items in PASSIVE_SKIPS.items():
        phase_short = PHASES.get(phase_num, "").split("(")[0].strip()
        for i, (tool, reason) in enumerate(items):
            label = f"Ph.{phase_num}" if i == 0 else ""
            t_skip.add_row(label, tool, reason)
    console.print(t_skip)

    console.print("\n  [bold green]STILL RUNS in passive-only mode:[/bold green]")
    t_keep = Table(show_header=True, header_style="bold green", show_lines=True)
    t_keep.add_column("Phase", style="cyan", width=7, no_wrap=True)
    t_keep.add_column("Retained Action (third-party API / offline only)", style="green")
    for phase_num, items in PASSIVE_RETAINED.items():
        for i, item in enumerate(items):
            label = f"Ph.{phase_num}" if i == 0 else ""
            t_keep.add_row(label, item)
    console.print(t_keep)
    console.print()


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

def skipped(label: str) -> None:
    console.print(f"  [dim yellow][PASSIVE-SKIP] {label}[/dim yellow]")


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
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, **(env or {})},
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


def get_resolvers(output_dir: Path) -> Path:
    rf = output_dir / "resolvers.txt"
    if rf.exists() and len(read_lines(rf)) > 10:
        return rf
    try:
        r = requests.get(RESOLVERS_URL, timeout=30)
        rf.write_text(r.text, encoding="utf-8")
        info(f"Downloaded {len(r.text.splitlines())} resolvers.")
    except Exception:
        rf.write_text("8.8.8.8\n1.1.1.1\n9.9.9.9\n8.8.4.4\n", encoding="utf-8")
        warn("Could not download resolvers list -- using fallback.")
    return rf


# =============================================================================
# SCOPE & SESSION
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
        # Set False at startup when user declines active scanning.
        # When False, only direct read-only third-party API calls execute.
        self.active_allowed: bool = True

    def prompt(self) -> None:
        section("Scope Definition")
        warn("Provide ONLY assets you are authorized to assess.")

        raw_domains = Prompt.ask(
            "\n  [cyan]Root domain(s)[/cyan]  (comma-separated, e.g. target.com,sub.target.com)"
        )
        self.domains = [d.strip().lower() for d in raw_domains.split(",") if d.strip()]

        raw_ips = Prompt.ask(
            "  [cyan]IP / CIDR range(s)[/cyan]  (comma-separated, or ENTER to skip)",
            default="",
        )
        if raw_ips.strip():
            self.ip_ranges = [r.strip() for r in raw_ips.split(",") if r.strip()]

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
            "  [cyan]Shodan API key[/cyan]  (or set SHODAN_API_KEY env var, ENTER to skip)",
            default="", password=True,
        )
        self.censys_id = os.environ.get("CENSYS_API_ID") or Prompt.ask(
            "  [cyan]Censys API ID[/cyan]  (or set CENSYS_API_ID env var, ENTER to skip)",
            default="", password=True,
        )
        self.censys_secret = os.environ.get("CENSYS_API_SECRET") or Prompt.ask(
            "  [cyan]Censys API Secret[/cyan]  (or set CENSYS_API_SECRET env var, ENTER to skip)",
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
        candidates = [
            self.output_dir / "phase3_dns" / "resolved_subdomains.txt",
            self.output_dir / "phase3_dns" / "all_subdomains_raw.txt",
            self.output_dir / "phase2_ct" / "ct_subdomains.txt",
        ]
        for c in candidates:
            if c.exists() and read_lines(c):
                return c
        fallback = self.output_dir / "scope_domains.txt"
        save_lines(fallback, self.domains)
        return fallback


# =============================================================================
# PHASE 1 -- SEED DATA COLLECTION
# All actions query registrar/registry APIs -- runs in full regardless of mode.
# =============================================================================

def phase1_seed(scope: Scope) -> None:
    section("Phase 1 -- Seed Data Collection & Asset Universe Definition")
    out = make_dir(scope.output_dir, "phase1_seed")

    write_json(out / "seed_data.json", {
        "domains": scope.domains,
        "ip_ranges": scope.ip_ranges,
        "org_name": scope.org_name,
        "asn": scope.asn,
        "active_mode": scope.active_allowed,
        "timestamp": datetime.datetime.utcnow().isoformat(),
    })
    success(f"Seed data saved -> {out / 'seed_data.json'}")

    for domain in scope.domains:
        info(f"WHOIS: {domain}")
        run_tool(["whois", domain], out / f"whois_{domain}.txt", timeout=30)

    if scope.org_name:
        info(f"ARIN REST search for: {scope.org_name}")
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
                    success(f"AS{asn_digits}: {len(prefixes)} prefixes saved.")
        except Exception as exc:
            warn(f"ipinfo.io ASN lookup failed: {exc}")

        asn_tag = scope.asn.upper()
        if not asn_tag.startswith("AS"):
            asn_tag = "AS" + asn_tag
        info(f"RADB route lookup for {asn_tag}")
        radb_raw = run_tool(
            ["whois", "-h", "whois.radb.net", "--", f"-i origin {asn_tag}"],
            out / f"radb_{asn_tag}.txt",
            timeout=30,
        )
        if radb_raw:
            routes = re.findall(r"route(?:6)?:\s+(\S+)", radb_raw)
            if routes:
                save_lines(out / "radb_routes.txt", routes)
                success(f"RADB: {len(routes)} route entries found.")

    for domain in scope.domains[:3]:
        try:
            r = requests.get(f"https://archive.org/wayback/available?url={domain}", timeout=10)
            if r.ok:
                wb = r.json()
                write_json(out / f"wayback_{domain}.json", wb)
                snap = wb.get("archived_snapshots", {}).get("closest", {})
                if snap:
                    info(f"Wayback Machine: earliest snapshot for {domain} at {snap.get('timestamp', '?')}")
        except Exception:
            pass

    success("Phase 1 complete.")


# =============================================================================
# PHASE 2 -- CERTIFICATE TRANSPARENCY & PASSIVE RECON
# All actions query third-party APIs -- runs in full regardless of mode.
# =============================================================================

def phase2_ct(scope: Scope) -> None:
    section("Phase 2 -- Certificate Transparency & Passive Recon")
    out = make_dir(scope.output_dir, "phase2_ct")
    all_subdomains: Set[str] = set()

    for domain in scope.domains:
        for query in [f"%.{domain}", domain]:
            info(f"crt.sh query: {query}")
            try:
                r = requests.get(
                    f"https://crt.sh/?q={requests.utils.quote(query)}&output=json",
                    timeout=60,
                    headers={"Accept": "application/json"},
                    verify=False,
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
                else:
                    warn(f"crt.sh returned HTTP {r.status_code} for {query}")
            except Exception as exc:
                warn(f"crt.sh query failed for {query}: {exc}")

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

    if scope.censys_id and scope.censys_secret and CENSYS_AVAILABLE:
        info("Querying Censys API for certificate/host data")
        try:
            os.environ["CENSYS_API_ID"] = scope.censys_id
            os.environ["CENSYS_API_SECRET"] = scope.censys_secret
            h = CensysHosts()
            for domain in scope.domains:
                results = []
                for page in h.search(f"parsed.names: {domain}", per_page=100, pages=5):
                    results.extend(page)
                write_json(out / f"censys_hosts_{domain}.json", results)
                success(f"Censys: {len(results)} hosts found for {domain}")
        except Exception as exc:
            warn(f"Censys API query failed: {exc}")
    elif scope.censys_id:
        warn("Censys library not installed -- skipping. (pip3 install censys)")

    if scope.shodan_key and SHODAN_AVAILABLE:
        info("Querying Shodan for SSL certificate matches")
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
            warn(f"Shodan API query failed: {exc}")
    elif scope.shodan_key:
        warn("Shodan library not installed -- skipping. (pip3 install shodan)")

    if all_subdomains:
        save_lines(out / "ct_subdomains.txt", list(all_subdomains))
        success(f"CT passive recon total unique subdomains: {len(all_subdomains)}")

    success("Phase 2 complete.")


# =============================================================================
# PHASE 3 -- DNS ENUMERATION
# PASSIVE MODE: All DNS tools skipped. CT subdomain list from Phase 2 is
# carried forward unchanged as the subdomain list for downstream phases.
# ACTIVE MODE: subfinder, amass, AXFR, puredns, dnsx run.
# =============================================================================

def phase3_dns(scope: Scope) -> None:
    section("Phase 3 -- DNS Enumeration")
    out = make_dir(scope.output_dir, "phase3_dns")
    all_subdomains: Set[str] = set()

    ct_file = scope.output_dir / "phase2_ct" / "ct_subdomains.txt"
    if ct_file.exists():
        all_subdomains.update(read_lines(ct_file))
        info(f"Loaded {len(all_subdomains)} subdomains from Phase 2 CT data")

    if not scope.active_allowed:
        warn("PASSIVE-ONLY MODE: All DNS enumeration tools skipped.")
        for tool, reason in PASSIVE_SKIPS[3]:
            skipped(f"{tool} -- {reason}")
        if all_subdomains:
            f = out / "all_subdomains_raw.txt"
            save_lines(f, list(all_subdomains))
            info(f"Subdomain list carried forward from CT data: {len(all_subdomains)} entries")
        else:
            warn("No CT subdomain data found -- run Phase 2 first.")
        success("Phase 3 complete (passive -- CT data only).")
        return

    # ── Active DNS enumeration ─────────────────────────────────────────────
    for domain in scope.domains:
        info(f"--- Enumerating: {domain} ---")

        if tool_available("subfinder"):
            sf_out = out / f"subfinder_{domain}.txt"
            info("Running Subfinder (50+ passive sources)")
            run_tool(["subfinder", "-d", domain, "-all", "-silent", "-o", str(sf_out)], timeout=300)
            results = read_lines(sf_out)
            all_subdomains.update(results)
            success(f"Subfinder: {len(results)} results")
        else:
            warn("subfinder not found. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")

        if tool_available("amass"):
            am_out = out / f"amass_{domain}.txt"
            info("Running Amass (passive mode)")
            run_tool(["amass", "enum", "-passive", "-d", domain, "-o", str(am_out)], timeout=600)
            results = read_lines(am_out)
            all_subdomains.update(results)
            success(f"Amass: {len(results)} results")
        else:
            warn("amass not found. Install: apt install amass  OR  snap install amass")

        info(f"Attempting AXFR zone transfer for {domain}")
        try:
            ns_answers = dns.resolver.resolve(domain, "NS")
            nameservers = [str(r).rstrip(".") for r in ns_answers]
            for ns in nameservers:
                info(f"  AXFR attempt -> {ns}")
                try:
                    xfr = dns.query.xfr(ns, domain, timeout=10, lifetime=15)
                    zone = dns.zone.from_xfr(xfr)
                    zone_names = [str(n) for n in zone.nodes.keys()]
                    axfr_file = out / f"AXFR_SUCCESS_{domain}_{ns}.txt"
                    axfr_file.write_text("\n".join(zone_names), encoding="utf-8")
                    critical(f"AXFR SUCCEEDED against {ns}! Critical misconfiguration. Zone saved.")
                    for n in zone_names:
                        if n not in ("@", ""):
                            all_subdomains.add(f"{n}.{domain}")
                except Exception as axfr_err:
                    info(f"    AXFR blocked/failed at {ns}: {type(axfr_err).__name__}")
        except Exception as exc:
            warn(f"NS resolution failed for {domain}: {exc}")

        if tool_available("dnsrecon"):
            run_tool(
                ["dnsrecon", "-d", domain, "-t", "axfr"],
                out / f"dnsrecon_axfr_{domain}.txt",
                timeout=60,
            )

    all_subs_file = out / "all_subdomains_raw.txt"
    save_lines(all_subs_file, list(all_subdomains))
    info(f"Total raw subdomains before resolution: {len(all_subdomains)}")

    resolvers_file = get_resolvers(out)

    if tool_available("puredns"):
        info("Running PureDNS (wildcard detection + mass resolution)")
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
        success(f"PureDNS: {len(read_lines(resolved_file))} subdomains resolved")
    else:
        warn("puredns not found. Install: go install github.com/d3mondev/puredns/v2@latest")
        resolved_file = all_subs_file

    if tool_available("dnsx"):
        info("Running dnsx for A/CNAME record breakdown")
        dnsx_out = out / "dnsx_resolved.txt"
        run_tool(
            ["dnsx", "-l", str(resolved_file), "-a", "-cname", "-resp", "-o", str(dnsx_out), "-silent"],
            timeout=600,
        )
        success(f"dnsx record breakdown saved -> {dnsx_out}")
    else:
        warn("dnsx not found. Install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest")

    success("Phase 3 complete.")


# =============================================================================
# PHASE 4 -- IP SPACE & ASN ENUMERATION
# ipinfo.io and Shodan API always run.
# PTR / reverse-DNS skipped in passive mode.
# =============================================================================

def phase4_asn(scope: Scope) -> None:
    section("Phase 4 -- IP Space & ASN Enumeration")
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
        info(f"Fetching full ASN info for AS{asn_digits} via ipinfo.io")
        try:
            r = requests.get(f"https://ipinfo.io/AS{asn_digits}/json", timeout=15)
            if r.ok:
                data = r.json()
                write_json(out / f"asn_AS{asn_digits}_full.json", data)
                prefixes = data.get("prefixes", [])
                if prefixes:
                    save_lines(out / "asn_cidrs.txt", [p.get("netblock", "") for p in prefixes if p.get("netblock")])
                    success(f"AS{asn_digits}: {len(prefixes)} prefixes")
                console.print(f"    Org:     [cyan]{data.get('org', 'N/A')}[/]")
                console.print(f"    Country: [cyan]{data.get('country', 'N/A')}[/]")
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

    if all_ips:
        if not scope.active_allowed:
            for tool, reason in PASSIVE_SKIPS[4]:
                skipped(f"{tool} -- {reason}")
        else:
            resolvers_file = get_resolvers(out)
            if tool_available("massdns"):
                info("Running massdns for PTR (reverse DNS) lookups")
                ptr_queries_file = out / "ptr_queries.txt"
                ptr_lines = [
                    ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
                    for ip in all_ips[:10000]
                ]
                ptr_queries_file.write_text("\n".join(ptr_lines), encoding="utf-8")
                run_tool(
                    ["massdns", "-r", str(resolvers_file), "-t", "PTR",
                     str(ptr_queries_file), "-o", "S", "-w", str(out / "ptr_results.txt")],
                    timeout=600,
                )
                success("massdns PTR lookups complete")
            else:
                info("massdns not found -- running Python PTR fallback (capped at 500 IPs)")
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 2
                ptr_results = []
                for ip in all_ips[:500]:
                    try:
                        rev = dns.reversename.from_address(ip)
                        ans = resolver.resolve(rev, "PTR")
                        for rr in ans:
                            ptr_results.append(f"{ip} -> {rr}")
                    except Exception:
                        pass
                if ptr_results:
                    (out / "ptr_results.txt").write_text("\n".join(ptr_results), encoding="utf-8")
                    success(f"PTR lookups: {len(ptr_results)} hostnames found")
                warn("Install massdns for full-range PTR enumeration: apt install massdns")

    success("Phase 4 complete.")


# =============================================================================
# PHASE 5 -- INTERNET-WIDE SCANNING
# Shodan and Censys passive API queries always run.
# masscan and nmap skipped in passive mode.
# =============================================================================

def phase5_scanning(scope: Scope) -> None:
    section("Phase 5 -- Internet-Wide Scanning & Service Discovery")
    out = make_dir(scope.output_dir, "phase5_scanning")

    if scope.shodan_key and SHODAN_AVAILABLE:
        info("Shodan passive queries (IP ranges + org)")
        try:
            api = shodan_lib.Shodan(scope.shodan_key)
            for cidr in scope.ip_ranges:
                results = api.search(f"net:{cidr}")
                write_json(out / f"shodan_net_{cidr.replace('/', '_')}.json", results)
                success(f"Shodan net:{cidr} -> {results.get('total', 0)} results")
            if scope.org_name:
                for query, label in [
                    (f'org:"{scope.org_name}" http.title:"admin"', "admin_panels"),
                    (f'org:"{scope.org_name}" port:3389',           "rdp_exposed"),
                    (f'org:"{scope.org_name}" port:22',             "ssh_exposed"),
                    (f'org:"{scope.org_name}" port:9200',           "elasticsearch"),
                    (f'org:"{scope.org_name}" port:6379',           "redis"),
                    (f'org:"{scope.org_name}" port:27017',          "mongodb"),
                    (f'org:"{scope.org_name}" port:2375',           "docker_api"),
                ]:
                    results = api.search(query)
                    total = results.get("total", 0)
                    if total > 0:
                        write_json(out / f"shodan_{label}.json", results)
                        sev = "bold red" if label in ("rdp_exposed", "elasticsearch", "docker_api") else "bold yellow"
                        console.print(f"  [{sev}][!] {label.replace('_', ' ').upper()}:[/] {total} results")
        except Exception as exc:
            warn(f"Shodan passive scan failed: {exc}")

    if scope.censys_id and scope.censys_secret and CENSYS_AVAILABLE:
        info("Censys passive queries (IP ranges)")
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
            warn(f"Censys passive scan failed: {exc}")

    if not scope.ip_ranges:
        warn("No IP ranges in scope -- no active scanning possible.")
        success("Phase 5 complete (passive API queries only).")
        return

    if not scope.active_allowed:
        for tool, reason in PASSIVE_SKIPS[5]:
            skipped(f"{tool} -- {reason}")
        success("Phase 5 complete (Shodan/Censys passive results only).")
        return

    # Per-session active authorization checkpoint
    console.print("\n  [bold red][ AUTHORIZATION CHECKPOINT ][/bold red]")
    console.print("  masscan and nmap will send packets directly to the target IP ranges.")
    console.print("  Unauthorized scanning may violate the CFAA and equivalent laws.")
    if not Confirm.ask("  Do you have WRITTEN authorization to actively scan these IP ranges?"):
        warn("Active scanning declined -- passive results retained.")
        success("Phase 5 complete (passive only).")
        return

    port_str = ",".join(str(p) for p in FINANCIAL_RISK_PORTS)

    if tool_available("masscan"):
        info(f"Running masscan on {len(FINANCIAL_RISK_PORTS)} high-risk financial ports")
        masscan_out = out / "masscan_results.json"
        run_tool(
            ["masscan"] + scope.ip_ranges + ["-p", port_str, "--rate", "1000", "-oJ", str(masscan_out)],
            timeout=3600,
        )
        if masscan_out.exists():
            try:
                raw = masscan_out.read_text(encoding="utf-8").strip()
                if raw.endswith(","):
                    raw = raw[:-1]
                if not raw.startswith("["):
                    raw = "[" + raw
                if not raw.endswith("]"):
                    raw += "]"
                data = json.loads(raw)
                open_ports = [
                    f"{h['ip']}:{p['port']}"
                    for h in data
                    for p in h.get("ports", [])
                ]
                save_lines(out / "open_ports.txt", open_ports)
                success(f"masscan: {len(open_ports)} open port:IP pairs found")
            except Exception as exc:
                warn(f"masscan JSON parse error: {exc}")
    else:
        warn("masscan not found. Install: apt install masscan")

    if tool_available("nmap"):
        info("nmap: web port service detection (80,443,8080,8443)")
        run_tool(
            ["nmap", "-sV", "-sC", "-p", "80,443,8080,8443,8000,9090",
             "--open", "--max-retries", "1", "-T4",
             "-oA", str(out / "nmap_web")] + scope.ip_ranges,
            timeout=1800,
        )
        info("nmap: TLS cipher / cert analysis (port 443)")
        run_tool(
            ["nmap", "-p", "443", "--script", "ssl-enum-ciphers,ssl-cert,ssl-dh-params",
             "-T4", "-oA", str(out / "nmap_tls")] + scope.ip_ranges,
            timeout=900,
        )
        info("nmap: SMB EternalBlue check (MS17-010 -- port 445)")
        run_tool(
            ["nmap", "--script", "smb-vuln-ms17-010",
             "-p", "445", "-T4", "-oA", str(out / "nmap_smb")] + scope.ip_ranges,
            timeout=600,
        )
        success("nmap scans complete")
    else:
        warn("nmap not found. Install: apt install nmap")

    success("Phase 5 complete.")


# =============================================================================
# PHASE 6 -- ASSET VALIDATION & LIVENESS
# Entire phase skipped in passive mode (httpx, tlsx, CAA checks all contact
# the target or its nameservers).
# =============================================================================

def phase6_validation(scope: Scope) -> None:
    section("Phase 6 -- Asset Validation & Liveness Determination")
    out = make_dir(scope.output_dir, "phase6_validation")

    if not scope.active_allowed:
        warn("PASSIVE-ONLY MODE: Entire phase skipped.")
        for tool, reason in PASSIVE_SKIPS[6]:
            skipped(f"{tool} -- {reason}")
        success("Phase 6 complete (skipped -- passive-only mode).")
        return

    subs_file = scope.best_subdomain_file()
    info(f"Validating {len(read_lines(subs_file))} targets from: {subs_file}")

    if tool_available("httpx"):
        info("Running httpx (status, title, server, tech-detect, TLS)")
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
            for line in read_lines(httpx_json):
                try:
                    h = json.loads(line)
                    url = h.get("url", "")
                    status = h.get("status_code", 0)
                    body = h.get("body", "") or ""
                    if status:
                        live_hosts.append(url)
                    if status in (401, 403):
                        auth_interfaces.append(url)
                    for platform, fp in TAKEOVER_FINGERPRINTS.items():
                        if fp.lower() in body.lower():
                            takeover_hits.append({"url": url, "platform": platform, "fingerprint": fp})
                except Exception:
                    pass
            save_lines(out / "live_hosts.txt", live_hosts)
            if auth_interfaces:
                save_lines(out / "auth_interfaces.txt", auth_interfaces)
                warn(f"{len(auth_interfaces)} auth interfaces found (review if internet-accessible)")
            if takeover_hits:
                write_json(out / "httpx_takeover_candidates.json", takeover_hits)
                critical(f"{len(takeover_hits)} TAKEOVER CANDIDATES from httpx body fingerprints!")
            success(f"httpx: {len(live_hosts)} live hosts identified")
    else:
        warn("httpx not found. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")

    if tool_available("tlsx"):
        info("Running tlsx for bulk TLS certificate analysis")
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
                except Exception:
                    pass
            cert_findings: Dict[str, List[str]] = {}
            if expired:
                cert_findings["expired_certs"] = expired
                warn(f"{len(expired)} EXPIRED TLS certificates found!")
            if lets_encrypt:
                cert_findings["letsencrypt_certs"] = lets_encrypt
                info(f"{len(lets_encrypt)} Let's Encrypt certs (verify expected issuer for each)")
            if self_signed:
                cert_findings["self_signed_certs"] = self_signed
                warn(f"{len(self_signed)} self-signed certificates")
            if cert_findings:
                write_json(out / "cert_findings.json", cert_findings)
    else:
        warn("tlsx not found. Install: go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest")

    info("Checking CAA records for all root domains")
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
# Entire phase skipped in passive mode (nuclei, subjack, CNAME chain analysis
# all generate HTTP requests or DNS queries toward the target).
# =============================================================================

def phase7_takeover(scope: Scope) -> None:
    section("Phase 7 -- Subdomain Takeover Detection")
    out = make_dir(scope.output_dir, "phase7_takeover")

    if not scope.active_allowed:
        warn("PASSIVE-ONLY MODE: Entire phase skipped.")
        for tool, reason in PASSIVE_SKIPS[7]:
            skipped(f"{tool} -- {reason}")
        info("Tip: review the CT subdomain list from Phase 2 manually for CNAME")
        info("patterns at crt.sh -- any subdomain containing 'dev', 'staging',")
        info("or 'preview' pointing to cloud platforms warrants manual CNAME lookup.")
        success("Phase 7 complete (skipped -- passive-only mode).")
        return

    subs_file = scope.best_subdomain_file()

    if tool_available("nuclei"):
        info("Updating Nuclei templates")
        run_tool(["nuclei", "-update-templates", "-silent"], timeout=120)
        info("Running Nuclei takeover templates")
        nuclei_out = out / "nuclei_takeovers.txt"
        run_tool(
            ["nuclei", "-l", str(subs_file), "-t", "takeovers/", "-o", str(nuclei_out), "-silent"],
            timeout=900,
        )
        hits = read_lines(nuclei_out)
        if hits:
            critical(f"Nuclei found {len(hits)} potential subdomain takeovers!")
            for h in hits:
                console.print(f"    [red]{h}[/]")
    else:
        warn("nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

    if tool_available("subjack"):
        info("Running subjack (complementary takeover scanner)")
        subjack_out = out / "subjack_results.txt"
        run_tool(
            ["subjack", "-w", str(subs_file), "-t", "100", "-timeout", "30",
             "-ssl", "-o", str(subjack_out), "-v"],
            timeout=900,
        )
        hits = read_lines(subjack_out)
        if hits:
            warn(f"subjack found {len(hits)} potential takeovers -- review {subjack_out}")
    else:
        warn("subjack not found. Install: go install github.com/haccer/subjack@latest")

    info("Running Python CNAME dangling-record analysis")
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
        critical(f"{len(dangling)} dangling CNAME records found -- remediate immediately!")
    else:
        success("No dangling CNAMEs detected in automated check")

    success("Phase 7 complete.")


# =============================================================================
# PHASE 8 -- WEB APPLICATION FINGERPRINTING
# Entire phase skipped in passive mode.
# =============================================================================

def phase8_fingerprint(scope: Scope) -> None:
    section("Phase 8 -- Web Application Fingerprinting")
    out = make_dir(scope.output_dir, "phase8_fingerprint")

    if not scope.active_allowed:
        warn("PASSIVE-ONLY MODE: Entire phase skipped.")
        for tool, reason in PASSIVE_SKIPS[8]:
            skipped(f"{tool} -- {reason}")
        success("Phase 8 complete (skipped -- passive-only mode).")
        return

    subs_file = scope.best_subdomain_file()

    if tool_available("whatweb"):
        info("Running WhatWeb (aggressive fingerprinting -a3)")
        run_tool(
            ["whatweb", "-i", str(subs_file),
             "--log-json", str(out / "whatweb_results.json"), "-a", "3"],
            timeout=900,
        )
        success("WhatWeb complete")
    else:
        warn("whatweb not found. Install: apt install whatweb")

    if tool_available("nuclei"):
        info("Running Nuclei technology fingerprinting templates")
        run_tool(
            ["nuclei", "-l", str(subs_file), "-t", "technologies/",
             "-o", str(out / "nuclei_technologies.txt"), "-silent"],
            timeout=900,
        )
        info("Checking for exposed API documentation (Swagger, OpenAPI, GraphQL)")
        run_tool(
            ["nuclei", "-l", str(subs_file), "-t", "exposures/apis/",
             "-o", str(out / "nuclei_api_exposure.txt"), "-silent"],
            timeout=600,
        )

    httpx_file = scope.output_dir / "phase6_validation" / "httpx_results.json"
    if httpx_file.exists():
        info("Analyzing HTTP security headers from Phase 6 httpx data")
        missing: Dict[str, List[str]] = {
            "strict-transport-security": [],
            "content-security-policy": [],
            "x-frame-options": [],
            "x-content-type-options": [],
            "permissions-policy": [],
        }
        cors_wildcard: List[str] = []
        server_versions: List[Dict] = []

        for line in read_lines(httpx_file):
            try:
                h = json.loads(line)
                url = h.get("url", "")
                headers = {k.lower(): v for k, v in (h.get("headers") or {}).items()}
                for header_name in missing:
                    if header_name not in headers:
                        missing[header_name].append(url)
                if headers.get("access-control-allow-origin", "") == "*":
                    cors_wildcard.append(url)
                server = headers.get("server", "")
                if any(v in server for v in ("Apache/", "nginx/", "IIS/", "PHP/")):
                    server_versions.append({"url": url, "server": server})
            except Exception:
                pass

        write_json(out / "header_analysis.json", {
            "missing_hsts":              missing["strict-transport-security"][:50],
            "missing_csp":               missing["content-security-policy"][:50],
            "missing_xframe":            missing["x-frame-options"][:50],
            "missing_xcto":              missing["x-content-type-options"][:50],
            "cors_wildcard":             cors_wildcard,
            "server_version_disclosure": server_versions[:50],
        })
        if cors_wildcard:
            critical(f"{len(cors_wildcard)} hosts with wildcard CORS (Access-Control-Allow-Origin: *)")
        if server_versions:
            warn(f"{len(server_versions)} hosts disclosing server version strings")
    else:
        warn("Phase 6 httpx data not found -- run Phase 6 before Phase 8 for header analysis.")

    if tool_available("gau"):
        info("Collecting JavaScript URLs via gau (Wayback + CommonCrawl + URLScan)")
        for domain in scope.domains:
            gau_out = run_tool(
                ["gau", "--blacklist", "png,jpg,gif,svg,woff,woff2,ttf,eot,ico", domain],
                timeout=180,
            )
            if gau_out:
                js_urls = [u for u in gau_out.splitlines() if u.strip().endswith(".js")]
                save_lines(out / f"js_urls_{domain}.txt", js_urls)
                success(f"gau: {len(js_urls)} JS URLs collected for {domain}")
    else:
        warn("gau not found. Install: go install github.com/lc/gau/v2/cmd/gau@latest")

    success("Phase 8 complete.")


# =============================================================================
# PHASE 9 -- CLOUD ASSET DISCOVERY
# Shodan API queries always run (third-party).
# cloud_enum and S3 HEAD checks skipped in passive mode.
# =============================================================================

def phase9_cloud(scope: Scope) -> None:
    section("Phase 9 -- Cloud Asset Discovery & Misconfiguration (Unauthenticated)")
    out = make_dir(scope.output_dir, "phase9_cloud")

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
    info(f"Generated {len(permutations)} bucket name permutations (saved -- no requests sent)")

    if not scope.active_allowed:
        for tool, reason in PASSIVE_SKIPS[9]:
            skipped(f"{tool} -- {reason}")
        info("Running Shodan cloud queries (passive API only)")
    else:
        if tool_available("cloud_enum"):
            info("Running cloud_enum (S3, Azure Blob, GCP Storage)")
            cmd = ["cloud_enum"] + [item for kw in list(base_keywords)[:6] for item in ["-k", kw]]
            cmd += ["-l", str(out / "cloud_enum_results.txt")]
            run_tool(cmd, timeout=900)
            success("cloud_enum complete")
        else:
            warn("cloud_enum not found. Install:")
            warn("  git clone https://github.com/initstring/cloud_enum")
            warn("  pip3 install -r cloud_enum/requirements.txt")
            warn("  ln -s $(pwd)/cloud_enum/cloud_enum.py /usr/local/bin/cloud_enum")
            info("Falling back to Python S3 HEAD checks (no credentials needed)")
            public_buckets: List[Dict] = []
            for name in list(permutations)[:150]:
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
                        info(f"  Bucket exists (private 403): {name}.s3.amazonaws.com")
                except requests.exceptions.ConnectionError:
                    pass
                except Exception:
                    pass
            if public_buckets:
                write_json(out / "s3_findings.json", public_buckets)
                if any(b["access"] == "PUBLIC" for b in public_buckets):
                    critical(f"{sum(1 for b in public_buckets if b['access']=='PUBLIC')} PUBLIC S3 BUCKETS found!")

    if scope.shodan_key and SHODAN_AVAILABLE:
        info("Shodan cloud-focused queries (Kubernetes, Docker API, Elasticsearch, Redis)")
        try:
            api = shodan_lib.Shodan(scope.shodan_key)
            cloud_queries = []
            if scope.org_name:
                cloud_queries = [
                    (f'org:"{scope.org_name}" product:"Kubernetes"', "kubernetes"),
                    (f'org:"{scope.org_name}" port:2375',             "docker_api"),
                    (f'org:"{scope.org_name}" port:9200 product:"Elasticsearch"', "elasticsearch"),
                    (f'org:"{scope.org_name}" port:6379',             "redis"),
                    (f'org:"{scope.org_name}" port:9090 product:"Prometheus"',    "prometheus"),
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
        "\n  [bold yellow]NOTE:[/] For authenticated cloud posture assessment:\n"
        "    AWS:   prowler aws -g cis_level2 -M json,csv\n"
        "    Azure: python3 scout.py azure --report-dir scout_report/\n"
        "    GCP:   python3 scout.py gcp --report-dir scout_report/\n"
    )
    success("Phase 9 complete.")


# =============================================================================
# PHASE 10 -- VULNERABILITY ANALYSIS
# CISA KEV download always runs (cisa.gov API -- not target infrastructure).
# All nuclei scans skipped in passive mode.
# =============================================================================

def phase10_vulns(scope: Scope) -> None:
    section("Phase 10 -- Vulnerability Analysis & Exposure Scoring")
    out = make_dir(scope.output_dir, "phase10_vulns")

    # Always download CISA KEV regardless of mode
    info("Downloading CISA Known Exploited Vulnerabilities catalog")
    kev_cves: Set[str] = set()
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=30,
        )
        if r.ok:
            kev_data = r.json()
            (out / "cisa_kev.json").write_text(r.text, encoding="utf-8")
            kev_cves = {v["cveID"] for v in kev_data.get("vulnerabilities", [])}
            success(f"CISA KEV: {len(kev_cves)} known-exploited CVEs downloaded and saved")
    except Exception as exc:
        warn(f"CISA KEV download failed: {exc}")

    if not scope.active_allowed:
        warn("PASSIVE-ONLY MODE: All nuclei scans skipped.")
        for tool, reason in PASSIVE_SKIPS[10]:
            skipped(f"{tool} -- {reason}")
        info("CISA KEV saved above. Cross-reference manually once active scan results are available.")
        success("Phase 10 complete (CISA KEV only -- passive-only mode).")
        return

    subs_file = scope.best_subdomain_file()

    if not tool_available("nuclei"):
        error("nuclei is required for active Phase 10.")
        warn("Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        return

    info("Updating Nuclei templates")
    run_tool(["nuclei", "-update-templates", "-silent"], timeout=120)

    nuclei_runs = [
        ("CVE detection (critical + high)",          ["cves/"],          "-severity", "critical,high", "cve_findings.txt",      2400),
        ("Exposure templates (.env, .git, phpinfo)", ["exposures/"],     None,        None,            "exposure_findings.txt", 1200),
        ("Default login detection",                  ["default-logins/"],None,        None,            "default_logins.txt",    1200),
        ("Misconfiguration checks",                  ["misconfiguration/"],None,      None,            "misconfig_findings.txt",1200),
        ("Exposed admin/management panels",          ["exposed-panels/"],None,        None,            "exposed_panels.txt",    1200),
        ("Cloud bucket exposure",                    ["cloud/"],         None,        None,            "cloud_exposure.txt",    600),
    ]

    all_finding_counts: Dict[str, int] = {}
    for label, templates, sev_flag, sev_val, output_name, timeout in nuclei_runs:
        info(f"Nuclei: {label}")
        cmd = ["nuclei", "-l", str(subs_file), "-silent", "-o", str(out / output_name)]
        for t in templates:
            cmd += ["-t", t]
        if sev_flag and sev_val:
            cmd += [sev_flag, sev_val]
        run_tool(cmd, timeout=timeout)
        count = len(read_lines(out / output_name))
        if count > 0:
            all_finding_counts[output_name.replace(".txt", "").replace("_", " ")] = count

    cve_file = out / "cve_findings.txt"
    if kev_cves and cve_file.exists():
        kev_hits: List[Dict] = []
        for finding in read_lines(cve_file):
            for cve_id in kev_cves:
                if cve_id.lower() in finding.lower():
                    kev_hits.append({"finding": finding, "kev_cve": cve_id})
        if kev_hits:
            write_json(out / "kev_hits.json", kev_hits)
            critical(f"{len(kev_hits)} findings match CISA KEV -- IMMEDIATE P0/P1 ESCALATION REQUIRED!")
            for hit in kev_hits[:10]:
                console.print(f"    [red]{hit['kev_cve']}[/]: {hit['finding'][:120]}")

    if all_finding_counts:
        console.print("\n  [bold yellow]Nuclei Finding Summary:[/]")
        t = Table(show_header=True, header_style="bold magenta")
        t.add_column("Category", style="cyan")
        t.add_column("Findings", style="red")
        for cat, count in all_finding_counts.items():
            t.add_row(cat.title(), str(count))
        console.print(t)

    success("Phase 10 complete.")


# =============================================================================
# PHASE 11 -- CREDENTIAL & DATA LEAK MONITORING
# trufflehog (GitHub), gitleaks (GitHub), HIBP, and dork file generation
# all query third-party services -- run regardless of mode.
# nuclei token scan skipped in passive mode.
# =============================================================================

def phase11_leaks(scope: Scope) -> None:
    section("Phase 11 -- Credential & Data Leak Monitoring")
    out = make_dir(scope.output_dir, "phase11_leaks")
    subs_file = scope.best_subdomain_file()

    if scope.github_org:
        if tool_available("trufflehog"):
            info(f"Running trufflehog on GitHub org: {scope.github_org} (verified secrets only)")
            truff_out = out / f"trufflehog_{scope.github_org}.json"
            run_tool(
                ["trufflehog", "github", f"--org={scope.github_org}", "--only-verified", "--json"],
                truff_out,
                timeout=2400,
            )
            hits = [l for l in read_lines(truff_out) if l and "{" in l]
            if hits:
                critical(f"trufflehog found {len(hits)} VERIFIED secrets in {scope.github_org}!")
            else:
                success(f"trufflehog: No verified secrets found in {scope.github_org}")
        else:
            warn("trufflehog not found. Install:")
            warn("  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin")

    if scope.github_org:
        if tool_available("gitleaks"):
            info(f"Running gitleaks on GitHub org: {scope.github_org}")
            run_tool(
                ["gitleaks", "detect",
                 "--source", f"https://github.com/{scope.github_org}",
                 "-v", "--report-format", "json",
                 "--report-path", str(out / "gitleaks_report.json")],
                timeout=900,
            )
        else:
            warn("gitleaks not found. Install: apt install gitleaks")

    info("Checking HaveIBeenPwned public breach data")
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
                    warn(f"HIBP: {len(matches)} breach(es) associated with {domain}")
                    for b in matches[:5]:
                        console.print(f"    [yellow]{b.get('Name', '?')}[/] ({b.get('BreachDate', '?')}): {b.get('DataClasses', [])}")
                else:
                    success(f"HIBP: No direct breach records for {domain}")
    except Exception as exc:
        warn(f"HIBP API request failed: {exc}")

    if not scope.active_allowed:
        for tool, reason in PASSIVE_SKIPS[11]:
            skipped(f"{tool} -- {reason}")
    elif tool_available("nuclei"):
        info("Running Nuclei token/secret exposure templates")
        run_tool(
            ["nuclei", "-l", str(subs_file), "-t", "exposures/tokens/",
             "-o", str(out / "nuclei_tokens.txt"), "-silent"],
            timeout=600,
        )

    info("Generating GitHub dork query file for manual investigation")
    dorks: List[str] = []
    for domain in scope.domains:
        org_handle = scope.github_org or domain.split(".")[0]
        dorks += [
            f"org:{org_handle} api_key",
            f"org:{org_handle} aws_secret_access_key",
            f"org:{org_handle} BEGIN RSA PRIVATE KEY",
            f"org:{org_handle} internal.{domain}",
            f"org:{org_handle} password",
            f"org:{org_handle} token",
            f"org:{org_handle} secret",
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" .env',
        ]
    save_lines(out / "github_dorks.txt", dorks)
    info(f"GitHub dork queries saved -> {out / 'github_dorks.txt'}")
    info("Run manually at https://github.com/search?q=<dork>&type=code (requires GitHub login)")

    success("Phase 11 complete.")


# =============================================================================
# PHASE 14 -- CONTINUOUS CERTIFICATE MONITORING (CertStream)
# Connects to certstream.calidog.io (third-party) -- runs regardless of mode.
# =============================================================================

def phase14_certstream(scope: Scope) -> None:
    section("Phase 14 -- Continuous Certificate Monitoring (CertStream)")
    out = make_dir(scope.output_dir, "phase14_certstream")

    if not CERTSTREAM_AVAILABLE:
        error("certstream library not installed.")
        warn("Install: pip3 install certstream")
        return

    alerts_file = out / "cert_alerts.jsonl"
    monitored = scope.domains[:]

    console.print(f"\n  Monitoring CT log stream for: [cyan]{', '.join(monitored)}[/cyan]")
    console.print("  [yellow]New certificates appear within seconds of issuance.")
    console.print("  Let's Encrypt certs on monitored domains may indicate takeovers in progress.")
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
            issuer_cn = leaf.get("issuer", {}).get("CN", "")
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
                            "issuer_cn": issuer_cn,
                            "all_domains_on_cert": cert_domains[:15],
                        }))
                        console.print(
                            f"  [green][CERT][/green] {cert_domain} | Issuer: {issuer_org}{le_flag}"
                        )
        except Exception:
            pass

    try:
        certstream.listen_for_events(callback, url="wss://certstream.calidog.io/")
    except KeyboardInterrupt:
        console.print(f"\n  [yellow]CertStream stopped after {alert_count} events.[/yellow]")
        success(f"Certificate alerts saved -> {alerts_file}")


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
            "active_mode": scope.active_allowed,
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "output_dir": str(scope.output_dir),
        },
        "finding_highlights": {},
    }

    checks = [
        ("dangling_cnames",          "phase7_takeover/dangling_cnames.json",             "json"),
        ("nuclei_takeovers",         "phase7_takeover/nuclei_takeovers.txt",             "lines"),
        ("kev_hits",                 "phase10_vulns/kev_hits.json",                      "json"),
        ("cve_findings",             "phase10_vulns/cve_findings.txt",                   "count"),
        ("exposure_findings",        "phase10_vulns/exposure_findings.txt",              "count"),
        ("default_logins",           "phase10_vulns/default_logins.txt",                 "count"),
        ("exposed_panels",           "phase10_vulns/exposed_panels.txt",                 "count"),
        ("expired_certs",            "phase6_validation/cert_findings.json",             "json"),
        ("httpx_takeover_hits",      "phase6_validation/httpx_takeover_candidates.json", "json"),
        ("s3_public_buckets",        "phase9_cloud/s3_findings.json",                    "json"),
        ("trufflehog_secrets",       f"phase11_leaks/trufflehog_{scope.github_org}.json","count"),
        ("hibp_matches",             f"phase11_leaks/hibp_{scope.primary_domain}.json",  "json"),
        ("ct_subdomain_count",       "phase2_ct/ct_subdomains.txt",                      "count"),
        ("resolved_subdomain_count", "phase3_dns/resolved_subdomains.txt",               "count"),
        ("cisa_kev_vuln_count",      "phase10_vulns/cisa_kev.json",                      "kev"),
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
    write_json(path, summary)
    return path


# =============================================================================
# PHASE MENU
# =============================================================================

PHASE_FUNCTIONS = {
    1:  phase1_seed,
    2:  phase2_ct,
    3:  phase3_dns,
    4:  phase4_asn,
    5:  phase5_scanning,
    6:  phase6_validation,
    7:  phase7_takeover,
    8:  phase8_fingerprint,
    9:  phase9_cloud,
    10: phase10_vulns,
    11: phase11_leaks,
    14: phase14_certstream,
}


def show_not_automatable() -> None:
    console.print("\n  [bold red]Phases / features NOT automated:[/bold red]\n")
    for name, reason in NOT_AUTOMATABLE:
        console.print(f"  [bold yellow]{name}[/bold yellow]")
        for line in reason.splitlines():
            console.print(f"    {line}")
        console.print()


def phase_menu() -> List[int]:
    console.print("\n  [bold cyan]Available Phases:[/bold cyan]\n")
    t = Table(show_header=True, header_style="bold magenta")
    t.add_column("#", style="cyan", width=4)
    t.add_column("Phase Description", style="white")
    for num, desc in PHASES.items():
        t.add_row(str(num), desc)
    console.print(t)

    console.print(
        "\n  [cyan]all[/]     -- Run all phases in sequence\n"
        "  [cyan]1,3,7[/]   -- Run specific phases (comma-separated numbers)\n"
        "  [cyan]info[/]    -- Show what cannot be automated\n"
    )

    choice = Prompt.ask("  Select phases").strip().lower()

    if choice == "info":
        show_not_automatable()
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
                warn(f"Phase {n} is not in this script (see 'info' for why).")
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
            "[bold red]AUTHORIZED USE ONLY[/bold red]\n\n"
            "This script can perform both passive and active attack surface enumeration.\n"
            "Active actions (DNS brute-force, port scans, HTTP probes, nuclei scans)\n"
            "send traffic directly to target infrastructure.\n"
            "Unauthorized scanning may violate the CFAA and equivalent laws.\n"
            "Written authorization from an appropriate executive is required before use.",
            title="[bold red]Legal Disclaimer[/bold red]",
            border_style="red",
        )
    )

    # ── Step 1: Authorization confirmation ────────────────────────────────
    if not Confirm.ask("\n  I confirm I have written authorization to assess all assets in my defined scope"):
        console.print("  Exiting.")
        sys.exit(0)

    # ── Step 2: Active vs passive mode ────────────────────────────────────
    console.print()
    console.print(
        Panel(
            "[bold green]ACTIVE MODE[/bold green]\n"
            "Runs all tools: DNS brute-force (puredns/dnsx), AXFR zone transfers,\n"
            "port scans (masscan/nmap), HTTP probes (httpx), TLS checks (tlsx),\n"
            "vuln scans (nuclei), takeover detection (subjack), web fingerprinting\n"
            "(whatweb), and cloud bucket checks (cloud_enum / S3 HEAD).\n\n"
            "[bold yellow]PASSIVE MODE[/bold yellow]\n"
            "Runs ONLY read-only API calls to trusted third-party services:\n"
            "crt.sh, Shodan, Censys, ARIN, ipinfo.io, RADB, Wayback Machine, HIBP,\n"
            "CISA KEV, CertStream (certstream.calidog.io),\n"
            "trufflehog on GitHub repos, gitleaks on GitHub repos.\n\n"
            "Nothing that generates DNS queries, TCP connections, or HTTP requests\n"
            "directed at or routing through the target's own infrastructure.",
            title="[bold white]Scan Mode[/bold white]",
            border_style="cyan",
        )
    )

    run_active = Confirm.ask(
        "  Run ACTIVE scans?\n"
        "  (No = passive third-party API queries only -- nothing touches target infrastructure)"
    )

    scope = Scope()
    scope.active_allowed = run_active

    if not scope.active_allowed:
        show_passive_only_notice()

    # ── Step 3: Scope definition ──────────────────────────────────────────
    scope.prompt()

    # ── Step 4: Phase selection ───────────────────────────────────────────
    selected = phase_menu()
    if not selected:
        error("No valid phases selected.")
        sys.exit(1)

    mode_label = "[bold green]ACTIVE[/bold green]" if scope.active_allowed else "[bold yellow]PASSIVE-ONLY[/bold yellow]"
    console.print(f"\n  Mode:          {mode_label}")
    console.print(f"  Phases queued: [cyan]{sorted(selected)}[/cyan]\n")

    start_time = datetime.datetime.now()

    for phase_num in sorted(selected):
        try:
            PHASE_FUNCTIONS[phase_num](scope)
        except KeyboardInterrupt:
            warn(f"Phase {phase_num} interrupted by user -- continuing.")
        except Exception as exc:
            error(f"Phase {phase_num} raised an unhandled exception: {exc}")
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
