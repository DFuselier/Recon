#!/usr/bin/env python3
"""
ASM Enterprise v2.0 -- Attack Surface Management
Enterprise Financial Services SOP
FOR AUTHORIZED USE ONLY. Written authorization required before use.

Usage:
  Interactive:  python3 asm_enterprise.py
  GUI mode:     python3 asm_enterprise.py --config /path/config.json --phases 1,2,3 --non-interactive
"""

import argparse
import os
import sys
import json
import re
import subprocess
import datetime
import ipaddress
import time
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
from pathlib import Path
from typing import List, Optional, Set, Dict, Any, Tuple

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] 'requests' not found. Run: pip3 install requests --break-system-packages")
    sys.exit(1)

try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.reversename
    import dns.exception
except ImportError:
    print("[!] 'dnspython' not found. Run: pip3 install dnspython --break-system-packages")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn
except ImportError:
    print("[!] 'rich' not found. Run: pip3 install rich --break-system-packages")
    sys.exit(1)

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

import base64
import hashlib

# ─── Parse CLI args early so Console can be configured ───────────────────────
_parser = argparse.ArgumentParser(add_help=False)
_parser.add_argument("--config",          default=None)
_parser.add_argument("--phases",          default=None)
_parser.add_argument("--non-interactive", action="store_true")
_parser.add_argument("--no-color",        action="store_true")
_parser.add_argument("--debug",           action="store_true")
_parser.add_argument("-h", "--help",      action="store_true")
_args, _ = _parser.parse_known_args()

GUI_MODE       = _args.non_interactive
NO_COLOR       = _args.no_color
DEBUG_MODE     = _args.debug
CONFIG_PATH    = _args.config
PHASES_ARG     = _args.phases

console = Console(no_color=NO_COLOR, highlight=False)

# Debug log file handle -- set in main() when --debug is active
_debug_log = None

def _dlog(msg: str) -> None:
    """Write plain text to debug log file if active."""
    global _debug_log
    if _debug_log:
        try:
            _debug_log.write(f"[{datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}\n")
            _debug_log.flush()
        except Exception:
            pass

# ─── Constants ────────────────────────────────────────────────────────────────

BANNER = r"""
   ___   ____  __  __   _____       _
  / _ \ / ___||  \/  | | ____|_ __ | |_ ___ _ __ _ __  _ __ _  ___  ___
 | | | |\___ \| |\/| | |  _| | '_ \| __/ _ \ '__| '_ \| '__| |/ __|/ _ \
 | |_| | ___) | |  | | | |___| | | | ||  __/ |  | |_) | |  | |\__ \  __/
  \___/ |____/|_|  |_| |_____|_| |_|\__\___|_|  | .__/|_|  |_||___/\___|
                                                  |_|
  Attack Surface Management  --  Enterprise Financial Services v2.0
  FOR AUTHORIZED USE ONLY
"""

RESOLVERS_URL = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt"

TAKEOVER_SIGNATURES = [
    "there is no app here", "no such bucket", "nosuchdomain",
    "domain not found", "this page does not exist", "project not found",
    "sorry, we can't find that page", "repository not found",
    "this github pages site", "herokudns.com", "has been suspended",
    "fastly error: unknown domain",
]

DANGEROUS_CNAME_ENDINGS = [
    ".amazonaws.com", ".azurewebsites.net", ".cloudfront.net",
    ".github.io", ".herokudns.com", ".ghost.io", ".bitbucket.io",
    ".myshopify.com", ".cargo.site", ".unbouncepages.com",
    ".helpjuice.com", ".helpscoutdocs.com", ".strikingly.com",
    ".zendesk.com", ".desk.com", ".launchrock.com", ".netlify.app",
    ".netlify.com", ".web.app", ".firebaseapp.com", ".statuspage.io",
    ".uservoice.com", ".feedpress.me", ".readthedocs.io",
]

BUCKET_SUFFIXES = [
    "-prod", "-staging", "-dev", "-backup", "-data", "-logs",
    "-assets", "-static", "-media", "-files", "-upload", "-downloads",
    "-internal", "-archive", "-db", "-database", "-config",
]

DKIM_SELECTORS = [
    "default", "google", "mail", "k1", "k2", "selector1", "selector2",
    "dkim", "email", "smtp", "mx", "postfix", "sendgrid", "mailjet",
    "mandrill", "ses", "amazonses", "mimecast", "proofpoint",
]

GOOGLE_DORK_TEMPLATES = [
    "site:{domain} filetype:env",
    "site:{domain} filetype:sql",
    "site:{domain} filetype:log",
    "site:{domain} filetype:bak",
    "site:{domain} inurl:admin",
    "site:{domain} inurl:login",
    "site:{domain} inurl:api",
    "site:{domain} inurl:swagger",
    "site:{domain} inurl:phpinfo",
    'site:{domain} intext:"Index of /"',
    'site:{domain} intext:"password"',
    '"{domain}" "api_key"',
    '"{domain}" "aws_access_key"',
    '"{domain}" "BEGIN PRIVATE KEY"',
    '"{domain}" "internal" site:pastebin.com',
    '"{domain}" site:github.com',
    '"{domain}" site:trello.com',
    '"{domain}" site:jira.atlassian.com',
]

JS_ENDPOINT_PATTERNS = [
    re.compile(r'["\`](/api/[^\s"\'`\)]{3,80})["\`]'),
    re.compile(r'["\`](/v\d+/[^\s"\'`\)]{3,80})["\`]'),
    re.compile(r'["\`](/graphql[^\s"\'`\)]{0,40})["\`]'),
    re.compile(r'["\`](/admin[^\s"\'`\)]{0,60})["\`]'),
    re.compile(r'["\`](/internal[^\s"\'`\)]{0,60})["\`]'),
    re.compile(r'["\`](/wp-json[^\s"\'`\)]{0,60})["\`]'),
    re.compile(r'fetch\s*\(\s*["\`]([^"\'`\)]{10,120})["\`]'),
    re.compile(r'axios\.[a-z]+\s*\(\s*["\`]([^"\'`\)]{10,120})["\`]'),
    re.compile(r'\.get\s*\(\s*["\`](/[^"\'`\)]{5,80})["\`]'),
    re.compile(r'\.post\s*\(\s*["\`](/[^"\'`\)]{5,80})["\`]'),
]

ENTROPY_THRESHOLD = 4.2

SECRET_PATTERNS = [
    ("Generic Password",        re.compile(r'(?i)(password|passwd|pass|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']')),
    ("Generic Secret",          re.compile(r'(?i)(secret|api_secret|client_secret)\s*[:=]\s*["\']([^"\']{8,})["\']')),
    ("Generic API Key",         re.compile(r'(?i)(api_key|apikey|api-key)\s*[:=]\s*["\']([^"\']{8,})["\']')),
    ("Generic Token",           re.compile(r'(?i)(token|auth_token|access_token|bearer)\s*[:=]\s*["\']([^"\']{8,})["\']')),
    ("AWS Access Key",          re.compile(r'AKIA[0-9A-Z]{16}')),
    ("AWS Secret Key",          re.compile(r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']')),
    ("Stripe Live Key",         re.compile(r'sk_live_[0-9a-zA-Z]{24,}')),
    ("Stripe Test Key",         re.compile(r'sk_test_[0-9a-zA-Z]{24,}')),
    ("SendGrid API Key",        re.compile(r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}')),
    ("Mailgun API Key",         re.compile(r'key-[0-9a-zA-Z]{32}')),
    ("Twilio Account SID",      re.compile(r'AC[a-zA-Z0-9]{32}')),
    ("GitHub Token",            re.compile(r'ghp_[0-9a-zA-Z]{36}')),
    ("GitHub OAuth",            re.compile(r'gho_[0-9a-zA-Z]{36}')),
    ("Slack Token",             re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}')),
    ("Slack Webhook",           re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+')),
    ("Google API Key",          re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("Firebase URL",            re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com')),
    ("JWT Token",               re.compile(r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*')),
    ("Bearer Token Header",     re.compile(r'(?i)Authorization:\s*Bearer\s+[A-Za-z0-9\-_.~+/=]{20,}')),
    ("Connection String (SQL)", re.compile(r'(?i)(Server|Host)=[^;]+;.{0,40}(Password|Pwd)=[^;\'"]+')),
    ("MongoDB URI",             re.compile(r'mongodb(\+srv)?://[^:]+:[^@]+@[^\s"\'<>]+')),
    ("PostgreSQL DSN",          re.compile(r'postgres(?:ql)?://[^:]+:[^@]+@[^\s"\'<>]+')),
    ("MySQL DSN",               re.compile(r'mysql://[^:]+:[^@]+@[^\s"\'<>]+')),
    ("Private Key Header",      re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ("process.env inlined",     re.compile(r'process\.env\.[A-Z_]{3,}\s*=\s*["\'][^"\']{4,}["\']')),
]

def shannon_entropy(data: str) -> float:
    import math
    if not data: return 0.0
    freq: Dict[str, int] = {}
    for c in data: freq[c] = freq.get(c, 0) + 1
    n = len(data)
    return -sum((v/n) * math.log2(v/n) for v in freq.values())

def js_scan_content(content: str, source: str) -> List[Dict]:
    """Scan JS/config text for secrets via pattern matching and entropy."""
    findings: List[Dict] = []
    for name, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(content):
            line_no = content[:m.start()].count("\n") + 1
            findings.append({
                "type": name, "source": source,
                "match": m.group(0)[:200], "line": line_no, "method": "pattern",
            })
    # High-entropy string detection
    candidates = re.findall(r'["\']([A-Za-z0-9+/=_\-]{20,80})["\']', content)
    for candidate in set(candidates):
        if shannon_entropy(candidate) >= ENTROPY_THRESHOLD:
            findings.append({
                "type": "High Entropy String", "source": source,
                "match": candidate, "entropy": round(shannon_entropy(candidate), 2),
                "method": "entropy",
            })
    return findings

# ─── Utilities ────────────────────────────────────────────────────────────────

def info(msg: str)     -> None: console.print(f"  [cyan][*][/cyan] {msg}");           _dlog(f"[INFO]     {msg}")
def success(msg: str)  -> None: console.print(f"  [green][+][/green] {msg}");          _dlog(f"[SUCCESS]  {msg}")
def warn(msg: str)     -> None: console.print(f"  [yellow][!][/yellow] {msg}");        _dlog(f"[WARN]     {msg}")
def error(msg: str)    -> None: console.print(f"  [red][ERROR][/red] {msg}");          _dlog(f"[ERROR]    {msg}")
def critical(msg: str) -> None: console.print(f"  [bold red][CRITICAL][/bold red] {msg}"); _dlog(f"[CRITICAL] {msg}")
def section(title: str)-> None: console.rule(f"[bold cyan]{title}[/bold cyan]");       _dlog(f"\n{'='*60}\n{title}\n{'='*60}")

def tool_available(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None

# Shodan plan cache -- populated on first use to avoid repeated api.info() calls
_shodan_plan_cache: Dict[str, str] = {}

def shodan_plan(api) -> str:
    """Return Shodan plan name ('dev', 'edu', 'oss', 'plus', 'small', 'medium', 'large').
    Free 'dev' keys cannot use api.search() -- only api.host().
    Caches result to avoid repeated API calls per run."""
    global _shodan_plan_cache
    key_id = str(id(api))
    if key_id not in _shodan_plan_cache:
        try:
            info = api.info()
            _shodan_plan_cache[key_id] = info.get("plan", "dev")
        except Exception:
            _shodan_plan_cache[key_id] = "dev"
    return _shodan_plan_cache[key_id]

def shodan_search(api, query: str, **kwargs) -> Optional[Dict]:
    """Wrapper around api.search() that checks plan first.
    Free 'dev' keys cannot run search -- returns None and warns."""
    plan = shodan_plan(api)
    if plan == "dev":
        warn(f"Shodan search skipped (free 'dev' plan): {query[:60]}")
        warn("  Upgrade to a paid Shodan API plan to enable org/html/favicon searches.")
        return None
    try:
        return api.search(query, **kwargs)
    except Exception as exc:
        if "403" in str(exc) or "Forbidden" in str(exc):
            warn(f"Shodan 403 on [{query[:50]}] -- paid plan required for this query type.")
        else:
            warn(f"Shodan query failed [{query[:50]}]: {exc}")
        return None

def run_tool(
    cmd: List[str],
    output_file: Optional[Path] = None,
    timeout: int = 300,
    capture: bool = False,
) -> Optional[str]:
    if DEBUG_MODE:
        info(f"[DEBUG] CMD: {' '.join(str(c) for c in cmd)}")
    try:
        if output_file:
            with open(output_file, "w") as f:
                subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL,
                               timeout=timeout, check=False)
            return None
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout, check=False)
        if capture:
            return result.stdout
        return None
    except subprocess.TimeoutExpired:
        warn(f"Tool timed out ({timeout}s): {cmd[0]}")
        return None
    except FileNotFoundError:
        warn(f"Tool not found: {cmd[0]}")
        return None
    except Exception as exc:
        warn(f"Tool error ({cmd[0]}): {exc}")
        return None

def make_dir(base: Path, name: str) -> Path:
    p = base / name
    p.mkdir(parents=True, exist_ok=True)
    return p

def read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text(errors="ignore").splitlines() if l.strip()]

def save_lines(path: Path, lines: List[str]) -> None:
    path.write_text("\n".join(sorted(set(l for l in lines if l))) + "\n", encoding="utf-8")

def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

def safe_get(url: str, timeout: int = 10, **kwargs) -> Optional[requests.Response]:
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
        info(f"Downloaded {len(r.text.splitlines())} trusted resolvers.")
    except Exception:
        rf.write_text("8.8.8.8\n1.1.1.1\n9.9.9.9\n8.8.4.4\n", encoding="utf-8")
        warn("Could not download resolvers -- using fallback.")
    return rf

# ─── Scope ────────────────────────────────────────────────────────────────────

class Scope:
    def __init__(self) -> None:
        self.domains:            List[str] = []
        self.ip_ranges:          List[str] = []
        self.org_name:           str = ""
        self.asn:                str = ""
        self.github_org:         str = ""
        self.shodan_key:         str = ""
        self.censys_id:          str = ""
        self.censys_secret:      str = ""
        self.securitytrails_key: str = ""
        self.output_dir:         Path = Path("output") / "default"

    @classmethod
    def from_config(cls, cfg: Dict[str, Any]) -> "Scope":
        s = cls()
        s.domains            = [d.strip().lower() for d in cfg.get("domains", []) if d.strip()]
        s.ip_ranges          = [r.strip() for r in cfg.get("ip_ranges", []) if r.strip()]
        s.org_name           = cfg.get("org_name", "")
        s.asn                = cfg.get("asn", "")
        s.github_org         = cfg.get("github_org", "")
        s.shodan_key         = cfg.get("shodan_key", "") or os.environ.get("SHODAN_API_KEY", "")
        s.censys_id          = cfg.get("censys_id", "") or os.environ.get("CENSYS_API_ID", "")
        s.censys_secret      = cfg.get("censys_secret", "") or os.environ.get("CENSYS_API_SECRET", "")
        s.securitytrails_key = cfg.get("securitytrails_key", "") or os.environ.get("SECURITYTRAILS_API_KEY", "")
        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^\w.-]", "_", s.domains[0] if s.domains else "unknown")
        out  = cfg.get("output_dir", "")
        s.output_dir = Path(out) if out else Path("output") / f"{safe}_{ts}"
        s.output_dir.mkdir(parents=True, exist_ok=True)
        success(f"Output directory: {s.output_dir}")
        return s

    def prompt(self) -> None:
        section("Scope Definition")
        warn("Provide ONLY assets you have written authorization to assess.")
        raw = Prompt.ask("\n  [cyan]Root domain(s)[/cyan]  (comma-separated)")
        self.domains = [d.strip().lower() for d in raw.split(",") if d.strip()]
        raw = Prompt.ask("  [cyan]IP / CIDR range(s)[/cyan]  (or ENTER to skip)", default="")
        if raw.strip():
            self.ip_ranges = [r.strip() for r in raw.split(",") if r.strip()]
        self.org_name           = Prompt.ask("  [cyan]Organization name[/cyan]  (or ENTER to skip)", default="")
        self.asn                = Prompt.ask("  [cyan]ASN[/cyan]  (e.g. AS12345, or ENTER to skip)", default="")
        self.github_org         = Prompt.ask("  [cyan]GitHub org handle[/cyan]  (or ENTER to skip)", default="")
        self.shodan_key         = os.environ.get("SHODAN_API_KEY") or Prompt.ask("  [cyan]Shodan API key[/cyan]", default="", password=True)
        self.censys_id          = os.environ.get("CENSYS_API_ID") or Prompt.ask("  [cyan]Censys API ID[/cyan]", default="", password=True)
        self.censys_secret      = os.environ.get("CENSYS_API_SECRET") or Prompt.ask("  [cyan]Censys API Secret[/cyan]", default="", password=True)
        self.securitytrails_key = os.environ.get("SECURITYTRAILS_API_KEY") or Prompt.ask("  [cyan]SecurityTrails API key[/cyan]", default="", password=True)
        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^\w.-]", "_", self.domains[0] if self.domains else "unknown")
        self.output_dir = Path("output") / f"{safe}_{ts}"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        success(f"Output directory: {self.output_dir}")

    @property
    def primary_domain(self) -> str:
        return self.domains[0] if self.domains else ""

    def best_subdomain_file(self) -> Path:
        for c in [
            self.output_dir / "phase3_dns" / "resolved_subdomains.txt",
            self.output_dir / "phase3_dns" / "all_subdomains_raw.txt",
            self.output_dir / "phase2_ct"  / "ct_subdomains.txt",
        ]:
            if c.exists() and read_lines(c):
                return c
        fallback = self.output_dir / "scope_domains.txt"
        save_lines(fallback, self.domains)
        return fallback

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1 -- SEED DATA COLLECTION
# ═══════════════════════════════════════════════════════════════════════════════

def phase1_seed(scope: Scope) -> None:
    section("Phase 1 -- Seed Data Collection")
    out = make_dir(scope.output_dir, "phase1_seed")
    write_json(out / "seed_data.json", {
        "domains": scope.domains, "ip_ranges": scope.ip_ranges,
        "org_name": scope.org_name, "asn": scope.asn,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    })
    for domain in scope.domains:
        info(f"WHOIS: {domain}")
        run_tool(["whois", domain], out / f"whois_{domain}.txt", timeout=30)
    if scope.org_name:
        try:
            r = requests.get("https://search.arin.net/rest/search",
                             params={"q": scope.org_name},
                             headers={"Accept": "application/json"}, timeout=15)
            if r.ok:
                write_json(out / "arin_search.json", r.json())
                success("ARIN search saved.")
        except Exception as exc:
            warn(f"ARIN search failed: {exc}")
    if scope.asn:
        asn_digits = re.sub(r"[^0-9]", "", scope.asn)
        try:
            r = requests.get(f"https://ipinfo.io/AS{asn_digits}/json", timeout=15)
            if r.ok:
                data = r.json()
                write_json(out / f"asn_{asn_digits}_ipinfo.json", data)
                prefixes = [p.get("netblock", "") for p in data.get("prefixes", []) if p.get("netblock")]
                if prefixes:
                    save_lines(out / "asn_prefixes.txt", prefixes)
                    success(f"AS{asn_digits}: {len(prefixes)} prefixes found.")
        except Exception as exc:
            warn(f"ipinfo.io ASN lookup failed: {exc}")
        asn_tag = scope.asn.upper()
        if not asn_tag.startswith("AS"):
            asn_tag = "AS" + asn_tag
        run_tool(["whois", "-h", "whois.radb.net", f"!gAS{re.sub(r'[^0-9]','',scope.asn)}"],
                 out / f"radb_{asn_tag}.txt", timeout=30)
    for domain in scope.domains[:3]:
        r = safe_get(f"http://web.archive.org/cdx/search/cdx",
                     params={"url": f"*.{domain}", "output": "json",
                             "fl": "original", "collapse": "urlkey", "limit": "5000"},
                     timeout=30)
        if r and r.ok:
            try:
                entries = r.json()
                subs: Set[str] = set()
                for entry in entries[1:]:
                    m = re.match(r"https?://([^/]+)", entry[0])
                    if m:
                        h = m.group(1).lower().rstrip(".")
                        if h.endswith(f".{domain}") or h == domain:
                            subs.add(h)
                if subs:
                    save_lines(out / f"wayback_subdomains_{domain}.txt", sorted(subs))
                    success(f"Wayback CDX [{domain}]: {len(subs)} unique hosts.")
            except Exception:
                pass
    success("Phase 1 complete.")


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2 -- CT & PASSIVE RECON
# ═══════════════════════════════════════════════════════════════════════════════

def phase2_ct_passive(scope: Scope) -> None:
    section("Phase 2 -- Certificate Transparency & Passive Recon")
    out = make_dir(scope.output_dir, "phase2_ct")
    all_subdomains: Set[str] = set()
    for domain in scope.domains:
        try:
            r = requests.get("https://crt.sh/",
                             params={"q": f"%.{domain}", "output": "json"},
                             timeout=30, verify=False)
            if r.ok:
                entries = r.json()
                write_json(out / f"crtsh_{domain}.json", entries)
                for e in entries:
                    for name in e.get("name_value", "").splitlines():
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(f".{domain}") or name == domain:
                            all_subdomains.add(name)
                success(f"crt.sh [{domain}]: {len(entries)} certs.")
        except Exception as exc:
            warn(f"crt.sh failed for {domain}: {exc}")
    if scope.censys_id and scope.censys_secret and CENSYS_AVAILABLE:
        try:
            os.environ["CENSYS_API_ID"]     = scope.censys_id
            os.environ["CENSYS_API_SECRET"] = scope.censys_secret
            h = CensysHosts()
            for domain in scope.domains:
                results = list(h.search(f"parsed.names: {domain}", per_page=100, pages=3))
                write_json(out / f"censys_hosts_{domain}.json", results)
                for host in results:
                    for name in host.get("parsed", {}).get("names", []):
                        if name.endswith(f".{domain}") or name == domain:
                            all_subdomains.add(name.lower())
                success(f"Censys [{domain}]: {len(results)} hosts.")
        except Exception as exc:
            warn(f"Censys query failed: {exc}")
    if scope.shodan_key and SHODAN_AVAILABLE:
        try:
            api = shodan_lib.Shodan(scope.shodan_key)
            for domain in scope.domains:
                results = shodan_search(api, f"ssl.cert.subject.cn:{domain}")
                if results is None: continue
                write_json(out / f"shodan_ssl_{domain}.json", results)
                success(f"Shodan SSL [{domain}]: {results.get('total',0)} results.")
            if scope.org_name:
                results = shodan_search(api, f'org:"{scope.org_name}"')
                if results is None: continue
                write_json(out / "shodan_org.json", results)
                success(f"Shodan org: {results.get('total',0)} results.")
        except Exception as exc:
            warn(f"Shodan query failed: {exc}")
    if all_subdomains:
        save_lines(out / "ct_subdomains.txt", list(all_subdomains))
        success(f"CT passive: {len(all_subdomains)} unique subdomains.")
    success("Phase 2 complete.")


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3 -- ACTIVE DNS ENUMERATION
# (+assetfinder, +waybackurls)
# ═══════════════════════════════════════════════════════════════════════════════

def phase3_dns(scope: Scope) -> None:
    section("Phase 3 -- Active DNS Enumeration")
    out = make_dir(scope.output_dir, "phase3_dns")
    all_subdomains: Set[str] = set()
    resolvers = get_resolvers(scope.output_dir)
    ct_file = scope.output_dir / "phase2_ct" / "ct_subdomains.txt"
    if ct_file.exists():
        all_subdomains.update(read_lines(ct_file))
        info(f"Seeded {len(all_subdomains)} subdomains from Phase 2.")

    for domain in scope.domains:
        info(f"--- Enumerating: {domain} ---")
        if tool_available("subfinder"):
            sf_out = out / f"subfinder_{domain}.txt"
            run_tool(["subfinder", "-d", domain, "-all", "-silent", "-o", str(sf_out)], timeout=300)
            r = read_lines(sf_out); all_subdomains.update(r)
            success(f"subfinder [{domain}]: {len(r)} results.")
        else:
            warn("subfinder not found. Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")

        if tool_available("amass"):
            am_out = out / f"amass_{domain}.txt"
            run_tool(["amass", "enum", "-passive", "-d", domain, "-o", str(am_out)], timeout=600)
            r = read_lines(am_out); all_subdomains.update(r)
            success(f"amass [{domain}]: {len(r)} results.")
        else:
            warn("amass not found. Install: apt install amass")

        # assetfinder -- lightweight passive subdomain finder
        if tool_available("assetfinder"):
            af_raw = run_tool(["assetfinder", "--subs-only", domain], capture=True, timeout=120)
            if af_raw:
                af_subs = [l for l in af_raw.splitlines() if l.strip() and
                           (l.strip().endswith(f".{domain}") or l.strip() == domain)]
                all_subdomains.update(af_subs)
                save_lines(out / f"assetfinder_{domain}.txt", af_subs)
                success(f"assetfinder [{domain}]: {len(af_subs)} results.")
        else:
            warn("assetfinder not found. Install: go install github.com/tomnomnom/assetfinder@latest")

        # waybackurls -- Wayback Machine historical URL discovery
        if tool_available("waybackurls"):
            wb_raw = run_tool(["waybackurls", domain], capture=True, timeout=120)
            if wb_raw:
                wb_subs: Set[str] = set()
                for url in wb_raw.splitlines():
                    m = re.match(r"https?://([^/]+)", url.strip())
                    if m:
                        host = m.group(1).lower().rstrip(".")
                        if host.endswith(f".{domain}") or host == domain:
                            wb_subs.add(host)
                all_subdomains.update(wb_subs)
                save_lines(out / f"waybackurls_{domain}.txt", list(wb_subs))
                success(f"waybackurls [{domain}]: {len(wb_subs)} unique hosts.")
        else:
            warn("waybackurls not found. Install: go install github.com/tomnomnom/waybackurls@latest")

        # AXFR zone transfer attempt
        try:
            ns_answers = dns.resolver.resolve(domain, "NS")
            for ns_rdata in ns_answers:
                ns = str(ns_rdata.target).rstrip(".")
                try:
                    z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))
                    axfr_subs = [f"{n}.{domain}" for n in z.nodes.keys() if str(n) not in ("@","")]
                    if axfr_subs:
                        save_lines(out / f"AXFR_SUCCESS_{domain}_{ns}.txt", axfr_subs)
                        critical(f"ZONE TRANSFER SUCCEEDED on {ns}! {len(axfr_subs)} records.")
                        all_subdomains.update(axfr_subs)
                except Exception:
                    pass
        except Exception:
            pass

    raw_file = out / "all_subdomains_raw.txt"
    save_lines(raw_file, list(all_subdomains))
    info(f"Raw subdomains before resolution: {len(all_subdomains)}")

    if tool_available("puredns"):
        resolved_file = out / "resolved_subdomains.txt"
        run_tool(["puredns", "resolve", str(raw_file), "-r", str(resolvers),
                  "-w", str(resolved_file)], timeout=1200)
        success(f"puredns: {len(read_lines(resolved_file))} live subdomains.")
    else:
        warn("puredns not found. Install: go install github.com/d3mondev/puredns/v2@latest")

    if tool_available("dnsx"):
        run_tool(["dnsx", "-l", str(scope.best_subdomain_file()),
                  "-a", "-aaaa", "-cname", "-mx", "-txt",
                  "-json", "-o", str(out / "dnsx_resolved.json"), "-silent"], timeout=600)
        success("dnsx record enrichment complete.")
    else:
        warn("dnsx not found. Install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest")

    success("Phase 3 complete.")


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4 -- IP & ASN MAPPING
# ═══════════════════════════════════════════════════════════════════════════════

def phase4_ip(scope: Scope) -> None:
    section("Phase 4 -- IP & ASN Mapping")
    out = make_dir(scope.output_dir, "phase4_ip")
    all_ips: Set[str] = set()
    for cidr in scope.ip_ranges:
        try:
            for host in ipaddress.ip_network(cidr, strict=False).hosts():
                all_ips.add(str(host))
        except ValueError:
            warn(f"Invalid CIDR: {cidr}")
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3; resolver.lifetime = 3
    for sub in read_lines(scope.best_subdomain_file())[:5000]:
        try:
            for rdata in resolver.resolve(sub, "A"):
                all_ips.add(str(rdata))
        except Exception:
            pass
    if all_ips:
        save_lines(out / "all_ips.txt", sorted(all_ips))
        success(f"Total unique IPs: {len(all_ips)}")
    if scope.asn:
        asn_digits = re.sub(r"[^0-9]", "", scope.asn)
        run_tool(["whois", "-h", "whois.radb.net", f"!gAS{asn_digits}"],
                 out / f"radb_AS{asn_digits}.txt", timeout=30)
    if scope.shodan_key and SHODAN_AVAILABLE and scope.org_name:
        try:
            api     = shodan_lib.Shodan(scope.shodan_key)
            results = shodan_search(api, f'org:"{scope.org_name}"', limit=1000)
            if results is None: continue
            shodan_ips = [m.get("ip_str") for m in results.get("matches", []) if m.get("ip_str")]
            if shodan_ips:
                save_lines(out / "shodan_org_ips.txt", shodan_ips)
                success(f"Shodan org IPs: {len(shodan_ips)} discovered.")
        except Exception as exc:
            warn(f"Shodan org IP query failed: {exc}")
    success("Phase 4 complete.")

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5 -- WEB SERVER VALIDATION & TLS ANALYSIS
# (+robots.txt/sitemap, +CORS wildcard/server version parsing, +TLS expiry analysis)
# ═══════════════════════════════════════════════════════════════════════════════

def phase5_validation(scope: Scope) -> None:
    section("Phase 5 -- Web Server Validation & TLS Analysis")
    out       = make_dir(scope.output_dir, "phase5_validation")
    subs_file = scope.best_subdomain_file()

    if tool_available("httpx"):
        info("Running httpx web server probe")
        run_tool(
            ["httpx", "-l", str(subs_file),
             "-title", "-tech-detect", "-status-code", "-content-length",
             "-follow-redirects", "-json", "-o", str(out / "httpx_results.json"), "-silent"],
            timeout=1200,
        )
        httpx_results = []
        httpx_file = out / "httpx_results.json"
        if httpx_file.exists():
            for line in httpx_file.read_text(errors="ignore").splitlines():
                try:
                    httpx_results.append(json.loads(line))
                except Exception:
                    pass

        live_hosts    = [r.get("url","") for r in httpx_results if r.get("status_code")]
        auth_keywords = ["login","admin","portal","vpn","remote","citrix","owa","webmail","sso","auth"]
        auth_hosts    = [r.get("url","") for r in httpx_results
                         if any(kw in r.get("url","").lower() or kw in r.get("title","").lower()
                                for kw in auth_keywords)]
        takeover_candidates = [r for r in httpx_results
                               if any(sig in r.get("body","").lower() for sig in TAKEOVER_SIGNATURES)]

        save_lines(out / "live_hosts.txt", live_hosts)
        if auth_hosts:
            save_lines(out / "auth_interfaces.txt", auth_hosts)
            warn(f"Found {len(auth_hosts)} authentication interfaces.")
        if takeover_candidates:
            write_json(out / "httpx_takeover_candidates.json", takeover_candidates)
            critical(f"{len(takeover_candidates)} potential takeover signatures in HTTP responses.")

        # CORS wildcard + server version disclosure parsing
        cors_wildcard:    List[str] = []
        server_versions:  List[Dict] = []
        missing_headers:  Dict[str,int] = {"strict-transport-security":0,"content-security-policy":0,
                                            "x-frame-options":0,"x-content-type-options":0}
        for entry in httpx_results:
            headers = {k.lower(): v for k,v in (entry.get("headers") or {}).items()}
            url     = entry.get("url","")
            if headers.get("access-control-allow-origin","") == "*":
                cors_wildcard.append(url)
            server = headers.get("server","")
            if re.search(r"\d+\.\d+", server):
                server_versions.append({"url": url, "server": server})
            for hdr in missing_headers:
                if hdr not in headers:
                    missing_headers[hdr] += 1

        if cors_wildcard:
            save_lines(out / "cors_wildcard.txt", cors_wildcard)
            critical(f"{len(cors_wildcard)} hosts with wildcard CORS (Access-Control-Allow-Origin: *)")
        if server_versions:
            write_json(out / "server_version_disclosure.json", server_versions[:200])
            warn(f"{len(server_versions)} hosts disclosing server version strings.")
        write_json(out / "header_analysis.json", {
            "cors_wildcard":   cors_wildcard,
            "server_versions": server_versions[:50],
            "missing_headers": missing_headers,
        })
        success(f"httpx: {len(live_hosts)} live hosts.")
    else:
        warn("httpx not found. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")

    # tlsx with expiry, LE, and self-signed analysis
    if tool_available("tlsx"):
        info("Running tlsx bulk TLS analysis")
        run_tool(
            ["tlsx", "-l", str(subs_file), "-san", "-cn", "-not-after",
             "-expired", "-json", "-o", str(out / "tlsx_results.json"), "-silent"],
            timeout=900,
        )
        tlsx_file = out / "tlsx_results.json"
        if tlsx_file.exists():
            expired:       List[str]  = []
            expiring_soon: List[Dict] = []
            lets_encrypt:  List[str]  = []
            self_signed:   List[str]  = []
            for line in tlsx_file.read_text(errors="ignore").splitlines():
                try:
                    t      = json.loads(line)
                    host   = t.get("host","")
                    issuer = (t.get("issuer_cn") or t.get("issuer_org") or "").lower()
                    if t.get("expired"):
                        expired.append(host)
                    if "let's encrypt" in issuer or "letsencrypt" in issuer:
                        lets_encrypt.append(host)
                    if not issuer or "self-signed" in issuer or issuer == host.lower():
                        self_signed.append(host)
                    not_after = t.get("not_after","")
                    if not_after:
                        try:
                            expiry    = datetime.datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%SZ")
                            days_left = (expiry - datetime.datetime.now()).days
                            if 0 < days_left <= 30:
                                expiring_soon.append({"host": host, "days_left": days_left})
                        except Exception:
                            pass
                except Exception:
                    pass
            cert_findings: Dict[str, Any] = {}
            if expired:       cert_findings["expired_certs"]          = expired;       critical(f"{len(expired)} EXPIRED TLS certificates!")
            if expiring_soon: cert_findings["expiring_within_30d"]    = expiring_soon; warn(f"{len(expiring_soon)} certs expiring within 30 days.")
            if lets_encrypt:  cert_findings["lets_encrypt_certs"]     = lets_encrypt;  info(f"{len(lets_encrypt)} Let's Encrypt certs (verify issuer expectation).")
            if self_signed:   cert_findings["self_signed_certs"]      = self_signed;   warn(f"{len(self_signed)} self-signed certificates.")
            if cert_findings:
                write_json(out / "cert_findings.json", cert_findings)
        success("tlsx TLS analysis complete.")
    else:
        warn("tlsx not found. Install: go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest")

    # robots.txt + sitemap.xml (browser-equivalent GET requests)
    info("Fetching robots.txt and sitemap.xml")
    live_file     = out / "live_hosts.txt"
    hosts_to_probe = read_lines(live_file)[:200] if live_file.exists() else [f"https://{d}" for d in scope.domains]
    robots_findings: List[Dict] = []
    from urllib.parse import urljoin
    for host in hosts_to_probe:
        for path, label in [("/robots.txt","robots"), ("/sitemap.xml","sitemap")]:
            r = safe_get(f"{host.rstrip('/')}{path}", timeout=8)
            if r and r.status_code == 200 and len(r.text) > 20:
                entry: Dict[str, Any] = {"host": host, "path": path, "length": len(r.text)}
                if label == "robots":
                    entry["disallowed_paths"] = re.findall(r"(?i)Disallow:\s*(\S+)", r.text)[:50]
                    entry["sitemaps_referenced"] = re.findall(r"(?i)Sitemap:\s*(\S+)", r.text)
                robots_findings.append(entry)
    if robots_findings:
        write_json(out / "robots_sitemap_findings.json", robots_findings)
        success(f"robots.txt/sitemap: {len(robots_findings)} files found.")

    # CAA record check
    resolver = dns.resolver.Resolver(); resolver.timeout = 3
    missing_caa: List[str] = []
    for domain in scope.domains:
        try:
            resolver.resolve(domain, "CAA")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            missing_caa.append(domain)
            warn(f"No CAA record for {domain} -- any CA can issue certificates.")
        except Exception:
            pass
    if missing_caa:
        save_lines(out / "missing_caa.txt", missing_caa)

    success("Phase 5 complete.")


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6 -- CNAME DANGLING ANALYSIS  [NEW]
# Passive-equivalent: DNS queries through public resolvers only.
# Cannot cause damage. Flags NXDOMAIN dangling CNAMEs as P0.
# ═══════════════════════════════════════════════════════════════════════════════

def phase6_cname(scope: Scope) -> None:
    section("Phase 6 -- CNAME Dangling Analysis")
    out       = make_dir(scope.output_dir, "phase6_cname")
    subs_file = scope.best_subdomain_file()
    subs      = read_lines(subs_file)

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    dangling: List[Dict] = []
    info(f"Checking {min(len(subs), 5000)} subdomains for dangling CNAMEs via public resolvers")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as progress:
        task = progress.add_task("Checking CNAME chains...", total=min(len(subs), 5000))
        for sub in subs[:5000]:
            progress.advance(task)
            try:
                cname_answers = resolver.resolve(sub, "CNAME")
                for rdata in cname_answers:
                    target    = str(rdata.target).rstrip(".")
                    dangerous = any(target.endswith(e) for e in DANGEROUS_CNAME_ENDINGS)
                    try:
                        resolver.resolve(target, "A")
                        status = "RESOLVES"
                    except dns.resolver.NXDOMAIN:
                        status = "NXDOMAIN"
                        if dangerous:
                            critical(f"DANGLING CNAME: {sub} -> {target} (NXDOMAIN on dangerous platform)")
                    except Exception:
                        status = "NODATA"
                    if dangerous or status == "NXDOMAIN":
                        dangling.append({
                            "subdomain": sub, "cname_target": target,
                            "status": status, "dangerous_platform": dangerous,
                        })
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            except Exception:
                pass

    if dangling:
        write_json(out / "dangling_cnames.json", dangling)
        actionable = [d for d in dangling if d["status"] == "NXDOMAIN"]
        if actionable:
            critical(f"{len(actionable)} NXDOMAIN dangling CNAMEs -- immediate takeover risk!")
        save_lines(out / "dangling_cnames_summary.txt",
                   [f"{d['subdomain']} -> {d['cname_target']} [{d['status']}]" for d in dangling])
    else:
        success("No dangling CNAMEs detected.")

    success("Phase 6 complete.")

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 7 -- CLOUD ASSET ENUMERATION (UNAUTHENTICATED)
# ═══════════════════════════════════════════════════════════════════════════════

def phase7_cloud(scope: Scope) -> None:
    section("Phase 7 -- Cloud Asset Enumeration (Unauthenticated)")
    out = make_dir(scope.output_dir, "phase7_cloud")
    keywords = [re.sub(r"[^\w]", "", k.split(".")[0]) for k in (scope.domains + ([scope.org_name] if scope.org_name else []))]
    perms: Set[str] = set()
    for kw in keywords:
        for pre in ["", "dev-", "staging-", "prod-"]:
            for suf in BUCKET_SUFFIXES + [""]:
                perms.add(f"{pre}{kw}{suf}")
    save_lines(out / "bucket_permutations.txt", sorted(perms))
    info(f"Generated {len(perms)} bucket name permutations.")
    if tool_available("cloud_enum"):
        for kw in keywords[:3]:
            run_tool(["cloud_enum", "-k", kw, "-l", str(out / f"cloud_enum_{kw}.txt")], timeout=600)
        success("cloud_enum complete.")
    else:
        warn("cloud_enum not found. Install: git clone https://github.com/initstring/cloud_enum && pip3 install -r requirements.txt")
    info("Probing S3 bucket names via HEAD requests (unauthenticated)")
    s3_findings: List[Dict] = []
    session = requests.Session(); session.headers.update({"User-Agent": "Mozilla/5.0"})
    for name in list(perms)[:200]:
        for s3_url in [f"https://{name}.s3.amazonaws.com", f"https://s3.amazonaws.com/{name}"]:
            try:
                r = session.head(s3_url, timeout=5, allow_redirects=False)
                if r.status_code in (200, 403):
                    finding = {"bucket": name, "url": s3_url, "status": r.status_code, "public": r.status_code == 200}
                    s3_findings.append(finding)
                    if r.status_code == 200: critical(f"PUBLIC S3 BUCKET: {s3_url}")
                    else: info(f"S3 bucket exists (private): {name}")
            except Exception:
                pass
    if s3_findings:
        write_json(out / "s3_findings.json", s3_findings)
        public = [f for f in s3_findings if f["public"]]
        if public: critical(f"{len(public)} PUBLIC S3 buckets found!")
    if scope.shodan_key and SHODAN_AVAILABLE and scope.org_name:
        api = shodan_lib.Shodan(scope.shodan_key)
        for query, label in [
            (f'product:"Docker" org:"{scope.org_name}"', "docker_api"),
            (f'product:"Kubernetes" org:"{scope.org_name}"', "kubernetes"),
            (f'product:"Elasticsearch" org:"{scope.org_name}"', "elasticsearch"),
            (f'product:"Redis" org:"{scope.org_name}"', "redis"),
        ]:
            try:
                results = shodan_search(api, query)
                if results is None: continue
                write_json(out / f"shodan_{label}.json", results)
                if results.get("total", 0) > 0:
                    warn(f"Shodan: {results['total']} {label} instances found!")
            except Exception as exc:
                warn(f"Shodan {label} query failed: {exc}")
    success("Phase 7 complete.")


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 8 -- CREDENTIAL & DATA LEAK MONITORING
# (+Google dork file generation)
# ═══════════════════════════════════════════════════════════════════════════════

def phase8_leaks(scope: Scope) -> None:
    section("Phase 8 -- Credential & Data Leak Monitoring")
    out       = make_dir(scope.output_dir, "phase17_leaks")
    subs_file = scope.best_subdomain_file()

    if scope.github_org:
        if tool_available("trufflehog"):
            info(f"trufflehog: scanning GitHub org {scope.github_org} (verified only)")
            run_tool(["trufflehog", "github", f"--org={scope.github_org}", "--only-verified", "--json"],
                     out / f"trufflehog_{scope.github_org}.json", timeout=2400)
            hits = [l for l in read_lines(out / f"trufflehog_{scope.github_org}.json") if l and "{" in l]
            if hits: critical(f"trufflehog: {len(hits)} VERIFIED secrets in {scope.github_org}!")
            else: success(f"trufflehog: No verified secrets in {scope.github_org}.")
        else:
            warn("trufflehog not found. Install via the trufflehog install script.")
        if tool_available("gitleaks"):
            info(f"gitleaks: scanning GitHub org {scope.github_org}")
            run_tool(["gitleaks", "detect", "--source", f"https://github.com/{scope.github_org}",
                      "-v", "--report-format", "json", "--report-path", str(out / "gitleaks_report.json")],
                     timeout=900)
        else:
            warn("gitleaks not found. Install: apt install gitleaks")

    info("HIBP: checking public breach data")
    try:
        r = requests.get("https://haveibeenpwned.com/api/v3/breaches",
                         headers={"User-Agent": "ASM-Enterprise/2.0"}, timeout=15)
        if r.ok:
            all_breaches = r.json()
            for domain in scope.domains:
                matches = [b for b in all_breaches if domain.lower() in b.get("Domain","").lower()]
                if matches:
                    write_json(out / f"hibp_{domain}.json", matches)
                    warn(f"HIBP: {len(matches)} breach(es) for {domain}")
                    for b in matches[:5]:
                        console.print(f"    [yellow]{b.get('Name','?')}[/] ({b.get('BreachDate','?')}): {b.get('DataClasses',[])}")
                else:
                    success(f"HIBP: No breaches for {domain}")
    except Exception as exc:
        warn(f"HIBP API failed: {exc}")

    # Google / search engine dork file generation (zero network, offline)
    info("Generating Google/search engine dork query file")
    dorks: List[str] = []
    for domain in scope.domains:
        org_handle = scope.github_org or domain.split(".")[0]
        for template in GOOGLE_DORK_TEMPLATES:
            dorks.append(template.format(domain=domain))
        if scope.org_name:
            dorks += [f'"{scope.org_name}" filetype:pdf', f'"{scope.org_name}" "confidential"',
                      f'"{scope.org_name}" site:linkedin.com']
        dorks += [
            f"org:{org_handle} api_key", f"org:{org_handle} aws_secret_access_key",
            f"org:{org_handle} BEGIN RSA PRIVATE KEY", f"org:{org_handle} password",
            f"org:{org_handle} token", f"org:{org_handle} secret",
            f'"{domain}" api_key', f'"{domain}" .env', f'"{domain}" "Authorization:"',
        ]
    save_lines(out / "search_dorks.txt", dorks)
    info(f"Dork queries saved ({len(dorks)} queries) -> {out / 'search_dorks.txt'}")
    info("Run manually at: google.com, bing.com, github.com/search, pastebin.com")

    # ── Filesystem scan of Phase 8 JS dump (if Phase 8 JS collection ran first) ──
    js_dump = scope.output_dir / "phase8_js" / "dump"
    if js_dump.exists() and any(js_dump.iterdir()):
        info(f"Phase 8 JS dump found -- running trufflehog/gitleaks in filesystem mode")
        if tool_available("trufflehog"):
            info("trufflehog filesystem scan of JS dump (--no-verification)")
            run_tool(
                ["trufflehog", "filesystem", str(js_dump),
                 "--json", "--no-verification"],
                out / "trufflehog_js_dump.json", timeout=600,
            )
            hits = [l for l in read_lines(out / "trufflehog_js_dump.json") if l and "{" in l]
            if hits: critical(f"trufflehog JS dump: {len(hits)} potential secret(s) in fetched JS!")
            else: success("trufflehog JS dump: No secrets found.")
        else:
            warn("trufflehog not installed -- skipping JS dump filesystem scan.")
        if tool_available("gitleaks"):
            info("gitleaks filesystem scan of JS dump (--no-git)")
            run_tool(
                ["gitleaks", "detect", "--source", str(js_dump), "--no-git",
                 "--report-format", "json",
                 "--report-path", str(out / "gitleaks_js_dump.json"),
                 "--redact", "--exit-code", "0"],
                timeout=600,
            )
            try:
                gl = json.loads((out / "gitleaks_js_dump.json").read_text(errors="ignore"))
                if gl: warn(f"gitleaks JS dump: {len(gl)} finding(s).")
                else: success("gitleaks JS dump: No secrets found.")
            except Exception:
                pass
        else:
            warn("gitleaks not installed -- skipping JS dump filesystem scan.")
    else:
        info("No Phase 8 JS dump found -- run Phase 8 (JS collection) first to enable filesystem scanning.")

    success("Phase 8 complete.")


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 9 -- CONTINUOUS CERTIFICATE MONITORING (CertStream)
# (+Let's Encrypt flagging as takeover indicator)
# ═══════════════════════════════════════════════════════════════════════════════

def phase9_certstream(scope: Scope) -> None:
    section("Phase 9 -- Continuous Certificate Monitoring (CertStream)")
    out = make_dir(scope.output_dir, "phase9_certstream")
    if not CERTSTREAM_AVAILABLE:
        error("certstream library not installed. Run: pip3 install certstream --break-system-packages")
        return
    alert_file   = out / "cert_alerts.jsonl"
    watch_terms  = [t.lower() for t in (scope.domains + ([scope.org_name] if scope.org_name else [])) if t]
    alert_count  = 0
    info(f"Monitoring CertStream for: {watch_terms}")
    info("Let's Encrypt certs on your domains may indicate an active takeover.")
    info("Press Ctrl+C to stop.")

    def callback(message, context):
        nonlocal alert_count
        if message.get("message_type") != "certificate_update":
            return
        try:
            leaf         = message["data"]["leaf_cert"]
            cert_domains = leaf.get("all_domains", [])
            issuer_org   = leaf.get("issuer", {}).get("O", "Unknown")
            is_le        = "Let's Encrypt" in issuer_org
            for cert_domain in cert_domains:
                for term in watch_terms:
                    if cert_domain.lower() == term or cert_domain.lower().endswith(f".{term}"):
                        alert_count += 1
                        le_flag = " [LE -- CHECK FOR TAKEOVER]" if is_le else ""
                        with open(alert_file, "a") as f:
                            f.write(json.dumps({
                                "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                "cert_domain": cert_domain, "issuer_org": issuer_org,
                                "lets_encrypt": is_le, "all_domains": cert_domains[:15],
                            }) + "\n")
                        if is_le:
                            critical(f"NEW CERT (Let's Encrypt): {cert_domain}{le_flag}")
                        else:
                            warn(f"New cert: {cert_domain} | Issuer: {issuer_org}")
                        break
        except Exception:
            pass

    try:
        certstream.listen_for_events(callback, url="wss://certstream.calidog.io/")
    except KeyboardInterrupt:
        console.print(f"\n  [yellow]CertStream stopped. {alert_count} events recorded.[/yellow]")
        success(f"Alerts saved -> {alert_file}")
    success("Phase 9 complete.")

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 10 -- REVERSE PTR SWEEPS
# ═══════════════════════════════════════════════════════════════════════════════

def phase10_ptr(scope: Scope) -> None:
    section("Phase 10 -- Reverse PTR Sweeps")
    out      = make_dir(scope.output_dir, "phase10_ptr")
    all_ips: List[str] = []
    phase4_ips = scope.output_dir / "phase4_ip" / "all_ips.txt"
    if phase4_ips.exists():
        all_ips = read_lines(phase4_ips)
        info(f"Loaded {len(all_ips)} IPs from Phase 4.")
    elif scope.ip_ranges:
        for cidr in scope.ip_ranges:
            try:
                for h in ipaddress.ip_network(cidr, strict=False).hosts():
                    all_ips.append(str(h))
            except ValueError:
                pass
    else:
        resolver = dns.resolver.Resolver(); resolver.timeout = 3
        for domain in scope.domains:
            try:
                for rdata in resolver.resolve(domain, "A"):
                    all_ips.append(str(rdata))
            except Exception:
                pass
    if not all_ips:
        warn("No IPs for PTR sweep. Run Phase 4 first or define IP ranges in scope.")
        return
    if tool_available("dnsx"):
        ip_file = out / "ips_for_ptr.txt"
        save_lines(ip_file, all_ips[:5000])
        run_tool(["dnsx", "-l", str(ip_file), "-ptr", "-resp", "-json",
                  "-o", str(out / "ptr_results.json"), "-silent"], timeout=900)
        known_subs = set(read_lines(scope.best_subdomain_file()))
        new_hosts: List[str] = []
        ptr_file = out / "ptr_results.json"
        if ptr_file.exists():
            for line in ptr_file.read_text(errors="ignore").splitlines():
                try:
                    entry = json.loads(line)
                    for ptr in entry.get("ptr", []):
                        host = ptr.rstrip(".").lower()
                        for domain in scope.domains:
                            if (host.endswith(f".{domain}") or host == domain) and host not in known_subs:
                                new_hosts.append(host)
                except Exception:
                    pass
        if new_hosts:
            save_lines(out / "ptr_new_hosts.txt", sorted(set(new_hosts)))
            success(f"PTR sweep: {len(set(new_hosts))} new hosts not in subdomain enumeration.")
        else:
            success("PTR sweep complete -- no new hosts beyond existing subdomain set.")
    else:
        warn("dnsx not found. Install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
    success("Phase 10 complete.")


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 11 -- DNS PERMUTATION / SECOND-ROUND BRUTE FORCE
# ═══════════════════════════════════════════════════════════════════════════════

def phase11_permutation(scope: Scope) -> None:
    section("Phase 11 -- DNS Permutation & Second-Round Brute Force")
    out       = make_dir(scope.output_dir, "phase11_permutation")
    resolvers = get_resolvers(scope.output_dir)
    subs_file = scope.best_subdomain_file()
    known_subs = set(read_lines(subs_file))
    if not known_subs:
        warn("No existing subdomains to permute. Run Phase 3 first.")
        return
    info(f"Generating permutations from {len(known_subs)} known subdomains.")
    if tool_available("alterx"):
        alterx_out = out / "alterx_permutations.txt"
        run_tool(["alterx", "-l", str(subs_file), "-silent", "-o", str(alterx_out)], timeout=300)
        perms = read_lines(alterx_out)
        info(f"alterx: {len(perms)} permutation candidates.")
    else:
        warn("alterx not found. Install: go install github.com/projectdiscovery/alterx/cmd/alterx@latest")
        warn("Using Python permutation fallback.")
        PATTERNS = ["dev","staging","prod","uat","test","qa","old","new","api","api2",
                    "v2","v3","internal","ext","beta","preview","demo","sandbox","corp","mgmt"]
        perms: List[str] = []
        for sub in list(known_subs)[:500]:
            parts = sub.split(".")
            if len(parts) < 2: continue
            label = parts[0]; base = ".".join(parts[1:])
            for pat in PATTERNS:
                perms += [f"{label}-{pat}.{base}", f"{pat}-{label}.{base}", f"{label}{pat}.{base}"]
        perms = sorted(set(perms) - known_subs)
        alterx_out = out / "alterx_permutations.txt"
        save_lines(alterx_out, perms)
    if not perms:
        warn("No permutations generated."); return
    if tool_available("puredns"):
        resolved_out = out / "permutation_resolved.txt"
        run_tool(["puredns", "resolve", str(alterx_out), "-r", str(resolvers),
                  "-w", str(resolved_out)], timeout=1800)
        resolved  = read_lines(resolved_out)
        new_hosts = sorted(set(resolved) - known_subs)
        if new_hosts:
            save_lines(out / "permutation_new_hosts.txt", new_hosts)
            critical(f"Permutation brute force found {len(new_hosts)} NEW live hosts!")
        else:
            success("Permutation resolution complete -- no new live hosts.")
    else:
        warn("puredns not found. Permutation candidates saved for manual resolution.")
    success("Phase 11 complete.")


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 12 -- FAVICON HASH PIVOTING
# ═══════════════════════════════════════════════════════════════════════════════

def phase12_favicon(scope: Scope) -> None:
    section("Phase 12 -- Favicon Hash Pivoting")
    out = make_dir(scope.output_dir, "phase12_favicon")
    live_hosts: List[str] = []
    httpx_file = scope.output_dir / "phase5_validation" / "httpx_results.json"
    if httpx_file.exists():
        for line in httpx_file.read_text(errors="ignore").splitlines():
            try:
                entry = json.loads(line)
                if entry.get("status_code") in (200, 301, 302):
                    live_hosts.append(entry.get("url",""))
            except Exception:
                pass
    else:
        live_hosts = [f"https://{d}" for d in scope.domains]
    favicon_data: List[Dict] = []
    if tool_available("httpx") and live_hosts:
        hosts_file = out / "hosts_for_favicon.txt"
        save_lines(hosts_file, [h.replace("https://","").replace("http://","").split("/")[0] for h in live_hosts])
        run_tool(["httpx", "-l", str(hosts_file), "-favicon", "-json",
                  "-o", str(out / "httpx_favicon.json"), "-silent"], timeout=900)
        favicon_out = out / "httpx_favicon.json"
        if favicon_out.exists():
            for line in favicon_out.read_text(errors="ignore").splitlines():
                try:
                    e = json.loads(line)
                    if e.get("favicon-mmh3"):
                        favicon_data.append({"host": e.get("host",""), "url": e.get("url",""),
                                             "favicon_hash": e.get("favicon-mmh3")})
                except Exception:
                    pass
    else:
        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0"})
        for host_url in live_hosts[:100]:
            r = safe_get(f"{host_url.rstrip('/')}/favicon.ico", timeout=8)
            if r and r.status_code == 200 and len(r.content) > 100:
                import base64
                encoded = base64.encodebytes(r.content)
                fhash   = mmh3.hash(encoded) if MMH3_AVAILABLE else int(hashlib.md5(r.content).hexdigest(),16) % (2**32)
                favicon_data.append({"host": host_url, "favicon_hash": fhash})
    if not favicon_data:
        warn("No favicon hashes collected."); success("Phase 12 complete."); return
    write_json(out / "favicon_hashes.json", favicon_data)
    success(f"Collected {len(favicon_data)} favicon hashes.")
    if scope.shodan_key and SHODAN_AVAILABLE:
        api = shodan_lib.Shodan(scope.shodan_key)
        known_ips = set(read_lines(scope.output_dir / "phase4_ip" / "all_ips.txt"))
        pivot_results: List[Dict] = []
        unique = list({str(e["favicon_hash"]): e for e in favicon_data}.values())
        for entry in unique[:20]:
            fhash = entry["favicon_hash"]
            try:
                results = shodan_search(api, f"http.favicon.hash:{fhash}")
                if results is None: continue
                total   = results.get("total", 0)
                if total > 0:
                    ips = [m.get("ip_str") for m in results.get("matches",[])[:20]]
                    pivot_results.append({"favicon_hash": fhash, "origin": entry.get("host",""),
                                          "shodan_hits": total, "sample_ips": ips})
                    info(f"Favicon hash {fhash}: {total} Shodan hits.")
                    novel = [ip for ip in ips if ip and ip not in known_ips]
                    if novel:
                        critical(f"Favicon pivot: {len(novel)} IPs outside current scope -- potential shadow IT!")
            except Exception as exc:
                warn(f"Shodan favicon pivot failed: {exc}")
        if pivot_results:
            write_json(out / "favicon_pivot_results.json", pivot_results)
            all_novel = [ip for pr in pivot_results for ip in pr.get("sample_ips",[]) if ip and ip not in known_ips]
            if all_novel: save_lines(out / "favicon_novel_ips.txt", sorted(set(all_novel)))
    success("Phase 12 complete.")


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 13 -- DMARC / SPF / DKIM ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════════

def phase13_email_security(scope: Scope) -> None:
    section("Phase 13 -- DMARC / SPF / DKIM Enumeration")
    out      = make_dir(scope.output_dir, "phase13_email_security")
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8","1.1.1.1"]; resolver.timeout = 5; resolver.lifetime = 5
    all_findings: List[Dict] = []
    for domain in scope.domains:
        finding: Dict[str, Any] = {"domain": domain, "issues": []}
        # SPF
        try:
            txts = resolver.resolve(domain, "TXT")
            spf  = [str(r).strip('"') for r in txts if "v=spf1" in str(r).lower()]
            finding["spf"] = spf
            if not spf:
                finding["issues"].append("NO SPF RECORD -- domain spoofable via email")
                critical(f"No SPF record: {domain}")
            elif len(spf) > 1:
                finding["issues"].append("MULTIPLE SPF RECORDS -- RFC violation")
            elif "+all" in spf[0]:
                finding["issues"].append("SPF +all -- any server can send as this domain")
                critical(f"SPF +all: {domain}")
            elif "~all" in spf[0]:
                finding["issues"].append("SPF ~all (SoftFail) -- spoofed mail marked but not rejected")
                warn(f"SPF SoftFail: {domain}")
            else:
                success(f"SPF HardFail (-all): {domain}")
        except Exception:
            finding["issues"].append("SPF lookup error"); finding["spf"] = []
        # DMARC
        try:
            dmarc_txts = resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc      = [str(r).strip('"') for r in dmarc_txts if "v=dmarc1" in str(r).lower()]
            finding["dmarc"] = dmarc
            if not dmarc:
                finding["issues"].append("NO DMARC RECORD"); critical(f"No DMARC: {domain}")
            else:
                pm = re.search(r"p=(\w+)", dmarc[0], re.IGNORECASE)
                if pm:
                    policy = pm.group(1).lower()
                    if policy == "none":   finding["issues"].append("DMARC p=none -- monitor only, no enforcement"); warn(f"DMARC p=none: {domain}")
                    elif policy == "reject": success(f"DMARC p=reject: {domain}")
                if "rua=" not in dmarc[0].lower():
                    finding["issues"].append("No DMARC aggregate reporting (rua=) configured")
        except dns.resolver.NXDOMAIN:
            finding["issues"].append("NO DMARC RECORD"); finding["dmarc"] = []; critical(f"No DMARC: {domain}")
        except Exception:
            finding["dmarc"] = []
        # DKIM
        found_dkim: List[str] = []
        for selector in DKIM_SELECTORS:
            try:
                dkim_txts = resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                for r in dkim_txts:
                    if "v=dkim1" in str(r).lower() or "p=" in str(r).lower():
                        found_dkim.append(f"{selector}: {str(r)[:80]}"); break
            except Exception:
                pass
        finding["dkim_selectors_found"] = found_dkim
        if not found_dkim:
            finding["issues"].append("No common DKIM selectors found")
            warn(f"No DKIM selectors found for {domain}")
        all_findings.append(finding)
    write_json(out / "email_security_findings.json", all_findings)
    t = Table(show_header=True, header_style="bold magenta", title="Email Security Summary")
    t.add_column("Domain",style="cyan"); t.add_column("SPF",style="white")
    t.add_column("DMARC Policy",style="white"); t.add_column("DKIM Selectors",style="white")
    t.add_column("Issues",style="red")
    for f in all_findings:
        spf_s = "present" if f.get("spf") else "MISSING"
        dv    = "".join(f.get("dmarc") or [])
        pm    = re.search(r"p=(\w+)", dv, re.IGNORECASE) if dv else None
        t.add_row(f["domain"], spf_s, pm.group(1) if pm else "MISSING",
                  str(len(f.get("dkim_selectors_found",[]))), str(len(f.get("issues",[]))))
    console.print(t)
    success("Phase 13 complete.")


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 14 -- HISTORICAL DNS (SecurityTrails)
# ═══════════════════════════════════════════════════════════════════════════════

def phase14_historical_dns(scope: Scope) -> None:
    section("Phase 14 -- Historical DNS (SecurityTrails)")
    out = make_dir(scope.output_dir, "phase14_historical_dns")
    if not scope.securitytrails_key:
        warn("No SecurityTrails API key provided. Set SECURITYTRAILS_API_KEY or enter at startup.")
        warn("Free tier: https://securitytrails.com/app/account"); return
    headers  = {"APIKEY": scope.securitytrails_key, "Accept": "application/json"}
    base_url = "https://api.securitytrails.com/v1"
    for domain in scope.domains:
        domain_findings: Dict[str, Any] = {"domain": domain}
        for record_type in ["a","aaaa","mx","ns","cname","txt"]:
            try:
                r = requests.get(f"{base_url}/history/{domain}/dns/{record_type}",
                                 headers=headers, timeout=15)
                if r.status_code == 401: error("SecurityTrails API key invalid."); return
                if r.ok:
                    records = r.json().get("records",[])
                    if records:
                        domain_findings[f"history_{record_type}"] = records
                        if record_type == "a":
                            for rs in records:
                                for v in rs.get("values",[]):
                                    ip = v.get("ip","")
                                    if ip:
                                        domain_findings.setdefault("historical_ips",[]).append({
                                            "ip": ip, "first_seen": rs.get("first_seen"),
                                            "last_seen": rs.get("last_seen")})
                time.sleep(0.5)
            except Exception as exc:
                warn(f"SecurityTrails {record_type} history failed: {exc}")
        try:
            r = requests.get(f"{base_url}/domain/{domain}/subdomains",
                             headers=headers,
                             params={"children_only": "false", "include_inactive": "true"}, timeout=15)
            if r.ok:
                st_subs = [f"{s}.{domain}" for s in r.json().get("subdomains",[])]
                known_subs = set(read_lines(scope.best_subdomain_file()))
                new_subs = sorted(set(st_subs) - known_subs)
                if st_subs: save_lines(out / f"st_subdomains_{domain}.txt", st_subs)
                if new_subs:
                    save_lines(out / f"st_new_subdomains_{domain}.txt", new_subs)
                    warn(f"SecurityTrails: {len(new_subs)} subdomains not in current enumeration for {domain}.")
                domain_findings["new_subdomains"] = new_subs[:50]
            time.sleep(0.5)
        except Exception as exc:
            warn(f"SecurityTrails subdomain lookup failed: {exc}")
        write_json(out / f"st_full_{domain}.json", domain_findings)
        hist_ips = domain_findings.get("historical_ips",[])
        if hist_ips:
            save_lines(out / f"historical_ips_{domain}.txt",
                       [f"{e['ip']} (last: {e.get('last_seen','?')})" for e in hist_ips])
            warn(f"{len(hist_ips)} historical A records -- review for CDN/Cloudflare origin IP exposure.")
    success("Phase 14 complete.")


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 15 -- EMAIL HARVESTING
# ═══════════════════════════════════════════════════════════════════════════════

def phase15_email_harvest(scope: Scope) -> None:
    section("Phase 15 -- Email Harvesting")
    out = make_dir(scope.output_dir, "phase15_email_harvest")
    if not tool_available("theHarvester"):
        warn("theHarvester not found. Install: apt install theharvester  OR  pip3 install theHarvester"); return
    passive_sources = ["anubis","baidu","bing","binaryedge","bufferoverun","crtsh","dnsdumpster",
                       "duckduckgo","hackertarget","otx","rapiddns","threatcrowd","urlscan","virustotal"]
    all_emails: Set[str] = set()
    all_hosts:  Set[str] = set()
    for domain in scope.domains:
        harvest_out = out / f"theharvester_{domain}.json"
        run_tool(["theHarvester", "-d", domain, "-b", ",".join(passive_sources),
                  "-f", str(harvest_out)], timeout=600)
        for candidate in [harvest_out, Path(str(harvest_out)+".json")]:
            if candidate.exists():
                try:
                    data = json.loads(candidate.read_text(errors="ignore"))
                    all_emails.update(data.get("emails",[]))
                    all_hosts.update(data.get("hosts",[]) + data.get("interesting_urls",[]))
                    success(f"theHarvester [{domain}]: {len(data.get('emails',[]))} emails, {len(data.get('hosts',[]))} hosts.")
                    break
                except Exception:
                    pass
    if all_emails:
        save_lines(out / "harvested_emails.txt", sorted(all_emails))
        success(f"Total emails harvested: {len(all_emails)}")
        domain_set = set(scope.domains)
        external = [e for e in all_emails if not any(e.lower().endswith(f"@{d}") for d in domain_set)]
        if external: save_lines(out / "external_domain_emails.txt", external)
    if all_hosts:
        known = set(read_lines(scope.best_subdomain_file()))
        new   = sorted(set(all_hosts) - known)
        if new: save_lines(out / "harvest_new_hosts.txt", new)
    success("Phase 15 complete.")


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 16 -- PASTE SITE MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

def phase16_pastes(scope: Scope) -> None:
    section("Phase 16 -- Paste Site Monitoring")
    out     = make_dir(scope.output_dir, "phase16_pastes")
    session = requests.Session(); session.headers.update({"User-Agent": "Mozilla/5.0"})
    all_paste_hits: List[Dict] = []
    for domain in scope.domains:
        try:
            r = session.get("https://www.google.com/search",
                            params={"q": f'site:pastebin.com "{domain}"', "num": "20"}, timeout=10)
            paste_urls = list(set(re.findall(r"https://pastebin\.com/[A-Za-z0-9]{6,10}", r.text)))
            if paste_urls:
                save_lines(out / f"pastebin_urls_{domain}.txt", paste_urls)
                warn(f"Pastebin: {len(paste_urls)} paste URLs found mentioning {domain}.")
                all_paste_hits.append({"source": "pastebin_google", "domain": domain, "urls": paste_urls})
        except Exception as exc:
            warn(f"Pastebin search failed for {domain}: {exc}")
        time.sleep(2)
    for domain in scope.domains:
        for query in [f'"{domain}" password', f'"{domain}" api_key', f'"{domain}" secret']:
            try:
                r = session.get("https://api.github.com/search/code",
                                params={"q": query, "per_page": "10"},
                                headers={"Accept": "application/vnd.github.v3+json"}, timeout=10)
                if r.status_code == 200:
                    data  = r.json()
                    total = data.get("total_count", 0)
                    if total > 0:
                        hit = {"source": "github_code_search", "query": query, "total_count": total,
                               "sample_urls": [i.get("html_url") for i in data.get("items",[])[:5]]}
                        all_paste_hits.append(hit)
                        warn(f"GitHub code [{query}]: {total} results.")
                elif r.status_code == 403:
                    warn("GitHub API rate limit reached."); break
                time.sleep(3)
            except Exception as exc:
                warn(f"GitHub search failed [{query}]: {exc}")
    for domain in scope.domains:
        try:
            r = session.get(f"https://leakix.net/domain/{domain}",
                            headers={"Accept": "application/json"}, timeout=10)
            if r.ok:
                data = r.json()
                if data:
                    write_json(out / f"leakix_{domain}.json", data)
                    warn(f"LeakIX: {len(data) if isinstance(data,list) else 1} record(s) for {domain}.")
                    all_paste_hits.append({"source": "leakix", "domain": domain})
        except Exception:
            pass
        time.sleep(1)
    dehashed_links = [f"https://dehashed.com/search?query={d}" for d in scope.domains]
    save_lines(out / "dehashed_manual_links.txt", dehashed_links)
    if all_paste_hits:
        write_json(out / "paste_hits_summary.json", all_paste_hits)
        warn(f"Paste/leak monitoring: {len(all_paste_hits)} hit categories found.")
    else:
        success("No paste or leak hits found.")
    success("Phase 16 complete.")

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 17 -- JS COLLECTION, ENDPOINT EXTRACTION & SECRET SCANNING
# Passive-equivalent: fetches publicly served JS files (browser-identical GETs).
# Runs inline secret pattern matching + entropy detection on all fetched content.
# Dumps JS files to disk so Phase 8 (leaks) can run trufflehog/gitleaks against them.
# ═══════════════════════════════════════════════════════════════════════════════

def phase17_js_endpoints(scope: Scope) -> None:
    section("Phase 17 -- JS Collection, Endpoint Extraction & Secret Scanning")
    out  = make_dir(scope.output_dir, "phase8_js")
    dump = make_dir(out, "dump")   # JS files saved here for Phase 8 filesystem scan
    all_endpoints:    Set[str]  = set()
    all_js_urls:      List[str] = []
    all_secrets:      List[Dict] = []

    if tool_available("gau"):
        info("Running gau to collect JS URLs from Wayback, CommonCrawl, URLScan")
        for domain in scope.domains:
            gau_out = run_tool(
                ["gau", "--blacklist", "png,jpg,gif,svg,woff,woff2,ttf,eot,ico,css", domain],
                capture=True, timeout=180,
            )
            if gau_out:
                js_urls = [u for u in gau_out.splitlines() if u.strip().endswith(".js")]
                save_lines(out / f"gau_js_{domain}.txt", js_urls)
                all_js_urls += js_urls
                success(f"gau [{domain}]: {len(js_urls)} JS URLs collected.")
    else:
        warn("gau not found. Install: go install github.com/lc/gau/v2/cmd/gau@latest")

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"})
    session.verify = False
    JS_INTEREST = ["/api/","/v1/","/v2/","/auth/","/user","/account",
                   "/admin","/internal","/graphql","/rest","/token"]
    fetched = 0

    for js_url in all_js_urls[:200]:
        r = safe_get(js_url, timeout=8)
        if not r or r.status_code != 200:
            continue
        fetched += 1
        content = r.text

        # Dump JS to disk for Phase 8 trufflehog/gitleaks filesystem scan
        safe_name = re.sub(r'[^\w.\-]', '_', js_url.split("://",1)[-1])[:120] + ".js"
        try:
            (dump / safe_name).write_text(content, encoding="utf-8", errors="ignore")
        except Exception:
            pass

        # Endpoint extraction
        for pattern in JS_ENDPOINT_PATTERNS:
            for m in pattern.finditer(content):
                ep = (m.group(1) if m.lastindex else m.group(0)).strip("\"'`")
                if ep and any(kw in ep.lower() for kw in JS_INTEREST):
                    all_endpoints.add(ep)

        # Inline secret scanning
        all_secrets += js_scan_content(content, js_url)
        time.sleep(0.3)

    # Scan inline scripts from live pages
    live_file = scope.output_dir / "phase5_validation" / "live_hosts.txt"
    if live_file.exists():
        for host in read_lines(live_file)[:50]:
            r = safe_get(host, timeout=8)
            if not r or r.status_code != 200:
                continue
            inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>',
                                        r.text, re.DOTALL | re.IGNORECASE)
            for i, script in enumerate(inline_scripts):
                label = f"{host}#inline-{i}"
                for pattern in JS_ENDPOINT_PATTERNS:
                    for m in pattern.finditer(script):
                        ep = (m.group(1) if m.lastindex else m.group(0)).strip("\"'`")
                        if ep and any(kw in ep.lower() for kw in JS_INTEREST):
                            all_endpoints.add(ep)
                all_secrets += js_scan_content(script, label)
            time.sleep(0.3)

    # Output -- endpoints
    if all_endpoints:
        save_lines(out / "js_endpoints.txt", sorted(all_endpoints))
        success(f"JS endpoints: {len(all_endpoints)} unique API paths from {fetched} JS files.")
        high_value = [ep for ep in all_endpoints
                      if any(kw in ep.lower() for kw in
                             ["/admin","/internal","graphql","swagger","openapi","/debug","/config"])]
        if high_value:
            save_lines(out / "js_endpoints_high_value.txt", sorted(high_value))
            warn(f"{len(high_value)} high-value endpoints (admin/internal/graphql/swagger).")
    else:
        info("No API endpoints extracted from JS files.")

    # Output -- secrets
    if all_secrets:
        # Deduplicate by (type, match)
        seen: set = set()
        unique_secrets = []
        for s in all_secrets:
            key = (s["type"], s["match"][:60])
            if key not in seen:
                seen.add(key)
                unique_secrets.append(s)

        write_json(out / "js_secrets.json", unique_secrets)
        pattern_hits  = [s for s in unique_secrets if s.get("method") == "pattern"]
        entropy_hits  = [s for s in unique_secrets if s.get("method") == "entropy"]

        if pattern_hits:
            critical(f"JS secret scan: {len(pattern_hits)} pattern matches "
                     f"(credentials/keys/tokens in JS files!):")
            for s in pattern_hits[:10]:
                console.print(f"    [red]{s['type']}[/red] in {s['source']}: "
                               f"{s['match'][:80]}")
        if entropy_hits:
            warn(f"JS secret scan: {len(entropy_hits)} high-entropy strings "
                 f"(potential secrets -- review js_secrets.json).")

        dumped_count = sum(1 for _ in dump.iterdir()) if dump.exists() else 0
        info(f"{dumped_count} JS files saved to {dump}  "
             f"-- run Phase 8 (leaks) to scan with trufflehog/gitleaks.")
    else:
        success("JS secret scan: no secrets detected by pattern matching or entropy.")

    success("Phase 17 complete.")


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 18 -- REVERSE WHOIS  [NEW]
# Fully passive: queries third-party whois aggregator APIs.
# Finds domains registered with same org name, registrant email, or address.
# Surfaces domains with no CT trail -- pre-HTTPS era domains, shadow acquisitions.
# ═══════════════════════════════════════════════════════════════════════════════

def phase18_reverse_whois(scope: Scope) -> None:
    section("Phase 18 -- Reverse Whois")
    out     = make_dir(scope.output_dir, "phase18_reverse_whois")
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
    all_related_domains: Set[str] = set()
    known_domains       = set(scope.domains)

    # First collect registrant data from WHOIS of known domains
    registrant_emails:  Set[str] = set()
    registrant_orgs:    Set[str] = set()
    for domain in scope.domains:
        try:
            import subprocess as sp
            result = sp.run(["whois", domain], capture_output=True, text=True, timeout=30)
            for line in result.stdout.splitlines():
                lower = line.lower()
                if any(kw in lower for kw in ["registrant email","admin email","tech email"]):
                    m = re.search(r"[\w.+-]+@[\w.-]+\.\w+", line)
                    if m: registrant_emails.add(m.group(0).lower())
                if any(kw in lower for kw in ["registrant organization","registrant org"]):
                    parts = line.split(":",1)
                    if len(parts) > 1 and parts[1].strip():
                        registrant_orgs.add(parts[1].strip())
        except Exception:
            pass
    if scope.org_name:
        registrant_orgs.add(scope.org_name)
    info(f"Reverse whois pivot targets: {len(registrant_emails)} emails, {len(registrant_orgs)} org names.")

    # viewdns.info reverse whois (free, no API key required)
    for email in list(registrant_emails)[:5]:
        try:
            r = session.get("https://viewdns.info/reversewhois/",
                            params={"q": email}, timeout=15)
            if r.ok:
                matches = re.findall(r'([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})', r.text)
                domain_matches = [m for m in matches if "." in m and len(m) > 4
                                  and not m.startswith("viewdns") and m not in known_domains]
                all_related_domains.update(domain_matches[:100])
                if domain_matches:
                    info(f"viewdns.info reverse whois [{email}]: {len(domain_matches)} related domains.")
            time.sleep(2)
        except Exception as exc:
            warn(f"viewdns.info reverse whois failed for {email}: {exc}")

    # reversewhois.io (free)
    for org in list(registrant_orgs)[:3]:
        try:
            r = session.get("https://www.reversewhois.io/",
                            params={"q": org}, timeout=15)
            if r.ok:
                matches = re.findall(r'([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})', r.text)
                domain_matches = [m for m in matches if "." in m and len(m) > 4
                                  and m not in known_domains]
                all_related_domains.update(domain_matches[:100])
                if domain_matches:
                    info(f"reversewhois.io [{org}]: {len(domain_matches)} related domains.")
            time.sleep(2)
        except Exception as exc:
            warn(f"reversewhois.io failed for {org}: {exc}")

    # amass intel reverse whois (if available)
    if tool_available("amass") and (registrant_emails or scope.org_name):
        info("Running amass intel reverse whois")
        for domain in scope.domains[:2]:
            amass_out = run_tool(
                ["amass", "intel", "-d", domain, "-whois"],
                capture=True, timeout=300,
            )
            if amass_out:
                amass_domains = [l.strip() for l in amass_out.splitlines() if l.strip() and "." in l]
                new_ones = [d for d in amass_domains if d not in known_domains]
                all_related_domains.update(new_ones)
                if new_ones: info(f"amass intel whois [{domain}]: {len(new_ones)} related domains.")

    if all_related_domains:
        novel = sorted(all_related_domains - known_domains)
        save_lines(out / "reverse_whois_domains.txt", novel)
        success(f"Reverse whois: {len(novel)} related domains discovered not in current scope.")
        write_json(out / "reverse_whois_summary.json", {
            "registrant_emails_pivoted": list(registrant_emails),
            "registrant_orgs_pivoted":   list(registrant_orgs),
            "total_related_domains":     len(novel),
        })
        if len(novel) > 5:
            warn("Review reverse_whois_domains.txt -- may include subsidiaries, acquired companies,")
            warn("or pre-HTTPS era domains that have no certificate transparency trail.")
    else:
        info("No additional related domains found via reverse whois.")
    success("Phase 18 complete.")


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 19 -- DIGITAL FOOTPRINT & SHADOW ASSET DISCOVERY  [NEW]
# Fully passive: Shodan API queries only, no target contact.
# Combines tracker/analytics ID pivoting + copyright/unique string search.
# Surfaces related infrastructure, CDN-bypassed assets, and shadow IT.
# ═══════════════════════════════════════════════════════════════════════════════

def phase19_digital_footprint(scope: Scope) -> None:
    section("Phase 19 -- Digital Footprint & Shadow Asset Discovery")
    out = make_dir(scope.output_dir, "phase19_digital_footprint")
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})
    session.verify = False
    all_findings: List[Dict] = []
    known_ips = set(read_lines(scope.output_dir / "phase4_ip" / "all_ips.txt"))

    # ── Part A: Tracker / Analytics ID Pivoting ───────────────────────────────
    info("Collecting tracker / analytics IDs from live pages")
    live_file  = scope.output_dir / "phase5_validation" / "live_hosts.txt"
    live_hosts = read_lines(live_file)[:30] if live_file.exists() else [f"https://{d}" for d in scope.domains]

    TRACKER_PATTERNS = [
        ("Google Tag Manager",   re.compile(r'GTM-[A-Z0-9]{4,10}')),
        ("Google Analytics GA4", re.compile(r'G-[A-Z0-9]{8,12}')),
        ("Google Analytics UA",  re.compile(r'UA-\d{6,10}-\d{1,3}')),
        ("Facebook Pixel",       re.compile(r'fbq\s*\(\s*["\']init["\']\s*,\s*["\'](\d{10,20})["\']')),
        ("Hotjar",               re.compile(r'hjid\s*[:=]\s*(\d{6,10})')),
        ("Mixpanel Token",       re.compile(r'mixpanel\.init\s*\(\s*["\']([a-f0-9]{32})["\']')),
        ("Sentry DSN",           re.compile(r'https://[a-f0-9]{32}@[a-z0-9.]+sentry\.io/\d+')),
    ]

    collected_ids: Dict[str, List[str]] = {}
    for host in live_hosts:
        r = safe_get(host, timeout=8)
        if not r or r.status_code != 200:
            continue
        for tracker_name, pattern in TRACKER_PATTERNS:
            matches = pattern.findall(r.text)
            for match in matches:
                tracker_id = match if isinstance(match, str) else match
                if tracker_id and len(tracker_id) > 4:
                    collected_ids.setdefault(tracker_name, [])
                    if tracker_id not in collected_ids[tracker_name]:
                        collected_ids[tracker_name].append(tracker_id)
        time.sleep(0.3)

    if collected_ids:
        write_json(out / "tracker_ids_found.json", collected_ids)
        success(f"Tracker IDs collected: {sum(len(v) for v in collected_ids.values())} across {len(collected_ids)} platforms.")
        for tracker_name, ids in collected_ids.items():
            for tid in ids[:3]:
                info(f"  {tracker_name}: {tid}")

        # Pivot via BuiltWith/SpyOnWeb (free, no API key)
        for tracker_name, ids in collected_ids.items():
            if "Analytics" in tracker_name or "Tag Manager" in tracker_name:
                for tid in ids[:2]:
                    try:
                        r = session.get(f"https://spyonweb.com/{tid}", timeout=10)
                        if r.ok:
                            dom_matches = re.findall(r'([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})', r.text)
                            related = [d for d in dom_matches if "." in d and len(d) > 4
                                       and not d.startswith("spyonweb") and d not in set(scope.domains)]
                            if related:
                                all_findings.append({"method": "tracker_pivot",
                                                     "tracker": tracker_name, "id": tid,
                                                     "related_domains": related[:50]})
                                warn(f"Tracker pivot [{tracker_name} {tid}]: {len(related)} related domains on SpyOnWeb.")
                        time.sleep(2)
                    except Exception:
                        pass
    else:
        info("No tracker IDs found on live hosts.")

    # ── Part B: Copyright / Unique String Shodan Search ──────────────────────
    if scope.shodan_key and SHODAN_AVAILABLE:
        info("Shodan copyright / unique string search")
        # Build candidate strings: org name, domain-derived strings
        search_strings: List[str] = []
        if scope.org_name:
            search_strings.append(scope.org_name)
            # Copyright variant
            year = datetime.datetime.now(datetime.timezone.utc).year
            search_strings.append(f"Copyright {year} {scope.org_name}")
            search_strings.append(f"© {scope.org_name}")
        for domain in scope.domains[:2]:
            # Unique domain-derived strings likely embedded in error pages / footers
            search_strings.append(domain.split(".")[0])

        try:
            api = shodan_lib.Shodan(scope.shodan_key)
            for search_str in search_strings[:5]:
                try:
                    results = shodan_search(api, f'http.html:"{search_str}"')
                    if results is None: continue
                    total   = results.get("total", 0)
                    if total > 0:
                        matches = results.get("matches", [])
                        match_ips = [m.get("ip_str","") for m in matches[:20]]
                        novel_ips = [ip for ip in match_ips if ip and ip not in known_ips]
                        all_findings.append({
                            "method":    "copyright_string_shodan",
                            "query":     f'http.html:"{search_str}"',
                            "total":     total,
                            "sample_ips": match_ips,
                            "novel_ips": novel_ips,
                        })
                        write_json(out / f"shodan_copyright_{re.sub(r'[^\w]','_',search_str)[:40]}.json", results)
                        info(f"Shodan html search [{search_str[:40]}]: {total} hits.")
                        if novel_ips:
                            critical(f"{len(novel_ips)} IPs outside current scope sharing your org's HTML content -- shadow IT!")
                    time.sleep(1)
                except Exception as exc:
                    warn(f"Shodan html search failed for [{search_str}]: {exc}")
        except Exception as exc:
            warn(f"Shodan API unavailable: {exc}")
    else:
        if not scope.shodan_key:
            warn("No Shodan API key -- skipping copyright/unique string search.")

    if all_findings:
        write_json(out / "digital_footprint_findings.json", all_findings)
        novel_ips_all = list(set(ip for f in all_findings for ip in f.get("novel_ips",[])))
        if novel_ips_all:
            save_lines(out / "novel_ips_from_footprint.txt", sorted(set(novel_ips_all)))
            critical(f"Digital footprint analysis: {len(set(novel_ips_all))} novel IPs not in current scope.")
    else:
        success("No novel assets discovered via digital footprint analysis.")
    success("Phase 19 complete.")

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

PHASES: Dict[int, str] = {
    1:  "Seed Data Collection         (WHOIS, ARIN, ipinfo.io, RADB, Wayback)",
    2:  "CT & Passive Recon           (crt.sh, Censys, Shodan SSL/org)",
    3:  "Active DNS Enumeration       (subfinder, amass, assetfinder, waybackurls, AXFR, puredns, dnsx)",
    4:  "IP & ASN Mapping             (CIDR expansion, A records, RADB, Shodan org IPs)",
    5:  "Web Validation & TLS         (httpx, tlsx, robots.txt, sitemap, CORS, server versions)",
    6:  "CNAME Dangling Analysis      (Python dnspython via public resolvers -- P0 takeover detection)",
    7:  "Cloud Asset Enumeration      (cloud_enum, S3 HEAD, Shodan Docker/K8s/ES/Redis)",
    8:  "JS Collection, Endpoint Extraction & Secret Scanning (gau, regex, entropy -- dumps JS to disk)",
    9:  "Certificate Monitoring       (CertStream real-time CT -- LE flagging for takeover detection)",
    10: "Reverse PTR Sweeps           (dnsx -ptr across IP ranges)",
    11: "DNS Permutation              (alterx + puredns second-round brute force)",
    12: "Favicon Hash Pivoting        (httpx -favicon + Shodan http.favicon.hash pivot)",
    13: "DMARC / SPF / DKIM           (email security posture -- FFIEC/NY DFS compliance)",
    14: "Historical DNS               (SecurityTrails -- CDN origin IP bypass, forgotten assets)",
    15: "Email Harvesting             (theHarvester against 15 passive OSINT sources)",
    16: "Paste Site Monitoring        (GitHub code search, LeakIX, Pastebin, Dehashed links)",
    17: "Credential & Leak Monitoring (trufflehog, gitleaks, HIBP, dork file + JS dump filesystem scan)",
    18: "Reverse Whois                (viewdns.info, reversewhois.io, amass intel -whois)",
    19: "Digital Footprint            (tracker ID pivoting + copyright/unique string Shodan search)",
}

PHASE_FUNCTIONS: Dict[int, Any] = {
    1:  phase1_seed,
    2:  phase2_ct_passive,
    3:  phase3_dns,
    4:  phase4_ip,
    5:  phase5_validation,
    6:  phase6_cname,
    7:  phase7_cloud,
    8:  phase17_js_endpoints,
    9:  phase9_certstream,
    10: phase10_ptr,
    11: phase11_permutation,
    12: phase12_favicon,
    13: phase13_email_security,
    14: phase14_historical_dns,
    15: phase15_email_harvest,
    16: phase16_pastes,
    17: phase8_leaks,
    18: phase18_reverse_whois,
    19: phase19_digital_footprint,
}

PASSIVE_PHASES = {6, 10, 11, 12, 13, 14, 15, 16, 18, 19}

NOT_AUTOMATABLE = [
    ("Third-Party Supply Chain",      "Requires vendor lists from target IT. Manual: procurement records, OAuth consent logs."),
    ("M&A Pre-Acquisition",           "Run passive phases only (1,2,4,6,10-19). Do NOT run active phases without CISO auth."),
    ("Dark Web / Flashpoint",         "Enterprise license required. Configure Flashpoint Collections manually post-deal."),
    ("Authenticated Cloud Posture",   "Requires provisioned credentials. Use ScoutSuite/Prowler with IAM read-only creds."),
    ("Port Scanning",                 "Intentionally excluded. masscan + nmap reserved for a separate asm_active.py."),
    ("CVE / Default-Login Testing",   "Intentionally excluded. nuclei cves/ and default-logins/ reserved for asm_active.py."),
]


def show_not_automatable() -> None:
    console.print("\n  [bold red]Not automated:[/bold red]\n")
    for name, reason in NOT_AUTOMATABLE:
        console.print(f"  [bold yellow]{name}[/bold yellow]")
        console.print(f"    {reason}")
    console.print()


def phase_menu() -> List[int]:
    t = Table(show_header=True, header_style="bold magenta")
    t.add_column("#", style="cyan", width=4)
    t.add_column("Phase Description", style="white")
    t.add_column("Mode", style="green", width=10)
    for num, desc in PHASES.items():
        mode = "PASSIVE" if num in PASSIVE_PHASES else "mixed"
        t.add_row(str(num), desc, mode)
    console.print(t)
    console.print(
        "\n  [cyan]all[/]      -- All phases\n"
        "  [cyan]passive[/]  -- Passive-only (1,2,4,6,10-19) -- safe for M&A pre-authorization\n"
        "  [cyan]1,3,7[/]    -- Specific phases (comma-separated)\n"
        "  [cyan]info[/]     -- Show what is not automated\n"
    )
    choice = Prompt.ask("  Select phases").strip().lower()
    if choice == "info":
        show_not_automatable(); return phase_menu()
    if choice == "all":
        return sorted(PHASE_FUNCTIONS.keys())
    if choice == "passive":
        passive = sorted([1,2,4] + list(PASSIVE_PHASES))
        console.print(f"  [green]Passive mode: phases {passive}[/green]")
        return passive
    selected: List[int] = []
    for part in choice.split(","):
        part = part.strip()
        try:
            n = int(part)
            if n in PHASE_FUNCTIONS: selected.append(n)
            else: warn(f"Phase {n} not available (enter 'info' to see non-automated features).")
        except ValueError:
            if part: warn(f"'{part}' is not a valid phase number.")
    return selected


def generate_summary(scope: Scope) -> Path:
    summary: Dict[str, Any] = {
        "generated":  datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "script":     "asm_enterprise.py v2.0",
        "scope":      {"domains": scope.domains, "ip_ranges": scope.ip_ranges,
                       "org_name": scope.org_name, "asn": scope.asn},
        "findings":   {},
    }
    checks = [
        ("axfr_successes",     list(scope.output_dir.glob("phase3_dns/AXFR_SUCCESS_*.txt")),   "list"),
        ("ct_subdomains",      scope.output_dir / "phase2_ct/ct_subdomains.txt",               "count"),
        ("resolved_subdomains",scope.output_dir / "phase3_dns/resolved_subdomains.txt",        "count"),
        ("live_hosts",         scope.output_dir / "phase5_validation/live_hosts.txt",          "count"),
        ("cors_wildcard",      scope.output_dir / "phase5_validation/cors_wildcard.txt",       "count"),
        ("dangling_cnames",    scope.output_dir / "phase6_cname/dangling_cnames.json",         "json"),
        ("s3_public",          scope.output_dir / "phase7_cloud/s3_findings.json",             "json"),
        ("trufflehog_secrets", list(scope.output_dir.glob("phase17_leaks/trufflehog_*.json")), "list"),
        ("cert_alerts",        scope.output_dir / "phase9_certstream/cert_alerts.jsonl",       "count"),
        ("ptr_new_hosts",      scope.output_dir / "phase10_ptr/ptr_new_hosts.txt",             "count"),
        ("permutation_new",    scope.output_dir / "phase11_permutation/permutation_new_hosts.txt","count"),
        ("favicon_novel_ips",  scope.output_dir / "phase12_favicon/favicon_novel_ips.txt",    "count"),
        ("email_issues",       scope.output_dir / "phase13_email_security/email_security_findings.json","json"),
        ("historical_dns",     list(scope.output_dir.glob("phase14_historical_dns/st_full_*.json")),"list"),
        ("harvested_emails",   scope.output_dir / "phase15_email_harvest/harvested_emails.txt","count"),
        ("paste_hits",         scope.output_dir / "phase16_pastes/paste_hits_summary.json",   "json"),
        ("js_secrets",         scope.output_dir / "phase8_js/js_secrets.json",                 "json"),
        ("js_endpoints",       scope.output_dir / "phase8_js/js_endpoints.txt",                "count"),
        ("reverse_whois",      scope.output_dir / "phase18_reverse_whois/reverse_whois_domains.txt","count"),
        ("novel_footprint_ips",scope.output_dir / "phase19_digital_footprint/novel_ips_from_footprint.txt","count"),
    ]
    for key, val, fmt in checks:
        if isinstance(val, list):
            summary["findings"][key] = len(val)
        elif isinstance(val, Path):
            if not val.exists(): summary["findings"][key] = 0; continue
            if fmt == "count":
                summary["findings"][key] = len(read_lines(val))
            elif fmt == "json":
                try:
                    data = json.loads(val.read_text(errors="ignore"))
                    summary["findings"][key] = len(data) if isinstance(data,list) else "present"
                except Exception:
                    summary["findings"][key] = "present"
    path = scope.output_dir / "SUMMARY_REPORT.json"
    write_json(path, summary)
    return path


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    if _args.help:
        console.print(BANNER, style="bold cyan")
        console.print("Usage:")
        console.print("  Interactive:  python3 asm_enterprise.py")
        console.print("  GUI mode:     python3 asm_enterprise.py --config config.json --phases 1,2,3 --non-interactive")
        console.print("\nOptions:")
        console.print("  --config FILE       JSON config file (output of GUI)")
        console.print("  --phases 1,2,3      Comma-separated phase numbers to run")
        console.print("  --non-interactive   Skip all prompts, use config file only")
        console.print("  --no-color          Disable ANSI color (for GUI log capture)")
        console.print("  --debug             Print every tool command as it runs + extra diagnostics")
        sys.exit(0)

    # GUI / non-interactive mode: load config from JSON
    if GUI_MODE and CONFIG_PATH:
        try:
            with open(CONFIG_PATH) as f:
                cfg = json.load(f)
            scope = Scope.from_config(cfg)
        except Exception as exc:
            error(f"Failed to load config from {CONFIG_PATH}: {exc}")
            sys.exit(1)
        info(f"[GUI MODE] Config loaded: {CONFIG_PATH}")
        info(f"[GUI MODE] Domains: {scope.domains}")
        info(f"[GUI MODE] Org: {scope.org_name or '(not set)'}")
        info(f"[GUI MODE] Debug: {DEBUG_MODE}")
        if PHASES_ARG:
            selected = []
            for part in PHASES_ARG.split(","):
                try:
                    n = int(part.strip())
                    if n in PHASE_FUNCTIONS: selected.append(n)
                except ValueError:
                    pass
        else:
            selected = sorted(PHASE_FUNCTIONS.keys())
    else:
        # Interactive mode
        console.print(BANNER, style="bold cyan")
        console.print(
            Panel(
                "[bold red]AUTHORIZED USE ONLY[/bold red]\n\n"
                "All HTTP requests in this script are indistinguishable from browser traffic.\n"
                "DNS queries go through public resolvers. No packets are crafted.\n"
                "No credentials are tested. No CVEs are exploited.\n\n"
                "[bold yellow]Written authorization from an appropriate executive is required\n"
                "before running any reconnaissance against a target.[/bold yellow]",
                title="[bold white]ASM Enterprise v2.0[/bold white]",
                border_style="green",
            )
        )
        if not Confirm.ask("\n  I confirm I have written authorization to assess all defined scope"):
            console.print("  Exiting."); sys.exit(0)
        scope = Scope()
        scope.prompt()
        console.print("\n  [bold cyan]Available Phases:[/bold cyan]\n")
        selected = phase_menu()
        if not selected:
            error("No valid phases selected."); sys.exit(1)

    console.print(f"\n  Phases queued: [cyan]{sorted(selected)}[/cyan]\n")
    start_time = datetime.datetime.now()

    # Emit output dir so GUI can track it
    print(f"ASM_OUTPUT_DIR={scope.output_dir}", flush=True)

    # Open debug log file if --debug active
    global _debug_log
    if DEBUG_MODE:
        debug_path = scope.output_dir / "debug.log"
        try:
            _debug_log = open(debug_path, "w", encoding="utf-8")
            _dlog(f"ASM Enterprise v2.0 debug log")
            _dlog(f"Domains: {scope.domains}")
            _dlog(f"Phases:  {sorted(selected)}")
            _dlog(f"Output:  {scope.output_dir}")
            info(f"[DEBUG] Log file: {debug_path}")
            print(f"ASM_DEBUG_LOG={debug_path}", flush=True)
        except Exception as exc:
            warn(f"Could not open debug log: {exc}")

    for phase_num in sorted(selected):
        fn = PHASE_FUNCTIONS[phase_num]
        try:
            fn(scope)
        except KeyboardInterrupt:
            warn(f"Phase {phase_num} interrupted -- continuing.")
        except Exception as exc:
            error(f"Phase {phase_num} unhandled exception: {exc}")
            import traceback; traceback.print_exc()

    elapsed      = datetime.datetime.now() - start_time
    console.rule("[bold green]Complete[/bold green]")
    summary_path = generate_summary(scope)
    console.print(f"\n  [bold green]Summary:[/bold green]  {summary_path}")
    console.print(f"  [bold green]Outputs:[/bold green]  {scope.output_dir}/")
    console.print(f"  [bold green]Elapsed:[/bold green]  {str(elapsed).split('.')[0]}\n")
    print(f"ASM_COMPLETE={scope.output_dir}", flush=True)
    if _debug_log:
        _dlog(f"Scan complete. Elapsed: {str(elapsed).split('.')[0]}")
        _debug_log.close()


if __name__ == "__main__":
    main()
