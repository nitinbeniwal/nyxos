"""
NyxOS Recon Skill — OSINT and Network Reconnaissance

Wraps: whois, dig, theHarvester, amass, subfinder, shodan, dnsx
Provides structured reconnaissance data gathering with deduplication
across chained tool executions.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger
from rich.console import Console
from rich.table import Table

from nyxos.skills.base_skill import BaseSkill, SkillResult
from nyxos.core.config.settings import get_config
from nyxos.core.security.safety_guard import SafetyGuard, Scope
from nyxos.core.security.audit_logger import AuditLogger
from nyxos.skills.skill_manager import skill_registry

console = Console()

# ---------------------------------------------------------------------------
# Intent keywords for routing natural language to tools
# ---------------------------------------------------------------------------

INTENT_KEYWORDS: Dict[str, List[str]] = {
    "whois": ["whois", "registrar", "registrant", "domain owner", "domain info"],
    "dns": ["dns", "dig", "nameserver", "mx record", "a record", "txt record", "dns record"],
    "email_harvest": ["email", "harvest", "employee", "contact"],
    "subdomain": ["subdomain", "sub domain", "sub-domain", "enumerate subdomains"],
    "shodan": ["shodan", "internet search", "exposed service"],
    "asn": ["asn", "autonomous system", "bgp", "ip range"],
    "full_recon": ["full recon", "full osint", "complete recon", "all recon", "full reconnaissance"],
}




def _match_intent(text: str) -> str:
    """Return the best matching intent key for *text*, defaulting to 'whois'."""
    text_lower = text.lower()
    # Full recon takes priority
    for kw in INTENT_KEYWORDS["full_recon"]:
        if kw in text_lower:
            return "full_recon"
    best: Optional[str] = None
    best_score = 0
    for intent, keywords in INTENT_KEYWORDS.items():
        if intent == "full_recon":
            continue
        score = sum(1 for kw in keywords if kw in text_lower)
        if score > best_score:
            best_score = score
            best = intent
    return best if best else "whois"


def _run(cmd: List[str], timeout: int = 120) -> Tuple[str, str, int]:
    """Run a subprocess and return (stdout, stderr, returncode)."""
    logger.debug("Running: {}", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out after {}s: {}", timeout, " ".join(cmd))
        return "", f"Timed out after {timeout}s", 1
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]}", 127


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


# ---------------------------------------------------------------------------
# ReconSkill
# ---------------------------------------------------------------------------

@skill_registry
class ReconSkill(BaseSkill):


    """OSINT and network reconnaissance skill for NyxOS.

    Wraps whois, dig, theHarvester, amass, subfinder, shodan CLI, and dnsx
    to perform structured reconnaissance with deduplication.
    """

    name: str = "recon"
    description: str = "OSINT and network reconnaissance (whois, DNS, subdomains, emails, Shodan)"
    requires_tools: List[str] = ["whois", "dig"]  # minimum required

    def __init__(self) -> None:
        self.safety = SafetyGuard()
        self.audit = AuditLogger()
        self._findings: List[Dict[str, Any]] = []
        self._commands_run: List[str] = []

    # ------------------------------------------------------------------
    # BaseSkill interface
    # ------------------------------------------------------------------

    def get_commands(self, intent: str) -> List[str]:
        """Return example CLI commands for a given intent string."""
        mapping = {
            "whois": ["whois {target}"],
            "dns": ["dig {target} ANY +noall +answer"],
            "email_harvest": ["theHarvester -d {target} -b google,bing -l 100"],
            "subdomain": ["subfinder -d {target} -silent", "amass enum -passive -d {target}"],
            "shodan": ["shodan host {target}"],
            "asn": ["whois -h whois.radb.net -- '-i origin {target}'"],
            "full_recon": [
                "whois {target}",
                "dig {target} ANY +noall +answer",
                "theHarvester -d {target} -b google,bing -l 100",
                "subfinder -d {target} -silent",
            ],
        }
        matched = _match_intent(intent)
        return mapping.get(matched, mapping["whois"])

    def execute(self, params: dict) -> SkillResult:
        """Execute a recon task described by *params*.

        Expected params:
            target (str): domain or IP to investigate
            intent (str): natural-language or keyword intent
            timeout (int, optional): per-tool timeout in seconds
        """
        target: str = params.get("target", "").strip()
        intent_raw: str = params.get("intent", "whois")
        timeout: int = int(params.get("timeout", 120))

        if not target:
            return SkillResult(
                success=False,
                output="No target specified.",
                parsed_data={},
                findings=[],
                commands_run=[],
                duration_seconds=0.0,
            )

        # Safety check
        safe, reason, risk = self.safety.check_command(f"recon {target}", Scope(targets=[target]))
        if not safe:
            return SkillResult(
                success=False,
                output=f"Blocked by SafetyGuard: {reason}",
                parsed_data={},
                findings=[],
                commands_run=[],
                duration_seconds=0.0,
            )

        self._findings = []
        self._commands_run = []
        start = time.time()

        intent = _match_intent(intent_raw)
        raw_outputs: List[str] = []

        dispatch = {
            "whois": [self._whois],
            "dns": [self._dns],
            "email_harvest": [self._email_harvest],
            "subdomain": [self._subdomains],
            "shodan": [self._shodan],
            "asn": [self._asn],
            "full_recon": [self._whois, self._dns, self._email_harvest, self._subdomains],
        }

        for fn in dispatch.get(intent, [self._whois]):
            out = fn(target, timeout)
            raw_outputs.append(out)

        # Deduplicate findings
        deduped = self._deduplicate(self._findings)

        elapsed = time.time() - start
        combined_output = "\n\n".join(raw_outputs)

        self.audit.log("SKILL_USE", f"recon:{intent}", user="current", details={
            "target": target,
            "findings_count": len(deduped),
        })

        return SkillResult(
            success=True,
            output=combined_output,
            parsed_data={"target": target, "intent": intent},
            findings=deduped,
            commands_run=self._commands_run,
            duration_seconds=round(elapsed, 2),
        )

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """Generic parse — most parsing is done per-tool."""
        return {"raw": raw_output}

    # ------------------------------------------------------------------
    # Individual tool runners
    # ------------------------------------------------------------------

    def _whois(self, target: str, timeout: int = 120) -> str:
        if not _tool_available("whois"):
            logger.warning("whois not installed")
            return "[!] whois not installed"

        cmd = ["whois", target]
        self._commands_run.append(" ".join(cmd))
        stdout, stderr, rc = _run(cmd, timeout)

        if rc != 0:
            return f"[!] whois failed: {stderr}"

        # Parse interesting fields
        for line in stdout.splitlines():
            line_s = line.strip()
            lower = line_s.lower()
            if any(k in lower for k in ("registrant", "admin email", "tech email", "abuse")):
                email_match = re.search(r'[\w.+-]+@[\w-]+\.[\w.]+', line_s)
                if email_match:
                    self._findings.append({
                        "type": "email",
                        "severity": "info",
                        "value": email_match.group(),
                        "source": "whois",
                        "title": "Email found in WHOIS",
                        "description": f"Contact email discovered in WHOIS record: {line_s}",
                    })
            if lower.startswith("registrar:"):
                self._findings.append({
                    "type": "domain",
                    "severity": "info",
                    "value": line_s.split(":", 1)[-1].strip(),
                    "source": "whois",
                    "title": "Registrar identified",
                    "description": line_s,
                })
            if lower.startswith("name server:") or lower.startswith("nserver:"):
                ns = line_s.split(":", 1)[-1].strip().lower()
                self._findings.append({
                    "type": "domain",
                    "severity": "info",
                    "value": ns,
                    "source": "whois",
                    "title": "Name server found",
                    "description": f"Nameserver: {ns}",
                })

        # Always add a raw WHOIS summary finding
        self._findings.append({
            "type": "domain",
            "severity": "info",
            "value": target,
            "source": "whois",
            "title": f"WHOIS lookup for {target}",
            "description": f"WHOIS query completed — {len(stdout.splitlines())} lines returned",
        })

        return stdout

    def _dns(self, target: str, timeout: int = 120) -> str:
        if not _tool_available("dig"):
            logger.warning("dig not installed")
            return "[!] dig not installed"

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        all_output: List[str] = []

        for rtype in record_types:
            cmd = ["dig", target, rtype, "+noall", "+answer", "+short"]
            self._commands_run.append(" ".join(cmd))
            stdout, stderr, rc = _run(cmd, timeout)
            if stdout.strip():
                all_output.append(f"--- {rtype} ---\n{stdout}")
                for line in stdout.strip().splitlines():
                    value = line.strip().rstrip(".")
                    if not value:
                        continue
                    ftype = "ip_address" if rtype in ("A", "AAAA") else "domain"
                    self._findings.append({
                        "type": ftype,
                        "severity": "info",
                        "value": value,
                        "source": "dig",
                        "title": f"{rtype} record: {value}",
                        "description": f"DNS {rtype} record for {target}: {value}",
                    })

        return "\n".join(all_output) if all_output else "[*] No DNS records returned"

    def _email_harvest(self, target: str, timeout: int = 300) -> str:
        if not _tool_available("theHarvester"):
            logger.warning("theHarvester not installed")
            return "[!] theHarvester not installed — skipping email harvest"

        cmd = ["theHarvester", "-d", target, "-b", "google,bing,crtsh", "-l", "100"]
        self._commands_run.append(" ".join(cmd))
        stdout, stderr, rc = _run(cmd, timeout)

        if rc != 0 and not stdout:
            return f"[!] theHarvester failed: {stderr}"

        # Parse emails
        emails = set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', stdout))
        for email in emails:
            self._findings.append({
                "type": "email",
                "severity": "info",
                "value": email,
                "source": "theHarvester",
                "title": "Email found",
                "description": f"Employee email discovered: {email}",
            })

        # Parse hosts/subdomains from theHarvester output
        host_section = False
        for line in stdout.splitlines():
            if "hosts found" in line.lower():
                host_section = True
                continue
            if host_section and line.strip():
                parts = line.strip().split(":")
                host = parts[0].strip()
                if "." in host:
                    self._findings.append({
                        "type": "domain",
                        "severity": "info",
                        "value": host,
                        "source": "theHarvester",
                        "title": "Host discovered",
                        "description": f"Host found via theHarvester: {host}",
                    })

        return stdout

    def _subdomains(self, target: str, timeout: int = 300) -> str:
        outputs: List[str] = []

        # Try subfinder first (faster)
        if _tool_available("subfinder"):
            cmd = ["subfinder", "-d", target, "-silent"]
            self._commands_run.append(" ".join(cmd))
            stdout, stderr, rc = _run(cmd, timeout)
            if stdout.strip():
                outputs.append(f"--- subfinder ---\n{stdout}")
                for line in stdout.strip().splitlines():
                    sub = line.strip()
                    if sub and "." in sub:
                        self._findings.append({
                            "type": "domain",
                            "severity": "info",
                            "value": sub,
                            "source": "subfinder",
                            "title": "Subdomain discovered",
                            "description": f"Subdomain found: {sub}",
                        })

        # Try amass passive
        if _tool_available("amass"):
            cmd = ["amass", "enum", "-passive", "-d", target, "-timeout", "3"]
            self._commands_run.append(" ".join(cmd))
            stdout, stderr, rc = _run(cmd, timeout)
            if stdout.strip():
                outputs.append(f"--- amass ---\n{stdout}")
                for line in stdout.strip().splitlines():
                    sub = line.strip()
                    if sub and "." in sub:
                        self._findings.append({
                            "type": "domain",
                            "severity": "info",
                            "value": sub,
                            "source": "amass",
                            "title": "Subdomain discovered",
                            "description": f"Subdomain found: {sub}",
                        })

        if not outputs:
            return "[!] Neither subfinder nor amass installed — skipping subdomain enumeration"

        # Validate with dnsx if available
        if _tool_available("dnsx") and self._findings:
            subs = [f["value"] for f in self._findings if f["source"] in ("subfinder", "amass")]
            if subs:
                logger.info("Validating {} subdomains with dnsx", len(subs))
                # dnsx reads from stdin
                try:
                    proc = subprocess.run(
                        ["dnsx", "-silent"],
                        input="\n".join(subs),
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                    )
                    valid = set(proc.stdout.strip().splitlines())
                    if valid:
                        outputs.append(f"--- dnsx validated: {len(valid)} live ---")
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass

        return "\n".join(outputs)

    def _shodan(self, target: str, timeout: int = 60) -> str:
        if not _tool_available("shodan"):
            logger.warning("shodan CLI not installed")
            return "[!] shodan CLI not installed — run: pip install shodan && shodan init <API_KEY>"

        # Determine if target is IP or domain
        ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
        if ip_pattern.match(target):
            cmd = ["shodan", "host", target]
        else:
            cmd = ["shodan", "search", f"hostname:{target}", "--limit", "20"]

        self._commands_run.append(" ".join(cmd))
        stdout, stderr, rc = _run(cmd, timeout)

        if rc != 0:
            return f"[!] Shodan query failed: {stderr}"

        # Parse open ports from shodan host output
        for line in stdout.splitlines():
            port_match = re.match(r'^\s*(\d+)/(\w+)\s+(.*)', line)
            if port_match:
                port, proto, service = port_match.groups()
                self._findings.append({
                    "type": "technology",
                    "severity": "info",
                    "value": f"{target}:{port}/{proto} — {service.strip()}",
                    "source": "shodan",
                    "title": f"Open port {port}/{proto}",
                    "description": f"Shodan reports {port}/{proto} open: {service.strip()}",
                })

        return stdout

    def _asn(self, target: str, timeout: int = 60) -> str:
        if not _tool_available("whois"):
            return "[!] whois not installed"

        cmd = ["whois", "-h", "whois.radb.net", f"-- -i origin {target}"]
        self._commands_run.append(" ".join(cmd))
        stdout, stderr, rc = _run(cmd, timeout)

        if not stdout.strip():
            # Fallback: regular whois and look for ASN
            cmd2 = ["whois", target]
            self._commands_run.append(" ".join(cmd2))
            stdout, stderr, rc = _run(cmd2, timeout)

        asn_matches = re.findall(r'AS\d+', stdout)
        for asn in set(asn_matches):
            self._findings.append({
                "type": "ip_address",
                "severity": "info",
                "value": asn,
                "source": "whois",
                "title": f"ASN identified: {asn}",
                "description": f"Autonomous System Number {asn} associated with {target}",
            })

        return stdout

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings based on (type, value) pairs."""
        seen: set = set()
        deduped: List[Dict[str, Any]] = []
        for f in findings:
            key = (f.get("type", ""), f.get("value", "").lower())
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    def display_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Print a rich table of findings to the console."""
        if not findings:
            console.print("[yellow]No findings to display.[/yellow]")
            return

        table = Table(title="Recon Findings", show_lines=True)
        table.add_column("Type", style="cyan", width=14)
        table.add_column("Value", style="green")
        table.add_column("Source", style="magenta", width=16)
        table.add_column("Title", style="white")

        for f in findings:
            table.add_row(
                f.get("type", ""),
                f.get("value", ""),
                f.get("source", ""),
                f.get("title", ""),
            )

        console.print(table)
