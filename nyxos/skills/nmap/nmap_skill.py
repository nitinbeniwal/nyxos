"""
NyxOS Nmap Reconnaissance Skill
Location: nyxos/skills/recon/nmap_skill.py

First concrete skill implementation — demonstrates the pattern.
"""

import re
import subprocess
import shutil
from typing import Dict, Any, List
from loguru import logger

from nyxos.skills.base_skill import BaseSkill, SkillMetadata, SkillResult


class NmapSkill(BaseSkill):
    """
    AI-powered Nmap scanning skill.
    Translates natural language to Nmap commands,
    executes them, and provides AI analysis of results.
    """

    def get_metadata(self) -> SkillMetadata:
        return SkillMetadata(
            name="nmap-recon",
            version="1.0.0",
            description="AI-powered network reconnaissance using Nmap",
            author="NyxOS Team",
            category="recon",
            tags=[
                "scan", "port", "nmap", "network", "recon",
                "reconnaissance", "service", "detection", "host",
                "discovery", "open ports", "service version"
            ],
            min_model_capability="any",
            requires_tools=["nmap"],
            requires_root=True,  # SYN scan needs root
            risk_level="medium",
            estimated_tokens=800,
            license="Apache-2.0"
        )

    def get_system_prompt(self) -> str:
        """Focused system prompt — only Nmap knowledge"""
        return """You are NyxAI's Nmap specialist. You generate precise Nmap commands.

Nmap scan types:
- -sS: SYN scan (stealthy, needs root) — DEFAULT for most scans
- -sT: TCP connect scan (no root needed, more visible)
- -sU: UDP scan (slow but important)
- -sV: Version detection (identify services)
- -sC: Default scripts (safe, informational)
- -A: Aggressive (OS detection + version + scripts + traceroute)
- -Pn: Skip host discovery (use when host blocks ping)

Speed/stealth:
- -T0 to -T5: Timing (0=paranoid, 3=normal, 5=insane)
- --min-rate: Minimum packets per second
- -f: Fragment packets (basic IDS evasion)
- --scan-delay: Delay between probes

Port specification:
- -p-: All 65535 ports
- -p 1-1000: Port range
- --top-ports 100: Most common ports
- -p 80,443,8080: Specific ports

Output:
- -oN: Normal output
- -oX: XML output (best for parsing)
- -oG: Grepable output
- -oA: All formats at once

RULES:
1. Always save output with -oA when possible
2. For initial scans, use --top-ports or common ports first
3. Only do -p- (all ports) when user specifically asks
4. Default to -sS when root, -sT when not root
5. Include -sV for service detection unless speed is priority"""

    def execute(self, user_input: str, context: Dict[str, Any]) -> SkillResult:
        """Execute an Nmap scan based on user input"""
        import time
        start_time = time.time()

        # Check if nmap is available
        if not self.check_tool_available("nmap"):
            return SkillResult(
                success=False,
                output="Nmap is not installed. Install with: sudo apt install nmap",
                error="Tool not found: nmap"
            )

        # Extract target from context
        target = context.get("target", "")
        if not target:
            return SkillResult(
                success=False,
                output="No target specified. Set a target first with 'scope set'",
                error="No target"
            )

        # Determine scan type from user input
        command = self._build_command(user_input, target, context)

        # Execute the scan
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )

            execution_time = time.time() - start_time
            raw_output = result.stdout

            # Parse the output
            parsed = self.parse_output(raw_output)

            # Build findings
            findings = self._extract_findings(parsed)

            return SkillResult(
                success=result.returncode == 0,
                output=raw_output,
                structured_data=parsed,
                commands_executed=[command],
                findings=findings,
                suggestions=self._generate_suggestions(parsed),
                execution_time=execution_time
            )

        except subprocess.TimeoutExpired:
            return SkillResult(
                success=False,
                output="Scan timed out after 10 minutes",
                commands_executed=[command],
                error="Timeout"
            )
        except Exception as e:
            return SkillResult(
                success=False,
                output=str(e),
                commands_executed=[command],
                error=str(e)
            )

    def _build_command(self, user_input: str, target: str, context: Dict) -> str:
        """Build Nmap command from user input"""
        user_lower = user_input.lower()

        # Base command
        base = "nmap"

        # Determine scan type
        if "stealth" in user_lower or "quiet" in user_lower:
            scan_type = "-sS -T2"
        elif "aggressive" in user_lower or "full" in user_lower:
            scan_type = "-A"
        elif "quick" in user_lower or "fast" in user_lower:
            scan_type = "-sS -T4 --top-ports 100"
        elif "udp" in user_lower:
            scan_type = "-sU --top-ports 50"
        elif "version" in user_lower or "service" in user_lower:
            scan_type = "-sS -sV"
        elif "all ports" in user_lower:
            scan_type = "-sS -p-"
        elif "vuln" in user_lower:
            scan_type = "-sV --script=vuln"
        else:
            scan_type = "-sS -sV --top-ports 1000"

        # Output file
        output_dir = os.path.expanduser("~/.nyxos/projects/current/scans")
        os.makedirs(output_dir, exist_ok=True)
        timestamp = int(time.time())
        output = f"-oA {output_dir}/nmap_{timestamp}"

        return f"sudo {base} {scan_type} {output} {target}"

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse Nmap output into structured data"""
        import time
        result = {
            "hosts": [],
            "total_hosts_up": 0,
            "total_ports_found": 0,
            "scan_time": ""
        }

        current_host = None

        for line in raw_output.split("\n"):
            # Host discovery
            host_match = re.match(r"Nmap scan report for (.+?)(?:\s+\((.+?)\))?$", line)
            if host_match:
                if current_host:
                    result["hosts"].append(current_host)
                hostname = host_match.group(1)
                ip = host_match.group(2) or hostname
                current_host = {
                    "hostname": hostname,
                    "ip": ip,
                    "ports": [],
                    "os": ""
                }
                continue

            # Port information
            port_match = re.match(
                r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)",
                line
            )
            if port_match and current_host:
                port_info = {
                    "port": int(port_match.group(1)),
                    "protocol": port_match.group(2),
                    "state": port_match.group(3),
                    "service": port_match.group(4),
                    "version": port_match.group(5).strip()
                }
                current_host["ports"].append(port_info)
                result["total_ports_found"] += 1
                continue

            # OS detection
            os_match = re.match(r"OS details:\s+(.+)", line)
            if os_match and current_host:
                current_host["os"] = os_match.group(1)

        # Don't forget the last host
        if current_host:
            result["hosts"].append(current_host)

        result["total_hosts_up"] = len(result["hosts"])

        return result

    def _extract_findings(self, parsed: Dict) -> List[Dict]:
        """Extract security-relevant findings from parsed data"""
        findings = []

        for host in parsed.get("hosts", []):
            for port in host.get("ports", []):
                if port["state"] != "open":
                    continue

                finding = {
                    "type": "open_port",
                    "host": host["ip"],
                    "port": port["port"],
                    "service": port["service"],
                    "version": port["version"],
                    "severity": self._assess_port_risk(port),
                }

                findings.append(finding)

        return findings

    def _assess_port_risk(self, port: Dict) -> str:
        """Assess risk level of an open port"""
        high_risk_ports = [21, 23, 445, 1433, 3306, 3389, 5900, 6379, 27017]
        medium_risk_ports = [22, 25, 53, 110, 143, 993, 995, 8080, 8443]

        if port["port"] in high_risk_ports:
            return "high"
        elif port["port"] in medium_risk_ports:
            return "medium"
        return "low"

    def _generate_suggestions(self, parsed: Dict) -> List[str]:
        """Generate next-step suggestions based on scan results"""
        suggestions = []

        for host in parsed.get("hosts", []):
            for port in host.get("ports", []):
                if port["state"] != "open":
                    continue

                svc = port["service"].lower()
                p = port["port"]

                if svc in ("http", "https") or p in (80, 443, 8080, 8443):
                    suggestions.append(
                        f"Web server on {host['ip']}:{p} — Run: gobuster/nikto for web enumeration"
                    )
                elif svc == "ssh" or p == 22:
                    suggestions.append(
                        f"SSH on {host['ip']}:{p} — Check version for known CVEs"
                    )
                elif svc == "smb" or p == 445:
                    suggestions.append(
                        f"SMB on {host['ip']}:{p} — Run: enum4linux for share enumeration"
                    )
                elif svc == "ftp" or p == 21:
                    suggestions.append(
                        f"FTP on {host['ip']}:{p} — Check for anonymous login"
                    )
                elif svc in ("mysql", "postgresql", "mssql") or p in (3306, 5432, 1433):
                    suggestions.append(
                        f"Database on {host['ip']}:{p} — Check for default credentials"
                    )

        return suggestions
