"""
NyxOS Web Security Skill
Location: nyxos/skills/web/web_skill.py

Wraps common web security tools (gobuster, nikto, whatweb, curl, wfuzz,
sqlmap, ffuf) into a unified skill interface with structured findings.
"""

import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from loguru import logger

from nyxos.skills.base_skill import BaseSkill, SkillMetadata, SkillResult


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
SMALL_WORDLIST = "/usr/share/wordlists/dirb/small.txt"
DNS_WORDLIST = "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt"
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 300
SQLMAP_TIMEOUT = 600

INTENT_TOOL_MAP: Dict[str, str] = {
    "directory": "gobuster",
    "dir": "gobuster",
    "dirbust": "gobuster",
    "enumerate directories": "gobuster",
    "directory enumeration": "gobuster",
    "fingerprint": "whatweb",
    "identify": "whatweb",
    "technology": "whatweb",
    "web fingerprint": "whatweb",
    "web fingerprinting": "whatweb",
    "vulnerability": "nikto",
    "vuln": "nikto",
    "nikto": "nikto",
    "vulnerability scan": "nikto",
    "sqli": "sqlmap",
    "sql injection": "sqlmap",
    "sql injection test": "sqlmap",
    "sqlmap": "sqlmap",
    "subdomain": "gobuster_dns",
    "subdomains": "gobuster_dns",
    "subdomain enumeration": "gobuster_dns",
    "header": "curl",
    "headers": "curl",
    "header analysis": "curl",
    "fuzz": "ffuf",
    "fuzzing": "ffuf",
    "ffuf": "ffuf",
    "wfuzz": "wfuzz",
}


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------

def _run_tool(
    cmd: List[str],
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[int, str, str]:
    """Run an external tool. Returns (returncode, stdout, stderr).
    Negative codes: -1=timeout, -2=not found, -3=OS error.
    """
    logger.debug("Executing: {}", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        logger.warning("Timed out after {}s: {}", timeout, " ".join(cmd))
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        logger.error("Tool not found: {}", cmd[0])
        return -2, "", f"Tool '{cmd[0]}' is not installed"
    except OSError as exc:
        logger.error("OS error running {}: {}", cmd[0], exc)
        return -3, "", str(exc)


# ---------------------------------------------------------------------------
# WebSkill
# ---------------------------------------------------------------------------

class WebSkill(BaseSkill):
    """Web application security scanning skill.

    Wraps gobuster, nikto, whatweb, curl, wfuzz, sqlmap, and ffuf.
    """

    def __init__(self) -> None:
        self._tools: Dict[str, bool] = {}
        self._check_tools()
        super().__init__()

    def _check_tools(self) -> None:
        """Check which tools are installed."""
        for tool in ["gobuster", "nikto", "whatweb", "curl", "wfuzz", "sqlmap", "ffuf"]:
            self._tools[tool] = shutil.which(tool) is not None
        missing = [t for t, ok in self._tools.items() if not ok]
        if missing:
            logger.warning("WebSkill: missing tools — {}", ", ".join(missing))

    def _ensure_tool(self, tool: str) -> Optional[str]:
        """Return error message if tool missing, else None."""
        if not self._tools.get(tool, False):
            return f"Tool '{tool}' is not installed. Install with: sudo apt install {tool}"
        return None

    # ------------------------------------------------------------------
    # Abstract method implementations
    # ------------------------------------------------------------------

    def get_metadata(self) -> SkillMetadata:
        """Return skill metadata."""
        return SkillMetadata(
            name="web-scan",
            version="1.0.0",
            description="AI-powered web application security scanning",
            author="NyxOS Team",
            category="web",
            tags=[
                "web", "directory", "enumeration", "nikto", "gobuster",
                "fingerprint", "whatweb", "sqli", "sqlmap", "headers",
                "fuzzing", "ffuf", "wfuzz", "vulnerability", "subdomain",
            ],
            min_model_capability="any",
            requires_tools=["gobuster", "nikto", "whatweb", "curl", "sqlmap", "ffuf"],
            requires_root=False,
            risk_level="medium",
            estimated_tokens=800,
            license="Apache-2.0",
        )

    def get_system_prompt(self) -> str:
        """Focused system prompt — only web scanning knowledge."""
        return """You are NyxAI's web application security specialist. You generate precise web scanning commands.

Tools available:
- gobuster dir: Directory/file enumeration (fast, Go-based)
- gobuster dns: Subdomain enumeration
- nikto: Web vulnerability scanner (comprehensive, slow)
- whatweb: Web technology fingerprinting
- curl -sI: HTTP header analysis
- sqlmap: SQL injection testing (DANGEROUS — needs confirmation)
- ffuf: Fast web fuzzer (modern, JSON output)
- wfuzz: Web fuzzer (classic, flexible)

Common patterns:
- Directory scan: gobuster dir -u <URL> -w <WORDLIST> -t 10
- Subdomain scan: gobuster dns -d <DOMAIN> -w <WORDLIST> -t 10
- Vuln scan: nikto -h <URL>
- Fingerprint: whatweb -v <URL>
- Headers: curl -sI -L <URL>
- SQLi test: sqlmap -u <URL> --batch --level=3 --risk=2
- Fuzz: ffuf -u <URL>/FUZZ -w <WORDLIST> -t 10

RULES:
1. Always validate target URL before scanning
2. sqlmap requires explicit HIGH risk confirmation
3. Use default wordlist: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
4. Parse all output into structured findings with severity ratings
5. Check security headers on every web target
6. Never scan targets outside the defined scope"""

    def execute(self, user_input: str, context: Dict[str, Any]) -> SkillResult:
        """Execute a web security scan based on user input."""
        start = time.time()

        # Extract target from context
        target = context.get("target", "")
        if not target:
            return SkillResult(
                success=False,
                output="No target specified. Set a target first.",
                error="No target",
            )

        # Normalise URL
        url = target if "://" in target else f"http://{target}"

        # Resolve intent
        tool_key = self._resolve_intent(user_input)
        logger.info("WebSkill: input='{}' → tool='{}'", user_input, tool_key)

        # Dispatch
        dispatch = {
            "gobuster": self._run_gobuster_dir,
            "gobuster_dns": self._run_gobuster_dns,
            "whatweb": self._run_whatweb,
            "nikto": self._run_nikto,
            "sqlmap": self._run_sqlmap,
            "curl": self._run_curl_headers,
            "ffuf": self._run_ffuf,
            "wfuzz": self._run_wfuzz,
        }

        handler = dispatch.get(tool_key)
        if handler is None:
            return SkillResult(
                success=False,
                output=f"Unknown web intent. Supported: {', '.join(dispatch.keys())}",
                error=f"Unknown intent: {user_input}",
            )

        try:
            result = handler(url, context)
        except Exception as exc:
            logger.exception("WebSkill handler '{}' raised: {}", tool_key, exc)
            return SkillResult(
                success=False,
                output=f"Error in {tool_key}: {exc}",
                error=str(exc),
            )

        result.execution_time = round(time.time() - start, 2)
        return result

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """Generic output parser."""
        return {
            "urls": list(set(re.findall(r"https?://\S+", raw_output))),
            "status_codes": list(set(
                re.findall(r"(?:Status|HTTP/\d\.\d)\s*[:=]?\s*(\d{3})", raw_output)
            )),
            "line_count": len(raw_output.splitlines()),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_intent(user_input: str) -> str:
        """Map user input to a tool key."""
        lower = user_input.lower().strip()
        # Direct match
        if lower in INTENT_TOOL_MAP:
            return INTENT_TOOL_MAP[lower]
        # Keyword search
        for keyword, tool in INTENT_TOOL_MAP.items():
            if keyword in lower:
                return tool
        # Default to gobuster dir
        return "gobuster"

    @staticmethod
    def _wordlist(context: dict, kind: str = "dir") -> str:
        """Resolve wordlist path."""
        wl = context.get("wordlist", "")
        if wl and Path(wl).is_file():
            return wl
        candidates = (
            [DNS_WORDLIST, SMALL_WORDLIST] if kind == "dns"
            else [DEFAULT_WORDLIST, SMALL_WORDLIST]
        )
        for c in candidates:
            if Path(c).is_file():
                return c
        return DEFAULT_WORDLIST

    @staticmethod
    def _threads(context: dict) -> int:
        return int(context.get("threads", DEFAULT_THREADS))

    @staticmethod
    def _extract_domain(url: str) -> str:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return parsed.hostname or url

    @staticmethod
    def _dir_severity(path: str, status: int) -> str:
        sensitive = [
            "/admin", "/administrator", "/phpmyadmin", "/wp-admin",
            "/cpanel", "/manager", "/console", "/.env", "/.git",
            "/backup", "/config", "/debug", "/server-status",
        ]
        path_lower = path.lower()
        for s in sensitive:
            if path_lower.startswith(s):
                return "high" if status == 200 else "medium"
        if status == 200:
            return "low"
        return "info"

    @staticmethod
    def _dir_recommendation(path: str, status: int) -> str:
        path_lower = path.lower()
        if any(p in path_lower for p in ["/admin", "/administrator", "/manager", "/console"]):
            return "Restrict access to administrative interfaces. Use IP allowlisting or VPN."
        if any(p in path_lower for p in ["/.env", "/.git", "/config", "/wp-config"]):
            return "Remove sensitive files from the web root or block access via server config."
        if "/backup" in path_lower:
            return "Remove backup files from the web root."
        return "Review whether this resource should be publicly accessible."

    def _fail(self, message: str) -> SkillResult:
        logger.error("WebSkill: {}", message)
        return SkillResult(success=False, output=message, error=message)

    # ==================================================================
    # TOOL RUNNERS — each returns SkillResult
    # ==================================================================

    def _run_gobuster_dir(self, url: str, context: dict) -> SkillResult:
        """Directory enumeration with gobuster."""
        err = self._ensure_tool("gobuster")
        if err:
            return self._fail(err)

        wordlist = self._wordlist(context, "dir")
        threads = self._threads(context)
        extensions = context.get("extensions", "")

        cmd = [
            "gobuster", "dir", "-u", url, "-w", wordlist,
            "-t", str(threads), "-q", "--no-error", "-z",
        ]
        if extensions:
            cmd.extend(["-x", extensions])

        rc, stdout, stderr = _run_tool(cmd)
        if rc < 0:
            return self._fail(stderr)

        findings = self._parse_gobuster_dir(stdout, url)
        return SkillResult(
            success=True,
            output=stdout,
            structured_data={"tool": "gobuster", "mode": "dir", "url": url, "entries": len(findings)},
            commands_executed=[" ".join(cmd)],
            findings=findings,
            suggestions=self._gobuster_suggestions(findings),
        )

    def _parse_gobuster_dir(self, raw: str, base_url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        pattern = re.compile(r"(/\S*)\s+\(Status:\s*(\d+)\)\s*(?:$$Size:\s*(\d+)$$)?")
        for line in raw.splitlines():
            m = pattern.search(line)
            if not m:
                continue
            path, status, size = m.group(1), int(m.group(2)), m.group(3)
            findings.append({
                "type": "directory_found",
                "url": f"{base_url.rstrip('/')}{path}",
                "severity": self._dir_severity(path, status),
                "title": f"Directory/file found: {path}",
                "description": f"{path} returned HTTP {status}" + (f" ({size} bytes)" if size else ""),
                "evidence": line.strip(),
                "recommendation": self._dir_recommendation(path, status),
            })
        return findings

    @staticmethod
    def _gobuster_suggestions(findings: list) -> List[str]:
        suggestions = []
        for f in findings:
            if f.get("severity") in ("high", "critical"):
                suggestions.append(f"Investigate {f['url']} — severity: {f['severity']}")
        if not suggestions:
            suggestions.append("Consider scanning with different wordlists or file extensions.")
        return suggestions

    # --- gobuster dns ---

    def _run_gobuster_dns(self, url: str, context: dict) -> SkillResult:
        """Subdomain enumeration with gobuster dns."""
        err = self._ensure_tool("gobuster")
        if err:
            return self._fail(err)

        domain = self._extract_domain(url)
        wordlist = self._wordlist(context, "dns")
        threads = self._threads(context)

        cmd = ["gobuster", "dns", "-d", domain, "-w", wordlist, "-t", str(threads), "-q"]

        rc, stdout, stderr = _run_tool(cmd)
        if rc < 0:
            return self._fail(stderr)

        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            match = re.match(r"(?:Found:\s*)?(\S+\.\S+)", line)
            if match:
                subdomain = match.group(1)
                findings.append({
                    "type": "directory_found",
                    "url": subdomain,
                    "severity": "info",
                    "title": f"Subdomain: {subdomain}",
                    "description": f"Subdomain {subdomain} resolved successfully.",
                    "evidence": line,
                    "recommendation": "Investigate for exposed services.",
                })

        return SkillResult(
            success=True, output=stdout,
            structured_data={"tool": "gobuster", "mode": "dns", "domain": domain, "subdomains": len(findings)},
            commands_executed=[" ".join(cmd)], findings=findings,
            suggestions=[f"Found {len(findings)} subdomains. Run port scans on each."] if findings else [],
        )

    # --- whatweb ---

    def _run_whatweb(self, url: str, context: dict) -> SkillResult:
        """Web fingerprinting with whatweb."""
        err = self._ensure_tool("whatweb")
        if err:
            return self._fail(err)

        cmd = ["whatweb", "--color=never", "-v", "--log-json=-", url]
        rc, stdout, stderr = _run_tool(cmd)
        if rc < -1:
            return self._fail(stderr)

        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    if not isinstance(item, dict) or "plugins" not in item:
                        continue
                    for plugin_name, details in item["plugins"].items():
                        ver = ""
                        if isinstance(details, dict):
                            vl = details.get("version", [])
                            if vl:
                                ver = ", ".join(str(v) for v in vl)
                        findings.append({
                            "type": "technology",
                            "url": url,
                            "severity": "info",
                            "title": f"Technology: {plugin_name}",
                            "description": f"{plugin_name}" + (f" v{ver}" if ver else ""),
                            "evidence": json.dumps(details) if isinstance(details, dict) else str(details),
                            "recommendation": "Ensure technology is up to date.",
                        })
                continue
            except (json.JSONDecodeError, TypeError):
                pass
            # Fallback text parse
            techs = re.findall(r"(\w[\w\s.-]+?)(?:$$([\d.]+)$$)?(?:,|$)", line)
            for name, ver in techs:
                name = name.strip()
                if len(name) < 2 or name.startswith("http"):
                    continue
                findings.append({
                    "type": "technology", "url": url, "severity": "info",
                    "title": f"Technology: {name}",
                    "description": f"{name}" + (f" v{ver}" if ver else ""),
                    "evidence": line[:300],
                    "recommendation": "Ensure technology is up to date.",
                })

        return SkillResult(
            success=True, output=stdout,
            structured_data={"tool": "whatweb", "url": url},
            commands_executed=[" ".join(cmd)], findings=findings,
            suggestions=["Run nikto for deeper vulnerability scanning."] if findings else [],
        )

    # --- nikto ---

    def _run_nikto(self, url: str, context: dict) -> SkillResult:
        """Vulnerability scanning with nikto."""
        err = self._ensure_tool("nikto")
        if err:
            return self._fail(err)

        cmd = ["nikto", "-h", url, "-Format", "json", "-output", "-"]
        rc, stdout, stderr = _run_tool(cmd, timeout=600)
        combined = stdout + "\n" + stderr
        if rc < -1:
            return self._fail(stderr)

        findings = []
        # Try JSON parse
        try:
            data = json.loads(combined)
            vulns = []
            if isinstance(data, dict):
                vulns = data.get("vulnerabilities", [])
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        vulns.extend(item.get("vulnerabilities", []))
            for v in vulns:
                findings.append({
                    "type": "vulnerability", "url": v.get("url", url), "severity": "medium",
                    "title": v.get("msg", "Nikto finding"), "description": v.get("msg", ""),
                    "evidence": f"OSVDB-{v['osvdb']}" if "osvdb" in v else "",
                    "recommendation": "Review and remediate.",
                })
        except (json.JSONDecodeError, TypeError):
            pass

        # Fallback text parse
        if not findings:
            osvdb_re = re.compile(r"\+\s+(?:OSVDB-(\d+):\s*)?(/\S*)?:\s*(.*)")
            for line in combined.splitlines():
                m = osvdb_re.match(line.strip())
                if not m:
                    continue
                osvdb_id, path, msg = m.group(1), m.group(2), m.group(3)
                sev = "medium"
                ml = msg.lower()
                if any(w in ml for w in ["remote code", "injection", "rce", "backdoor"]):
                    sev = "critical"
                elif any(w in ml for w in ["xss", "cross-site", "sql", "redirect"]):
                    sev = "high"
                elif any(w in ml for w in ["directory index", "listing"]):
                    sev = "low"
                findings.append({
                    "type": "vulnerability",
                    "url": f"{url.rstrip('/')}{path}" if path else url,
                    "severity": sev, "title": msg[:120] if msg else "Nikto finding",
                    "description": msg,
                    "evidence": f"OSVDB-{osvdb_id}" if osvdb_id else line.strip()[:200],
                    "recommendation": "Review and remediate.",
                })

        return SkillResult(
            success=True, output=combined,
            structured_data={"tool": "nikto", "url": url, "vulns": len(findings)},
            commands_executed=[" ".join(cmd)], findings=findings,
            suggestions=["Run sqlmap on forms found." if findings else "Target appears clean."],
        )

    # --- sqlmap ---

    def _run_sqlmap(self, url: str, context: dict) -> SkillResult:
        """SQL injection testing. Requires high_risk_confirmed."""
        if not context.get("high_risk_confirmed", False):
            return SkillResult(
                success=False,
                output="SQL injection testing requires explicit HIGH risk confirmation. "
                       "Set context['high_risk_confirmed'] = True.",
                error="High risk not confirmed",
            )

        err = self._ensure_tool("sqlmap")
        if err:
            return self._fail(err)

        level = str(context.get("level", 3))
        risk = str(context.get("risk", 2))
        cmd = [
            "sqlmap", "-u", url, "--batch",
            f"--level={level}", f"--risk={risk}",
            "--output-dir=/tmp/nyxos_sqlmap", "--flush-session",
        ]

        rc, stdout, stderr = _run_tool(cmd, timeout=SQLMAP_TIMEOUT)
        combined = stdout + "\n" + stderr
        if rc < -1:
            return self._fail(stderr)

        findings = []
        injectable_re = re.compile(r"(?:GET|POST)\s+parameter\s+'(\w+)'\s+.*injectable", re.IGNORECASE)
        for line in combined.splitlines():
            m = injectable_re.search(line)
            if m:
                param = m.group(1)
                findings.append({
                    "type": "vulnerability", "url": url, "severity": "critical",
                    "title": f"SQL Injection in '{param}'",
                    "description": f"Parameter '{param}' is injectable. {line.strip()}",
                    "evidence": line.strip()[:300],
                    "recommendation": "Use parameterized queries. Never concatenate user input into SQL.",
                })

        dbms = re.search(r"back-end DBMS:\s*(.+)", combined)
        if dbms:
            findings.append({
                "type": "technology", "url": url, "severity": "info",
                "title": f"Database: {dbms.group(1).strip()}",
                "description": f"DBMS identified: {dbms.group(1).strip()}",
                "evidence": dbms.group(0).strip(),
                "recommendation": "Ensure database is hardened and patched.",
            })

        if not findings and "is vulnerable" in combined.lower():
            findings.append({
                "type": "vulnerability", "url": url, "severity": "critical",
                "title": "SQL Injection detected",
                "description": "sqlmap confirmed vulnerability.",
                "evidence": "See raw output.", "recommendation": "Use parameterized queries.",
            })

        return SkillResult(
            success=True, output=combined,
            structured_data={"tool": "sqlmap", "url": url, "injectable": len(findings)},
            commands_executed=[" ".join(cmd)], findings=findings,
        )

    # --- curl headers ---

    def _run_curl_headers(self, url: str, context: dict) -> SkillResult:
        """HTTP header analysis."""
        err = self._ensure_tool("curl")
        if err:
            return self._fail(err)

        cmd = ["curl", "-sI", "-L", "--max-time", "30", url]
        rc, stdout, stderr = _run_tool(cmd, timeout=35)
        if rc < 0:
            return self._fail(stderr)

        # Parse headers
        headers: Dict[str, str] = {}
        for line in stdout.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        findings = self._analyse_headers(stdout, headers, url)

        return SkillResult(
            success=True, output=stdout,
            structured_data={"tool": "curl", "url": url, "headers": headers},
            commands_executed=[" ".join(cmd)], findings=findings,
            suggestions=["Run nikto for deeper vulnerability scanning."],
        )

    @staticmethod
    def _analyse_headers(raw: str, headers: dict, url: str) -> List[Dict[str, Any]]:
        """Check for missing security headers and info leakage."""
        findings = []

        security_headers = {
            "strict-transport-security": ("Missing HSTS", "medium",
                "HSTS not set. Browsers may allow HTTP.", "Add Strict-Transport-Security header."),
            "x-content-type-options": ("Missing X-Content-Type-Options", "low",
                "MIME sniffing possible.", "Add X-Content-Type-Options: nosniff."),
            "x-frame-options": ("Missing X-Frame-Options", "medium",
                "Clickjacking possible.", "Add X-Frame-Options: DENY or SAMEORIGIN."),
            "content-security-policy": ("Missing CSP", "medium",
                "No Content-Security-Policy. XSS risk increased.", "Implement CSP header."),
            "x-xss-protection": ("Missing X-XSS-Protection", "low",
                "X-XSS-Protection not set.", "Add X-XSS-Protection: 1; mode=block."),
            "referrer-policy": ("Missing Referrer-Policy", "low",
                "Referrer-Policy not set.", "Add Referrer-Policy header."),
            "permissions-policy": ("Missing Permissions-Policy", "low",
                "Permissions-Policy not set.", "Add Permissions-Policy header."),
        }

        for hdr, (title, sev, desc, rec) in security_headers.items():
            if hdr not in headers:
                findings.append({
                    "type": "header_issue", "url": url, "severity": sev,
                    "title": title, "description": desc,
                    "evidence": f"Header '{hdr}' not present.",
                    "recommendation": rec,
                })

        leaky = {"server": "Server version disclosed", "x-powered-by": "Tech stack disclosed"}
        for hdr, title in leaky.items():
            if hdr in headers:
                findings.append({
                    "type": "header_issue", "url": url, "severity": "low",
                    "title": title, "description": f"{hdr}: {headers[hdr]}",
                    "evidence": f"{hdr}: {headers[hdr]}",
                    "recommendation": f"Remove or suppress '{hdr}' header.",
                })

        # Check cookies
        for line in raw.splitlines():
            if not line.lower().startswith("set-cookie:"):
                continue
            cookie_str = line.split(":", 1)[1].strip()
            issues = []
            if "secure" not in cookie_str.lower():
                issues.append("Secure flag missing")
            if "httponly" not in cookie_str.lower():
                issues.append("HttpOnly flag missing")
            if "samesite" not in cookie_str.lower():
                issues.append("SameSite missing")
            if issues:
                name = cookie_str.split("=")[0].strip()
                findings.append({
                    "type": "header_issue", "url": url, "severity": "medium",
                    "title": f"Insecure cookie: {name}",
                    "description": f"Cookie '{name}' missing: {', '.join(issues)}.",
                    "evidence": line.strip()[:200],
                    "recommendation": "Set Secure, HttpOnly, and SameSite on all cookies.",
                })

        return findings

    # --- ffuf ---

    def _run_ffuf(self, url: str, context: dict) -> SkillResult:
        """Fast fuzzing with ffuf."""
        err = self._ensure_tool("ffuf")
        if err:
            return self._fail(err)

        fuzz_url = url if "FUZZ" in url else f"{url.rstrip('/')}/FUZZ"
        wordlist = self._wordlist(context, "dir")
        threads = self._threads(context)

        cmd = [
            "ffuf", "-u", fuzz_url, "-w", wordlist, "-t", str(threads),
            "-mc", "200,204,301,302,307,401,403,405",
            "-o", "/dev/stdout", "-of", "json", "-s",
        ]

        rc, stdout, stderr = _run_tool(cmd)
        if rc < -1:
            return self._fail(stderr)

        findings = []
        try:
            data = json.loads(stdout)
            for r in data.get("results", []):
                inp = r.get("input", {})
                path = inp.get("FUZZ", "") if isinstance(inp, dict) else str(inp)
                status = r.get("status", 0)
                length = r.get("length", 0)
                full_url = r.get("url", f"{url.rstrip('/')}/{path}")
                findings.append({
                    "type": "directory_found", "url": full_url,
                    "severity": self._dir_severity(f"/{path}", status),
                    "title": f"Found: /{path}",
                    "description": f"/{path} → HTTP {status} ({length} bytes).",
                    "evidence": f"HTTP {status} — {length} bytes",
                    "recommendation": self._dir_recommendation(f"/{path}", status),
                })
        except (json.JSONDecodeError, TypeError):
            for line in stdout.splitlines():
                m = re.search(r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)", line.strip())
                if m:
                    path, status, size = m.group(1), int(m.group(2)), m.group(3)
                    findings.append({
                        "type": "directory_found", "url": f"{url.rstrip('/')}/{path}",
                        "severity": self._dir_severity(f"/{path}", status),
                        "title": f"Found: /{path}",
                        "description": f"/{path} → HTTP {status} ({size} bytes).",
                        "evidence": line[:200],
                        "recommendation": self._dir_recommendation(f"/{path}", status),
                    })

        return SkillResult(
            success=True, output=stdout,
            structured_data={"tool": "ffuf", "url": url, "entries": len(findings)},
            commands_executed=[" ".join(cmd)], findings=findings,
        )

    # --- wfuzz ---

    def _run_wfuzz(self, url: str, context: dict) -> SkillResult:
        """Web fuzzing with wfuzz. Falls back to ffuf if unavailable."""
        err = self._ensure_tool("wfuzz")
        if err:
            if self._tools.get("ffuf", False):
                logger.info("wfuzz unavailable, falling back to ffuf")
                return self._run_ffuf(url, context)
            return self._fail(err)

        fuzz_url = url if "FUZZ" in url else f"{url.rstrip('/')}/FUZZ"
        wordlist = self._wordlist(context, "dir")

        cmd = ["wfuzz", "-c", "-z", f"file,{wordlist}", "--hc", "404", fuzz_url]

        rc, stdout, stderr = _run_tool(cmd)
        if rc < -1:
            return self._fail(stderr)

        findings = []
        pattern = re.compile(r"\d+:\s+(\d+)\s+\d+\s+L\s+\d+\s+W\s+(\d+)\s+Ch\s+\"(.+?)\"")
        for line in stdout.splitlines():
            m = pattern.search(line)
            if m:
                status, size, word = int(m.group(1)), m.group(2), m.group(3)
                findings.append({
                    "type": "directory_found", "url": f"{url.rstrip('/')}/{word}",
                    "severity": self._dir_severity(f"/{word}", status),
                    "title": f"Found: /{word}",
                    "description": f"/{word} → HTTP {status} ({size} chars).",
                    "evidence": line.strip()[:200],
                    "recommendation": self._dir_recommendation(f"/{word}", status),
                })

        return SkillResult(
            success=True, output=stdout,
            structured_data={"tool": "wfuzz", "url": url, "entries": len(findings)},
            commands_executed=[" ".join(cmd)], findings=findings,
        )
