"""
NyxOS Safety Guard
Location: nyxos/core/security/safety_guard.py

Protects: INTEGRITY & AVAILABILITY (CIA Triad)
- Prevents dangerous command execution
- Enforces scope limitations
- Blocks commands targeting out-of-scope systems
- Validates AI-generated commands before execution

Defends against:
- Accidental system destruction
- Unauthorized scanning (legal protection)
- AI hallucination executing harmful commands
- Command injection through AI prompts
"""

import re
import ipaddress
from typing import Tuple, List, Optional
from dataclasses import dataclass, field
from loguru import logger


@dataclass
class Scope:
    """Defines the authorized testing scope"""
    name: str = ""
    targets: List[str] = field(default_factory=list)  # IPs, CIDRs, domains
    excluded: List[str] = field(default_factory=list)  # Explicitly excluded
    ports: List[str] = field(default_factory=list)  # Allowed port ranges
    authorization_confirmed: bool = False
    notes: str = ""


@dataclass
class SafetyResult:
    """Result of a safety check"""
    is_safe: bool
    risk_level: str  # low, medium, high, critical
    reason: str
    suggestion: str = ""


class SafetyGuard:
    """
    Validates every command before execution.
    This is the last line of defense before anything runs on the system.
    """

    # Commands that should NEVER be executed
    BLOCKED_PATTERNS = [
        # System destruction
        (r"rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?/\s*$", "critical", "Attempted to delete root filesystem"),
        (r"rm\s+-rf\s+/(?:home|usr|var|etc|boot|opt)", "critical", "Attempted to delete critical directory"),
        (r"mkfs\.", "critical", "Attempted to format a filesystem"),
        (r"dd\s+.*of=/dev/[sh]d[a-z]", "critical", "Attempted to overwrite disk"),
        (r":\(\)\{\s*:\|:&\s*\};:", "critical", "Fork bomb detected"),
        (r"chmod\s+-R\s+777\s+/", "critical", "Attempted to remove all permissions on root"),
        (r">\s*/dev/[sh]d[a-z]", "critical", "Attempted to overwrite disk device"),

        # Network destruction
        (r"iptables\s+-F", "high", "Flushing all firewall rules"),
        (r"iptables\s+.*DROP.*-j\s+DROP", "high", "Dropping all traffic"),

        # Credential exposure
        (r"cat\s+.*/etc/shadow", "high", "Attempting to read shadow file"),
        (r"curl\s+.*\|\s*bash", "high", "Piping remote script to bash"),
        (r"wget\s+.*\|\s*sh", "high", "Piping remote script to shell"),
    ]

    # Commands that need user confirmation
    WARNING_PATTERNS = [
        (r"nmap\s+.*-sS", "medium", "SYN scan — may trigger IDS"),
        (r"nmap\s+.*-A", "medium", "Aggressive scan — generates significant traffic"),
        (r"sqlmap", "medium", "SQL injection testing — could modify data"),
        (r"hydra|medusa", "medium", "Brute force attack — may lock accounts"),
        (r"metasploit|msfconsole|msfvenom", "high", "Exploitation framework — use with caution"),
        (r"aircrack|aireplay|airmon", "medium", "Wireless attack — ensure authorization"),
        (r"responder", "high", "Network poisoning — ensure isolated network"),
        (r"john|hashcat", "low", "Password cracking — resource intensive"),
        (r"nikto", "medium", "Web vulnerability scan — generates traffic"),
        (r"gobuster|ffuf|dirb", "low", "Directory brute forcing"),
    ]

    def __init__(self):
        self.scope: Optional[Scope] = None
        self.command_history: List[dict] = []

    def set_scope(self, scope: Scope):
        """Set the authorized testing scope"""
        self.scope = scope
        logger.info(f"Scope set: {scope.name} — {len(scope.targets)} targets")

    def validate_command(self, command: str) -> SafetyResult:
        """
        Main validation entry point.
        Every command passes through here before execution.
        """
        command = command.strip()

        # Check 1: Blocked patterns (never allow)
        result = self._check_blocked(command)
        if result:
            return result

        # Check 2: Scope enforcement
        result = self._check_scope(command)
        if result:
            return result

        # Check 3: Command injection detection
        result = self._check_injection(command)
        if result:
            return result

        # Check 4: Warning patterns (allow with confirmation)
        result = self._check_warnings(command)
        if result:
            return result

        # Passed all checks
        return SafetyResult(
            is_safe=True,
            risk_level="low",
            reason="Command passed all safety checks"
        )

    def _check_blocked(self, command: str) -> Optional[SafetyResult]:
        """Check against absolutely blocked patterns"""
        for pattern, severity, description in self.BLOCKED_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                logger.warning(f"BLOCKED: {description} — Command: {command}")
                return SafetyResult(
                    is_safe=False,
                    risk_level=severity,
                    reason=f"⛔ BLOCKED: {description}",
                    suggestion="This command is too dangerous to execute."
                )
        return None

    def _check_scope(self, command: str) -> Optional[SafetyResult]:
        """Ensure targets are within authorized scope"""
        if not self.scope or not self.scope.authorization_confirmed:
            # Check if command targets a remote host
            if self._targets_remote_host(command):
                return SafetyResult(
                    is_safe=False,
                    risk_level="high",
                    reason="⛔ No scope defined. Cannot scan remote targets without authorization.",
                    suggestion="Use 'scope set' to define your authorized targets first."
                )
            return None

        # Extract target IPs/domains from command
        targets = self._extract_targets(command)
        for target in targets:
            if not self._is_in_scope(target):
                return SafetyResult(
                    is_safe=False,
                    risk_level="high",
                    reason=f"⛔ Target {target} is OUTSIDE your authorized scope.",
                    suggestion=f"Your scope includes: {', '.join(self.scope.targets)}"
                )

            if self._is_excluded(target):
                return SafetyResult(
                    is_safe=False,
                    risk_level="high",
                    reason=f"⛔ Target {target} is explicitly EXCLUDED from scope.",
                    suggestion="This target was marked as off-limits."
                )

        return None

    def _check_injection(self, command: str) -> Optional[SafetyResult]:
        """
        Detect command injection attempts.
        
        This protects against prompt injection where a malicious
        AI response tries to execute hidden commands.
        """
        injection_patterns = [
            (r";\s*rm\s", "Command injection: rm after semicolon"),
            (r";\s*curl\s+.*\|\s*bash", "Command injection: remote code execution"),
            (r"\$\(.*rm\s", "Command injection: rm in subshell"),
            (r"`.*rm\s", "Command injection: rm in backticks"),
            (r"\|\s*tee\s+/etc/", "Pipe writing to system config"),
            (r"&&\s*chmod\s+[0-7]+\s+/", "Chained permission change on root"),
            (r">\s*/etc/", "Redirect overwriting system config"),
        ]

        for pattern, description in injection_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                logger.warning(f"INJECTION DETECTED: {description} — Command: {command}")
                return SafetyResult(
                    is_safe=False,
                    risk_level="critical",
                    reason=f"⛔ Possible command injection detected: {description}",
                    suggestion="The AI may have generated a dangerous command. Please review manually."
                )

        return None

    def _check_warnings(self, command: str) -> Optional[SafetyResult]:
        """Check for commands that need user confirmation"""
        for pattern, severity, description in self.WARNING_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return SafetyResult(
                    is_safe=True,  # Safe but needs confirmation
                    risk_level=severity,
                    reason=f"⚠️  {description}",
                    suggestion="Proceed with caution. Ensure you have authorization."
                )
        return None

    def _extract_targets(self, command: str) -> List[str]:
        """Extract IP addresses and domains from a command"""
        targets = []

        # Match IP addresses
        ip_pattern = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b"
        targets.extend(re.findall(ip_pattern, command))

        # Match domain names
        domain_pattern = r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)\b"
        domains = re.findall(domain_pattern, command)
        # Filter out common non-target domains
        ignore_domains = {"github.com", "google.com", "example.com", "localhost"}
        targets.extend([d for d in domains if d not in ignore_domains])

        return targets

    def _is_in_scope(self, target: str) -> bool:
        """Check if a target is within the authorized scope"""
        if not self.scope:
            return False

        for scope_target in self.scope.targets:
            # Direct match
            if target == scope_target:
                return True

            # CIDR match
            try:
                if "/" in scope_target:
                    network = ipaddress.ip_network(scope_target, strict=False)
                    target_ip = ipaddress.ip_address(target)
                    if target_ip in network:
                        return True
                else:
                    if ipaddress.ip_address(target) == ipaddress.ip_address(scope_target):
                        return True
            except ValueError:
                # Not an IP — try domain matching
                if target.endswith(scope_target) or scope_target.endswith(target):
                    return True

        return False

    def _is_excluded(self, target: str) -> bool:
        """Check if target is explicitly excluded"""
        if not self.scope:
            return False
        return target in self.scope.excluded

    def _targets_remote_host(self, command: str) -> bool:
        """Check if command targets any remote host"""
        targets = self._extract_targets(command)
        local_prefixes = ["127.", "192.168.", "10.", "172.16.", "localhost"]
        for target in targets:
            is_local = any(target.startswith(prefix) for prefix in local_prefixes)
            if not is_local:
                return True
        return False
