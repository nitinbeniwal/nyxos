"""
NyxOS Password Skill — Hash Cracking and Wordlist Management

Wraps john (John the Ripper) and hashcat for dictionary, brute-force,
rules-based, and hybrid password cracking. Includes wordlist management
and rich result formatting.

NOTE: This file COMPLETES the partial implementation. The existing hash
type detection and basic output parser logic are preserved and extended.
"""

from __future__ import annotations

import gzip
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from nyxos.skills.base_skill import BaseSkill, SkillResult
from nyxos.core.config.settings import get_config
from nyxos.core.security.safety_guard import SafetyGuard, Scope
from nyxos.core.security.audit_logger import AuditLogger
from nyxos.skills.skill_manager import skill_registry


console = Console()

# ---------------------------------------------------------------------------
# Hash type detection (existing logic — preserved and extended)
# ---------------------------------------------------------------------------

HASH_TYPES: List[Tuple[str, re.Pattern, str, Optional[int]]] = [
    # (name, regex, john_format, hashcat_mode)
    ("MD5", re.compile(r'^[a-fA-F0-9]{32}$'), "Raw-MD5", 0),
    ("SHA-1", re.compile(r'^[a-fA-F0-9]{40}$'), "Raw-SHA1", 100),
    ("SHA-256", re.compile(r'^[a-fA-F0-9]{64}$'), "Raw-SHA256", 1400),
    ("SHA-512", re.compile(r'^[a-fA-F0-9]{128}$'), "Raw-SHA512", 1700),
    ("NTLM", re.compile(r'^[a-fA-F0-9]{32}$'), "NT", 1000),
    ("bcrypt", re.compile(r'^\$2[aby]?\$\d{2}\$.{53}$'), "bcrypt", 3200),
    ("MD5 Crypt", re.compile(r'^\$1\$.{8}\$.{22}$'), "md5crypt", 500),
    ("SHA-256 Crypt", re.compile(r'^\$5\$.+\$.{43}$'), "sha256crypt", 7400),
    ("SHA-512 Crypt", re.compile(r'^\$6\$.+\$.{86}$'), "sha512crypt", 1800),
    ("MySQL 4.1+", re.compile(r'^\*[a-fA-F0-9]{40}$'), "mysql-sha1", 300),
    ("LM", re.compile(r'^[a-fA-F0-9]{32}$'), "LM", 3000),
]


def detect_hash_type(hash_value: str) -> List[Dict[str, Any]]:
    """Identify possible hash types for a given hash string.

    Returns a list of dicts with keys: name, john_format, hashcat_mode.
    """
    hash_value = hash_value.strip()
    matches: List[Dict[str, Any]] = []

    for name, pattern, john_fmt, hc_mode in HASH_TYPES:
        if pattern.match(hash_value):
            matches.append({
                "name": name,
                "john_format": john_fmt,
                "hashcat_mode": hc_mode,
            })

    # Disambiguate 32-char hex (MD5 vs NTLM vs LM)
    if len(matches) > 1 and all(m["name"] in ("MD5", "NTLM", "LM") for m in matches):
        # Default to MD5 first, keep others as alternatives
        matches.sort(key=lambda m: 0 if m["name"] == "MD5" else 1)

    return matches if matches else [{"name": "Unknown", "john_format": None, "hashcat_mode": None}]


# ---------------------------------------------------------------------------
# Basic output parsers (existing logic — preserved)
# ---------------------------------------------------------------------------

def _parse_john_output(stdout: str, stderr: str) -> List[Dict[str, str]]:
    """Parse cracked passwords from john the ripper output."""
    results: List[Dict[str, str]] = []
    for line in (stdout + "\n" + stderr).splitlines():
        # john outputs: password  (hash)
        # or with --show: hash:password
        if ":" in line and not line.startswith("Using") and not line.startswith("Loaded"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                results.append({"hash": parts[0].strip(), "password": parts[1].strip()})
    return results


def _parse_hashcat_output(stdout: str, stderr: str) -> List[Dict[str, str]]:
    """Parse cracked passwords from hashcat output."""
    results: List[Dict[str, str]] = []
    for line in stdout.splitlines():
        # hashcat outputs: hash:password
        if ":" in line and not line.startswith("[") and not line.startswith("Session"):
            parts = line.rsplit(":", 1)
            if len(parts) == 2:
                results.append({"hash": parts[0].strip(), "password": parts[1].strip()})
    return results


# ---------------------------------------------------------------------------
# Helper: run subprocess
# ---------------------------------------------------------------------------

def _run(cmd: List[str], timeout: int = 300, stdin_data: Optional[str] = None) -> Tuple[str, str, int]:
    """Run a subprocess and return (stdout, stderr, returncode)."""
    logger.debug("Running: {}", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin_data,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out after {}s: {}", timeout, " ".join(cmd))
        return "", f"Timed out after {timeout}s", 1
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]}", 127


def _tool_available(name: str) -> bool:
    """Check if a CLI tool is installed and on PATH."""
    return shutil.which(name) is not None


# ---------------------------------------------------------------------------
# WordlistManager
# ---------------------------------------------------------------------------

class WordlistManager:
    """Manages wordlists for password cracking operations.

    Handles default wordlist paths, availability checking, and
    decompressing compressed wordlists (e.g., rockyou.txt.gz).
    """

    DEFAULT_WORDLISTS: Dict[str, str] = {
        "common": "/usr/share/wordlists/rockyou.txt",
        "rockyou": "/usr/share/wordlists/rockyou.txt",
        "web": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "small": "/usr/share/wordlists/dirb/small.txt",
        "big": "/usr/share/wordlists/dirb/big.txt",
        "common_dirb": "/usr/share/wordlists/dirb/common.txt",
        "fasttrack": "/usr/share/wordlists/fasttrack.txt",
    }

    COMPRESSED_VARIANTS: Dict[str, str] = {
        "/usr/share/wordlists/rockyou.txt": "/usr/share/wordlists/rockyou.txt.gz",
    }

    def get(self, name: str) -> Optional[str]:
        """Return the path to a wordlist by name, or *None* if unavailable.

        If the wordlist is compressed (e.g., rockyou.txt.gz), automatically
        decompresses it.
        """
        path = self.DEFAULT_WORDLISTS.get(name.lower())
        if not path:
            # Treat name as a direct path
            if Path(name).exists():
                return name
            return None

        if Path(path).exists():
            return path

        # Check for compressed version
        gz_path = self.COMPRESSED_VARIANTS.get(path)
        if gz_path and Path(gz_path).exists():
            logger.info("Found compressed wordlist: {} — decompressing", gz_path)
            self._decompress_gz(gz_path, path)
            if Path(path).exists():
                return path

        return None

    def list_available(self) -> List[Dict[str, str]]:
        """Return list of wordlists with their availability status."""
        results: List[Dict[str, str]] = []
        for name, path in self.DEFAULT_WORDLISTS.items():
            exists = Path(path).exists()
            gz_path = self.COMPRESSED_VARIANTS.get(path, "")
            gz_exists = Path(gz_path).exists() if gz_path else False

            if exists:
                size = Path(path).stat().st_size
                status = f"available ({size // (1024 * 1024)}MB)"
            elif gz_exists:
                status = "compressed (will auto-decompress on use)"
            else:
                status = "not found"

            results.append({"name": name, "path": path, "status": status})
        return results

    def download(self, name: str) -> None:
        """Decompress a wordlist if the .gz variant exists.

        For security reasons, we don't download from the internet
        automatically. On Kali, wordlists come preinstalled.
        """
        path = self.DEFAULT_WORDLISTS.get(name.lower())
        if not path:
            logger.warning("Unknown wordlist: {}", name)
            console.print(f"[yellow]Unknown wordlist: {name}[/yellow]")
            return

        if Path(path).exists():
            console.print(f"[green]Wordlist already available: {path}[/green]")
            return

        gz_path = self.COMPRESSED_VARIANTS.get(path)
        if gz_path and Path(gz_path).exists():
            console.print(f"[cyan]Decompressing {gz_path}...[/cyan]")
            self._decompress_gz(gz_path, path)
            if Path(path).exists():
                size = Path(path).stat().st_size
                console.print(f"[green]Done — {path} ({size // (1024 * 1024)}MB)[/green]")
            else:
                console.print(f"[red]Decompression failed.[/red]")
        else:
            console.print(
                f"[yellow]Wordlist '{name}' not found and no compressed variant available.\n"
                f"On Kali Linux, install with: sudo apt install wordlists[/yellow]"
            )

    @staticmethod
    def _decompress_gz(gz_path: str, output_path: str) -> None:
        """Decompress a .gz file to *output_path*."""
        try:
            with gzip.open(gz_path, "rb") as f_in:
                with open(output_path, "wb") as f_out:
                    # Read in chunks to handle large files
                    while True:
                        chunk = f_in.read(1024 * 1024)  # 1MB chunks
                        if not chunk:
                            break
                        f_out.write(chunk)
            logger.info("Decompressed {} → {}", gz_path, output_path)
        except (gzip.BadGzipFile, OSError, PermissionError) as exc:
            logger.error("Failed to decompress {}: {}", gz_path, exc)

    def display_wordlists(self) -> None:
        """Print a rich table of available wordlists."""
        table = Table(title="Available Wordlists", show_lines=True)
        table.add_column("Name", style="cyan", width=14)
        table.add_column("Path", style="white")
        table.add_column("Status", style="green")

        for wl in self.list_available():
            status_style = "green" if "available" in wl["status"] else "yellow"
            if "not found" in wl["status"]:
                status_style = "red"
            table.add_row(
                wl["name"],
                wl["path"],
                f"[{status_style}]{wl['status']}[/{status_style}]",
            )

        console.print(table)


# ---------------------------------------------------------------------------
# Intent keywords
# ---------------------------------------------------------------------------

INTENT_KEYWORDS: Dict[str, List[str]] = {
    "crack": ["crack", "brute", "dictionary", "attack", "recover", "password"],
    "identify": ["identify", "what hash", "hash type", "detect"],
    "wordlist": ["wordlist", "word list", "list wordlists", "rockyou"],
}


def _match_intent(text: str) -> str:
    """Return the best matching intent for natural-language input."""
    text_lower = text.lower()
    best: Optional[str] = None
    best_score = 0
    for intent, keywords in INTENT_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text_lower)
        if score > best_score:
            best_score = score
            best = intent
    return best if best else "crack"


# ---------------------------------------------------------------------------
# PasswordSkill
# ---------------------------------------------------------------------------

@skill_registry
class PasswordSkill(BaseSkill):
    """Password cracking skill for NyxOS.

    Wraps John the Ripper and Hashcat with automatic hash type detection,
    wordlist management, and rich result formatting. Supports dictionary,
    brute-force, rules-based, and hybrid cracking modes.
    """

    name: str = "password"
    description: str = "Password hash cracking with john/hashcat, wordlist management, hash identification"
    requires_tools: List[str] = []  # will check john/hashcat at runtime

    # Default cracking timeout in seconds
    DEFAULT_TIMEOUT: int = 300  # 5 minutes

    def __init__(self) -> None:
        self.safety = SafetyGuard()
        self.audit = AuditLogger()
        self.wordlists = WordlistManager()
        self._cracking_tool: Optional[str] = self._detect_cracking_tool()

    # ------------------------------------------------------------------
    # Tool detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_cracking_tool() -> Optional[str]:
        """Detect which cracking tool is available, preferring john."""
        if _tool_available("john"):
            return "john"
        if _tool_available("hashcat"):
            return "hashcat"
        logger.warning("Neither john nor hashcat found on PATH")
        return None

    # ------------------------------------------------------------------
    # BaseSkill interface
    # ------------------------------------------------------------------

    def get_commands(self, intent: str) -> List[str]:
        """Return example CLI commands for a given intent."""
        mapping = {
            "crack": [
                "john --wordlist=/usr/share/wordlists/rockyou.txt --format={format} {hash_file}",
                "hashcat -m {mode} {hash_file} /usr/share/wordlists/rockyou.txt",
            ],
            "identify": ["hash-identifier", "john --list=formats"],
            "wordlist": ["ls /usr/share/wordlists/"],
        }
        matched = _match_intent(intent)
        return mapping.get(matched, mapping["crack"])

    def execute(self, params: dict) -> SkillResult:
        """Execute a password skill action.

        Expected params:
            hash_value (str): hash to crack or identify
            hash_file (str, optional): file containing hashes
            mode (str): 'dictionary' | 'brute_force' | 'rules' | 'hybrid'
            intent (str): 'crack' | 'identify' | 'wordlist'
            wordlist (str, optional): wordlist name or path
            timeout (int, optional): cracking timeout in seconds
            hash_type (str, optional): override auto-detection
        """
        intent_raw: str = params.get("intent", "crack")
        intent = _match_intent(intent_raw)

        if intent == "identify":
            return self._identify_hash(params)
        elif intent == "wordlist":
            return self._list_wordlists(params)
        else:
            return self.crack_hash(params)

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """Generic output parser."""
        return {"raw": raw_output}

    # ------------------------------------------------------------------
    # Hash identification
    # ------------------------------------------------------------------

    def _identify_hash(self, params: dict) -> SkillResult:
        """Identify the type of a hash value."""
        hash_value: str = params.get("hash_value", "").strip()
        if not hash_value:
            return SkillResult(
                success=False,
                output="No hash value provided.",
                parsed_data={},
                findings=[],
                commands_run=[],
                duration_seconds=0.0,
            )

        types = detect_hash_type(hash_value)
        type_names = [t["name"] for t in types]
        output = f"Hash: {hash_value}\nPossible types: {', '.join(type_names)}"

        # Show details
        details_lines: List[str] = []
        for t in types:
            jf = t.get("john_format") or "N/A"
            hm = t.get("hashcat_mode")
            hm_str = str(hm) if hm is not None else "N/A"
            details_lines.append(f"  {t['name']}: john --format={jf} | hashcat -m {hm_str}")
        output += "\n\nCracking commands:\n" + "\n".join(details_lines)

        return SkillResult(
            success=True,
            output=output,
            parsed_data={"hash": hash_value, "types": types},
            findings=[{
                "type": "intermediate_finding",
                "severity": "info",
                "title": f"Hash identified: {', '.join(type_names)}",
                "description": output,
                "evidence": hash_value,
            }],
            commands_run=[],
            duration_seconds=0.0,
        )

    # ------------------------------------------------------------------
    # Wordlist listing
    # ------------------------------------------------------------------

    def _list_wordlists(self, params: dict) -> SkillResult:
        """List available wordlists."""
        available = self.wordlists.list_available()
        self.wordlists.display_wordlists()

        output_lines = [f"{wl['name']}: {wl['path']} ({wl['status']})" for wl in available]
        return SkillResult(
            success=True,
            output="\n".join(output_lines),
            parsed_data={"wordlists": available},
            findings=[],
            commands_run=[],
            duration_seconds=0.0,
        )

    # ------------------------------------------------------------------
    # Cracking orchestrator
    # ------------------------------------------------------------------

    def crack_hash(self, params: dict) -> SkillResult:
        """Orchestrate hash cracking.

        Steps:
            1. Identify hash type (auto or from params)
            2. Choose tool (john vs hashcat — use whichever is installed)
            3. Build command with appropriate flags for the mode
            4. Run with timeout (default 5 min)
            5. Parse output for cracked password
            6. Format and return result

        Params:
            hash_value (str): single hash to crack
            hash_file (str, optional): file containing hashes (overrides hash_value)
            mode (str): 'dictionary' | 'brute_force' | 'rules' | 'hybrid'
            wordlist (str, optional): wordlist name or path (default: 'common')
            timeout (int, optional): timeout in seconds (default: 300)
            hash_type (str, optional): override auto-detection (john format name)
        """
        start = time.time()
        hash_value: str = params.get("hash_value", "").strip()
        hash_file: str = params.get("hash_file", "").strip()
        mode: str = params.get("mode", "dictionary").lower()
        wordlist_name: str = params.get("wordlist", "common")
        timeout: int = int(params.get("timeout", self.DEFAULT_TIMEOUT))
        hash_type_override: Optional[str] = params.get("hash_type")

        commands_run: List[str] = []
        temp_hash_file: Optional[str] = None

	# Safety check before cracking               # ← NEW
        safe, reason, risk = self.safety.check_command(  # ← NEW
            f"password crack {hash_value[:32] if hash_value else hash_file}",  # ← NEW
            Scope(targets=[]),                        # ← NEW
        )                                             # ← NEW
        if not safe:                                  # ← NEW
            return SkillResult(                       # ← NEW
                success=False,                        # ← NEW
                output=f"Blocked by SafetyGuard: {reason}",  # ← NEW
                parsed_data={},                       # ← NEW
                findings=[],                          # ← NEW
                commands_run=[],                      # ← NEW
                duration_seconds=0.0,                 # ← NEW
            )                                         # ← NEW




        # Validate we have something to crack
        if not hash_value and not hash_file:
            return SkillResult(
                success=False,
                output="No hash value or hash file provided.",
                parsed_data={},
                findings=[],
                commands_run=[],
                duration_seconds=0.0,
            )

        # Check cracking tool
        if not self._cracking_tool:
            self._cracking_tool = self._detect_cracking_tool()
        if not self._cracking_tool:
            return SkillResult(
                success=False,
                output=(
                    "[!] Neither john nor hashcat found.\n"
                    "Install with: sudo apt install john hashcat"
                ),
                parsed_data={},
                findings=[],
                commands_run=[],
                duration_seconds=0.0,
            )

        # Step 1: Identify hash type
        if hash_type_override:
            detected = [{"name": hash_type_override, "john_format": hash_type_override, "hashcat_mode": None}]
        elif hash_value:
            detected = detect_hash_type(hash_value)
        else:
            # If only hash_file provided, try to read first line
            try:
                with open(hash_file, "r") as f:
                    first_hash = f.readline().strip()
                    # Handle user:hash format
                    if ":" in first_hash:
                        first_hash = first_hash.split(":")[-1].strip()
                    detected = detect_hash_type(first_hash)
            except (OSError, IndexError):
                detected = [{"name": "Unknown", "john_format": None, "hashcat_mode": None}]

        primary_type = detected[0]
        logger.info("Detected hash type: {} ({})", primary_type["name"], primary_type)

        # Step 2: Write hash to temp file if hash_value provided (not hash_file)
        if hash_value and not hash_file:
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".hash", prefix="nyxos_", delete=False
            )
            tmp.write(hash_value + "\n")
            tmp.close()
            temp_hash_file = tmp.name
            hash_file = temp_hash_file

        # Step 3: Resolve wordlist
        wordlist_path: Optional[str] = None
        if mode in ("dictionary", "rules", "hybrid"):
            wordlist_path = self.wordlists.get(wordlist_name)
            if not wordlist_path:
                # Fallback to small wordlist
                wordlist_path = self.wordlists.get("small")
            if not wordlist_path:
                # Clean up temp file
                if temp_hash_file:
                    Path(temp_hash_file).unlink(missing_ok=True)
                return SkillResult(
                    success=False,
                    output=(
                        f"[!] Wordlist '{wordlist_name}' not found.\n"
                        f"Available wordlists:\n"
                        + "\n".join(
                            f"  {wl['name']}: {wl['status']}"
                            for wl in self.wordlists.list_available()
                        )
                    ),
                    parsed_data={},
                    findings=[],
                    commands_run=[],
                    duration_seconds=round(time.time() - start, 2),
                )

        # Step 4: Build and run cracking command
        try:
            if self._cracking_tool == "john":
                cracked = self._crack_with_john(
                    hash_file=hash_file,
                    hash_type=primary_type,
                    mode=mode,
                    wordlist_path=wordlist_path,
                    timeout=timeout,
                    commands_run=commands_run,
                )
            else:
                cracked = self._crack_with_hashcat(
                    hash_file=hash_file,
                    hash_type=primary_type,
                    mode=mode,
                    wordlist_path=wordlist_path,
                    timeout=timeout,
                    commands_run=commands_run,
                )
        except Exception as exc:
            logger.error("Cracking failed: {}", exc)
            cracked = []
        finally:
            # Clean up temp file
            if temp_hash_file:
                Path(temp_hash_file).unlink(missing_ok=True)

        elapsed = round(time.time() - start, 2)

        # Step 5: Format results
        findings: List[Dict[str, Any]] = []
        if cracked:
            for entry in cracked:
                findings.append({
                    "type": "credential",
                    "severity": "critical",
                    "title": "Password cracked",
                    "description": (
                        f"Hash {entry['hash'][:32]}... cracked to: {entry['password']}"
                    ),
                    "evidence": f"{entry['hash']} → {entry['password']}",
                    "recommendation": "Enforce stronger password policies",
                    "tool_used": self._cracking_tool,
                    "time_seconds": elapsed,
                })
            self._format_results(cracked, elapsed)
            output = f"Cracked {len(cracked)} hash(es) in {elapsed}s using {self._cracking_tool}"
        else:
            output = (
                f"No passwords cracked after {elapsed}s using {self._cracking_tool} ({mode} mode).\n"
                f"Hash type: {primary_type['name']}\n"
                f"Try: different wordlist, rules mode, or longer timeout."
            )

        self.audit.log("SKILL_USE", f"password:crack:{mode}", user="current", details={
            "hash_type": primary_type["name"],
            "tool": self._cracking_tool,
            "cracked_count": len(cracked),
            "timeout": timeout,
            "duration": elapsed,
        })

        return SkillResult(
            success=bool(cracked),
            output=output,
            parsed_data={
                "hash_type": primary_type,
                "mode": mode,
                "tool": self._cracking_tool,
                "cracked": cracked,
            },
            findings=findings,
            commands_run=commands_run,
            duration_seconds=elapsed,
        )

    # ------------------------------------------------------------------
    # John the Ripper
    # ------------------------------------------------------------------

    def _crack_with_john(
        self,
        hash_file: str,
        hash_type: Dict[str, Any],
        mode: str,
        wordlist_path: Optional[str],
        timeout: int,
        commands_run: List[str],
    ) -> List[Dict[str, str]]:
        """Run john the ripper and return cracked results."""
        cmd: List[str] = ["john"]

        # Add format if known
        john_format = hash_type.get("john_format")
        if john_format:
            cmd.extend(["--format=" + john_format])

        # Mode-specific flags
        if mode == "dictionary" and wordlist_path:
            cmd.extend(["--wordlist=" + wordlist_path])
        elif mode == "brute_force":
            cmd.append("--incremental")
        elif mode == "rules" and wordlist_path:
            cmd.extend(["--wordlist=" + wordlist_path, "--rules=All"])
        elif mode == "hybrid" and wordlist_path:
            cmd.extend(["--wordlist=" + wordlist_path, "--rules=Jumbo"])

        cmd.append(hash_file)
        commands_run.append(" ".join(cmd))

        console.print(f"[cyan]Running: {' '.join(cmd)}[/cyan]")
        console.print(f"[dim]Timeout: {timeout}s[/dim]")

        stdout, stderr, rc = _run(cmd, timeout=timeout)
        logger.debug("john stdout: {}", stdout[:500])
        logger.debug("john stderr: {}", stderr[:500])

        # Parse results from the run output
        results = _parse_john_output(stdout, stderr)

        # Also run --show to get previously cracked hashes
        show_cmd = ["john", "--show"]
        if john_format:
            show_cmd.append("--format=" + john_format)
        show_cmd.append(hash_file)
        commands_run.append(" ".join(show_cmd))

        show_stdout, show_stderr, _ = _run(show_cmd, timeout=30)
        show_results = _parse_john_output(show_stdout, show_stderr)

        # Merge results, deduplicate by hash
        seen_hashes: set = set()
        merged: List[Dict[str, str]] = []
        for r in results + show_results:
            h = r["hash"]
            if h not in seen_hashes:
                seen_hashes.add(h)
                merged.append(r)

        return merged

    # ------------------------------------------------------------------
    # Hashcat
    # ------------------------------------------------------------------

    def _crack_with_hashcat(
        self,
        hash_file: str,
        hash_type: Dict[str, Any],
        mode: str,
        wordlist_path: Optional[str],
        timeout: int,
        commands_run: List[str],
    ) -> List[Dict[str, str]]:
        """Run hashcat and return cracked results."""
        hashcat_mode = hash_type.get("hashcat_mode")
        if hashcat_mode is None:
            logger.warning("No hashcat mode for hash type: {}", hash_type["name"])
            # Try with auto-detect
            hashcat_mode = 0

        # Create a potfile in temp to avoid conflicts
        potfile = tempfile.NamedTemporaryFile(
            suffix=".potfile", prefix="nyxos_hc_", delete=False
        ).name

        cmd: List[str] = [
            "hashcat",
            "-m", str(hashcat_mode),
            "--potfile-path", potfile,
            "--force",  # allow running without GPU
            "-O",       # optimized kernels
        ]

        # Attack mode
        if mode == "dictionary" and wordlist_path:
            cmd.extend(["-a", "0", hash_file, wordlist_path])
        elif mode == "brute_force":
            cmd.extend(["-a", "3", hash_file, "?a?a?a?a?a?a?a?a"])
        elif mode == "rules" and wordlist_path:
            cmd.extend(["-a", "0", "-r", "/usr/share/hashcat/rules/best64.rule",
                        hash_file, wordlist_path])
        elif mode == "hybrid" and wordlist_path:
            cmd.extend(["-a", "6", hash_file, wordlist_path, "?d?d?d"])
        else:
            if wordlist_path:
                cmd.extend(["-a", "0", hash_file, wordlist_path])
            else:
                cmd.extend(["-a", "3", hash_file])

        # Runtime limit
        cmd.extend(["--runtime", str(timeout)])

        commands_run.append(" ".join(cmd))

        console.print(f"[cyan]Running: {' '.join(cmd)}[/cyan]")
        console.print(f"[dim]Timeout: {timeout}s[/dim]")

        stdout, stderr, rc = _run(cmd, timeout=timeout + 30)  # extra buffer
        logger.debug("hashcat stdout: {}", stdout[:500])
        logger.debug("hashcat stderr: {}", stderr[:500])

        results = _parse_hashcat_output(stdout, stderr)

        # Also check potfile for results
        try:
            if Path(potfile).exists():
                with open(potfile, "r") as f:
                    for line in f:
                        line = line.strip()
                        if ":" in line:
                            parts = line.rsplit(":", 1)
                            if len(parts) == 2:
                                h, p = parts
                                if not any(r["hash"] == h for r in results):
                                    results.append({"hash": h, "password": p})
        except OSError:
            pass
        finally:
            Path(potfile).unlink(missing_ok=True)

        return results

    # ------------------------------------------------------------------
    # Result formatter
    # ------------------------------------------------------------------

    def _format_results(self, results: List[Dict[str, str]], elapsed: float) -> None:
        """Display cracked passwords in a rich Table.

        Columns: Hash | Cracked Password | Time | Tool Used
        """
        if not results:
            console.print("[yellow]No passwords cracked.[/yellow]")
            return

        table = Table(
            title="🔓 Cracked Passwords",
            show_lines=True,
            title_style="bold green",
        )
        table.add_column("Hash", style="dim white", max_width=40, no_wrap=False)
        table.add_column("Cracked Password", style="bold green")
        table.add_column("Time", style="cyan", justify="right")
        table.add_column("Tool", style="magenta")

        for entry in results:
            hash_display = entry["hash"]
            if len(hash_display) > 36:
                hash_display = hash_display[:16] + "..." + hash_display[-16:]

            table.add_row(
                hash_display,
                entry["password"],
                f"{elapsed:.1f}s",
                self._cracking_tool or "unknown",
            )

        console.print()
        console.print(table)
        console.print(
            f"\n[green]✓ {len(results)} password(s) cracked in {elapsed:.1f}s "
            f"using {self._cracking_tool}[/green]\n"
        )

    def display_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Print findings in a formatted table."""
        cred_findings = [f for f in findings if f.get("type") == "credential"]
        if cred_findings:
            results = []
            for f in cred_findings:
                evidence = f.get("evidence", "")
                if " → " in evidence:
                    h, p = evidence.split(" → ", 1)
                    results.append({"hash": h, "password": p})
            elapsed = cred_findings[0].get("time_seconds", 0) if cred_findings else 0
            self._format_results(results, elapsed)
        else:
            console.print("[yellow]No credential findings to display.[/yellow]")
