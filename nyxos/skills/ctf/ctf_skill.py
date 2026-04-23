"""
NyxOS CTF Skill — Challenge Solving Assistant

Provides encoding/decoding, hash identification, steganography,
file analysis, reverse engineering helpers, and an AI-powered
progressive hint system that avoids spoiling solutions.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import json
import re
import shutil
import subprocess
import string
import time
import urllib.parse
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
# Flag detection
# ---------------------------------------------------------------------------

FLAG_PATTERNS = [
    re.compile(r'FLAG\{[^}]+\}', re.IGNORECASE),
    re.compile(r'CTF\{[^}]+\}', re.IGNORECASE),
    re.compile(r'HTB\{[^}]+\}', re.IGNORECASE),
    re.compile(r'picoCTF\{[^}]+\}'),
    re.compile(r'flag\{[^}]+\}'),
    re.compile(r'FLAG-[\w-]+'),
]

# ---------------------------------------------------------------------------
# Intent keywords
# ---------------------------------------------------------------------------

INTENT_KEYWORDS: Dict[str, List[str]] = {
    "decode": ["decode", "decrypt", "base64", "hex", "rot13", "url decode", "from binary", "morse"],
    "encode": ["encode", "encrypt", "to base64", "to hex", "url encode", "to binary"],
    "hash_id": ["hash", "identify hash", "what hash", "hash type"],
    "stego": ["stego", "steganography", "hidden", "steghide", "stegsolve", "lsb"],
    "file_analysis": ["file", "strings", "binwalk", "exiftool", "analyze file", "examine"],
    "crypto": ["cipher", "crypto", "vigenere", "caesar", "xor", "rsa"],
    "web_challenge": ["web", "curl", "http", "cookie", "sql", "xss"],
    "reversing": ["reverse", "binary", "ltrace", "strace", "disassemble", "decompile"],
    "hint": ["hint", "help me", "stuck", "next step", "clue"],
}


def _match_intent(text: str) -> str:
    text_lower = text.lower()
    best: Optional[str] = None
    best_score = 0
    for intent, keywords in INTENT_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text_lower)
        if score > best_score:
            best_score = score
            best = intent
    return best if best else "decode"


def _run(cmd: List[str], timeout: int = 120, stdin_data: Optional[str] = None) -> Tuple[str, str, int]:
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
        return "", f"Timed out after {timeout}s", 1
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]}", 127


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _detect_flags(text: str) -> List[str]:
    """Scan *text* for common CTF flag formats."""
    flags: List[str] = []
    for pattern in FLAG_PATTERNS:
        flags.extend(pattern.findall(text))
    return list(set(flags))


# ---------------------------------------------------------------------------
# Encoding / Decoding helpers
# ---------------------------------------------------------------------------

class Codec:
    """Pure-Python encode/decode utilities."""

    @staticmethod
    def base64_decode(data: str) -> str:
        try:
            return base64.b64decode(data.strip()).decode("utf-8", errors="replace")
        except Exception:
            return "[!] Invalid base64"

    @staticmethod
    def base64_encode(data: str) -> str:
        return base64.b64encode(data.encode()).decode()

    @staticmethod
    def hex_decode(data: str) -> str:
        cleaned = data.replace(" ", "").replace("0x", "").replace("\\x", "")
        try:
            return bytes.fromhex(cleaned).decode("utf-8", errors="replace")
        except ValueError:
            return "[!] Invalid hex"

    @staticmethod
    def hex_encode(data: str) -> str:
        return data.encode().hex()

    @staticmethod
    def rot13(data: str) -> str:
        return codecs.encode(data, "rot_13")

    @staticmethod
    def url_decode(data: str) -> str:
        return urllib.parse.unquote(data)

    @staticmethod
    def url_encode(data: str) -> str:
        return urllib.parse.quote(data)

    @staticmethod
    def binary_decode(data: str) -> str:
        bits = data.replace(" ", "")
        if not all(c in "01" for c in bits):
            return "[!] Invalid binary string"
        try:
            chars = [chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8)]
            return "".join(chars)
        except ValueError:
            return "[!] Invalid binary"

    @staticmethod
    def binary_encode(data: str) -> str:
        return " ".join(format(ord(c), "08b") for c in data)

    MORSE_TABLE: Dict[str, str] = {
        "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".",
        "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---",
        "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---",
        "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-",
        "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--",
        "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
        "3": "...--", "4": "....-", "5": ".....", "6": "-....",
        "7": "--...", "8": "---..", "9": "----.", " ": "/",
        "{": "-.--.", "}": "-.--.-", "_": "..--.-",
    }

    @classmethod
    def morse_decode(cls, data: str) -> str:
        reverse = {v: k for k, v in cls.MORSE_TABLE.items()}
        words = data.strip().split(" / ")
        decoded: List[str] = []
        for word in words:
            chars = word.strip().split(" ")
            decoded.append("".join(reverse.get(c, "?") for c in chars if c))
        return " ".join(decoded)

    @classmethod
    def morse_encode(cls, data: str) -> str:
        return " ".join(cls.MORSE_TABLE.get(c.upper(), "?") for c in data)


# ---------------------------------------------------------------------------
# Hash identification
# ---------------------------------------------------------------------------

HASH_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    ("MD5", re.compile(r'^[a-fA-F0-9]{32}$'), "md5"),
    ("SHA-1", re.compile(r'^[a-fA-F0-9]{40}$'), "sha1"),
    ("SHA-256", re.compile(r'^[a-fA-F0-9]{64}$'), "sha256"),
    ("SHA-512", re.compile(r'^[a-fA-F0-9]{128}$'), "sha512"),
    ("bcrypt", re.compile(r'^\$2[aby]?\$\d+\$.{53}$'), "bcrypt"),
    ("MD5 Crypt", re.compile(r'^\$1\$.{8}\$.{22}$'), "md5crypt"),
    ("SHA-512 Crypt", re.compile(r'^\$6\$.+\$.+$'), "sha512crypt"),
    ("NTLM", re.compile(r'^[a-fA-F0-9]{32}$'), "ntlm"),  # same as MD5 by length
]


def identify_hash(value: str) -> List[str]:
    """Return list of possible hash type names for *value*."""
    value = value.strip()
    matches = [name for name, pattern, _ in HASH_PATTERNS if pattern.match(value)]
    return matches if matches else ["Unknown"]


# ---------------------------------------------------------------------------
# CTFSkill
# ---------------------------------------------------------------------------

@skill_registry
class CTFSkill(BaseSkill):
    """CTF challenge solving assistant for NyxOS.

    Provides encoding/decoding, hash identification, steganography,
    file analysis, reverse engineering helpers, and an AI-powered
    progressive hint system.
    """

    name: str = "ctf"
    description: str = "CTF challenge solving: decode, encode, stego, file analysis, AI hints, flag detection"
    requires_tools: List[str] = []  # core features work without external tools

    def __init__(self, ai_router: Any = None) -> None:
        self.ai_router = ai_router
        self.safety = SafetyGuard()
        self.audit = AuditLogger()
        self.codec = Codec()

    # ------------------------------------------------------------------
    # BaseSkill interface
    # ------------------------------------------------------------------

    def get_commands(self, intent: str) -> List[str]:
        mapping = {
            "decode": ["echo '<data>' | base64 -d"],
            "encode": ["echo '<data>' | base64"],
            "hash_id": ["hash-identifier"],
            "stego": ["steghide extract -sf <image>", "binwalk <file>"],
            "file_analysis": ["file <path>", "strings <path>", "exiftool <path>"],
            "crypto": ["(AI-assisted cipher analysis)"],
            "web_challenge": ["curl -v <url>", "nikto -h <url>"],
            "reversing": ["strings <binary>", "ltrace ./<binary>", "strace ./<binary>"],
            "hint": ["(AI-powered progressive hint)"],
        }
        matched = _match_intent(intent)
        return mapping.get(matched, mapping["decode"])

    def execute(self, params: dict) -> SkillResult:
        """Execute a CTF skill action.

        Expected params:
            intent (str): what to do
            data (str, optional): data to decode/encode/analyze
            file_path (str, optional): file for analysis/stego
            challenge (str, optional): challenge name/description
            current_findings (list, optional): what's been found so far (for hints)
            encoding (str, optional): specific encoding to use
        """
        intent_raw: str = params.get("intent", "decode")
        data: str = params.get("data", "")
        file_path: str = params.get("file_path", "")
        challenge: str = params.get("challenge", "unknown")
        current_findings: List[str] = params.get("current_findings", [])
        encoding: str = params.get("encoding", "auto")

        start = time.time()
        intent = _match_intent(intent_raw)

        # Safety check before execution
        safe, reason, risk = self.safety.check_command(
            f"ctf {intent} {file_path or data[:50]}", Scope(targets=[])
        )
        if not safe:
            return SkillResult(
                success=False,
                output=f"Blocked by SafetyGuard: {reason}",
                parsed_data={},
                findings=[],
                commands_run=[],
                duration_seconds=0.0,
            )

        dispatch = {
            "decode": self._decode,
            "encode": self._encode,
            "hash_id": self._hash_identify,
            "stego": self._steganography,
            "file_analysis": self._file_analysis,
            "crypto": self._crypto_hint,
            "web_challenge": self._web_challenge,
            "reversing": self._reversing,
            "hint": self._hint,
        }

        handler = dispatch.get(intent, self._decode)
        result = handler(params)

        # Scan output for flags
        all_text = result.output + " ".join(str(f.get("value", "")) for f in result.findings)
        flags = _detect_flags(all_text)
        for flag in flags:
            if not any(f.get("type") == "flag" and f.get("value") == flag for f in result.findings):
                result.findings.append({
                    "type": "flag",
                    "value": flag,
                    "challenge": challenge,
                    "method": f"{intent} analysis",
                })
                console.print(Panel(
                    f"[bold green]🏁 FLAG FOUND: {flag}[/bold green]",
                    title="🎉 Congratulations!",
                    border_style="green",
                ))

        result.duration_seconds = round(time.time() - start, 2)

        self.audit.log("SKILL_USE", f"ctf:{intent}", user="current", details={
            "challenge": challenge,
            "flags_found": len(flags),
        })

        return result

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        flags = _detect_flags(raw_output)
        return {"flags": flags, "raw": raw_output}

    # ------------------------------------------------------------------
    # Hint system
    # ------------------------------------------------------------------

    def get_hint(self, challenge_description: str, current_findings: List[str]) -> str:
        """Ask AI for a progressive hint without spoiling the solution."""
        if not self.ai_router:
            return "[!] AI router not available — cannot provide hints"

        prompt = (
            f"I'm solving a CTF challenge.\n"
            f"Challenge: {challenge_description}\n"
            f"What I've found so far: {json.dumps(current_findings)}\n\n"
            f"Give me a hint for the next step. Do NOT give the full solution or the flag. "
            f"Just nudge me in the right direction with one concrete suggestion."
        )
        try:
            response = self.ai_router.route(prompt, task_type="explain")
            return response.text
        except Exception as exc:
            logger.error("AI hint failed: {}", exc)
            return f"[!] Hint generation failed: {exc}"

    # ------------------------------------------------------------------
    # Decode / Encode
    # ------------------------------------------------------------------

    def _decode(self, params: dict) -> SkillResult:
        data: str = params.get("data", "")
        encoding: str = params.get("encoding", "auto").lower()
        findings: List[Dict[str, Any]] = []
        commands: List[str] = []
        outputs: List[str] = []

        if not data:
            return SkillResult(False, "No data provided to decode.", {}, [], [], 0.0)

        if encoding == "auto":
            # Try all decodings and report successes
            attempts = [
                ("base64", self.codec.base64_decode),
                ("hex", self.codec.hex_decode),
                ("rot13", self.codec.rot13),
                ("url", self.codec.url_decode),
                ("binary", self.codec.binary_decode),
                ("morse", self.codec.morse_decode),
            ]
            for name, fn in attempts:
                try:
                    result = fn(data)
                    if result and not result.startswith("[!]") and result != data:
                        # Check if result looks like readable text
                        printable_ratio = sum(1 for c in result if c in string.printable) / max(len(result), 1)
                        if printable_ratio > 0.7:
                            outputs.append(f"[{name}] → {result}")
                            findings.append({
                                "type": "intermediate_finding",
                                "value": result,
                                "challenge": params.get("challenge", "unknown"),
                                "method": f"{name} decode",
                            })
                except Exception:
                    continue
        else:
            codec_map = {
                "base64": self.codec.base64_decode,
                "hex": self.codec.hex_decode,
                "rot13": self.codec.rot13,
                "url": self.codec.url_decode,
                "binary": self.codec.binary_decode,
                "morse": self.codec.morse_decode,
            }
            fn = codec_map.get(encoding)
            if fn:
                result = fn(data)
                outputs.append(f"[{encoding}] → {result}")
                if not result.startswith("[!]"):
                    findings.append({
                        "type": "intermediate_finding",
                        "value": result,
                        "challenge": params.get("challenge", "unknown"),
                        "method": f"{encoding} decode",
                    })
            else:
                outputs.append(f"[!] Unknown encoding: {encoding}")

        output_text = "\n".join(outputs) if outputs else "[!] No successful decodings"
        return SkillResult(
            success=bool(findings),
            output=output_text,
            parsed_data={"input": data, "encoding": encoding},
            findings=findings,
            commands_run=commands,
            duration_seconds=0.0,
        )

    def _encode(self, params: dict) -> SkillResult:
        data: str = params.get("data", "")
        encoding: str = params.get("encoding", "base64").lower()

        if not data:
            return SkillResult(False, "No data provided to encode.", {}, [], [], 0.0)

        codec_map = {
            "base64": self.codec.base64_encode,
            "hex": self.codec.hex_encode,
            "rot13": self.codec.rot13,
            "url": self.codec.url_encode,
            "binary": self.codec.binary_encode,
            "morse": self.codec.morse_encode,
        }

        fn = codec_map.get(encoding)
        if not fn:
            return SkillResult(False, f"Unknown encoding: {encoding}", {}, [], [], 0.0)

        result = fn(data)
        return SkillResult(
            success=True,
            output=f"[{encoding}] → {result}",
            parsed_data={"input": data, "encoding": encoding, "result": result},
            findings=[{
                "type": "intermediate_finding",
                "value": result,
                "challenge": params.get("challenge", "unknown"),
                "method": f"{encoding} encode",
            }],
            commands_run=[],
            duration_seconds=0.0,
        )

    # ------------------------------------------------------------------
    # Hash identification
    # ------------------------------------------------------------------

    def _hash_identify(self, params: dict) -> SkillResult:
        data: str = params.get("data", "")
        if not data:
            return SkillResult(False, "No hash provided.", {}, [], [], 0.0)

        types = identify_hash(data)
        output = f"Hash: {data}\nPossible types: {', '.join(types)}"

        return SkillResult(
            success=True,
            output=output,
            parsed_data={"hash": data, "possible_types": types},
            findings=[{
                "type": "intermediate_finding",
                "value": f"Hash identified as: {', '.join(types)}",
                "challenge": params.get("challenge", "unknown"),
                "method": "hash identification",
            }],
            commands_run=[],
            duration_seconds=0.0,
        )

    # ------------------------------------------------------------------
    # Steganography
    # ------------------------------------------------------------------

    def _steganography(self, params: dict) -> SkillResult:
        file_path: str = params.get("file_path", "")
        passphrase: str = params.get("passphrase", "")
        findings: List[Dict[str, Any]] = []
        commands: List[str] = []
        outputs: List[str] = []

        if not file_path or not Path(file_path).exists():
            return SkillResult(False, f"File not found: {file_path}", {}, [], [], 0.0)

        # steghide
        if _tool_available("steghide"):
            cmd = ["steghide", "extract", "-sf", file_path, "-f"]
            if passphrase:
                cmd.extend(["-p", passphrase])
            else:
                cmd.extend(["-p", ""])
            commands.append(" ".join(cmd))
            stdout, stderr, rc = _run(cmd, timeout=30)
            combined = stdout + stderr
            outputs.append(f"--- steghide ---\n{combined}")
            if rc == 0 and "wrote extracted data" in combined.lower():
                findings.append({
                    "type": "intermediate_finding",
                    "value": f"steghide extracted hidden data from {file_path}",
                    "challenge": params.get("challenge", "unknown"),
                    "method": "steghide extraction",
                })

        # binwalk
        if _tool_available("binwalk"):
            cmd = ["binwalk", file_path]
            commands.append(" ".join(cmd))
            stdout, stderr, rc = _run(cmd, timeout=60)
            outputs.append(f"--- binwalk ---\n{stdout}")
            if stdout.strip():
                for line in stdout.strip().splitlines()[1:]:  # skip header
                    if line.strip():
                        findings.append({
                            "type": "intermediate_finding",
                            "value": line.strip(),
                            "challenge": params.get("challenge", "unknown"),
                            "method": "binwalk analysis",
                        })

        # strings for good measure
        if _tool_available("strings"):
            cmd = ["strings", file_path]
            commands.append(" ".join(cmd))
            stdout, stderr, rc = _run(cmd, timeout=30)
            # Only search for flags in strings output
            flags = _detect_flags(stdout)
            for flag in flags:
                findings.append({
                    "type": "flag",
                    "value": flag,
                    "challenge": params.get("challenge", "unknown"),
                    "method": "strings on image file",
                })
            if not flags:
                outputs.append(f"--- strings --- ({len(stdout.splitlines())} lines, no flags detected)")

        output_text = "\n".join(outputs)
        return SkillResult(
            success=bool(findings),
            output=output_text,
            parsed_data={"file": file_path},
            findings=findings,
            commands_run=commands,
            duration_seconds=0.0,
        )

    # ------------------------------------------------------------------
    # File analysis
    # ------------------------------------------------------------------

    def _file_analysis(self, params: dict) -> SkillResult:
        file_path: str = params.get("file_path", "")
        findings: List[Dict[str, Any]] = []
        commands: List[str] = []
        outputs: List[str] = []

        if not file_path or not Path(file_path).exists():
            return SkillResult(False, f"File not found: {file_path}", {}, [], [], 0.0)

        # file command
        if _tool_available("file"):
            cmd = ["file", file_path]
            commands.append(" ".join(cmd))
            stdout, _, _ = _run(cmd)
            outputs.append(f"--- file ---\n{stdout.strip()}")
            findings.append({
                "type": "intermediate_finding",
                "value": stdout.strip(),
                "challenge": params.get("challenge", "unknown"),
                "method": "file type identification",
            })

        # exiftool
        if _tool_available("exiftool"):
            cmd = ["exiftool", file_path]
            commands.append(" ".join(cmd))
            stdout, _, _ = _run(cmd)
            outputs.append(f"--- exiftool ---\n{stdout.strip()}")
            # Check for interesting metadata
            flags = _detect_flags(stdout)
            for flag in flags:
                findings.append({
                    "type": "flag",
                    "value": flag,
                    "challenge": params.get("challenge", "unknown"),
                    "method": "exiftool metadata",
                })

        # strings
        if _tool_available("strings"):
            cmd = ["strings", file_path]
            commands.append(" ".join(cmd))
            stdout, _, _ = _run(cmd, timeout=30)
            interesting = [l for l in stdout.splitlines() if len(l.strip()) > 4]
            flags = _detect_flags(stdout)
            for flag in flags:
                findings.append({
                    "type": "flag",
                    "value": flag,
                    "challenge": params.get("challenge", "unknown"),
                    "method": "strings extraction",
                })
            outputs.append(f"--- strings --- ({len(interesting)} interesting strings)")

        # binwalk
        if _tool_available("binwalk"):
            cmd = ["binwalk", file_path]
            commands.append(" ".join(cmd))
            stdout, _, _ = _run(cmd, timeout=60)
            outputs.append(f"--- binwalk ---\n{stdout.strip()}")

        output_text = "\n".join(outputs)
        return SkillResult(
            success=True,
            output=output_text,
            parsed_data={"file": file_path},
            findings=findings,
            commands_run=commands,
            duration_seconds=0.0,
        )

    # ------------------------------------------------------------------
    # Crypto (AI-assisted)
    # ------------------------------------------------------------------

    def _crypto_hint(self, params: dict) -> SkillResult:
        data: str = params.get("data", "")
        challenge: str = params.get("challenge", "unknown")

        if self.ai_router and data:
            prompt = (
                f"Analyze this ciphertext/crypto challenge data:\n{data}\n\n"
                f"Identify the cipher type, explain the pattern, and suggest "
                f"how to approach decryption. Don't solve it completely — "
                f"explain the method."
            )
            try:
                response = self.ai_router.route(prompt, task_type="explain")
                return SkillResult(
                    success=True,
                    output=response.text,
                    parsed_data={"data": data},
                    findings=[{
                        "type": "hint_used",
                        "value": "AI crypto analysis",
                        "challenge": challenge,
                        "method": "AI cipher analysis",
                    }],
                    commands_run=[],
                    duration_seconds=0.0,
                )
            except Exception as exc:
                logger.error("AI crypto hint failed: {}", exc)

        return SkillResult(
            success=False,
            output="[!] AI router not available or no data provided for crypto analysis.",
            parsed_data={},
            findings=[],
            commands_run=[],
            duration_seconds=0.0,
        )

    # ------------------------------------------------------------------
    # Web challenge
    # ------------------------------------------------------------------

    def _web_challenge(self, params: dict) -> SkillResult:
        url: str = params.get("url", params.get("data", ""))
        findings: List[Dict[str, Any]] = []
        commands: List[str] = []
        outputs: List[str] = []

        if not url:
            return SkillResult(False, "No URL provided.", {}, [], [], 0.0)

        # curl with verbose headers
        if _tool_available("curl"):
            cmd = ["curl", "-sI", "-L", "--max-time", "10", url]
            commands.append(" ".join(cmd))
            stdout, stderr, rc = _run(cmd, timeout=15)
            outputs.append(f"--- curl headers ---\n{stdout}")
            flags = _detect_flags(stdout)
            for flag in flags:
                findings.append({
                    "type": "flag",
                    "value": flag,
                    "challenge": params.get("challenge", "unknown"),
                    "method": "HTTP headers",
                })

            # Also get body
            cmd2 = ["curl", "-s", "-L", "--max-time", "10", url]
            commands.append(" ".join(cmd2))
            body, _, _ = _run(cmd2, timeout=15)
            flags = _detect_flags(body)
            for flag in flags:
                findings.append({
                    "type": "flag",
                    "value": flag,
                    "challenge": params.get("challenge", "unknown"),
                    "method": "HTTP response body",
                })
            # Check HTML comments
            comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
            for comment in comments:
                findings.append({
                    "type": "intermediate_finding",
                    "value": f"HTML comment: {comment.strip()[:200]}",
                    "challenge": params.get("challenge", "unknown"),
                    "method": "HTML comment extraction",
                })

        output_text = "\n".join(outputs)
        return SkillResult(
            success=True,
            output=output_text,
            parsed_data={"url": url},
            findings=findings,
            commands_run=commands,
            duration_seconds=0.0,
        )

    # ------------------------------------------------------------------
    # Reverse engineering
    # ------------------------------------------------------------------

    def _reversing(self, params: dict) -> SkillResult:
        file_path: str = params.get("file_path", "")
        findings: List[Dict[str, Any]] = []
        commands: List[str] = []
        outputs: List[str] = []

        if not file_path or not Path(file_path).exists():
            return SkillResult(False, f"File not found: {file_path}", {}, [], [], 0.0)

        # file type
        if _tool_available("file"):
            cmd = ["file", file_path]
            commands.append(" ".join(cmd))
            stdout, _, _ = _run(cmd)
            outputs.append(f"--- file ---\n{stdout.strip()}")

        # strings
        if _tool_available("strings"):
            cmd = ["strings", file_path]
            commands.append(" ".join(cmd))
            stdout, _, _ = _run(cmd, timeout=30)
            flags = _detect_flags(stdout)
            for flag in flags:
                findings.append({
                    "type": "flag",
                    "value": flag,
                    "challenge": params.get("challenge", "unknown"),
                    "method": "strings on binary",
                })
            interesting = [l.strip() for l in stdout.splitlines()
                          if len(l.strip()) > 4 and any(c.isalpha() for c in l)]
            outputs.append(f"--- strings --- ({len(interesting)} interesting)")
            # Show some notable strings
            for s in interesting[:30]:
                findings.append({
                    "type": "intermediate_finding",
                    "value": s[:200],
                    "challenge": params.get("challenge", "unknown"),
                    "method": "strings extraction",
                })

        # ltrace (dynamic analysis — only if binary is executable)
        if _tool_available("ltrace") and Path(file_path).stat().st_mode & 0o111:
            cmd = ["ltrace", "-e", "strcmp+strlen+puts+printf", file_path]
            commands.append(" ".join(cmd))
            stdout, stderr, rc = _run(cmd, timeout=10)
            combined = stdout + stderr
            outputs.append(f"--- ltrace ---\n{combined[:2000]}")
            flags = _detect_flags(combined)
            for flag in flags:
                findings.append({
                    "type": "flag",
                    "value": flag,
                    "challenge": params.get("challenge", "unknown"),
                    "method": "ltrace dynamic analysis",
                })

        output_text = "\n".join(outputs)
        return SkillResult(
            success=True,
            output=output_text,
            parsed_data={"file": file_path},
            findings=findings,
            commands_run=commands,
            duration_seconds=0.0,
        )

    # ------------------------------------------------------------------
    # AI Hint
    # ------------------------------------------------------------------

    def _hint(self, params: dict) -> SkillResult:
        challenge: str = params.get("challenge", params.get("data", "unknown"))
        current_findings: List[str] = params.get("current_findings", [])

        hint_text = self.get_hint(challenge, current_findings)

        return SkillResult(
            success=True,
            output=hint_text,
            parsed_data={"challenge": challenge},
            findings=[{
                "type": "hint_used",
                "value": hint_text[:200],
                "challenge": challenge,
                "method": "AI progressive hint",
            }],
            commands_run=[],
            duration_seconds=0.0,
        )
