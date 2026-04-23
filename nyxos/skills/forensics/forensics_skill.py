"""
NyxOS Digital Forensics Skill
Location: nyxos/skills/forensics/forensics_skill.py

CRITICAL: Original evidence files are NEVER modified.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

from nyxos.skills.base_skill import BaseSkill, SkillMetadata, SkillResult

DEFAULT_TIMEOUT = 300
VOLATILITY_TIMEOUT = 600
FOREMOST_TIMEOUT = 900
HEXDUMP_DEFAULT_BYTES = 256

INTENT_TOOL_MAP = {
    "memory": "volatility", "memory analysis": "volatility",
    "volatility": "volatility", "memdump": "volatility",
    "metadata": "exiftool", "file metadata": "exiftool",
    "exif": "exiftool", "exiftool": "exiftool",
    "binary": "binwalk", "binary analysis": "binwalk",
    "binwalk": "binwalk", "firmware": "binwalk",
    "carving": "foremost", "file carving": "foremost",
    "recover": "foremost", "foremost": "foremost",
    "deleted": "foremost", "deleted files": "foremost",
    "hash": "hash", "hash verification": "hash",
    "verify": "hash", "integrity": "hash", "checksum": "hash",
    "hex": "hexdump", "hex dump": "hexdump", "hexdump": "hexdump",
    "strings": "strings", "string extraction": "strings",
    "extract strings": "strings",
    "file type": "file", "file identification": "file",
    "identify": "file",
}


def _run_tool(cmd, timeout=DEFAULT_TIMEOUT):
    logger.debug("Executing: {}", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timed out after %ds" % timeout
    except FileNotFoundError:
        return -2, "", "Tool '%s' not installed" % cmd[0]
    except OSError as exc:
        return -3, "", str(exc)


@dataclass
class EvidenceIntegrity:
    file_path: str
    md5_before: str = ""
    sha256_before: str = ""
    md5_after: str = ""
    sha256_after: str = ""
    verified: bool = False

    def compute_hashes(self, label="before"):
        path = Path(self.file_path)
        if not path.is_file():
            return
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5.update(chunk)
                    sha256.update(chunk)
        except OSError:
            return
        if label == "before":
            self.md5_before = md5.hexdigest()
            self.sha256_before = sha256.hexdigest()
        else:
            self.md5_after = md5.hexdigest()
            self.sha256_after = sha256.hexdigest()

    def verify(self):
        if not self.md5_before or not self.md5_after:
            return True
        self.verified = (self.md5_before == self.md5_after and
                         self.sha256_before == self.sha256_after)
        if not self.verified:
            logger.error("EVIDENCE INTEGRITY VIOLATION: {}", self.file_path)
        return self.verified

    def to_dict(self):
        return {
            "file_path": self.file_path,
            "md5_before": self.md5_before, "sha256_before": self.sha256_before,
            "md5_after": self.md5_after, "sha256_after": self.sha256_after,
            "verified": str(self.verified),
        }


class ForensicsSkill(BaseSkill):
    """Digital forensics skill. Never modifies original evidence."""

    def __init__(self):
        self._tools = {}
        self._check_tools()
        super().__init__()

    def _check_tools(self):
        for tool in ["vol3", "volatility3", "vol", "strings", "binwalk",
                      "exiftool", "file", "hexdump", "foremost", "md5sum", "sha256sum"]:
            self._tools[tool] = shutil.which(tool) is not None
        self._tools["volatility"] = any(
            self._tools.get(n, False) for n in ("vol3", "volatility3", "vol")
        )

    def _ensure_tool(self, tool):
        if not self._tools.get(tool, False):
            return "Tool '%s' not installed." % tool
        return None

    def _vol_bin(self):
        for n in ("vol3", "volatility3", "vol"):
            if self._tools.get(n, False):
                return n
        return "vol3"

    def get_metadata(self):
        return SkillMetadata(
            name="forensics", version="1.0.0",
            description="AI-powered digital forensics analysis",
            author="NyxOS Team", category="forensics",
            tags=["forensics", "memory", "volatility", "strings", "binwalk",
                  "exiftool", "metadata", "carving", "foremost", "hash",
                  "hexdump", "evidence", "malware", "analysis"],
            min_model_capability="any",
            requires_tools=["strings", "file", "hexdump", "md5sum", "sha256sum"],
            requires_root=False, risk_level="low",
            estimated_tokens=800, license="Apache-2.0",
        )

    def get_system_prompt(self):
        return (
            "You are NyxAI's digital forensics specialist.\n"
            "Tools: volatility3, exiftool, binwalk, foremost, strings, file, hexdump, md5sum/sha256sum.\n"
            "RULES:\n"
            "1. NEVER modify original evidence\n"
            "2. Record hashes BEFORE and AFTER analysis\n"
            "3. Flag suspicious processes, connections, artifacts\n"
            "4. Suspicious: mimikatz, meterpreter, nc.exe, psexec, powershell -enc\n"
            "5. Suspicious paths: temp, downloads, appdata"
        )

    def execute(self, user_input, context):
        start = time.time()
        file_path_str = context.get("file_path", context.get("target", ""))
        if not file_path_str:
            return SkillResult(success=False, output="No file_path in context.", error="No file_path")

        file_path = Path(file_path_str).expanduser().resolve()
        if not file_path.exists():
            return SkillResult(success=False, output="Not found: %s" % file_path, error="Not found")

        integrity = EvidenceIntegrity(file_path=str(file_path))
        integrity.compute_hashes("before")

        tool_key = self._resolve_intent(user_input)
        logger.info("ForensicsSkill: '{}' -> '{}'", user_input, tool_key)

        dispatch = {
            "volatility": self._run_volatility, "exiftool": self._run_exiftool,
            "binwalk": self._run_binwalk, "foremost": self._run_foremost,
            "hash": self._run_hash, "hexdump": self._run_hexdump,
            "strings": self._run_strings, "file": self._run_file,
        }

        handler = dispatch.get(tool_key)
        if handler is None:
            keys = ", ".join(dispatch.keys())
            return SkillResult(success=False,
                output="Unknown intent. Supported: %s" % keys,
                error="Unknown: %s" % user_input)

        try:
            result = handler(file_path, context)
        except Exception as exc:
            logger.exception("Error: {}", exc)
            return SkillResult(success=False, output=str(exc), error=str(exc))

        integrity.compute_hashes("after")
        integrity.verify()
        result.structured_data["evidence_integrity"] = integrity.to_dict()

        if not integrity.verified and integrity.md5_after:
            result.findings.append({
                "type": "artifact", "severity": "critical",
                "title": "EVIDENCE INTEGRITY VIOLATION",
                "description": "Modified! MD5 before:%s after:%s" % (
                    integrity.md5_before, integrity.md5_after),
                "evidence_path": str(file_path),
                "timestamp": self._now(), "tool_used": tool_key,
            })

        result.execution_time = round(time.time() - start, 2)
        return result

    def parse_output(self, raw_output):
        return {
            "line_count": len(raw_output.splitlines()),
            "ips": list(set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", raw_output))),
            "urls": list(set(re.findall(r"https?://\S+", raw_output))),
        }

    @staticmethod
    def _resolve_intent(user_input):
        lower = user_input.lower().strip()
        if lower in INTENT_TOOL_MAP:
            return INTENT_TOOL_MAP[lower]
        for kw, tool in INTENT_TOOL_MAP.items():
            if kw in lower:
                return tool
        return lower

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _output_dir(context):
        explicit = context.get("output_dir", "")
        if explicit:
            out = Path(explicit).expanduser().resolve()
        else:
            proj = context.get("project_name", "default")
            out = Path.home() / ".nyxos" / "projects" / proj / "evidence"
        out.mkdir(parents=True, exist_ok=True)
        return out

    def _fail(self, msg):
        logger.error("ForensicsSkill: {}", msg)
        return SkillResult(success=False, output=msg, error=msg)

    # === VOLATILITY ===

    def _run_volatility(self, file_path, context):
        err = self._ensure_tool("volatility")
        if err:
            return self._fail(err)
        vol = self._vol_bin()
        plugin = context.get("volatility_plugin", "windows.pslist.PsList")
        out_dir = self._output_dir(context)
        cmd = [vol, "-f", str(file_path), plugin]
        rc, stdout, stderr = _run_tool(cmd, timeout=VOLATILITY_TIMEOUT)
        combined = stdout + "\n" + stderr
        if rc < -1:
            return self._fail(stderr)
        out_file = out_dir / ("vol_%s_%d.txt" % (plugin.replace(".", "_"), int(time.time())))
        try:
            out_file.write_text(combined, encoding="utf-8")
        except OSError:
            pass
        findings = self._parse_vol(combined, plugin, str(out_file))
        return SkillResult(success=rc >= 0 or bool(findings), output=combined,
            structured_data={"tool": "volatility3", "plugin": plugin},
            commands_executed=[" ".join(cmd)], findings=findings)

    @staticmethod
    def _parse_vol(raw, plugin, out_path):
        findings = []
        now = datetime.now(timezone.utc).isoformat()
        pl = plugin.lower()
        bad_procs = ["cmd.exe", "powershell", "mimikatz", "meterpreter",
                     "nc.exe", "netcat", "psexec", "procdump", "lazagne"]

        if "pslist" in pl or "pstree" in pl:
            hdr = False
            for line in raw.splitlines():
                s = line.strip()
                if "PID" in s and "PPID" in s:
                    hdr = True
                    continue
                if not hdr or not s:
                    continue
                p = s.split()
                if len(p) < 3:
                    continue
                pid, ppid, name = p[0], p[1], p[2]
                sev = "high" if name.lower() in bad_procs else "info"
                findings.append({
                    "type": "artifact", "severity": sev,
                    "title": "Process: %s (PID:%s)" % (name, pid),
                    "description": "%s PID:%s PPID:%s" % (name, pid, ppid),
                    "evidence_path": out_path, "timestamp": now,
                    "tool_used": "volatility3",
                })

        elif "netscan" in pl:
            hdr = False
            for line in raw.splitlines():
                s = line.strip()
                if "Offset" in s and "Local" in s:
                    hdr = True
                    continue
                if not hdr or not s:
                    continue
                p = s.split()
                if len(p) < 5:
                    continue
                local = p[2] if len(p) > 2 else "?"
                foreign = p[4] if len(p) > 4 else "?"
                state = p[6] if len(p) > 6 else "?"
                owner = p[-1] if len(p) > 7 else "?"
                sev = "info"
                if state.upper() == "ESTABLISHED":
                    sev = "medium"
                priv = ("*", "0.0.0.0", "::", "127.", "10.", "192.168.")
                if not any(foreign.startswith(x) for x in priv):
                    sev = "high"
                findings.append({
                    "type": "artifact", "severity": sev,
                    "title": "%s -> %s (%s)" % (local, foreign, state),
                    "description": "Process '%s': %s to %s" % (owner, state, foreign),
                    "evidence_path": out_path, "timestamp": now,
                    "tool_used": "volatility3",
                })

        elif "cmdline" in pl:
            susp = ["-enc", "encodedcommand", "downloadstring", "bypass",
                    "hidden", "iex(", "certutil"]
            for line in raw.splitlines():
                s = line.strip()
                if not s or ("PID" in s and "Process" in s):
                    continue
                parts = s.split(None, 2)
                if len(parts) < 3:
                    continue
                pid, proc, cmdline = parts[0], parts[1], parts[2]
                sev = "info"
                for a in susp:
                    if a in cmdline.lower():
                        sev = "critical"
                        break
                ftype = "malware_indicator" if sev == "critical" else "artifact"
                findings.append({
                    "type": ftype, "severity": sev,
                    "title": "CmdLine: %s (PID:%s)" % (proc, pid),
                    "description": "Command: %s" % cmdline[:500],
                    "evidence_path": out_path, "timestamp": now,
                    "tool_used": "volatility3",
                })

        elif "malfind" in pl:
            for block in re.split(r"(?=Process:)", raw):
                m = re.search(r"Process:\s+(\S+)\s+Pid:\s+(\d+)", block)
                if m:
                    findings.append({
                        "type": "malware_indicator", "severity": "critical",
                        "title": "Injection: %s PID:%s" % (m.group(1), m.group(2)),
                        "description": "Malfind detected in '%s'" % m.group(1),
                        "evidence_path": out_path, "timestamp": now,
                        "tool_used": "volatility3",
                    })
        else:
            lc = len([l for l in raw.splitlines() if l.strip()])
            if lc > 2:
                findings.append({
                    "type": "artifact", "severity": "info",
                    "title": "Plugin '%s': %d lines" % (plugin, lc),
                    "description": "Review output file.",
                    "evidence_path": out_path, "timestamp": now,
                    "tool_used": "volatility3",
                })
        return findings

    # === EXIFTOOL ===

    def _run_exiftool(self, file_path, context):
        err = self._ensure_tool("exiftool")
        if err:
            return self._fail(err)
        cmd = ["exiftool", "-json", "-G", str(file_path)]
        rc, stdout, stderr = _run_tool(cmd)
        if rc < -1:
            return self._fail(stderr)
        metadata = {}
        try:
            parsed = json.loads(stdout)
            if isinstance(parsed, list) and parsed:
                metadata = parsed[0]
        except (json.JSONDecodeError, TypeError, IndexError):
            metadata = {"raw": stdout[:2000]}
        findings = []
        now = self._now()
        interesting = {
            "GPS": ("GPS found", "medium"), "Author": ("Author", "low"),
            "Creator": ("Creator", "low"), "Software": ("Software", "info"),
            "Company": ("Company", "low"), "Computer": ("Computer", "medium"),
            "User": ("User", "low"),
        }
        for key, val in metadata.items():
            if not val or str(val).strip() in ("-", "", "n/a"):
                continue
            clean = key.split(":")[-1].strip() if ":" in key else key
            for pat, (desc, sev) in interesting.items():
                if pat.lower() in clean.lower():
                    findings.append({
                        "type": "artifact",
                        "severity": sev,
                        "title": "%s: %s" % (desc, clean),
                        "description": "%s: %s" % (clean, str(val)[:500]),
                        "evidence_path": str(file_path),
                        "timestamp": now,
                        "tool_used": "exiftool",
                    })
                    break

        ft = metadata.get("File:FileType", metadata.get("FileType", "unknown"))
        mime = metadata.get("File:MIMEType", metadata.get("MIMEType", "unknown"))
        findings.insert(0, {
            "type": "artifact",
            "severity": "info",
            "title": "File type: %s (%s)" % (ft, mime),
            "description": "%s: %s %s, %d fields" % (file_path.name, ft, mime, len(metadata)),
            "evidence_path": str(file_path),
            "timestamp": now,
            "tool_used": "exiftool",
        })

        return SkillResult(
            success=True,
            output=stdout,
            structured_data={"tool": "exiftool", "file": str(file_path), "metadata": metadata},
            commands_executed=[" ".join(cmd)],
            findings=findings,
        )

    # === BINWALK ===

    def _run_binwalk(self, file_path, context):
        """Binary/firmware analysis. Extract works on copies only."""
        err = self._ensure_tool("binwalk")
        if err:
            return self._fail(err)

        do_extract = context.get("extract", False)
        out_dir = self._output_dir(context)

        if do_extract:
            copy_path = out_dir / ("copy_%s" % file_path.name)
            try:
                shutil.copy2(str(file_path), str(copy_path))
            except OSError as exc:
                return self._fail("Copy failed: %s" % exc)
            cmd = ["binwalk", "-e", "--directory", str(out_dir), str(copy_path)]
        else:
            cmd = ["binwalk", str(file_path)]

        rc, stdout, stderr = _run_tool(cmd)
        if rc < -1:
            return self._fail(stderr)

        findings = []
        now = self._now()
        suspicious_types = [
            "executable", "elf", "pe32", "shellcode",
            "encrypted", "private key",
        ]
        header_found = False

        for line in stdout.splitlines():
            s = line.strip()
            if "DECIMAL" in s and "HEXADECIMAL" in s:
                header_found = True
                continue
            if not header_found or not s or s.startswith("-"):
                continue
            parts = s.split(None, 2)
            if len(parts) < 3:
                continue
            off_dec, off_hex, desc = parts[0], parts[1], parts[2]
            sev = "info"
            for st in suspicious_types:
                if st in desc.lower():
                    sev = "medium"
                    break
            findings.append({
                "type": "artifact",
                "severity": sev,
                "title": "Sig at %s: %s" % (off_hex, desc[:80]),
                "description": "Offset %s (%s): %s" % (off_dec, off_hex, desc),
                "evidence_path": str(file_path),
                "timestamp": now,
                "tool_used": "binwalk",
            })

        return SkillResult(
            success=True,
            output=stdout + "\n" + stderr,
            structured_data={
                "tool": "binwalk",
                "file": str(file_path),
                "signatures": len(findings),
            },
            commands_executed=[" ".join(cmd)],
            findings=findings,
        )

    # === FOREMOST ===

    def _run_foremost(self, file_path, context):
        """File carving / recovery. Reads input, writes to output dir."""
        err = self._ensure_tool("foremost")
        if err:
            return self._fail(err)

        out_dir = self._output_dir(context)
        carve_dir = out_dir / ("foremost_%d" % int(time.time()))
        carve_dir.mkdir(parents=True, exist_ok=True)

        cmd = ["foremost", "-i", str(file_path), "-o", str(carve_dir), "-T"]
        rc, stdout, stderr = _run_tool(cmd, timeout=FOREMOST_TIMEOUT)
        if rc < -1:
            return self._fail(stderr)

        findings = []
        now = self._now()

        for root, dirs, files in os.walk(str(carve_dir)):
            for fname in files:
                if fname == "audit.txt":
                    continue
                fpath = Path(root) / fname
                rel = Path(root).relative_to(carve_dir)
                ftype = str(rel) if str(rel) != "." else "unknown"
                try:
                    fsize = fpath.stat().st_size
                except OSError:
                    fsize = 0
                findings.append({
                    "type": "deleted_file",
                    "severity": "medium",
                    "title": "Recovered %s: %s" % (ftype, fname),
                    "description": "Carved '%s' (%d bytes) from %s" % (
                        fname, fsize, file_path.name),
                    "evidence_path": str(fpath),
                    "timestamp": now,
                    "tool_used": "foremost",
                })

        return SkillResult(
            success=True,
            output=stdout + "\n" + stderr,
            structured_data={
                "tool": "foremost",
                "carved": len(findings),
                "output_dir": str(carve_dir),
            },
            commands_executed=[" ".join(cmd)],
            findings=findings,
        )

    # === HASH ===

    def _run_hash(self, file_path, context):
        """Compute MD5, SHA1, SHA256 hashes for integrity verification."""
        cmds_run = []
        tool_outputs = []

        if self._tools.get("md5sum", False):
            cmd = ["md5sum", str(file_path)]
            rc, stdout, stderr = _run_tool(cmd, timeout=60)
            cmds_run.append(" ".join(cmd))
            if stdout.strip():
                tool_outputs.append(stdout.strip())

        if self._tools.get("sha256sum", False):
            cmd = ["sha256sum", str(file_path)]
            rc, stdout, stderr = _run_tool(cmd, timeout=60)
            cmds_run.append(" ".join(cmd))
            if stdout.strip():
                tool_outputs.append(stdout.strip())

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
        except OSError as exc:
            return self._fail("Cannot read file: %s" % exc)

        md5_hex = md5.hexdigest()
        sha1_hex = sha1.hexdigest()
        sha256_hex = sha256.hexdigest()
        fsize = file_path.stat().st_size

        output_text = (
            "File:   %s\n"
            "Size:   %d bytes\n"
            "MD5:    %s\n"
            "SHA1:   %s\n"
            "SHA256: %s\n"
        ) % (file_path, fsize, md5_hex, sha1_hex, sha256_hex)

        if tool_outputs:
            output_text += "\n" + "\n".join(tool_outputs)

        findings = [{
            "type": "artifact",
            "severity": "info",
            "title": "Hash: %s" % file_path.name,
            "description": "MD5:%s SHA1:%s SHA256:%s Size:%d" % (
                md5_hex, sha1_hex, sha256_hex, fsize),
            "evidence_path": str(file_path),
            "timestamp": self._now(),
            "tool_used": "hash",
        }]

        return SkillResult(
            success=True,
            output=output_text,
            structured_data={
                "tool": "hash",
                "file": str(file_path),
                "file_size": fsize,
                "md5": md5_hex,
                "sha1": sha1_hex,
                "sha256": sha256_hex,
            },
            commands_executed=cmds_run,
            findings=findings,
        )

    # === HEXDUMP ===

    def _run_hexdump(self, file_path, context):
        """Hex dump of first N bytes with magic byte detection."""
        err = self._ensure_tool("hexdump")
        if err:
            return self._fail(err)

        num_bytes = int(context.get("num_bytes", HEXDUMP_DEFAULT_BYTES))
        cmd = ["hexdump", "-C", "-n", str(num_bytes), str(file_path)]
        rc, stdout, stderr = _run_tool(cmd, timeout=30)
        if rc < -1:
            return self._fail(stderr)

        findings = []
        now = self._now()

        magic_sigs = {
            "4d5a": ("PE executable (MZ header)", "medium"),
            "7f454c46": ("ELF executable", "medium"),
            "504b0304": ("ZIP archive", "info"),
            "25504446": ("PDF document", "info"),
            "ffd8ff": ("JPEG image", "info"),
            "89504e47": ("PNG image", "info"),
            "47494638": ("GIF image", "info"),
            "52617221": ("RAR archive", "info"),
            "1f8b08": ("Gzip compressed", "info"),
            "cafebabe": ("Java class / Mach-O fat binary", "medium"),
            "d0cf11e0": ("MS OLE compound document", "info"),
        }

        hex_bytes = ""
        for line in stdout.splitlines():
            parts = line.strip().split("|")[0].split()
            if parts and len(parts) > 1:
                hex_bytes += "".join(parts[1:])
                if len(hex_bytes) >= 16:
                    break

        hex_lower = hex_bytes.lower()
        for sig, (desc, sev) in magic_sigs.items():
            if hex_lower.startswith(sig):
                findings.append({
                    "type": "artifact",
                    "severity": sev,
                    "title": "File type: %s" % desc,
                    "description": "Magic bytes %s match: %s" % (sig, desc),
                    "evidence_path": str(file_path),
                    "timestamp": now,
                    "tool_used": "hexdump",
                })
                break

        findings.append({
            "type": "artifact",
            "severity": "info",
            "title": "Hex dump: %s (first %d bytes)" % (file_path.name, num_bytes),
            "description": "Hex dump generated for forensic review.",
            "evidence_path": str(file_path),
            "timestamp": now,
            "tool_used": "hexdump",
        })

        return SkillResult(
            success=True,
            output=stdout,
            structured_data={
                "tool": "hexdump",
                "file": str(file_path),
                "bytes_dumped": num_bytes,
            },
            commands_executed=[" ".join(cmd)],
            findings=findings,
        )

    # === STRINGS ===

    def _run_strings(self, file_path, context):
        """Extract readable strings from binary files."""
        err = self._ensure_tool("strings")
        if err:
            return self._fail(err)

        min_len = str(context.get("min_length", 4))

        cmd_ascii = ["strings", "-a", "-n", min_len, str(file_path)]
        rc, stdout_ascii, stderr = _run_tool(cmd_ascii)
        if rc < -1:
            return self._fail(stderr)

        cmd_wide = ["strings", "-el", "-n", min_len, str(file_path)]
        rc_w, stdout_wide, stderr_w = _run_tool(cmd_wide)

        combined = stdout_ascii
        commands = [" ".join(cmd_ascii)]
        if rc_w >= 0 and stdout_wide.strip():
            combined += "\n--- Wide strings (UTF-16) ---\n" + stdout_wide
            commands.append(" ".join(cmd_wide))

        findings = self._parse_strings_output(combined, str(file_path))

        ascii_count = len(stdout_ascii.strip().splitlines()) if stdout_ascii else 0
        wide_count = len(stdout_wide.strip().splitlines()) if stdout_wide else 0

        return SkillResult(
            success=True,
            output=combined,
            structured_data={
                "tool": "strings",
                "file": str(file_path),
                "ascii_strings": ascii_count,
                "wide_strings": wide_count,
                "total_strings": ascii_count + wide_count,
            },
            commands_executed=commands,
            findings=findings,
        )

    @staticmethod
    def _parse_strings_output(raw, file_path):
        """Scan extracted strings for suspicious patterns."""
        findings = []
        now = datetime.now(timezone.utc).isoformat()

        patterns = {
            "url": (
                re.compile(r"https?://\S+", re.IGNORECASE),
                "URL found", "medium",
            ),
            "ip": (
                re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
                "IP address found", "medium",
            ),
            "email": (
                re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
                "Email found", "medium",
            ),
            "registry": (
                re.compile(r"HKEY_[A-Z_]+\\[\\\w]+", re.IGNORECASE),
                "Registry key", "medium",
            ),
            "winpath": (
                re.compile(r"[A-Z]:\\[\w\\. -]+", re.IGNORECASE),
                "Windows path", "low",
            ),
            "password": (
                re.compile(
                    r"(?:password|passwd|pwd|secret|api.?key)\s*[:=]",
                    re.IGNORECASE,
                ),
                "Credential keyword", "high",
            ),
            "base64": (
                re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
                "Possible Base64 data", "medium",
            ),
            "shell": (
                re.compile(
                    r"(?:/bin/(?:sh|bash|zsh)|cmd\.exe|powershell)",
                    re.IGNORECASE,
                ),
                "Shell reference", "medium",
            ),
            "crypto": (
                re.compile(
                    r"(?:AES|RSA|DES|BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY)",
                    re.IGNORECASE,
                ),
                "Crypto reference", "high",
            ),
        }

        seen = {k: set() for k in patterns}
        max_per_pattern = 10

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            for pname, (regex, title, sev) in patterns.items():
                if len(seen[pname]) >= max_per_pattern:
                    continue
                for match in regex.findall(line):
                    match_str = match if isinstance(match, str) else str(match)
                    if match_str in seen[pname]:
                        continue
                    seen[pname].add(match_str)
                    findings.append({
                        "type": "artifact",
                        "severity": sev,
                        "title": "%s: %s" % (title, match_str[:80]),
                        "description": "%s: %s" % (pname, match_str[:200]),
                        "evidence_path": file_path,
                        "timestamp": now,
                        "tool_used": "strings",
                    })

        total_lines = len([l for l in raw.splitlines() if l.strip()])
        total_interesting = sum(len(v) for v in seen.values())
        findings.insert(0, {
            "type": "artifact",
            "severity": "info",
            "title": "Strings: %d from %s" % (total_lines, Path(file_path).name),
            "description": "%d strings extracted, %d interesting patterns." % (
                total_lines, total_interesting),
            "evidence_path": file_path,
            "timestamp": now,
            "tool_used": "strings",
        })

        return findings

    # === FILE ===

    def _run_file(self, file_path, context):
        """File type identification using the file command."""
        err = self._ensure_tool("file")
        if err:
            return self._fail(err)

        cmd_mime = ["file", "-b", "--mime", str(file_path)]
        rc_m, stdout_mime, stderr_m = _run_tool(cmd_mime, timeout=30)

        cmd_desc = ["file", "-b", str(file_path)]
        rc_d, stdout_desc, stderr_d = _run_tool(cmd_desc, timeout=30)

        output = "MIME: %s\nDescription: %s" % (
            stdout_mime.strip(), stdout_desc.strip()
        )

        sev = "info"
        suspicious_indicators = [
            "executable", "elf", "pe32", "mach-o",
            "shellcode", "script", "batch", "dll",
        ]
        for indicator in suspicious_indicators:
            if indicator in stdout_desc.lower():
                sev = "medium"
                break

        findings = [{
            "type": "artifact",
            "severity": sev,
            "title": "File type: %s" % stdout_desc.strip()[:100],
            "description": "File: %s\nMIME: %s\nDescription: %s" % (
                file_path.name, stdout_mime.strip(), stdout_desc.strip()),
            "evidence_path": str(file_path),
            "timestamp": self._now(),
            "tool_used": "file",
        }]

        return SkillResult(
            success=True,
            output=output,
            structured_data={
                "tool": "file",
                "file": str(file_path),
                "mime_type": stdout_mime.strip(),
                "description": stdout_desc.strip(),
            },
            commands_executed=[" ".join(cmd_mime), " ".join(cmd_desc)],
            findings=findings,
        )
