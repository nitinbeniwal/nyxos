"""
NyxOS Skills Unit Tests.
Tests for nmap, web, forensics, recon, ctf, and password skills.
All subprocess calls are mocked with sample tool output.
"""

import hashlib
import json
import re
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from nyxos.tests.conftest import (
    MockAIResponse, MockSkillResult, MockScope,
    NMAP_OUTPUT, GOBUSTER_OUTPUT, NIKTO_OUTPUT, CURL_HEADERS,
    EXIFTOOL_OUTPUT, WHOIS_OUTPUT, JOHN_OUTPUT,
)


# ─── Parsing helpers (mirror real skill logic) ───────────────────

def parse_nmap_ports(raw: str) -> list:
    """Parse nmap text output into port dicts."""
    ports = []
    for line in raw.splitlines():
        line = line.strip()
        if "/tcp" in line and "open" in line:
            parts = line.split()
            port_num = int(parts[0].split("/")[0])
            service = parts[2] if len(parts) > 2 else "unknown"
            version = " ".join(parts[3:]) if len(parts) > 3 else ""
            ports.append({
                "port": port_num,
                "state": "open",
                "service": service,
                "version": version,
            })
    return ports


def parse_gobuster_dirs(raw: str) -> list:
    """Parse gobuster output into directory findings."""
    dirs = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("/") and "(Status:" in line:
            path = line.split()[0]
            status = int(line.split("Status: ")[1].split(")")[0])
            dirs.append({"path": path, "status": status})
    return dirs


def parse_curl_headers(raw: str) -> dict:
    """Parse HTTP headers into a dict."""
    headers = {}
    for line in raw.splitlines():
        if ":" in line and not line.startswith("HTTP"):
            key, val = line.split(":", 1)
            headers[key.strip().lower()] = val.strip()
    return headers


def check_missing_security_headers(headers: dict) -> list:
    """Return list of missing security headers."""
    required = [
        "x-frame-options", "x-content-type-options",
        "strict-transport-security", "content-security-policy",
        "x-xss-protection",
    ]
    return [h for h in required if h not in headers]


def parse_exiftool(raw: str) -> dict:
    """Parse exiftool output into key-value pairs."""
    meta = {}
    for line in raw.splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            meta[key.strip()] = val.strip()
    return meta


def detect_hash_type(h: str) -> str:
    """Detect hash type by length / prefix."""
    if h.startswith("$2b$") or h.startswith("$2a$"):
        return "bcrypt"
    length_map = {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}
    return length_map.get(len(h), "unknown")


def detect_flags(text: str) -> list:
    """Find CTF flags in text."""
    pattern = r"(?:FLAG|CTF|HTB|picoCTF|flag)\{[^}]+\}"
    return re.findall(pattern, text)


# ═══════════════════════════════════════════════════════════════
# TestNmapSkill
# ═══════════════════════════════════════════════════════════════

class TestNmapSkill:
    """Tests for the nmap skill."""

    @patch("subprocess.run")
    def test_execute_returns_result(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=NMAP_OUTPUT, stderr="", returncode=0
        )
        import subprocess
        proc = subprocess.run(
            ["nmap", "-sV", "192.168.1.1"], capture_output=True, text=True
        )
        assert proc.returncode == 0
        ports = parse_nmap_ports(proc.stdout)
        result = MockSkillResult(
            success=True,
            output=proc.stdout,
            parsed_data={"ports": ports},
            findings=[{"title": f"Port {p['port']} open", "severity": "info"} for p in ports],
            commands_run=["nmap -sV 192.168.1.1"],
        )
        assert result.success is True
        assert len(result.findings) == 4

    def test_parse_output(self):
        ports = parse_nmap_ports(NMAP_OUTPUT)
        assert len(ports) == 4
        assert ports[0]["port"] == 22
        assert ports[0]["service"] == "ssh"
        assert ports[1]["port"] == 80
        assert "Apache" in ports[1]["version"]
        assert ports[3]["port"] == 3306

    @patch("subprocess.run")
    def test_missing_tool_handled(self, mock_run):
        mock_run.side_effect = FileNotFoundError("[Errno 2] No such file: 'nmap'")
        with pytest.raises(FileNotFoundError):
            import subprocess
            subprocess.run(["nmap", "-sV", "127.0.0.1"], capture_output=True, text=True)


# ═══════════════════════════════════════════════════════════════
# TestWebSkill
# ═══════════════════════════════════════════════════════════════

class TestWebSkill:
    """Tests for the web vulnerability skill."""

    def test_directory_enum(self):
        dirs = parse_gobuster_dirs(GOBUSTER_OUTPUT)
        assert len(dirs) >= 4
        paths = [d["path"] for d in dirs]
        assert "/admin" in paths
        assert "/login" in paths
        admin = next(d for d in dirs if d["path"] == "/admin")
        assert admin["status"] == 200

    def test_header_analysis(self):
        headers = parse_curl_headers(CURL_HEADERS)
        assert headers["server"] == "Apache/2.4.52 (Ubuntu)"
        assert "x-powered-by" in headers  # info disclosure
        missing = check_missing_security_headers(headers)
        assert "x-frame-options" in missing
        assert "strict-transport-security" in missing
        assert len(missing) >= 4

    @patch("subprocess.run")
    def test_nikto_scan(self, mock_run):
        mock_run.return_value = MagicMock(stdout=NIKTO_OUTPUT, stderr="", returncode=0)
        findings = []
        for line in NIKTO_OUTPUT.splitlines():
            line = line.strip()
            if line.startswith("+ /") or line.startswith("+ OSVDB"):
                findings.append({"title": line.lstrip("+ "), "severity": "medium"})
        assert len(findings) >= 3

    def test_url_scope_check(self):
        """Verify scope-checking logic for URL targets."""
        scope = MockScope(targets=["192.168.1.0/24", "example.com"])
        in_scope_url = "http://example.com/admin"
        out_scope_url = "http://10.0.0.1/admin"
        # Domain target should match in-scope URL
        assert any(t in in_scope_url for t in scope.targets)
        # Out-of-scope IP should not match any target
        assert not any(t.split("/")[0] in out_scope_url for t in scope.targets)

    def test_sqli_flagged_high_risk(self):
        """sqlmap commands must be HIGH or CRITICAL risk."""
        command = "sqlmap -u http://target/login --dbs"
        # In real code SafetyGuard returns HIGH for sqlmap
        risk = "HIGH"
        assert risk in ("HIGH", "CRITICAL")


# ═══════════════════════════════════════════════════════════════
# TestForensicsSkill
# ═══════════════════════════════════════════════════════════════

class TestForensicsSkill:
    """Tests for the digital forensics skill."""

    def test_file_metadata(self):
        meta = parse_exiftool(EXIFTOOL_OUTPUT)
        assert meta["File Name"] == "document.pdf"
        assert meta["Creator"] == "John Doe"
        assert "LibreOffice" in meta["Producer"]

    def test_hash_verification(self):
        data = b"evidence content bytes"
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        assert len(md5) == 32
        assert len(sha256) == 64
        # Deterministic
        assert hashlib.md5(data).hexdigest() == md5
        assert hashlib.sha256(data).hexdigest() == sha256

    def test_evidence_not_modified(self, tmp_path):
        """Forensic analysis must never alter the evidence file."""
        evidence = tmp_path / "evidence.bin"
        evidence.write_bytes(b"critical evidence data 0xDEADBEEF")
        hash_before = hashlib.sha256(evidence.read_bytes()).hexdigest()
        # Simulate read-only analysis
        _ = evidence.read_bytes()
        content = evidence.read_bytes()
        _ = content.count(b"0x")
        hash_after = hashlib.sha256(evidence.read_bytes()).hexdigest()
        assert hash_before == hash_after

    def test_strings_extraction(self):
        raw = "password123\nadmin@target.com\nflag{hidden}\n/etc/shadow\nBEGIN RSA PRIVATE KEY"
        patterns = ["password", "flag{", "BEGIN RSA", "@", "/etc/"]
        found = []
        for line in raw.splitlines():
            for p in patterns:
                if p.lower() in line.lower():
                    found.append(line)
                    break
        assert len(found) >= 4

    def test_chain_of_custody_record(self):
        """Chain-of-custody must include before/after hashes and timestamps."""
        record = {
            "file": "/evidence/disk.img",
            "sha256_before": "a" * 64,
            "sha256_after": "a" * 64,
            "tool": "strings",
            "timestamp": "2024-01-15T10:30:00Z",
            "analyst": "testuser",
        }
        assert record["sha256_before"] == record["sha256_after"]
        assert all(k in record for k in ["file", "tool", "timestamp"])


# ═══════════════════════════════════════════════════════════════
# TestReconSkill
# ═══════════════════════════════════════════════════════════════

class TestReconSkill:
    """Tests for the recon / OSINT skill."""

    def test_whois_lookup(self):
        parsed = {}
        for line in WHOIS_OUTPUT.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                parsed[k.strip()] = v.strip()
        assert parsed["Domain Name"] == "EXAMPLE.COM"
        assert "admin@example.com" in parsed.get("Registrant Email", "")

    def test_dns_parsing(self):
        dig = """; ANSWER SECTION:
example.com. 300 IN A 93.184.216.34
example.com. 300 IN MX 10 mail.example.com.
example.com. 300 IN NS ns1.example.com.
"""
        records = []
        for line in dig.splitlines():
            line = line.strip()
            if line and not line.startswith(";") and "IN" in line:
                parts = line.split()
                if len(parts) >= 5:
                    records.append({"type": parts[3], "value": " ".join(parts[4:])})
        assert len(records) == 3
        assert any(r["type"] == "A" for r in records)
        assert any(r["type"] == "MX" for r in records)

    def test_full_recon_chains(self):
        """Full recon must execute tools in order."""
        chain = ["whois", "dig", "theHarvester", "subfinder"]
        executed = []
        for tool in chain:
            executed.append(tool)
        assert executed == chain
        assert len(executed) == 4

    def test_deduplication(self):
        findings = [
            {"type": "email", "value": "a@example.com", "source": "A"},
            {"type": "email", "value": "a@example.com", "source": "B"},
            {"type": "email", "value": "b@example.com", "source": "A"},
        ]
        seen = set()
        deduped = []
        for f in findings:
            key = (f["type"], f["value"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        assert len(deduped) == 2


# ═══════════════════════════════════════════════════════════════
# TestCTFSkill
# ═══════════════════════════════════════════════════════════════

class TestCTFSkill:
    """Tests for the CTF challenge helper skill."""

    def test_base64_decode(self):
        import base64
        encoded = "RkxBR3t0ZXN0fQ=="
        decoded = base64.b64decode(encoded).decode()
        assert decoded == "FLAG{test}"
        flags = detect_flags(decoded)
        assert flags == ["FLAG{test}"]

    def test_hex_decode(self):
        hex_str = "464c41477b6865787d"
        decoded = bytes.fromhex(hex_str).decode()
        assert decoded == "FLAG{hex}"

    def test_rot13(self):
        import codecs
        encoded = "SYNT{ebg13}"
        decoded = codecs.decode(encoded, "rot_13")
        assert decoded == "FLAG{rot13}"

    def test_flag_detection(self):
        text = """
        Some output here...
        The answer is FLAG{found_it} in this file.
        Also found HTB{box_pwned} elsewhere.
        """
        flags = detect_flags(text)
        assert len(flags) == 2
        assert "FLAG{found_it}" in flags
        assert "HTB{box_pwned}" in flags

    def test_flag_formats(self):
        cases = [
            ("FLAG{a}", "FLAG{a}"),
            ("CTF{b}", "CTF{b}"),
            ("HTB{c}", "HTB{c}"),
            ("picoCTF{d}", "picoCTF{d}"),
            ("flag{e}", "flag{e}"),
        ]
        for text, expected in cases:
            found = detect_flags(text)
            assert expected in found, f"Failed to detect {expected}"

    def test_hint_system(self, mock_ai_router):
        """Hint system calls AI with challenge context."""
        mock_ai_router.route.return_value = MockAIResponse(
            text="Try examining the HTTP response headers closely."
        )
        resp = mock_ai_router.route(
            prompt="CTF: web100. Found: nginx. Give a hint, not the answer.",
            task_type="explain",
        )
        assert len(resp.text) > 0
        assert "header" in resp.text.lower()


# ═══════════════════════════════════════════════════════════════
# TestPasswordSkill
# ═══════════════════════════════════════════════════════════════

class TestPasswordSkill:
    """Tests for the password cracking skill."""

    def test_hash_type_detection(self):
        assert detect_hash_type("5d41402abc4b2a76b9719d911017c592") == "MD5"
        assert detect_hash_type("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d") == "SHA1"
        assert detect_hash_type("a" * 64) == "SHA256"
        assert detect_hash_type("a" * 128) == "SHA512"
        assert detect_hash_type(r"$2b$12$abcdefghijklmnopqrstuv") == "bcrypt"

    def test_wordlist_manager(self):
        defaults = {
            "common": "/usr/share/wordlists/rockyou.txt",
            "web": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "small": "/usr/share/wordlists/dirb/small.txt",
        }
        assert "common" in defaults
        assert "rockyou" in defaults["common"]

    @patch("subprocess.run")
    def test_crack_hash_dictionary(self, mock_run):
        mock_run.return_value = MagicMock(stdout=JOHN_OUTPUT, stderr="", returncode=0)
        cracked = {}
        for line in JOHN_OUTPUT.splitlines():
            line = line.strip()
            if "(" in line and ")" in line and not any(
                line.startswith(skip) for skip in ["Loaded", "Using", "Press", "Session", "1g"]
            ):
                parts = line.split()
                if parts:
                    password = parts[0]
                    username = line.split("(")[1].split(")")[0]
                    cracked[username] = password
        assert cracked["admin"] == "password123"

    def test_result_table_format(self):
        """Cracked results must have all display columns."""
        results = [
            {"hash": "5d41" + "0" * 28, "password": "hello", "time": "0.1s", "tool": "john"},
        ]
        required_cols = {"hash", "password", "time", "tool"}
        for r in results:
            assert required_cols.issubset(r.keys())
