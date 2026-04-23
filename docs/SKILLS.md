# NyxOS Skills Reference

Skills are modular AI capability modules that wrap cybersecurity tools.

## Available Skills

| Skill | Tools Wrapped | Category |
|-------|--------------|----------|
| **NmapSkill** | nmap | Network Scanning |
| **WebSkill** | gobuster, nikto, whatweb, curl, sqlmap, ffuf, wfuzz | Web Testing |
| **ForensicsSkill** | volatility3, strings, binwalk, exiftool, foremost, hexdump | Forensics |
| **ReconSkill** | whois, dig, theHarvester, amass, subfinder, shodan | OSINT / Recon |
| **CTFSkill** | base64, steghide, binwalk, strings, file | CTF Challenges |
| **PasswordSkill** | john, hashcat | Password Cracking |

## Using Skills

### From the Shell
scan 192.168.1.1 # NmapSkill auto-selected
web scan http://target.com # WebSkill
recon target.com # ReconSkill
crack hash 5f4dcc3b5aa765d61d83... # PasswordSkill

text

### Natural Language
"scan this target for open ports"
"find subdomains of example.com"
"analyze this memory dump"
"decode this base64 string"

text

## Creating Custom Skills

See [CONTRIBUTING.md](CONTRIBUTING.md) for step-by-step instructions.

## Skill Architecture
nyxos/skills/
├── base_skill.py # BaseSkill abstract class
├── skill_manager.py # Discovery + routing
├── nmap/nmap_skill.py # Network scanning
├── web/web_skill.py # Web application testing
├── forensics/forensics_skill.py # Digital forensics
├── recon/recon_skill.py # OSINT and reconnaissance
├── ctf/ctf_skill.py # CTF challenge helpers
└── password/password_skill.py # Password cracking

text

Each skill returns a `SkillResult` with:
- `success`: bool
- `output`: raw terminal output
- `parsed_data`: structured data dict
- `findings`: list of finding dicts
- `commands_run`: exact commands executed
- `duration_seconds`: execution time
EOF
