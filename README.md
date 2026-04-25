<div align="center">
███╗ ██╗██╗ ██╗██╗ ██╗ ██████╗ ███████╗
████╗ ██║╚██╗ ██╔╝╚██╗██╔╝██╔═══██╗██╔════╝
██╔██╗ ██║ ╚████╔╝ ╚███╔╝ ██║ ██║███████╗
██║╚██╗██║ ╚██╔╝ ██╔██╗ ██║ ██║╚════██║
██║ ╚████║ ██║ ██╔╝ ██╗╚██████╔╝███████║
╚═╝ ╚═══╝ ╚═╝ ╚═╝ ╚═╝ ╚═════╝ ╚══════╝

text

### 🌙 The AI-Native Cybersecurity Operating System

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-red.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Skills: Apache 2.0](https://img.shields.io/badge/Skills-Apache%202.0-orange.svg)](https://opensource.org/licenses/Apache-2.0)
[![Base: Kali Linux](https://img.shields.io/badge/Base-Kali%20Linux-557C94?logo=kalilinux&logoColor=white)](https://kali.org)
[![Tests: 108 Passing](https://img.shields.io/badge/Tests-108%20Passing-brightgreen?logo=pytest&logoColor=white)](#testing)
[![AI Providers](https://img.shields.io/badge/AI-Claude%20%7C%20OpenAI%20%7C%20Gemini%20%7C%20Ollama-purple)](#ai-providers)

**Type plain English. Get expert-level security operations.**

[Quick Start](#-quick-start) •
[Features](#-features) •
[Architecture](#-architecture) •
[Skills](#-skills) •
[Documentation](#-documentation) •
[Contributing](#-contributing)

---

</div>

## 🎯 What is NyxOS?

NyxOS is a fully **AI-native cybersecurity operating system** built on top of Kali Linux. AI isn't bolted on — it's woven into every interaction. The shell, the package manager, the process manager, the reports, the onboarding — everything speaks human.
┌─────────────────────────────────────────────────────────────────┐
│ [nyx] pentester@nyxos ~/engagements/acme > │
│ │
│ > scan acme-corp.com for open ports and check for vulns │
│ │
│ 🧠 Planning: nmap service scan → vulnerability scripts │
│ 🔒 Safety: Target in scope ✓ | Risk: LOW │
│ ⚡ Running: nmap -sV --script vuln acme-corp.com │
│ │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ PORT STATE SERVICE VERSION │ │
│ │ 22/tcp open ssh OpenSSH 8.9p1 │ │
│ │ 80/tcp open http nginx 1.21.6 │ │
│ │ 443/tcp open https nginx 1.21.6 │ │
│ │ 8080/tcp open http-proxy Apache 2.4.49 │ │
│ └──────────────────────────────────────────────────────────┘ │
│ │
│ 📊 4 ports open | 2 findings: │
│ 🔴 HIGH: Apache 2.4.49 Path Traversal (CVE-2021-41773) │
│ 🟡 MED: Missing security headers on port 443 │
│ │
│ 💡 Suggested: "test the Apache path traversal on port 8080" │
│ │
│ > generate a pentest report │
│ 📝 Report saved to ~/.nyxos/exports/pentest_20250425.pdf │
└─────────────────────────────────────────────────────────────────┘

text

### The Core Flow
You type English → AI understands intent → Selects the right tool
→ Executes it → Analyzes output → Presents findings → Remembers everything

text

No more memorizing flags. No more parsing raw output. No more copy-pasting between tools. Just describe what you want to do.

---

## ⚡ Quick Start

```bash
# Clone
git clone https://github.com/nitinbeniwal/nyxos.git
cd nyxos

# Install (handles everything)
sudo ./install.sh

# Launch
./run.sh
On first launch, the onboarding wizard will guide you through:

Role selection — Pentester, Bug Bounty, Red Team, Blue Team, Forensics, CTF, DevSecOps, Researcher
Skill level — Beginner to Expert (adjusts AI verbosity)
AI provider setup — Bring your own API key or use local Ollama
✨ Features
🧠 AI-Powered Shell
Type natural language or traditional commands — NyxOS understands both.

bash
> find open ports on 192.168.1.1          # Natural language → nmap
> nmap -sV 192.168.1.1                     # Traditional → runs directly
> what vulnerabilities does Apache 2.4.49 have?  # Knowledge query
> !ls -la                                  # Bang prefix forces shell
🔧 Modular Skill System
Skills are AI capability modules that wrap security tools, optimize token usage, and produce standardized findings.

Skill	Tools	What It Does
Nmap	nmap	Port scanning, service detection, OS fingerprinting, vuln scripts
Web	gobuster, nikto, whatweb, sqlmap, ffuf	Web app scanning, directory enum, SQLi testing
Recon	whois, dig, theHarvester, amass, subfinder	OSINT, DNS enum, subdomain discovery
Forensics	volatility3, binwalk, exiftool, foremost, strings	Memory analysis, file carving, metadata extraction
CTF	Built-in + AI	Decode/encode, steganography, flag detection, AI hints
Password	john, hashcat	Hash identification, dictionary attacks, wordlist management
🤖 Multi-Provider AI (Zero Lock-in)
Choose your provider. Switch anytime. No lock-in. Ever.

Provider	Models	Type
Claude (Anthropic)	claude-sonnet-4-20250514, Haiku	Cloud API
OpenAI	GPT-4o, GPT-4o-mini	Cloud API
Google Gemini	Gemini Pro, Flash	Cloud API
Mistral	Mistral Large, Small	Cloud API
Ollama	Llama 3.1, Mistral, CodeLlama	100% Local
🧩 Agent Orchestration
Agents chain multiple skills together for complex objectives:

text
> do full recon on example.com

🧠 Planning reconnaissance...

📋 Plan (5 tasks, ~3 minutes):
  1. WHOIS lookup → Domain info
  2. DNS enumeration → Records
  3. Subdomain discovery → Attack surface
  4. Port scan → Services
  5. Technology detection → Stack

[1/5] WHOIS... ✅  Registrar: Namecheap
[2/5] DNS... ✅  12 records found
[3/5] Subdomains... ✅  7 subdomains
[4/5] Port scan... ✅  4 open ports
[5/5] Tech detect... ✅  nginx, PHP, WordPress

📊 23 findings stored | Report ready
🧠 Memory System
NyxOS learns how you work across three levels:

Level	Scope	Persistence	What It Remembers
Session	Current session	RAM only	Commands, targets, findings
Project	Per engagement	Disk	Scope, all findings, notes, timeline
User	Permanent	Disk	Preferred tools, corrections, work patterns
📊 Report Generation
AI-written professional reports in multiple formats:

Pentest Report — Full technical findings with evidence and remediation
Bug Bounty Report — Per-vulnerability reports ready for submission
Executive Summary — Business-language risk overview for management
CTF Writeup — Step-by-step solution documentation
Export to PDF (WeasyPrint) or Markdown.

🛡️ Security Built-in
SafetyGuard — Every command checked against scope before execution
Encryption — API keys encrypted at rest (Fernet AES)
Audit Logging — Every action logged (JSON lines)
Rate Limiting — Token abuse prevention
Scope Enforcement — Out-of-scope targets automatically blocked
No Auto-Exploit — Exploit suggestions only, never automatic execution
🌐 Web Dashboard
Real-time monitoring dashboard at localhost:8080:

Live terminal output
Scan progress visualization
Findings panel grouped by severity
WebSocket real-time updates
🔌 Plugin System
Extend NyxOS without modifying core code:

python
from nyxos.plugins.plugin_manager import BasePlugin

class SlackNotifier(BasePlugin):
    def on_finding(self, finding):
        if finding["severity"] in ["critical", "high"]:
            self.send_to_slack(finding)
🏗️ Architecture
text
┌─────────────────────────────────────────────────────────────┐
│                      User Input                              │
│              "scan target for open ports"                     │
└──────────────────────┬──────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  NyxShell                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐ │
│  │ Classify  │→│ AI Route  │→│ Safety   │→│ Execute      │ │
│  │ Input     │  │ Intent    │  │ Guard    │  │ Skill/Cmd   │ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────────┘ │
└──────────────────────┬──────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  Core Services                                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐ │
│  │ AI Engine │  │ Memory   │  │ Security │  │ Config      │ │
│  │ (Router)  │  │ Manager  │  │ (Audit)  │  │ (Settings)  │ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────────┘ │
└──────────────────────┬──────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  Skills & Agents                                              │
│  ┌──────┐┌─────┐┌───────┐┌──────────┐┌─────┐┌──────────┐   │
│  │ Nmap ││ Web ││ Recon ││Forensics ││ CTF ││ Password │   │
│  └──────┘└─────┘└───────┘└──────────┘└─────┘└──────────┘   │
│  ┌───────────┐┌──────────────┐┌───────────┐┌────────────┐   │
│  │TaskPlanner││ AttackChain  ││ReconAgent ││ReportAgent │   │
│  └───────────┘└──────────────┘└───────────┘└────────────┘   │
└──────────────────────────────────────────────────────────────┘
Project Structure
text
nyxos/
├── main.py                    # Entry point
├── install.sh                 # Beautiful installer
├── requirements.txt           # Python dependencies
│
├── nyxos/
│   ├── core/
│   │   ├── config/            # NyxConfig dataclass, settings
│   │   ├── security/          # Encryption, auth, safety guard, audit
│   │   ├── ai_engine/         # Provider adapters, router, cache, prompts
│   │   ├── memory/            # Session, project, user memory
│   │   ├── shell/             # NyxShell — the main AI shell
│   │   └── utils/
│   │
│   ├── skills/                # Modular tool wrappers
│   │   ├── nmap/              # Network scanning
│   │   ├── web/               # Web vulnerability scanning
│   │   ├── recon/             # OSINT & reconnaissance
│   │   ├── forensics/         # Digital forensics
│   │   ├── ctf/               # CTF challenge helper
│   │   └── password/          # Hash cracking
│   │
│   ├── agents/                # Multi-step AI orchestration
│   ├── reporting/             # Report engine + PDF/MD exporters
│   ├── dashboard/             # Web UI (FastAPI + vanilla JS)
│   ├── onboarding/            # First-run wizard
│   ├── plugins/               # Plugin system
│   └── tests/                 # 108 tests, all passing
│
├── docs/                      # Documentation
└── build/                     # Kali ISO remaster scripts
🤖 AI Providers
Cloud Providers (API Key Required)
Claude (Anthropic) — Recommended
OpenAI
Google Gemini
Local AI (No API Key, No Internet)
Ollama — 100% Offline
🔧 Skills
Built-in Skills
Every skill follows the same pattern: execute → parse → findings.

python
# All skills return standardized SkillResult
@dataclass
class SkillResult:
    success: bool              # Did the tool run?
    output: str                # Raw output
    parsed_data: dict          # Structured data
    findings: List[dict]       # Standardized findings
    commands_run: List[str]    # Commands executed
    duration_seconds: float    # Execution time

# All findings follow the same format
{
    "type": "vulnerability",
    "title": "Apache 2.4.49 Path Traversal",
    "severity": "high",        # critical|high|medium|low|info
    "description": "...",
    "evidence": "...",
    "recommendation": "...",
    "tool_used": "nmap",
    "timestamp": "2025-04-25T10:30:00Z"
}
Creating Custom Skills
bash
mkdir -p nyxos/skills/masscan
python
# nyxos/skills/masscan/masscan_skill.py
from nyxos.skills.base_skill import BaseSkill, SkillResult

class MasscanSkill(BaseSkill):
    name = "masscan"
    description = "High-speed port scanner"
    requires_tools = ["masscan"]
    keywords = ["masscan", "fast scan", "mass scan"]
    
    def execute(self, params):
        # Your implementation
        ...
    
    def get_commands(self, intent):
        ...
    
    def parse_output(self, raw):
        ...
Skills are auto-discovered. Just drop them in nyxos/skills/your_tool/ and restart.

See docs/SKILLS.md for the full guide.

🎭 Roles
NyxOS adapts its AI behavior based on your role:

Role	AI Behavior
Beginner	Explains everything, suggests safe commands, teaches as it goes
Bug Bounty	Focuses on web vulns, generates submission-ready reports
Pentester	Full methodology, chains tools, professional reporting
Red Team	Stealth-focused, OPSEC reminders, attack path optimization
Blue Team	Defensive focus, detection rules, incident response
Forensics	Evidence preservation, chain of custody, timeline analysis
CTF	Hints without spoilers, decode/encode, challenge categorization
DevSecOps	CI/CD integration, SAST/DAST, compliance checking
Researcher	Deep technical analysis, CVE research, exploit development
🧪 Testing
bash
# Run all tests
./test.sh

# Or manually
source .venv/bin/activate
pytest nyxos/tests/ -v

# With coverage
pytest nyxos/tests/ -v --cov=nyxos --cov-report=html
text
108 passed in 0.28s ✅

Tests cover:
├── test_integration.py    — End-to-end: input → AI → command → finding → report
├── test_shell.py          — Input classification, builtins, AI dispatch
├── test_skills.py         — All 6 skills with mocked subprocess output
├── test_memory.py         — Session/project/user memory + persistence
└── test_reporting.py      — Report generation, templates, PDF/MD export
📖 Documentation
Document	Description
README.md	This file — project overview
docs/INSTALL.md	Detailed installation guide
docs/SKILLS.md	Skill system reference & creation guide
docs/AGENTS.md	Agent orchestration system
docs/CONTRIBUTING.md	Contribution guidelines
🤝 Contributing
We welcome contributions! The easiest way to start:

Add a new skill — Wrap a Kali tool you love
Write a plugin — Slack notifier, Jira integration, etc.
Improve docs — Better examples, tutorials
Fix bugs — Check Issues
bash
# Fork, clone, branch
git clone https://github.com/YOUR_USERNAME/nyxos.git
cd nyxos
sudo ./install.sh
git checkout -b feature/my-skill

# Make changes, test, push
./test.sh
git push origin feature/my-skill
# Open a PR
See docs/CONTRIBUTING.md for the full guide.

🛡️ Ethical Usage
NyxOS is designed for authorized security testing only.

✅ Penetration testing with written authorization
✅ Bug bounty programs within scope
✅ CTF competitions
✅ Security research on your own systems
✅ Educational purposes
❌ Unauthorized access to systems
❌ Any illegal activity
The SafetyGuard system enforces scope boundaries, but you are responsible for ensuring you have authorization.

📋 Key Decisions
Decision	Choice	Why
Base OS	Kali Linux remaster	Don't reinvent the wheel — Kali has every tool
AI	Hybrid (cloud + local)	Flexibility, no vendor lock-in
Language	Python 3.12+	Security tool ecosystem, AI library support
Skills License	Apache 2.0	Encourage community + commercial skills
Core License	GPL v3	Keep the core open forever
Shell	Custom (prompt_toolkit + rich)	Full control over AI integration
Dashboard	FastAPI + vanilla JS	Lightweight, no heavy frontend framework
🗺️ Roadmap
 AI Shell with natural language understanding
 6 built-in skills (nmap, web, recon, forensics, CTF, password)
 Multi-provider AI (Claude, OpenAI, Gemini, Ollama)
 Memory system (session, project, user)
 Agent orchestration (task planner, attack chain)
 Report generation (PDF, Markdown)
 Web dashboard
 Plugin system
 108 tests passing
 Kali ISO remaster build
 More skills (Burp Suite, Metasploit, Wireshark)
 Collaborative multi-user mode
 AI model fine-tuning for security tasks
 Mobile companion app
📄 License
Core (nyxos/core/, nyxos/shell/, etc.) — GPL v3
Skills (nyxos/skills/) — Apache 2.0
Plugins (nyxos/plugins/) — Apache 2.0
👤 Author
Nitin Beniwal — @nitinbeniwal

NyxOS — Because security tools should speak human.

⭐ Star this repo if you find it useful!


