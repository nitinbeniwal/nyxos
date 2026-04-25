<div align="center">

```
                                                   ███╗   ██╗██╗   ██╗██╗  ██╗ ██████╗ ███████╗
                                                   ████╗  ██║╚██╗ ██╔╝╚██╗██╔╝██╔═══██╗██╔════╝
                                                   ██╔██╗ ██║ ╚████╔╝  ╚███╔╝ ██║   ██║███████╗
                                                   ██║╚██╗██║  ╚██╔╝   ██╔██╗ ██║   ██║╚════██║
                                                   ██║ ╚████║   ██║   ██╔╝ ██╗╚██████╔╝███████║
                                                   ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

### 🌙 The World's First AI-Native Cybersecurity Operating System

<br/>

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: GPL v3](https://img.shields.io/badge/License-GPL_v3-EF3B2D?style=for-the-badge)](https://www.gnu.org/licenses/gpl-3.0)
[![Skills: Apache 2.0](https://img.shields.io/badge/Skills-Apache_2.0-FF6B35?style=for-the-badge)](https://opensource.org/licenses/Apache-2.0)
[![Base: Kali Linux](https://img.shields.io/badge/Base-Kali_Linux-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white)](https://kali.org)

[![Tests: 108 Passing](https://img.shields.io/badge/Tests-108_Passing-00D26A?style=for-the-badge&logo=pytest&logoColor=white)](#-testing)
[![AI Providers](https://img.shields.io/badge/AI-Claude_%7C_OpenAI_%7C_Gemini_%7C_Ollama-7B2FBE?style=for-the-badge)](#-ai-providers)
[![Stars](https://img.shields.io/github/stars/nitinbeniwal/nyxos?style=for-the-badge&color=FFD700)](https://github.com/nitinbeniwal/nyxos/stargazers)

<br/>

**Type plain English. Get expert-level security operations.**

<br/>

[⚡ Quick Start](#-quick-start) &nbsp;•&nbsp;
[✨ Features](#-features) &nbsp;•&nbsp;
[🏗️ Architecture](#️-architecture) &nbsp;•&nbsp;
[🔧 Skills](#-skills) &nbsp;•&nbsp;
[📖 Docs](#-documentation) &nbsp;•&nbsp;
[🤝 Contributing](#-contributing)

---

</div>

## 🎯 What is NyxOS?

NyxOS is a **fully AI-native cybersecurity operating system** built on top of Kali Linux. AI isn't bolted on — it's woven into **every interaction**. The shell, the scanner, the reports, the onboarding — everything speaks human.

```
┌─────────────────────────────────────────────────────────────────────┐
│  [nyx] pentester@nyxos ~/engagements/acme >                         │
│                                                                     │
│  > scan acme-corp.com for open ports and check for vulns            │
│                                                                     │
│  🧠 Planning: nmap service scan → vulnerability scripts             │
│  🔒 Safety:   Target in scope ✓  |  Risk: LOW                       │
│  ⚡ Running:  nmap -sV --script vuln acme-corp.com                  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  PORT      STATE   SERVICE   VERSION                         │   │
│  │  22/tcp    open    ssh       OpenSSH 8.9p1                   │   │
│  │  80/tcp    open    http      nginx 1.21.6                    │   │
│  │  443/tcp   open    https     nginx 1.21.6                    │   │
│  │  8080/tcp  open    http      Apache 2.4.49  ← ⚠️ VULN       │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  📊 4 ports open  |  2 findings                                     │
│  🔴 HIGH:  Apache 2.4.49 Path Traversal (CVE-2021-41773)           │
│  🟡 MED:   Missing security headers on port 443                     │
│                                                                     │
│  💡 Next: "test the Apache path traversal on port 8080"            │
│                                                                     │
│  > generate a pentest report                                        │
│  📝 Report saved → ~/.nyxos/exports/pentest_20250425.pdf           │
└─────────────────────────────────────────────────────────────────────┘
```

> **The core flow:**
> You type English → AI understands intent → Selects the right tool → Executes it → Analyzes output → Presents findings → Remembers everything

No more memorizing flags. No more parsing raw output. No more copy-pasting between tools.

---

## ⚡ Quick Start

```bash
# Clone
git clone https://github.com/nitinbeniwal/nyxos.git
cd nyxos

# Install (handles everything — tools, venv, dependencies)
sudo ./install.sh

# Launch
./run.sh
```

On first launch, the onboarding wizard guides you through:

- 🎭 **Role selection** — Pentester, Bug Bounty, Red Team, Blue Team, Forensics, CTF, DevSecOps, Researcher
- 📊 **Skill level** — Beginner to Expert (adjusts AI verbosity and explanations)
- 🔑 **AI provider setup** — Bring your own API key or use local Ollama (fully offline)

---

## ✨ Features

### 🧠 AI-Powered Shell

Type natural language or traditional commands — NyxOS understands both.

```bash
> find open ports on 192.168.1.1            # Natural language → nmap
> nmap -sV 192.168.1.1                      # Traditional → runs directly
> what vulnerabilities does Apache 2.4.49 have?   # Knowledge query → AI answers
> !ls -la                                   # Bang prefix forces shell passthrough
```

---

### 🔧 Modular Skill System

Skills are AI capability modules that wrap security tools, optimize token usage, and produce standardized findings.

| Skill | Tools Wrapped | What It Does |
|-------|---------------|--------------|
| **Nmap** | `nmap` | Port scanning, service detection, OS fingerprinting, vuln scripts |
| **Web** | `gobuster`, `nikto`, `whatweb`, `sqlmap`, `ffuf` | Web app scanning, directory enum, SQLi testing |
| **Recon** | `whois`, `dig`, `theHarvester`, `amass`, `subfinder` | OSINT, DNS enum, subdomain discovery |
| **Forensics** | `volatility3`, `binwalk`, `exiftool`, `foremost` | Memory analysis, file carving, metadata extraction |
| **CTF** | Built-in + AI | Decode/encode, steganography, flag detection, AI hints |
| **Password** | `john`, `hashcat` | Hash identification, dictionary attacks, wordlist management |

---

### 🤖 Multi-Provider AI — Zero Lock-in

Choose your provider. Switch anytime. No lock-in. Ever.

| Provider | Models | Type |
|----------|--------|------|
| **Claude** (Anthropic) ⭐ | claude-sonnet-4, Haiku | Cloud API |
| **OpenAI** | GPT-4o, GPT-4o-mini | Cloud API |
| **Google Gemini** | Gemini Pro, Flash | Cloud API |
| **Mistral** | Large, Small | Cloud API |
| **Ollama** | Llama 3.1, Mistral, CodeLlama | 🏠 100% Local |

---

### 🕸️ Agent Orchestration

Agents chain multiple skills together for complex, multi-step objectives — automatically.

```
> do full recon on example.com

🧠 Planning reconnaissance...

📋 Plan (5 tasks, ~3 minutes):
  1. WHOIS lookup          →  Domain registration info
  2. DNS enumeration       →  All DNS records
  3. Subdomain discovery   →  Extended attack surface
  4. Port scan             →  Open services
  5. Technology detection  →  Full tech stack

  [1/5] WHOIS.............. ✅  Registrar: Namecheap | Expires: 2026-01-15
  [2/5] DNS................ ✅  12 records found (MX, A, CNAME, TXT)
  [3/5] Subdomains......... ✅  7 subdomains discovered
  [4/5] Port scan.......... ✅  4 open ports | 2 interesting services
  [5/5] Tech detect........ ✅  nginx 1.21, PHP 8.1, WordPress 6.4

📊 23 findings stored  |  Report ready  |  Tokens used: 1,847
```

---

### 🧠 Three-Layer Memory System

NyxOS learns how you work — across sessions, engagements, and your entire history.

| Layer | Scope | Persists | What It Remembers |
|-------|-------|----------|-------------------|
| **Session** | Current session | RAM only | Commands run, targets, findings |
| **Project** | Per engagement | Disk | Scope, all findings, notes, timeline |
| **User** | Permanent | Disk | Preferred tools, corrections, work patterns |

---

### 📊 Professional Report Generation

AI writes the narrative. You deliver the report.

```
> generate pentest report

📝 Generating report...
   ✅ Collecting 23 findings from project memory
   ✅ Sorting by severity (3 critical, 7 high, 9 medium, 4 low)
   ✅ AI writing executive summary...
   ✅ AI writing finding narratives...
   ✅ AI writing remediation section...
   ✅ Rendering HTML template...
   ✅ Exporting to PDF...

📄 Report saved → ~/.nyxos/exports/pentest_acme_20250425.pdf  (2.4 MB)
```

Report types: **Pentest Report** · **Bug Bounty Report** · **Executive Summary** · **CTF Writeup**
Export formats: **PDF** (WeasyPrint) · **Markdown** (GitHub-ready)

---

### 🛡️ Security Built Into Every Layer

| Feature | What It Does |
|---------|--------------|
| **SafetyGuard** | Every command is checked against defined scope before execution |
| **Encryption** | API keys encrypted at rest using Fernet (AES-128-CBC) |
| **Audit Logging** | Every action logged in structured JSON — full traceability |
| **Rate Limiting** | Prevents runaway token consumption and abuse |
| **Scope Enforcement** | Out-of-scope targets automatically blocked, not just warned |
| **No Auto-Exploit** | Exploit suggestions only — never automatic execution |

---

### 🌐 Live Web Dashboard

Real-time monitoring alongside the terminal at `localhost:8080`.

```
┌──────────────┬────────────────────────────────┬───────────────────┐
│  Sidebar     │  Main Panel                    │  Findings         │
│              │                                │                   │
│  • Status    │  Live terminal output          │  🔴 Critical  3   │
│  • Skills    │  ──────────────────────────    │  🟠 High      7   │
│  • Stats     │  Scan progress visualization   │  🟡 Medium    9   │
│  • Projects  │  Port map / directory tree     │  🔵 Low       4   │
│              │                                │                   │
│  Tokens: ▓░░ │  WebSocket: connected ●        │  [Click to expand]│
├──────────────┴────────────────────────────────┴───────────────────┤
│  > AI-powered command input...                         [Execute]  │
└───────────────────────────────────────────────────────────────────┘
```

---

### 🔌 Plugin System

Extend NyxOS without modifying core code. Plugins can add skills, builtins, AI providers, or hook into events.

```python
from nyxos.plugins.plugin_manager import BasePlugin

class SlackNotifier(BasePlugin):
    """Send critical findings to Slack in real time."""
    
    def on_finding(self, finding: dict):
        if finding["severity"] in ["critical", "high"]:
            self.post_to_slack(
                channel="#security-alerts",
                message=f"🚨 {finding['title']} — {finding['description']}"
            )
    
    def on_session_end(self, summary: dict):
        self.post_summary(summary)
```

---

## 🏗️ Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                          User Input                               │
│                  "scan target for open ports"                     │
└────────────────────────────┬──────────────────────────────────────┘
                             ▼
┌───────────────────────────────────────────────────────────────────┐
│  NyxShell  (nyxos/core/shell/nyxsh.py)                           │
│                                                                   │
│   ┌───────────┐   ┌────────────┐   ┌─────────────┐   ┌────────┐ │
│   │ Classify  │──▶│ AI Router  │──▶│ SafetyGuard │──▶│Execute │ │
│   │ Input     │   │ Intent     │   │ Scope Check │   │Skill   │ │
│   └───────────┘   └────────────┘   └─────────────┘   └────────┘ │
└────────────────────────────┬──────────────────────────────────────┘
                             ▼
┌───────────────────────────────────────────────────────────────────┐
│  Core Services                                                    │
│                                                                   │
│   ┌────────────┐  ┌──────────────┐  ┌──────────┐  ┌──────────┐  │
│   │ AI Engine  │  │ Memory       │  │ Security │  │ Config   │  │
│   │ (Router)   │  │ Manager      │  │ & Audit  │  │ Settings │  │
│   └────────────┘  └──────────────┘  └──────────┘  └──────────┘  │
└────────────────────────────┬──────────────────────────────────────┘
                             ▼
┌───────────────────────────────────────────────────────────────────┐
│  Skills                         Agents                            │
│                                                                   │
│  ┌──────┐ ┌─────┐ ┌───────┐    ┌────────────┐ ┌──────────────┐  │
│  │ Nmap │ │ Web │ │ Recon │    │TaskPlanner │ │ AttackChain  │  │
│  └──────┘ └─────┘ └───────┘    └────────────┘ └──────────────┘  │
│  ┌──────────┐ ┌─────┐ ┌──────┐ ┌────────────┐ ┌──────────────┐  │
│  │Forensics │ │ CTF │ │ Pass │ │ ReconAgent │ │ReportAgent   │  │
│  └──────────┘ └─────┘ └──────┘ └────────────┘ └──────────────┘  │
└───────────────────────────────────────────────────────────────────┘
```

### Project Structure

```
nyxos/
├── main.py                         # Entry point
├── install.sh                      # One-command installer
├── run.sh                          # Launch NyxOS
├── requirements.txt                # Python dependencies
│
├── nyxos/
│   ├── core/
│   │   ├── config/                 # NyxConfig dataclass + settings
│   │   ├── security/               # Encryption, auth, safety guard, audit
│   │   ├── ai_engine/              # Provider adapters, router, cache, prompts
│   │   ├── memory/                 # Session, project, and user memory
│   │   └── shell/                  # NyxShell — the AI shell (main REPL)
│   │
│   ├── skills/                     # Modular tool wrappers
│   │   ├── nmap/                   # Network scanning
│   │   ├── web/                    # Web vulnerability scanning
│   │   ├── recon/                  # OSINT & reconnaissance
│   │   ├── forensics/              # Digital forensics
│   │   ├── ctf/                    # CTF challenge helper
│   │   └── password/               # Hash identification & cracking
│   │
│   ├── agents/                     # Multi-step AI orchestration
│   ├── reporting/                  # Report engine + PDF/MD exporters
│   ├── dashboard/                  # Web UI (FastAPI + vanilla JS)
│   ├── onboarding/                 # First-run wizard
│   └── plugins/                    # Plugin system
│
├── tests/                          # 108 tests, all passing
└── docs/                           # Documentation
```

---

## 🎭 Roles

NyxOS adapts its AI behavior, verbosity, and tool choices based on your role.

| Role | AI Behavior |
|------|-------------|
| 🟢 **Beginner** | Explains everything, suggests safe commands, teaches as it goes |
| 🐛 **Bug Bounty** | Focuses on web vulns, generates submission-ready reports |
| 🔐 **Pentester** | Full methodology, chains tools automatically, professional reports |
| 🔴 **Red Team** | Stealth-focused, OPSEC reminders, attack path optimization |
| 🔵 **Blue Team** | Defensive focus, detection rules, incident response guidance |
| 🔬 **Forensics** | Evidence preservation, chain of custody, timeline analysis |
| 🏁 **CTF** | Hints without spoilers, decode/encode, challenge categorization |
| ⚙️ **DevSecOps** | CI/CD integration, SAST/DAST focus, compliance checking |
| 🔭 **Researcher** | Deep technical analysis, CVE research, exploit development |

---

## 🔧 Skills

### Standardized Output — Every Skill, Every Time

```python
# All skills return the same structure
@dataclass
class SkillResult:
    success: bool              # Did the tool run successfully?
    output: str                # Raw terminal output
    parsed_data: dict          # Structured parsed data
    findings: List[dict]       # Standardized findings list
    commands_run: List[str]    # Exact commands executed
    duration_seconds: float    # Execution time

# All findings share the same format
{
    "type":           "vulnerability",
    "title":          "Apache 2.4.49 Path Traversal",
    "severity":       "high",        # critical | high | medium | low | info
    "description":    "Server vulnerable to CVE-2021-41773...",
    "evidence":       "HTTP 200 on GET /cgi-bin/.%2F.%2Fetc/passwd",
    "recommendation": "Upgrade Apache to 2.4.51 or later",
    "tool_used":      "nmap",
    "timestamp":      "2025-04-25T10:30:00Z"
}
```

### Creating a Custom Skill

```bash
mkdir -p nyxos/skills/masscan
```

```python
# nyxos/skills/masscan/masscan_skill.py
from nyxos.skills.base_skill import BaseSkill, SkillResult

class MasscanSkill(BaseSkill):
    name = "masscan"
    description = "High-speed internet-scale port scanner"
    requires_tools = ["masscan"]
    keywords = ["masscan", "fast scan", "mass scan", "internet scan"]

    def execute(self, params: dict) -> SkillResult:
        target = params.get("target")
        rate = params.get("rate", "1000")
        cmd = f"masscan {target} --rate={rate} -p0-65535"
        # run, parse, return SkillResult
        ...

    def get_commands(self, intent: str) -> list[str]:
        ...

    def parse_output(self, raw: str) -> dict:
        ...
```

Skills are **auto-discovered** — drop them in `nyxos/skills/your_tool/` and restart. That's it.

> 📖 See [`docs/SKILLS.md`](docs/SKILLS.md) for the complete guide.

---

## 🧪 Testing

```bash
# Run all 108 tests
./test.sh

# Or manually
source .venv/bin/activate
pytest nyxos/tests/ -v

# With coverage report
pytest nyxos/tests/ -v --cov=nyxos --cov-report=html
```

```
108 passed in 0.28s ✅

Tests:
├── test_integration.py   — End-to-end: input → AI → command → finding → report
├── test_shell.py         — Input classification, builtins, AI dispatch
├── test_skills.py        — All 6 skills with mocked subprocess output
├── test_memory.py        — Session/project/user memory + persistence
└── test_reporting.py     — Report generation, templates, PDF/MD export
```

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [`README.md`](README.md) | This file — project overview |
| [`docs/INSTALL.md`](docs/INSTALL.md) | Detailed installation guide (VirtualBox, WSL2, native) |
| [`docs/SKILLS.md`](docs/SKILLS.md) | Skill system reference & custom skill creation guide |
| [`docs/AGENTS.md`](docs/AGENTS.md) | Agent orchestration system |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | Contribution guidelines |

---

## 🤝 Contributing

Contributions are welcome! The easiest ways to start:

- 🔧 **Add a new skill** — Wrap a Kali tool you love
- 🔌 **Write a plugin** — Slack notifier, Jira integration, Discord alerts
- 📖 **Improve docs** — Better examples, tutorials, translations
- 🐛 **Fix bugs** — Check [Issues](https://github.com/nitinbeniwal/nyxos/issues)

```bash
# Fork, clone, branch
git clone https://github.com/YOUR_USERNAME/nyxos.git
cd nyxos
sudo ./install.sh
git checkout -b feature/my-skill

# Develop, test, push
./test.sh
git push origin feature/my-skill
# Open a PR — we'll review within 48 hours
```

> 📖 See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) for the full guide.

---

## 🛡️ Ethical Usage

NyxOS is designed for **authorized security testing only**.

| ✅ Allowed | ❌ Not Allowed |
|-----------|---------------|
| Penetration testing with written authorization | Unauthorized access to any system |
| Bug bounty programs within defined scope | Any illegal activity |
| CTF competitions | Targeting systems you don't own |
| Security research on your own systems | Bypassing scope restrictions |
| Educational and learning purposes | Using findings for malicious purposes |

> The SafetyGuard system enforces scope boundaries automatically — but **you** are responsible for ensuring proper authorization before any test.

---

## 📋 Key Design Decisions

| Decision | Choice | Reasoning |
|----------|--------|-----------|
| **Base OS** | Kali Linux remaster | Don't reinvent the wheel — Kali has every tool pre-installed |
| **AI** | Hybrid (cloud + local) | Flexibility, privacy options, no vendor lock-in |
| **Language** | Python 3.12+ | Richest security tool and AI library ecosystem |
| **Shell** | Custom (prompt_toolkit + rich) | Full control over AI integration at every keystroke |
| **Dashboard** | FastAPI + vanilla JS | Lightweight, no heavy frontend framework required |
| **Skills License** | Apache 2.0 | Encourage community and commercial skill development |
| **Core License** | GPL v3 | Keep the core open forever |

---

## 🗺️ Roadmap

- [x] AI Shell with natural language understanding
- [x] 6 built-in skills (nmap, web, recon, forensics, CTF, password)
- [x] Multi-provider AI (Claude, OpenAI, Gemini, Ollama)
- [x] Three-layer memory system (session, project, user)
- [x] Agent orchestration (task planner, attack chain)
- [x] Professional report generation (PDF, Markdown)
- [x] Real-time web dashboard
- [x] Plugin system
- [x] 108 tests passing
- [ ] Kali ISO remaster — bootable USB / VirtualBox OVA *(in progress)*
- [ ] More skills — Burp Suite, Metasploit, Wireshark integration
- [ ] Collaborative multi-user mode
- [ ] AI model fine-tuning for security tasks
- [ ] Mobile companion app

---

## 📄 License

| Component | License |
|-----------|---------|
| Core (`nyxos/core/`, shell, agents) | [GPL v3](LICENSE) |
| Skills (`nyxos/skills/`) | [Apache 2.0](LICENSE-SKILLS) |
| Plugins (`nyxos/plugins/`) | [Apache 2.0](LICENSE-SKILLS) |

---

<div align="center">

## 👤 Author

**Nitin Beniwal**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Nitin_Beniwal-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/nitinbeniwal)
[![GitHub](https://img.shields.io/badge/GitHub-nitinbeniwal-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/nitinbeniwal)

<br/>

---

**NyxOS — Because security tools should speak human.**

*If this project helps you, please* ⭐ *star the repo — it helps more people discover it.*

[![Star History](https://img.shields.io/github/stars/nitinbeniwal/nyxos?style=social)](https://github.com/nitinbeniwal/nyxos/stargazers)

</div>
