<div align="center">

# 🌙 NyxOS

> **Created by [Nitin Beniwal](https://github.com/nitinbeniwal)** — Architect


### The World's First AI-Native Cybersecurity Operating System

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Built on Kali](https://img.shields.io/badge/built%20on-Kali%20Linux-557C94.svg)](https://www.kali.org/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](docs/CONTRIBUTING.md)

**Type in plain English. NyxOS understands your intent, picks the right tool,
executes it, analyzes the output, and presents findings — automatically.**

[Quick Start](#-quick-start) •
[Features](#-features) •
[Install](#-installation) •
[Skills](#-available-skills) •
[Contributing](#-contributing) •
[Docs](docs/)

</div>

---

## 🔮 What is NyxOS?

NyxOS is a fully AI-native cybersecurity operating system built on top of Kali Linux.
It is **not** Kali with AI bolted on — AI is woven into every interaction: the shell,
the package manager, the process manager, the reports, and the onboarding. A user boots
NyxOS, types in plain English ("scan this target for open ports"), and the AI understands
intent, selects the right tool, executes it, analyzes the output, and presents findings
— all automatically.

NyxOS supports multiple AI providers (Claude, OpenAI, Gemini, Mistral, or local Ollama)
with no vendor lock-in. It features a role-based system that adapts its behavior to your
expertise level — whether you are a complete beginner, a bug bounty hunter, a red team
operator, or a forensics analyst. Every action is safety-checked, audited, and scoped to
prevent accidental damage.


┌──────────────────────────────────────────────────────────────┐
│ [nyx] user@nyxos ~ > find open ports on 192.168.1.1 │
│ │
│ 🤖 I'll run: nmap -sCV 192.168.1.1 — Confirm? [Y/n] y │
│ │
│ ┌─ Scan Results ──────────────────────────────────────────┐ │
│ │ PORT STATE SERVICE VERSION │ │
│ │ 22/tcp open ssh OpenSSH 8.9p1 │ │
│ │ 80/tcp open http Apache 2.4.52 │ │
│ │ 443/tcp open https Apache 2.4.52 │ │
│ │ 3306/tcp open mysql MySQL 8.0.33 │ │
│ └─────────────────────────────────────────────────────────┘ │
│ │
│ 📋 4 findings recorded to project memory │
│ ⚠️ MySQL exposed on port 3306 — recommend restricting │
│ │
│ [nyx] user@nyxos ~ > │
└──────────────────────────────────────────────────────────────┘


---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🧠 **AI-Powered Shell** | Type natural language or commands — NyxOS understands both |
| 🔄 **Multi-Provider AI** | Claude, OpenAI, Gemini, Mistral, or local Ollama — switch anytime |
| 🎭 **Role-Based System** | Adapts behavior for Beginner, Bug Bounty, Pentester, Red Team, Blue Team, Forensics, CTF, DevSecOps, Researcher |
| 🛠️ **Skills System** | Modular AI capability modules wrapping security tools |
| 🧠 **Memory System** | Session, project, and user-level memory — AI learns how you work |
| 🛡️ **Safety Guard** | Every command checked for scope, risk, and authorization |
| 📊 **Dashboard** | Real-time web dashboard with findings panel and terminal |
| 📝 **AI Reports** | Auto-generated pentest, bug bounty, and executive reports |
| 🤖 **Agent System** | Multi-step autonomous attack chains with safety checkpoints |
| 🔌 **Plugin System** | Community-extensible architecture |
| 📦 **Bootable ISO** | Full Kali remaster — boot and go |
| 🔒 **Audit Logging** | Every action logged for compliance and review |

---

## 🚀 Quick Start

### Installation (3 commands)

```bash
git clone https://github.com/nyxos-project/nyxos.git
cd nyxos
pip install -e .

First Run
bash
nyxos
# or
python main.py
On first boot, NyxOS walks you through setup: username, role, AI provider, and API key.

5 Commands to Try
bash
# 1. Get help
help

# 2. Scan a target
scan 192.168.1.1

# 3. Ask in plain English
find open ports on 10.0.0.1

# 4. Analyze the last output
analyze

# 5. Generate a report
report pentest
🏗️ Architecture Overview
text
┌─────────────────────────────────────────────────────────┐
│                      User Input                          │
│            (Natural Language / Commands)                  │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│                    NyxSH (AI Shell)                       │
│         Classifies → Builtin / Shell / NL                │
└──────┬──────────────┬──────────────────┬────────────────┘
       │              │                  │
       ▼              ▼                  ▼
┌────────────┐ ┌─────────────┐  ┌──────────────────┐
│  Builtins  │ │  Subprocess │  │   AI Router       │
│  (scan,    │ │  (ls, nmap, │  │   (Claude/GPT/    │
│   report,  │ │   curl...)  │  │    Gemini/Ollama) │
│   memory)  │ └─────────────┘  └────────┬─────────┘
└─────┬──────┘                           │
      │                                  ▼
      ▼                         ┌──────────────────┐
┌──────────────┐                │  Safety Guard     │
│ Skill Manager │◄──────────────│  (scope, risk,    │
│ (nmap, web,   │               │   confirmation)   │
│  recon, ctf,  │               └──────────────────┘
│  forensics,   │
│  password)    │
└──────┬───────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│                    Memory System                          │
│      Session (RAM) │ Project (Disk) │ User (Disk)        │
└──────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│               Reporting Engine + Dashboard                │
│        HTML/PDF/Markdown Reports │ Web UI on :8080       │
└──────────────────────────────────────────────────────────┘



🛠️ Available Skills
Skill	Tools Wrapped	What It Does
nmap	nmap	Port scanning, service detection, OS fingerprinting
web	gobuster, nikto, whatweb, curl, sqlmap, ffuf	Directory enumeration, web vuln scanning, SQLi testing
recon	whois, dig, theHarvester, amass, subfinder, shodan	OSINT, DNS enumeration, subdomain discovery
forensics	volatility3, strings, binwalk, exiftool, foremost	Memory analysis, file carving, metadata extraction
ctf	base64, steghide, strings, binwalk	Decode/encode, stego, flag detection, AI hints
password	john, hashcat	Hash identification, dictionary/brute-force cracking
See docs/SKILLS.md for full documentation.

🤖 AI Providers Supported
Provider	Models	Local?	Free Tier?
Anthropic Claude	claude-3.5-sonnet, claude-3-haiku	No	Limited
OpenAI	gpt-4o, gpt-4o-mini	No	Limited
Google Gemini	gemini-1.5-pro, gemini-1.5-flash	No	Yes
Mistral	mistral-large, mistral-small	No	Yes
Ollama	llama3, mixtral, codestral	✅ Yes	✅ Fully free
You can switch providers at any time with config set provider <name>.

🧪 Running Tests
bash
pip install -e ".[dev]"
pytest nyxos/tests/ -v
All tests run without network access or installed tools — everything is mocked.

🤝 Contributing
We welcome contributions! See docs/CONTRIBUTING.md for:

How to create a new skill
How to create a plugin
Code style guide
PR process
📄 License
NyxOS core is licensed under GPL v3.
Skills and plugins are licensed under Apache 2.0.

🌐 Community
GitHub: github.com/nyxos-project/nyxos
Discord: Join our server
LinkedIn: NyxOS Project
Built with 🖤 by the NyxOS community

NyxOS is intended for authorized security testing only.
Always obtain proper authorization before testing any target.
