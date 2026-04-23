"""
NyxOS Role Selector (Step 3)
Presents available security roles and skill levels,
letting the user choose their persona for AI interaction tuning.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt
from rich.align import Align
from loguru import logger


@dataclass(frozen=True)
class RoleDefinition:
    """Definition of a NyxOS user role."""

    number: int
    key: str
    name: str
    short_desc: str
    detail: str
    icon: str


# All 9 supported roles
ROLES: List[RoleDefinition] = [
    RoleDefinition(
        number=1,
        key="beginner",
        name="Beginner / Student",
        short_desc="Learning cybersecurity from scratch",
        detail=(
            "Extra explanations for every command and concept. "
            "Safe defaults enabled — dangerous operations require explicit confirmation. "
            "AI acts as a patient teacher, explaining the 'why' behind every step."
        ),
        icon="📚",
    ),
    RoleDefinition(
        number=2,
        key="bug_bounty",
        name="Bug Bounty Hunter",
        short_desc="Finding vulnerabilities for rewards",
        detail=(
            "Focused on web application vulnerabilities — XSS, SQLi, SSRF, IDOR. "
            "AI helps with scope management, PoC writing, and platform-ready reports. "
            "Integrates with HackerOne/Bugcrowd report templates."
        ),
        icon="🎯",
    ),
    RoleDefinition(
        number=3,
        key="pentester",
        name="Penetration Tester",
        short_desc="Professional security assessments",
        detail=(
            "Full PTES/OWASP methodology guidance. Professional output formatting. "
            "AI assists with scoping, tool selection, finding documentation, and "
            "client-ready report generation with executive summaries."
        ),
        icon="🔓",
    ),
    RoleDefinition(
        number=4,
        key="red_team",
        name="Red Team Operator",
        short_desc="Advanced adversary simulation",
        detail=(
            "Focus on stealth, evasion, and MITRE ATT&CK mapping. "
            "AI suggests OPSEC-safe alternatives, C2 configurations, and "
            "living-off-the-land techniques. Minimal noise, maximum impact."
        ),
        icon="🔴",
    ),
    RoleDefinition(
        number=5,
        key="blue_team",
        name="Blue Team / SOC Analyst",
        short_desc="Detection, monitoring, and defense",
        detail=(
            "Focus on log analysis, SIEM queries, indicator extraction, and "
            "incident response workflows. AI helps write detection rules, "
            "analyze alerts, and build timeline reconstructions."
        ),
        icon="🔵",
    ),
    RoleDefinition(
        number=6,
        key="forensics",
        name="Forensics Analyst",
        short_desc="Digital evidence and investigation",
        detail=(
            "Evidence chain-of-custody awareness. AI assists with memory analysis, "
            "disk forensics, timeline reconstruction, and court-ready documentation. "
            "Never modifies original evidence — works on copies."
        ),
        icon="🔍",
    ),
    RoleDefinition(
        number=7,
        key="ctf",
        name="CTF Player",
        short_desc="Capture The Flag competitions",
        detail=(
            "AI provides hints without spoilers. Auto-detects common flag formats. "
            "Helps with crypto, stego, reversing, web, and pwn challenges. "
            "Tracks flags found and generates writeups."
        ),
        icon="🏁",
    ),
    RoleDefinition(
        number=8,
        key="devsecops",
        name="Developer / DevSecOps",
        short_desc="Secure development and CI/CD",
        detail=(
            "Focus on code review, dependency scanning, SAST/DAST integration, "
            "and container security. AI helps identify vulnerable code patterns, "
            "suggests secure alternatives, and generates security policies."
        ),
        icon="⚙️",
    ),
    RoleDefinition(
        number=9,
        key="researcher",
        name="Security Researcher",
        short_desc="CVE research and exploit development",
        detail=(
            "Deep technical analysis mode. AI assists with vulnerability research, "
            "PoC development, binary analysis, and responsible disclosure workflows. "
            "Minimal hand-holding — assumes expert-level knowledge."
        ),
        icon="🧪",
    ),
]

# Skill levels
SKILL_LEVELS = [
    ("novice", "New to security — explain everything"),
    ("intermediate", "Familiar with basics — explain advanced concepts"),
    ("advanced", "Experienced — concise output, minimal explanation"),
    ("expert", "Deep expertise — terse output, skip all basics"),
]


class RoleSelector:
    """
    Interactive role and skill level selector for NyxOS onboarding.
    Presents all available roles with descriptions and lets the user choose.
    """

    def __init__(self, console: Console | None = None) -> None:
        """
        Initialize the role selector.

        Args:
            console: Rich Console instance. Created if not provided.
        """
        self.console = console or Console()

    def select_role(self) -> str:
        """
        Display role selection menu and return the chosen role key.

        Returns:
            The selected role key string (e.g., 'pentester', 'ctf').

        Raises:
            KeyboardInterrupt: If user cancels with Ctrl+C.
        """
        self.console.print()
        header = Panel(
            "[bold white]Choose your primary role. This shapes how the AI communicates with you, "
            "which tools it prioritizes, and what methodology it follows.\n\n"
            "[dim]You can change this anytime with:[/dim] [cyan]config set role <role>[/cyan]",
            title="[bold cyan]Step 3 — Select Your Role[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
        self.console.print(header)
        self.console.print()

        # Build the role table
        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim cyan",
            padding=(0, 1),
            expand=True,
        )
        table.add_column("#", style="bold yellow", width=3, justify="center")
        table.add_column("", width=3, justify="center")  # icon
        table.add_column("Role", style="bold white", min_width=22)
        table.add_column("Description", style="dim white")

        for role in ROLES:
            table.add_row(
                str(role.number),
                role.icon,
                role.name,
                role.short_desc,
            )

        self.console.print(table)
        self.console.print()

        # Get user selection
        while True:
            try:
                choice = Prompt.ask(
                    "[bold yellow]Select role[/bold yellow]",
                    choices=[str(r.number) for r in ROLES],
                    default="3",
                )
                selected_role = ROLES[int(choice) - 1]
                break
            except (ValueError, IndexError):
                self.console.print("[red]Invalid selection. Please enter a number 1-9.[/red]")
            except KeyboardInterrupt:
                raise

        # Show detail for selected role
        self.console.print()
        detail_panel = Panel(
            f"[white]{selected_role.detail}[/white]",
            title=f"[bold cyan]{selected_role.icon} {selected_role.name}[/bold cyan]",
            border_style="green",
            padding=(1, 2),
        )
        self.console.print(detail_panel)
        self.console.print()

        logger.info(f"User selected role: {selected_role.key}")
        return selected_role.key

    def select_skill_level(self) -> str:
        """
        Display skill level selection and return the chosen level.

        Returns:
            The selected skill level string (e.g., 'intermediate').

        Raises:
            KeyboardInterrupt: If user cancels with Ctrl+C.
        """
        self.console.print()
        self.console.print(
            "[bold cyan]What's your current skill level?[/bold cyan]"
        )
        self.console.print(
            "[dim]This controls how verbose the AI is and what it explains vs. assumes.[/dim]"
        )
        self.console.print()

        # Build skill level table
        table = Table(
            show_header=False,
            border_style="dim cyan",
            padding=(0, 1),
            expand=False,
        )
        table.add_column("#", style="bold yellow", width=3, justify="center")
        table.add_column("Level", style="bold white", min_width=16)
        table.add_column("Description", style="dim white")

        for i, (level, desc) in enumerate(SKILL_LEVELS, 1):
            table.add_row(str(i), level.capitalize(), desc)

        self.console.print(table)
        self.console.print()

        while True:
            try:
                choice = Prompt.ask(
                    "[bold yellow]Select skill level[/bold yellow]",
                    choices=["1", "2", "3", "4"],
                    default="2",
                )
                selected_level = SKILL_LEVELS[int(choice) - 1][0]
                break
            except (ValueError, IndexError):
                self.console.print("[red]Invalid selection. Please enter a number 1-4.[/red]")
            except KeyboardInterrupt:
                raise

        logger.info(f"User selected skill level: {selected_level}")
        return selected_level

    def run(self) -> tuple[str, str]:
        """
        Run the full role selection flow (role + skill level).

        Returns:
            Tuple of (role_key, skill_level).

        Raises:
            KeyboardInterrupt: If user cancels with Ctrl+C.
        """
        role = self.select_role()
        skill_level = self.select_skill_level()

        self.console.print()
        self.console.print(
            f"[bold green]✓[/bold green] Role set to [bold cyan]{role}[/bold cyan] "
            f"at [bold cyan]{skill_level}[/bold cyan] level"
        )

        return role, skill_level


def get_role_name(role_key: str) -> str:
    """
    Get the display name for a role key.

    Args:
        role_key: The role key string (e.g., 'pentester').

    Returns:
        The display name (e.g., 'Penetration Tester').
    """
    for role in ROLES:
        if role.key == role_key:
            return role.name
    return role_key.replace("_", " ").title()


def get_role_icon(role_key: str) -> str:
    """
    Get the icon for a role key.

    Args:
        role_key: The role key string.

    Returns:
        The emoji icon for the role.
    """
    for role in ROLES:
        if role.key == role_key:
            return role.icon
    return "🔒"
