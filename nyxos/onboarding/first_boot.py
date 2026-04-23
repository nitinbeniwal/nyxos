"""
NyxOS First Boot — Welcome Screen (Step 1)
Displays the NyxOS ASCII logo, version info, credits, and license.
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from loguru import logger


# NyxOS version
NYXOS_VERSION = "0.1.0"
NYXOS_CODENAME = "Genesis"

# ASCII art logo — designed for wide terminals but degrades gracefully
NYXOS_LOGO = r"""
 ███╗   ██╗██╗   ██╗██╗  ██╗ ██████╗ ███████╗
 ████╗  ██║╚██╗ ██╔╝╚██╗██╔╝██╔═══██╗██╔════╝
 ██╔██╗ ██║ ╚████╔╝  ╚███╔╝ ██║   ██║███████╗
 ██║╚██╗██║  ╚██╔╝   ██╔██╗ ██║   ██║╚════██║
 ██║ ╚████║   ██║   ██╔╝ ██╗╚██████╔╝███████║
 ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
"""

TAGLINE = "The World's First AI-Native Cybersecurity Operating System"

CREDITS = (
    "Built on Kali Linux · Powered by AI · Open Source (GPL v3)\n"
    "github.com/nyxos · Community-driven security platform"
)


class FirstBootScreen:
    """Displays the initial welcome screen on first boot of NyxOS."""

    def __init__(self, console: Console | None = None) -> None:
        """
        Initialize the first boot screen.

        Args:
            console: Rich Console instance. Created if not provided.
        """
        self.console = console or Console()

    def show(self) -> None:
        """
        Display the full welcome screen and wait for user acknowledgment.

        Shows ASCII logo, version, tagline, credits, and waits for
        the user to press Enter to continue. Handles Ctrl+C gracefully.
        """
        try:
            self._render_welcome()
            self._wait_for_continue()
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Setup interrupted. You can restart anytime.[/yellow]")
            raise

    def _render_welcome(self) -> None:
        """Render the welcome screen with logo and information."""
        self.console.clear()

        # Logo in cyan
        logo_text = Text(NYXOS_LOGO, style="bold cyan")
        self.console.print(Align.center(logo_text))

        # Tagline
        tagline_text = Text(TAGLINE, style="bold white")
        self.console.print(Align.center(tagline_text))
        self.console.print()

        # Version panel
        version_info = Text()
        version_info.append("Version: ", style="dim white")
        version_info.append(f"{NYXOS_VERSION} ", style="bold green")
        version_info.append(f'("{NYXOS_CODENAME}")', style="italic dim white")

        self.console.print(Align.center(version_info))
        self.console.print()

        # Credits panel
        credits_panel = Panel(
            Align.center(Text(CREDITS, style="dim white")),
            border_style="cyan",
            padding=(1, 4),
            title="[bold cyan]About[/bold cyan]",
            title_align="center",
        )
        self.console.print(credits_panel)
        self.console.print()

        # Feature highlights
        features_text = Text()
        features_text.append("  ⚡ ", style="cyan")
        features_text.append("AI understands your intent — type in plain English\n", style="white")
        features_text.append("  🛡️ ", style="cyan")
        features_text.append("Built-in safety guards protect against accidents\n", style="white")
        features_text.append("  🔌 ", style="cyan")
        features_text.append("Modular skills system — extensible and open source\n", style="white")
        features_text.append("  🧠 ", style="cyan")
        features_text.append("AI learns how you work and adapts over time\n", style="white")
        features_text.append("  📊 ", style="cyan")
        features_text.append("Professional reporting — PDF, Markdown, HTML", style="white")

        features_panel = Panel(
            features_text,
            border_style="dim cyan",
            title="[bold cyan]Features[/bold cyan]",
            title_align="center",
            padding=(1, 2),
        )
        self.console.print(features_panel)
        self.console.print()

    def _wait_for_continue(self) -> None:
        """Wait for the user to press Enter to continue."""
        continue_text = Align.center(
            Text("Press Enter to begin setup...", style="bold yellow blink")
        )
        self.console.print(continue_text)
        self.console.print()

        try:
            input()
        except EOFError:
            # Handle non-interactive environments
            pass

        logger.info("User acknowledged welcome screen, proceeding to setup")
