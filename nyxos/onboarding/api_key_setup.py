"""
NyxOS API Key Setup (Step 4)
Guides the user through selecting and configuring one or more AI providers.
Tests API keys before saving, encrypts them, and stores to config.
"""

from __future__ import annotations

import getpass
import socket
import time
from dataclasses import dataclass
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, Confirm
from loguru import logger

from nyxos.core.config.settings import NyxConfig
from nyxos.core.security.encryption import EncryptionManager


@dataclass(frozen=True)
class ProviderDefinition:
    """Definition of a supported AI provider."""

    number: int
    key: str
    name: str
    provider_type: str  # maps to adapter class names
    description: str
    requires_key: bool
    default_model: str
    test_prompt: str
    icon: str


# All 6 supported providers
PROVIDERS: List[ProviderDefinition] = [
    ProviderDefinition(
        number=1,
        key="claude",
        name="Anthropic Claude",
        provider_type="claude",
        description="Recommended — excellent reasoning, long context, safety-aware",
        requires_key=True,
        default_model="claude-sonnet-4-20250514",
        test_prompt="Say 'NyxOS connected' in exactly 3 words.",
        icon="🟣",
    ),
    ProviderDefinition(
        number=2,
        key="openai",
        name="OpenAI GPT",
        provider_type="openai",
        description="GPT-4o — fast, versatile, widely used",
        requires_key=True,
        default_model="gpt-4o",
        test_prompt="Say 'NyxOS connected' in exactly 3 words.",
        icon="🟢",
    ),
    ProviderDefinition(
        number=3,
        key="gemini",
        name="Google Gemini",
        provider_type="gemini",
        description="Gemini Pro — large context window, multimodal capable",
        requires_key=True,
        default_model="gemini-pro",
        test_prompt="Say 'NyxOS connected' in exactly 3 words.",
        icon="🔵",
    ),
    ProviderDefinition(
        number=4,
        key="mistral",
        name="Mistral AI",
        provider_type="mistral",
        description="Open-weight models — fast, efficient, privacy-focused",
        requires_key=True,
        default_model="mistral-large-latest",
        test_prompt="Say 'NyxOS connected' in exactly 3 words.",
        icon="🟠",
    ),
    ProviderDefinition(
        number=5,
        key="ollama",
        name="Local Ollama",
        provider_type="ollama",
        description="Run models locally — no API key needed, fully private",
        requires_key=False,
        default_model="llama3",
        test_prompt="Say 'NyxOS connected' in exactly 3 words.",
        icon="🏠",
    ),
    ProviderDefinition(
        number=6,
        key="custom",
        name="Custom API Endpoint",
        provider_type="custom",
        description="Any OpenAI-compatible API endpoint (LMStudio, vLLM, etc.)",
        requires_key=True,
        default_model="default",
        test_prompt="Say 'NyxOS connected' in exactly 3 words.",
        icon="🔧",
    ),
]


class APIKeySetup:
    """
    Interactive AI provider configuration for NyxOS onboarding.
    Handles provider selection, API key input, key testing, encryption, and storage.
    """

    def __init__(
        self,
        config: NyxConfig,
        encryption: EncryptionManager,
        console: Console | None = None,
    ) -> None:
        """
        Initialize the API key setup wizard.

        Args:
            config: NyxOS configuration instance to save provider settings to.
            encryption: Encryption manager for API key encryption.
            console: Rich Console instance. Created if not provided.
        """
        self.config = config
        self.encryption = encryption
        self.console = console or Console()
        self.configured_providers: List[str] = []

    def run(self) -> List[str]:
        """
        Run the full API provider setup flow.

        Allows the user to configure one or more AI providers.
        At least one provider must be configured to proceed.

        Returns:
            List of configured provider keys.

        Raises:
            KeyboardInterrupt: If user cancels with Ctrl+C.
        """
        self.console.print()
        header = Panel(
            "[bold white]NyxOS needs an AI provider to power its intelligence layer.\n"
            "You can configure multiple providers and switch between them anytime.\n\n"
            "[dim]API keys are encrypted and stored locally — never sent anywhere except "
            "the provider you choose.[/dim]",
            title="[bold cyan]Step 4 — Configure AI Provider[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
        self.console.print(header)

        # First provider is required
        self._setup_provider(required=True)

        # Offer to add more
        while True:
            try:
                self.console.print()
                add_more = Confirm.ask(
                    "[bold yellow]Add another AI provider?[/bold yellow]",
                    default=False,
                )
                if not add_more:
                    break
                self._setup_provider(required=False)
            except KeyboardInterrupt:
                self.console.print("\n[dim]Skipping additional providers.[/dim]")
                break

        # Set active provider if more than one configured
        if len(self.configured_providers) > 1:
            self._select_active_provider()
        elif len(self.configured_providers) == 1:
            self.config.active_provider = self.configured_providers[0]

        self.console.print()
        self.console.print(
            f"[bold green]✓[/bold green] AI configured with "
            f"[bold cyan]{len(self.configured_providers)}[/bold cyan] provider(s). "
            f"Active: [bold cyan]{self.config.active_provider}[/bold cyan]"
        )

        return self.configured_providers

    def _setup_provider(self, required: bool = False) -> None:
        """
        Set up a single AI provider.

        Args:
            required: If True, user cannot skip this step.
        """
        self.console.print()

        # Show provider table
        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim cyan",
            padding=(0, 1),
            expand=False,
        )
        table.add_column("#", style="bold yellow", width=3, justify="center")
        table.add_column("", width=3, justify="center")  # icon
        table.add_column("Provider", style="bold white", min_width=22)
        table.add_column("Description", style="dim white")
        table.add_column("Key?", style="dim white", width=5, justify="center")

        for provider in PROVIDERS:
            # Mark already-configured providers
            already = "✓" if provider.key in self.configured_providers else ""
            key_needed = "No" if not provider.requires_key else "Yes"
            name_display = provider.name
            if already:
                name_display += " [green](configured)[/green]"
            table.add_row(
                str(provider.number),
                provider.icon,
                name_display,
                provider.description,
                key_needed,
            )

        self.console.print(table)
        self.console.print()

        # Get provider selection
        valid_choices = [str(p.number) for p in PROVIDERS]
        while True:
            try:
                choice = Prompt.ask(
                    "[bold yellow]Select provider[/bold yellow]",
                    choices=valid_choices,
                    default="1",
                )
                selected = PROVIDERS[int(choice) - 1]
                break
            except (ValueError, IndexError):
                self.console.print("[red]Invalid selection.[/red]")
            except KeyboardInterrupt:
                if required and not self.configured_providers:
                    self.console.print(
                        "[red]At least one provider is required. Please select one.[/red]"
                    )
                    continue
                raise

        # Handle the selected provider
        if selected.key == "ollama":
            self._setup_ollama(selected)
        elif selected.key == "custom":
            self._setup_custom(selected)
        else:
            self._setup_api_key_provider(selected)

    def _setup_api_key_provider(self, provider: ProviderDefinition) -> None:
        """
        Set up a provider that requires an API key.

        Args:
            provider: The provider definition.
        """
        self.console.print()
        self.console.print(
            f"[bold cyan]{provider.icon} Setting up {provider.name}[/bold cyan]"
        )

        # Ask for model (with default)
        model = Prompt.ask(
            "[dim]Model[/dim]",
            default=provider.default_model,
        )

        # Ask for API key (hidden input)
        self.console.print()
        self.console.print("[dim]Enter your API key (input is hidden):[/dim]")

        while True:
            try:
                api_key = getpass.getpass(f"  {provider.name} API Key: ")
                if not api_key.strip():
                    self.console.print("[red]API key cannot be empty.[/red]")
                    continue
                break
            except (EOFError, KeyboardInterrupt):
                self.console.print("\n[yellow]Cancelled API key input.[/yellow]")
                return

        api_key = api_key.strip()

        # Test the key
        test_success = self._test_api_key(provider, api_key, model)

        if not test_success:
            save_anyway = Confirm.ask(
                "[yellow]API key test failed. Save the key anyway?[/yellow]",
                default=True,
            )
            if not save_anyway:
                self.console.print("[dim]Skipping this provider.[/dim]")
                return

        # Encrypt and save
        self._save_provider(provider, api_key, model)

    def _setup_ollama(self, provider: ProviderDefinition) -> None:
        """
        Set up local Ollama provider (no API key needed).

        Args:
            provider: The Ollama provider definition.
        """
        self.console.print()
        self.console.print(
            f"[bold cyan]{provider.icon} Setting up {provider.name}[/bold cyan]"
        )
        self.console.print(
            "[dim]Ollama runs models locally on your machine. No API key needed.[/dim]"
        )
        self.console.print()

        # Check if Ollama is reachable
        ollama_host = Prompt.ask(
            "[dim]Ollama host[/dim]",
            default="http://localhost:11434",
        )

        model = Prompt.ask(
            "[dim]Model name[/dim]",
            default=provider.default_model,
        )

        # Quick connectivity check
        reachable = self._check_ollama_connectivity(ollama_host)
        if reachable:
            self.console.print("[bold green]✓[/bold green] Ollama is reachable")
        else:
            self.console.print(
                "[yellow]⚠ Cannot reach Ollama at "
                f"{ollama_host}. Make sure Ollama is running.[/yellow]"
            )
            save_anyway = Confirm.ask(
                "[yellow]Save configuration anyway?[/yellow]",
                default=True,
            )
            if not save_anyway:
                return

        # Save — Ollama doesn't need an encrypted key, store the host as the "key"
        self._save_provider(provider, ollama_host, model)

    def _setup_custom(self, provider: ProviderDefinition) -> None:
        """
        Set up a custom OpenAI-compatible API endpoint.

        Args:
            provider: The custom provider definition.
        """
        self.console.print()
        self.console.print(
            f"[bold cyan]{provider.icon} Setting up Custom API Endpoint[/bold cyan]"
        )
        self.console.print(
            "[dim]Supports any OpenAI-compatible API (LMStudio, vLLM, text-generation-webui, etc.)[/dim]"
        )
        self.console.print()

        endpoint = Prompt.ask(
            "[dim]API endpoint URL[/dim]",
            default="http://localhost:8000/v1",
        )

        model = Prompt.ask(
            "[dim]Model name[/dim]",
            default="default",
        )

        # API key is optional for custom endpoints
        self.console.print("[dim]API key (leave empty if not required):[/dim]")
        try:
            api_key = getpass.getpass("  API Key (optional): ")
        except (EOFError, KeyboardInterrupt):
            api_key = ""

        api_key = api_key.strip() if api_key else endpoint

        # Save with endpoint as part of the key if no key provided
        self._save_provider(provider, api_key or endpoint, model, endpoint=endpoint)

    def _test_api_key(
        self, provider: ProviderDefinition, api_key: str, model: str
    ) -> bool:
        """
        Test an API key by making a simple request to the provider.

        Args:
            provider: The provider definition.
            api_key: The raw (unencrypted) API key.
            model: The model name to use.

        Returns:
            True if the test succeeded, False otherwise.
        """
        self.console.print()
        self.console.print("[dim]Testing API key...[/dim]", end=" ")

        try:
            # Import the appropriate provider adapter
            if provider.provider_type == "claude":
                from nyxos.core.ai_engine.adapter import ClaudeProvider, AIProviderConfig

                config = AIProviderConfig(
                    provider="claude",
                    model=model,
                    api_key_encrypted="",  # We'll pass raw key for testing
                    temperature=0.7,
                    max_tokens=50,
                )
                test_provider = ClaudeProvider(config)
                # Override the key directly for testing
                response = self._test_with_raw_key(test_provider, api_key, provider.test_prompt)

            elif provider.provider_type == "openai":
                from nyxos.core.ai_engine.adapter import OpenAIProvider, AIProviderConfig

                config = AIProviderConfig(
                    provider="openai",
                    model=model,
                    api_key_encrypted="",
                    temperature=0.7,
                    max_tokens=50,
                )
                test_provider = OpenAIProvider(config)
                response = self._test_with_raw_key(test_provider, api_key, provider.test_prompt)

            elif provider.provider_type == "gemini":
                from nyxos.core.ai_engine.adapter import GeminiProvider, AIProviderConfig

                config = AIProviderConfig(
                    provider="gemini",
                    model=model,
                    api_key_encrypted="",
                    temperature=0.7,
                    max_tokens=50,
                )
                test_provider = GeminiProvider(config)
                response = self._test_with_raw_key(test_provider, api_key, provider.test_prompt)

            elif provider.provider_type == "mistral":
                # Mistral uses OpenAI-compatible API
                from nyxos.core.ai_engine.adapter import CustomProvider, AIProviderConfig

                config = AIProviderConfig(
                    provider="mistral",
                    model=model,
                    api_key_encrypted="",
                    temperature=0.7,
                    max_tokens=50,
                )
                test_provider = CustomProvider(config)
                response = self._test_with_raw_key(test_provider, api_key, provider.test_prompt)

            else:
                self.console.print("[yellow]⚠ No test available for this provider[/yellow]")
                return True

            if response:
                self.console.print("[bold green]✓ Success![/bold green]")
                self.console.print(f"[dim]Response: {response[:100]}[/dim]")
                return True
            else:
                self.console.print("[bold red]✗ No response received[/bold red]")
                return False

        except ImportError as e:
            self.console.print(
                f"[yellow]⚠ Provider library not installed: {e}[/yellow]"
            )
            self.console.print(
                "[dim]Install it later and the key will work.[/dim]"
            )
            return False

        except Exception as e:
            self.console.print(f"[bold red]✗ Test failed: {e}[/bold red]")
            logger.warning(f"API key test failed for {provider.key}: {e}")
            return False

    def _test_with_raw_key(
        self, provider_instance: object, raw_key: str, prompt: str
    ) -> Optional[str]:
        """
        Test a provider by temporarily injecting the raw API key.

        This is a workaround since the adapter normally expects encrypted keys.
        We directly call the underlying API library for testing.

        Args:
            provider_instance: The provider adapter instance.
            raw_key: The unencrypted API key.
            prompt: The test prompt to send.

        Returns:
            The response text, or None on failure.
        """
        provider_type = getattr(provider_instance, 'config', None)
        if provider_type is None:
            return None

        ptype = provider_type.provider

        try:
            if ptype == "claude":
                import anthropic

                client = anthropic.Anthropic(api_key=raw_key)
                message = client.messages.create(
                    model=provider_type.model,
                    max_tokens=50,
                    messages=[{"role": "user", "content": prompt}],
                )
                return message.content[0].text

            elif ptype == "openai":
                import openai

                client = openai.OpenAI(api_key=raw_key)
                response = client.chat.completions.create(
                    model=provider_type.model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=50,
                )
                return response.choices[0].message.content

            elif ptype == "gemini":
                import google.generativeai as genai

                genai.configure(api_key=raw_key)
                model = genai.GenerativeModel(provider_type.model)
                response = model.generate_content(prompt)
                return response.text

            elif ptype == "mistral":
                # Use requests for Mistral API
                import requests

                headers = {
                    "Authorization": f"Bearer {raw_key}",
                    "Content-Type": "application/json",
                }
                data = {
                    "model": provider_type.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 50,
                }
                resp = requests.post(
                    "https://api.mistral.ai/v1/chat/completions",
                    headers=headers,
                    json=data,
                    timeout=30,
                )
                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]["content"]

        except Exception as e:
            logger.debug(f"Raw key test failed for {ptype}: {e}")
            raise

        return None

    def _check_ollama_connectivity(self, host: str) -> bool:
        """
        Check if Ollama is reachable at the given host.

        Args:
            host: The Ollama host URL (e.g., http://localhost:11434).

        Returns:
            True if Ollama responds, False otherwise.
        """
        try:
            import requests

            # Ollama has a simple /api/tags endpoint
            url = host.rstrip("/") + "/api/tags"
            resp = requests.get(url, timeout=5)
            return resp.status_code == 200
        except Exception:
            # Fallback: try socket connection
            try:
                from urllib.parse import urlparse

                parsed = urlparse(host)
                hostname = parsed.hostname or "localhost"
                port = parsed.port or 11434
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((hostname, port))
                sock.close()
                return result == 0
            except Exception:
                return False

    def _save_provider(
        self,
        provider: ProviderDefinition,
        api_key: str,
        model: str,
        endpoint: Optional[str] = None,
    ) -> None:
        """
        Encrypt the API key and save the provider configuration.

        Args:
            provider: The provider definition.
            api_key: The raw API key (will be encrypted).
            model: The model name.
            endpoint: Optional custom endpoint URL.
        """
        try:
            # Encrypt the API key
            if provider.requires_key and provider.key != "ollama":
                encrypted_key = self.encryption.encrypt_api_key(api_key)
            else:
                # For Ollama, store the host URL; for custom without key, store endpoint
                encrypted_key = self.encryption.encrypt_api_key(api_key)

            # Build provider config dict
            provider_config = {
                "provider": provider.provider_type,
                "model": model,
                "api_key_encrypted": encrypted_key,
                "temperature": 0.7,
                "max_tokens": 4096,
            }

            # Add endpoint for custom providers
            if endpoint:
                provider_config["endpoint"] = endpoint

            # Save to config
            if not hasattr(self.config, 'ai_providers') or self.config.ai_providers is None:
                self.config.ai_providers = {}

            self.config.ai_providers[provider.key] = provider_config

            # Set as active if first provider
            if not self.configured_providers:
                self.config.active_provider = provider.key

            self.configured_providers.append(provider.key)

            self.console.print(
                f"[bold green]✓[/bold green] {provider.name} configured "
                f"(model: [cyan]{model}[/cyan])"
            )
            logger.info(
                f"Provider configured: {provider.key} with model {model}"
            )

        except Exception as e:
            self.console.print(
                f"[bold red]✗ Failed to save provider config: {e}[/bold red]"
            )
            logger.error(f"Failed to save provider {provider.key}: {e}")

    def _select_active_provider(self) -> None:
        """
        Ask the user which configured provider should be the active (default) one.
        """
        self.console.print()
        self.console.print(
            "[bold cyan]Multiple providers configured. Which should be the default?[/bold cyan]"
        )

        table = Table(show_header=False, border_style="dim cyan", padding=(0, 1))
        table.add_column("#", style="bold yellow", width=3, justify="center")
        table.add_column("Provider", style="bold white")

        for i, key in enumerate(self.configured_providers, 1):
            # Find the display name
            name = key
            for p in PROVIDERS:
                if p.key == key:
                    name = f"{p.icon} {p.name}"
                    break
            table.add_row(str(i), name)

        self.console.print(table)

        valid = [str(i) for i in range(1, len(self.configured_providers) + 1)]
        choice = Prompt.ask(
            "[bold yellow]Select default provider[/bold yellow]",
            choices=valid,
            default="1",
        )

        self.config.active_provider = self.configured_providers[int(choice) - 1]
        logger.info(f"Active provider set to: {self.config.active_provider}")

