"""
NyxOS AI Router
Location: nyxos/core/ai_engine/router.py

Routes AI requests to the appropriate provider and model.
Handles:
- Provider selection based on user preference
- Fallback if primary provider fails
- Task-based routing (simple tasks → cheap model, complex → powerful model)
- Token budget enforcement
- Response caching
"""

import re
import time
from typing import Optional, Dict, List
from loguru import logger

from .adapter import (
    BaseProvider, AIResponse,
    ClaudeProvider, OpenAIProvider, GeminiProvider,
    OllamaProvider, CustomProvider
)
from .token_tracker import TokenTracker
from .cache import ResponseCache
from ..config.settings import NyxConfig, AIProviderConfig
from ..security.encryption import EncryptionManager


class AIRouter:
    """
    Central AI routing system.
    Every AI request in NyxOS goes through this router.
    """

    def __init__(self, config: NyxConfig, encryption: EncryptionManager):
        self.config = config
        self.encryption = encryption
        self.providers: Dict[str, BaseProvider] = {}
        self.token_tracker = TokenTracker(config.tokens)
        self.cache = ResponseCache()
        self._initialize_providers()

    def _initialize_providers(self):
        """Initialize all configured AI providers"""
        for name, provider_config in self.config.ai_providers.items():
            try:
                provider = self._create_provider(name, provider_config)
                if provider:
                    self.providers[name] = provider
                    logger.info(f"AI Provider initialized: {name}")
            except Exception as e:
                logger.warning(f"Failed to initialize provider {name}: {e}")

        # Always try to initialize Ollama as fallback
        if "ollama" not in self.providers:
            try:
                ollama = OllamaProvider()
                if ollama.is_available():
                    self.providers["ollama"] = ollama
                    logger.info("Ollama available as fallback provider")
            except Exception:
                pass

        if not self.providers:
            logger.error("No AI providers available!")

    def _create_provider(self, name: str, config: AIProviderConfig) -> Optional[BaseProvider]:
        """Create a provider instance from config"""
        # Decrypt API key if encrypted
        api_key = ""
        if config.api_key_encrypted:
            try:
                api_key = self.encryption.decrypt_api_key(config.api_key_encrypted)
            except Exception:
                logger.warning(f"Could not decrypt API key for {name}")
                return None

        provider_map = {
            "claude": lambda: ClaudeProvider(api_key=api_key, model=config.model),
            "openai": lambda: OpenAIProvider(api_key=api_key, model=config.model),
            "gemini": lambda: GeminiProvider(api_key=api_key, model=config.model),
            "ollama": lambda: OllamaProvider(model=config.model),
            "custom": lambda: CustomProvider(
                api_key=api_key,
                base_url=config.base_url,
                model=config.model
            ),
        }

        creator = provider_map.get(name)
        if creator:
            return creator()

        # Check if name contains a known provider type
        for key, creator_fn in provider_map.items():
            if key in name.lower():
                return creator_fn()

        logger.warning(f"Unknown provider type: {name}")
        return None

    def get_active_provider(self) -> Optional[BaseProvider]:
        """Get the currently active provider"""
        active = self.config.active_provider
        if active in self.providers:
            return self.providers[active]

        # Fallback chain
        fallback_order = ["ollama", "claude", "openai", "gemini", "custom"]
        for fallback in fallback_order:
            if fallback in self.providers:
                logger.warning(f"Active provider {active} unavailable, falling back to {fallback}")
                return self.providers[fallback]

        return None

    def classify_task_complexity(self, prompt: str) -> str:
        """
        Classify how complex a task is to route to appropriate model.
        
        Returns: simple, medium, complex
        
        Simple tasks use cheaper/local models.
        Complex tasks use powerful API models.
        """
        prompt_lower = prompt.lower()

        # Simple tasks — can use local/cheap model
        simple_patterns = [
            r"what (does|is) .{3,30}\??$",  # Short questions
            r"explain .{3,30}$",  # Brief explanations
            r"(convert|translate) .{3,50}$",  # Simple conversions
            r"list .{3,30}$",  # Listing things
            r"how to install",  # Installation help
        ]

        for pattern in simple_patterns:
            if re.search(pattern, prompt_lower):
                return "simple"

        # Complex tasks — need powerful model
        complex_indicators = [
            "analyze", "vulnerability", "exploit", "attack chain",
            "penetration test", "full scan", "investigate",
            "write a report", "create a plan", "reverse engineer",
            "forensic", "malware", "incident response",
            "multi-step", "comprehensive"
        ]

        complex_count = sum(1 for indicator in complex_indicators if indicator in prompt_lower)

        if complex_count >= 2:
            return "complex"
        elif complex_count == 1:
            return "medium"

        # Check prompt length as heuristic
        if len(prompt) > 500:
            return "complex"
        elif len(prompt) > 200:
            return "medium"

        return "simple"

    def generate(
        self,
        prompt: str,
        system_prompt: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.3,
        provider_override: Optional[str] = None,
        use_cache: bool = True,
        task_type: str = "general"
    ) -> AIResponse:
        """
        Main generation method — all AI requests go through here.
        
        Flow:
        1. Check cache
        2. Check token budget
        3. Route to appropriate provider
        4. Generate response
        5. Track tokens
        6. Cache response
        7. Return
        """

        # Step 1: Check cache
        if use_cache and self.cache.enabled:
            cached = self.cache.get(prompt, system_prompt)
            if cached:
                logger.debug("Cache hit — returning cached response")
                cached.cached = True
                return cached

        # Step 2: Check token budget
        budget_ok, budget_msg = self.token_tracker.check_budget(max_tokens)
        if not budget_ok:
            return AIResponse(
                content=f"⚠️ Token budget exceeded: {budget_msg}",
                model="none",
                provider="budget_guard",
                error=budget_msg
            )

        # Step 3: Select provider
        if provider_override and provider_override in self.providers:
            provider = self.providers[provider_override]
        elif self.config.tokens.use_local_for_simple:
            complexity = self.classify_task_complexity(prompt)
            provider = self._route_by_complexity(complexity)
        else:
            provider = self.get_active_provider()

        if not provider:
            return AIResponse(
                content="❌ No AI provider available. Please configure one with 'nyx config ai'.",
                model="none",
                provider="none",
                error="No provider available"
            )

        # Step 4: Generate response
        logger.debug(f"Routing to {provider.get_model_name()} ({type(provider).__name__})")

        response = provider.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            max_tokens=max_tokens,
            temperature=temperature
        )

        # Step 5: Handle errors with fallback
        if response.error:
            logger.warning(f"Provider error: {response.error}. Trying fallback...")
            fallback_response = self._try_fallback(prompt, system_prompt, max_tokens, temperature)
            if fallback_response and not fallback_response.error:
                response = fallback_response

        # Step 6: Track token usage
        if not response.error:
            self.token_tracker.record_usage(
                provider=response.provider,
                model=response.model,
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
                total_tokens=response.tokens_used
            )

        # Step 7: Cache successful response
        if not response.error and use_cache and self.cache.enabled:
            self.cache.store(prompt, system_prompt, response)

        return response

    def _route_by_complexity(self, complexity: str) -> Optional[BaseProvider]:
        """Route to appropriate provider based on task complexity"""
        if complexity == "simple" and "ollama" in self.providers:
            return self.providers["ollama"]
        elif complexity == "complex":
            # Prefer powerful API models
            for name in ["claude", "openai", "gemini"]:
                if name in self.providers:
                    return self.providers[name]

        return self.get_active_provider()

    def _try_fallback(self, prompt: str, system_prompt: str,
                      max_tokens: int, temperature: float) -> Optional[AIResponse]:
        """Try fallback providers if primary fails"""
        active = self.config.active_provider

        for name, provider in self.providers.items():
            if name == active:
                continue
            try:
                response = provider.generate(prompt, system_prompt, max_tokens, temperature)
                if not response.error:
                    logger.info(f"Fallback to {name} succeeded")
                    return response
            except Exception:
                continue

        return None

    def switch_provider(self, provider_name: str) -> bool:
        """Switch active AI provider"""
        if provider_name in self.providers:
            self.config.active_provider = provider_name
            self.config.save()
            logger.info(f"Switched to provider: {provider_name}")
            return True
        logger.warning(f"Provider not found: {provider_name}")
        return False

    def add_provider(self, name: str, provider_config: AIProviderConfig) -> bool:
        """Add a new AI provider at runtime"""
        try:
            provider = self._create_provider(name, provider_config)
            if provider and provider.is_available():
                self.providers[name] = provider
                self.config.ai_providers[name] = provider_config
                self.config.save()
                logger.info(f"Added new provider: {name}")
                return True
        except Exception as e:
            logger.error(f"Failed to add provider {name}: {e}")
        return False

    def list_providers(self) -> Dict[str, dict]:
        """List all available providers and their status"""
        result = {}
        for name, provider in self.providers.items():
            result[name] = {
                "model": provider.get_model_name(),
                "available": provider.is_available(),
                "is_active": name == self.config.active_provider,
                "type": type(provider).__name__
            }
        return result

    def get_usage_stats(self) -> dict:
        """Get token usage statistics"""
        return self.token_tracker.get_stats()
