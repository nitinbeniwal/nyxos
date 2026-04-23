"""
NyxOS Universal AI Adapter
Location: nyxos/core/ai_engine/adapter.py

One interface, any model behind it.
Supports: Claude, OpenAI, Gemini, Mistral, Ollama, Custom

This is the CORE of NyxOS AI integration.
"""

import os
import json
import time
from abc import ABC, abstractmethod
from typing import Optional, Dict, Generator
from dataclasses import dataclass
from loguru import logger


@dataclass
class AIResponse:
    """Standardized AI response across all providers"""
    content: str
    model: str
    provider: str
    tokens_used: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    cached: bool = False
    error: Optional[str] = None


class BaseProvider(ABC):
    """Abstract base class for all AI providers"""

    @abstractmethod
    def generate(self, prompt: str, system_prompt: str = "",
                 max_tokens: int = 4096, temperature: float = 0.3) -> AIResponse:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @abstractmethod
    def get_model_name(self) -> str:
        pass


class ClaudeProvider(BaseProvider):
    """Anthropic Claude API Provider"""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key
        self.model = model
        self._client = None

    def _get_client(self):
        if not self._client:
            import anthropic
            self._client = anthropic.Anthropic(api_key=self.api_key)
        return self._client

    def generate(self, prompt: str, system_prompt: str = "",
                 max_tokens: int = 4096, temperature: float = 0.3) -> AIResponse:
        start_time = time.time()
        try:
            client = self._get_client()
            message = client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system_prompt if system_prompt else "You are NyxAI, the AI core of NyxOS cybersecurity operating system.",
                messages=[{"role": "user", "content": prompt}]
            )

            latency = int((time.time() - start_time) * 1000)

            return AIResponse(
                content=message.content[0].text,
                model=self.model,
                provider="claude",
                input_tokens=message.usage.input_tokens,
                output_tokens=message.usage.output_tokens,
                tokens_used=message.usage.input_tokens + message.usage.output_tokens,
                latency_ms=latency
            )
        except Exception as e:
            logger.error(f"Claude API error: {e}")
            return AIResponse(
                content="", model=self.model, provider="claude",
                error=str(e)
            )

    def is_available(self) -> bool:
        try:
            self._get_client()
            return True
        except Exception:
            return False

    def get_model_name(self) -> str:
        return self.model


class OpenAIProvider(BaseProvider):
    """OpenAI API Provider"""

    def __init__(self, api_key: str, model: str = "gpt-4o"):
        self.api_key = api_key
        self.model = model
        self._client = None

    def _get_client(self):
        if not self._client:
            import openai
            self._client = openai.OpenAI(api_key=self.api_key)
        return self._client

    def generate(self, prompt: str, system_prompt: str = "",
                 max_tokens: int = 4096, temperature: float = 0.3) -> AIResponse:
        start_time = time.time()
        try:
            client = self._get_client()
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature
            )

            latency = int((time.time() - start_time) * 1000)
            usage = response.usage

            return AIResponse(
                content=response.choices[0].message.content,
                model=self.model,
                provider="openai",
                input_tokens=usage.prompt_tokens,
                output_tokens=usage.completion_tokens,
                tokens_used=usage.total_tokens,
                latency_ms=latency
            )
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return AIResponse(
                content="", model=self.model, provider="openai",
                error=str(e)
            )

    def is_available(self) -> bool:
        try:
            self._get_client()
            return True
        except Exception:
            return False

    def get_model_name(self) -> str:
        return self.model


class GeminiProvider(BaseProvider):
    """Google Gemini API Provider"""

    def __init__(self, api_key: str, model: str = "gemini-1.5-pro"):
        self.api_key = api_key
        self.model = model
        self._client = None

    def _get_client(self):
        if not self._client:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            self._client = genai.GenerativeModel(self.model)
        return self._client

    def generate(self, prompt: str, system_prompt: str = "",
                 max_tokens: int = 4096, temperature: float = 0.3) -> AIResponse:
        start_time = time.time()
        try:
            client = self._get_client()
            full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt

            response = client.generate_content(
                full_prompt,
                generation_config={
                    "max_output_tokens": max_tokens,
                    "temperature": temperature
                }
            )

            latency = int((time.time() - start_time) * 1000)

            return AIResponse(
                content=response.text,
                model=self.model,
                provider="gemini",
                tokens_used=0,  # Gemini doesn't always report token usage directly
                latency_ms=latency
            )
        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            return AIResponse(
                content="", model=self.model, provider="gemini",
                error=str(e)
            )

    def is_available(self) -> bool:
        return bool(self.api_key)

    def get_model_name(self) -> str:
        return self.model


class OllamaProvider(BaseProvider):
    """Local Ollama Provider (No API key needed)"""

    def __init__(self, model: str = "mistral:7b-instruct-v0.2-q4_K_M",
                 base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url

    def generate(self, prompt: str, system_prompt: str = "",
                 max_tokens: int = 4096, temperature: float = 0.3) -> AIResponse:
        start_time = time.time()
        try:
            import ollama
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt or "You are NyxAI."},
                    {"role": "user", "content": prompt}
                ],
                options={
                    "num_predict": max_tokens,
                    "temperature": temperature
                }
            )

            latency = int((time.time() - start_time) * 1000)

            return AIResponse(
                content=response["message"]["content"],
                model=self.model,
                provider="ollama",
                tokens_used=response.get("eval_count", 0),
                latency_ms=latency
            )
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            return AIResponse(
                content="", model=self.model, provider="ollama",
                error=str(e)
            )

    def is_available(self) -> bool:
        try:
            import ollama
            ollama.list()
            return True
        except Exception:
            return False

    def get_model_name(self) -> str:
        return self.model


class CustomProvider(BaseProvider):
    """Custom API endpoint (OpenAI-compatible)"""

    def __init__(self, api_key: str, base_url: str, model: str):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model

    def generate(self, prompt: str, system_prompt: str = "",
                 max_tokens: int = 4096, temperature: float = 0.3) -> AIResponse:
        start_time = time.time()
        try:
            import openai
            client = openai.OpenAI(api_key=self.api_key, base_url=self.base_url)

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature
            )

            latency = int((time.time() - start_time) * 1000)

            return AIResponse(
                content=response.choices[0].message.content,
                model=self.model,
                provider="custom",
                tokens_used=getattr(response.usage, 'total_tokens', 0),
                latency_ms=latency
            )
        except Exception as e:
            logger.error(f"Custom provider error: {e}")
            return AIResponse(
                content="", model=self.model, provider="custom", tokens_used=0
            )
