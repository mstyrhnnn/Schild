import os
from abc import ABC, abstractmethod
from typing import Optional, Callable, Iterator
from enum import Enum

from schild.core.config import (
    AIProvider, DEFAULT_AI_PROVIDER,
    OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY,
    TRIAGE_MODEL, ANALYST_MODEL,
    ANTHROPIC_TRIAGE_MODEL, ANTHROPIC_ANALYST_MODEL,
    GEMINI_TRIAGE_MODEL, GEMINI_ANALYST_MODEL,
    OLLAMA_TRIAGE_MODEL, OLLAMA_ANALYST_MODEL, OLLAMA_BASE_URL, OLLAMA_API_KEY,
    COLORS,
)


class ModelTier(Enum):
    TRIAGE  = "triage"   # Fast / cheap
    ANALYST = "analyst"  # Powerful / deep


class AIProviderBase(ABC):
    """
    Abstract base for all SCHILD AI providers.
    Supports two call modes:
      - complete()  → returns full response string
      - stream()    → yields tokens one by one
    """

    @abstractmethod
    def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        tier: ModelTier = ModelTier.ANALYST,
        timeout: int = 120,
    ) -> str:
        """Return full response text."""
        ...

    @abstractmethod
    def stream(
        self,
        prompt: str,
        system_prompt: str = "",
        tier: ModelTier = ModelTier.ANALYST,
        timeout: int = 120,
        callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Stream response, calling callback per token. Returns full text."""
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        ...

    @property
    @abstractmethod
    def triage_model(self) -> str:
        ...

    @property
    @abstractmethod
    def analyst_model(self) -> str:
        ...

    def _model_for_tier(self, tier: ModelTier) -> str:
        return self.triage_model if tier == ModelTier.TRIAGE else self.analyst_model


# OpenAI 

class OpenAIProvider(AIProviderBase):
    """OpenAI GPT provider via openai SDK."""

    def __init__(self, api_key: Optional[str] = None):
        try:
            from openai import OpenAI  # type: ignore
        except ImportError:
            raise ImportError("Install openai: pip install openai")

        from schild.core.config import OPENAI_BASE_URL
        
        self._client = OpenAI(
            api_key=api_key or OPENAI_API_KEY,
            base_url=OPENAI_BASE_URL,
        )

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def triage_model(self) -> str:
        return TRIAGE_MODEL

    @property
    def analyst_model(self) -> str:
        return ANALYST_MODEL

    def complete(self, prompt: str, system_prompt: str = "",
                 tier: ModelTier = ModelTier.ANALYST, timeout: int = 120) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            resp = self._client.chat.completions.create(
                model=self._model_for_tier(tier),
                messages=messages,
                timeout=timeout,
            )
            return resp.choices[0].message.content or ""
        except Exception as e:
            return f"OpenAI API error: {e}"

    def stream(self, prompt: str, system_prompt: str = "",
               tier: ModelTier = ModelTier.ANALYST, timeout: int = 120,
               callback: Optional[Callable[[str], None]] = None) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            full_text = []
            with self._client.chat.completions.create(
                model=self._model_for_tier(tier),
                messages=messages,
                stream=True,
                timeout=timeout,
            ) as stream_resp:
                for chunk in stream_resp:
                    token = (chunk.choices[0].delta.content or "") if chunk.choices else ""
                    if token:
                        full_text.append(token)
                        if callback:
                            callback(token)
                        else:
                            print(token, end="", flush=True)
            if not callback:
                print()
            return "".join(full_text)
        except Exception as e:
            return f"OpenAI stream error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Anthropic Provider
# ─────────────────────────────────────────────────────────────────────────────

class AnthropicProvider(AIProviderBase):
    """Anthropic Claude provider."""

    def __init__(self, api_key: Optional[str] = None):
        try:
            import anthropic as _anthropic  # type: ignore
            self._anthropic = _anthropic
        except ImportError:
            raise ImportError("Install anthropic: pip install anthropic")

        self._client = _anthropic.Anthropic(api_key=api_key or ANTHROPIC_API_KEY)

    @property
    def provider_name(self) -> str:
        return "anthropic"

    @property
    def triage_model(self) -> str:
        return ANTHROPIC_TRIAGE_MODEL

    @property
    def analyst_model(self) -> str:
        return ANTHROPIC_ANALYST_MODEL

    def complete(self, prompt: str, system_prompt: str = "",
                 tier: ModelTier = ModelTier.ANALYST, timeout: int = 120) -> str:
        kwargs = {
            "model": self._model_for_tier(tier),
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            kwargs["system"] = system_prompt

        try:
            msg = self._client.messages.create(**kwargs)
            return msg.content[0].text if msg.content else ""
        except Exception as e:
            return f"Anthropic API error: {e}"

    def stream(self, prompt: str, system_prompt: str = "",
               tier: ModelTier = ModelTier.ANALYST, timeout: int = 120,
               callback: Optional[Callable[[str], None]] = None) -> str:
        kwargs = {
            "model": self._model_for_tier(tier),
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            kwargs["system"] = system_prompt

        try:
            full_text = []
            with self._client.messages.stream(**kwargs) as stream_resp:
                for token in stream_resp.text_stream:
                    full_text.append(token)
                    if callback:
                        callback(token)
                    else:
                        print(token, end="", flush=True)
            if not callback:
                print()
            return "".join(full_text)
        except Exception as e:
            return f"Anthropic stream error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Gemini Provider
# ─────────────────────────────────────────────────────────────────────────────

class GeminiProvider(AIProviderBase):
    """Google Gemini provider."""

    def __init__(self, api_key: Optional[str] = None):
        try:
            import google.generativeai as genai  # type: ignore
            self._genai = genai
        except ImportError:
            raise ImportError("Install google-generativeai: pip install google-generativeai")

        genai.configure(api_key=api_key or GEMINI_API_KEY)

    @property
    def provider_name(self) -> str:
        return "gemini"

    @property
    def triage_model(self) -> str:
        return GEMINI_TRIAGE_MODEL

    @property
    def analyst_model(self) -> str:
        return GEMINI_ANALYST_MODEL

    def _make_model(self, tier: ModelTier, system_prompt: str = ""):
        config = {"temperature": 0.3}
        if system_prompt:
            return self._genai.GenerativeModel(
                model_name=self._model_for_tier(tier),
                system_instruction=system_prompt,
                generation_config=config,
            )
        return self._genai.GenerativeModel(
            model_name=self._model_for_tier(tier),
            generation_config=config,
        )

    def complete(self, prompt: str, system_prompt: str = "",
                 tier: ModelTier = ModelTier.ANALYST, timeout: int = 120) -> str:
        try:
            model = self._make_model(tier, system_prompt)
            resp = model.generate_content(prompt)
            return resp.text or ""
        except Exception as e:
            return f"Gemini API error: {e}"

    def stream(self, prompt: str, system_prompt: str = "",
               tier: ModelTier = ModelTier.ANALYST, timeout: int = 120,
               callback: Optional[Callable[[str], None]] = None) -> str:
        try:
            model = self._make_model(tier, system_prompt)
            full_text = []
            for chunk in model.generate_content(prompt, stream=True):
                token = chunk.text or ""
                if token:
                    full_text.append(token)
                    if callback:
                        callback(token)
                    else:
                        print(token, end="", flush=True)
            if not callback:
                print()
            return "".join(full_text)
        except Exception as e:
            return f"Gemini stream error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Ollama Provider (local / self-hosted)
# ─────────────────────────────────────────────────────────────────────────────

class OllamaProvider(AIProviderBase):
    """
    Ollama local LLM provider.

    Berkomunikasi dengan Ollama REST API menggunakan endpoint:
      POST /api/chat  (OpenAI-compatible chat format)

    Konfigurasi via env:
      OLLAMA_BASE_URL            — default: http://localhost:11434
      SCHILD_OLLAMA_TRIAGE_MODEL  — default: llama3
      SCHILD_OLLAMA_ANALYST_MODEL — default: llama3
      OLLAMA_API_KEY              — opsional, untuk server Ollama remote dengan auth
    """

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        try:
            import requests as _requests  # type: ignore
            self._requests = _requests
        except ImportError:
            raise ImportError("Install requests: pip install requests")

        self._base_url = (base_url or OLLAMA_BASE_URL).rstrip("/")
        self._api_key  = api_key or OLLAMA_API_KEY  # None = tidak perlu auth

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self._api_key:
            h["Authorization"] = f"Bearer {self._api_key}"
        return h

    @property
    def provider_name(self) -> str:
        return "ollama"

    @property
    def triage_model(self) -> str:
        return OLLAMA_TRIAGE_MODEL

    @property
    def analyst_model(self) -> str:
        return OLLAMA_ANALYST_MODEL

    def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        tier: ModelTier = ModelTier.ANALYST,
        timeout: int = 120,
    ) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self._model_for_tier(tier),
            "messages": messages,
            "stream": False,
        }

        try:
            resp = self._requests.post(
                f"{self._base_url}/api/chat",
                json=payload,
                headers=self._headers(),
                timeout=timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("message", {}).get("content", "") or ""
        except self._requests.exceptions.ConnectionError:
            return (
                f"Ollama connection error: pastikan Ollama berjalan di "
                f"{self._base_url} (jalankan: ollama serve)"
            )
        except Exception as e:
            return f"Ollama API error: {e}"

    def stream(
        self,
        prompt: str,
        system_prompt: str = "",
        tier: ModelTier = ModelTier.ANALYST,
        timeout: int = 120,
        callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        import json as _json

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self._model_for_tier(tier),
            "messages": messages,
            "stream": True,
        }

        try:
            full_text: list[str] = []
            with self._requests.post(
                f"{self._base_url}/api/chat",
                json=payload,
                headers=self._headers(),
                timeout=timeout,
                stream=True,
            ) as resp:
                resp.raise_for_status()
                for raw_line in resp.iter_lines():
                    if not raw_line:
                        continue
                    try:
                        chunk = _json.loads(raw_line)
                    except _json.JSONDecodeError:
                        continue
                    token = chunk.get("message", {}).get("content", "") or ""
                    if token:
                        full_text.append(token)
                        if callback:
                            callback(token)
                        else:
                            print(token, end="", flush=True)
                    if chunk.get("done"):
                        break
            if not callback:
                print()
            return "".join(full_text)
        except self._requests.exceptions.ConnectionError:
            return (
                f"Ollama connection error: pastikan Ollama berjalan di "
                f"{self._base_url} (jalankan: ollama serve)"
            )
        except Exception as e:
            return f"Ollama stream error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────────────────────────────────────

def create_provider(
    provider: Optional[AIProvider] = None,
    api_key: Optional[str] = None,
) -> AIProviderBase:
    """
    Factory — returns the correct AIProvider instance.
    Falls back to DEFAULT_AI_PROVIDER from config if not specified.
    """
    chosen = provider or DEFAULT_AI_PROVIDER

    if chosen == AIProvider.OPENAI:
        return OpenAIProvider(api_key=api_key)
    elif chosen == AIProvider.ANTHROPIC:
        return AnthropicProvider(api_key=api_key)
    elif chosen == AIProvider.GEMINI:
        return GeminiProvider(api_key=api_key)
    elif chosen == AIProvider.OLLAMA:
        return OllamaProvider(api_key=api_key)
    else:
        raise ValueError(f"Unknown AI provider: {chosen}")


def verify_provider(provider: AIProviderBase) -> bool:
    """Quick connectivity test — returns True if provider responds."""
    try:
        test_response = provider.complete(
            "Reply with exactly: OK",
            system_prompt="You are a test agent.",
            tier=ModelTier.TRIAGE,
            timeout=15,
        )
        ok = "ok" in test_response.lower() or len(test_response) > 0
        if ok:
            print(
                f"{COLORS['success']} AI Provider [{provider.provider_name}] "
                f"({provider.triage_model} / {provider.analyst_model}) — Connected{COLORS['reset']}"
            )
        return ok
    except Exception as e:
        print(f"{COLORS['error']} AI Provider connection failed: {e}{COLORS['reset']}")
        return False
