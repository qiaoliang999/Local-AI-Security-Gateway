"""
Configuration module for Local AI Security Gateway.
Supports environment variables and .env files for easy customization.
"""
import os
from dataclasses import dataclass, field
from typing import Dict, Optional

# Try to load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


@dataclass
class AIProvider:
    """Represents an AI provider endpoint configuration."""
    name: str
    base_url: str
    api_path_prefix: str  # e.g. "/v1" for OpenAI-compatible APIs
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer"


# ─── Supported AI Providers ───────────────────────────────────────────────────
# Each provider is mapped by a key used in routing logic.
AI_PROVIDERS: Dict[str, AIProvider] = {
    "openai": AIProvider(
        name="OpenAI",
        base_url="https://api.openai.com",
        api_path_prefix="/v1",
    ),
    "anthropic": AIProvider(
        name="Anthropic (Claude)",
        base_url="https://api.anthropic.com",
        api_path_prefix="/v1",
        auth_header="x-api-key",
        auth_prefix="",
    ),
    "google": AIProvider(
        name="Google Gemini",
        base_url="https://generativelanguage.googleapis.com",
        api_path_prefix="/v1beta",
    ),
    "groq": AIProvider(
        name="Groq",
        base_url="https://api.groq.com",
        api_path_prefix="/openai/v1",
    ),
    "mistral": AIProvider(
        name="Mistral AI",
        base_url="https://api.mistral.ai",
        api_path_prefix="/v1",
    ),
    "deepseek": AIProvider(
        name="DeepSeek",
        base_url="https://api.deepseek.com",
        api_path_prefix="/v1",
    ),
    "xai": AIProvider(
        name="xAI (Grok)",
        base_url="https://api.x.ai",
        api_path_prefix="/v1",
    ),
    "cohere": AIProvider(
        name="Cohere",
        base_url="https://api.cohere.com",
        api_path_prefix="/v2",
    ),
    "together": AIProvider(
        name="Together AI",
        base_url="https://api.together.xyz",
        api_path_prefix="/v1",
    ),
    "openrouter": AIProvider(
        name="OpenRouter",
        base_url="https://openrouter.ai",
        api_path_prefix="/api/v1",
    ),
    "ollama": AIProvider(
        name="Ollama (Local)",
        base_url="http://localhost:11434",
        api_path_prefix="/api",
    ),
}


@dataclass
class GatewayConfig:
    """Main gateway configuration loaded from environment."""
    host: str = field(default_factory=lambda: os.getenv("GATEWAY_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("GATEWAY_PORT", "8000")))

    # Default upstream provider when client connects to localhost
    default_provider: str = field(
        default_factory=lambda: os.getenv("DEFAULT_PROVIDER", "openai")
    )

    # Custom upstream URL override (takes priority over default_provider)
    custom_upstream_url: Optional[str] = field(
        default_factory=lambda: os.getenv("CUSTOM_UPSTREAM_URL")
    )

    # Proxy settings for upstream requests (e.g. Clash, V2Ray)
    http_proxy: Optional[str] = field(
        default_factory=lambda: os.getenv("HTTPS_PROXY")
        or os.getenv("HTTP_PROXY")
        or os.getenv("https_proxy")
        or os.getenv("http_proxy")
    )

    # Timeout for upstream requests in seconds
    upstream_timeout: float = field(
        default_factory=lambda: float(os.getenv("UPSTREAM_TIMEOUT", "120"))
    )

    # Enable/disable DLP
    dlp_enabled: bool = field(
        default_factory=lambda: os.getenv("DLP_ENABLED", "true").lower() == "true"
    )

    # Log level
    log_level: str = field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "INFO")
    )

    def get_default_provider(self) -> AIProvider:
        """Get the configured default AI provider."""
        return AI_PROVIDERS.get(self.default_provider, AI_PROVIDERS["openai"])


# Singleton configuration
config = GatewayConfig()
