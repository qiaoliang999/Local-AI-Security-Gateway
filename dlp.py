"""
Enhanced DLP (Data Loss Prevention) Engine.
Detects and redacts sensitive information in AI API payloads.
Thread-safe with comprehensive pattern library.
"""
import re
import json
import logging
import datetime
import threading
from typing import Any, Dict, List, Tuple

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


class DLPEngine:
    """
    Data Loss Prevention Engine with bidirectional redaction.
    Detects sensitive data patterns, redacts them before sending upstream,
    and restores originals in the response for a seamless developer experience.
    """

    def __init__(self):
        # Comprehensive registry of sensitive data patterns
        # Format: { "CATEGORY": (regex_pattern, description) }
        self.patterns: Dict[str, Tuple[str, str]] = {
            # ── Cloud Provider Keys ────────────────────────────────────────
            "AWS_ACCESS_KEY": (
                r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])",
                "AWS Access Key ID",
            ),
            "AWS_SECRET_KEY": (
                r"(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
                "AWS Secret Access Key",
            ),
            "GCP_SERVICE_KEY": (
                r"(?i)\"private_key\":\s*\"-----BEGIN (?:RSA )?PRIVATE KEY-----",
                "GCP Service Account Key",
            ),
            "AZURE_KEY": (
                r"(?i)(?:azure|subscription)[_-]?(?:key|secret|password)\s*[=:]\s*['\"]?([A-Za-z0-9+/=]{32,})['\"]?",
                "Azure API Key",
            ),

            # ── AI Provider API Keys ───────────────────────────────────────
            "OPENAI_KEY": (
                r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}",
                "OpenAI API Key (legacy)",
            ),
            "OPENAI_KEY_V2": (
                r"sk-proj-[A-Za-z0-9_-]{60,}",
                "OpenAI API Key (project)",
            ),
            "ANTHROPIC_KEY": (
                r"sk-ant-[A-Za-z0-9_-]{80,}",
                "Anthropic API Key",
            ),
            "GOOGLE_AI_KEY": (
                r"AIza[A-Za-z0-9_-]{35}",
                "Google AI API Key",
            ),
            "GROQ_KEY": (
                r"gsk_[A-Za-z0-9]{52,}",
                "Groq API Key",
            ),
            "DEEPSEEK_KEY": (
                r"sk-[a-f0-9]{48,}",
                "DeepSeek API Key",
            ),
            "COHERE_KEY": (
                r"(?i)(?:cohere[_-]?(?:api[_-]?)?key)\s*[=:]\s*['\"]?([A-Za-z0-9]{40})['\"]?",
                "Cohere API Key",
            ),
            "HUGGINGFACE_TOKEN": (
                r"hf_[A-Za-z0-9]{34}",
                "HuggingFace Token",
            ),

            # ── Personal Identifiable Information (PII) ────────────────────
            "EMAIL": (
                r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
                "Email Address",
            ),
            "PHONE_US": (
                r"(?<!\d)(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s][0-9]{3}[-.\s]?[0-9]{4}(?!\d)",
                "US Phone Number",
            ),
            "PHONE_CN": (
                r"(?<![A-Za-z0-9])(?:\+86[-.\s]?)?1[3-9][0-9]{9}(?![A-Za-z0-9])",
                "Chinese Phone Number",
            ),
            "SSN": (
                r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)",
                "Social Security Number",
            ),
            "CREDIT_CARD": (
                r"(?<!\d)(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})(?!\d)",
                "Credit Card Number",
            ),
            "CN_ID_CARD": (
                r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)",
                "Chinese ID Card Number",
            ),

            # ── Infrastructure / Connection Strings ────────────────────────
            "DATABASE_URL": (
                r"(?i)(?:mysql|postgres|postgresql|mongodb|redis|mssql)://[^\s'\"]+",
                "Database Connection String",
            ),
            "PRIVATE_KEY": (
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
                "Private Key",
            ),
            "JWT_TOKEN": (
                r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                "JWT Token",
            ),

            # ── Generic Secret Detection ──────────────────────────────────
            "GENERIC_SECRET": (
                r"(?i)(?:api[_-]?key|secret|token|password|passwd|credential|auth[_-]?token)[_-]?\s*[=:]\s*['\"]?([A-Za-z0-9_/+=-]{16,64})['\"]?",
                "Generic API Key / Secret",
            ),

            # ── IP Addresses (Private Networks) ────────────────────────────
            "PRIVATE_IP": (
                r"(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)",
                "Private IP Address",
            ),
        }

        # Thread-safe vault for bidirectional mapping
        self._lock = threading.Lock()
        self.vault: Dict[str, str] = {}
        self.redact_counter: int = 0
        self.incident_log: List[Dict[str, Any]] = []

        # Compile patterns for performance
        self._compiled_patterns: Dict[str, re.Pattern] = {
            name: re.compile(pattern)
            for name, (pattern, _) in self.patterns.items()
        }

    def redact_text(self, text: str) -> str:
        """Scan text and replace sensitive patterns with placeholders."""
        redacted_text = text

        for entity_type, compiled_re in self._compiled_patterns.items():
            matches = list(compiled_re.finditer(redacted_text))
            if not matches:
                continue

            # Process in reverse so index positions remain valid
            for match in reversed(matches):
                # For patterns with capture groups, redact only the captured group
                if match.lastindex and match.lastindex >= 1:
                    secret_value = match.group(1)
                    start, end = match.span(1)
                else:
                    secret_value = match.group(0)
                    start, end = match.span()

                # Skip very short matches to reduce false positives
                if len(secret_value) < 4:
                    continue

                with self._lock:
                    placeholder = f"[REDACTED_{entity_type}_{self.redact_counter}]"
                    self.vault[placeholder] = secret_value
                    self.redact_counter += 1

                    # Create obfuscated version for audit logging
                    if len(secret_value) > 6:
                        obfuscated = secret_value[:3] + "****" + secret_value[-3:]
                    elif len(secret_value) > 4:
                        obfuscated = secret_value[:2] + "****" + secret_value[-2:]
                    else:
                        obfuscated = "****"

                    _, desc = self.patterns[entity_type]
                    self.incident_log.append({
                        "id": self.redact_counter - 1,
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "type": entity_type,
                        "description": desc,
                        "placeholder": placeholder,
                        "obfuscated": obfuscated,
                    })

                logger.warning(f"🛡️ [DLP] Sensitive {entity_type} detected and secured → {placeholder}")

                redacted_text = redacted_text[:start] + placeholder + redacted_text[end:]

        return redacted_text

    def redact_payload(self, payload: Any) -> Any:
        """Recursively redact text within a JSON-serializable payload."""
        if isinstance(payload, str):
            return self.redact_text(payload)
        elif isinstance(payload, dict):
            return {k: self.redact_payload(v) for k, v in payload.items()}
        elif isinstance(payload, list):
            return [self.redact_payload(item) for item in payload]
        else:
            return payload

    def unredact_text(self, text: str) -> str:
        """Restore original values from placeholders in response text."""
        restored_text = text
        with self._lock:
            for placeholder, original_value in self.vault.items():
                if placeholder in restored_text:
                    restored_text = restored_text.replace(placeholder, original_value)
        return restored_text

    def unredact_payload(self, payload: Any) -> Any:
        """Recursively restore placeholders to original values in a payload."""
        if isinstance(payload, str):
            return self.unredact_text(payload)
        elif isinstance(payload, dict):
            return {k: self.unredact_payload(v) for k, v in payload.items()}
        elif isinstance(payload, list):
            return [self.unredact_payload(item) for item in payload]
        else:
            return payload

    def get_stats(self) -> Dict[str, Any]:
        """Return statistics about DLP interceptions."""
        with self._lock:
            type_counts: Dict[str, int] = {}
            for entry in self.incident_log:
                t = entry["type"]
                type_counts[t] = type_counts.get(t, 0) + 1

            return {
                "total_intercepts": len(self.incident_log),
                "type_breakdown": type_counts,
                "patterns_loaded": len(self.patterns),
            }


# Module-level singleton
dlp_engine = DLPEngine()
