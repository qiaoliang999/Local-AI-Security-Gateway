import re
import json
import logging
from typing import Any, Dict

# Set up basic logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

class DLPEngine:
    def __init__(self):
        # A simple registry of regex patterns to catch sensitive data
        self.patterns = {
            "EMAIL": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "AWS_KEY": r"(?i)AKIA[0-9A-Z]{16}",
            "GENERIC_API_KEY": r"(?i)(?:key|token|secret|password)[_-]?\s*[:=]\s*['"]?([a-zA-Z0-9]{16,})['"]?"
        }
        # Keep track of redacted values to un-redact them later if needed
        self.vault = {}
        self.redact_counter = 0

    def redact_text(self, text: str) -> str:
        """Scan text and replace sensitive patterns with placeholders."""
        redacted_text = text
        for entity_type, pattern in self.patterns.items():
            matches = re.finditer(pattern, redacted_text)
            # Process matches in reverse order so replacements don't shift indices
            for match in reversed(list(matches)):
                # If the generic pattern matches, the actual secret might be in a capture group
                if entity_type == "GENERIC_API_KEY" and match.lastindex == 1:
                    secret_value = match.group(1)
                    start, end = match.span(1)
                else:
                    secret_value = match.group(0)
                    start, end = match.span()

                placeholder = f"[REDACTED_{entity_type}_{self.redact_counter}]"
                self.vault[placeholder] = secret_value
                logger.warning(f"Intercepted sensitive data: {entity_type}")
                
                redacted_text = redacted_text[:start] + placeholder + redacted_text[end:]
                self.redact_counter += 1

        return redacted_text

    def redact_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively redact text within a JSON payload."""
        if isinstance(payload, str):
            return self.redact_text(payload)
        elif isinstance(payload, dict):
            return {k: self.redact_payload(v) for k, v in payload.items()}
        elif isinstance(payload, list):
            return [self.redact_payload(item) for item in payload]
        else:
            return payload

    def unredact_text(self, text: str) -> str:
        """Restore original values from placeholders in the response."""
        restored_text = text
        for placeholder, original_value in self.vault.items():
            if placeholder in restored_text:
                restored_text = restored_text.replace(placeholder, original_value)
        return restored_text

    def unredact_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively restore text within a JSON payload."""
        if isinstance(payload, str):
            return self.unredact_text(payload)
        elif isinstance(payload, dict):
            return {k: self.unredact_payload(v) for k, v in payload.items()}
        elif isinstance(payload, list):
            return [self.unredact_payload(item) for item in payload]
        else:
            return payload

dlp_engine = DLPEngine()
