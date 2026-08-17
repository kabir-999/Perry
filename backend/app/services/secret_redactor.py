import re

# Common keys that indicate a secret value
SECRET_KEY_PATTERNS = re.compile(
    r"(?i)(api[_-]?key|secret[_-]?key|password|passwd|db[_-]?password|db[_-]?pass|"
    r"aws[_-]?secret|aws[_-]?access|private[_-]?key|token|access[_-]?token|auth[_-]?token|"
    r"credential|client[_-]?secret|database_url)"
)

# Values that look like actual secrets (not placeholders like "your_key_here")
SECRET_VALUE_PATTERNS = [
    # AWS Access Key ID
    re.compile(r"(?i)AKIA[0-9A-Z]{16}"),
    # Common token prefixes (GitHub, Stripe, Slack, etc.)
    re.compile(r"(?i)(ghp|gho|ghu|ghs|ghr|sk_live|sk_test|xoxb|xoxp|gsk)_[a-zA-Z0-9]{16,}"),
    # High entropy base64-ish or hex strings (very rough heuristic, usually needs context)
    # We mainly rely on the key name, but this can catch things if the key is generic.
    re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"),
    re.compile(r"^[0-9a-f]{32,}$", re.IGNORECASE),
]


def redact_env_values(text: str) -> str:
    """Redact values in KEY=value format where KEY looks sensitive or VALUE looks like a secret."""
    lines = text.splitlines()
    redacted_lines = []
    for line in lines:
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("#"):
            redacted_lines.append(line)
            continue
        
        parts = line.split("=", 1)
        if len(parts) == 2:
            key, val = parts
            key = key.strip()
            val = val.strip()
            
            # Simple check if value is a placeholder
            val_lower = val.lower()
            is_placeholder = (
                not val
                or val_lower in ("null", "none", "true", "false")
                or "your_" in val_lower
                or "changeme" in val_lower
                or val_lower == "example"
                or val_lower == "test"
            )
            
            if not is_placeholder and (SECRET_KEY_PATTERNS.search(key) or _looks_like_secret(val)):
                redacted_lines.append(f"{key}=[REDACTED]")
            else:
                redacted_lines.append(line)
        else:
            redacted_lines.append(line)
            
    return "\n".join(redacted_lines)


def redact_json_secrets(text: str) -> str:
    """Redact values for sensitive keys in JSON-like strings.
    This uses regex to avoid full parsing/serialization if the JSON is malformed.
    """
    # Simple regex to replace "key": "value" where key is sensitive
    def replacer(match):
        key = match.group(1)
        if SECRET_KEY_PATTERNS.search(key):
            # match.group(0) is the whole match: "key": "value"
            return f'"{key}": "[REDACTED]"'
        return match.group(0)

    # Matches "key": "value" or "key": 123
    return re.sub(r'"([^"]+)":\s*(?:"[^"]*"|\d+|true|false|null)', replacer, text)


def redact_secrets_from_summary(summary: dict) -> dict:
    """Scrub sensitive information from a scan summary before external use."""
    import copy
    
    redacted_summary = copy.deepcopy(summary)
    
    if "findings" in redacted_summary:
        for finding in redacted_summary["findings"]:
            finding["evidence"] = _redact_text(finding.get("evidence", ""))
            finding["response_summary"] = _redact_text(finding.get("response_summary", ""))
            
    return redacted_summary

def _redact_text(text: str) -> str:
    if not text:
        return text
    text = redact_env_values(text)
    # Could add more redaction logic here (e.g. redact_json_secrets)
    return text

def _looks_like_secret(val: str) -> bool:
    # Strip quotes
    val = val.strip("\"'")
    for pattern in SECRET_VALUE_PATTERNS:
        if pattern.search(val):
            # Only match the generic b64/hex if it's long enough
            if pattern.pattern.startswith("^") and len(val) < 32:
                continue
            return True
    return False
