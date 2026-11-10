
import re


# Initial rule-based detection patterns.
# This is a baseline detector, not a complete security solution.
PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"disregard\s+(all\s+)?previous\s+instructions",
    r"forget\s+(all\s+)?(your\s+)?instructions",
    r"reveal\s+(your\s+)?system\s+prompt",
    r"show\s+(me\s+)?(your\s+)?system\s+prompt",
    r"act\s+as\s+if\s+you\s+have\s+no\s+restrictions",
    r"bypass\s+(your\s+)?(security|safety|restrictions)",
    r"developer\s+message",
    r"system\s+prompt",
    r"jailbreak"
]


def detect_prompt_injection(text: str) -> dict:
    """
    Detect common prompt injection phrases.
    Returns detection status and matched patterns.
    """

    if not isinstance(text, str) or not text.strip():
        return {
            "is_suspicious": False,
            "matched_patterns": [],
            "message": "Empty or invalid input"
        }

    normalized_text = re.sub(r"\s+", " ", text.lower())

    matched_patterns = []

    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, normalized_text, re.IGNORECASE):
            matched_patterns.append(pattern)

    is_suspicious = len(matched_patterns) > 0

    return {
        "is_suspicious": is_suspicious,
        "matched_patterns": matched_patterns,
        "message": (
            "Potential prompt injection detected"
            if is_suspicious
            else "No known injection pattern detected"
        )
    }
