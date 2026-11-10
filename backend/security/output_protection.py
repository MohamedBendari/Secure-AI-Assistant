
import re


SENSITIVE_PATTERNS = {
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",

    "phone": r"\b(?:\+?20|0)?1[0125][0-9]{8}\b",

    "jwt_token": r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",

    "api_key": r"\b(?:sk-[A-Za-z0-9_-]{10,}|AIza[A-Za-z0-9_-]{20,})\b",

    "password_assignment": r"(?i)\b(password|passwd|secret)\s*[:=]\s*\S+"
}


def protect_output(text: str) -> dict:

    if not isinstance(text, str):
        return {
            "is_sensitive": False,
            "protected_output": "",
            "detected_types": [],
            "message": "Invalid output"
        }

    protected_text = text
    detected_types = []

    for category, pattern in SENSITIVE_PATTERNS.items():

        if re.search(pattern, protected_text):
            detected_types.append(category)

            protected_text = re.sub(
                pattern,
                "[REDACTED]",
                protected_text
            )

    return {
        "is_sensitive": len(detected_types) > 0,
        "protected_output": protected_text,
        "detected_types": detected_types,
        "message": (
            "Sensitive information detected and redacted"
            if detected_types
            else "No known sensitive information detected"
        )
    }
