
import re


UNSAFE_PATTERNS = {
    "violent_threat": [
        r"\bi will kill you\b",
        r"\bi am going to kill you\b",
        r"\bkill that person\b",
        r"\bhow to murder someone\b",
    ],

    "weapons_and_explosives": [
        r"\bhow to make a bomb\b",
        r"\bbuild an explosive device\b",
        r"\bhow to make an explosive\b",
    ],

    "poisoning": [
        r"\bhow to poison someone\b",
        r"\bways to poison a person\b",
    ],

    "harassment": [
        r"\bhow to threaten someone\b",
        r"\bhelp me intimidate someone\b",
    ]
}


def check_content_safety(text: str) -> dict:

    if not isinstance(text, str) or not text.strip():
        return {
            "is_unsafe": False,
            "category": None,
            "matched_patterns": [],
            "message": "Empty or invalid input"
        }

    normalized_text = re.sub(r"\s+", " ", text.lower())

    matched_patterns = []
    detected_category = None

    for category, patterns in UNSAFE_PATTERNS.items():

        for pattern in patterns:

            if re.search(pattern, normalized_text, re.IGNORECASE):
                matched_patterns.append(pattern)

                if detected_category is None:
                    detected_category = category

    is_unsafe = len(matched_patterns) > 0

    return {
        "is_unsafe": is_unsafe,
        "category": detected_category,
        "matched_patterns": matched_patterns,
        "message": (
            "Potentially unsafe content detected"
            if is_unsafe
            else "No known unsafe content pattern detected"
        )
    }
