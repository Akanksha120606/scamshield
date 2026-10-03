import re

# Order matters: the most specific patterns come first
REDACTION_PATTERNS = [
    ("EMAIL",   re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
    ("UPI_ID",  re.compile(r"\b[\w.\-]{2,}@[a-zA-Z]{2,}\b")),
    ("PAN",     re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")),
    ("AADHAAR", re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")),
    ("CARD",    re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("PHONE",   re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)")),
    ("OTP",     re.compile(r"(?i)(\b(?:otp|code|pin)\b[^\d\n]{0,20})(\d{4,8})\b")),
    ("ACCOUNT", re.compile(r"\b\d{9,18}\b")),
]


def redact(text: str):
    """Returns (cleaned_text, number_of_items_hidden)."""
    count = 0
    for label, pattern in REDACTION_PATTERNS:
        if label == "OTP":
            text, n = pattern.subn(r"\1[OTP]", text)
        else:
            text, n = pattern.subn(f"[{label}]", text)
        count += n
    return text, count