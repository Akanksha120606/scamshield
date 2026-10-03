import re
from urllib.parse import urlparse

# Finds links in the text
URL_PATTERN = re.compile(
    r"(?:https?://|www\.)[^\s]+"
    r"|\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|rb\.gy|shorturl\.at)/\S+",
    re.IGNORECASE,
)

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "shorturl.at"}
SUSPICIOUS_TLDS = (".xyz", ".top", ".click", ".link", ".online", ".site", ".icu", ".buzz", ".cfd", ".shop")

# brand keyword -> its real domains
OFFICIAL_DOMAINS = {
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "axisbank": ["axisbank.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"],
    "irctc": ["irctc.co.in"],
    "indiapost": ["indiapost.gov.in"],
}

# (description, regex, points)
TEXT_PATTERNS = [
    ("Creates urgency or threatens to block/suspend something",
     r"\b(urgent|immediately|within \d+ (hours?|minutes?)|last warning|expires? today|blocked|suspended|deactivated)\b", 20),
    ("Asks for OTP, PIN, CVV or password",
     r"\b(otp|pin|cvv|password|passcode)\b", 25),
    ("Pushes a KYC / PAN / Aadhaar update",
     r"\b(kyc|pan (card )?(update|verification)|aadhaar (update|link))\b", 20),
    ("Lottery, prize or reward bait",
     r"\b(lottery|you have won|winner|lucky draw|cashback|reward points|claim your)\b", 20),
    ("Too-good-to-be-true job or earning offer",
     r"\b(work from home|part[- ]time job|task[- ]based|like and earn|earn (rs\.?|₹)?\s?\d+)", 20),
    ("Claims to be police, customs or a government agency",
     r"\b(cbi|police|customs|narcotics|arrest warrant|digital arrest|cyber ?crime department|trai)\b", 25),
    ("Asks you to approve a payment request or pay a fee",
     r"\b(collect request|approve the request|scan (this )?qr|processing fee|registration fee|refundable)\b", 20),
    ("Promises guaranteed investment returns",
     r"\b(guaranteed returns?|double your money|stock tips|vip group|trading group)\b", 15),
    ("Fake parcel/courier problem",
     r"\b(parcel|courier|package|delivery) (is )?(held|stuck|pending|failed|on hold)\b", 15),
]


def get_host(url: str) -> str:
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def check_rules(text: str) -> dict:
    score = 0
    flags = []

    # 1. Check the wording of the message
    for description, pattern, points in TEXT_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            score += points
            flags.append(description)

    # 2. Check every link in the message
    urls = URL_PATTERN.findall(text)
    for url in urls:
        host = get_host(url)

        if host in SHORTENERS:
            score += 15
            flags.append(f"Shortened link hides the real destination ({host})")

        if host.endswith(SUSPICIOUS_TLDS):
            score += 20
            flags.append(f"Link uses a domain ending often used in scams ({host})")

        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            score += 25
            flags.append("Link uses a raw IP address instead of a website name")

        for brand, real_domains in OFFICIAL_DOMAINS.items():
            if brand in host:
                is_real = any(host == d or host.endswith("." + d) for d in real_domains)
                if not is_real:
                    score += 35
                    flags.append(f"Link imitates '{brand}' but is not its real website ({host})")

    return {"score": min(score, 100), "flags": list(dict.fromkeys(flags)), "urls": urls}