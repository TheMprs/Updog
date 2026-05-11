from langdetect import detect, LangDetectException
from bs4 import BeautifulSoup
import re
from .utils import parse_email

# tests conducted on content.py:
# 1. test content score for email with phishing keywords

# English phishing keywords
ENGLISH_PHISHING_KEYWORDS = {
    # money related
    "due", "bill", "payment", "invoice", "transfer", "bank", "cash", "reward", "prize", 
    "winner", "lottery", "free", "offer", "claim", "credit", "upgrade", "subscription", "refund", 
    "compensation", "bonus", "gift", "deal", "discount", "limited time", "exclusive", "save", 
    "earn", "income", "investment", "opportunity", "money", "pay", "wire", "western union",
    "paypal", "venmo", "zelle", "cashapp", "cryptocurrency", "bitcoin", "ethereum", "crypto", 
    "wallet", "exchange", "mining", "token", "nft", 
    # urgency related
    "confirm", "urgent", "act now", "immediately", "asap", "important", "last chance",
    "final", "notice", "deadline", "expires", "soon", "critical", "emergency", "risk", "suspicious", "compromise",
    # actions needed
    "verify", "validate", "authenticate", "confirm identity", "click here", 
    "update", "re-enable", "reactivate", "needed", "act", "login", "sign in", "register" 
    # account related
    "locked", "unusual activity", "password", "expire", "suspended", "contact",
    "account", "action required", "alert", "warning", "compromise", "secure", "security",
    # high language keywords
    "dear", "sir", "madam", "customer", "user", "member", "valued", "client", "friend",
}

# Hebrew phishing keywords
HEBREW_PHISHING_KEYWORDS = {
}

SAFE_LANGUAGES = {"en", "he"}  # English and Hebrew


def detect_obfuscation(email_html):
    """
    Detect HTML obfuscation techniques used to bypass spam filters.
    Returns obfuscation_score between 0.0 (none) and 1.0 (highly obfuscated).
    """
    if not email_html:
        return 0.0

    try:
        soup = BeautifulSoup(email_html, 'html.parser')
    except Exception:
        return 0.0

    obfuscation_score = 0.0
    obfuscation_count = 0

    # Detect invisible text (white text, 0px fonts, etc.)
    for tag in soup.find_all(style=True):
        style = tag.get('style', '').lower()
        clean_style = style.replace(" ", "")

        # White text on white/transparent background
        if 'color' in style and ('white' in style or '#fff' in style or '#ffffff' in style):
            # Check if background is specifically white/transparent
            bg_match = re.search(r'background[^:]*:\s*([^;]+)', style)
            if bg_match:
                bg_value = bg_match.group(1).lower()
                if any(x in bg_value for x in ['white', '#fff', '#ffffff', 'transparent']):
                    obfuscation_count += 1
                    
        # Detect font sizes smaller than 1px
        font_size_pattern = r'font-size\s*:\s*([\d.]+)(px|em|rem)?'
        font_matches = re.finditer(font_size_pattern, style, re.IGNORECASE)
        for match in font_matches:
            value = float(match.group(1))
            unit = (match.group(2) or 'px').lower()

            # Check if font is smaller than 1px
            if unit == 'px' and value < 1 and value > 0:
                obfuscation_count += 1
            elif unit == 'em' and value < 0.067:  # 0.067em ≈ 1px (15px base)
                obfuscation_count += 1
            elif unit == 'rem' and value < 0.067:
                obfuscation_count += 1

    # Detect base64 encoded content (often used to hide malicious content)
    html_str = str(soup)
    base64_pattern = r'data:text/html;base64,'
    if re.search(base64_pattern, html_str):
        obfuscation_count += 2  # Higher weight for base64 encoding

    # Convert count to score (each technique adds 0.2, cap at 1.0)
    obfuscation_score = min(1.0, obfuscation_count * 0.2)

    return obfuscation_score


def detect_language(text):
    """
    Detect language of email text. 
    Returns language code (e.g., 'en', 'he')
    or None if detection fails or text is too short.
    """
    if not text or len(text.strip()) < 10:
        return None

    try:
        lang = detect(text)
        return lang
    except LangDetectException:
        return None


def count_phishing_keywords(text, keywords):
    """Count occurrences of phishing keywords in text"""
    text_lower = text.lower()
    count = 0
    for keyword in keywords:
        count += text_lower.count(keyword)
    return count


def analyze_content(email):
    """
    Analyze email for phishing indicators.

    Args:
        email: Full email string (headers + body)

    Returns:
        content_score: 0.0 (safe) to 1.0 (malicious)
    """
    parsed = parse_email(email)
    email_subject = parsed["subject"]
    email_body = parsed["body"]
    email_html = parsed["body"] if parsed["is_html"] else None

    combined_text = f"{email_subject} {email_body}".strip()

    if not combined_text and not email_html:
        return 0.0

    # Detect language from text
    detected_lang = detect_language(combined_text)

    # Score based on language
    language_penalty = 0.0
    if detected_lang and detected_lang not in SAFE_LANGUAGES:
        language_penalty = 0.15  # Minor boost for unexpected language

    # Count phishing keywords based on detected language
    phishing_count = 0
    if detected_lang == "en" or detected_lang is None:  # Default to English if detection fails
        phishing_count = count_phishing_keywords(combined_text, ENGLISH_PHISHING_KEYWORDS)
    elif detected_lang == "he":
        phishing_count = count_phishing_keywords(combined_text, HEBREW_PHISHING_KEYWORDS)
    else:
        # For other languages, no keyword detection
        phishing_count = 0

    # Normalize keyword count to 0-1 score (cap at 0.7 to leave room for other factors)
    keyword_score = min(0.7, phishing_count / 10)

    # Detect HTML obfuscation (if HTML is provided)
    obfuscation_score = 0.0
    if email_html:
        obfuscation_score = detect_obfuscation(email_html)

    # Combine scores: keywords + language penalty + obfuscation
    content_score = min(1.0, keyword_score + language_penalty + obfuscation_score)

    return content_score
