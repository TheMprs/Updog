from langdetect import detect, LangDetectException
from bs4 import BeautifulSoup
import re
import json
import os
from .utils import parse_email

# tests conducted on content.py:
# 1. parse email for phishing keywords
# 2. check if email is in unexpected language (lang is not heb/eng)
# 3. detect HTML obfuscation techniques (invisible text, tiny fonts, base64 encoding)

def _load_keywords():
    path = os.path.join(os.path.dirname(__file__), "phishing_keywords.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("english", {}), data.get("hebrew", {})

ENGLISH_PHISHING_KEYWORDS, HEBREW_PHISHING_KEYWORDS = _load_keywords()


def count_phishing_categories(text, keyword_dict):
    """Count how many categories have at least one keyword match."""
    text_lower = text.lower()
    return sum(1 for keywords in keyword_dict.values() if any(kw in text_lower for kw in keywords))

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

            # Check if font is smaller than 1px (including 0)
            if unit == 'px' and value < 1:
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

    # Convert count to score (each technique adds 0.25, cap at 1.0)
    obfuscation_score = min(1.0, obfuscation_count * 0.25)

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

def detect_caps_abuse(text):
    """Detect excessive all-caps usage — a classic spam signal."""
    if not text or len(text.strip()) < 20:
        return 0.0
    words = re.findall(r'\b[A-Za-z]{3,}\b', text)
    if len(words) < 5:
        return 0.0
    ratio = sum(1 for w in words if w.isupper()) / len(words)
    if ratio >= 0.4:
        return 0.5
    if ratio >= 0.25:
        return 0.25
    return 0.0


def detect_large_money_amounts(text):
    """Detect suspicious large monetary amounts (advance-fee fraud indicator)."""
    pattern = r'\$[\d,]+\s*(million|billion)|\b\d+\s*(million|billion)\s*(dollar|usd)'
    return 0.4 if re.search(pattern, text, re.IGNORECASE) else 0.0


def analyze_content(email, attachment_filenames=None):
    """
    Analyze email for phishing indicators.

    Args:
        email: Full email string (headers + body)
        attachment_filenames: Optional list of attachment filenames to scan for keywords

    Returns:
        content_score: 0.0 (safe) to 1.0 (malicious)
    """
    parsed = parse_email(email)
    email_subject = parsed["subject"]
    email_body = parsed["body"]
    email_html = parsed["body"] if parsed["is_html"] else None

    filenames_text = " ".join(attachment_filenames) if attachment_filenames else ""
    combined_text = f"{email_subject} {email_body} {filenames_text}".strip()

    if not combined_text and not email_html:
        return 0.0, {"phishing_keywords": 0, "detected_language": None, "obfuscation_detected": False}

    # Detect language from text only (not from raw HTML markup)
    text_for_language_detection = combined_text
    if email_html:
        try:
            soup = BeautifulSoup(email_html, 'html.parser')
            text_for_language_detection = f"{email_subject} {soup.get_text()}".strip()
        except Exception:
            pass  # Fall back to combined_text if parsing fails

    # Detect language from text
    detected_lang = detect_language(text_for_language_detection)

    # Score based on language
    language_penalty = 0.0
    if detected_lang and detected_lang not in SAFE_LANGUAGES:
        language_penalty = 0.15  # Minor boost for unexpected language

    # Count phishing keyword categories with at least one hit
    phishing_count = 0
    if detected_lang == "en" or detected_lang is None:
        phishing_count = count_phishing_categories(combined_text, ENGLISH_PHISHING_KEYWORDS)
    elif detected_lang == "he":
        phishing_count = count_phishing_categories(combined_text, HEBREW_PHISHING_KEYWORDS)

    # Normalize by total categories (score only rises when multiple category types are hit)
    total_categories = max(len(ENGLISH_PHISHING_KEYWORDS), 1)
    keyword_score = min(0.7, phishing_count / total_categories)

    # Detect HTML obfuscation (if HTML is provided)
    obfuscation_score = 0.0
    if email_html:
        obfuscation_score = detect_obfuscation(email_html)

    caps_score  = detect_caps_abuse(combined_text)
    money_score = detect_large_money_amounts(combined_text)
    effective_obfuscation = obfuscation_score if obfuscation_score >= 0.5 else 0.0
    content_score = min(1.0, keyword_score + language_penalty + effective_obfuscation + caps_score + money_score)

    return content_score, {
        "phishing_keywords":   phishing_count,
        "detected_language":   detected_lang,
        "obfuscation_detected": obfuscation_score >= 0.5,
        "caps_abuse":          caps_score > 0,
        "large_money_amount":  money_score > 0,
    }
