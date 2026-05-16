from langdetect import detect, LangDetectException
from bs4 import BeautifulSoup
import re
import json
import os
from .utils import parse_email, is_html

# tests conducted on content.py:
# 1. parse email for phishing keywords
# 2. check if email is in unexpected language (lang is not heb/eng)
# 3. detect HTML cloaking techniques (invisible text, tiny fonts, base64 encoding)

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

def count_phishing_matches(text, keyword_dict):
    """Count total individual keyword matches across all categories."""
    text_lower = text.lower()
    return sum(1 for keywords in keyword_dict.values() for kw in keywords if kw in text_lower)

SAFE_LANGUAGES = {"en", "he"}  # English and Hebrew

def detect_cloaking(email_html):
    """
    Detect HTML cloaking techniques used to bypass spam filters.
    Returns (score, triggers) where score is 0.0–1.0 and triggers is a list of fired check names.
    """
    if not email_html:
        return 0.0, []

    try:
        soup = BeautifulSoup(email_html, 'html.parser')
    except Exception:
        return 0.0, []

    cloaking_count = 0
    triggers = []

    # Detect invisible text (white text, 0px fonts, etc.)
    for tag in soup.find_all(style=True):
        style = tag.get('style', '').lower()

        # White text on white/transparent background
        text_color_match = re.search(r'(?<![a-z-])color\s*:\s*([^;]+)', style)
        if text_color_match:
            text_color = text_color_match.group(1).strip()
            if any(x in text_color for x in ['white', '#fff', '#ffffff', 'transparent']):
                bg_match = re.search(r'background[^:]*:\s*([^;]+)', style)
                if bg_match:
                    bg_value = bg_match.group(1).lower()
                    if any(x in bg_value for x in ['white', '#fff', '#ffffff', 'transparent']):
                        cloaking_count += 1
                        triggers.append("white_on_white_text")

        # Detect font sizes smaller than 1px — only flag if the tag has direct text
        # (excludes layout containers whose 0px applies to spacing, not hidden text)
        direct_text = "".join(s for s in tag.find_all(string=True, recursive=False) if s.strip() and s.strip() != "\xa0")
        if direct_text:
            font_size_pattern = r'font-size\s*:\s*([\d.]+)(px|em|rem)?'
            for match in re.finditer(font_size_pattern, style, re.IGNORECASE):
                value = float(match.group(1))
                unit = (match.group(2) or 'px').lower()
                if unit == 'px' and value < 1:
                    cloaking_count += 1
                    triggers.append(f"tiny_font_{value}px")
                elif unit in ('em', 'rem') and value < 0.067:
                    cloaking_count += 1
                    triggers.append(f"tiny_font_{value}{unit}")

    html_str = str(soup)

    # Detect base64-encoded HTML data URI (hides content from text scanners)
    if re.search(r'data:text/html;base64,', html_str):
        cloaking_count += 2
        triggers.append("base64_html_data_uri")

    # Detect executable script tags — anything that isn't JSON-LD structured data
    for script in soup.find_all("script"):
        script_type = (script.get("type") or "").strip().lower()
        if script_type != "application/ld+json":
            cloaking_count += 2
            triggers.append(f"executable_script_type:{script_type or 'none'}")
            break

    # Detect javascript: hrefs — always malicious intent in email
    for tag in soup.find_all(href=True):
        if tag["href"].strip().lower().startswith("javascript:"):
            cloaking_count += 2
            triggers.append("javascript_href")
            break

    # tiny_font alone is a common legitimate pattern (email preheader text) — only flag it
    # when combined with at least one other obfuscation technique
    other_triggers = [t for t in triggers if not t.startswith("tiny_font_")]
    if not other_triggers:
        return 0.0, []

    cloaking_score = min(1.0, cloaking_count * 0.25)
    return cloaking_score, triggers

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
    email_html = parsed["body"] if (parsed["is_html"] or is_html(parsed["body"])) else None

    filenames_text = " ".join(attachment_filenames) if attachment_filenames else ""
    plain_body = BeautifulSoup(email_body, "html.parser").get_text() if email_html else email_body
    combined_text = f"{email_subject} {plain_body} {filenames_text}".strip()

    if not combined_text and not email_html:
        return 0.0, {"phishing_keywords": 0, "detected_language": None, "cloaking_detected": False}

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

    # Count phishing keyword categories and total matches
    phishing_count = 0
    phishing_matches = 0
    if detected_lang == "en" or detected_lang is None:
        phishing_count = count_phishing_categories(combined_text, ENGLISH_PHISHING_KEYWORDS)
        phishing_matches = count_phishing_matches(combined_text, ENGLISH_PHISHING_KEYWORDS)
    elif detected_lang == "he":
        phishing_count = count_phishing_categories(combined_text, HEBREW_PHISHING_KEYWORDS)
        phishing_matches = count_phishing_matches(combined_text, HEBREW_PHISHING_KEYWORDS)

    # Density: ratio of keyword matches to total words — long legitimate emails dilute the score
    total_words = max(len(re.findall(r'\b\w+\b', combined_text)), 1)
    density = phishing_matches / total_words
    # Scale: 5% density = 0.5 multiplier, 10%+ density = 1.0 multiplier
    density_multiplier = min(1.0, density / 0.10)

    active_keywords = HEBREW_PHISHING_KEYWORDS if detected_lang == "he" else ENGLISH_PHISHING_KEYWORDS
    total_categories = max(len(active_keywords), 1)
    category_ratio = phishing_count / total_categories
    keyword_score = min(0.7, category_ratio * density_multiplier)

    # Detect HTML cloaking (if HTML is provided)
    cloaking_score = 0.0
    cloaking_triggers = []
    if email_html:
        cloaking_score, cloaking_triggers = detect_cloaking(email_html)

    caps_score  = detect_caps_abuse(combined_text) if detected_lang == "en" else 0.0
    money_score = detect_large_money_amounts(combined_text)
    effective_cloaking = cloaking_score if cloaking_score >= 0.5 else 0.0
    content_score = min(1.0, keyword_score + language_penalty + effective_cloaking + caps_score + money_score)

    return content_score, {
        "phishing_keywords":    phishing_count,
        "detected_language":    detected_lang,
        "high_keyword_density": keyword_score >= 0.3,
        "cloaking_detected": cloaking_score >= 0.5,
        "cloaking_triggers": ", ".join(cloaking_triggers) if cloaking_triggers else None,
        "caps_abuse":           caps_score > 0,
        "large_money_amount":   money_score > 0,
    }
