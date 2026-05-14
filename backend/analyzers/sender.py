import re
import os
import sys
from datetime import datetime, timezone
from .utils import parse_email

import whois as whois_lib

# tests conducted on sender.py:
# 1. check domain age 
# 2. test typosquatting of major brands
# 3. check display name mismatch with brand keywords
# 4. check email provider matching email sender 
# 5. test reply-to mismatch 

MAJOR_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "bank", "irs.gov", "fedex.com", "ups.com", "upwind"
}

# Display name keywords associated with major brands
MAJOR_BRAND_KEYWORDS = {
    "google", "gmail", "microsoft", "outlook", "hotmail", "apple", "icloud",
    "amazon", "aws", "paypal", "fedex", "ups", "irs", "bank", "chase",
    "wells fargo", "citibank", "netflix", "facebook", "instagram", "twitter",
    "linkedin", "dropbox", "upwind", "leumi", "hapoalim", "isracard", "visa", "mastercard",
    "maccabi", "clal", "discount", "cal", "union", "psagot", "menora", "migdal", "yad2"
}

FREE_EMAIL_PROVIDERS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"}

def _levenshtein(a, b):
    """
    Calculate the Levenshtein distance between two strings.
    This is a measure of how many single-character edits (insertions, deletions, substitutions)
    are required to change one string into the other.
    """
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev_row = range(len(b) + 1)
    for c in a:
        curr_row = [prev_row[0] + 1]
        for j, d in enumerate(b):
            curr_row.append(min(prev_row[j + 1] + 1, curr_row[j] + 1, prev_row[j] + (c != d)))
        prev_row = curr_row
    return prev_row[-1]

def _extract_domain(email_addr):
    """
    Extract domain from email address, handling formats like "Name <email@domain.com>"
    """
    if not email_addr:
        return ""
    match = re.search(r'<([^>]+)>', email_addr)
    if match:
        email_addr = match.group(1)
    parts = email_addr.strip().split('@')
    return parts[-1].lower() if len(parts) == 2 else ""

def check_domain_age(domain):
    """
    Check if domain was registered recently (< 30-90 days).
    Returns age_score: 0.0 (old/safe) to 1.0 (newly registered/suspicious)
    """
    if not domain:
        return 0.0
    try:
        # suppress whois library noise (it prints socket errors before throwing)
        with open(os.devnull, 'w') as devnull:
            sys.stdout, sys.stderr = devnull, devnull
            try:
                info = whois_lib.whois(domain)
            finally:
                sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__
        creation_date = info.get("creation_date")
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return 0.0
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation_date).days
        if age_days < 30:
            return 1.0
        if age_days < 90:
            return 0.7
        return 0.0
    except Exception:
        return 0.0

def check_typosquatting(sender_domain):
    """
    Check if sender domain is a typosquat of major domains using edit distance.
    Examples: paypa1.com, arnazon.com, micros0ft.com
    Returns (typo_score, target): score 0.0-1.0 and the matched major domain or None
    """
    if not sender_domain:
        return 0.0, None

    # exact match or legitimate subdomain (mail.paypal.com) — always clean
    for major in MAJOR_DOMAINS:
        if sender_domain == major or sender_domain.endswith('.' + major):
            return 0.0, None

    sender_labels = sender_domain.lower().split('.')
    sender_base = sender_labels[0]

    for major in MAJOR_DOMAINS:
        major_base = major.split('.')[0].lower()
        if len(major_base) < 4:
            continue

        # typosquatting: edit distance on primary label (paypai.com, arnazon.com)
        dist = _levenshtein(sender_base, major_base)
        if dist == 1:
            return 0.9, major
        if dist == 2 and len(major_base) >= 6:
            return 0.7, major

        # subdomain spoofing: brand name used as a label (paypal.evil.com)
        if major_base in sender_labels:
            return 0.7, major

    return 0.0, None

def check_display_name_spoofing(from_header, sender_domain):
    """
    Check if display name claims to be from a major brand but domain doesn't match.
    Example: "Apple Support" <attacker@evil.com>
    Returns spoofing_score: 0.0 (legitimate) to 1.0 (clear spoofing)
    """
    if not from_header or not sender_domain:
        return 0.0

    display_name_match = re.match(r'^"?([^"<]+)"?\s*<', from_header)
    if not display_name_match:
        return 0.0

    display_name = display_name_match.group(1).strip().lower()
    sender_domain_lower = sender_domain.lower()

    for keyword in MAJOR_BRAND_KEYWORDS:
        if keyword in display_name:
            # Brand keyword in display name but not in the actual sending domain
            keyword_base = keyword.split()[0]
            if keyword_base not in sender_domain_lower:
                return 0.9

    return 0.0

def check_free_email_provider(sender_domain, from_header=""):
    """
    Flag free provider only when the display name claims to be a known brand.
    A small business legitimately using Gmail should not be penalized.
    """
    if not sender_domain or sender_domain.lower() not in FREE_EMAIL_PROVIDERS:
        return 0.0

    display_name_match = re.match(r'^"?([^"<]+)"?\s*<', from_header)
    if not display_name_match:
        return 0.0

    display_name = display_name_match.group(1).strip().lower()
    for keyword in MAJOR_BRAND_KEYWORDS:
        if keyword in display_name:
            return 0.3

    return 0.0

def check_reply_to_mismatch(from_domain, reply_to_domain):
    """
    Check if Reply-To header differs significantly from From domain.
    Example: From: bank@legit.com but Reply-To: harvest@evil.com
    Returns mismatch_score: 0.0 (matches) to 1.0 (severe mismatch)
    """
    if not from_domain or not reply_to_domain:
        return 0.0

    from_domain = from_domain.lower()
    reply_to_domain = reply_to_domain.lower()

    if from_domain == reply_to_domain:
        return 0.0

    # Allow subdomain differences (support.example.com vs example.com)
    from_base = '.'.join(from_domain.split('.')[-2:])
    reply_base = '.'.join(reply_to_domain.split('.')[-2:])

    if from_base == reply_base:
        return 0.0

    return 0.5

def check_undisclosed_recipients(to_header):
    """Detect bulk spam pattern where To is hidden."""
    if not to_header:
        return 0.0
    return 0.4 if "undisclosed-recipients" in to_header.lower() else 0.0


def analyze_sender(email):
    """
    Analyze sender/domain for phishing indicators.

    Args:
        email: Full email string (headers + body)

    Returns:
        sender_score: 0.0 (safe) to 1.0 (malicious)
    """
    parse_email(email)  # validate email format

    email = email.replace('\r\n', '\n').replace('\r', '\n')
    parts = email.split('\n\n', 1)
    headers_str = parts[0] if parts else ""
    headers_dict = {}
    current_key = None
    for line in headers_str.split('\n'):
        if line and line[0] in (' ', '\t') and current_key:
            headers_dict[current_key] += ' ' + line.strip()
        elif ':' in line:
            key, value = line.split(':', 1)
            current_key = key.strip()
            headers_dict[current_key] = value.strip()

    from_header = headers_dict.get("From", "")
    reply_to_header = headers_dict.get("Reply-To", "")
    to_header = headers_dict.get("To", "")

    sender_domain = _extract_domain(from_header)
    reply_to_domain = _extract_domain(reply_to_header)

    age_score = check_domain_age(sender_domain)
    typo_score, typo_target = check_typosquatting(sender_domain)
    spoofing_score = check_display_name_spoofing(from_header, sender_domain)
    free_email_score = check_free_email_provider(sender_domain, from_header)
    mismatch_score = check_reply_to_mismatch(sender_domain, reply_to_domain)
    undisclosed_score = check_undisclosed_recipients(to_header)

    high_signal = max(spoofing_score, typo_score, mismatch_score)

    if high_signal > 0:
        sender_score = min(1.0, high_signal + age_score * 0.15 + free_email_score * 0.1 + undisclosed_score * 0.2)
    else:
        sender_score = min(1.0, age_score * 0.7 + free_email_score * 0.3 + undisclosed_score * 0.3)

    return sender_score, {
        "display_name_spoof":    spoofing_score > 0,
        "reply_to_mismatch":     mismatch_score > 0,
        "free_provider_spoof":   free_email_score > 0,
        "typosquat_detected":    typo_score > 0,
        "typosquat_target":      typo_target,
        "from_domain":           sender_domain,
        "undisclosed_recipients": undisclosed_score > 0,
    }
