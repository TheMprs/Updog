import re
from typing import Dict, Optional

# tests conducted on header.py:
# 1. test gmail's authentication results header
# 2. test gmail's spam score header

# Major companies whose domains are commonly spoofed
MAJOR_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "bank", "irs.gov", "fedex.com", "ups.com", "upwind"
}

def check_spam_score(headers):
    """
    Score based on Gmail's X-Spam-Score header.
    Higher score = more suspicious.
    Returns 0.0-1.0
    """
    try:
        spam_score = float(headers.get("X-Spam-Score", "0"))
        # gmail uses a scale of 10, we normalize it to 0-1 
        return min(1.0, max(0.0, spam_score / 10))  
    except (ValueError, TypeError):
        return 0.0

def parse_authentication_results(auth_header):
    """
    Parse the Authentication-Results header to extract SPF, DKIM, and DMARC results.
    Returns a dict like {"spf": "pass", "dkim": "fail", "dmarc": "fail"}
    """

    # spf: check that email comes from declared sending server 
    # dkim: check that email is signed by sender's domain (prevents modification in transit)
    # dmarc: check that spf/dkim align with sender's domain and policy (each company has a different policy)

    if not auth_header:
        return {"spf": None, "dkim": None, "dmarc": None}

    results: Dict[str, Optional[str]] = {"spf": None, "dkim": None, "dmarc": None}

    # extract spf, dkim, dmarc status from header
    spf_match = re.search(r'spf=(\w+)', auth_header, re.IGNORECASE)
    dkim_match = re.search(r'(?<!\w)dkim=(\w+)', auth_header, re.IGNORECASE)
    dmarc_match = re.search(r'dmarc=(\w+)', auth_header, re.IGNORECASE)

    if spf_match:
        results["spf"] = spf_match.group(1).lower()
    if dkim_match:
        results["dkim"] = dkim_match.group(1).lower()
    if dmarc_match:
        results["dmarc"] = dmarc_match.group(1).lower()

    return results

def is_major_domain(from_address):
    """
    Check if the email is claiming to be from a major domain.
    """
    if not from_address:
        return False

    domain = from_address.split('@')[-1].lower()
    return any(major in domain for major in MAJOR_DOMAINS)

def check_auth_failures(headers):
    """
    Score based on SPF/DKIM/DMARC failures.
    Higher score = more suspicious.
    Returns 0.0-1.0
    """
    auth_header = headers.get("Authentication-Results", "")
    from_address = headers.get("From", "")

    if not auth_header:
        return 0.0

    auth_status = parse_authentication_results(auth_header)

    # count explicit failures only — missing (None) means header not present, not a failure
    failures = sum(1 for check in ["spf", "dkim", "dmarc"]
                   if auth_status[check] is not None and auth_status[check] != "pass")
    
    # base score: 0.3 per failure
    score = failures * 0.3

    # address is from major domain but has auth failures - likely spoof
    if is_major_domain(from_address) and failures > 0:
        return min(0.9, score * 2)

    return score

def analyze_headers(email):
    """
    Analyze email headers for malicious patterns.

    Args:
        email: Full email string (headers + body)

    Returns:
        (header_score, signals): score 0.0 (safe) to 1.0 (malicious), and raw signal dict
    """
    email = email.replace('\r\n', '\n').replace('\r', '\n')
    parts = email.split('\n\n', 1)
    headers_str = parts[0] if len(parts) > 0 else ""

    headers_dict = {}
    current_key = None
    for line in headers_str.split('\n'):
        if line and line[0] in (' ', '\t') and current_key:
            headers_dict[current_key] += ' ' + line.strip()
        elif ':' in line:
            key, value = line.split(':', 1)
            current_key = key.strip()
            headers_dict[current_key] = value.strip()

    auth_header = headers_dict.get("Authentication-Results", "")
    from_address = headers_dict.get("From", "")
    auth_status = parse_authentication_results(auth_header)

    auth_score = check_auth_failures(headers_dict)
    spam_score = check_spam_score(headers_dict)
    combined_score = auth_score

    return combined_score, {
        "spf": auth_status["spf"],
        "dkim": auth_status["dkim"],
        "dmarc": auth_status["dmarc"],
        "is_major_domain": is_major_domain(from_address),
        "spam_score": spam_score,
    }
