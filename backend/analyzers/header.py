import re
from typing import Dict, Optional
from .utils import MAJOR_DOMAINS, parse_headers

# tests conducted on header.py:
# 1. test gmail's authentication results header
# 2. test gmail's spam score header


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
    headers_dict = parse_headers(email)
    auth_header = headers_dict.get("Authentication-Results", "")
    from_address = headers_dict.get("From", "")
    auth_status = parse_authentication_results(auth_header)

    auth_score = check_auth_failures(headers_dict)

    return auth_score, {
        "spf": auth_status["spf"],
        "dkim": auth_status["dkim"],
        "dmarc": auth_status["dmarc"],
        "is_major_domain": is_major_domain(from_address),
    }
