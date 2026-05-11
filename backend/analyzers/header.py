import re

# tests conducted on header.py:
# 1. test gmail's authentication results header
# 2. test gmail's spam score header

# Major companies whose domains are commonly spoofed
MAJOR_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "bank", "irs.gov", "fedex.com", "ups.com"
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

    results = {"spf": None, "dkim": None, "dmarc": None}

    # extract spf, dkim, dmarc status from header
    spf_match = re.search(r'spf=(\w+)', auth_header)
    dkim_match = re.search(r'dkim=(\w+)', auth_header)
    dmarc_match = re.search(r'dmarc=(\w+)', auth_header)

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

    auth_status = parse_authentication_results(auth_header)

    # count failures (0-3)
    failures = sum(1 for check in ["spf", "dkim", "dmarc"] 
                   if auth_status[check] and auth_status[check] != "pass")
    
    # base score: 0.3 per failure
    score = failures * 0.3

    # address is from major domain but has auth failures - likely spoof
    if is_major_domain(from_address) and failures > 0:
        return min(0.9, score * 2)

    return score

def analyze_headers(email_headers):
    """
    Analyze email headers for malicious patterns using authentication results and spam score.
    Returns a combined score between 0.0 (safe) and 1.0 (malicious).
    """
    auth_score = check_auth_failures(email_headers)
    spam_score = check_spam_score(email_headers)
    # combine scores, giving more weight to authentication failures
    combined_score = min(1.0, auth_score * 0.7 + spam_score * 0.3)
    
    return combined_score
