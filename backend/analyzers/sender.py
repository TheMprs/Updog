from .utils import parse_email

MAJOR_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "bank", "irs.gov", "fedex.com", "ups.com", "upwind"
}

FREE_EMAIL_PROVIDERS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"}


def check_domain_age(domain):
    """
    Check if domain was registered recently (< 30-90 days).
    Returns age_score: 0.0 (old/safe) to 1.0 (newly registered/suspicious)
    """
    pass


def check_typosquatting(sender_domain):
    """
    Check if sender domain is a typosquat of major domains using edit distance.
    Examples: paypa1.com, arnazon.com, micros0ft.com
    Returns typo_score: 0.0 (not a typo) to 1.0 (likely typosquat)
    """
    pass


def check_display_name_spoofing(from_header, sender_domain):
    """
    Check if display name claims to be from a major brand but domain doesn't match.
    Example: "Apple Support" <attacker@evil.com>
    Returns spoofing_score: 0.0 (legitimate) to 1.0 (clear spoofing)
    """
    pass


def check_free_email_provider(sender_domain):
    """
    Check if sender is using free email provider (@gmail, @yahoo, etc).
    Returns free_email_score: 0.0 (business domain) to 1.0 (free provider)
    """
    pass


def check_reply_to_mismatch(from_domain, reply_to_domain):
    """
    Check if Reply-To header differs significantly from From domain.
    Example: From: bank@legit.com but Reply-To: harvest@evil.com
    Returns mismatch_score: 0.0 (matches) to 1.0 (severe mismatch)
    """
    pass


def analyze_sender(email):
    """
    Analyze sender/domain for phishing indicators.

    Args:
        email: Full email string (headers + body)

    Returns:
        sender_score: 0.0 (safe) to 1.0 (malicious)
    """
    parsed = parse_email(email)

    # Extract sender info from headers
    # from_header, reply_to_header, sender_domain, reply_to_domain

    # Run all checks
    age_score = check_domain_age("")
    typo_score = check_typosquatting("")
    spoofing_score = check_display_name_spoofing("", "")
    free_email_score = check_free_email_provider("")
    mismatch_score = check_reply_to_mismatch("", "")

    # Combine scores
    sender_score = 0.0

    return sender_score
