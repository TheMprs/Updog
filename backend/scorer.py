import re

from analyzers.header import analyze_headers
from analyzers.content import analyze_content
from analyzers.url import analyze_urls
from analyzers.attachment import analyze_attachments
from analyzers.sender import analyze_sender

_FWD_FROM_RE = re.compile(
    r'(?:---------- Forwarded message ---------|-----Original Message-----)[ \t]*\r?\n'
    r'From:[ \t]*(.+)',
    re.IGNORECASE
)

def _extract_inner_from(email_str: str) -> str:
    m = _FWD_FROM_RE.search(email_str)
    return m.group(1).strip() if m else ""

WEIGHTS = {
    "url":        0.30, # url analysis comes from google, strongest signal
    "sender":     0.25, # brand impersonation and domain age are classic phishing signals
    "header":     0.20, # auth failures are strong indicators of sus but companies can make mistakes
    "content":    0.15, # least reliable as phishers can use generic language, but still important for context
    "attachment": 0.10, # attachments are common in phishing but many legitimate emails have them too, so lowest weight
}

# Prevent signal dilution by safe scores elsewhere.
# List of (analyzer_key, threshold, min_score) — multiple rules per key are allowed.
SIGNAL_FLOORS = [
    ("url",        0.8, 95),  # known malicious URL → near-certain malicious
    ("attachment", 0.6, 80),  # risky file type (.exe, .ps1 etc.) → likely malicious
    ("header",     0.6, 35),  # 2 auth failures → at least Suspicious
    ("header",     0.9, 60),  # 3 auth failures → Suspicious
    ("sender",     0.7, 55),  # newly registered domain or free provider → at least 55
    ("sender",     0.9, 85),  # clear spoofing/typosquat → Likely Malicious
    ("content",    0.7, 55),  # high phishing content → at least 55
    ("content",    0.9, 70),  # very high phishing content → at least 70
]

SCORE_BANDS = [
    (0,  30,  "Safe",             "green"),
    (31, 60,  "Suspicious",       "yellow"),
    (61, 80,  "Likely Malicious", "orange"),
    (81, 100, "Malicious",        "red"),
]

BULLET_RULES = [
    (lambda s: s.get("spf") not in ("pass", None),       "❌", "SPF authentication failed"),
    (lambda s: s.get("dkim") not in ("pass", None),      "❌", "DKIM signature invalid"),
    (lambda s: s.get("dmarc") not in ("pass", None),     "❌", "DMARC policy failed"),
    (lambda s: s.get("display_name_spoof"),               "❌", "Display name impersonates a known brand"),
    (lambda s: s.get("reply_to_mismatch"),                "⚠️", "Reply-To address differs from sender domain"),
    (lambda s: s.get("typosquat_detected") and not s.get("typosquat_auth_mitigated"), "❌", "Sender domain closely resembles a known brand"),
    (lambda s: s.get("typosquat_auth_mitigated"),          "⚠️", "Sender domain uses brand as subdomain — auth passed, likely a sending service"),
    (lambda s: s.get("free_provider_spoof"),              "⚠️", "Business email sent from free provider"),
    (lambda s: s.get("malicious_urls"),                   "❌", "Malicious URLs detected"),
    (lambda s: s.get("high_keyword_density"),             "⚠️", "High concentration of phishing keywords"),
    (lambda s: s.get("obfuscation_detected"),             "❌", "HTML obfuscation techniques detected"),
    (lambda s: s.get("mime_mismatch"),                    "❌", "Attachment file type is disguised"),
    (lambda s: s.get("encrypted_archive"),                "⚠️", "Password-protected archive attached"),
    (lambda s: s.get("risky_extension"),                  "⚠️", "Risky attachment type detected"),
    (lambda s: s.get("caps_abuse"),                       "⚠️", "Excessive use of capitals detected"),
    (lambda s: s.get("large_money_amount"),               "❌", "Large monetary amounts mentioned"),
    (lambda s: s.get("undisclosed_recipients"),           "⚠️", "Email sent to undisclosed recipients"),
    (lambda s: s.get("domain_age_unknown"),               "⚠️", "Sender domain age could not be verified — treat with caution"),
    (lambda s: s.get("domain_recent_breach"),             "⚠️", lambda s: s.get("breach_info") or "Sender domain had a recent data breach"),
    (lambda s: s.get("forwarded_inner_sender"),           "⚠️", "Suspicious sender detected inside a forwarded email"),
]


def compute_score(scores: dict, has_urls: bool, has_attachments: bool) -> tuple:
    active_weights = {
        k: v for k, v in WEIGHTS.items()
        if not (k == "url" and not has_urls)
        and not (k == "attachment" and not has_attachments)
    }
    total_weight = sum(active_weights.values())
    weighted = sum(scores[k] * w for k, w in active_weights.items()) / total_weight
    weighted_score = round(weighted * 100)

    triggered_floors = [
        (key, threshold, min_score)
        for key, threshold, min_score in SIGNAL_FLOORS
        if key in active_weights and scores.get(key, 0) >= threshold
    ]
    floor = max((min_score for _, _, min_score in triggered_floors), default=0)
    final_score = round(min(100, max(weighted * 100, floor)))

    contributions = {
        k: round(scores[k] * (w / total_weight) * 100)
        for k, w in active_weights.items()
    }
    floor_applied = floor > weighted_score
    floor_reason = (
        f"{triggered_floors[-1][0]} score {round(scores[triggered_floors[-1][0]] * 100)}% "
        f">= {round(triggered_floors[-1][1] * 100)}% threshold → floor {floor}"
        if floor_applied and triggered_floors else None
    )

    calculation = {
        "contributions": contributions,
        "weighted_score": weighted_score,
        "floor_applied": floor_applied,
        "floor_reason": floor_reason,
        "final_score": final_score,
    }
    return final_score, calculation


def get_band(score: int) -> tuple:
    for low, high, verdict, color in SCORE_BANDS:
        if low <= score <= high:
            return verdict, color
    return "Safe", "green"


def generate_bullets(signals: dict) -> list:
    return [
        f"{icon} {text(signals) if callable(text) else text}"
        for condition, icon, text in BULLET_RULES
        if condition(signals)
    ]


def analyze(email: str) -> dict:
    header_score,     header_signals     = analyze_headers(email)
    attachment_score, attachment_signals = analyze_attachments(email)
    content_score,    content_signals    = analyze_content(email, attachment_signals.get("filenames", []))
    url_score,        url_signals        = analyze_urls(email)
    sender_score,     sender_signals     = analyze_sender(email, auth=header_signals)

    # For forwarded emails, also check the inner sender domain
    inner_from = _extract_inner_from(email)
    if inner_from:
        try:
            inner_score, inner_signals = analyze_sender(f"From: {inner_from}\n\n", auth=None)
            if inner_score > sender_score:
                sender_score = inner_score
                sender_signals = {**inner_signals, "forwarded_inner_sender": True}
        except Exception:
            pass

    has_urls        = url_signals.get("total_urls", 0) > 0
    has_attachments = attachment_signals.get("total_attachments", 0) > 0

    scores = {
        "header":     header_score,
        "sender":     sender_score,
        "url":        url_score,
        "content":    content_score,
        "attachment": attachment_score,
    }

    signals = {
        **header_signals,
        **sender_signals,
        **url_signals,
        **content_signals,
        **attachment_signals,
    }

    score, calculation = compute_score(scores, has_urls, has_attachments)
    verdict, color     = get_band(score)
    bullets            = generate_bullets(signals)

    return {
        "score":       score,
        "verdict":     verdict,
        "color":       color,
        "bullets":     bullets,
        "breakdown":   scores,
        "calculation": calculation,
        "signals": {
            "header":     header_signals,
            "sender":     sender_signals,
            "url":        url_signals,
            "content":    content_signals,
            "attachment": attachment_signals,
        },
    }
