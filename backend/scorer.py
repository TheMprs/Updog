import re
import concurrent.futures

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
    ("header",     0.3, 20),  # 1 auth failure → at least Likely Safe
    ("header",     0.6, 35),  # 2 auth failures → at least Suspicious
    ("header",     0.9, 60),  # 3 auth failures → Suspicious
    ("sender",     0.4, 35),  # suspicious domain extension + unverifiable domain age combined → at least Suspicious
    ("sender",     0.7, 55),  # newly registered domain or free provider → at least 55
    ("sender",     0.9, 85),  # clear spoofing/typosquat → Likely Malicious
    ("content",    0.7, 55),  # high phishing content → at least 55
    ("content",    0.9, 70),  # very high phishing content → at least 70
]

SCORE_BANDS = [
    (0,  14,  "Safe",             "green"),
    (15, 30,  "Likely Safe",      "lime"),
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
    (lambda s: s.get("malicious_urls"),                   "❌", "Malicious URLs detected"),
    (lambda s: s.get("high_keyword_density"),             "⚠️", "High concentration of phishing keywords"),
    (lambda s: s.get("cloaking_detected"),             "❌", "HTML cloaking techniques detected"),
    (lambda s: s.get("mime_mismatch"),                    "❌", "Attachment file type is disguised"),
    (lambda s: s.get("encrypted_archive"),                "⚠️", "Password-protected archive attached"),
    (lambda s: s.get("risky_extension"),                  "⚠️", "Risky attachment type detected"),
    (lambda s: s.get("pdf_active_content"),               "❌", "PDF contains executable actions (JavaScript or Launch)"),
    (lambda s: s.get("caps_abuse"),                       "⚠️", "Excessive use of capitals detected"),
    (lambda s: s.get("large_money_amount"),               "❌", "Large monetary amounts mentioned"),
    (lambda s: s.get("undisclosed_recipients"),           "⚠️", "Email sent to undisclosed recipients"),
    (lambda s: s.get("domain_age_unknown"),               "⚠️", "Sender domain age could not be verified — treat with caution"),
    (lambda s: s.get("domain_recent_breach"),             "⚠️", lambda s: s.get("breach_info") or "Sender domain had a recent data breach"),
    (lambda s: s.get("suspicious_tld"),                   "⚠️", "Sender domain uses an extension commonly associated with phishing"),
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
        if key in active_weights and round(scores.get(key, 0), 10) >= threshold
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


_SAFE_HEADER_RESULT  = (0.0, {"spf": None, "dkim": None, "dmarc": None, "is_major_domain": False, "spam_score": 0.0})
_SAFE_ATTACH_RESULT  = (0.0, {"risky_extension": False, "encrypted_archive": False, "mime_mismatch": False, "pdf_active_content": False, "risky_files": [], "filenames": [], "total_attachments": 0})
_SAFE_URL_RESULT     = (0.0, {"malicious_urls": [], "total_urls": 0})
_SAFE_CONTENT_RESULT = (0.0, {"phishing_keywords": 0, "detected_language": None, "high_keyword_density": False, "cloaking_detected": False, "cloaking_triggers": None, "caps_abuse": False, "large_money_amount": False})
_SAFE_SENDER_RESULT  = (0.0, {"display_name_spoof": False, "reply_to_mismatch": False, "typosquat_detected": False, "typosquat_auth_mitigated": False, "typosquat_target": None, "from_domain": "", "undisclosed_recipients": False, "domain_age_unknown": False, "domain_recent_breach": False, "breach_info": None, "suspicious_tld": False})


def _safe(future, fallback):
    try:
        return future.result()
    except Exception:
        return fallback


def analyze(email: str) -> dict:
    # Batch 1: headers, attachments, urls are fully independent
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        hdr_fut  = ex.submit(analyze_headers, email)
        att_fut  = ex.submit(analyze_attachments, email)
        url_fut  = ex.submit(analyze_urls, email)
        header_score,     header_signals     = _safe(hdr_fut, _SAFE_HEADER_RESULT)
        attachment_score, attachment_signals = _safe(att_fut, _SAFE_ATTACH_RESULT)
        url_score,        url_signals        = _safe(url_fut, _SAFE_URL_RESULT)

    # Batch 2: content needs attachment filenames, sender needs header auth signals
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        con_fut = ex.submit(analyze_content, email, attachment_signals.get("filenames", []))
        snd_fut = ex.submit(analyze_sender, email, header_signals)
        content_score, content_signals = _safe(con_fut, _SAFE_CONTENT_RESULT)
        sender_score,  sender_signals  = _safe(snd_fut, _SAFE_SENDER_RESULT)

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

    # Cross-analyzer combined floors
    auth_failed  = any(signals.get(k) not in ("pass", None) for k in ("spf", "dkim", "dmarc"))
    auth_missing = all(signals.get(k) is None for k in ("spf", "dkim", "dmarc"))
    if signals.get("domain_age_unknown"):
        if auth_failed and score < 35:
            score = 35
            calculation["floor_applied"] = True
            calculation["floor_reason"] = "domain age unknown + auth failure → floor 35"
        elif auth_missing and score < 25:
            score = 25
            calculation["floor_applied"] = True
            calculation["floor_reason"] = "domain age unknown + no auth headers → floor 25"

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
