import re
import email as email_lib
from email import policy


def is_html(content):
    """
    Detect if content is HTML or plain text.
    Returns True if HTML, False if plain text.
    """
    if not content:
        return False

    html_patterns = [
        r'<html', r'<body', r'<div', r'<p>', r'<a\s', r'<img',
        r'<table', r'<tr', r'<form', r'<script', r'<style',
        r'<!DOCTYPE', r'<meta', r'<head'
    ]

    content_lower = content.lower()
    for pattern in html_patterns:
        if re.search(pattern, content_lower):
            return True

    return False


def parse_email(email):
    """
    Parse full email string into structured data.
    Uses Python's email library to handle QP/base64/multipart decoding automatically.

    Returns:
        dict with keys: "subject", "body", "is_html"
    """
    if not email:
        return {"subject": "", "body": "", "is_html": False}

    msg = email_lib.message_from_string(email, policy=policy.compat32)

    subject = msg.get("Subject", "")

    # walk parts to find the best body candidate (prefer html, fall back to plain)
    plain_body = ""
    html_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/html" and not html_body:
                html_body = _decode_part(part)
            elif ctype == "text/plain" and not plain_body:
                plain_body = _decode_part(part)
    else:
        ctype = msg.get_content_type()
        body = _decode_part(msg)
        if ctype == "text/html":
            html_body = body
        else:
            plain_body = body

    body = html_body if html_body else plain_body

    return {
        "subject": subject,
        "body": body,
        "is_html": bool(html_body),
    }


def _decode_part(part):
    """Decode a message part to a string, handling charset and transfer encoding."""
    try:
        payload = part.get_payload(decode=True)  # decodes QP/base64 automatically
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    except Exception:
        return ""
