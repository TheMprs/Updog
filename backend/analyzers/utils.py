import re

def is_html(content):
    """
    Detect if content is HTML or plain text.
    Returns True if HTML, False if plain text.
    """
    if not content:
        return False

    # Check for common HTML tags and patterns
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
    Parse full email (headers + body) into structured data.

    Args:
        email: Full email string with headers and body separated by blank line

    Returns:
        dict with keys: "subject", "body", "is_html"
    """
    if not email:
        return {"subject": "", "body": "", "is_html": False}

    # Split headers from body (separated by blank line)
    parts = email.split('\n\n', 1)
    headers_str = parts[0] if len(parts) > 0 else ""
    body = parts[1] if len(parts) > 1 else ""

    # Extract subject from headers
    subject = ""
    for line in headers_str.split('\n'):
        if line.lower().startswith('subject:'):
            subject = line.split(':', 1)[1].strip()
            break

    # Detect if body is HTML
    html_detected = is_html(body)

    return {
        "subject": subject,
        "body": body,
        "is_html": html_detected
    }
