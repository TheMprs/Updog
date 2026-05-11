import pytest
import sys
from pathlib import Path

# Add backend to path so we can import analyzers as a package
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from analyzers.content import (
    detect_obfuscation,
    detect_language,
    count_phishing_keywords,
    analyze_content,
    ENGLISH_PHISHING_KEYWORDS,
)


class TestDetectObfuscation:
    def test_safe_html(self):
        # Normal email with standard inline CSS should return 0.0
        html = '<div style="color: black; font-size: 14px;">Hello, this is a normal email.</div>'
        score = detect_obfuscation(html)
        assert score == 0.0

    def test_zero_font_size_px(self):
        # font-size: 0px should be detected as obfuscation
        html = '<span style="font-size: 0px;">hidden text</span>'
        score = detect_obfuscation(html)
        assert score > 0.0

    def test_zero_font_size_no_unit(self):
        # font-size: 0 (unitless) should be detected as obfuscation
        html = '<span style="font-size: 0;">hidden text</span>'
        score = detect_obfuscation(html)
        assert score > 0.0

    def test_sub_pixel_font_size(self):
        # font-size: 0.5px (less than 1px) should be detected as obfuscation
        html = '<span style="font-size: 0.5px;">hidden text</span>'
        score = detect_obfuscation(html)
        assert score > 0.0

    def test_invisible_text_white_on_white(self):
        # White text on white background should be detected as obfuscation
        html = '<span style="color: white; background: #ffffff;">invisible</span>'
        score = detect_obfuscation(html)
        assert score > 0.0

    def test_invisible_text_hex_color(self):
        # #fff text on white background should be detected as obfuscation
        html = '<div style="color: #fff; background: white;">hidden</div>'
        score = detect_obfuscation(html)
        assert score > 0.0

    def test_base64_payload(self):
        # data:text/html;base64 pattern should be detected as obfuscation (weight 2)
        html = '<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe>'
        score = detect_obfuscation(html)
        assert score >= 0.4  # base64 counts as 2 obfuscation_count -> 0.4

    def test_multiple_obfuscation_techniques_capped(self):
        # Multiple techniques should cap at 1.0
        html = '''
        <span style="font-size: 0px; color: white; background: #ffffff;">hidden</span>
        <iframe src="data:text/html;base64,abc123"></iframe>
        '''
        score = detect_obfuscation(html)
        assert score == 1.0

    def test_empty_html(self):
        # Empty input should return 0.0
        score = detect_obfuscation("")
        assert score == 0.0

    def test_none_input(self):
        # None input should return 0.0
        score = detect_obfuscation(None)
        assert score == 0.0


class TestDetectLanguage:
    def test_english_text(self):
        # Clear English text should be detected as English
        lang = detect_language("Hello, please verify your account and click the link below.")
        assert lang == "en"

    def test_short_text_returns_none(self):
        # Text shorter than 10 characters should return None
        lang = detect_language("hi")
        assert lang is None

    def test_empty_string_returns_none(self):
        # Empty string should return None
        lang = detect_language("")
        assert lang is None

    def test_none_input_returns_none(self):
        # None input should return None
        lang = detect_language(None)
        assert lang is None

    def test_whitespace_only_returns_none(self):
        # Whitespace-only string is effectively too short
        lang = detect_language("         ")
        assert lang is None

    def test_spanish_text(self):
        # Spanish text should be detected as a non-safe language
        lang = detect_language("Haga clic aquí para verificar su cuenta bancaria urgente.")
        assert lang is not None
        assert lang not in ("en", "he")

    def test_russian_text(self):
        # Russian text should be detected as a non-safe language
        lang = detect_language("Пожалуйста, подтвердите свою учётную запись немедленно.")
        assert lang is not None
        assert lang not in ("en", "he")


class TestCountPhishingKeywords:
    def test_no_keywords(self):
        # Clean text with no phishing keywords should return 0
        count = count_phishing_keywords("The weather is nice today.", ENGLISH_PHISHING_KEYWORDS)
        assert count == 0

    def test_single_keyword(self):
        # Text with one phishing keyword should return 1
        count = count_phishing_keywords("Please verify your identity.", ENGLISH_PHISHING_KEYWORDS)
        assert count >= 1

    def test_multiple_keywords(self):
        # Text with multiple phishing keywords should count all occurrences
        count = count_phishing_keywords(
            "urgent payment required, verify your account immediately", ENGLISH_PHISHING_KEYWORDS
        )
        assert count >= 3

    def test_case_insensitive_urgent(self):
        # Mixed-case "uRgEnT" should still be counted
        count = count_phishing_keywords("uRgEnT action required", ENGLISH_PHISHING_KEYWORDS)
        assert count >= 1

    def test_case_insensitive_password(self):
        # Mixed-case "PaSsWoRd" should still be counted
        count = count_phishing_keywords("your PaSsWoRd has expired", ENGLISH_PHISHING_KEYWORDS)
        assert count >= 1

    def test_keyword_repeated(self):
        # Repeated keyword should be counted multiple times
        count = count_phishing_keywords("urgent urgent urgent", ENGLISH_PHISHING_KEYWORDS)
        assert count == 3


class TestAnalyzeContent:
    def test_empty_string(self):
        # Empty string should not crash and should return 0.0
        score = analyze_content("")
        assert score == 0.0

    def test_none_input(self):
        # None input should not crash and should return 0.0
        score = analyze_content(None)
        assert score == 0.0

    def test_safe_english_email(self):
        # Conversational English with no phishing keywords should score very low
        email = "From: friend@example.com\nSubject: Lunch tomorrow?\n\nHey, are you free for lunch tomorrow? Let me know!"
        score = analyze_content(email)
        assert score < 0.2

    def test_safe_hebrew_email(self):
        # Hebrew text with no phishing keywords should not trigger language penalty
        email = "From: friend@example.com\nSubject: שלום\n\nמה שלומך? הכל בסדר אצלי, נדבר בקרוב."
        score = analyze_content(email)
        assert score < 0.2

    def test_keyword_score_caps_at_0_7(self):
        # 20+ phishing keywords should cap the keyword score at 0.7 (not higher via keywords alone)
        many_keywords = " ".join([
            "urgent", "verify", "account", "password", "suspended", "locked",
            "alert", "warning", "confirm", "login", "payment", "invoice",
            "bank", "transfer", "credit", "reward", "prize", "winner",
            "claim", "offer", "free", "expired"
        ])
        email = f"From: scammer@evil.com\nSubject: Urgent\n\n{many_keywords}"
        score = analyze_content(email)
        # keyword_score alone is capped at 0.7, overall score can reach 1.0 with other factors
        assert score <= 1.0
        assert score >= 0.7  # should definitely hit the keyword cap

    def test_case_insensitive_keywords_in_full_email(self):
        # Mixed-case phishing keywords should be detected in a full email
        email = "From: scam@evil.com\nSubject: URGENT\n\nPlease VERIFY your ACCOUNT and LOGIN immediately. Your PASSWORD has EXPIRED."
        score = analyze_content(email)
        assert score > 0.0

    def test_language_penalty_applied_for_spanish(self):
        # Email in Spanish (non-safe language) should receive the 0.15 language penalty
        spanish_email = (
            "From: scammer@evil.com\nSubject: Urgente\n\n"
            "Haga clic aquí para verificar su cuenta bancaria de forma urgente antes de que expire."
        )
        score = analyze_content(spanish_email)
        assert score >= 0.15

    def test_language_penalty_applied_for_russian(self):
        # Email in Russian (non-safe language) should receive the 0.15 language penalty
        russian_email = (
            "From: scammer@evil.com\nSubject: Срочно\n\n"
            "Пожалуйста, подтвердите свою учётную запись немедленно. Ваш пароль истёк."
        )
        score = analyze_content(russian_email)
        assert score >= 0.15

    def test_perfectly_safe_empty_html(self):
        # Empty HTML body with no signals should score 0.0
        email = "From: user@example.com\nSubject: Hi\n\n<html><body></body></html>"
        score = analyze_content(email)
        assert score == 0.0

    def test_maximum_malicious_score_capped_at_1(self):
        # Obfuscated HTML + unexpected language + heavy phishing keywords should hit exactly 1.0
        obfuscated_keywords = " ".join([
            "urgent", "verify", "account", "password", "suspended", "locked",
            "alert", "warning", "confirm", "login", "payment", "invoice",
            "bank", "transfer", "credit", "reward", "prize", "winner",
        ])
        email = (
            "From: scammer@evil.com\nSubject: Urgente\n\n"
            f'<html><body>'
            f'<span style="font-size: 0px; color: white; background: #ffffff;">hidden</span>'
            f'<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe>'
            f'<p>Haga clic aquí para verificar. {obfuscated_keywords}</p>'
            f'</body></html>'
        )
        score = analyze_content(email)
        assert score == 1.0

    def test_obfuscation_alone_raises_score(self):
        # HTML obfuscation in an otherwise clean email should still raise the score
        email = (
            "From: scammer@evil.com\nSubject: Hello\n\n"
            '<html><body><span style="font-size: 0px;">.</span></body></html>'
        )
        score = analyze_content(email)
        assert score > 0.0
