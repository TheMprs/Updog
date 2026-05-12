import pytest
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from analyzers.sender import (
    check_domain_age,
    check_typosquatting,
    check_display_name_spoofing,
    check_free_email_provider,
    check_reply_to_mismatch,
    analyze_sender,
)


class TestCheckDomainAge:
    """Tests for check_domain_age."""

    def _mock_whois(self, creation_date):
        """Build a mock whois result with the given creation date."""
        return {"creation_date": creation_date}

    def test_very_new_domain(self):
        """Domain registered < 30 days ago should score 1.0."""
        creation = datetime.now(timezone.utc) - timedelta(days=10)
        with patch("analyzers.sender.whois_lib.whois", return_value=self._mock_whois(creation)):
            score = check_domain_age("new-phishing-domain.com")
        assert score == 1.0

    def test_young_domain(self):
        """Domain registered 30-90 days ago should score 0.7."""
        creation = datetime.now(timezone.utc) - timedelta(days=60)
        with patch("analyzers.sender.whois_lib.whois", return_value=self._mock_whois(creation)):
            score = check_domain_age("youngdomain.com")
        assert score == 0.7

    def test_old_domain(self):
        """Established domain should score 0.0."""
        creation = datetime.now(timezone.utc) - timedelta(days=365 * 5)
        with patch("analyzers.sender.whois_lib.whois", return_value=self._mock_whois(creation)):
            score = check_domain_age("established.com")
        assert score == 0.0

    def test_list_creation_date_uses_first(self):
        """When creation_date is a list, the first value is used."""
        old = datetime.now(timezone.utc) - timedelta(days=1000)
        new = datetime.now(timezone.utc) - timedelta(days=5)
        with patch("analyzers.sender.whois_lib.whois", return_value=self._mock_whois([old, new])):
            score = check_domain_age("multidomain.com")
        assert score == 0.0  # first date is old

    def test_empty_domain(self):
        """Empty domain should return 0.0 without crashing."""
        score = check_domain_age("")
        assert score == 0.0

    def test_none_creation_date(self):
        """Missing creation date in whois result should return 0.0."""
        with patch("analyzers.sender.whois_lib.whois", return_value=self._mock_whois(None)):
            score = check_domain_age("nodatadomain.com")
        assert score == 0.0

    def test_whois_exception_returns_zero(self):
        """Network or lookup failures should not raise — return 0.0."""
        with patch("analyzers.sender.whois_lib.whois", side_effect=Exception("Network error")):
            score = check_domain_age("unreachable.com")
        assert score == 0.0


class TestCheckTyposquatting:
    """Tests for check_typosquatting, which returns (score, target)."""

    def test_exact_major_domain_is_safe(self):
        """Exact match should not be flagged as a typosquat."""
        score, target = check_typosquatting("google.com")
        assert score == 0.0
        assert target is None

    def test_paypal_typo_one_char(self):
        """One-char edit from 'paypal' should score 0.9 and name the target."""
        score, target = check_typosquatting("paypa1.com")
        assert score == 0.9
        assert target == "paypal.com"

    def test_amazon_typo_two_chars(self):
        """Two-char edit from a 6+ char base should score 0.7."""
        score, target = check_typosquatting("arnazon.com")
        assert score == 0.7
        assert target == "amazon.com"

    def test_microsoft_typo_one_char(self):
        """One extra char in 'microsofft' is edit distance 1."""
        score, target = check_typosquatting("microsofft.com")
        assert score == 0.9
        assert target == "microsoft.com"

    def test_apple_typo_one_char(self):
        """Double-l in 'applle' is edit distance 1."""
        score, target = check_typosquatting("applle.com")
        assert score == 0.9
        assert target == "apple.com"

    def test_unrelated_domain(self):
        """Completely unrelated domain should return safe with no target."""
        score, target = check_typosquatting("totallyunrelated.com")
        assert score == 0.0
        assert target is None

    def test_empty_domain(self):
        """Empty domain should return 0.0 with no target."""
        score, target = check_typosquatting("")
        assert score == 0.0
        assert target is None


class TestCheckDisplayNameSpoofing:
    """Tests for check_display_name_spoofing."""

    def test_apple_spoofing(self):
        """Brand name in display but unrelated domain should score 0.9."""
        score = check_display_name_spoofing('"Apple Support" <attacker@evil.com>', "evil.com")
        assert score == 0.9

    def test_paypal_spoofing(self):
        """PayPal brand keyword in display name should be caught."""
        score = check_display_name_spoofing('"PayPal Security" <no-reply@phish.net>', "phish.net")
        assert score == 0.9

    def test_legitimate_google_email(self):
        """Google display name with google.com domain is legitimate."""
        score = check_display_name_spoofing('"Google" <noreply@google.com>', "google.com")
        assert score == 0.0

    def test_no_display_name(self):
        """Plain address with no display name cannot be spoofed this way."""
        score = check_display_name_spoofing("attacker@evil.com", "evil.com")
        assert score == 0.0

    def test_empty_from_header(self):
        """Empty from header should return 0.0."""
        assert check_display_name_spoofing("", "evil.com") == 0.0

    def test_empty_sender_domain(self):
        """Missing sender domain should return 0.0."""
        assert check_display_name_spoofing('"Apple" <x@y.com>', "") == 0.0

    def test_non_brand_display_name(self):
        """Generic display name with no brand keyword should return 0.0."""
        score = check_display_name_spoofing('"John Doe" <john@randomdomain.com>', "randomdomain.com")
        assert score == 0.0

    def test_bank_spoofing(self):
        """'Bank' keyword in display name with unrelated domain should score 0.9."""
        score = check_display_name_spoofing('"Your Bank" <alerts@scam-site.org>', "scam-site.org")
        assert score == 0.9


class TestCheckFreeEmailProvider:
    """Tests for check_free_email_provider."""

    def test_gmail(self):
        """Gmail should be recognized as free provider."""
        assert check_free_email_provider("gmail.com") == 0.3

    def test_yahoo(self):
        """Yahoo should be recognized as free provider."""
        assert check_free_email_provider("yahoo.com") == 0.3

    def test_hotmail(self):
        """Hotmail should be recognized as free provider."""
        assert check_free_email_provider("hotmail.com") == 0.3

    def test_outlook(self):
        """Outlook should be recognized as free provider."""
        assert check_free_email_provider("outlook.com") == 0.3

    def test_aol(self):
        """AOL should be recognized as free provider."""
        assert check_free_email_provider("aol.com") == 0.3

    def test_business_domain(self):
        """Custom business domain should return 0.0."""
        assert check_free_email_provider("company.com") == 0.0

    def test_empty_domain(self):
        """Empty domain should return 0.0."""
        assert check_free_email_provider("") == 0.0

    def test_case_insensitive(self):
        """Check is case-insensitive."""
        assert check_free_email_provider("Gmail.com") == 0.3


class TestCheckReplyToMismatch:
    """Tests for check_reply_to_mismatch."""

    def test_same_domain(self):
        """Identical from and reply-to domains should return 0.0."""
        assert check_reply_to_mismatch("bank.com", "bank.com") == 0.0

    def test_subdomain_is_fine(self):
        """Subdomain of same base domain should not be flagged."""
        assert check_reply_to_mismatch("support.example.com", "example.com") == 0.0

    def test_completely_different_domain(self):
        """Completely different reply-to domain is a strong phishing signal."""
        score = check_reply_to_mismatch("legit-bank.com", "evil.net")
        assert score == 0.8

    def test_different_tld(self):
        """Same name but different TLD (bank.com vs bank.net) should be flagged."""
        score = check_reply_to_mismatch("bank.com", "bank.net")
        assert score == 0.8

    def test_empty_from_domain(self):
        """Missing from domain means no basis for comparison — return 0.0."""
        assert check_reply_to_mismatch("", "evil.com") == 0.0

    def test_empty_reply_to_domain(self):
        """Missing reply-to domain means the header is absent — not a signal."""
        assert check_reply_to_mismatch("legit.com", "") == 0.0

    def test_both_empty(self):
        """Both empty should return 0.0."""
        assert check_reply_to_mismatch("", "") == 0.0


class TestAnalyzeSender:
    """Tests for analyze_sender, which returns (score, signals)."""

    def _build_email(self, from_header, reply_to=None, body="Hello"):
        """Construct a minimal email string with the given headers."""
        headers = f"From: {from_header}\nSubject: Test\n"
        if reply_to:
            headers += f"Reply-To: {reply_to}\n"
        return headers + "\n" + body

    def test_clean_email_low_score(self):
        """Legitimate sender with no suspicious signals should score low."""
        email = self._build_email("John Doe <john@established-company.com>")
        score, signals = analyze_sender(email)
        assert score < 0.3

    def test_display_name_spoofing_detected(self):
        """Brand keyword in display name with wrong domain should score high."""
        email = self._build_email('"Apple Support" <attacker@evil-domain.com>')
        score, signals = analyze_sender(email)
        assert score >= 0.7
        assert signals["display_name_spoof"] is True

    def test_typosquatting_detected(self):
        """One-char deviation from 'paypal' should be caught."""
        email = self._build_email("billing@paypa1.com")
        score, signals = analyze_sender(email)
        assert score >= 0.7
        assert signals["typosquat_detected"] is True
        assert signals["typosquat_target"] == "paypal.com"

    def test_reply_to_mismatch_detected(self):
        """Reply-To pointing to a different domain is a phishing indicator."""
        email = self._build_email(
            "support@legit-bank.com",
            reply_to="harvest@completely-different.net"
        )
        score, signals = analyze_sender(email)
        assert score >= 0.6
        assert signals["reply_to_mismatch"] is True

    def test_free_provider_alone_is_low_risk(self):
        """Free provider without any other signal should not score high."""
        email = self._build_email("someone@gmail.com")
        score, signals = analyze_sender(email)
        assert score < 0.2
        assert signals["free_provider_spoof"] is True

    def test_score_capped_at_one(self):
        """Combined worst-case signals should never exceed 1.0."""
        email = self._build_email(
            '"PayPal Security" <billing@paypa1.com>',
            reply_to="collect@scam.net"
        )
        score, _ = analyze_sender(email)
        assert 0.0 <= score <= 1.0

    def test_no_from_header_returns_zero(self):
        """Email with no From header should score 0.0."""
        email = "Subject: Test\n\nNo from header"
        score, signals = analyze_sender(email)
        assert score == 0.0

    def test_signals_dict_shape(self):
        """Returned signals dict must contain all expected keys."""
        email = self._build_email("user@example.com")
        _, signals = analyze_sender(email)
        assert "display_name_spoof" in signals
        assert "reply_to_mismatch" in signals
        assert "free_provider_spoof" in signals
        assert "typosquat_detected" in signals
        assert "typosquat_target" in signals
        assert "from_domain" in signals

    def test_from_domain_captured(self):
        """from_domain in signals should match the actual sender domain."""
        email = self._build_email("user@example.com")
        _, signals = analyze_sender(email)
        assert signals["from_domain"] == "example.com"
