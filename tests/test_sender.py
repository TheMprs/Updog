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
    def _mock_whois(self, creation_date):
        mock_info = MagicMock()
        mock_info.creation_date = creation_date
        return mock_info

    def test_very_new_domain(self):
        creation = datetime.now(timezone.utc) - timedelta(days=10)
        with patch("analyzers.sender.whois_lib.whois", return_value=self._mock_whois(creation)):
            with patch("analyzers.sender.WHOIS_AVAILABLE", True):
                score = check_domain_age("new-phishing-domain.com")
        assert score == 1.0

    def test_young_domain(self):
        creation = datetime.now(timezone.utc) - timedelta(days=60)
        with patch("analyzers.sender.whois_lib.whois", return_value=self._mock_whois(creation)):
            with patch("analyzers.sender.WHOIS_AVAILABLE", True):
                score = check_domain_age("youngdomain.com")
        assert score == 0.7

    def test_old_domain(self):
        creation = datetime.now(timezone.utc) - timedelta(days=365 * 5)
        with patch("analyzers.sender.whois_lib.whois", return_value=self._mock_whois(creation)):
            with patch("analyzers.sender.WHOIS_AVAILABLE", True):
                score = check_domain_age("established.com")
        assert score == 0.0

    def test_list_creation_date_uses_first(self):
        old = datetime.now(timezone.utc) - timedelta(days=1000)
        new = datetime.now(timezone.utc) - timedelta(days=5)
        with patch("analyzers.sender.whois_lib.whois", return_value=self._mock_whois([old, new])):
            with patch("analyzers.sender.WHOIS_AVAILABLE", True):
                score = check_domain_age("multidomain.com")
        assert score == 0.0  # first date is old

    def test_whois_unavailable(self):
        with patch("analyzers.sender.WHOIS_AVAILABLE", False):
            score = check_domain_age("example.com")
        assert score == 0.0

    def test_empty_domain(self):
        score = check_domain_age("")
        assert score == 0.0

    def test_none_creation_date(self):
        with patch("analyzers.sender.whois_lib.whois", return_value=self._mock_whois(None)):
            with patch("analyzers.sender.WHOIS_AVAILABLE", True):
                score = check_domain_age("nodatadomain.com")
        assert score == 0.0

    def test_whois_exception_returns_zero(self):
        with patch("analyzers.sender.whois_lib.whois", side_effect=Exception("Network error")):
            with patch("analyzers.sender.WHOIS_AVAILABLE", True):
                score = check_domain_age("unreachable.com")
        assert score == 0.0


class TestCheckTyposquatting:
    def test_exact_major_domain_is_safe(self):
        assert check_typosquatting("google.com") == 0.0

    def test_paypal_typo_one_char(self):
        # paypa1.com vs paypal.com - edit distance 1
        score = check_typosquatting("paypa1.com")
        assert score == 0.9

    def test_amazon_typo_two_chars(self):
        # arnazon (7) vs amazon (6) - edit distance 2, base >= 6 chars
        score = check_typosquatting("arnazon.com")
        assert score == 0.7

    def test_microsoft_typo_two_chars(self):
        # microsofft.com vs microsoft.com - edit distance 1
        score = check_typosquatting("microsofft.com")
        assert score == 0.9

    def test_apple_two_char_typo(self):
        # applle.com vs apple.com - edit distance 1
        score = check_typosquatting("applle.com")
        assert score == 0.9

    def test_unrelated_domain(self):
        score = check_typosquatting("totallyunrelated.com")
        assert score == 0.0

    def test_empty_domain(self):
        assert check_typosquatting("") == 0.0

    def test_short_major_domain_skipped(self):
        # "bank" is in MAJOR_DOMAINS but < 4 chars so distance check is skipped
        # "ban.com" would not match any domain with len >= 4
        score = check_typosquatting("ban.com")
        assert score == 0.0


class TestCheckDisplayNameSpoofing:
    def test_apple_spoofing(self):
        score = check_display_name_spoofing('"Apple Support" <attacker@evil.com>', "evil.com")
        assert score == 0.9

    def test_paypal_spoofing(self):
        score = check_display_name_spoofing('"PayPal Security" <no-reply@phish.net>', "phish.net")
        assert score == 0.9

    def test_legitimate_google_email(self):
        score = check_display_name_spoofing('"Google" <noreply@google.com>', "google.com")
        assert score == 0.0

    def test_no_display_name(self):
        # Plain email address with no display name
        score = check_display_name_spoofing("attacker@evil.com", "evil.com")
        assert score == 0.0

    def test_empty_from_header(self):
        assert check_display_name_spoofing("", "evil.com") == 0.0

    def test_empty_sender_domain(self):
        assert check_display_name_spoofing('"Apple" <x@y.com>', "") == 0.0

    def test_non_brand_display_name(self):
        score = check_display_name_spoofing('"John Doe" <john@randomdomain.com>', "randomdomain.com")
        assert score == 0.0

    def test_bank_spoofing(self):
        score = check_display_name_spoofing('"Your Bank" <alerts@scam-site.org>', "scam-site.org")
        assert score == 0.9


class TestCheckFreeEmailProvider:
    def test_gmail(self):
        assert check_free_email_provider("gmail.com") == 0.3

    def test_yahoo(self):
        assert check_free_email_provider("yahoo.com") == 0.3

    def test_hotmail(self):
        assert check_free_email_provider("hotmail.com") == 0.3

    def test_outlook(self):
        assert check_free_email_provider("outlook.com") == 0.3

    def test_aol(self):
        assert check_free_email_provider("aol.com") == 0.3

    def test_business_domain(self):
        assert check_free_email_provider("company.com") == 0.0

    def test_empty_domain(self):
        assert check_free_email_provider("") == 0.0

    def test_case_insensitive(self):
        assert check_free_email_provider("Gmail.com") == 0.3


class TestCheckReplyToMismatch:
    def test_same_domain(self):
        assert check_reply_to_mismatch("bank.com", "bank.com") == 0.0

    def test_subdomain_is_fine(self):
        # support.example.com and example.com share base domain
        assert check_reply_to_mismatch("support.example.com", "example.com") == 0.0

    def test_completely_different_domain(self):
        score = check_reply_to_mismatch("legit-bank.com", "harvest@evil.net".split('@')[-1])
        assert score == 0.8

    def test_different_tld(self):
        # bank.com vs bank.net - different base
        score = check_reply_to_mismatch("bank.com", "bank.net")
        assert score == 0.8

    def test_empty_from_domain(self):
        assert check_reply_to_mismatch("", "evil.com") == 0.0

    def test_empty_reply_to_domain(self):
        assert check_reply_to_mismatch("legit.com", "") == 0.0

    def test_both_empty(self):
        assert check_reply_to_mismatch("", "") == 0.0


class TestAnalyzeSender:
    def _build_email(self, from_header, reply_to=None, body="Hello"):
        headers = f"From: {from_header}\nSubject: Test\n"
        if reply_to:
            headers += f"Reply-To: {reply_to}\n"
        return headers + "\n" + body

    def test_clean_email(self):
        email = self._build_email("John Doe <john@established-company.com>")
        score = analyze_sender(email)
        assert score < 0.3

    def test_display_name_spoofing_detected(self):
        email = self._build_email('"Apple Support" <attacker@evil-domain.com>')
        score = analyze_sender(email)
        assert score >= 0.7

    def test_typosquatting_detected(self):
        email = self._build_email("billing@paypa1.com")
        score = analyze_sender(email)
        assert score >= 0.7

    def test_reply_to_mismatch_detected(self):
        email = self._build_email(
            "support@legit-bank.com",
            reply_to="harvest@completely-different.net"
        )
        score = analyze_sender(email)
        assert score >= 0.6

    def test_free_provider_alone_is_low_risk(self):
        email = self._build_email("someone@gmail.com")
        score = analyze_sender(email)
        assert score < 0.2

    def test_score_capped_at_one(self):
        # Even worst-case combination should not exceed 1.0
        email = self._build_email(
            '"PayPal Security" <billing@paypa1.com>',
            reply_to="collect@scam.net"
        )
        score = analyze_sender(email)
        assert 0.0 <= score <= 1.0

    def test_no_from_header(self):
        email = "Subject: Test\n\nNo from header"
        score = analyze_sender(email)
        assert score == 0.0
