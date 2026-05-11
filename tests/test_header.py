import pytest
import sys
from pathlib import Path

# Add backend to path so we can import analyzers
sys.path.insert(0, str(Path(__file__).parent.parent / "backend" / "analyzers"))

from header import (
    parse_authentication_results,
    is_major_domain,
    check_auth_failures,
    check_spam_score,
    analyze_headers,
)

class TestParseAuthenticationResults:
    def test_all_pass(self):
        # Verify parsing when all auth checks pass
        auth = "spf=pass dkim=pass dmarc=pass"
        result = parse_authentication_results(auth)
        assert result == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}

    def test_mixed_results(self):
        # Verify parsing with mixed pass/fail/neutral results
        auth = "spf=pass dkim=fail dmarc=neutral"
        result = parse_authentication_results(auth)
        assert result["spf"] == "pass"
        assert result["dkim"] == "fail"
        assert result["dmarc"] == "neutral"

    def test_uppercase_keys(self):
        # Verify regex handles uppercase SPF/DKIM/DMARC keys
        auth = "SPF=pass DKIM=fail DMARC=pass"
        result = parse_authentication_results(auth)
        assert result["spf"] == "pass"
        assert result["dkim"] == "fail"

    def test_empty_header(self):
        # Verify empty header returns all None values
        result = parse_authentication_results("")
        assert result == {"spf": None, "dkim": None, "dmarc": None}

    def test_none_header(self):
        # Verify None input returns all None values
        result = parse_authentication_results(None)
        assert result == {"spf": None, "dkim": None, "dmarc": None}

    def test_partial_results(self):
        # Verify parsing when only some checks are present
        auth = "spf=pass dmarc=fail"
        result = parse_authentication_results(auth)
        assert result["spf"] == "pass"
        assert result["dkim"] is None
        assert result["dmarc"] == "fail"

class TestIsMajorDomain:
    def test_apple(self):
        # Verify Apple domain is recognized as major
        assert is_major_domain("support@apple.com") is True

    def test_google(self):
        # Verify Google domain is recognized as major
        assert is_major_domain("noreply@google.com") is True

    def test_amazon(self):
        # Verify Amazon domain is recognized as major
        assert is_major_domain("orders@amazon.com") is True

    def test_random_domain(self):
        # Verify unknown domain is not flagged as major
        assert is_major_domain("admin@randomcompany.com") is False

    def test_none_address(self):
        # Verify None input returns False
        assert is_major_domain(None) is False

    def test_empty_address(self):
        # Verify empty string returns False
        assert is_major_domain("") is False

    def test_no_at_symbol(self):
        # Verify invalid email without @ returns False
        assert is_major_domain("invalid-email") is False

    def test_bank_keyword(self):
        # Verify domain containing "bank" keyword is recognized as major
        assert is_major_domain("support@mybank.com") is True

class TestCheckAuthFailures:
    def test_all_pass(self):
        # Verify all passing checks result in 0.0 score
        headers = {
            "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
            "From": "user@example.com",
        }
        score = check_auth_failures(headers)
        assert score == 0.0

    def test_one_failure(self):
        # Verify one failed check gives 0.3 score (0.3 per failure)
        headers = {
            "Authentication-Results": "spf=fail dkim=pass dmarc=pass",
            "From": "user@example.com",
        }
        score = check_auth_failures(headers)
        assert score == 0.3

    def test_all_failures(self):
        # Verify all failed checks give 0.9 score (capped)
        headers = {
            "Authentication-Results": "spf=fail dkim=fail dmarc=fail",
            "From": "user@example.com",
        }
        score = check_auth_failures(headers)
        assert score == pytest.approx(0.9)

    def test_major_domain_with_failure(self):
        # Verify major domain with failures gets 2x boost
        headers = {
            "Authentication-Results": "spf=fail dkim=pass dmarc=pass",
            "From": "support@apple.com",
        }
        score = check_auth_failures(headers)
        assert score == 0.6  # 0.3 * 2

    def test_major_domain_all_failures(self):
        # Verify major domain with all failures capped at 0.9
        headers = {
            "Authentication-Results": "spf=fail dkim=fail dmarc=fail",
            "From": "noreply@google.com",
        }
        score = check_auth_failures(headers)
        assert score == 0.9  # Capped at 0.9

    def test_missing_auth_header(self):
        # Verify completely missing auth header is treated as all failures
        headers = {"From": "user@example.com"}
        score = check_auth_failures(headers)
        assert score == pytest.approx(0.9)  # All 3 are None = 3 failures

    def test_none_values_treated_as_failures(self):
        # Verify None check results count as failures
        headers = {
            "Authentication-Results": "spf=pass",
            "From": "user@example.com",
        }
        score = check_auth_failures(headers)
        # dkim and dmarc are None (treated as failures), spf is pass
        assert score == 0.6  # 2 failures * 0.3

class TestCheckSpamScore:
    def test_normal_score(self):
        # Verify spam score is normalized to 0-1 range
        headers = {"X-Spam-Score": "3"}
        score = check_spam_score(headers)
        assert score == 0.3

    def test_high_spam_score(self):
        # Verify high spam score maps correctly
        headers = {"X-Spam-Score": "8"}
        score = check_spam_score(headers)
        assert score == 0.8

    def test_zero_score(self):
        # Verify zero spam score returns 0.0
        headers = {"X-Spam-Score": "0"}
        score = check_spam_score(headers)
        assert score == 0.0

    def test_missing_header(self):
        # Verify missing header defaults to 0.0
        headers = {}
        score = check_spam_score(headers)
        assert score == 0.0

    def test_invalid_score(self):
        # Verify invalid score string returns 0.0
        headers = {"X-Spam-Score": "invalid"}
        score = check_spam_score(headers)
        assert score == 0.0

    def test_score_capped_at_1(self):
        # Verify high scores are capped at 1.0
        headers = {"X-Spam-Score": "15"}
        score = check_spam_score(headers)
        assert score == 1.0

    def test_negative_score_capped_at_0(self):
        # Verify negative scores are capped at 0.0
        headers = {"X-Spam-Score": "-5"}
        score = check_spam_score(headers)
        assert score == 0.0

class TestAnalyzeHeaders:
    def test_clean_email(self):
        # Verify clean email with all passing checks scores 0.0
        headers = {
            "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
            "X-Spam-Score": "0",
            "From": "user@example.com",
        }
        score = analyze_headers(headers)
        assert score == 0.0

    def test_spoofed_apple(self):
        # Verify spoofed Apple email scores high (0.78)
        headers = {
            "Authentication-Results": "spf=fail dkim=fail dmarc=fail",
            "X-Spam-Score": "5",
            "From": "support@apple.com",
        }
        score = analyze_headers(headers)
        # auth_score = 0.9, spam_score = 0.5
        # combined = 0.9 * 0.7 + 0.5 * 0.3 = 0.63 + 0.15 = 0.78
        assert 0.77 < score < 0.79

    def test_suspicious_email(self):
        # Verify email with mixed failures and spam scores 0.63
        headers = {
            "Authentication-Results": "spf=fail dkim=pass dmarc=fail",
            "X-Spam-Score": "7",
            "From": "admin@example.com",
        }
        score = analyze_headers(headers)
        # auth_score = 0.6, spam_score = 0.7
        # combined = 0.6 * 0.7 + 0.7 * 0.3 = 0.42 + 0.21 = 0.63
        assert 0.62 < score < 0.64
