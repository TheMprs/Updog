import pytest
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from scorer import compute_score, get_band, generate_bullets, analyze


class TestComputeScore:
    """Tests for compute_score — weighted average with dynamic weight dropping and signal floors."""

    def _all_scores(self, **overrides):
        """Return a baseline zero-score dict with optional overrides."""
        base = {"header": 0.0, "sender": 0.0, "url": 0.0, "content": 0.0, "attachment": 0.0}
        base.update(overrides)
        return base

    def test_all_zeros_returns_zero(self):
        """All zero scores should produce 0."""
        assert compute_score(self._all_scores(), has_urls=True, has_attachments=True) == 0

    def test_all_ones_returns_hundred(self):
        """All perfect scores should produce 100."""
        assert compute_score(self._all_scores(header=1.0, sender=1.0, url=1.0, content=1.0, attachment=1.0), True, True) == 100

    def test_url_dropped_when_no_urls(self):
        """Without URLs the url weight is excluded and remaining weights renormalize."""
        # url=1.0 but has_urls=False — should not push score up
        scores_with = self._all_scores(url=1.0)
        score_no_url = compute_score(scores_with, has_urls=False, has_attachments=False)
        score_with_url = compute_score(scores_with, has_urls=True, has_attachments=False)
        assert score_no_url == 0
        assert score_with_url > 0

    def test_attachment_dropped_when_no_attachments(self):
        """Without attachments the attachment weight is excluded."""
        scores = self._all_scores(attachment=1.0)
        score_no_att = compute_score(scores, has_urls=False, has_attachments=False)
        score_with_att = compute_score(scores, has_urls=False, has_attachments=True)
        assert score_no_att == 0
        assert score_with_att > 0

    def test_url_floor_triggers(self):
        """Malicious URL score >= 0.8 should floor the result at 75."""
        scores = self._all_scores(url=0.9)
        score = compute_score(scores, has_urls=True, has_attachments=False)
        assert score >= 75

    def test_attachment_floor_triggers(self):
        """Risky attachment score >= 0.6 should floor the result at 65."""
        scores = self._all_scores(attachment=0.6)
        score = compute_score(scores, has_urls=False, has_attachments=True)
        assert score >= 65

    def test_sender_floor_triggers(self):
        """Clear spoofing score >= 0.9 should floor the result at 70."""
        scores = self._all_scores(sender=0.9)
        score = compute_score(scores, has_urls=False, has_attachments=False)
        assert score >= 70

    def test_floor_does_not_override_higher_weighted_score(self):
        """When weighted average exceeds the floor, the higher value wins."""
        scores = self._all_scores(header=1.0, sender=1.0, url=1.0, content=1.0, attachment=1.0)
        score = compute_score(scores, has_urls=True, has_attachments=True)
        assert score == 100

    def test_returns_int(self):
        """compute_score must return an int, not a float."""
        score = compute_score(self._all_scores(header=0.5), has_urls=False, has_attachments=False)
        assert isinstance(score, int)

    def test_score_bounded_0_to_100(self):
        """Score must never fall outside the 0–100 range."""
        scores = self._all_scores(header=1.0, sender=1.0, url=1.0, content=1.0, attachment=1.0)
        score = compute_score(scores, has_urls=True, has_attachments=True)
        assert 0 <= score <= 100


class TestGetBand:
    """Tests for get_band — maps integer score to (verdict, color)."""

    def test_score_0_is_safe(self):
        """Bottom of safe band."""
        assert get_band(0) == ("Safe", "green")

    def test_score_30_is_safe(self):
        """Top of safe band."""
        assert get_band(30) == ("Safe", "green")

    def test_score_31_is_suspicious(self):
        """Bottom of suspicious band."""
        assert get_band(31) == ("Suspicious", "yellow")

    def test_score_60_is_suspicious(self):
        """Top of suspicious band."""
        assert get_band(60) == ("Suspicious", "yellow")

    def test_score_61_is_likely_malicious(self):
        """Bottom of likely malicious band."""
        assert get_band(61) == ("Likely Malicious", "orange")

    def test_score_80_is_likely_malicious(self):
        """Top of likely malicious band."""
        assert get_band(80) == ("Likely Malicious", "orange")

    def test_score_81_is_malicious(self):
        """Bottom of malicious band."""
        assert get_band(81) == ("Malicious", "red")

    def test_score_100_is_malicious(self):
        """Top of malicious band."""
        assert get_band(100) == ("Malicious", "red")


class TestGenerateBullets:
    """Tests for generate_bullets — table-driven signal-to-text mapping."""

    def test_no_signals_no_bullets(self):
        """All-clear signals should produce an empty bullet list."""
        signals = {
            "spf": "pass", "dkim": "pass", "dmarc": "pass",
            "display_name_spoof": False, "reply_to_mismatch": False,
            "typosquat_detected": False, "free_provider_spoof": False,
            "malicious_urls": [], "phishing_keywords": 0,
            "obfuscation_detected": False, "mime_mismatch": False,
            "encrypted_archive": False, "risky_extension": False,
        }
        assert generate_bullets(signals) == []

    def test_spf_fail_produces_bullet(self):
        """SPF failure should produce one bullet."""
        bullets = generate_bullets({"spf": "fail"})
        assert any("SPF" in b for b in bullets)

    def test_dkim_fail_produces_bullet(self):
        """DKIM failure should produce one bullet."""
        bullets = generate_bullets({"dkim": "fail"})
        assert any("DKIM" in b for b in bullets)

    def test_dmarc_fail_produces_bullet(self):
        """DMARC failure should produce one bullet."""
        bullets = generate_bullets({"dmarc": "fail"})
        assert any("DMARC" in b for b in bullets)

    def test_malicious_url_produces_bullet(self):
        """Non-empty malicious URL list should fire the URL bullet."""
        bullets = generate_bullets({"malicious_urls": ["http://evil.com"]})
        assert any("Malicious URL" in b for b in bullets)

    def test_keyword_count_below_threshold_no_bullet(self):
        """5 or fewer phishing keywords should not produce a bullet."""
        bullets = generate_bullets({"phishing_keywords": 5})
        assert not any("phishing keyword" in b for b in bullets)

    def test_keyword_count_above_threshold_produces_bullet(self):
        """More than 5 phishing keywords should fire the keyword bullet."""
        bullets = generate_bullets({"phishing_keywords": 6})
        assert any("phishing keyword" in b for b in bullets)

    def test_obfuscation_produces_bullet(self):
        """HTML obfuscation flag should produce a bullet."""
        bullets = generate_bullets({"obfuscation_detected": True})
        assert any("obfuscation" in b.lower() for b in bullets)

    def test_risky_extension_produces_bullet(self):
        """Risky file extension should produce a bullet."""
        bullets = generate_bullets({"risky_extension": True})
        assert any("attachment" in b.lower() for b in bullets)

    def test_encrypted_archive_produces_bullet(self):
        """Password-protected archive should produce a bullet."""
        bullets = generate_bullets({"encrypted_archive": True})
        assert any("archive" in b.lower() for b in bullets)

    def test_mime_mismatch_produces_bullet(self):
        """MIME type mismatch should produce a bullet."""
        bullets = generate_bullets({"mime_mismatch": True})
        assert any("disguised" in b.lower() for b in bullets)

    def test_multiple_signals_produce_multiple_bullets(self):
        """Multiple fired signals should each produce a bullet."""
        signals = {"spf": "fail", "dkim": "fail", "malicious_urls": ["http://x.com"]}
        bullets = generate_bullets(signals)
        assert len(bullets) >= 3

    def test_bullets_contain_icon_prefix(self):
        """Every bullet should start with an emoji icon."""
        bullets = generate_bullets({"spf": "fail"})
        assert bullets[0].startswith(("❌", "⚠️"))


class TestAnalyze:
    """Tests for analyze — full pipeline orchestration."""

    def _make_analyzer_return(self, score, signals):
        """Build the (score, signals) tuple that analyzers return."""
        return (score, signals)

    def _patch_all_analyzers(self, header=(0.0, {}), sender=(0.0, {}),
                              url=(0.0, {"total_urls": 0, "malicious_urls": []}),
                              attachment=(0.0, {"total_attachments": 0, "risky_extension": False,
                                                "encrypted_archive": False, "mime_mismatch": False,
                                                "risky_files": []}),
                              content=(0.0, {"phishing_keywords": 0, "obfuscation_detected": False,
                                             "detected_language": "en"})):
        """Context manager that mocks all five analyzers."""
        return [
            patch("scorer.analyze_headers", return_value=header),
            patch("scorer.analyze_sender",  return_value=sender),
            patch("scorer.analyze_urls",    return_value=url),
            patch("scorer.analyze_attachments", return_value=attachment),
            patch("scorer.analyze_content", return_value=content),
        ]

    def test_return_shape(self):
        """analyze must return all required keys."""
        patches = self._patch_all_analyzers()
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            result = analyze("From: user@example.com\n\nHello")
        assert "score"     in result
        assert "verdict"   in result
        assert "color"     in result
        assert "bullets"   in result
        assert "breakdown" in result

    def test_breakdown_contains_all_analyzers(self):
        """breakdown dict must include scores for all five analyzers."""
        patches = self._patch_all_analyzers()
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            result = analyze("From: user@example.com\n\nHello")
        for key in ("header", "sender", "url", "content", "attachment"):
            assert key in result["breakdown"]

    def test_clean_email_scores_safe(self):
        """All-zero analyzer scores should produce a Safe verdict."""
        patches = self._patch_all_analyzers()
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            result = analyze("From: user@example.com\n\nHello")
        assert result["verdict"] == "Safe"
        assert result["color"]   == "green"
        assert result["score"]   == 0

    def test_malicious_url_floor_applied(self):
        """High URL score should floor the final score at >= 75."""
        url_signals = {"total_urls": 1, "malicious_urls": ["http://evil.com"]}
        patches = self._patch_all_analyzers(url=(0.9, url_signals))
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            result = analyze("From: x@y.com\n\nClick here")
        assert result["score"] >= 75

    def test_bullets_generated_from_signals(self):
        """Fired signals should appear as bullets in the response."""
        header_signals = {"spf": "fail", "dkim": "pass", "dmarc": "pass",
                          "is_major_domain": False, "spam_score": 0.0}
        patches = self._patch_all_analyzers(header=(0.3, header_signals))
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            result = analyze("From: x@y.com\n\nHello")
        assert any("SPF" in b for b in result["bullets"])

    def test_score_is_int(self):
        """score field must be an integer."""
        patches = self._patch_all_analyzers()
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            result = analyze("From: x@y.com\n\nHello")
        assert isinstance(result["score"], int)
