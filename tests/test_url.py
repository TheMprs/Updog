import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add backend to path so we can import analyzers as a package
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from analyzers.url import extract_urls, score_url, analyze_urls

class TestExtractUrls:
    def test_simple_href(self):
        # Extract URL from href attribute in anchor tag
        html = '<a href="https://example.com">Click</a>'
        urls = extract_urls(html)
        assert "https://example.com" in urls

    def test_multiple_links(self):
        # Extract multiple URLs from multiple anchor tags
        html = '''
        <a href="https://evil.com">Click</a>
        <a href="https://safe.com">Click</a>
        '''
        urls = extract_urls(html)
        assert "https://evil.com" in urls
        assert "https://safe.com" in urls

    def test_img_src(self):
        # Extract URL from src attribute in img tag
        html = '<img src="https://tracker.com/pixel.png">'
        urls = extract_urls(html)
        assert "https://tracker.com/pixel.png" in urls

    def test_iframe_src(self):
        # Extract URL from src attribute in iframe tag
        html = '<iframe src="https://embed.com/content"></iframe>'
        urls = extract_urls(html)
        assert "https://embed.com/content" in urls

    def test_script_src(self):
        # Extract URL from src attribute in script tag
        html = '<script src="https://cdn.com/script.js"></script>'
        urls = extract_urls(html)
        assert "https://cdn.com/script.js" in urls

    def test_form_action(self):
        # Extract URL from action attribute in form tag
        html = '<form action="https://login.com/verify"></form>'
        urls = extract_urls(html)
        assert "https://login.com/verify" in urls

    def test_plain_text_url(self):
        # Extract URL from plain text content
        html = 'Check this out: https://example.com for more info'
        urls = extract_urls(html)
        assert "https://example.com" in urls

    def test_plain_text_www_url(self):
        # Extract www URL from plain text content
        html = 'Visit www.example.com today'
        urls = extract_urls(html)
        assert "www.example.com" in urls

    def test_css_background_url(self):
        # Extract URL from CSS background-image style attribute
        html = '<div style="background-image: url(\'https://bg.com/bg.jpg\')"></div>'
        urls = extract_urls(html)
        assert "https://bg.com/bg.jpg" in urls

    def test_meta_refresh(self):
        # Extract URL from meta refresh redirect
        html = '<meta http-equiv="refresh" content="0; url=https://redirect.com">'
        urls = extract_urls(html)
        assert "https://redirect.com" in urls

    def test_trailing_punctuation_stripped(self):
        # Strip trailing period from URL extracted from plain text
        html = 'Visit https://example.com. for details'
        urls = extract_urls(html)
        assert "https://example.com" in urls
        assert "https://example.com." not in urls

    def test_javascript_filtered(self):
        # Verify javascript: URIs are filtered out
        html = '<a href="javascript:alert(\'xss\')">Click</a>'
        urls = extract_urls(html)
        assert not any(u.startswith('javascript:') for u in urls)

    def test_data_uri_filtered(self):
        # Verify data: URIs are filtered out
        html = '<a href="data:text/html,<script>alert()</script>">Click</a>'
        urls = extract_urls(html)
        assert not any(u.startswith('data:') for u in urls)

    def test_mailto_filtered(self):
        # Verify mailto: URIs are filtered out
        html = '<a href="mailto:attacker@evil.com">Email</a>'
        urls = extract_urls(html)
        assert not any(u.startswith('mailto:') for u in urls)

    def test_tel_filtered(self):
        # Verify tel: URIs are filtered out
        html = '<a href="tel:+1234567890">Call</a>'
        urls = extract_urls(html)
        assert not any(u.startswith('tel:') for u in urls)

    def test_no_duplicates(self):
        # Verify duplicate URLs are deduplicated
        html = '''
        <a href="https://example.com">Link 1</a>
        <a href="https://example.com">Link 2</a>
        https://example.com
        '''
        urls = extract_urls(html)
        count = sum(1 for u in urls if u == "https://example.com")
        assert count == 1

    def test_empty_html(self):
        # Verify empty HTML returns empty URL list
        urls = extract_urls("")
        assert len(urls) == 0

    def test_html_no_urls(self):
        # Verify HTML without URLs returns empty list
        html = "<p>Hello world</p>"
        urls = extract_urls(html)
        assert len(urls) == 0

class TestScoreUrl:
    def test_no_threats(self):
        # Verify URL with no threats scores 0.0
        score = score_url("https://safe.com", [])
        assert score == 0.0

    def test_malware_threat(self):
        # Verify MALWARE threat scores 1.0
        score = score_url("https://evil.com", ["MALWARE"])
        assert score == 1.0

    def test_social_engineering_threat(self):
        # Verify SOCIAL_ENGINEERING threat scores 0.8
        score = score_url("https://phish.com", ["SOCIAL_ENGINEERING"])
        assert score == 0.8

    def test_unwanted_software_threat(self):
        # Verify UNWANTED_SOFTWARE threat scores 0.6
        score = score_url("https://sketchy.com", ["UNWANTED_SOFTWARE"])
        assert score == 0.6

    def test_potentially_harmful_app(self):
        # Verify POTENTIALLY_HARMFUL_APPLICATION threat scores 0.4
        score = score_url("https://app.com", ["POTENTIALLY_HARMFUL_APPLICATION"])
        assert score == 0.4

    def test_multiple_threats_returns_highest(self):
        # Verify multiple threats returns highest score
        threats = ["POTENTIALLY_HARMFUL_APPLICATION", "MALWARE", "UNWANTED_SOFTWARE"]
        score = score_url("https://evil.com", threats)
        assert score == 1.0

    def test_unknown_threat_type(self):
        # Verify unknown threat type defaults to 0.5 score
        score = score_url("https://unknown.com", ["UNKNOWN_THREAT"])
        assert score == 0.5

class TestAnalyzeUrls:
    @patch('analyzers.url.requests.post')
    def test_no_urls_found(self, mock_post):
        # Verify no API call when no URLs found
        email = "From: test@example.com\n\n<p>No links here</p>"
        result, _ = analyze_urls(email)
        assert result == 0.0
        mock_post.assert_not_called()

    @patch('analyzers.url.requests.post')
    def test_safe_urls(self, mock_post):
        # Verify API returns 0.0 score when no threats found
        mock_response = MagicMock()
        mock_response.json.return_value = {"matches": []}
        mock_post.return_value = mock_response

        email = "From: test@example.com\n\n<a href=\"https://safe.com\">Link</a>"
        result, _ = analyze_urls(email)
        assert result == 0.0

    @patch('analyzers.url.requests.post')
    def test_malicious_url(self, mock_post):
        # Verify API returns 1.0 score when MALWARE threat found
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "matches": [
                {
                    "threat": {"url": "https://evil.com"},
                    "threatType": "MALWARE",
                }
            ]
        }
        mock_post.return_value = mock_response

        email = "From: test@example.com\n\n<a href=\"https://evil.com\">Click</a>"
        result, _ = analyze_urls(email)
        assert result == 1.0

    @patch('analyzers.url.requests.post')
    def test_multiple_urls_returns_max_score(self, mock_post):
        # Verify multiple malicious URLs returns highest threat score
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "matches": [
                {"threat": {"url": "https://evil1.com"}, "threatType": "SOCIAL_ENGINEERING"},
                {"threat": {"url": "https://evil2.com"}, "threatType": "MALWARE"},
            ]
        }
        mock_post.return_value = mock_response

        email = "From: test@example.com\n\n<a href=\"https://evil1.com\">Link1</a><a href=\"https://evil2.com\">Link2</a>"
        result, _ = analyze_urls(email)
        assert result == 1.0  # MALWARE score is highest

    @patch('analyzers.url.requests.post')
    def test_signals_returned(self, mock_post):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "matches": [{"threat": {"url": "https://evil.com"}, "threatType": "MALWARE"}]
        }
        mock_post.return_value = mock_response

        email = "From: test@example.com\n\n<a href=\"https://evil.com\">Click</a>"
        _, signals = analyze_urls(email)
        assert "https://evil.com" in signals["malicious_urls"]
        assert signals["total_urls"] >= 1

    @patch('analyzers.url.requests.post')
    def test_api_key_missing(self, mock_post):
        # Verify ValueError raised when API key not in environment
        import os
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="Safe Browsing API key"):
                email = "From: test@example.com\n\n<a href=\"https://example.com\">Link</a>"
                analyze_urls(email)

    @patch('analyzers.url.requests.post')
    def test_api_request_timeout(self, mock_post):
        # Verify Timeout exception propagates when API request times out
        import requests
        mock_post.side_effect = requests.Timeout()

        with pytest.raises(requests.Timeout):
            email = "From: test@example.com\n\n<a href=\"https://example.com\">Link</a>"
            analyze_urls(email)

    @patch('analyzers.url.requests.post')
    def test_api_retry_on_failure(self, mock_post):
        # Verify API retries once on connection error, succeeds on second attempt
        import requests
        mock_response = MagicMock()
        mock_response.json.return_value = {"matches": []}

        # First call fails, second succeeds
        mock_post.side_effect = [requests.ConnectionError(), mock_response]

        email = "From: test@example.com\n\n<a href=\"https://example.com\">Link</a>"
        result, _ = analyze_urls(email)
        assert result == 0.0
        assert mock_post.call_count == 2
