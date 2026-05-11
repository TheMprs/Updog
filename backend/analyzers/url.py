import os
import re
import requests
from dotenv import load_dotenv

# tests conducted on url.py:
# 1. test url against google's safe browsing API

load_dotenv() # load .env file

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION"
]

THREAT_TYPE_SCORES = {
    "MALWARE": 1.0,
    "SOCIAL_ENGINEERING": 0.8,
    "UNWANTED_SOFTWARE": 0.6,
    "POTENTIALLY_HARMFUL_APPLICATION": 0.4
}

def extract_urls(text):
    """
    Extract URLs from the given text using regex.
    """
    url_pattern = r'(https?://[^\s]+)'
    urls = re.findall(url_pattern, text)
    # remove trailing punctuation from URLs (example.com? -> example.com)
    return [url.rstrip('.,;:!?)"\'}') for url in urls]

def score_url(url, threat_matches):
    """
    Give a URL a score based on the threat types it matched.
    Returns a score between 0.0 (safe) and 1.0 (malicious)
    If no threats matched, returns 0.0.
    If multiple threats matched, returns the highest score among them.
    """
    # return 0 if no threats matched
    if not threat_matches:
        return 0.0
    # return the highest score among the matched threat types, defaulting to 0.5 for unknown types
    return max(THREAT_TYPE_SCORES.get(t, 0.5) for t in threat_matches)

def analyze_urls(body):
    """ 
    Analyze URLs in the email body using Google Safe Browsing API.
    Returns a score between 0.0 (safe) and 1.0 (malicious) based on the most dangerous URL found.
    If no URLs are found, returns 0.0.
    """
    api_key = os.getenv('SAFE_BROWSING_API_KEY')
    # check if API key exists
    if not api_key:
        raise ValueError("Safe Browsing API key not found in environment variables.")
    
    urls = extract_urls(body)

    # no urls found - return empty analysis
    if not urls:
        return 0
    
    # retry request in case of network issues
    for attempt in range(2):
        try:
            response = requests.post(
                'https://safebrowsing.googleapis.com/v4/threatMatches:find',
                params={'key': api_key},
                json={
                    "client": {
                        "clientId": "email-extension",
                        "clientVersion": "1.0"
                    },
                    "threatInfo": {
                        "threatTypes": THREAT_TYPES,
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url} for url in urls]
                    }
                },
                timeout=10
            )
            response.raise_for_status()  # check for bad HTTP status
            data = response.json() # transform into json object
            break  # Success, exit retry loop
        except (requests.Timeout, requests.ConnectionError, requests.RequestException) as e:
            if attempt == 1:  # were on the 2nd try, give up
                raise
            continue

    # Build threat map: url -> threat types
    threat_map = {}
    for match in data.get("matches", []):
        url = match["threat"]["url"]
        threat_map.setdefault(url, []).append(match["threatType"])
    
    # Score each URL, return max
    scores = [score_url(url, threat_map.get(url, [])) for url in urls]
    return max(scores) if scores else 0.0
