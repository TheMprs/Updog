import os
import re
import requests
from dotenv import load_dotenv

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

# extract URLs from text
def extract_urls(text):
    url_pattern = r'(https?://[^\s]+)'
    urls = re.findall(url_pattern, text)
    return urls

# give each url a score based on the worst threat it matched
def score_url(url, threat_matches):
    # return 0 if no threats matched
    if not threat_matches:
        return 0.0
    # return the highest score among the matched threat types, defaulting to 0.5 for unknown types
    return max(THREAT_TYPE_SCORES.get(t, 0.5) for t in threat_matches)

# analyze URLs using Google Safe Browsing API
def analyze_urls(body):
    api_key = os.getenv('SAFE_BROWSING_API_KEY')
    # check if API key exists
    if not api_key:
        raise ValueError("Safe Browsing API key not found in environment variables.")
    
    urls = extract_urls(body)

    # no urls found - return empty analysis
    if not urls:
        return {"total": 0, "malicious": 0, "score": 0}
    
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
        }
    ).json()
    
    # Build threat map: url -> threat types
    threat_map = {}
    for match in response.get("matches", []):
        url = match["threat"]["url"]
        threat_map.setdefault(url, []).append(match["threatType"])
    
    # Score each URL, return max
    scores = [score_url(url, threat_map.get(url, [])) for url in urls]
    return {
        "total": len(urls),
        "malicious": len(threat_map),
        "score": max(scores) if scores else 0.0,
    }
