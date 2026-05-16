import sys
from pathlib import Path
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from scorer import analyze

EMAIL_DIR = Path(r"C:\Users\nisim\Downloads\phishing_pot-main\phishing_pot-main\email")

# Flags we want to showcase
WANT = [
    "malicious_urls",
    "display_name_spoof",
    "typosquat_detected",
    "cloaking_detected",
    "mime_mismatch",
    "encrypted_archive",
    "risky_extension",
    "pdf_active_content",
    "large_money_amount",
    "caps_abuse",
    "domain_recent_breach",
    "forwarded_inner_sender",
    "suspicious_tld",
    "undisclosed_recipients",
]

# One representative per flag, plus a clean safe email
found = {}   # flag -> (score, verdict, filename, bullets, signals)
safe_pick = None

files = sorted(EMAIL_DIR.glob("*.eml"))

def flat_signals(result):
    s = {}
    for v in result.get("signals", {}).values():
        s.update(v)
    return s

for path in files:
    if len(found) == len(WANT) and safe_pick:
        break
    try:
        raw = path.read_bytes().decode("utf-8", errors="replace")
        result = analyze(raw)
        score = result["score"]
        sig = flat_signals(result)

        if safe_pick is None and score == 0 and not result["bullets"]:
            safe_pick = (score, result["verdict"], path.name, result["bullets"], sig)

        for flag in WANT:
            if flag in found:
                continue
            val = sig.get(flag)
            fired = bool(val) if not isinstance(val, list) else len(val) > 0
            if fired:
                found[flag] = (score, result["verdict"], path.name, result["bullets"], sig)

    except Exception as e:
        print(f"ERROR {path.name}: {e}", flush=True)

def safe_str(s):
    return s.encode("ascii", errors="replace").decode("ascii")

print("\n" + "="*60)
print("DEMO EMAIL CANDIDATES")
print("="*60)

all_picks = list(found.items())
if safe_pick:
    all_picks.append(("SAFE (no signals)", safe_pick))

for flag, (score, verdict, name, bullets, sig) in all_picks:
    print(f"\n  [{flag}]")
    print(f"  File    : {name}")
    print(f"  Score   : {score} ({verdict})")
    key_sigs = {k: v for k, v in sig.items() if v not in (False, None, [], "", 0)}
    print(f"  Signals : {key_sigs}")
    print(f"  Bullets :")
    for b in bullets:
        print(f"    {safe_str(b)}")
    if not bullets:
        print(f"    (none)")
