import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from scorer import analyze

args = sys.argv[1:]
debug = "--debug" in args
file_args = [a for a in args if not a.startswith("--")]


def score_file(path: Path):
    email = path.read_text(encoding="utf-8", errors="replace")
    result = analyze(email)
    print(f"\n{'='*50}")
    print(f"File:    {path.name}")
    print(f"Score:   {result['score']} — {result['verdict']} ({result['color']})")
    if result["bullets"]:
        print()
        for b in result["bullets"]:
            print(f"  {b}")
    if debug:
        print(f"\n--- Breakdown ---")
        for analyzer, score in result["breakdown"].items():
            print(f"\n  {analyzer.upper()}  {score:.2f}")
            for key, val in result["signals"][analyzer].items():
                print(f"    {key}: {val}")


if file_args:
    target = Path(file_args[0])
    if target.is_dir():
        files = sorted(target.glob("*.eml"))
        if not files:
            print(f"No .eml files found in {target}")
            sys.exit(1)
        for f in files:
            score_file(f)
    else:
        score_file(target)
else:
    email = sys.stdin.read()
    result = analyze(email)
    print(f"Score:   {result['score']} — {result['verdict']} ({result['color']})")
    if result["bullets"]:
        print()
        for b in result["bullets"]:
            print(f"  {b}")
    if debug:
        print(f"\n--- Breakdown ---")
        for analyzer, score in result["breakdown"].items():
            print(f"\n  {analyzer.upper()}  {score:.2f}")
            for key, val in result["signals"][analyzer].items():
                print(f"    {key}: {val}")
