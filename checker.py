"""Password policy checker: evaluates sample passwords against a policy.

Passwords are never printed or logged; reports show a masked form and a
short SHA-256 fingerprint-free identifier (row number) instead.
"""
import argparse
import json
import math
import string
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).parent
COMMON_FILE = HERE / "sample_data" / "common_passwords.txt"


@dataclass
class Policy:
    min_length: int = 12
    require_upper: bool = True
    require_lower: bool = True
    require_digit: bool = True
    require_symbol: bool = True
    min_entropy_bits: float = 50.0


def load_common(path=COMMON_FILE):
    return {l.strip().lower() for l in Path(path).read_text().splitlines() if l.strip()}


def estimate_entropy(password: str) -> float:
    """Rough upper-bound entropy: length * log2(character pool size)."""
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation or c == " " for c in password):
        pool += 33
    if pool == 0:
        return 0.0
    return round(len(password) * math.log2(pool), 1)


def check_password(password: str, policy: Policy, common: set) -> list:
    """Return a list of failed-rule names (empty list means it passes)."""
    problems = []
    if len(password) < policy.min_length:
        problems.append("too_short")
    if policy.require_upper and not any(c.isupper() for c in password):
        problems.append("no_uppercase")
    if policy.require_lower and not any(c.islower() for c in password):
        problems.append("no_lowercase")
    if policy.require_digit and not any(c.isdigit() for c in password):
        problems.append("no_digit")
    if policy.require_symbol and not any(c in string.punctuation for c in password):
        problems.append("no_symbol")
    if password.lower() in common:
        problems.append("common_password")
    if estimate_entropy(password) < policy.min_entropy_bits:
        problems.append("low_entropy")
    return problems


def mask(password: str) -> str:
    return "*" * len(password)


def audit(passwords, policy=None, common=None):
    policy = policy or Policy()
    common = common if common is not None else load_common()
    results = []
    for i, pw in enumerate(passwords, 1):
        problems = check_password(pw, policy, common)
        results.append({
            "id": i,
            "masked": mask(pw),
            "length": len(pw),
            "entropy_bits": estimate_entropy(pw),
            "passed": not problems,
            "failures": problems,
        })
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check sample passwords against a policy.")
    ap.add_argument("file", help="text file with one TEST password per line, or - for stdin "
                                 "(never use real account passwords)")
    ap.add_argument("--min-length", type=int, default=12)
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--fail-on-weak", action="store_true", help="exit 1 if any password fails the policy")
    args = ap.parse_args(argv)
    if not 1 <= args.min_length <= 256:
        print("error: --min-length must be between 1 and 256", file=sys.stderr)
        return 2
    try:
        text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text()
    except (OSError, UnicodeDecodeError) as e:
        print(f"error: cannot read {args.file}: {e}", file=sys.stderr)
        return 2
    pws = [l.rstrip("\n") for l in text.splitlines() if l.strip()]
    if not pws:
        print("error: no passwords found in input", file=sys.stderr)
        return 2
    results = audit(pws, Policy(min_length=args.min_length))
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            status = "PASS" if r["passed"] else "FAIL"
            print(f"#{r['id']:<3} {r['masked']:<20} len={r['length']:<3} "
                  f"entropy={r['entropy_bits']:<6} {status} {', '.join(r['failures'])}")
        passed = sum(r["passed"] for r in results)
        print(f"\n{passed}/{len(results)} passed")
    return 1 if (args.fail_on_weak and not all(r["passed"] for r in results)) else 0


if __name__ == "__main__":
    sys.exit(main())
