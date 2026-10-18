# Password Policy Checker

[![CI](https://github.com/AJJudkins/password-policy-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/AJJudkins/password-policy-checker/actions/workflows/ci.yml)

Weak passwords are a common cause of account compromise. This tool checks a list of passwords against a configurable policy (length, character classes, a small bundled common-password list) and gives a rough entropy estimate, so you can see how a policy treats different choices.

> Portfolio project. Uses simulated/sample data only.

## Architecture

```mermaid
flowchart LR
  A[password list file] --> B[checker.py]
  C[common_passwords.txt] --> B
  P[Policy settings] --> B
  B --> D[per-password rule checks]
  B --> E[entropy estimate]
  D --> F[masked report]
  E --> F
```

## Setup

```bash
git clone https://github.com/AJJudkins/password-policy-checker.git
cd password-policy-checker
# Python 3.9+, standard library only
```

## Usage

```bash
python checker.py sample_data/sample_passwords.txt
python checker.py sample_data/sample_passwords.txt --min-length 14 --json
```

## Sample output

```text
#1   ********             len=8   entropy=37.6   FAIL too_short, no_uppercase, no_digit, no_symbol, common_password, low_entropy
#2   **********           len=10  entropy=59.5   FAIL too_short, no_symbol
#3   *******              len=7   entropy=42.8   FAIL too_short, no_uppercase, low_entropy
#4   *********************** len=23  entropy=151.1  PASS 
#5   ******               len=6   entropy=28.2   FAIL too_short, no_uppercase, no_digit, no_symbol, common_password, low_entropy
#6   ********************* len=21  entropy=138.0  PASS 
#7   *******************  len=19  entropy=89.3   FAIL no_uppercase, no_digit, no_symbol

2/7 passed
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

## What this demonstrates

- Policy-as-code with a small dataclass and testable rule functions
- Privacy-minded design: passwords are never printed or logged; output shows only a masked placeholder, length and entropy
- Basic security concepts: complexity rules, common-password blocklists, entropy
- Clean CLI with text and JSON output, and pytest coverage

## Limitations

- All passwords in `sample_data` are fake. Do not feed real passwords to any tool you have not reviewed.
- Masked output still reveals each password's length.
- Entropy is a crude `length x log2(character pool)` upper bound. It overrates predictable patterns like `Summer2024!`; it is not a substitute for a real estimator such as zxcvbn.
- The bundled common-password list has only 14 entries; real use needs a much larger list.
- Does not follow any specific standard (e.g. NIST 800-63B) out of the box.

## Hardening notes
- Never run this on real account passwords. Input can come from a file or from stdin (`-`) so nothing has to be saved to disk; output only shows masked values, lengths and failed rule names.
- `--min-length` is validated, unreadable or empty input exits with code 2, and `--fail-on-weak` returns 1 if any password fails (for CI checks of test fixtures).
- The bundled common-password list is tiny and for demonstration; use a real breached-password list for anything serious. Use an editable install for the console script (`pip install -e .`) so it finds the bundled list.

## Security and testing status

- **Safety:** offline; passwords are never printed, logged or sent anywhere (output is masked); stdin input avoids writing them to disk. Intended for test data only.
- **Tested:** policy rules, entropy estimate, masking, stdin input and exit codes using made-up test passwords.
- **Not tested:** real password databases or breached-password lists, Unicode edge cases, and any use as an actual enforcement control (the entropy estimate is rough).
- See [SECURITY.md](SECURITY.md).

## License

MIT
