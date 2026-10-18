import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import checker as c


def test_entropy_grows_with_length_and_pool():
    assert c.estimate_entropy("abc") < c.estimate_entropy("abcdef")
    assert c.estimate_entropy("abcdef") < c.estimate_entropy("aBcD1!")
    assert c.estimate_entropy("") == 0.0


def test_common_password_flagged():
    r = c.audit(["password"], common={"password"})[0]
    assert not r["passed"] and "common_password" in r["failures"]


def test_strong_password_passes():
    r = c.audit(["T3st-Only-Fake#Pass99"], common=c.load_common())[0]
    assert r["passed"], r["failures"]


def test_missing_classes_reported():
    f = c.check_password("alllowercaseletters", c.Policy(), set())
    assert {"no_uppercase", "no_digit", "no_symbol"} <= set(f)


def test_report_never_contains_password():
    r = c.audit(["Sup3r-Secret-Fake!"], common=set())[0]
    assert "Sup3r" not in str(r)
