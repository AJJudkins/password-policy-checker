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


def test_cli_exit_codes_and_stdin(tmp_path, monkeypatch, capsys):
    import io, sys
    import checker
    f = tmp_path / "p.txt"
    f.write_text("short\n")
    assert checker.main([str(f)]) == 0
    assert checker.main([str(f), "--fail-on-weak"]) == 1
    assert checker.main([str(tmp_path / "missing.txt")]) == 2
    assert checker.main([str(f), "--min-length", "0"]) == 2
    empty = tmp_path / "e.txt"
    empty.write_text("\n")
    assert checker.main([str(empty)]) == 2
    monkeypatch.setattr(sys, "stdin", io.StringIO("Tr0ub4dor&3-horse-battery\n"))
    capsys.readouterr()
    assert checker.main(["-", "--fail-on-weak"]) == 0
    assert "horse" not in capsys.readouterr().out  # passwords are never echoed
