"""The conformance runner's scoring, against stand-in implementations."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

from conftest import SPEC_DIR

ONLY = "replay: one mailbox, its alias, and a second mailbox"


def _runner() -> ModuleType:
    name = "colophon_conformance_run"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SPEC_DIR / "conformance" / "run.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look their module up while the class is built
    spec.loader.exec_module(module)
    return module


def _stand_in(tmp_path: Path, deliveries: list[dict[str, object]]) -> list[str]:
    """A command that ignores its input and answers ``deliveries``."""
    answer = tmp_path / "answer.json"
    answer.write_text(json.dumps({"deliveries": deliveries}))
    script = tmp_path / "stand_in.py"
    script.write_text(
        f"import sys\nsys.stdin.read()\nsys.stdout.write(open({str(answer)!r}).read())\n"
    )
    return [sys.executable, str(script)]


def _run(capsys: pytest.CaptureFixture[str], command: list[str]) -> tuple[int, list[str]]:
    code = _runner().main(["--only", ONLY, "--", *command])
    return code, capsys.readouterr().out.splitlines()


def _answer(verdict: str, resinfo: object = ...) -> dict[str, object]:
    out: dict[str, object] = (
        {"verdict": "verified"}
        if verdict == "verified"
        else {"verdict": "not_verified", "reason": verdict}
    )
    if resinfo is not ...:
        out["authentication_results"] = resinfo
    return out


def _expected() -> list[str]:
    doc = json.loads((SPEC_DIR / "reference" / "vectors.json").read_text())
    (case,) = [c for c in doc["cases"] if c["name"] == ONLY]
    assert [d["expected"] for d in case["deliveries"]] == OUTCOMES
    return [d["expected_authentication_results"] for d in case["deliveries"]]


OUTCOMES = ["verified", "replay", "replay", "verified"]


def test_a_missing_resinfo_is_not_checked(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out = _run(capsys, _stand_in(tmp_path, [_answer(o) for o in OUTCOMES]))
    assert code == 0
    assert out[-2:] == [
        "4/4 deliveries pass (1 vectors)",
        "Authentication-Results resinfo: not checked (the implementation reported none)",
    ]


def test_resinfo_is_compared_exactly(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    expected = _expected()
    answers = [_answer(o, r) for o, r in zip(OUTCOMES, expected, strict=True)]
    answers[1] = _answer("replay", "colophon=fail reason=replay")  # unquoted: not the same text
    answers[3] = _answer("verified")
    code, out = _run(capsys, _stand_in(tmp_path, answers))
    assert code == 1
    assert f"        want {expected[1]}" in out
    assert out[-2:] == [
        "4/4 deliveries pass (1 vectors)",
        "2/3 Authentication-Results resinfo match, 1 not checked",
    ]

    answers = [_answer(o, r) for o, r in zip(OUTCOMES, expected, strict=True)]
    code, out = _run(capsys, _stand_in(tmp_path, answers))
    assert code == 0
    assert out[-1] == "4/4 Authentication-Results resinfo match"


def test_a_resinfo_that_is_not_a_string_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = [_answer(o) for o in OUTCOMES]
    answers[0] = _answer("verified", None)
    code, out = _run(capsys, _stand_in(tmp_path, answers))
    assert code == 1
    assert out[-1] == "0/1 Authentication-Results resinfo match, 3 not checked"
