"""Redaction and run_with_secret."""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

import pytest

from burndrop import Agent, run_with_secret
from burndrop.agent import RunError
from burndrop.redact import MIN_REDACT_LEN, Redactor

BS = chr(92)
PY = sys.executable


def test_redactor_replaces_value_and_encodings() -> None:
    redactor = Redactor()
    value = b"super-secret-value"
    redactor.add("api-key", value)
    assert len(redactor) == 3, "raw, base64, hex; the other encodings collapse into these"
    forms = {
        "raw": value.decode(),
        "b64": base64.b64encode(value).decode(),
        "b64 unpadded": base64.b64encode(value).decode().rstrip("="),
        "urlsafe": base64.urlsafe_b64encode(value).decode(),
        "hex": value.hex(),
    }
    for label, form in forms.items():
        assert redactor.redact("x " + form + " y") == "x [redacted:api-key] y", label
    assert redactor.redact("token=super-secret-value") == "token=[redacted:api-key]"
    assert redactor.redact_bytes(b"pre" + value + b"post") == b"pre[redacted:api-key]post"
    assert redactor.redact("nothing here") == "nothing here"
    assert redactor.redact("") == ""


def test_redactor_covers_url_and_json_escaping() -> None:
    redactor = Redactor()
    value = 'p@ss w/rd+"<&>"'
    redactor.add("pw", value.encode())
    assert redactor.redact(value) == "[redacted:pw]"
    query = "p%40ss+w%2Frd%2B%22%3C%26%3E%22"
    assert redactor.redact("?v=" + query) == "?v=[redacted:pw]"
    path = "p@ss%20w%2Frd+%22%3C&%3E%22"
    assert redactor.redact("/" + path) == "/[redacted:pw]"
    json_form = "p@ss w/rd+" + BS + '"' + BS + "u003c" + BS + "u0026" + BS + "u003e" + BS + '"'
    assert redactor.redact('{"v":"' + json_form + '"}') == '{"v":"[redacted:pw]"}'


def test_redactor_ignores_short_values_and_trims() -> None:
    redactor = Redactor()
    redactor.add("short", b"v7")
    assert len(redactor) == 0
    assert redactor.redact("v7") == "v7"
    redactor.add("padded", b"  padded-value \n")
    assert redactor.redact("x padded-value y") == "x [redacted:padded] y"
    assert MIN_REDACT_LEN == 6


def test_redactor_prefers_longest_form_and_forgets_by_name() -> None:
    redactor = Redactor()
    redactor.add("one", b"abcdefgh")
    redactor.add("two", b"abcdefghijkl")
    assert redactor.redact("abcdefghijkl") == "[redacted:two]"
    assert redactor.redact("abcdefgh") == "[redacted:one]"
    redactor.remove("two")
    assert redactor.redact("abcdefghijkl") == "[redacted:one]ijkl"
    redactor.remove("one")
    assert redactor.redact("abcdefghijkl") == "abcdefghijkl"
    assert len(redactor) == 0


def test_redactor_handles_binary_values() -> None:
    redactor = Redactor()
    value = b"\x00\x01\x02\xff\xfe\xfd\xfc"
    redactor.add("bin", value)
    assert redactor.redact_bytes(b"<" + value + b">") == b"<[redacted:bin]>"
    assert redactor.redact(base64.b64encode(value).decode()) == "[redacted:bin]"
    assert redactor.redact("pässwörd") == "pässwörd"
    redactor.add("uni", "pässwörd".encode())
    assert redactor.redact("x pässwörd y") == "x [redacted:uni] y"


def script(code: str) -> list[str]:
    return [PY, "-c", code]


def test_run_with_secret_injects_and_redacts() -> None:
    result = run_with_secret(
        script(
            "import os, sys; print('key=' + os.environ['API_KEY']); "
            "print('err=' + os.environ['API_KEY'], file=sys.stderr)"
        ),
        {"API_KEY": b"super-secret-value"},
    )
    assert result.exit_code == 0
    assert "key=[redacted:API_KEY]" in result.stdout
    assert "err=[redacted:API_KEY]" in result.stderr
    assert "super-secret" not in result.stdout + result.stderr
    assert not result.timed_out
    assert not result.truncated
    assert result.duration_ms >= 0


def test_run_with_secret_redacts_encoded_forms_and_accepts_str() -> None:
    result = run_with_secret(
        script(
            "import base64, os; v = os.environ['API_KEY'].encode(); "
            "print(base64.b64encode(v).decode()); print(v.hex())"
        ),
        {"API_KEY": "super-secret-value"},
    )
    b64 = base64.b64encode(b"super-secret-value").decode()
    assert b64 not in result.stdout
    assert b"super-secret-value".hex() not in result.stdout
    assert result.stdout.count("[redacted:API_KEY]") == 2


def test_run_with_secret_exit_code_and_discard() -> None:
    result = run_with_secret(script("raise SystemExit(3)"), {}, discard_output=True)
    assert result.exit_code == 3
    assert result.stdout == ""
    assert result.stderr == ""


def test_run_with_secret_truncates() -> None:
    result = run_with_secret(script("print('a' * 200)"), {}, max_output_bytes=50)
    assert result.truncated
    assert result.stdout.endswith("[truncated]")
    assert len(result.stdout) <= 70


def test_run_with_secret_times_out() -> None:
    result = run_with_secret(script("import time; time.sleep(10)"), {}, timeout=1)
    assert result.timed_out
    assert result.exit_code == -1


def test_run_with_secret_validation() -> None:
    with pytest.raises(ValueError, match="program name"):
        run_with_secret([], {})
    with pytest.raises(ValueError, match="program name"):
        run_with_secret(["  "], {})
    with pytest.raises(ValueError, match="environment variable"):
        run_with_secret(script("pass"), {"1BAD": b"value-value"})
    with pytest.raises(ValueError, match="environment variable"):
        run_with_secret(script("pass"), {"A=B": b"value-value"})
    with pytest.raises(RunError) as excinfo:
        run_with_secret(["definitely-not-a-program-xyz-burndrop"], {"K": b"hidden-value-1"})
    assert "hidden-value" not in str(excinfo.value)


def test_run_with_secret_cwd_and_stdin(tmp_path: Path) -> None:
    result = run_with_secret(script("import os; print(os.getcwd())"), {}, cwd=tmp_path)
    assert tmp_path.name in result.stdout
    result = run_with_secret(
        script("import sys; print('got ' + sys.stdin.read())"), {}, stdin="from stdin"
    )
    assert "got from stdin" in result.stdout
    result = run_with_secret(script("import sys; print(sys.stdin.read())"), {}, stdin=b"raw")
    assert "raw" in result.stdout


def test_run_with_secret_does_not_leak_into_parent_environment() -> None:
    run_with_secret(script("pass"), {"BURNDROP_TEST_LEAK": b"leaked-value"})
    assert "BURNDROP_TEST_LEAK" not in os.environ


def test_agent_run_with_secret_uses_learned_values() -> None:
    agent = Agent("https://relay.example")
    agent.redactor.add("api-key", b"learned-value-123")
    result = agent.run_with_secret(
        script("import os; print(os.environ['A']); print(os.environ['B'])"),
        {"A": b"learned-value-123", "B": b"injected-value-456"},
    )
    assert "learned-value" not in result.stdout
    assert "injected-value" not in result.stdout
    assert "[redacted:api-key]" in result.stdout
    assert "[redacted:B]" in result.stdout
