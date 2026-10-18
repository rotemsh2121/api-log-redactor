import json
import subprocess
import sys

from rules import load_rules
from server import create_app, parse_addr

RULES = load_rules("rules.yaml")


def client():
    """A test client: sends requests to the app without a real network."""
    return create_app(RULES).test_client()


def test_health_reports_ok_and_the_number_of_rules():
    response = client().get("/healthz")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "rules": 10}


def test_redact_returns_redacted_ndjson():
    body = b'{"body":{"email":"a@b.com"}}\nnot json\n{"headers":{"Authorization":"Bearer x"}}\n'
    response = client().post("/redact", data=body)

    assert response.status_code == 200
    assert response.mimetype == "application/x-ndjson"
    lines = [json.loads(line) for line in response.get_data(as_text=True).splitlines()]
    assert lines[0]["body"]["email"].startswith("sha256:")
    assert lines[1] == {"_redactor_error": "invalid_json", "line": 2}
    assert lines[2] == {"headers": {"Authorization": "****"}}


def test_redact_only_accepts_post():
    assert client().get("/redact").status_code == 405


def test_unknown_path_is_not_found():
    assert client().get("/nothing").status_code == 404


def test_parse_addr():
    assert parse_addr(":8080") == ("0.0.0.0", 8080)
    assert parse_addr("127.0.0.1:9000") == ("127.0.0.1", 9000)


def test_service_does_not_start_without_rules(tmp_path):
    # It exits before opening a port, so no traffic can reach it unredacted.
    rules = tmp_path / "rules.yaml"
    rules.write_text("version: 1\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "redactor.py", "--serve", "--rules", str(rules)],
        capture_output=True,
        timeout=30,
    )

    assert result.returncode == 2
    assert b"cannot load rules" in result.stderr
