"""End-to-end tests: run redactor.py as a real program, like a user would."""

import json
import subprocess
import sys


def run(*args, input=None):
    """Run `py redactor.py <args>` and return the finished process (exit code, stdout, stderr)."""
    return subprocess.run(
        [sys.executable, "redactor.py", *args],
        input=input,
        capture_output=True,
    )


def test_redacts_the_sample_file():
    result = run("--rules", "rules.yaml", "testdata/input.ndjson")

    assert result.returncode == 0
    lines = result.stdout.decode("utf-8").splitlines()
    assert len(lines) == 48  # 50 input lines minus 2 blank ones.
    for line in lines:
        json.loads(line)  # Every output line is valid JSON.
    # Secrets from the sample that the provided rules cover (line numbers in the input file):
    assert b"4111111111111111" not in result.stdout   # many lines
    assert b"p@ssw0rd!" not in result.stdout          # line 10, JSON inside a string
    assert b"alice@example.com" not in result.stdout  # line 3, deep inside arrays
    assert b"sk_live_" not in result.stdout           # lines 1, 9 and 42
    assert b"hunter2" not in result.stdout            # line 8 (form) and line 41 (free text)


def test_summary_goes_to_stderr_without_sensitive_data():
    result = run("testdata/input.ndjson")
    stderr = result.stderr.decode("utf-8")

    assert "email:" in stderr
    assert "line 21: invalid_json" in stderr
    # Line 21 contains erin@example.com: the problem is reported, the data is not.
    assert "erin" not in stderr


def test_reads_stdin_when_no_file_is_given():
    result = run(input=b'{"body":{"email":"a@b.com"}}\n')

    assert result.returncode == 0
    assert b"a@b.com" not in result.stdout
    assert b"sha256:" in result.stdout


def test_bad_rules_file_passes_nothing_through(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("version: 1\n", encoding="utf-8")

    result = run("--rules", str(rules), input=b'{"body":{"email":"a@b.com"}}\n')

    assert result.returncode == 2
    assert result.stdout == b""  # Not a single unredacted line.
    assert b"cannot load rules" in result.stderr


def test_running_on_its_own_output_changes_nothing():
    # The idempotency requirement, on the whole sample file.
    first = run("testdata/input.ndjson")
    second = run(input=first.stdout)

    assert second.stdout == first.stdout
