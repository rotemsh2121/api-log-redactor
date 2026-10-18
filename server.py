"""Service mode: POST /redact streams NDJSON in and redacted NDJSON out, GET /healthz reports health."""

import sys

from flask import Flask, Response, request, stream_with_context

from pipeline import redact_lines


def create_app(rules):
    """Build the web app around rules that are already loaded: there is no app without rules."""
    app = Flask(__name__)
    rule_count = len(rules["key_rules"]) + len(rules["value_rules"])

    @app.get("/healthz")
    def healthz():
        # The server only starts after the rules loaded, so answering at all means it is ready.
        return {"status": "ok", "rules": rule_count}

    @app.post("/redact")
    def redact():
        counts = {}
        errors = []

        def generate():
            # Read one line of the request, send one line of the response, and so on:
            # the whole body is never in memory.
            yield from redact_lines(request.stream, rules, counts, errors)
            log_summary(counts, errors)

        return Response(stream_with_context(generate()), mimetype="application/x-ndjson")

    return app


def log_summary(counts, errors):
    """Log one line per request to stderr: counts and line numbers only, never content."""
    redactions = ", ".join(f"{name}={count}" for name, count in sorted(counts.items())) or "none"
    lines = ", ".join(f"{line}:{kind}" for line, kind in errors) or "none"
    print(f"POST /redact redactions: {redactions}; error lines: {lines}", file=sys.stderr)


def parse_addr(addr):
    """Turn ":8080" or "127.0.0.1:8080" into (host, port). Raises ValueError if it is not valid."""
    host, _, port = addr.rpartition(":")
    if not port.isdigit():
        raise ValueError(f"invalid address {addr!r}, expected host:port or :port")
    return host or "0.0.0.0", int(port)


def serve(rules, addr):
    host, port = parse_addr(addr)
    create_app(rules).run(host=host, port=port, threaded=True)
