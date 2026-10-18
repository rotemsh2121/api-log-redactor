# API Traffic Log Redactor

A command line tool that reads API traffic logs as NDJSON (one HTTP transaction per line), redacts
sensitive data according to a YAML rules file, and writes the same NDJSON with the sensitive parts
masked, partially masked, hashed or removed.

**Language:** Python 3.11+. Go is new to me

## 1. Build, run and test

```bash
pip install -r requirements-dev.txt
```

`requirements.txt` has what the tool needs to run: PyYAML (reading the rules) and Flask (service mode).
`requirements-dev.txt` adds pytest for the tests. On Windows, use `py` in place of `python` below.

### CLI

```bash
python redactor.py [--rules rules.yaml] [input-file]
```

- Reads `input-file`, or stdin if no file is given.
- Writes the redacted NDJSON to **stdout**.
- Writes a summary to **stderr**: redactions per rule, and the numbers of lines that could not be
  processed.

```bash
python redactor.py --rules rules.yaml testdata/input.ndjson > redacted.ndjson
cat testdata/input.ndjson | python redactor.py
```

Example summary for the sample file:

```
redactions per rule:
  auth-headers: 9
  api-key-names: 8
  ...
lines replaced by an error record: 3
  line 20: invalid_json
  line 21: invalid_json
  line 50: invalid_json
```

Exit codes: `0` when the input was processed (even if some lines were replaced by error records),
`2` when the rules file or the input file cannot be opened or loaded. In that case nothing is written
to stdout.

### Service mode

```bash
python redactor.py --serve --addr :8080 --rules rules.yaml
```

```bash
curl -s localhost:8080/healthz
curl -s --data-binary @testdata/input.ndjson localhost:8080/redact
curl -s -X POST -T - localhost:8080/redact < testdata/input.ndjson   # upload from stdin, sent chunked
```

- **`POST /redact`:** the request body is NDJSON, the response is redacted NDJSON
  (`application/x-ndjson`). It streams: each line is read from the request, redacted and sent in the
  response before the next line is read, so the body is never held in memory. Lines that cannot be
  processed become error records, exactly like in the CLI. Each request logs one summary line to stderr:
  counts per rule and error line numbers, no content.
- **`GET /healthz`:** `200 {"status":"ok","rules":10}`. The rules are loaded **before** the server opens
  its port, so if it answers at all, the rules are loaded and it is ready for traffic. The rule count
  helps to check that the right file was loaded. Kubernetes uses it for both the readiness and the
  liveness probe. If hot reloading of rules were added, readiness would need its own check.
- **If the rules cannot be loaded, the service does not start:** it exits with code 2 before listening,
  so there is nothing to send traffic to. In Kubernetes the pod never becomes ready and gets no traffic.

### Tests

```bash
python -m pytest -v
```

| File | What it tests |
|---|---|
| `test_rules.py` | Loading and validating the rules file |
| `test_actions.py` | mask, partial, hash and remove |
| `test_validators.py` | The Luhn check |
| `test_engine.py` | Redaction of strings and whole records: recursion, scopes, string bodies, the JWT and card fixes |
| `test_pipeline.py` | Raw lines and streams: bad JSON, bad UTF-8, deep nesting, long lines |
| `test_cli.py` | The real program end to end, including idempotency over the whole sample file |
| `test_server.py` | `/redact`, `/healthz`, and that the service does not start without valid rules |

### Code layout

| File | Responsibility |
|---|---|
| `rules.py` | Load `rules.yaml`, validate it, compile the regexes once |
| `actions.py` | The four actions |
| `validators.py` | Luhn |
| `engine.py` | Redact one parsed record: recursion, key rules, value rules, string bodies |
| `pipeline.py` | Raw bytes in, redacted lines out: decoding, error records, streaming |
| `redactor.py` | Command line arguments and the stderr summary |
| `server.py` | Service mode (Flask): `/redact` and `/healthz` |

## 2. Design decisions and trade-offs

### Streaming

The input is read **one line at a time** (`readline`) and every line is written out as soon as it is
redacted, so the whole input is never in memory. A single line is limited to 10 MB: a longer line is
replaced by a `line_too_long` error record and skipped in chunks, so even a huge file with no
newlines cannot exhaust memory.

- **Memory:** O(L), where L is the longest line (at most 10 MB), independent of the input size.
- **Time:** O(N × R), where N is the size of the input and R the number of rules: every string is
  scanned once per value rule, and every key is compared with every key rule.

### Recursion

Each line is parsed with `json.loads` and walked recursively: objects and arrays are opened, strings
go through the value rules, and numbers, booleans and null are kept. A recursive walk is the simplest
way to reach every depth (for example the email in `orders[1].items[0][0].deep[0]` on line 3).

The **scope** of a key rule (`headers`, `body` or `any`) is decided at the top of the record: everything
inside `headers` or `body` (also inside `response`) has that scope, however deep it is. Top-level fields
such as `ts`, `method` and `path` belong to neither, so only `any` key rules and value rules apply to
them.

### Rule matching

- **Key rules are checked first**, in file order, and the first match wins. `exact` names are compared
  case-insensitively (header names are case-insensitive: line 14 has `AUTHORIZATION`).
- When a key rule matches, it replaces **the whole value** and the value rules do not run on it. A list
  or an object under a matching key is redacted item by item, so its shape is kept. `null` and `""` are
  kept, since there is nothing to hide. A number becomes a string (a card number stored as a JSON number
  becomes `"************1111"`). `remove` drops the key.
- **Value rules** run in file order on every other string. Each finds its regex anywhere in the text and
  replaces only the match, so the rest of a sentence is kept. With `validator: luhn`, a match that fails
  the Luhn check is left as it is (an order number is not a card number).
- Rules run one after another, so a later rule sees the output of an earlier one. This is safe because
  what the actions write cannot match another rule: a hash is `sha256:` plus lowercase hex (no `@`,
  no `eyJ`, no `sk_`, no free-standing run of 13 digits), and a mask is `****`.
- Only real changes are counted, so running the tool on its own output reports zero redactions.

### The actions

- `mask` writes the replacement from `settings` (`****`).
- `partial` keeps the last 4 characters and replaces every other character with `*`, so the length is
  kept (`************1111`, the same format as the already redacted line 12). A value of 4 characters or
  fewer is masked completely, because "keep the last 4" would reveal all of it.
- `hash` writes `sha256:<hex digest>`. The prefix makes it idempotent: a value that is exactly a hash we
  wrote is not hashed again. The check uses the whole value (`fullmatch`), so a secret placed after a
  real-looking hash is still hashed.
- `remove` drops the key (key rules) or deletes the matched text (value rules).

### String bodies

When `body` is a string, it may still have structure:

- **Form** (`Content-Type: application/x-www-form-urlencoded`, line 8): split into fields, which are
  URL-decoded (`%40` becomes `@`) and redacted like JSON keys, then encoded again. The form is
  recognised by its Content-Type and not by guessing, because free text such as
  `password=hunter2 for user=zed` (line 41) would be mistaken for a form.
- **JSON inside a string** (lines 10 and 11): if it starts with `{` or `[` and parses, it is redacted
  like any JSON body and written back as a string. If it does not parse, it is treated as text.
- **Anything else** is plain text and gets the value rules.

A body that needs no redaction is returned exactly as it was, keeping its formatting.

### Failure handling

A line that cannot be processed safely is replaced by an **error record** with no original content:

```json
{"_redactor_error":"invalid_json","line":21}
```

Passing the line through would leak data (line 21 is a plain log line with an email in it, line 20 is
cut in the middle of a JWT). Dropping it silently would lose the fact that something was there. An
error record keeps the output valid NDJSON, keeps the line's place in the output, and can be searched for.

| Kind | When |
|---|---|
| `invalid_json` | The line is not valid JSON |
| `invalid_utf8` | The bytes are not valid UTF-8 |
| `too_deep` | Nesting deeper than Python's recursion limit (about 1000 levels) |
| `line_too_long` | Longer than 10 MB |
| `internal_error` | Any unexpected error while redacting: a bug never lets the original line through |

Blank lines carry no data and are skipped. **stderr only ever gets line numbers and error kinds**, never
line content or exception messages, which can quote the input.

The rules are loaded and validated **before any input is read**. If they cannot be loaded, the tool exits
with code 2 and writes nothing to stdout. Validation rejects a missing file, invalid YAML, unknown
actions, scopes or validators, invalid regexes, and a file with no rules at all (which would let all
traffic through).

### Idempotency

Running the tool on its own output gives identical output (tested on the whole sample file):
`****` stays `****`, a length-preserving `partial` is unchanged, hashes carry a prefix, error records are
valid JSON, blank lines are already gone, and unchanged bodies keep their original text.

### Changes to `rules.yaml`

The format is unchanged. The rules themselves have three changes, each in its own commit with tests:

1. **`jwt`:** fixed to match base64url (see section 3).
2. **`credit-card`:** also matches numbers printed in groups, `4111 1111 1111 1111` or
   `5555-5555-5555-4444` (4-4-4-4) and `3782 822463 10005` (Amex, 4-6-5), which leaked on lines 1, 6,
   36 and 44. Separators are allowed only in these groupings: a looser "any single space or dash between
   digits" pattern read `qty 12 4111111111111111` as one 18-digit number, which fails Luhn, and the card
   leaked. `[0-9]` is used instead of `\d`, which in Python also matches non-Latin digits.
3. **`credentials-in-text`** (new): `password=...`, `token=...` and similar inside free text or a URL
   (`login attempt password=hunter2`, line 41; `/v1/reset?token=...`, line 30), where no key rule can
   see them.

## 3. The JWT report

> Users reported that the provided `rules.yaml` misses some JWTs seen in production samples.

**What I found:** the `jwt` pattern was written for standard base64 (`[A-Za-z0-9+/=]`), but the three
parts of a JWT are **base64url**, which uses `-` and `_` instead of `+` and `/`, and no `=` padding. Any
token with `-` or `_` in it, which is most of them, was handled wrongly in one of two ways:

- **`_` in the signature** (line 1): the match stopped at the `_`, so the token was only partly masked:
  `Bearer ****_adQssw5c`. This is the worse case, because the output looks redacted.
- **`_` in the payload** (lines 11 and 16, `eyJhIjoiPz8_In0`): the pattern could not reach the second
  dot, so the token was not matched at all and passed through whole.

**What I did:** I wrote two failing tests with tokens from the sample, then changed the character class
to `[A-Za-z0-9_-]`:

```yaml
pattern: 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
```

The third part stays optional (`*`), because an unsigned token (`"alg": "none"`) ends with a dot. The fix
is in the rules file, not in the code.

While checking the rest of the sample I found two more gaps in the provided rules, fixed the same way
(see "Changes to `rules.yaml`" above): card numbers with spaces or dashes, and `password=` in free text.

## 4. Deployment files

```bash
docker build -t redactor:1.0.0 .
docker run --rm -p 8080:8080 redactor:1.0.0

kubectl create configmap redactor-rules --from-file=rules.yaml
kubectl apply -f k8s/
```

I did not have Docker or a cluster on my machine, so these files are written carefully but **not tested**.

**`Dockerfile`**

- `python:3.12-slim`: the official image without compilers and extra tools, so it is smaller and has less
  that could be attacked.
- `requirements.txt` is copied and installed before the code, so a code change reuses the cached
  dependency layer. Only runtime dependencies are installed (no pytest), and `.dockerignore` keeps tests,
  sample data and `.git` out of the image.
- Runs as a non-root user (`USER 10001`): the service handles sensitive data and needs no privileges.
- The provided `rules.yaml` is copied to `/etc/redactor/rules.yaml` as a default, so the image also
  works on its own with `docker run`.

**`k8s/deployment.yaml` and `k8s/service.yaml`**

- **ConfigMap for the rules:** created from `rules.yaml` and mounted over `/etc/redactor`, so rules
  change without rebuilding the image. Rules are read at startup, so after changing them:
  `kubectl rollout restart deployment/redactor`.
- **2 replicas,** so one pod can restart or be updated while the other serves.
- **Readiness and liveness probes** on `/healthz`: Kubernetes only routes traffic to pods that answer,
  and restarts pods that stop answering. A pod whose rules fail to load exits and never answers.
- **Resource requests and limits,** so the scheduler knows what the pod needs and one pod cannot take
  the whole node. Memory use is bounded by design (one line at a time, at most 10 MB per line).
- **Locked-down security context:** non-root, no privilege escalation, read-only filesystem, all Linux
  capabilities dropped.
- **`ClusterIP` Service:** a stable in-cluster address (`http://redactor`) in front of the pods,
  reachable only from inside the cluster.

## 5. Known limitations and what I would do with more time

- **Hashes are not keyed.** An unsalted SHA-256 of an email can be reversed by hashing a list of likely
  emails and comparing. I would use HMAC-SHA-256 with a secret key (from a Kubernetes Secret), which keeps
  hashes stable for correlation but makes guessing impossible without the key. Only `sha256` is
  supported, and the `hash.algorithm` setting is not read.
- **Card edge case:** a group of 4 digits right before a grouped card (`2024 4111 1111 1111 1111`) is read
  as a 16-digit number, fails Luhn, and the real card is not found. Fixing it means trying several
  windows over a run of digit groups.
- **Luhn passes about 1 in 10 random numbers,** so some long numbers that are not cards are redacted. A
  check of known card prefixes would reduce this.
- **Free text without a clear marker** (`my password is hunter2`) is not detected. URL-encoded values in a
  path (`email=gina%40example.com` on line 30) are not decoded, so that email is not found.
- A form body **without a Content-Type** is treated as plain text.
- `mask` in `credentials-in-text` also hides the name (`****` instead of `password=****`). Keeping it
  needs regex groups in the rule format.
- **JSON is re-serialized,** so its formatting is normalized: `10.50` becomes `10.5` and `1e3` becomes
  `1000.0`. Large integers are kept exactly. With duplicate keys (line 25) only the last one is kept.
- Only `body` strings are checked for embedded JSON or forms, not every string.
- **Nesting deeper than about 1000 levels** becomes a `too_deep` error record. An iterative walk with an
  explicit stack would remove the limit.
- **Single threaded.** For more throughput I would process lines in parallel worker processes (the GIL
  stops threads from helping with CPU-bound work) and keep the output order with sequence numbers.
- **The service uses Flask's built-in server**, which is meant for development. In production I would run
  the same app under a WSGI server such as gunicorn (one that streams request bodies), and add a maximum
  request size and timeouts.

## 6. Inline on live traffic with a sub-millisecond budget

First, I would keep users from waiting for redaction at all: let the request go through as usual, send a
copy of it to a queue, and redact the copies before they are stored. If it really has to be inline, the
code should run inside the proxy that already handles the request, not as a separate service, because a
network call to another service can use up the whole budget by itself. Second, I would do less work per
request: combine all the value patterns into one regex so each string is scanned once instead of once per
rule, and run a cheap check before each expensive one (no `@` in the text means no need to run the email
regex). Third, I would write it in Go instead of Python, which is much faster for this kind of work. Finally,
it would fail closed: bodies over a size limit, or bodies that cannot be redacted in time, are dropped
instead of passed through unredacted.
