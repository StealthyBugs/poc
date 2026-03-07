# Static Source Code Analysis — Robinhood Open-Source Repositories

## Objective

Perform a comprehensive static security analysis of all 10 public repositories belonging to the GitHub organization **https://github.com/robinhood**. The goal is to identify **real, exploitable HIGH and CRITICAL severity vulnerabilities** in HTTP-facing code — not theoretical issues, not bugs requiring local system access, and absolutely no hallucinated findings.

---

## Target Repositories

| # | Repository | Language | Description |
|---|-----------|----------|-------------|
| 1 | `faust` | Python | Python Stream Processing |
| 2 | `airflow-prometheus-exporter` | Python | Prometheus Exporter for Airflow |
| 3 | `thorn` | Python | Easy Webhooks for Python |
| 4 | `ticker` | Java/Android | Android text view with scrolling text change animation |
| 5 | `spark` | Java/Android | Android sparkline chart view |
| 6 | `deux` | Python/Django | Multifactor Authentication for Django Rest Framework |
| 7 | `aiokafka` | Python | Async Kafka client (fork) |
| 8 | `kafka-python` | Python | Python client for Apache Kafka |
| 9 | `riemann` | Clojure | Robinhood Riemann configuration |
| 10 | `tsd-helpers` | Python | OpenTSDB helpers |

---

## Phase 1: Reconnaissance — Route, Endpoint & Parameter Discovery

**Minimum concurrency: 40 workers across all repositories simultaneously.**

### Instructions

For every repository, discover and catalog:

1. **HTTP Routes & Endpoints**
   - URL paths defined in views, routers, URL configs, `@app.route`, `@api_view`, Flask/Django/Faust web endpoints, REST framework routers, any `urlpatterns`, webhook receiver endpoints, health check endpoints, metrics endpoints, admin endpoints.
   - For Java repos: Servlets, Spring `@RequestMapping`, `@GetMapping`, `@PostMapping`, JAX-RS `@Path`, Android deep link handlers.
   - For Clojure repos: Ring handlers, Compojure routes, Pedestal interceptors.

2. **Parameters (all input vectors)**
   - **GET** query parameters (`request.GET`, `request.args`, `request.query_params`, `@RequestParam`)
   - **POST** body parameters (form data, `request.POST`, `request.data`, `request.body`)
   - **JSON** request bodies (`request.json`, `json.loads(request.body)`, `@RequestBody`, content-type application/json handling)
   - **XML** request bodies (any XML parsing: `xml.etree`, `lxml`, `xml.sax`, `xml.dom`, `defusedxml`, `javax.xml`, SAX/DOM/StAX parsers)
   - **URL path parameters** (`<int:id>`, `{id}`, path converters)
   - **HTTP Headers** consumed by application logic (Authorization, X-Forwarded-For, Host, custom headers)
   - **Cookies** read by the application
   - **File uploads** (`request.FILES`, multipart handling)
   - **WebSocket messages** (if any async websocket handlers exist)
   - **Webhook payloads** (especially in `thorn` — this is a webhooks library)

3. **Serialization & Deserialization**
   - Django REST Framework serializers and their field definitions
   - Marshmallow schemas
   - Manual JSON/XML parsing
   - Pickle/YAML/TOML deserialization
   - Protocol buffer definitions
   - Any custom deserialization logic

4. **Authentication & Authorization Boundaries**
   - Which endpoints require auth vs are unauthenticated
   - Token validation logic (JWT, API keys, session tokens)
   - Permission classes and decorators
   - Rate limiting configuration
   - CORS configuration

### Output Format for Phase 1

For each repository, produce a structured map:

```
Repository: <name>
├── Endpoint: <METHOD> <path>
│   ├── Parameters: [name: type, source: GET/POST/JSON/XML/Header/Cookie]
│   ├── Auth Required: Yes/No
│   ├── Serializer/Validator: <class name or "none">
│   ├── Handler Function: <file:line>
│   └── Notes: <anything unusual>
```

---

## Phase 2: Static Vulnerability Analysis

**Minimum concurrency: 40 workers across all repositories. Minimum 5 workers per file being analyzed.**

### Vulnerability Classes to Hunt (HIGH and CRITICAL only)

Analyze every repository for the following. For each class, trace data flow from user-controlled input to dangerous sink:

#### 1. Code Injection / Remote Code Execution
- `eval()`, `exec()`, `compile()` with user input
- `subprocess` / `os.system` / `os.popen` with unsanitized input
- `pickle.loads()` / `yaml.load()` (unsafe loader) on user data
- Dynamic import with user-controlled module names
- `__import__()` with user input
- Template code execution (Jinja2 `Environment` without sandboxing)
- Python `ast.literal_eval` misuse
- Java `Runtime.exec()`, `ProcessBuilder` with user input
- Clojure `eval`, `read-string` on untrusted input

#### 2. Server-Side Template Injection (SSTI)
- User input rendered directly in Jinja2/Mako/Django templates
- `Template(user_input).render()` patterns
- `render_template_string()` with user data
- Format string injection (`str.format()` or f-strings with user-controlled format specs)

#### 3. SQL Injection
- Raw SQL queries with string concatenation/formatting of user input
- `cursor.execute(f"SELECT ... {user_input}")` patterns
- Django `.raw()` or `.extra()` with unsanitized input
- ORM filter bypass through `__` lookups on user-controlled field names
- Clojure SQL string building without parameterization

#### 4. XML External Entity (XXE) Injection
- XML parsing without disabling external entities
- `xml.etree.ElementTree` (safe by default in Python, but check version)
- `lxml.etree.parse()` / `lxml.etree.fromstring()` without `resolve_entities=False`
- `xml.sax` parser without feature disabling
- `xml.dom.minidom` with external entity resolution
- Java XML parsers without `FEATURE_SECURE_PROCESSING`
- Any custom XML parsing that accepts user-supplied XML

#### 5. Dependency Confusion
- Internal package names that could be squatted on public PyPI/npm/Maven
- `setup.py` / `setup.cfg` / `pyproject.toml` referencing private packages without explicit index URLs
- `requirements.txt` with packages not pinned to a specific index
- Missing `--index-url` or `--extra-index-url` protections

#### 6. Command Injection
- Shell commands built with user input
- `subprocess.call(shell=True)` with unsanitized arguments
- Backtick execution in any language
- Pipes to shell commands
- `shlex.split()` misuse followed by `subprocess` calls

#### 7. Cross-Site Scripting (XSS) — Reflected, Stored, DOM
- User input reflected in HTML responses without escaping
- `mark_safe()` / `|safe` filter on user data in Django templates
- JSON responses with `text/html` content type containing user input
- Stored user data rendered without sanitization
- JavaScript template literals with user data
- `innerHTML` / `document.write` with untrusted data

#### 8. Server-Side Request Forgery (SSRF)
- User-controlled URLs passed to `requests.get()`, `urllib.urlopen()`, `httpx`, `aiohttp`
- Webhook URLs (especially in `thorn`) — can the user register arbitrary callback URLs?
- URL validation bypass (e.g., DNS rebinding, IP allowlist bypass, URL parser differentials)
- Redirect following to internal services
- Cloud metadata endpoint access (169.254.169.254)

#### 9. Local File Read / Path Traversal
- `open(user_input)` without path validation
- `os.path.join(base, user_input)` without checking for `../`
- `send_file()` / `send_from_directory()` with user-controlled paths
- Static file serving with path traversal
- Zip slip (extracting archives without validating entry paths)

#### 10. JWT Vulnerabilities
- JWT verification disabled or optional
- `algorithms=["none"]` accepted
- HMAC/RSA confusion (accepting HS256 when RS256 expected)
- Weak or hardcoded signing secrets
- Missing expiration validation
- JWT library vulnerabilities
- Token not validated at all (just decoded and trusted)

#### 11. Additional Edge-Case Hunting
Use your training knowledge of real-world vulnerability research. Look for:
- **Mass assignment / parameter pollution**: Can extra fields be injected through serializers?
- **Race conditions**: TOCTOU bugs in auth or financial operations
- **Insecure deserialization**: Beyond pickle — msgpack, protobuf custom deserializers
- **Open redirect**: User-controlled redirect targets after login/auth
- **Webhook signature bypass**: In `thorn`, can webhook signatures be forged or skipped?
- **Celery task injection**: Can user input control which Celery tasks are dispatched or their arguments?
- **Kafka message injection**: In kafka-python/aiokafka, can a consumer be tricked into processing crafted messages that lead to code execution?
- **Prototype pollution** (if any JS exists)
- **ReDoS**: Regex patterns with catastrophic backtracking on user input
- **Header injection / CRLF injection**: User input in HTTP response headers
- **Host header poisoning**: Password reset or URL generation using unvalidated Host header
- **Unsafe file operations**: Symlink following, temp file races

---

## Phase 3: Verification & False Positive Elimination

**This phase is MANDATORY. Do NOT skip it. Every single finding must pass through this gate.**

For EACH potential vulnerability identified in Phase 2, answer ALL of the following questions. If ANY answer indicates a false positive, **discard the finding immediately** and move on:

### Verification Checklist

1. **Is there a regex, allowlist, or input validation stopping this attack?**
   - Check for input sanitization in the same function
   - Check for validation in middleware, decorators, or base classes
   - Check for Django REST Framework serializer field validation
   - Check for schema validation (Marshmallow, Cerberus, jsonschema)

2. **Is this actually production code?**
   - Is it in a test file (`test_*.py`, `*_test.py`, `tests/`)?
   - Is it in example/demo code (`examples/`, `docs/`)?
   - Is it in a script meant for local development only?
   - Is it behind a `if __name__ == "__main__"` guard?
   - Is it in a disabled/deprecated module?

3. **Are there additional security checks upstream?**
   - Does a middleware sanitize the input before it reaches this code?
   - Is there an authentication layer that prevents unauthenticated access?
   - Does the framework itself handle escaping (Django auto-escapes templates)?
   - Is there a WAF or reverse proxy mentioned in configuration?

4. **Is the behavior expected and by design?**
   - Is this an admin-only function where admins are trusted?
   - Is this a CLI tool not exposed over HTTP?
   - Is this internal infrastructure code not user-facing?
   - Is this a library where the caller is responsible for sanitization?

5. **Is user input actually controllable?**
   - Trace the data flow: does user input ACTUALLY reach the sink?
   - Is the "user input" actually derived from a trusted source (database lookup, config file)?
   - Are there type coercions that neutralize the payload?

6. **Can the vulnerability be triggered via HTTP?**
   - The user specifically wants HTTP-exploitable bugs
   - If exploitation requires local file system access, shell access, or modifying server configs — **discard it**
   - If it requires being on the same network or Kafka cluster — **discard it**

### Re-verification

After the checklist, re-read the surrounding code one more time. Look at:
- 20 lines above and below the vulnerable line
- The calling function
- Any wrapper/decorator on the function
- The class hierarchy if it's a method

If there is ANY remaining doubt, **discard the finding**.

---

## Phase 4: Confirmed Vulnerability Report

Only findings that survive Phase 3 make it here.

### Report Format (per finding)

```
╔══════════════════════════════════════════════════════════════╗
║  CONFIRMED VULNERABILITY #[N]                                ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Severity:      [CRITICAL / HIGH]                            ║
║  Category:      [e.g., SQL Injection]                        ║
║  Repository:    [repo name]                                  ║
║  File:          [path/to/file.py:line_number]                ║
║  Function:      [function_name]                              ║
║  Endpoint:      [METHOD /path]                               ║
║                                                              ║
║  VULNERABLE CODE                                             ║
║  ─────────────────                                           ║
║  [Exact code snippet, 5-10 lines with the vulnerable         ║
║   line highlighted]                                          ║
║                                                              ║
║  ATTACK PATH                                                 ║
║  ───────────                                                 ║
║  1. [Step-by-step how an attacker reaches this code]         ║
║  2. [What user-controlled input is injected]                 ║
║  3. [How the input reaches the dangerous sink]               ║
║  4. [What the attacker gains — RCE, data exfil, etc.]       ║
║                                                              ║
║  WHY THIS IS NOT A FALSE POSITIVE                            ║
║  ────────────────────────────────                            ║
║  - [Explain why no sanitization catches this]                ║
║  - [Explain why this is reachable HTTP code]                 ║
║  - [Explain why framework defaults don't protect]            ║
║                                                              ║
║  PROOF-OF-CONCEPT HTTP REQUEST                               ║
║  ─────────────────────────────                               ║
║                                                              ║
║  ```http                                                     ║
║  POST /vulnerable/endpoint HTTP/1.1                          ║
║  Host: target.example.com                                    ║
║  Content-Type: application/json                              ║
║  Authorization: Bearer <token>                               ║
║                                                              ║
║  {"param": "<malicious payload>"}                            ║
║  ```                                                         ║
║                                                              ║
║  EXPECTED RESULT                                             ║
║  ───────────────                                             ║
║  [What happens when this request is sent — e.g.,             ║
║   "The server executes os.system('id') and returns           ║
║    command output in the response body"]                     ║
║                                                              ║
║  REMEDIATION                                                 ║
║  ───────────                                                 ║
║  [Specific fix — not generic advice. Show the exact code     ║
║   change needed.]                                            ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Execution Rules

1. **No hallucinations.** Every vulnerability must reference real code that exists in the repository. Every file path, function name, and line number must be verifiable. If you are not certain a vulnerability exists, do not report it.

2. **No theoretical bugs.** Do not report "if an attacker could modify the server config, then..." — only report bugs exploitable via HTTP by an external attacker or authenticated user.

3. **No low/medium severity.** Only HIGH and CRITICAL. An XSS in a non-sensitive admin page is not HIGH. An SQLi that leaks user data is CRITICAL.

4. **Trace the full data flow.** For every finding, show the exact path from HTTP input to dangerous operation. If you cannot trace it completely, it's not a confirmed finding.

5. **Quality over quantity.** One real, verified vulnerability is worth infinitely more than 50 false positives. If no real vulnerabilities exist, say so honestly. Do not manufacture findings.

6. **Take your time.** Use as many workers and as much time as needed. Re-read code. Follow imports. Check base classes. Read documentation. This is not a speed contest.

7. **Be honest.** If a repository has no HTTP-facing code (e.g., Android UI libraries like `ticker` and `spark`), state that clearly and move on. Do not force-fit vulnerabilities where none exist.

8. **Edge cases matter.** Look for the non-obvious. The interaction between two safe-looking functions that creates an unsafe condition. The default parameter that disables validation. The error handler that leaks stack traces. The debug endpoint left enabled.

9. **Libraries vs Applications.** Several of these repos are libraries (faust, thorn, kafka-python, aiokafka). For libraries, analyze: (a) Are there unsafe defaults? (b) Can a user of the library inadvertently create a vulnerability? (c) Does the library itself expose HTTP endpoints? (d) Are there example/default configurations that are insecure?

10. **Webhook-specific analysis for `thorn`.** This is a webhooks library. Pay special attention to: webhook URL validation (SSRF), webhook signature verification (bypass), webhook payload handling (injection), retry logic (timing attacks), and whether webhook recipients can be spoofed.

---

## Summary Section

After all phases complete, provide:

```
═══════════════════════════════════════════════
  EXECUTIVE SUMMARY
═══════════════════════════════════════════════

  Repositories Analyzed:     10/10
  Total Endpoints Found:     [N]
  Total Parameters Mapped:   [N]

  Confirmed Vulnerabilities: [N]
    ├── CRITICAL:            [N]
    └── HIGH:                [N]

  False Positives Eliminated: [N]

  Repositories with No HTTP Attack Surface:
    - [list repos like ticker, spark if applicable]

  Top Risk Repositories:
    1. [repo] — [N] findings ([brief description])
    2. [repo] — [N] findings ([brief description])

═══════════════════════════════════════════════
```

---

## Final Reminder

**Verify. Verify again. Then verify once more.**

The person reading this report will manually check every finding against the actual source code. A single false positive undermines the credibility of the entire report. When in doubt, leave it out. Only report what you can prove.
