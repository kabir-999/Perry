"""
AST-based static analysis with taint tracking.

Keyword matching cannot tell these apart:

    db.query("SELECT * FROM u WHERE id = " + req.query.id)   ← injectable
    db.query("SELECT * FROM u WHERE id = ?", [req.query.id]) ← parameterised
    db.query("SELECT * FROM u WHERE id = 1")                 ← no input at all

All three contain `db.query`. Only the first is a vulnerability. So this engine
parses real syntax trees — ``esprima`` for JavaScript/TypeScript, the stdlib
``ast`` for Python — and reports a finding only when it can trace:

    source (attacker-controlled)  →  [sanitizer?]  →  sink (dangerous)

A dangerous call with no tainted argument is not reported. A tainted value that
passes through a recognised sanitizer is reported at reduced severity with the
sanitizer named, because whether it neutralises *this* attack class is a
judgement the developer must make with the facts in front of them.

The analysis is intraprocedural: it follows assignments within a function/file,
not across module boundaries. Findings say so, and a path that cannot be traced
is reported as absent rather than assumed.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

try:
    import esprima
except ImportError:  # pragma: no cover - JS analysis degrades to skipped
    esprima = None


# ------------------------------------------------------------------ rules


@dataclass
class Rule:
    vuln_class: str
    title: str
    impact: str            # low | medium | high | critical
    cwe: str
    # Sink callee names, matched against the dotted call expression.
    sinks: tuple[str, ...]
    sanitizers: tuple[str, ...]
    principle: str         # the secure-coding principle that was violated
    learning: str          # developer education
    remediation: str
    verify: str            # how to check the fix


RULES: list[Rule] = [
    Rule(
        "sql_injection", "SQL injection", "critical", "CWE-89",
        ("query", "execute", "executemany", "raw", "cursor.execute",
         "db.query", "connection.query", "sequelize.query", "knex.raw",
         # Java (JDBC)
         "createStatement", "executeQuery", "executeUpdate",
         # Go (database/sql) — capitalized, distinct from the lowercase JS/py forms
         "Query", "Exec", "QueryRow",
         # PHP
         "mysqli_query", "pg_query",
         # Ruby
         "find_by_sql",
         # C# (ADO.NET)
         "ExecuteReader", "ExecuteNonQuery", "ExecuteScalar"),
        ("escape", "escapeId", "parameterize", "sql.identifier", "prepare"),
        "User input must never be concatenated into a query string.",
        "The database receives one string containing both the query and the "
        "user's data, so it cannot tell them apart. An input like "
        "`' OR 1=1 --` stops being data and becomes SQL the database executes. "
        "Parameterised queries send the query and the values separately, so "
        "user input is always treated as data.",
        "Use parameterised queries or prepared statements:\n"
        "  db.query('SELECT * FROM users WHERE id = ?', [userId])\n"
        "Never build SQL with string concatenation or template literals.",
        "Re-run the scan, and try the input `' OR '1'='1` — a fixed endpoint "
        "returns no rows rather than every row.",
    ),
    Rule(
        "nosql_injection", "NoSQL injection", "high", "CWE-943",
        ("find", "findOne", "findOneAndUpdate", "updateOne", "deleteOne",
         "aggregate", "where"),
        ("sanitize", "mongoSanitize", "toString", "String"),
        "Query objects must not be built directly from request data.",
        "Passing `req.body` straight into a MongoDB query lets an attacker "
        "send `{\"$ne\": null}` instead of a string, turning an equality check "
        "into 'not equal' and bypassing it entirely. Operators arrive as data "
        "and become query logic.",
        "Cast values explicitly and reject objects where a scalar is expected:\n"
        "  User.findOne({ email: String(req.body.email) })\n"
        "or use express-mongo-sanitize to strip `$`-prefixed keys.",
        "Send `{\"email\": {\"$ne\": null}}` — a fixed endpoint rejects it or "
        "finds nothing.",
    ),
    Rule(
        "command_injection", "OS command injection", "critical", "CWE-78",
        ("exec", "execSync", "spawn", "spawnSync", "system", "popen",
         "os.system", "subprocess.run", "subprocess.call", "subprocess.Popen",
         "child_process.exec",
         # Go (os/exec) — bare "exec" already covers the JS/Python forms, but
         # Go's own package-qualified form needs its own dotted entry.
         "exec.Command",
         # PHP
         "shell_exec", "passthru", "proc_open",
         # C# (System.Diagnostics)
         "Process.Start"),
        ("shlex.quote", "escapeShellArg", "quote"),
        "User input must never reach a shell.",
        "When input is interpolated into a shell command, characters like "
        "`;`, `|` and `$()` are interpreted by the shell as command syntax. "
        "`file.txt; rm -rf /` becomes two commands. Passing arguments as an "
        "array avoids a shell entirely.",
        "Pass arguments as a list and avoid the shell:\n"
        "  execFile('convert', [inputPath, outputPath])\n"
        "  subprocess.run(['ls', path], shell=False)",
        "Try an input containing `; echo pwned` — a fixed endpoint treats it "
        "as a literal filename.",
    ),
    Rule(
        "xss", "Cross-site scripting", "high", "CWE-79",
        ("send", "write", "end", "innerHTML", "outerHTML",
         "dangerouslySetInnerHTML", "document.write", "insertAdjacentHTML",
         # C# (ASP.NET)
         "Response.Write"),
        ("escape", "encodeURIComponent", "sanitize", "DOMPurify.sanitize",
         "escapeHtml", "textContent"),
        "Untrusted input must be encoded for the context it is rendered into.",
        "Input echoed into HTML without encoding is parsed as markup, so "
        "`<script>` becomes executable code running with the victim's session. "
        "Encoding turns those characters into text the browser displays "
        "instead of executes.",
        "Escape on output, or let the framework do it:\n"
        "  res.send(escapeHtml(userInput))\n"
        "  React renders {userInput} safely — avoid dangerouslySetInnerHTML.",
        "Submit `<script>alert(1)</script>` — a fixed page shows the text "
        "rather than running it.",
    ),
    Rule(
        "ssrf", "Server-side request forgery", "high", "CWE-918",
        ("fetch", "axios", "urlopen", "requests.get", "requests.post",
         "http.get", "https.get", "axios.get", "axios.post", "got",
         # Go (net/http) — capitalized package-qualified form
         "http.Get", "http.Post",
         # PHP
         "curl_exec",
         # Note: Ruby's Kernel#open (open-uri, SSRF-capable) is deliberately
         # NOT added here — bare "open" is already claimed by Python's
         # open() builtin under path_traversal below, and RULES order (ssrf
         # comes first) would silently steal that claim. Documented gap.
         # Rust
         "reqwest.get",
         # C#
         "GetAsync", "DownloadString"),
        ("validateURL", "isURL", "allowlist", "urlparse"),
        "The server must not fetch arbitrary attacker-supplied URLs.",
        "The server makes the request, so it reaches places the attacker "
        "cannot — internal services, `localhost`, and cloud metadata endpoints "
        "like 169.254.169.254 that hand out credentials. Blocklists fail to "
        "redirects and DNS tricks; an allowlist does not.",
        "Validate against an allowlist of permitted hosts, resolve the DNS "
        "name and reject private ranges, and disable redirect following.",
        "Request `http://169.254.169.254/` — a fixed endpoint rejects it.",
    ),
    Rule(
        "path_traversal", "Path traversal", "high", "CWE-22",
        ("readFile", "readFileSync", "createReadStream", "sendFile",
         "open", "unlink", "writeFile", "os.path.join",
         # Java
         "Files.readAllBytes", "readAllBytes",
         # Go
         "os.Open", "os.ReadFile", "ioutil.ReadFile",
         # PHP
         "fopen", "file_get_contents", "readfile",
         # Ruby (constant-based receiver: File.open/File.read)
         "File.open", "File.read",
         # Rust (normalized from File::open / fs::read / fs::read_to_string)
         "fs.read", "fs.read_to_string",
         # C#
         "File.ReadAllText", "File.Open", "File.ReadAllBytes"),
        ("basename", "path.basename", "resolve", "secure_filename", "normalize"),
        "File paths must be confined to an intended directory.",
        "`../` sequences walk up out of the intended folder, so a filename "
        "parameter can reach `/etc/passwd` or application config. Taking only "
        "the basename, then resolving and confirming the result is still "
        "inside the base directory, prevents the escape.",
        "Confine the path:\n"
        "  const safe = path.join(BASE, path.basename(name));\n"
        "  if (!path.resolve(safe).startsWith(path.resolve(BASE))) throw …",
        "Request `../../etc/passwd` — a fixed endpoint returns 400 or 404.",
    ),
    Rule(
        "unsafe_deserialization", "Unsafe deserialization", "critical", "CWE-502",
        ("pickle.loads", "pickle.load", "yaml.load", "marshal.loads",
         "unserialize", "deserialize",
         # Java
         "readObject",
         # Ruby
         "Marshal.load",
         # C# (best-effort bare match, no type inference)
         "Deserialize"),
        ("yaml.safe_load", "json.loads", "SafeLoader"),
        "Never deserialize untrusted data into live objects.",
        "Formats like pickle and unsafe YAML reconstruct arbitrary objects and "
        "can execute code during loading — before your own code inspects "
        "anything. The attacker controls what gets constructed.",
        "Use a data-only format: `json.loads(...)` or `yaml.safe_load(...)`.",
        "Confirm the endpoint rejects a pickle payload.",
    ),
    Rule(
        "code_execution", "Dynamic code execution", "critical", "CWE-95",
        ("eval", "Function", "vm.runInNewContext", "setTimeout", "exec",
         "compile", "execfile"),
        (),
        "Attacker-controlled input must never be executed as code.",
        "`eval` compiles and runs its argument, so any input reaching it runs "
        "with full application privileges. There is almost never a reason to "
        "evaluate user input.",
        "Remove eval. Parse data with `JSON.parse`, and use a lookup table or "
        "explicit branch instead of evaluating a string.",
        "Confirm the input is parsed as data rather than executed.",
    ),
    Rule(
        "open_redirect", "Open redirect", "medium", "CWE-601",
        ("redirect", "location", "Location",
         # Java
         "sendRedirect",
         # PHP (header("Location: " . $url))
         "header",
         # Ruby (Rails)
         "redirect_to",
         # Go
         "http.Redirect",
         # C#
         "Response.Redirect"),
        ("isURL", "allowlist", "startsWith"),
        "Redirect targets must be validated against an allowlist.",
        "An attacker sends a link to your trusted domain that bounces the "
        "victim to theirs, lending your reputation to a phishing page.",
        "Allow only relative paths, or match against a list of permitted "
        "hosts before redirecting.",
        "Request `?next=https://evil.tld` — a fixed endpoint refuses it.",
    ),
]

# Two lookups: exact dotted callee (precise) and bare name (fallback). A name
# claimed by more than one rule — `exec` is both a SQL and a shell sink — is
# resolved by the dotted form first, and a bare collision is left to the rule
# that owns it unambiguously.
_SINK_DOTTED: dict[str, Rule] = {}
_SINK_SHORT: dict[str, Rule] = {}
_SHORT_CLAIMS: dict[str, set[str]] = {}

for _rule in RULES:
    for _sink in _rule.sinks:
        if "." in _sink:
            _SINK_DOTTED.setdefault(_sink, _rule)
        short = _sink.split(".")[-1]
        _SHORT_CLAIMS.setdefault(short, set()).add(_rule.vuln_class)
        _SINK_SHORT.setdefault(short, _rule)


def _rule_for(callee: str) -> Rule | None:
    """Resolve a call expression to the rule that owns it."""
    if callee in _SINK_DOTTED:
        return _SINK_DOTTED[callee]
    short = callee.split(".")[-1]
    # `exec` is claimed by both SQL and command injection; the shell reading is
    # the dangerous one and the SQL reading needs a dotted db.* receiver, so
    # prefer command injection for the bare form.
    claims = _SHORT_CLAIMS.get(short, set())
    if len(claims) > 1 and "command_injection" in claims:
        return next(r for r in RULES if r.vuln_class == "command_injection")
    return _SINK_SHORT.get(short)


# ---------------------------------------------------------------- sources

# Attacker-controlled entry points. Matching one of these is what creates
# taint; nothing else does.
_JS_SOURCE_ROOTS = {"req", "request", "ctx", "event"}
_JS_SOURCE_PROPS = {
    "body", "query", "params", "headers", "cookies", "url", "originalUrl",
    "queryStringParameters", "pathParameters",
}
_PY_SOURCE_ROOTS = {"request", "flask_request"}
_PY_SOURCE_PROPS = {
    "args", "form", "json", "data", "files", "values", "GET", "POST",
    "COOKIES", "headers", "query_params", "path_params",
}


@dataclass
class SastFinding:
    rule: Rule
    file: str
    line: int
    source_expr: str
    source_line: int
    sink_expr: str
    code: str
    sanitizers: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)

    @property
    def sanitized(self) -> bool:
        return bool(self.sanitizers)

    def attack_path(self) -> str:
        chain = [f"{self.source_expr}  (attacker-controlled, line {self.source_line})"]
        chain.extend(self.steps)
        if self.sanitizers:
            chain.append(f"{', '.join(self.sanitizers)}()  (validation)")
        chain.append(f"{self.sink_expr}  (sink, line {self.line})")
        return "\n  ↓\n".join(chain)


# ------------------------------------------------------------ JS analysis


def _js_member_name(node: dict) -> str:
    """Flatten a MemberExpression into a dotted string."""
    if not isinstance(node, dict):
        return ""
    t = node.get("type")
    if t == "Identifier":
        return node.get("name", "")
    if t == "ThisExpression":
        return "this"
    if t == "MemberExpression":
        obj = _js_member_name(node.get("object") or {})
        prop = node.get("property") or {}
        name = prop.get("name") or prop.get("value") or ""
        return f"{obj}.{name}" if obj else str(name)
    if t == "CallExpression":
        return _js_member_name(node.get("callee") or {})
    return ""


def _js_is_source(node: dict) -> str:
    """Return the source expression if this node reads attacker input."""
    dotted = _js_member_name(node)
    if not dotted:
        return ""
    parts = dotted.split(".")
    if len(parts) >= 2 and parts[0] in _JS_SOURCE_ROOTS and parts[1] in _JS_SOURCE_PROPS:
        return dotted
    if dotted.endswith("searchParams.get") or dotted.endswith("formData.get"):
        return dotted
    return ""


def _js_walk(node, fn, parent=None):
    if isinstance(node, dict):
        fn(node, parent)
        for value in node.values():
            _js_walk(value, fn, node)
    elif isinstance(node, list):
        for item in node:
            _js_walk(item, fn, parent)


def analyze_javascript(path: Path, rel: str, code: str) -> list[SastFinding]:
    if esprima is None:
        return []
    try:
        tree = esprima.parseModule(code, {"loc": True, "tolerant": True}).toDict()
    except Exception:
        try:
            tree = esprima.parseScript(code, {"loc": True, "tolerant": True}).toDict()
        except Exception:
            return []

    lines = code.splitlines()
    # name -> (source expression, line, [sanitizers applied])
    tainted: dict[str, tuple[str, int, list[str]]] = {}
    findings: list[SastFinding] = []

    def taint_of(node) -> tuple[str, int, list[str]] | None:
        """Whether an expression carries attacker-controlled data."""
        if not isinstance(node, dict):
            return None
        direct = _js_is_source(node)
        if direct:
            return (direct, (node.get("loc") or {}).get("start", {}).get("line", 0), [])
        t = node.get("type")
        if t == "Identifier":
            return tainted.get(node.get("name", ""))
        if t == "MemberExpression":
            root = _js_member_name(node).split(".")[0]
            return tainted.get(root)
        if t in ("BinaryExpression", "LogicalExpression"):
            return taint_of(node.get("left")) or taint_of(node.get("right"))
        if t == "TemplateLiteral":
            for expr in node.get("expressions") or []:
                hit = taint_of(expr)
                if hit:
                    return hit
            return None
        if t == "CallExpression":
            callee = _js_member_name(node.get("callee") or {})
            short = callee.split(".")[-1]
            for arg in node.get("arguments") or []:
                hit = taint_of(arg)
                if hit:
                    # A call wrapping tainted data records the sanitizer.
                    return (hit[0], hit[1], hit[2] + [short])
            return None
        if t in ("AwaitExpression", "UnaryExpression"):
            return taint_of(node.get("argument"))
        return None

    def visit(node: dict, parent):
        t = node.get("type")

        # Propagate taint through assignments.
        if t == "VariableDeclarator":
            init = node.get("init")
            hit = taint_of(init) if init else None
            if hit:
                target = node.get("id") or {}
                if target.get("type") == "Identifier":
                    tainted[target["name"]] = hit
                elif target.get("type") == "ObjectPattern":
                    for prop in target.get("properties") or []:
                        val = prop.get("value") or {}
                        if val.get("type") == "Identifier":
                            tainted[val["name"]] = hit
        elif t == "AssignmentExpression":
            hit = taint_of(node.get("right"))
            if hit:
                left = node.get("left") or {}
                if left.get("type") == "Identifier":
                    tainted[left["name"]] = hit

        # Sink calls.
        if t == "CallExpression":
            callee = _js_member_name(node.get("callee") or {})
            short = callee.split(".")[-1]
            rule = _rule_for(callee)
            if rule is None:
                return
            args = node.get("arguments") or []

            # A parameterised call passes values in a separate argument, so
            # taint in argument 2+ of a query sink is the safe form.
            if rule.vuln_class == "sql_injection" and len(args) >= 2:
                if taint_of(args[0]) is None:
                    return

            for arg in args:
                hit = taint_of(arg)
                if hit is None:
                    continue
                source_expr, source_line, sanitizers = hit
                applied = [s for s in sanitizers if s in rule.sanitizers]
                line = (node.get("loc") or {}).get("start", {}).get("line", 0)
                findings.append(
                    SastFinding(
                        rule=rule, file=rel, line=line,
                        source_expr=source_expr, source_line=source_line,
                        sink_expr=f"{callee}()",
                        code=(lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""),
                        sanitizers=applied,
                        steps=[f"{s}()" for s in sanitizers if s not in rule.sanitizers],
                    )
                )
                break

    _js_walk(tree, visit)
    return findings


# -------------------------------------------------------- Python analysis


def _py_dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _py_dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _py_dotted(node.func)
    return ""


class _PyTaint(ast.NodeVisitor):
    def __init__(self, rel: str, lines: list[str]) -> None:
        self.rel = rel
        self.lines = lines
        self.tainted: dict[str, tuple[str, int, list[str]]] = {}
        self.findings: list[SastFinding] = []

    def _is_source(self, node: ast.AST) -> str:
        dotted = _py_dotted(node)
        parts = dotted.split(".")
        if len(parts) >= 2 and parts[0] in _PY_SOURCE_ROOTS and parts[1] in _PY_SOURCE_PROPS:
            return dotted
        return ""

    def taint_of(self, node: ast.AST) -> tuple[str, int, list[str]] | None:
        if node is None:
            return None
        direct = self._is_source(node)
        if direct:
            return (direct, getattr(node, "lineno", 0), [])
        if isinstance(node, ast.Name):
            return self.tainted.get(node.id)
        if isinstance(node, ast.Attribute):
            return self.tainted.get(_py_dotted(node).split(".")[0])
        if isinstance(node, ast.BinOp):
            return self.taint_of(node.left) or self.taint_of(node.right)
        if isinstance(node, ast.JoinedStr):  # f-string
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    hit = self.taint_of(value.value)
                    if hit:
                        return hit
            return None
        if isinstance(node, ast.Call):
            short = _py_dotted(node.func).split(".")[-1]
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                hit = self.taint_of(arg)
                if hit:
                    return (hit[0], hit[1], hit[2] + [short])
            return None
        return None

    def visit_Assign(self, node: ast.Assign) -> None:
        hit = self.taint_of(node.value)
        if hit:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted[target.id] = hit
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        callee = _py_dotted(node.func)
        short = callee.split(".")[-1]
        rule = _rule_for(callee)
        if rule is not None:
            args = list(node.args)
            # cursor.execute(sql, params) is the parameterised form.
            if rule.vuln_class == "sql_injection" and len(args) >= 2:
                if self.taint_of(args[0]) is None:
                    self.generic_visit(node)
                    return
            for arg in args + [kw.value for kw in node.keywords]:
                hit = self.taint_of(arg)
                if hit is None:
                    continue
                source_expr, source_line, sanitizers = hit
                applied = [s for s in sanitizers if s in rule.sanitizers]
                line = node.lineno
                self.findings.append(
                    SastFinding(
                        rule=rule, file=self.rel, line=line,
                        source_expr=source_expr, source_line=source_line,
                        sink_expr=f"{callee}()",
                        code=(self.lines[line - 1].strip()[:200]
                              if 0 < line <= len(self.lines) else ""),
                        sanitizers=applied,
                        steps=[f"{s}()" for s in sanitizers if s not in rule.sanitizers],
                    )
                )
                break
        self.generic_visit(node)


def analyze_python(path: Path, rel: str, code: str) -> list[SastFinding]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    visitor = _PyTaint(rel, code.splitlines())
    visitor.visit(tree)
    return visitor.findings


# ------------------------------------------------------------- entrypoint

_JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

# Extension -> tree-sitter grammar name, for the 6 polyglot languages
# (polyglot_sast.py). Kept here (not just in polyglot_sast) so
# `analyze_sources`/`compute_language_coverage` have one shared source of
# truth for "which extensions are source code Perry understands at all".
_POLYGLOT_EXT = {
    ".java": "java", ".go": "go", ".php": "php", ".rb": "ruby",
    ".rs": "rust", ".cs": "csharp",
}


def analyze_sources(repo_path: Path, files: list[Path]) -> list[SastFinding]:
    """Run taint analysis over every supported source file — Python, JS/TS
    natively, plus Java/Go/PHP/Ruby/Rust/C# via polyglot_sast.py (degrades to
    skipped, never a crash, if tree-sitter isn't installed)."""
    from app.services.polyglot_sast import analyze_polyglot

    findings: list[SastFinding] = []
    for file_path in files:
        suffix = file_path.suffix.lower()
        polyglot_lang = _POLYGLOT_EXT.get(suffix)
        if suffix not in _JS_EXT and suffix != ".py" and polyglot_lang is None:
            continue
        try:
            rel = str(file_path.relative_to(repo_path))
            code = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, ValueError):
            continue
        if len(code) > 1_000_000:
            continue
        try:
            if suffix == ".py":
                findings.extend(analyze_python(file_path, rel, code))
            elif suffix in _JS_EXT:
                findings.extend(analyze_javascript(file_path, rel, code))
            else:
                findings.extend(analyze_polyglot(file_path, rel, code, polyglot_lang))
        except RecursionError:
            continue

    # One finding per (file, line, class).
    seen: set[tuple] = set()
    unique: list[SastFinding] = []
    for f in findings:
        key = (f.file, f.line, f.rule.vuln_class)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# Human-readable label per extension, for the CLI's `languages` report.
_LANGUAGE_LABEL = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript (JSX)",
    ".ts": "TypeScript", ".tsx": "TypeScript (TSX)", ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".java": "Java", ".go": "Go", ".php": "PHP", ".rb": "Ruby",
    ".rs": "Rust", ".cs": "C#",
}


def compute_language_coverage(repo_path: Path, files: list[Path]) -> dict:
    """Per-language SAST coverage: how many source files of each recognized
    language were found vs. actually analyzed vs. skipped, and why.

    This is the direct fix for a scan silently reporting "0 findings" for a
    language that was never actually analyzed (e.g. tree-sitter not
    installed) — the honesty already established for the dynamic scanner's
    NOT_TESTED vs. NOT_VULNERABLE distinction, applied here to source
    analysis. Never touches disk beyond what the caller already gathered;
    purely a re-classification of `files` by extension.
    """
    from app.services.polyglot_sast import _TS_AVAILABLE

    coverage: dict[str, dict] = {}
    for file_path in files:
        suffix = file_path.suffix.lower()
        if suffix not in _LANGUAGE_LABEL:
            continue
        label = _LANGUAGE_LABEL[suffix]
        entry = coverage.setdefault(label, {
            "files_found": 0, "files_analyzed": 0, "files_skipped": 0,
            "skip_reason": "",
        })
        entry["files_found"] += 1
        if suffix in _POLYGLOT_EXT and not _TS_AVAILABLE:
            entry["files_skipped"] += 1
            entry["skip_reason"] = "tree-sitter not installed"
        else:
            entry["files_analyzed"] += 1
    return coverage
