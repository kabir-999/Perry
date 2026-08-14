"""
Polyglot AST-based taint tracking — Java, Go, PHP, Ruby, Rust, C#.

Extends `sast_engine.py`'s source → [sanitizer?] → sink model to six more
languages via `tree-sitter`, without duplicating a from-scratch parser/visitor
per language the way the existing hand-rolled Python (`ast`) and JS
(`esprima`) implementations do. One generic intraprocedural taint algorithm
(mirroring `sast_engine._PyTaint` exactly: track a `tainted: dict[name ->
provenance]`, propagate through assignment/string-concatenation, flag a
tainted value reaching a `Rule.sink`, downgrade through a `Rule.sanitizer`)
is driven by a small per-language table of tree-sitter node-type names and a
`_dotted()` name-flattener, verified against each grammar's real node shapes.

`Rule`/`SastFinding`/`_rule_for` are reused unmodified from `sast_engine.py`
— this module only supplies new sink/source recognition for the sink table
already extended in `sast_engine.RULES`.

Degrades gracefully: if `tree-sitter`/`tree-sitter-language-pack` aren't
installed, `_TS_AVAILABLE` is False and every function here returns `[]`
rather than raising — callers (`sast_engine.analyze_sources`) must record
this as a real coverage gap (see the CLI's `languages` report), never a
silent "0 findings".

Known limitations (intraprocedural, no type inference, same spirit as the
existing Python/JS engines' own stated scope):
  - No cross-file/cross-function taint. A path that cannot be traced within
    one file is reported as absent, not assumed.
  - No type inference: sinks like C#'s `.Deserialize`/`.GetAsync` are matched
    by bare method name (any receiver), trading some precision for recall,
    exactly like the existing engines already do for bare names such as
    `exec`/`query`.
  - Language constructs that aren't function calls in the grammar (PHP
    `include`/`require`/`echo`, Ruby backticks) aren't sinks here — this
    engine only recognizes call expressions.
  - String interpolation is tracked only via binary/concatenation nodes and
    macro argument lists (e.g. Rust's `format!`); deeper interpolation node
    types are not walked.
"""
from __future__ import annotations

from pathlib import Path

from app.services.sast_engine import RULES, SastFinding, _rule_for

try:
    from tree_sitter_language_pack import get_parser
    _TS_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when not installed
    _TS_AVAILABLE = False


# --------------------------------------------------------------- languages

_EXT_TO_LANGUAGE = {
    ".java": "java",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".rs": "rust",
    ".cs": "csharp",
}

# Node types treated as a "plain identifier" whose text is directly usable as
# a dotted-name segment (includes Ruby's capitalized `constant` — `File`,
# `Marshal` — used as call receivers).
_IDENT_TYPES = {"identifier", "field_identifier", "type_identifier", "constant"}
# PHP variable syntax ($x, $_GET) is its own node type, not `identifier`.
_PHP_VAR_TYPES = {"variable_name", "name"}

_CALL_TYPES = {
    "java": {"method_invocation"},
    "go": {"call_expression"},
    "php": {"function_call_expression", "member_call_expression"},
    "ruby": {"call"},
    "rust": {"call_expression", "macro_invocation"},
    "csharp": {"invocation_expression"},
}
_BINARY_TYPES = {"binary_expression", "binary"}
# SQL sinks whose call signature puts the connection/handle first and the
# query string second (`mysqli_query($conn, $sql)`), unlike the (query,
# params) shape the shared "2+ args means parameterized" heuristic below
# assumes (matching Python's `cursor.execute(sql, params)` / JS's
# `db.query(sql, params)`).
_CONN_FIRST_SQL_SINKS = {"mysqli_query", "pg_query"}

# ------------------------------------------------ framework param binding
#
# Real web frameworks rarely read input via a raw `request.getParameter(...)`
# call — they bind it directly onto handler-method PARAMETERS via an
# annotation (Java Spring, C# ASP.NET), a type hint (PHP Laravel/Symfony's
# `Request $request`), or a typed extractor pattern (Rust axum/actix
# `Query<T>`/`Json<T>`/`Path<T>`). Without recognizing these, the engine
# would see literally no attacker-controlled input in most idiomatic modern
# code and report a false "0 findings, MINIMAL risk" — indistinguishable
# from a genuinely clean codebase. This seeds `tainted` from a function's
# own parameter list before its body is walked, so detection matches how
# each language's frameworks actually receive input, not just its raw
# platform API.
_FUNC_TYPES = {
    "java": {"method_declaration", "constructor_declaration"},
    "go": {"function_declaration", "method_declaration"},
    "php": {"function_definition", "method_declaration"},
    "rust": {"function_item"},
    "csharp": {"method_declaration", "local_function_statement"},
}
_JAVA_PARAM_ANNOTATIONS = {
    "RequestParam", "PathVariable", "RequestBody", "RequestHeader",
    "CookieValue", "ModelAttribute", "RequestPart",
}
_CSHARP_PARAM_ATTRIBUTES = {"FromQuery", "FromRoute", "FromBody", "FromHeader", "FromForm"}
# PHP/framework request-object type hints that make the WHOLE parameter a
# bare source root (any property/array/method access off it is tainted),
# the same mechanism Ruby's bare `params` root already uses.
_PHP_REQUEST_TYPES = {"Request", "ServerRequestInterface", "RequestInterface"}
# Rust extractor wrapper types (axum/actix-web) — the pattern's bound
# identifier(s) become tainted, regardless of the inner generic type.
_RUST_EXTRACTOR_TYPES = {"Query", "Json", "Path", "Form", "Extension", "State"}
# Go parameter types that mark the parameter name (whatever it's called) as
# an additional per-file source root — generalizes the fixed r/req/request
# name-matching to any handler that names its *http.Request parameter
# something else.
_GO_REQUEST_TYPES = ("http.Request", "Request")


def _param_names_in_pattern(node) -> list[str]:
    """Every plain identifier bound by a (possibly nested) pattern, e.g.
    Rust's `Query(x)` binds `x`."""
    if node is None:
        return []
    if node.type == "identifier":
        return [_text(node)]
    return [n for c in node.children for n in _param_names_in_pattern(c)]


def _seed_params(lang: str, func_node, tainted: dict) -> None:
    params_node = func_node.child_by_field_name("parameters")
    if params_node is None:
        return
    line = func_node.start_point[0] + 1

    if lang == "java":
        for p in params_node.children:
            if p.type != "formal_parameter":
                continue
            mods = next((c for c in p.children if c.type == "modifiers"), None)
            name = p.child_by_field_name("name")
            if mods is None or name is None:
                continue
            if any(ann in _text(mods) for ann in _JAVA_PARAM_ANNOTATIONS):
                tainted[_text(name)] = (f"@param {_text(name)}", line, [])

    elif lang == "csharp":
        for p in params_node.children:
            if p.type != "parameter":
                continue
            attrs = next((c for c in p.children if c.type == "attribute_list"), None)
            name = p.child_by_field_name("name")
            if attrs is None or name is None:
                continue
            if any(a in _text(attrs) for a in _CSHARP_PARAM_ATTRIBUTES):
                tainted[_text(name)] = (f"[param] {_text(name)}", line, [])

    elif lang == "php":
        for p in params_node.children:
            if p.type != "simple_parameter":
                continue
            ptype = p.child_by_field_name("type")
            name = p.child_by_field_name("name")
            if ptype is None or name is None:
                continue
            type_text = _text(ptype).split("\\")[-1]
            if type_text in _PHP_REQUEST_TYPES:
                tainted[_text(name)] = (f"{_text(name)} ({type_text} parameter)", line, [])

    elif lang == "rust":
        for p in params_node.children:
            if p.type != "parameter":
                continue
            ptype = p.child_by_field_name("type")
            pattern = p.child_by_field_name("pattern")
            if ptype is None or pattern is None:
                continue
            type_text = _text(ptype)
            if any(type_text.startswith(t) for t in _RUST_EXTRACTOR_TYPES):
                for name in _param_names_in_pattern(pattern):
                    tainted[name] = (f"{name} ({type_text} extractor)", line, [])

    elif lang == "go":
        extra_roots = tainted.setdefault("__extra_go_roots__", set())
        for p in params_node.children:
            if p.type != "parameter_declaration":
                continue
            ptype = p.child_by_field_name("type")
            name = p.child_by_field_name("name")
            if ptype is None or name is None:
                continue
            type_text = _text(ptype).lstrip("*")
            if any(type_text.endswith(t) for t in _GO_REQUEST_TYPES):
                extra_roots.add(_text(name))
# Transparent single-operand wrappers (Rust's `&expr`, parens, `await`, casts)
# that carry no taint-relevant meaning of their own — taint passes through.
_WRAPPER_TYPES = {
    "reference_expression", "parenthesized_expression", "unary_expression",
    "await_expression", "try_expression", "cast_expression",
}

# --------------------------------------------------------- source patterns

# (root name, member/method name) pairs identify attacker-controlled input,
# the same shape as sast_engine._PY_SOURCE_ROOTS/_PROPS — generalized here to
# match anywhere in a dotted chain (not just position 0/1) so a chained call
# like Go's `r.URL.Query().Get(...)` (dotted: "r.URL.Query.Get") still matches
# on root "r" + any of {URL, Query, Get}.
_SOURCE_ROOTS = {
    "java": {"request", "req", "httpServletRequest"},
    "go": {"r", "req", "request"},
    "ruby": {"request"},
    "rust": {"req", "request"},
    "csharp": {"Request", "HttpContext"},
}
_SOURCE_PROPS = {
    "java": {"getParameter", "getParameterValues", "getParameterMap", "getHeader",
             "getQueryString", "getRequestURI", "getCookies", "getInputStream",
             "getReader"},
    "go": {"Query", "Get", "FormValue", "PostFormValue", "Header", "URL"},
    "ruby": {"params", "query_parameters", "body", "raw_post"},
    "rust": {"query", "query_string", "form", "json", "payload", "headers", "match_info"},
    "csharp": {"QueryString", "Form", "Headers", "Cookies", "Query"},
}
# A bare root name alone (no member access needed) is itself the source —
# Ruby's `params[:x]` reads as just `params`.
_BARE_SOURCE_ROOTS = {"ruby": {"params"}}
_PHP_SUPERGLOBAL_PREFIXES = ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "$_FILES")


def _is_source(lang: str, dotted: str, extra_roots: frozenset = frozenset()) -> bool:
    if not dotted:
        return False
    if lang == "php":
        return dotted.startswith(_PHP_SUPERGLOBAL_PREFIXES)
    parts = dotted.split(".")
    if parts[0] in _BARE_SOURCE_ROOTS.get(lang, ()):
        return True
    roots = _SOURCE_ROOTS.get(lang, set()) | extra_roots
    props = _SOURCE_PROPS.get(lang, set())
    return parts[0] in roots and any(p in props for p in parts[1:])


# -------------------------------------------------------- name flattening


def _text(node) -> str:
    return node.text.decode("utf-8", "ignore")


def _dotted(lang: str, node) -> str:
    """Flatten a call/member/subscript expression into a dotted string, the
    same role `_py_dotted`/`_js_member_name` play in sast_engine.py."""
    if node is None:
        return ""
    t = node.type
    if t in _IDENT_TYPES:
        return _text(node)
    if lang == "php" and t in _PHP_VAR_TYPES:
        return _text(node)

    if lang == "java":
        if t == "method_invocation":
            obj = node.child_by_field_name("object")
            name = node.child_by_field_name("name")
            base = _dotted(lang, obj) if obj is not None else ""
            nm = _text(name) if name is not None else ""
            return f"{base}.{nm}" if base else nm
        if t == "field_access":
            obj = node.child_by_field_name("object")
            fld = node.child_by_field_name("field")
            base = _dotted(lang, obj)
            f = _text(fld) if fld is not None else ""
            return f"{base}.{f}" if base else f

    elif lang == "go":
        if t == "selector_expression":
            operand = node.child_by_field_name("operand")
            fld = node.child_by_field_name("field")
            base = _dotted(lang, operand)
            f = _text(fld) if fld is not None else ""
            return f"{base}.{f}" if base else f
        if t == "call_expression":
            return _dotted(lang, node.child_by_field_name("function"))

    elif lang == "php":
        if t == "subscript_expression":
            return _dotted(lang, node.children[0]) if node.children else ""
        if t == "member_call_expression":
            obj = node.child_by_field_name("object")
            name = node.child_by_field_name("name")
            base = _dotted(lang, obj)
            nm = _text(name) if name is not None else ""
            return f"{base}.{nm}" if base else nm
        if t == "member_access_expression":
            obj = node.child_by_field_name("object")
            name = node.child_by_field_name("name")
            base = _dotted(lang, obj)
            nm = _text(name) if name is not None else ""
            return f"{base}.{nm}" if base else nm
        if t == "function_call_expression":
            return _dotted(lang, node.child_by_field_name("function"))
        if t == "scoped_call_expression":
            return _text(node).split("(")[0].replace("::", ".")

    elif lang == "ruby":
        if t == "call":
            receiver = node.child_by_field_name("receiver")
            method = node.child_by_field_name("method")
            base = _dotted(lang, receiver) if receiver is not None else ""
            m = _text(method) if method is not None else ""
            return f"{base}.{m}" if base else m
        if t == "element_reference":
            return _dotted(lang, node.children[0]) if node.children else ""

    elif lang == "rust":
        if t == "field_expression":
            value = node.child_by_field_name("value")
            fld = node.child_by_field_name("field")
            base = _dotted(lang, value)
            f = _text(fld) if fld is not None else ""
            return f"{base}.{f}" if base else f
        if t == "call_expression":
            return _dotted(lang, node.child_by_field_name("function"))
        if t == "scoped_identifier":
            return _text(node).replace("::", ".")
        if t == "macro_invocation":
            macro = node.child_by_field_name("macro")
            return _text(macro) if macro is not None else ""

    elif lang == "csharp":
        if t == "member_access_expression":
            expr = node.child_by_field_name("expression")
            name = node.child_by_field_name("name")
            base = _dotted(lang, expr)
            nm = _text(name) if name is not None else ""
            return f"{base}.{nm}" if base else nm
        if t == "invocation_expression":
            return _dotted(lang, node.child_by_field_name("function"))
        if t == "element_access_expression":
            return _dotted(lang, node.child_by_field_name("expression"))

    return ""


def _call_args(lang: str, node) -> list:
    """The argument expression nodes of a call (named children only — tree-
    sitter already excludes punctuation like `(`/`)`/`,`)."""
    if node.type == "macro_invocation":
        tt = next((c for c in node.children if c.type == "token_tree"), None)
        return list(tt.named_children) if tt is not None else []
    args_node = node.child_by_field_name("arguments")
    if args_node is None:
        return []
    raw = list(args_node.named_children)
    # PHP and C# wrap each argument in its own single-child `argument` node.
    return [a.named_children[0] if a.type == "argument" and a.named_children else a
            for a in raw]


# ------------------------------------------------------------- assignment


def _assignment_binding(lang: str, node) -> tuple[str, object] | None:
    """Return (name, value_node) if this node binds a local name to a value
    expression, else None. Mirrors visit_Assign/VariableDeclarator."""
    t = node.type
    if lang == "java" and t == "variable_declarator":
        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name is not None and value is not None and name.type in _IDENT_TYPES:
            return _text(name), value
    if t == "assignment_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        ident_types = _IDENT_TYPES | (_PHP_VAR_TYPES if lang == "php" else set())
        if left is not None and right is not None and left.type in ident_types:
            return _text(left), right
    if lang == "ruby" and t == "assignment":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is not None and right is not None and left.type in _IDENT_TYPES:
            return _text(left), right
    if lang == "go" and t == "short_var_declaration":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is not None and right is not None:
            names = [c for c in left.named_children if c.type == "identifier"]
            exprs = list(right.named_children)
            if len(names) == 1 and len(exprs) == 1:
                return _text(names[0]), exprs[0]
    if lang == "rust" and t == "let_declaration":
        pattern = node.child_by_field_name("pattern")
        value = node.child_by_field_name("value")
        if pattern is not None and value is not None and pattern.type == "identifier":
            return _text(pattern), value
    if lang == "csharp" and t == "variable_declarator":
        name = node.child_by_field_name("name")
        if name is None:
            return None
        value = None
        for c in reversed(node.children):
            if c is not name and c.type != "=":
                value = c
                break
        if value is not None:
            return _text(name), value
    return None


# ------------------------------------------------------------- taint core


def _taint_of(lang: str, node, tainted: dict) -> tuple[str, int, list[str]] | None:
    if node is None:
        return None
    dotted = _dotted(lang, node)
    extra_roots = tainted.get("__extra_go_roots__", frozenset())
    if dotted and _is_source(lang, dotted, extra_roots):
        return (dotted, node.start_point[0] + 1, [])

    t = node.type
    if t in _IDENT_TYPES or (lang == "php" and t in _PHP_VAR_TYPES):
        return tainted.get(_text(node))

    if t in _WRAPPER_TYPES:
        inner = node.named_children
        return _taint_of(lang, inner[0], tainted) if inner else None

    if t in _CALL_TYPES.get(lang, ()):
        short = dotted.split(".")[-1] if dotted else ""
        # A method called ON a tainted object also returns tainted data —
        # e.g. PHP's `$request->input('x')` is tainted because $request is
        # a known-tainted Request-typed parameter, independent of whether
        # the call's own arguments carry taint.
        if dotted:
            root = dotted.split(".")[0]
            root_hit = tainted.get(root)
            if root_hit and "." in dotted:
                return (root_hit[0], root_hit[1], root_hit[2] + [short])
        for arg in _call_args(lang, node):
            hit = _taint_of(lang, arg, tainted)
            if hit:
                return (hit[0], hit[1], hit[2] + [short])
        return None

    if t in _BINARY_TYPES:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        return _taint_of(lang, left, tainted) or _taint_of(lang, right, tainted)

    # Member/field/subscript access that isn't itself a recognised source:
    # fall back to the taint of its root identifier (mirrors the existing
    # engines' ast.Attribute / esprima MemberExpression lookup-by-root).
    if dotted:
        root = dotted.split(".")[0]
        if root in tainted:
            return tainted[root]
    return None


def _walk(lang: str, node, tainted: dict, findings: list, rel: str, lines: list[str]) -> None:
    if node.type in _FUNC_TYPES.get(lang, ()):
        _seed_params(lang, node, tainted)

    binding = _assignment_binding(lang, node)
    if binding:
        name, value_node = binding
        hit = _taint_of(lang, value_node, tainted)
        if hit:
            tainted[name] = hit

    if node.type in _CALL_TYPES.get(lang, ()):
        callee = _dotted(lang, node)
        rule = _rule_for(callee) if callee else None
        if rule is not None:
            args = _call_args(lang, node)
            short = callee.split(".")[-1]
            # Parameterised form: query(sql, params) — the second+ argument
            # carries values separately, so an untainted query-string
            # argument is safe. Most sinks put the query first; a few
            # (mysqli_query) put the connection first instead.
            if rule.vuln_class == "sql_injection" and len(args) >= 2:
                query_idx = 1 if short in _CONN_FIRST_SQL_SINKS else 0
                if query_idx >= len(args) or _taint_of(lang, args[query_idx], tainted) is None:
                    args = []
                else:
                    args = [args[query_idx]]
            for arg in args:
                hit = _taint_of(lang, arg, tainted)
                if hit is None:
                    continue
                source_expr, source_line, sanitizers = hit
                applied = [s for s in sanitizers if s in rule.sanitizers]
                line = node.start_point[0] + 1
                findings.append(SastFinding(
                    rule=rule, file=rel, line=line,
                    source_expr=source_expr, source_line=source_line,
                    sink_expr=f"{callee}()",
                    code=(lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""),
                    sanitizers=applied,
                    steps=[f"{s}()" for s in sanitizers if s not in rule.sanitizers],
                ))
                break

    for child in node.children:
        _walk(lang, child, tainted, findings, rel, lines)


def analyze_polyglot(path: Path, rel: str, code: str, language: str) -> list[SastFinding]:
    """Per-file entry point for one of the 6 new languages. Returns `[]` (not
    an exception) on parser-unavailable or parse failure, matching
    `analyze_javascript`'s degrade-to-empty behavior."""
    if not _TS_AVAILABLE:
        return []
    try:
        parser = get_parser(language)
        tree = parser.parse(code.encode("utf-8", "ignore"))
    except Exception:
        return []

    findings: list[SastFinding] = []
    try:
        _walk(language, tree.root_node, {}, findings, rel, code.splitlines())
    except RecursionError:
        pass
    except Exception:
        return []
    return findings
