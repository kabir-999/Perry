"""
Polyglot SAST — one true-positive + one true-negative per new language
(Java, Go, PHP, Ruby, Rust, C#), verified against real tree-sitter parses.
"""
from pathlib import Path

import pytest

from app.services.polyglot_sast import _TS_AVAILABLE, analyze_polyglot

pytestmark = pytest.mark.skipif(not _TS_AVAILABLE, reason="tree-sitter not installed")


def _analyze(lang: str, code: str):
    return analyze_polyglot(Path("x"), "x", code, lang)


# --------------------------------------------------------------------- Java

def test_java_sql_injection_true_positive():
    code = (
        'class A { void f() { Statement st = con.createStatement(); '
        'String s = req.getParameter("x"); st.executeQuery("SELECT " + s); } }'
    )
    findings = _analyze("java", code)
    assert any(f.rule.vuln_class == "sql_injection" for f in findings)


def test_java_path_traversal_true_positive():
    code = (
        'class A { void f() { String p = req.getParameter("x"); '
        'byte[] b = Files.readAllBytes(p); } }'
    )
    findings = _analyze("java", code)
    assert any(f.rule.vuln_class == "path_traversal" for f in findings)


def test_java_no_taint_no_finding():
    code = 'class A { void f() { con.createStatement().executeQuery("SELECT 1"); } }'
    assert _analyze("java", code) == []


# ---------------------------------------------------------------------- Go

def test_go_command_injection_true_positive():
    code = (
        'package main\n'
        'func f(r *http.Request) { c := r.FormValue("cmd"); exec.Command(c) }\n'
    )
    findings = _analyze("go", code)
    assert any(f.rule.vuln_class == "command_injection" for f in findings)


def test_go_sql_injection_true_positive():
    code = (
        'package main\n'
        'func f(r *http.Request) { q := r.URL.Query().Get("x"); db.Query("SELECT " + q) }\n'
    )
    findings = _analyze("go", code)
    assert any(f.rule.vuln_class == "sql_injection" for f in findings)


def test_go_parameterized_query_is_safe():
    code = (
        'package main\n'
        'func f(r *http.Request) { db.Query("SELECT * WHERE id = ?", r.URL.Query().Get("id")) }\n'
    )
    assert _analyze("go", code) == []


# --------------------------------------------------------------------- PHP

def test_php_sql_injection_true_positive():
    code = '<?php $x = $_GET["x"]; mysqli_query($conn, "SELECT " . $x); ?>'
    findings = _analyze("php", code)
    assert any(f.rule.vuln_class == "sql_injection" for f in findings)


def test_php_path_traversal_true_positive():
    code = '<?php $x = $_GET["file"]; file_get_contents($x); ?>'
    findings = _analyze("php", code)
    assert any(f.rule.vuln_class == "path_traversal" for f in findings)


def test_php_prepared_statement_is_safe():
    code = (
        '<?php $x = $_GET["x"]; $stmt = $conn->prepare("SELECT * WHERE id = ?"); '
        '$stmt->execute([$x]); ?>'
    )
    assert _analyze("php", code) == []


# -------------------------------------------------------------------- Ruby

def test_ruby_command_injection_true_positive():
    code = 'x = params[:x]\nsystem(x)\n'
    findings = _analyze("ruby", code)
    assert any(f.rule.vuln_class == "command_injection" for f in findings)


def test_ruby_open_redirect_true_positive():
    code = 'x = params[:x]\nredirect_to(x)\n'
    findings = _analyze("ruby", code)
    assert any(f.rule.vuln_class == "open_redirect" for f in findings)


def test_ruby_sql_injection_true_positive():
    code = 'x = params[:x]\ndb.execute("SELECT " + x)\n'
    findings = _analyze("ruby", code)
    assert any(f.rule.vuln_class == "sql_injection" for f in findings)


def test_ruby_no_taint_no_finding():
    code = 'x = "static"\nsystem(x)\n'
    assert _analyze("ruby", code) == []


# -------------------------------------------------------------------- Rust

def test_rust_path_traversal_true_positive():
    code = 'fn f() { let x = req.query("x"); let data = std::fs::read_to_string(x); }'
    findings = _analyze("rust", code)
    assert any(f.rule.vuln_class == "path_traversal" for f in findings)


def test_rust_sql_injection_true_positive():
    code = (
        'fn f() { let x = req.query("x"); '
        'conn.execute(&format!("SELECT {}", x)); }'
    )
    findings = _analyze("rust", code)
    assert any(f.rule.vuln_class == "sql_injection" for f in findings)


def test_rust_no_taint_no_finding():
    code = 'fn f() { let x = String::from("safe"); conn.execute(&x); }'
    assert _analyze("rust", code) == []


# ------------------------------------------------------------------- C#

def test_csharp_command_injection_true_positive():
    code = (
        'class A { void f() { string x = Request.QueryString["x"]; '
        'Process.Start(x); } }'
    )
    findings = _analyze("csharp", code)
    assert any(f.rule.vuln_class == "command_injection" for f in findings)


def test_csharp_path_traversal_true_positive():
    code = (
        'class A { void f() { string x = Request.QueryString["x"]; '
        'string data = File.ReadAllText(x); } }'
    )
    findings = _analyze("csharp", code)
    assert any(f.rule.vuln_class == "path_traversal" for f in findings)


def test_csharp_no_taint_no_finding():
    code = 'class A { void f() { Process.Start("notepad.exe"); } }'
    assert _analyze("csharp", code) == []


# ------------------------------------------ framework parameter binding
#
# Real frameworks bind input onto handler parameters (annotations/types),
# not raw platform calls — without recognizing this, idiomatic modern code
# looks falsely "clean". These are the exact patterns that motivated adding
# _seed_params: a Spring/ASP.NET/Laravel/axum/typed-Go handler with zero
# raw request.getParameter()-style calls anywhere in it.

def test_java_spring_request_param_annotation_is_tainted():
    code = (
        'class C { @GetMapping("/x") String h(@RequestParam String x) { '
        'Statement st = con.createStatement(); '
        'return st.executeQuery("SELECT " + x); } }'
    )
    findings = _analyze("java", code)
    assert any(f.rule.vuln_class == "sql_injection" for f in findings)


def test_csharp_aspnet_fromquery_attribute_is_tainted():
    code = 'class C { void H([FromQuery] string x) { Process.Start(x); } }'
    findings = _analyze("csharp", code)
    assert any(f.rule.vuln_class == "command_injection" for f in findings)


def test_php_laravel_request_typed_parameter_is_tainted():
    code = (
        '<?php function h(Request $request) { $x = $request->input("x"); '
        'mysqli_query($conn, "SELECT " . $x); } ?>'
    )
    findings = _analyze("php", code)
    assert any(f.rule.vuln_class == "sql_injection" for f in findings)


def test_rust_axum_query_extractor_is_tainted():
    code = 'fn h(Query(x): Query<Params>) { conn.execute(&format!("SELECT {}", x)); }'
    findings = _analyze("rust", code)
    assert any(f.rule.vuln_class == "sql_injection" for f in findings)


def test_go_differently_named_request_parameter_is_tainted():
    code = (
        'package main\n'
        'func handler(w http.ResponseWriter, incoming *http.Request) { '
        'x := incoming.FormValue("x"); exec.Command(x) }\n'
    )
    findings = _analyze("go", code)
    assert any(f.rule.vuln_class == "command_injection" for f in findings)


def test_java_method_without_binding_annotation_stays_untainted():
    code = 'class C { String h(String x) { return con.createStatement().executeQuery("SELECT " + x); } }'
    assert _analyze("java", code) == []


# ---------------------------------------------------------- degradation

def test_unavailable_tree_sitter_degrades_to_empty(monkeypatch):
    import app.services.polyglot_sast as mod
    monkeypatch.setattr(mod, "_TS_AVAILABLE", False)
    assert mod.analyze_polyglot(Path("x"), "x", "system(x)", "ruby") == []
