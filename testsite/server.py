"""
Deliberately vulnerable local test target for the scanner.

SAFETY: binds to 127.0.0.1 only; every "secret" is fake; the flaws are
simulated (no real filesystem/DB access). Never expose this to a network.

Run:  python3 testsite/server.py [--port 9000]
Then scan  http://127.0.0.1:9000  in the app.

It intentionally triggers: missing security headers, version disclosure,
insecure session cookie, reflected XSS, SQL-error disclosure, path traversal,
command injection (simulated), HTTP parameter pollution, open redirect,
directory listing, exposed .env / .git/config, an unauthenticated sensitive
API, and robots/sitemap/openapi discovery.

The command-injection route NEVER executes anything: it is a deterministic
simulation that returns canned command output when shell metacharacters are
present in the input. No user-supplied string is ever run as a shell command.
"""
from __future__ import annotations

import argparse
import html
import json
import re
import time as _time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BANNER = {"Server": "TestSite/2.4.1 (Ubuntu)", "X-Powered-By": "PHP/5.4.16"}
FAKE_ENV = "APP_ENV=production\nDB_PASSWORD=EXAMPLE_NOT_REAL\nAPI_KEY=EXAMPLE_NOT_REAL_KEY\n"
FAKE_GIT = '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://git.example.invalid/app.git\n'
FAKE_PASSWD = "root:x:0:0:root:/root:/bin/bash\nappuser:x:1000:1000::/home/appuser:/bin/bash\n"
ROBOTS = "User-agent: *\nDisallow: /admin\nDisallow: /backup.zip\nDisallow: /api/v1/config\n"
OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "TestSite API", "version": "1.0.0"},
    "paths": {
        "/api/v1/users": {"get": {"summary": "List users"}},
        "/api/v1/config": {"get": {"summary": "Config"}},
        "/api/v1/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
    },
}
USERS = [
    {"id": 1, "username": "admin", "role": "admin"},
    {"id": 2, "username": "jdoe", "role": "user"},
]


def page(title, body):
    return (
        f"<!doctype html><html><head><title>{title}</title></head><body>"
        f"<h1>{title}</h1>{body}<hr><footer>TestSite v2.4.1</footer></body></html>"
    ).encode()


INDEX = """
<p>Deliberately vulnerable app for scanner testing.</p>
<ul>
  <li><a href="/login">Login</a></li>
  <li><a href="/search?q=test">Search</a></li>
  <li><a href="/products?id=1">Products</a></li>
  <li><a href="/download?file=report.pdf">Download</a></li>
  <li><a href="/command?cmd=whoami">Command</a></li>
  <li><a href="/hpp?role=user">HPP</a></li>
  <li><a href="/render?tpl=hello">Render</a></li>
  <li><a href="/fetch?url=https://example.com">Fetch</a></li>
  <li><a href="/setlang?lang=en">Language</a></li>
  <li><a href="/comments">Comments</a></li>
  <li><a href="/orders/order_a">Orders</a></li>
  <li><a href="/redirect?url=/login">Redirect</a></li>
  <li><a href="/admin">Admin</a></li>
  <li><a href="/uploads/">Uploads</a></li>
  <li><a href="/api/v1/users">API</a></li>
</ul>
"""


# In-memory stores for the stateful Phase 2 workflows (deterministic, resettable
# by restarting the process). No database, no persistence to disk.
COMMENTS: list[str] = []
ORDER_OWNERS = {"order_a": "user_a", "order_b": "user_b"}

# Recognises the arithmetic template payloads used to prove SSTI, any syntax.
_TPL_RE = re.compile(r"(?:\{\{|\$\{|<%=|#\{)\s*(\d+)\s*\*\s*(\d+)\s*(?:\}\}|\}|%>)")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def _send(self, status, body, ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in BANNER.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status, payload, extra=None):
        self._send(status, json.dumps(payload, indent=2), "application/json", extra)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = urlparse(self.path)
        route = u.path.rstrip("/") or "/"
        q = parse_qs(u.query)
        h = self.ROUTES.get(route)
        if h:
            return h(self, q)
        # Prefix routes: object-level resources, e.g. /orders/<id>.
        for prefix, handler in self.PREFIX_ROUTES:
            if route.startswith(prefix):
                return handler(self, route[len(prefix):], q)
        self._send(404, page("404", "<p>Not found.</p>"))

    def _read_body(self):
        """Return the request body parsed as JSON (dict) or a form dict."""
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            length = 0
        raw = self.rfile.read(length) if length else b""
        ctype = (self.headers.get("Content-Type") or "").lower()
        if "application/json" in ctype:
            try:
                data = json.loads(raw.decode("utf-8", "replace"))
                return data if isinstance(data, dict) else {}
            except ValueError:
                return {}
        # urlencoded form
        return {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}

    def do_POST(self):
        u = urlparse(self.path)
        route = u.path.rstrip("/") or "/"
        body = self._read_body()
        h = self.POST_ROUTES.get(route)
        if h:
            return h(self, body)
        self._send(404, page("404", "<p>Not found.</p>"))

    # pages
    def r_index(self, q):
        self._send(200, page("TestSite", INDEX))

    def r_login(self, q):
        body = '<form method="post"><input name="username"><input type="password" name="password"></form>'
        self._send(200, page("Login", body), extra={"Set-Cookie": "sessionid=b7d41f9e; Path=/"})

    def r_search(self, q):
        term = (q.get("q") or [""])[0]  # reflected unescaped -> XSS
        self._send(200, page("Search", f"<p>Results for: {term}</p>"))

    def r_products(self, q):
        pid = (q.get("id") or ["1"])[0]
        if not pid.isdigit():  # simulated SQL error
            body = (
                "<pre>ERROR: unterminated quoted string at or near \"'\"\n"
                f"SELECT * FROM products WHERE id = '{html.escape(pid)}'</pre>"
            )
            return self._send(500, page("DB error", body))
        self._send(200, page("Product", f"<p>Product #{html.escape(pid)}</p>"))

    def r_download(self, q):
        name = (q.get("file") or [""])[0]
        if "etc/passwd" in name or "../" in name:  # simulated traversal
            return self._send(200, FAKE_PASSWD, "text/plain; charset=utf-8")
        self._send(200, page("Download", f"<p>Would serve: {html.escape(name)}</p>"))

    def r_redirect(self, q):
        self._send(302, "", extra={"Location": (q.get("url") or ["/"])[0]})

    # Shell metacharacters that a naive `os.system(f"ping {cmd}")` sink would
    # let through. Presence of any of these in the input is what a real command
    # injection would exploit; here we only *simulate* the resulting output.
    _CMD_METACHAR = re.compile(r"[;|&`]|\$\(")

    def r_command(self, q):
        """Simulated command-injection sink.

        SAFETY: nothing is ever executed. When the input contains shell
        metacharacters (the condition a real vulnerable sink would fail on) we
        return canned `id` output so the scanner's command-injection detector
        can observe evidence; otherwise we echo a benign, HTML-escaped result.
        """
        cmd = (q.get("cmd") or [""])[0]
        if self._CMD_METACHAR.search(cmd):
            body = "uid=1000(scanner) gid=1000(scanner) groups=1000(scanner)\n"
            return self._send(200, body, "text/plain; charset=utf-8")
        self._send(200, page("Command", f"<p>Pinging host: {html.escape(cmd)}</p>"))

    def r_hpp(self, q):
        """HTTP parameter pollution: ambiguous duplicate handling.

        With a single value the response is short; with duplicates the LAST
        value wins, is reflected, and an extra 'elevated' block is rendered —
        so a duplicated request differs meaningfully and reflects the second
        value, exactly what the HPP detector looks for. Deterministic; no
        framework-specific undefined behaviour.
        """
        roles = q.get("role") or []
        selected = roles[-1] if roles else "guest"
        body = f"<p>Effective role: {html.escape(selected)}</p>"
        if len(roles) > 1:
            body += (
                "<div class='elevated'>Duplicate 'role' parameters detected; the "
                "final value overrode the earlier one (parameter pollution) and "
                "elevated content was rendered for it.</div>"
            )
        self._send(200, page("HPP", body))

    # --- Phase 2 vulnerable routes (all deterministic simulations) ---------
    def r_render(self, q):
        """SSTI: evaluate an arithmetic template expression server-side.

        SAFETY: only `<int>*<int>` inside a template delimiter is ever computed
        (via int parsing), never arbitrary template/code execution."""
        tpl = (q.get("tpl") or [""])[0]
        m = _TPL_RE.search(tpl)
        if m:
            return self._send(200, page("Render", f"<p>{int(m.group(1)) * int(m.group(2))}</p>"))
        self._send(200, page("Render", f"<p>{html.escape(tpl)}</p>"))

    def r_fetch(self, q):
        """SSRF: simulate a server-side fetch. SAFETY: never makes a real
        outbound request — it echoes deterministic evidence for any URL."""
        target = (q.get("url") or [""])[0]
        if target.startswith(("http://", "https://", "//")):
            body = f"Fetched {html.escape(target)}\nSSRF-FETCHED"
            return self._send(200, body, "text/plain; charset=utf-8")
        self._send(200, page("Fetch", "<p>Provide a url parameter.</p>"))

    def r_fetch_safe(self, q):
        target = (q.get("url") or [""])[0]
        self._send(200, page("Fetch (safe)",
                             f"<p>Outbound fetch to {html.escape(target)} is blocked "
                             "by the allow-list.</p>"))

    def r_setlang(self, q):
        """CRLF: reflect the value into a response header. SAFETY: the injected
        header is parsed and re-emitted as a clean header (no raw CRLF is ever
        written to the socket)."""
        value = (q.get("lang") or [""])[0]
        extra = {}
        if "\r\n" in value:
            injected = value.split("\r\n", 1)[1]
            if ":" in injected:
                name, _, val = injected.partition(":")
                if name.strip() and val.strip():
                    extra[name.strip()] = val.strip()
        self._send(200, page("Language", "<p>Language preference saved.</p>"), extra=extra or None)

    def r_comments_get(self, q):
        rendered = "".join(f"<li>{c}</li>" for c in COMMENTS)  # rendered RAW (vuln)
        self._send(200, page("Comments", f"<ul>{rendered}</ul>"
                             '<form method="post" action="/comments">'
                             '<input name="comment"></form>'))

    def r_comments_safe_get(self, q):
        rendered = "".join(f"<li>{html.escape(c)}</li>" for c in COMMENTS)
        self._send(200, page("Comments (safe)", f"<ul>{rendered}</ul>"))

    def r_order(self, oid, q):
        """IDOR: return any object by id, ignoring the caller's identity."""
        oid = oid.strip("/")
        if oid not in ORDER_OWNERS:
            return self._json(404, {"error": "not found"})
        self._json(200, {"id": oid, "owner": ORDER_OWNERS[oid]})

    def r_order_safe(self, oid, q):
        oid = oid.strip("/")
        if oid not in ORDER_OWNERS:
            return self._json(404, {"error": "not found"})
        auth = self.headers.get("Authorization", "")
        ident = "user_a" if "user-a" in auth else ("user_b" if "user-b" in auth else "")
        if ORDER_OWNERS[oid] != ident:
            return self._json(403, {"error": "forbidden"})
        self._json(200, {"id": oid, "owner": ORDER_OWNERS[oid]})

    # --- Phase 2 POST routes ----------------------------------------------
    def r_comments_post(self, body):
        COMMENTS.append(body.get("comment", ""))
        self._send(302, "", extra={"Location": "/comments"})

    def r_nosql_login(self, body):
        """NoSQLi: authenticate whenever the password is a non-string (operator
        or type confusion) — the classic unsanitised NoSQL query bug."""
        pw = body.get("password")
        if not isinstance(pw, str):
            return self._json(200, {"authenticated": True, "token": "nosql-bypass"})
        if pw == "correct-horse":
            return self._json(200, {"authenticated": True})
        self._json(401, {"authenticated": False})

    def r_change_email(self, body):
        """CSRF (vulnerable): accepts the change with no token / Origin check and
        sets a session cookie with no SameSite."""
        self._send(200, page("Profile", "<p>Email updated.</p>"),
                   extra={"Set-Cookie": "sid=deadbeef; Path=/"})

    def r_change_email_safe(self, body):
        origin = self.headers.get("Origin", "")
        if origin and "127.0.0.1" not in origin and "localhost" not in origin:
            return self._send(403, page("Forbidden", "<p>Cross-site origin rejected.</p>"))
        self._send(200, page("Profile", "<p>Email updated.</p>"),
                   extra={"Set-Cookie": "sid=deadbeef; Path=/; SameSite=Strict"})

    # --- Phase 2 Batch 2: expanded SQLi + auth/session --------------------
    def r_items(self, q):
        """Boolean-based blind SQLi: the result set changes with the injected
        boolean condition (deterministic simulation; no real SQL)."""
        raw = (q.get("id") or ["1"])[0]
        if "1=2" in raw or "'1'='2" in raw:
            body = "<p>No items found.</p>"
        else:
            body = "<ul><li>Widget</li><li>Gadget</li><li>Gizmo</li></ul>"
        self._send(200, page("Items", body))

    def r_timedb(self, q):
        """Time-based blind SQLi: a SLEEP(n) payload delays the response.
        SAFETY: the delay is parsed from the payload and capped; no SQL runs."""
        raw = (q.get("id") or ["1"])[0]
        m = re.search(r"sleep\(\s*([0-9.]+)\s*\)", raw, re.I) or \
            re.search(r"pg_sleep\(\s*([0-9.]+)", raw, re.I)
        if m:
            try:
                _time.sleep(min(float(m.group(1)), 3.0))
            except ValueError:
                pass
        self._send(200, page("Item", "<p>ok</p>"))

    def r_auth_session(self, q):
        self._send(200, page("Session", "<p>Anonymous session started.</p>"),
                   extra={"Set-Cookie": "sid=FIXED123; Path=/"})

    def r_account(self, q):
        """Protected page. VULNERABLE: accepts any presented session id and
        never invalidates it (so logout/expiry do not take effect)."""
        if "sid=" in (self.headers.get("Cookie") or ""):
            return self._send(200, page("Account", "<p>Your account details.</p>"))
        self._send(401, page("Unauthorized", "<p>Login required.</p>"))

    def r_auth_logout(self, q):
        # Does NOT invalidate the server-side session (the weakness under test).
        self._send(200, page("Logout", "<p>You have been logged out.</p>"))

    def r_auth_login(self, body):
        """Username enumeration (distinct messages) + session fixation (keeps the
        pre-auth id after a successful login)."""
        user, pw = body.get("username", ""), body.get("password", "")
        if user == "admin":
            if pw == "admin-pass":
                return self._send(200, page("Welcome", "<p>Welcome, admin.</p>"),
                                  extra={"Set-Cookie": "sid=FIXED123; Path=/"})
            return self._send(401, page("Login", "<p>Incorrect password for admin.</p>"))
        self._send(404, page("Login", "<p>No such user.</p>"))

    def r_auth_reset(self, body):
        # Reset token is never consumed -> reusable (the weakness under test).
        if body.get("token") == "valid-reset-token":
            return self._json(200, {"reset": True})
        self._json(400, {"error": "invalid token"})

    def r_admin(self, q):
        self._send(200, page("Admin", "<p>No authentication enforced.</p>"))

    def r_uploads(self, q):
        body = "<p>Index of /uploads/</p><pre><a href='db-dump.sql'>db-dump.sql</a>\n<a href='employees.csv'>employees.csv</a></pre>"
        self._send(200, page("Uploads", body))

    def r_env(self, q):
        self._send(200, FAKE_ENV, "text/plain; charset=utf-8")

    def r_git(self, q):
        self._send(200, FAKE_GIT, "text/plain; charset=utf-8")

    def r_backup(self, q):
        self._send(200, b"PK\x03\x04FAKE-ZIP", "application/zip")

    def r_robots(self, q):
        self._send(200, ROBOTS, "text/plain; charset=utf-8")

    def r_sitemap(self, q):
        host = self.headers.get("Host", "localhost")
        urls = "".join(f"<url><loc>http://{host}{p}</loc></url>" for p in ("/", "/login", "/search"))
        self._send(200, f'<?xml version="1.0"?><urlset>{urls}</urlset>', "application/xml")

    def r_openapi(self, q):
        self._json(200, OPENAPI)

    def r_api_users(self, q):  # unauthenticated sensitive data
        self._json(200, {"users": USERS})

    def r_api_config(self, q):
        self._json(200, {"debug": True, "api_key": "EXAMPLE_NOT_REAL_KEY",
                         "database": {"host": "db.internal.invalid"}})

    def r_api_search(self, q):
        self._json(200, {"query": (q.get("q") or [""])[0], "results": []},
                   extra={"Access-Control-Allow-Origin": "*",
                          "Access-Control-Allow-Credentials": "true"})

    ROUTES = {
        "/": r_index, "/login": r_login, "/search": r_search,
        "/products": r_products, "/download": r_download, "/redirect": r_redirect,
        "/command": r_command, "/hpp": r_hpp,
        # Phase 2 (vulnerable + safe variants)
        "/render": r_render, "/fetch": r_fetch, "/fetch-safe": r_fetch_safe,
        "/setlang": r_setlang, "/comments": r_comments_get,
        "/comments-safe": r_comments_safe_get,
        "/items": r_items, "/timedb": r_timedb,
        "/auth/session": r_auth_session, "/account": r_account,
        "/auth/logout": r_auth_logout,
        "/admin": r_admin, "/uploads": r_uploads,
        "/.env": r_env, "/.git/config": r_git, "/backup.zip": r_backup,
        "/robots.txt": r_robots, "/sitemap.xml": r_sitemap, "/openapi.json": r_openapi,
        "/api/v1/users": r_api_users, "/api/v1/config": r_api_config,
        "/api/v1/search": r_api_search,
    }

    # Object-level (prefix) routes: /orders/<id> and its protected variant.
    PREFIX_ROUTES = [
        ("/orders-safe/", r_order_safe),
        ("/orders/", r_order),
    ]

    POST_ROUTES = {
        "/comments": r_comments_post,
        "/api/v1/nosql/login": r_nosql_login,
        "/profile/change-email": r_change_email,
        "/profile/change-email-safe": r_change_email_safe,
        "/auth/login": r_auth_login,
        "/auth/reset": r_auth_reset,
    }


# Alias used by the test suite's in-process fixture.
TestSiteHandler = Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9000)
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)  # loopback only
    print(f"Vulnerable test target: http://127.0.0.1:{args.port}  (Ctrl-C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.server_close()


if __name__ == "__main__":
    main()
