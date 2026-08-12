"""
Deliberately vulnerable local test target for the scanner.

SAFETY: binds to 127.0.0.1 only; every "secret" is fake; the flaws are
simulated (no real filesystem/DB access). Never expose this to a network.

Run:  python3 testsite/server.py [--port 9000]
Then scan  http://127.0.0.1:9000  in the app.

It intentionally triggers: missing security headers, version disclosure,
insecure session cookie, reflected XSS, SQL-error disclosure, path traversal,
open redirect, directory listing, exposed .env / .git/config, an
unauthenticated sensitive API, and robots/sitemap/openapi discovery.
"""
from __future__ import annotations

import argparse
import html
import json
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
  <li><a href="/redirect?url=/login">Redirect</a></li>
  <li><a href="/admin">Admin</a></li>
  <li><a href="/uploads/">Uploads</a></li>
  <li><a href="/api/v1/users">API</a></li>
</ul>
"""


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
        "/admin": r_admin, "/uploads": r_uploads,
        "/.env": r_env, "/.git/config": r_git, "/backup.zip": r_backup,
        "/robots.txt": r_robots, "/sitemap.xml": r_sitemap, "/openapi.json": r_openapi,
        "/api/v1/users": r_api_users, "/api/v1/config": r_api_config,
        "/api/v1/search": r_api_search,
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
