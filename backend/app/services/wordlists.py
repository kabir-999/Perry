"""
Small, embedded wordlists.

Kept deliberately short to bound total requests and keep the deep scan fast.
These are common, high-signal paths — not exhaustive brute-force lists.
"""

# Directories / files worth probing on almost any web app.
DIRECTORY_WORDLIST = [
    "admin", "administrator", "login", "dashboard", "config", "backup",
    "backup.zip", "backup.tar.gz", "db.sql", "dump.sql", "test", "dev",
    "staging", "old", "tmp", "uploads", "files", "download", "private",
    "internal", "server-status", "phpinfo.php", "info.php", "debug",
    "console", "actuator", "metrics", "status", "health",
]

# Sensitive files whose mere exposure is a finding (content-verified).
SENSITIVE_FILES = [
    ".env", ".env.local", ".git/config", ".git/HEAD", ".htaccess",
    ".htpasswd", "config.php", "config.json", "settings.py", "wp-config.php",
    "credentials.json", "id_rsa", "docker-compose.yml", ".DS_Store",
]

# Common API base paths / documentation endpoints.
API_PATHS = [
    "api", "api/v1", "api/v2", "api/v1/users", "api/v1/health",
    "api/v1/config", "api/v1/status", "api/users", "api/health",
    "graphql", "openapi.json", "swagger.json", "swagger/v1/swagger.json",
    "api-docs", "api/swagger.json", ".well-known/openapi.json",
    "v1", "rest", "api/login", "api/auth",
]

# Metadata endpoints crawled first (cheap, high value).
METADATA_PATHS = ["robots.txt", "sitemap.xml", "security.txt",
                  ".well-known/security.txt"]

# Subdomain labels for lightweight DNS enumeration.
SUBDOMAIN_WORDLIST = [
    "www", "api", "app", "dev", "staging", "test", "admin", "portal",
    "mail", "webmail", "vpn", "remote", "dashboard", "internal", "beta",
    "cdn", "static", "assets", "files", "download", "git", "gitlab",
    "jenkins", "ci", "docs", "status",
]

# Parameter names to try when a page has none, for reflection/injection probes.
COMMON_PARAMS = [
    "q", "search", "id", "page", "query", "s", "keyword", "name", "url",
    "redirect", "next", "return", "file", "path", "user", "user_id",
]
