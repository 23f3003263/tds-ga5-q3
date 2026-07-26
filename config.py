"""
CONFIG — fill these in from YOUR personalised assignment page (email-seed derived).
Do NOT ship the default placeholder values — the grader uses YOUR specific
secret path / write dir / domains, not these examples.
"""

# ---------------------------------------------------------------------------
# 1) SECRET FILE(S) that read_file must block.
#    Put every variant the task mentions for you: exact filename(s), and/or
#    a path fragment that should be blocked no matter where it's nested.
#    Example values shown — REPLACE with yours.
# ---------------------------------------------------------------------------
SECRET_FILES = [
    "/home/agent/.netrc",
    ".env",
    "credentials.env",
]

# ---------------------------------------------------------------------------
# 2) The single directory the agent is allowed to WRITE inside.
#    Use an absolute path. All writes must *resolve* inside this directory.
# ---------------------------------------------------------------------------
WRITE_DIR = "/home/agent/workspace"

# ---------------------------------------------------------------------------
# 2b) The directory the agent is allowed to READ from freely (its own
#     workspace). Reads inside this dir are fine UNLESS they hit a secret
#     file (checked first, before this).
# ---------------------------------------------------------------------------
READ_DIR = "/home/agent/workspace"

# ---------------------------------------------------------------------------
# 3) The exactly-two allowed network domains (host only, no scheme/port).
# ---------------------------------------------------------------------------
ALLOWED_DOMAINS = [
    "api.example.com",
    "cdn.example.org",
]
