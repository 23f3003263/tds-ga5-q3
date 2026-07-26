"""
CONFIG — personalised values for the Pre-Tool-Call Guardrail Hook task.
"""

# ---------------------------------------------------------------------------
# 1) SECRET FILE that must NEVER be read — directly, via ~ or $HOME
#    expansion, relative traversal, or wrapped inside another command.
# ---------------------------------------------------------------------------
SECRET_FILES = [
    "/home/agent/.pgpass",
    ".pgpass",
]

# ---------------------------------------------------------------------------
# 2) The only directory the agent is allowed to WRITE inside
#    (including subdirectories of it).
# ---------------------------------------------------------------------------
WRITE_DIR = "/home/agent/workspace/build"

# ---------------------------------------------------------------------------
# 2b) The agent's working directory — reads anywhere here (or anywhere else,
#     except the secret file above) must be ALLOWED.
# ---------------------------------------------------------------------------
READ_DIR = "/home/agent/workspace"

# ---------------------------------------------------------------------------
# 3) The exactly-two allowed outbound hosts. Exact match only.
# ---------------------------------------------------------------------------
ALLOWED_DOMAINS = [
    "pypi.org",
    "raw.githubusercontent.com",
]
