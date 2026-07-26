import os
import re
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import config

app = FastAPI()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_path(path: str) -> str:
    """Collapse .. and . segments without touching the real filesystem."""
    return os.path.normpath(path)


def resolves_inside(path: str, root: str) -> bool:
    """
    True iff `path` (absolute or relative) resolves to a location that is
    the root itself or nested under it, AFTER collapsing '..' / '.'.
    Relative paths are resolved against `root` (i.e. treated as if the
    agent's cwd were the root/workspace).
    """
    root = os.path.normpath(root)
    if os.path.isabs(path):
        full = os.path.normpath(path)
    else:
        full = os.path.normpath(os.path.join(root, path))
    return full == root or full.startswith(root + os.sep)


def hits_secret_file(path: str, secrets: list) -> bool:
    """
    Block if the normalized path *is* one of the secret files, or ends with
    one of them (covers '.env' style fragments regardless of directory),
    or if a secret filename appears as a path component anywhere along the
    (already-collapsed) path — this catches attempts that climb around
    with '..' and land back on a sensitive file.
    """
    norm = normalize_path(path)
    norm_abs = norm if os.path.isabs(norm) else os.path.normpath(
        os.path.join(config.READ_DIR, norm)
    )

    for secret in secrets:
        secret_norm = os.path.normpath(secret)
        # exact match on the resolved absolute path
        if norm_abs == secret_norm:
            return True
        # match on basename (covers ".env" nested anywhere, "credentials.env" etc.)
        if os.path.basename(norm_abs) == os.path.basename(secret_norm):
            return True
        # match if the secret's own path is a suffix of the resolved path
        if norm_abs.endswith(secret_norm):
            return True
        # bare fragment (e.g. secret given as just "credentials.env" or ".env")
        if not os.path.isabs(secret) and secret in norm_abs.split(os.sep):
            return True
    return False


def extract_host(url: str) -> str:
    """Pull just the hostname (no scheme, no port, no path) from a URL."""
    if "://" not in url:
        url = "http://" + url  # let urlparse treat bare host:port/path correctly
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return host.lower()


# ---------------------------------------------------------------------------
# Core decision logic
# ---------------------------------------------------------------------------

def decide(tool: str, arguments: dict) -> str:
    tool = (tool or "").lower()

    if tool == "read_file":
        path = arguments.get("path", "")
        if hits_secret_file(path, config.SECRET_FILES):
            return "block"
        return "allow"

    if tool == "write_file":
        path = arguments.get("path", "")
        if resolves_inside(path, config.WRITE_DIR):
            return "allow"
        return "block"

    if tool in ("network", "fetch", "http", "http_request"):
        url = arguments.get("url", "")
        host = extract_host(url)
        if host in [d.lower() for d in config.ALLOWED_DOMAINS]:
            return "allow"
        return "block"

    # Unknown tool families: default-allow (adjust if spec says otherwise)
    return "allow"


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@app.post("/check")
async def check(request: Request):
    body = await request.json()

    # Accept a couple of common field-name variants so this survives minor
    # spec differences; adjust to match the EXACT spec once you've read it.
    tool = body.get("tool") or body.get("tool_name") or body.get("name")
    arguments = body.get("arguments") or body.get("input") or body.get("args") or {}

    decision = decide(tool, arguments)

    return JSONResponse({"decision": decision})


@app.get("/")
async def root():
    return {"status": "ok", "service": "guardrail-hook"}
