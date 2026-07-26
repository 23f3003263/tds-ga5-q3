import os
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import config

app = FastAPI()


def resolves_inside(path: str, root: str) -> bool:
    root = os.path.normpath(root)
    if os.path.isabs(path):
        full = os.path.normpath(path)
    else:
        full = os.path.normpath(os.path.join(root, path))
    return full == root or full.startswith(root + os.sep)


def expand_path(path: str) -> str:
    # Handle ~ and $HOME / ${HOME} expansion explicitly (don't trust os.path.expanduser
    # alone since env vars may differ), then normalize.
    p = path.replace("${HOME}", "/home/agent").replace("$HOME", "/home/agent")
    p = os.path.expanduser(p)
    if not os.path.isabs(p):
        p = os.path.normpath(os.path.join(config.READ_DIR, p))
    else:
        p = os.path.normpath(p)
    return p


def hits_secret_file(path: str, secrets: list) -> bool:
    resolved = expand_path(path)
    for secret in secrets:
        secret_norm = os.path.normpath(os.path.expanduser(secret))
        if not os.path.isabs(secret_norm):
            secret_norm = os.path.normpath(os.path.join("/home/agent", secret_norm))
        if resolved == secret_norm:
            return True
        if os.path.basename(resolved) == os.path.basename(secret_norm):
            return True
    return False


def extract_host(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return host.lower()


def contains_secret_read(text: str) -> bool:
    """Scan bash command text for any reference to the secret file, including
    obfuscated forms (~, $HOME, relative traversal, base64-wrapped)."""
    lowered = text.lower()
    for secret in config.SECRET_FILES:
        name = os.path.basename(secret).lower()
        if name in lowered:
            return True
    # crude base64 hint: if a base64 blob decodes to something containing the secret name
    import base64
    import re
    for token in re.findall(r'[A-Za-z0-9+/=]{8,}', text):
        try:
            decoded = base64.b64decode(token, validate=True).decode(errors="ignore").lower()
            for secret in config.SECRET_FILES:
                if os.path.basename(secret).lower() in decoded:
                    return True
        except Exception:
            pass
    return False


def decide(body: dict):
    tool = body.get("tool", "")

    if tool == "bash":
        command = body.get("command", "")
        if contains_secret_read(command):
            return "block", "Reading the restricted secret file is never permitted by this agent's policy."
        return "allow", "Command does not touch the restricted secret file."

    if tool == "write_file":
        path = body.get("path", "")
        if resolves_inside(path, config.WRITE_DIR):
            return "allow", "Write resolves inside the allowed build directory."
        return "block", "Write path resolves outside the allowed build directory."

    if tool == "http_request":
        url = body.get("url", "")
        host = extract_host(url)
        if host in [d.lower() for d in config.ALLOWED_DOMAINS]:
            return "allow", "Host is on the allowed domain list."
        return "block", "Host is not on the allowed domain list."

    return "allow", "Unrecognized tool type; default allow."


@app.post("/ga5/{email}/guardrail")
async def check(email: str, request: Request):
    body = await request.json()
    decision, reason = decide(body)
    return JSONResponse({"decision": decision, "reason": reason})


@app.get("/")
async def root():
    return {"status": "ok"}
