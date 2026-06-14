"""
JWT helpers for the Auth test cases.

Pure-Python encode/decode (no signature verification) so the tool can decode and
tamper with tokens for security tests without needing the signing key. These are
intentionally producing INVALID signatures — that is the point of the auth tests.
"""
import base64
import json
import time
from typing import Any, Dict


def _b64_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_token(token: str) -> Dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Not a valid JWT (expected 3 dot-separated parts)")
    header = json.loads(_b64_decode(parts[0]))
    payload = json.loads(_b64_decode(parts[1]))
    return {"header": header, "payload": payload, "sig": parts[2], "raw": token}


def _encode(header: dict, payload: dict) -> str:
    h = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}"


def tamper_payload(token: str, mods: dict) -> str:
    """Modify payload claims while keeping the original signature (which is now invalid)."""
    d = decode_token(token)
    payload = {**d["payload"], **mods}
    return f"{_encode(d['header'], payload)}.{d['sig']}"


def alg_none(token: str) -> str:
    """Strip the signature and set alg=none (classic JWT signature-bypass probe)."""
    d = decode_token(token)
    header = {**d["header"], "alg": "none"}
    return f"{_encode(header, d['payload'])}."


def expired_token(token: str) -> str:
    """Backdate the exp claim by an hour."""
    return tamper_payload(token, {"exp": int(time.time()) - 3600})


def is_jwt(token: str) -> bool:
    try:
        decode_token(token)
        return True
    except Exception:
        return False


def get_token_summary(token: str) -> dict:
    """Safe summary of token claims for UI display."""
    try:
        d = decode_token(token)
        p = d["payload"]
        exp = p.get("exp")
        return {
            "sub": p.get("sub", "—"),
            "aud": p.get("aud", "—"),
            "scope": p.get("scope", p.get("scp", "—")),
            "iss": p.get("iss", "—"),
            "exp": exp if exp else "—",
            "expired": bool(exp and int(exp) < int(time.time())),
            "alg": d["header"].get("alg", "—"),
        }
    except Exception as e:
        return {"error": str(e)}
