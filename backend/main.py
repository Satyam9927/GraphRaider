"""
GraphRaider backend — FastAPI + WebSocket test runner.

Endpoints:
  GET  /health           liveness + test-case count
  GET  /config           load persisted config.json
  POST /config           persist config.json (settings, results, history, checklist, repeater)
  POST /decode-token     decode a JWT for the Settings token preview
  POST /repeater/send    proxy an arbitrary request for the Repeater tab
  WS   /ws               list_tests / run_test stream
"""
import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

import agents as ag
import jwt_utils
import proxy_log
import test_cases as tc_mod

CONFIG_PATH = os.environ.get("GRAPHRAIDER_CONFIG") or os.path.join(os.path.dirname(__file__), "config.json")
BASELINE_QUERY = json.dumps({"query": "{ __typename }"})

app = FastAPI(title="GraphRaider — GraphQL Security Tester")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]


async def _send(ws: WebSocket, msg: dict):
    msg["timestamp"] = _now()
    await ws.send_text(json.dumps(msg))


# ─────────────────────────────────────────────
# Auth header resolution
# ─────────────────────────────────────────────

def build_auth_headers(auth: dict) -> dict:
    """Translate a session's auth config into request headers."""
    if not auth:
        return {}
    kind = (auth.get("auth_type") or "bearer").lower()
    if kind == "bearer":
        tok = (auth.get("bearer_token") or "").strip()
        return {"Authorization": f"Bearer {tok}"} if tok else {}
    if kind == "cookie":
        name = (auth.get("cookie_name") or "").strip()
        val  = (auth.get("cookie_value") or "").strip()
        return {"Cookie": f"{name}={val}"} if name and val else {}
    if kind == "header":
        hn = (auth.get("header_name") or "").strip()
        hv = (auth.get("header_value") or "").strip()
        return {hn: hv} if hn and hv else {}
    return {}


def primary_bearer(auth: dict) -> str:
    if (auth or {}).get("auth_type", "bearer") == "bearer":
        return (auth or {}).get("bearer_token", "").strip()
    return ""


# ─────────────────────────────────────────────
# Config persistence
# ─────────────────────────────────────────────

@app.get("/config")
def get_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


@app.post("/config")
async def save_config(request: Request):
    body = await request.json()
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(body, f, indent=2)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True}


@app.post("/decode-token")
async def decode_token(request: Request):
    body = await request.json()
    return jwt_utils.get_token_summary(body.get("token", ""))


# ─────────────────────────────────────────────
# Repeater — send an arbitrary request
# ─────────────────────────────────────────────

@app.post("/repeater/send")
async def repeater_send(request: Request):
    body    = await request.json()
    proxy   = body.get("proxy") if body.get("proxy_enabled") else None
    headers = body.get("headers") or {}

    a1 = ag.Agent1()
    req = {
        "method":  body.get("method", "POST"),
        "url":     body.get("url", ""),
        "headers": headers,
        "body":    body.get("body"),
        "params":  body.get("params"),
        "timeout": 30,
    }
    if not req["url"]:
        return {"error": "No URL provided."}

    result = a1.send(req, proxy=proxy)
    return {
        "success":     result.success,
        "status_code": result.status_code,
        "headers":     dict(list(result.headers.items())[:40]),
        "body":        result.body,
        "latency_ms":  round(result.latency_ms, 1),
        "error":       result.error,
    }


# ─────────────────────────────────────────────
# Core test runner
# ─────────────────────────────────────────────

async def run_test(ws: WebSocket, test_id: str, config: dict):
    tc = tc_mod.TC_BY_ID.get(test_id)
    if not tc:
        await _send(ws, {"type": "error", "message": f"Unknown test ID: {test_id}"})
        return

    mode    = config.get("agent_mode", "rule_based")
    api_key = config.get("api_key", "")
    proxy   = config.get("proxy") if config.get("proxy_enabled") else None
    endpoint = config.get("endpoint", "")

    primary_auth   = config.get("primary", {})
    secondary_auth = config.get("secondary", {})
    auth_headers           = build_auth_headers(primary_auth)
    secondary_auth_headers = build_auth_headers(secondary_auth)

    a1, a2, a3 = ag.build_agents(mode, api_key)

    await _send(ws, {
        "type": "test_start", "test_id": test_id, "name": tc["name"],
        "category": tc["category"], "refs": tc.get("refs", ""),
        "description": tc.get("description", ""),
        "expected_pass": tc.get("expected_pass", ""),
        "expected_fail": tc.get("expected_fail", ""), "mode": mode,
    })

    proxy_log.clear_test(test_id)

    # Guard: secondary session required but not configured.
    if tc.get("requires_secondary") and not secondary_auth_headers:
        await _send(ws, {"type": "test_complete", "test_id": test_id, "status": "skipped",
                         "reason": "This test needs a second session — configure Session B in Settings.",
                         "findings": ["Set up Session B (bearer/cookie/header) to run cross-session tests."]})
        return

    # ── Baseline: { __typename } with primary auth ──────────────────
    baseline_req = {"method": "POST", "url": endpoint,
                    "headers": {**tc_mod.JSON_CT, **auth_headers}, "body": BASELINE_QUERY}
    await _send(ws, {"type": "agent", "agent": "Agent 1",
                     "message": "Sending baseline ({ __typename }) to confirm reachability…"})
    baseline = a1.send(baseline_req, proxy=proxy)
    proxy_log.record(test_id=test_id, label="[BASELINE] __typename", is_baseline=True,
                     method="POST", url=endpoint, req_headers=baseline_req["headers"],
                     req_body=baseline_req["body"], status_code=baseline.status_code,
                     resp_headers=baseline.headers, resp_body=baseline.body,
                     latency_ms=baseline.latency_ms, error=baseline.error)
    await _send(ws, {"type": "baseline", "status": baseline.status_code,
                     "latency_ms": round(baseline.latency_ms, 1),
                     "body_preview": baseline.body[:400], "error": baseline.error})

    if not baseline.success:
        await _send(ws, {"type": "test_complete", "test_id": test_id, "status": "error",
                         "reason": f"Endpoint unreachable: {baseline.error}",
                         "findings": ["Baseline failed — verify the endpoint URL, network, and proxy settings."]})
        return

    # ── Build attack requests ────────────────────────────────────────
    test_config = {**config, "endpoint": endpoint,
                   "auth_headers": auth_headers,
                   "secondary_auth_headers": secondary_auth_headers,
                   "primary_bearer": primary_bearer(primary_auth)}
    try:
        requests_list = tc["build_requests"](test_config)
    except Exception as e:
        await _send(ws, {"type": "test_complete", "test_id": test_id, "status": "error",
                         "reason": f"Failed to build requests: {e}", "findings": []})
        return

    if not requests_list:
        reason = ("This test needs a JWT bearer session — the configured session uses a different auth type."
                  if tc["category"] == "Authentication"
                  else "No requests produced for this test with the current configuration.")
        await _send(ws, {"type": "test_complete", "test_id": test_id, "status": "skipped",
                         "reason": reason, "findings": []})
        return

    # ── Send each request (with transport-retry loop) ───────────────
    all_results = []
    for idx, req in enumerate(requests_list):
        label = req.get("_label", f"Request {idx + 1}/{len(requests_list)}")
        safe_hdrs = {k: ("…[redacted]" if k.lower() in ("authorization", "cookie", "x-api-key")
                         else v) for k, v in req.get("headers", {}).items()}
        await _send(ws, {"type": "request", "label": label, "method": req.get("method", "POST"),
                         "url": req.get("url", ""), "headers": safe_hdrs,
                         "body": (req.get("body") or "")[:1200]})

        current = dict(req)
        result: Optional[ag.RequestResult] = None
        for attempt in range(ag.MAX_ATTEMPTS):
            await _send(ws, {"type": "agent", "agent": "Agent 1",
                             "message": f"Sending (attempt {attempt + 1}/{ag.MAX_ATTEMPTS})…"})
            result = a1.send(current, proxy=proxy)
            val = a2.validate(result, attempt, current, tc)
            await _send(ws, {"type": "agent", "agent": "Agent 2", "message": val.feedback})
            if val.can_proceed:
                break
            if val.request_mod:
                current = {**current, **val.request_mod}
            await asyncio.sleep(1.2)

        if result:
            await _send(ws, {"type": "response", "label": label, "status": result.status_code,
                             "latency_ms": round(result.latency_ms, 1),
                             "headers": dict(list(result.headers.items())[:15]),
                             "body": result.body[:2500], "error": result.error})
            proxy_log.record(test_id=test_id, label=label, is_baseline=False,
                             method=current.get("method", "POST"), url=current.get("url", ""),
                             req_headers=current.get("headers", {}), req_body=current.get("body", "") or "",
                             status_code=result.status_code, resp_headers=result.headers,
                             resp_body=result.body, latency_ms=result.latency_ms, error=result.error)
        all_results.append((req, result))

    # ── Pick the most security-relevant result, then run the Critic ──
    eval_req, eval_result = all_results[-1]
    for r_req, r_res in all_results:
        if r_res and r_res.success and r_res.status_code == 200:
            eval_req, eval_result = r_req, r_res
            break

    proxy_entries = proxy_log.get_entries_for_test(test_id)
    await _send(ws, {"type": "agent", "agent": "Agent 3 (Critic)",
                     "message": f"Evaluating — baseline HTTP {baseline.status_code}, "
                                f"{len(proxy_entries)} logged request(s)…"})
    try:
        verdict = a3.evaluate(tc, eval_req, eval_result,
                              baseline_result=baseline, proxy_entries=proxy_entries)
    except Exception as e:
        await _send(ws, {"type": "agent", "agent": "Agent 3 (Critic)",
                         "message": f"Critic error — falling back to rules. {e}"})
        verdict = ag.RuleAgent3().evaluate(tc, eval_req, eval_result,
                                           baseline_result=baseline, proxy_entries=proxy_entries)

    await _send(ws, {"type": "test_complete", "test_id": test_id,
                     "status": "pass" if verdict.passed else "fail",
                     "confidence": verdict.confidence, "reason": verdict.reason,
                     "findings": verdict.findings})


# ─────────────────────────────────────────────
# WebSocket
# ─────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await _send(ws, {"type": "error", "message": "Invalid JSON received."})
                continue

            mtype = msg.get("type")
            if mtype == "list_tests":
                await _send(ws, {"type": "test_list", "tests": [
                    {"id": t["id"], "name": t["name"], "category": t["category"],
                     "refs": t.get("refs", ""), "description": t.get("description", ""),
                     "requires_secondary": t.get("requires_secondary", False)}
                    for t in tc_mod.TEST_CASES]})
            elif mtype == "run_test":
                test_id = msg.get("test_id")
                config  = msg.get("config", {})
                if not test_id:
                    await _send(ws, {"type": "error", "message": "run_test requires test_id."})
                    continue
                if not config.get("endpoint"):
                    await _send(ws, {"type": "error", "message": "No GraphQL endpoint configured."})
                    continue
                await run_test(ws, test_id, config)
            elif mtype == "ping":
                await _send(ws, {"type": "pong"})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await _send(ws, {"type": "error", "message": str(e)})
        except Exception:
            pass


@app.get("/health")
def health():
    return {"status": "ok", "test_cases": len(tc_mod.TEST_CASES)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
