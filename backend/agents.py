"""
GraphRaider — three-agent evaluation framework.

  Agent 1  (Sender)    — issues the HTTP request, returns the raw result.
  Agent 2  (Validator) — decides whether the round-trip succeeded; on transport
                         failures it tells Agent 1 how to retry (timeout / SSL / backoff).
  Agent 3  (Critic)    — turns the response into a PASS / FAIL security verdict.

Three modes:
  rule_based  — all deterministic, no API key required.
  hybrid      — Agents 1 & 2 deterministic, Agent 3 (Critic) uses Claude.
  full_claude — all three agents are Claude-powered.

The rule-based Critic carries one evaluator per test id (see RuleAgent3). When a
new generic test case is added to test_cases.py, add a matching branch here.
"""
import json
import re
import time
from dataclasses import dataclass, field
from typing import Optional

# Max attempts per request (transport retries only — GraphQL queries are sent verbatim).
MAX_ATTEMPTS = 4

CRITIC_MODEL = "claude-sonnet-4-6"


# ─────────────────────────────────────────────
# Shared data classes
# ─────────────────────────────────────────────

@dataclass
class RequestResult:
    success: bool
    status_code: Optional[int]
    headers: dict
    body: str
    error: Optional[str]
    latency_ms: float


@dataclass
class ValidationResult:
    can_proceed: bool
    feedback: str
    request_mod: dict = field(default_factory=dict)


@dataclass
class CriticVerdict:
    passed: bool
    confidence: str          # high | medium | low
    reason: str
    findings: list = field(default_factory=list)


def _parse_gql(result: "RequestResult") -> tuple:
    """Return (error_messages, data) parsed from a GraphQL response body."""
    try:
        b = json.loads(result.body)
        return [e.get("message", "") for e in (b.get("errors") or [])], b.get("data")
    except Exception:
        return [], None


def _item_lists(data: dict):
    """Yield (path, items) for every {items:[...]} connection in the response data."""
    out = []
    for qname, qdata in (data or {}).items():
        if isinstance(qdata, dict) and isinstance(qdata.get("items"), list):
            out.append((qname, qdata["items"]))
        elif isinstance(qdata, list):
            out.append((qname, qdata))
    return out


# ─────────────────────────────────────────────
# Agent 1 — Sender
# ─────────────────────────────────────────────

class Agent1:
    """Issues an HTTP request and returns the raw result."""

    def send(self, req: dict, proxy: Optional[str] = None, verify_ssl: bool = True) -> RequestResult:
        import requests as _r

        method  = req.get("method", "POST")
        url     = req["url"]
        headers = req.get("headers", {})
        body    = req.get("body")
        params  = req.get("params")
        timeout = req.get("timeout", 30)
        proxies = {"http": proxy, "https": proxy} if proxy else None

        if "_verify_ssl" in req:
            verify_ssl = req["_verify_ssl"]
        if proxy:                       # routing through Burp/ZAP — let it intercept TLS
            verify_ssl = False

        start = time.time()
        try:
            resp = _r.request(
                method=method, url=url, headers=headers, data=body, params=params,
                proxies=proxies, timeout=timeout, verify=verify_ssl,
            )
            return RequestResult(
                success=True, status_code=resp.status_code, headers=dict(resp.headers),
                body=resp.text[:10000], error=None, latency_ms=(time.time() - start) * 1000,
            )
        except _r.exceptions.SSLError as e:
            return RequestResult(False, None, {}, "", f"SSL error: {e}", (time.time() - start) * 1000)
        except _r.exceptions.ConnectionError as e:
            return RequestResult(False, None, {}, "", f"Connection error: {e}", (time.time() - start) * 1000)
        except _r.exceptions.Timeout:
            return RequestResult(False, None, {}, "", "Request timed out", (time.time() - start) * 1000)
        except Exception as e:
            return RequestResult(False, None, {}, "", str(e), (time.time() - start) * 1000)


# ─────────────────────────────────────────────
# Agent 2 — Validator (rule-based)
# ─────────────────────────────────────────────

class RuleAgent2:
    """Confirms the HTTP round-trip completed; on transport failure tells Agent 1 how to retry."""

    def validate(self, result: RequestResult, attempt: int,
                 req: dict = None, tc: dict = None) -> ValidationResult:
        if result.success and result.status_code is not None:
            return ValidationResult(True, "Request completed — handing off to the Critic.")

        if attempt >= MAX_ATTEMPTS - 1:
            return ValidationResult(True, f"Max retries reached ({attempt + 1}). Last error: {result.error}")

        error = (result.error or "").lower()
        mod: dict = {}
        if "timeout" in error or "timed out" in error:
            new_timeout = (req or {}).get("timeout", 30) * 2
            mod["timeout"] = new_timeout
            fb = f"Timeout on attempt {attempt + 1} — doubling timeout to {new_timeout}s and retrying."
        elif "ssl" in error or "certificate" in error:
            mod["_verify_ssl"] = False
            fb = f"SSL error on attempt {attempt + 1}: {result.error}. Disabling cert verification for retry."
        elif "connection" in error or "refused" in error:
            fb = f"Connection error on attempt {attempt + 1}: {result.error}. Backing off 1.5s then retrying."
        else:
            fb = f"Unexpected error on attempt {attempt + 1}: {result.error}. Retrying."
        return ValidationResult(False, fb, request_mod=mod)


class ClaudeAgent2:
    """LLM-assisted transport diagnosis (full_claude mode). Falls back to rules on any error."""

    def __init__(self, api_key: str):
        import anthropic
        self.client = anthropic.Anthropic(api_key=api_key)

    def validate(self, result: RequestResult, attempt: int,
                 req: dict = None, tc: dict = None) -> ValidationResult:
        if result.success and result.status_code is not None:
            return ValidationResult(True, "Request completed — handing off to the Critic.")
        if attempt >= MAX_ATTEMPTS - 1:
            return ValidationResult(True, f"Max retries. Error: {result.error}")

        prompt = (
            "A GraphQL security-test HTTP request failed at the transport layer.\n"
            f"Test: {(tc or {}).get('id', '?')} — {(tc or {}).get('name', '?')}\n"
            f"Attempt: {attempt + 1}/{MAX_ATTEMPTS}\n"
            f"Error: {result.error}\n"
            f"Current timeout: {(req or {}).get('timeout', 30)}s\n\n"
            "Tell Agent 1 what to change for the retry. Reply JSON only:\n"
            '{"retry": true, "reason": "one sentence", '
            '"request_mod": {"timeout": null, "_verify_ssl": null}}'
        )
        try:
            resp = self.client.messages.create(
                model=CRITIC_MODEL, max_tokens=300,
                messages=[{"role": "user", "content": prompt}],
            )
            m = re.search(r"\{.*\}", resp.content[0].text, re.DOTALL)
            data = json.loads(m.group()) if m else {}
            mod = {k: v for k, v in (data.get("request_mod") or {}).items() if v is not None}
            return ValidationResult(not bool(data.get("retry", True)),
                                    f"[Claude] {data.get('reason', result.error)}", request_mod=mod)
        except Exception:
            return RuleAgent2().validate(result, attempt, req, tc)


# ─────────────────────────────────────────────
# Agent 3 — Critic (rule-based)
# ─────────────────────────────────────────────

class RuleAgent3:
    """Deterministic security verdicts, one branch per test id."""

    def evaluate(self, tc: dict, req: dict, result: RequestResult, *,
                 baseline_result=None, proxy_entries=None) -> CriticVerdict:
        if not result.success:
            return CriticVerdict(False, "high", f"Request never completed: {result.error}")

        tid    = tc["id"]
        status = result.status_code
        body   = result.body.lower()
        hdrs   = {k.lower(): v for k, v in result.headers.items()}
        msgs, data = _parse_gql(result)
        errs_l = " ".join(msgs).lower()

        # ── Introspection enabled ──────────────────────────────────────
        if tid == "TC-DISC-01":
            if "__schema" in body and ("querytype" in body or "types" in body):
                names = re.findall(r'"name"\s*:\s*"(_{0,2}[A-Za-z][\w]*)"', result.body)
                spicy = sorted({n for n in names if re.search(r"admin|internal|debug|secret|private", n, re.I)})
                f = [f"Sensitive type/field names exposed: {spicy[:8]}"] if spicy else []
                return CriticVerdict(False, "high",
                                     "Introspection is ENABLED — full schema is downloadable by anyone with endpoint access.", f)
            if status in (400, 401, 403) or "introspection" in errs_l:
                return CriticVerdict(True, "high", "Introspection appears disabled / blocked.")
            return CriticVerdict(True, "low", f"Introspection inconclusive (HTTP {status}).",
                                 ["Inspect the raw response in History."])

        # ── Field suggestions ("Did you mean") ─────────────────────────
        if tid == "TC-DISC-02":
            if "did you mean" in body:
                hints = re.findall(r'did you mean[^"]*', body)
                return CriticVerdict(False, "medium",
                                     "Field suggestions are ON — error messages leak valid field names even with introspection off.",
                                     [h[:120] for h in hints[:3]])
            return CriticVerdict(True, "high", "No 'Did you mean' suggestions in error responses.")

        # ── Deeply nested query / depth limit ──────────────────────────
        if tid == "TC-DOS-01":
            if result.latency_ms > 15000:
                return CriticVerdict(False, "high",
                                     f"No depth limit — nested query ran {result.latency_ms:.0f}ms before responding.",
                                     [f"Latency {result.latency_ms:.0f}ms suggests the server fully resolved the deep query."])
            if any(k in errs_l for k in ("depth", "too deep", "exceeds maximum", "complexity")):
                return CriticVerdict(True, "high", "Query depth/complexity limit is enforced.")
            if status == 200 and not msgs:
                return CriticVerdict(False, "medium",
                                     "Deeply nested query accepted without a depth-limit error.",
                                     ["Increase nesting depth manually to confirm a DoS ceiling."])
            return CriticVerdict(True, "medium", f"Deep query rejected (HTTP {status}).",
                                 [f"errors: {msgs[:2]}"] if msgs else [])

        # ── Alias-based amplification ───────────────────────────────────
        if tid == "TC-DOS-02":
            if any(k in errs_l for k in ("alias", "too many", "limit", "complexity", "max")):
                return CriticVerdict(True, "high", "Alias/amplification limit enforced.")
            if status == 200 and not msgs:
                return CriticVerdict(False, "medium",
                                     "Hundreds of aliased fields resolved in one request — amplification possible.",
                                     [f"Latency {result.latency_ms:.0f}ms; raise the alias count to test a DoS ceiling."])
            return CriticVerdict(True, "medium", f"Aliased request rejected (HTTP {status}).")

        # ── Query batching ─────────────────────────────────────────────
        if tid == "TC-DOS-03":
            if status == 200 and result.body.strip().startswith("["):
                try:
                    n = len(json.loads(result.body))
                except Exception:
                    n = "?"
                return CriticVerdict(False, "high",
                                     "Array-based query batching is ENABLED — request amplification / rate-limit bypass.",
                                     [f"Server returned a JSON array of {n} results."])
            return CriticVerdict(True, "high", f"Batching unsupported or rejected (HTTP {status}).")

        # ── Verbose errors / stack traces ──────────────────────────────
        if tid == "TC-INFO-01":
            sensitive = ["traceback", "stack trace", "at object.", "at module.", "/var/task",
                         "node_modules", "/opt/", "c:\\", "syntax error at", "exception in",
                         ".java:", ".py\", line", "goroutine", "panic:"]
            hits = [s for s in sensitive if s in body]
            if hits:
                return CriticVerdict(False, "high", "Stack trace / internal path leaked in error response.", hits)
            return CriticVerdict(True, "high", "No stack traces or internal paths in error responses.")

        # ── SQL / NoSQL injection markers ──────────────────────────────
        if tid in ("TC-INJ-01", "TC-INJ-02"):
            sql = ["sql syntax", "syntax error", "pg_", "unterminated", "psqlexception",
                   "sqlite", "mysql", "ora-0", "odbc", "column does not exist",
                   "operator does not exist", "mongoerror", "bson", "cast to"]
            hits = [k for k in sql if k in body]
            if hits:
                return CriticVerdict(False, "high", "Database error text leaked — injection sink reachable.", hits)
            if result.latency_ms > 5000:
                return CriticVerdict(False, "medium",
                                     f"Possible time-based injection — response took {result.latency_ms:.0f}ms.",
                                     ["A sleep payload may have executed; verify manually in Repeater."])
            return CriticVerdict(True, "high", "No database error indicators or timing anomaly.")

        # ── CSRF: GET-based execution ──────────────────────────────────
        if tid == "TC-CSRF-01":
            if status == 200 and data:
                return CriticVerdict(False, "high",
                                     "Query executed over GET — CSRF / cache-poisoning risk (state-changing ops over GET are critical).",
                                     ["Mutations served over GET would be directly CSRF-able."])
            return CriticVerdict(True, "high", f"GET-based query not served (HTTP {status}).")

        # ── CSRF: form-encoded content type ────────────────────────────
        if tid == "TC-CSRF-02":
            if status == 200 and data:
                return CriticVerdict(False, "medium",
                                     "Endpoint accepts non-JSON Content-Type — simple-request CSRF may bypass preflight.",
                                     ["application/x-www-form-urlencoded accepted; combine with cookie auth for CSRF."])
            return CriticVerdict(True, "high", f"Non-JSON content type rejected (HTTP {status}).")

        # ── Security headers ───────────────────────────────────────────
        if tid == "TC-TLS-01":
            issues = []
            if "strict-transport-security" not in hdrs:
                issues.append("Missing: Strict-Transport-Security")
            if "x-content-type-options" not in hdrs:
                issues.append("Missing: X-Content-Type-Options")
            if "x-powered-by" in hdrs:
                issues.append(f"Exposed: X-Powered-By: {hdrs['x-powered-by']}")
            if hdrs.get("server") and len(hdrs["server"]) > 8:
                issues.append(f"Verbose Server banner: {hdrs['server']}")
            if issues:
                return CriticVerdict(False, "medium", f"{len(issues)} security-header issue(s).", issues)
            return CriticVerdict(True, "high", "Expected security headers present, no version banners.")

        # ── CORS misconfiguration ──────────────────────────────────────
        if tid == "TC-TLS-02":
            acao = hdrs.get("access-control-allow-origin", "")
            acac = hdrs.get("access-control-allow-credentials", "").lower()
            if acao == "*" and acac == "true":
                return CriticVerdict(False, "high", "CRITICAL: wildcard CORS with credentials.",
                                     [f"ACAO: {acao}", f"ACAC: {acac}"])
            if "evil.example" in acao or "attacker" in acao:
                return CriticVerdict(False, "high", "Origin reflected into CORS header — any site can read responses.",
                                     [f"Reflected ACAO: {acao}", f"ACAC: {acac or 'unset'}"])
            if acao == "*":
                return CriticVerdict(False, "medium", "Wildcard CORS on an authenticated endpoint.", ["ACAO: *"])
            return CriticVerdict(True, "high", f"CORS restricted (origin: {acao or 'not reflected'}).")

        # ── Auth: unauthenticated access ───────────────────────────────
        if tid == "TC-AUTH-01":
            if status in (401, 403):
                return CriticVerdict(True, "high", f"Unauthenticated request correctly rejected (HTTP {status}).")
            if status == 200 and data and not msgs:
                return CriticVerdict(False, "high", "Endpoint returned data with NO credentials — broken authentication.",
                                     ["Unauthenticated query resolved successfully."])
            if status == 200 and msgs and any("auth" in m.lower() or "token" in m.lower() for m in msgs):
                return CriticVerdict(True, "high", "Unauthenticated request rejected via GraphQL auth error.")
            return CriticVerdict(True, "medium", f"Unauthenticated request returned HTTP {status} — review the body.")

        # ── Auth: tampered token (alg=none / bad signature) ────────────
        if tid == "TC-AUTH-02":
            if status in (401, 403):
                return CriticVerdict(True, "high", f"Tampered token rejected (HTTP {status}).")
            if status == 200 and data and not msgs:
                return CriticVerdict(False, "high", "Server accepted a token with a forged/none signature — signature not verified.",
                                     ["alg=none / tampered payload accepted (HTTP 200 with data)."])
            return CriticVerdict(True, "medium", f"Tampered token returned HTTP {status} — confirm in History.")

        # ── Auth: expired token ────────────────────────────────────────
        if tid == "TC-AUTH-03":
            if status in (401, 403):
                return CriticVerdict(True, "high", f"Expired token rejected (HTTP {status}).")
            if status == 200 and data and not msgs:
                return CriticVerdict(False, "high", "Expired token accepted — exp claim not enforced.",
                                     ["Backdated exp still resolved data."])
            return CriticVerdict(True, "medium", f"Expired token returned HTTP {status} — confirm in History.")

        # ── Cross-session / BOLA comparison ────────────────────────────
        if tid == "TC-AUTHZ-01":
            a_items, b_items = [], []
            for e in (proxy_entries or []):
                if e.get("is_baseline"):
                    continue
                lbl = e.get("label", "").lower()
                try:
                    d = json.loads(e.get("resp_body_preview") or "{}")
                except Exception:
                    continue
                for _, items in _item_lists(d.get("data") or {}):
                    (a_items if "session a" in lbl else b_items).append(len(items))
            if a_items and b_items:
                return CriticVerdict(True, "medium",
                                     "Both sessions returned data — compare records in History to confirm tenant isolation.",
                                     [f"Session A connections: {a_items}", f"Session B connections: {b_items}",
                                      "Identical IDs across sessions on private objects = BOLA/IDOR."])
            return CriticVerdict(True, "low", "Cross-session comparison ran — inspect both responses in History.",
                                 ["Manual review recommended."])

        # ── Default fallback ───────────────────────────────────────────
        if status == 200 and msgs and data is None:
            return CriticVerdict(False, "medium", "HTTP 200 with GraphQL errors and null data — query needs adjustment.",
                                 [f"errors: {msgs[:2]}"])
        if status in (400, 401, 403, 422):
            return CriticVerdict(True, "medium", f"HTTP {status} — request rejected as expected.")
        if status == 200:
            return CriticVerdict(True, "low", "HTTP 200 — inspect the response body manually.", ["Review body in History."])
        return CriticVerdict(False, "low", f"Unhandled status {status}.")


# ─────────────────────────────────────────────
# Agent 3 — Critic (Claude)
# ─────────────────────────────────────────────

class ClaudeAgent3:
    def __init__(self, api_key: str):
        import anthropic
        self.client = anthropic.Anthropic(api_key=api_key)

    def evaluate(self, tc: dict, req: dict, result: RequestResult, *,
                 baseline_result=None, proxy_entries=None) -> CriticVerdict:
        if not result.success:
            return CriticVerdict(False, "high", f"Request never completed: {result.error}")

        baseline_section = ""
        if baseline_result:
            bl = baseline_result.status_code
            note = "endpoint reachable." if bl == 200 else f"WARNING: baseline HTTP {bl}."
            baseline_section = (f"\n--- BASELINE (no-attack probe) ---\nStatus {bl} | "
                                f"{baseline_result.latency_ms:.0f}ms | {note}\n"
                                f"Body: {baseline_result.body[:200]}\n")

        proxy_section = ""
        if proxy_entries:
            lines = [f"  [{'BASE' if e['is_baseline'] else 'ATK'}] {e['label']} → "
                     f"HTTP {e.get('status_code')} ({e['latency_ms']}ms)" for e in proxy_entries]
            proxy_section = f"\n--- REQUEST LOG ({len(proxy_entries)}) ---\n" + "\n".join(lines) + "\n"

        safe_hdrs = {k: ("…[redacted]" if k.lower() in ("authorization", "cookie", "x-api-key")
                         else str(v)[:80]) for k, v in req.get("headers", {}).items()}

        prompt = (
            "You are a security critic judging one GraphQL API penetration-test case.\n\n"
            f"Test ID: {tc['id']}\nName: {tc['name']}\nCategory: {tc['category']}\n"
            f"References: {tc.get('refs', '—')}\n"
            f"PASS condition: {tc.get('expected_pass', '(unspecified)')}\n"
            f"FAIL condition: {tc.get('expected_fail', '(unspecified)')}\n"
            f"{baseline_section}{proxy_section}"
            f"\n--- ATTACK REQUEST ---\nMethod: {req.get('method', 'POST')}\nURL: {req.get('url', '')}\n"
            f"Headers: {json.dumps(safe_hdrs)}\nBody: {str(req.get('body', ''))[:500]}\n"
            f"\n--- RESPONSE ---\nHTTP {result.status_code} | {result.latency_ms:.0f}ms\n"
            f"Headers: {json.dumps(dict(list(result.headers.items())[:12]))}\n"
            f"Body: {result.body[:700]}\n"
            "\nIs the target SECURE for this case? PASS = secure/defended, FAIL = vulnerable.\n"
            'Reply JSON only: {"passed": true, "confidence": "high|medium|low", '
            '"reason": "one sentence", "findings": ["..."]}'
        )
        try:
            resp = self.client.messages.create(
                model=CRITIC_MODEL, max_tokens=500,
                messages=[{"role": "user", "content": prompt}],
            )
            m = re.search(r"\{.*\}", resp.content[0].text.strip(), re.DOTALL)
            if m:
                d = json.loads(m.group())
                return CriticVerdict(bool(d.get("passed", False)), str(d.get("confidence", "medium")),
                                     str(d.get("reason", "—")), list(d.get("findings", [])))
        except Exception as e:
            print(f"[ClaudeAgent3] {tc.get('id', '?')} API error: {e}")
        return RuleAgent3().evaluate(tc, req, result, baseline_result=baseline_result,
                                     proxy_entries=proxy_entries)


# ─────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────

def build_agents(mode: str, api_key: str = "") -> tuple:
    a1 = Agent1()
    if mode == "hybrid":
        return a1, RuleAgent2(), (ClaudeAgent3(api_key) if api_key else RuleAgent3())
    if mode == "full_claude":
        return (a1,
                ClaudeAgent2(api_key) if api_key else RuleAgent2(),
                ClaudeAgent3(api_key) if api_key else RuleAgent3())
    return a1, RuleAgent2(), RuleAgent3()
