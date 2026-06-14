"""
GraphRaider — generic GraphQL security test cases.

Every case is endpoint-agnostic: the probes rely only on universal GraphQL
features (`__typename`, introspection, aliasing, batching, GET transport) so they
run against ANY GraphQL server without prior schema knowledge. Endpoint-specific
data tests (BOLA on a known object, mass-assignment on a known mutation, …) are
left to the Repeater tab, where you can craft and replay them by hand.

Each entry:
  id, name, category, refs, description, expected_pass, expected_fail
  requires_secondary        — needs a second session configured
  build_requests(config)    — returns a list of HTTP request dicts for Agent 1

config keys provided by main.py:
  endpoint                  GraphQL URL
  auth_headers              dict of headers for the primary session (incl. Content-Type)
  secondary_auth_headers    dict of headers for the secondary session
  primary_bearer            raw JWT for the primary session ("" unless auth_type == bearer)
"""
import json
from typing import List, Dict
import jwt_utils

JSON_CT = {"Content-Type": "application/json"}


def _hdrs(c: dict, which: str = "primary") -> dict:
    """Full header set (auth + Content-Type) for a session."""
    auth = c.get("secondary_auth_headers" if which == "secondary" else "auth_headers", {}) or {}
    return {**JSON_CT, **auth}


def _post(c: dict, query: str, variables=None, which: str = "primary") -> dict:
    payload = {"query": query}
    if variables is not None:
        payload["variables"] = variables
    return {"method": "POST", "url": c.get("endpoint", ""),
            "headers": _hdrs(c, which), "body": json.dumps(payload)}


# Standard, server-agnostic introspection query.
INTROSPECTION = (
    "query IntrospectionQuery { __schema { queryType { name } mutationType { name } "
    "types { kind name fields { name args { name } type { name kind } } } "
    "directives { name } } }"
)


# ─────────────────────────────────────────────
# Discovery
# ─────────────────────────────────────────────

def _introspection(c):
    return [{**_post(c, INTROSPECTION), "_label": "Full introspection query"}]


def _field_suggestions(c):
    # Deliberate typo of __typename — a chatty server replies "Did you mean __typename?"
    return [{**_post(c, "{ __typenam }"), "_label": "Typo field — probe for 'Did you mean' suggestions"}]


# ─────────────────────────────────────────────
# Denial of Service
# ─────────────────────────────────────────────

def _deep_query(c):
    # Self-referential introspection nesting — deep without needing the app schema.
    inner = "name"
    for _ in range(12):
        inner = f"ofType {{ name {inner} }}"
        inner = f"type {{ {inner} }}"
        inner = f"fields {{ {inner} }}"
    q = f"query Depth {{ __schema {{ types {{ {inner} }} }} }}"
    return [{**_post(c, q), "_label": "Deeply nested introspection (depth-limit probe)", "timeout": 30}]


def _alias_amplification(c):
    aliases = " ".join(f"a{i}: __typename" for i in range(200))
    return [{**_post(c, "{ " + aliases + " }"), "_label": "200 aliased __typename fields (amplification)"}]


def _batching(c):
    batch = [{"query": "{ __typename }"} for _ in range(10)]
    return [{"method": "POST", "url": c.get("endpoint", ""), "headers": _hdrs(c),
             "body": json.dumps(batch), "_label": "Array-batched query (10 ops)"}]


# ─────────────────────────────────────────────
# Information disclosure
# ─────────────────────────────────────────────

def _verbose_errors(c):
    return [{**_post(c, "{ thisFieldDefinitelyDoesNotExist_zzz { id } }"),
             "_label": "Invalid field — probe error verbosity / stack traces"}]


# ─────────────────────────────────────────────
# Injection (best-effort, endpoint-agnostic)
# ─────────────────────────────────────────────

def _sqli(c):
    payload = "x' OR '1'='1' -- -"
    return [{**_post(c, 'query { __type(name: "%s") { name } }' % payload),
             "_label": "SQL-style payload in argument — checks for DB error leakage"}]


def _nosqli(c):
    payload = '{"$gt":""}'
    return [{**_post(c, 'query { __type(name: %s) { name } }' % json.dumps(payload)),
             "_label": "NoSQL/operator payload in argument — checks for driver error leakage"}]


# ─────────────────────────────────────────────
# CSRF / transport
# ─────────────────────────────────────────────

def _csrf_get(c):
    return [{"method": "GET", "url": c.get("endpoint", ""),
             "headers": {k: v for k, v in _hdrs(c).items() if k.lower() != "content-type"},
             "params": {"query": "{ __typename }"},
             "_label": "GET-based query execution (CSRF / cache poisoning)"}]


def _csrf_form(c):
    hdrs = {**(c.get("auth_headers") or {}), "Content-Type": "application/x-www-form-urlencoded"}
    return [{"method": "POST", "url": c.get("endpoint", ""), "headers": hdrs,
             "body": "query={ __typename }",
             "_label": "Form-encoded body (simple-request CSRF, preflight bypass)"}]


def _security_headers(c):
    return [{**_post(c, "{ __typename }"), "_label": "Baseline request — inspect security headers"}]


def _cors(c):
    hdrs = {**_hdrs(c), "Origin": "https://evil.example.com"}
    return [{"method": "POST", "url": c.get("endpoint", ""), "headers": hdrs,
             "body": json.dumps({"query": "{ __typename }"}),
             "_label": "Cross-origin request with attacker Origin header"}]


# ─────────────────────────────────────────────
# Authentication
# ─────────────────────────────────────────────

def _unauthenticated(c):
    # Strip every auth header — only Content-Type remains.
    return [{"method": "POST", "url": c.get("endpoint", ""), "headers": dict(JSON_CT),
             "body": json.dumps({"query": INTROSPECTION}),
             "_label": "Introspection with NO credentials"}]


def _tampered_token(c):
    tok = c.get("primary_bearer", "")
    if not tok or not jwt_utils.is_jwt(tok):
        return []   # only meaningful with a JWT bearer session
    reqs = []
    try:
        reqs.append({**_post_with_bearer(c, jwt_utils.alg_none(tok)),
                     "_label": "alg=none signature-strip"})
    except Exception:
        pass
    try:
        reqs.append({**_post_with_bearer(c, jwt_utils.tamper_payload(tok, {"sub": "admin", "role": "admin"})),
                     "_label": "Tampered payload (sub/role=admin), original signature"})
    except Exception:
        pass
    return reqs


def _expired_token(c):
    tok = c.get("primary_bearer", "")
    if not tok or not jwt_utils.is_jwt(tok):
        return []
    try:
        return [{**_post_with_bearer(c, jwt_utils.expired_token(tok)),
                 "_label": "Backdated exp claim"}]
    except Exception:
        return []


def _post_with_bearer(c, bearer: str) -> dict:
    return {"method": "POST", "url": c.get("endpoint", ""),
            "headers": {**JSON_CT, "Authorization": f"Bearer {bearer}"},
            "body": json.dumps({"query": INTROSPECTION})}


# ─────────────────────────────────────────────
# Authorization (cross-session harness)
# ─────────────────────────────────────────────

def _cross_session(c):
    if not (c.get("secondary_auth_headers")):
        return []
    q = "{ __typename }"
    return [
        {**_post(c, q, which="primary"),   "_label": "[Session A] reachability probe"},
        {**_post(c, q, which="secondary"), "_label": "[Session B] reachability probe"},
    ]


# ─────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────

TEST_CASES: List[Dict] = [
    {
        "id": "TC-DISC-01", "name": "Introspection enabled", "category": "Discovery",
        "refs": "WSTG-APIT-01 · OWASP GraphQL CS",
        "description": "Production GraphQL endpoints should disable introspection so attackers can't download the full schema.",
        "expected_pass": "Introspection disabled / 400/401/403.",
        "expected_fail": "Full __schema returned to an unprivileged caller.",
        "requires_secondary": False, "build_requests": _introspection,
    },
    {
        "id": "TC-DISC-02", "name": "Field-suggestion leakage", "category": "Discovery",
        "refs": "OWASP GraphQL CS",
        "description": "'Did you mean …' hints leak valid field names even when introspection is off.",
        "expected_pass": "No suggestions in error messages.",
        "expected_fail": "Server returns 'Did you mean' suggestions.",
        "requires_secondary": False, "build_requests": _field_suggestions,
    },
    {
        "id": "TC-DOS-01", "name": "Query depth limit", "category": "Denial of Service",
        "refs": "OWASP GraphQL CS · API4:2023",
        "description": "Deeply nested queries with no depth cap can exhaust resolvers and CPU.",
        "expected_pass": "Depth/complexity limit enforced or query rejected.",
        "expected_fail": "Deep query fully resolved with no limit error.",
        "requires_secondary": False, "build_requests": _deep_query,
    },
    {
        "id": "TC-DOS-02", "name": "Alias-based amplification", "category": "Denial of Service",
        "refs": "OWASP GraphQL CS · API4:2023",
        "description": "Hundreds of aliased fields in one request multiply server work — a cheap DoS.",
        "expected_pass": "Alias / complexity limit enforced.",
        "expected_fail": "All aliases resolved without limit.",
        "requires_secondary": False, "build_requests": _alias_amplification,
    },
    {
        "id": "TC-DOS-03", "name": "Query batching", "category": "Denial of Service",
        "refs": "OWASP GraphQL CS",
        "description": "Array-batched queries enable request amplification and rate-limit / brute-force bypass.",
        "expected_pass": "Batching unsupported or rejected.",
        "expected_fail": "Server returns an array of results.",
        "requires_secondary": False, "build_requests": _batching,
    },
    {
        "id": "TC-INFO-01", "name": "Verbose error / stack-trace leakage", "category": "Information Disclosure",
        "refs": "WSTG-ERRH · API8:2023",
        "description": "Errors should not leak stack traces, file paths, or framework internals.",
        "expected_pass": "Generic error, no internals.",
        "expected_fail": "Stack trace / file path / framework details in response.",
        "requires_secondary": False, "build_requests": _verbose_errors,
    },
    {
        "id": "TC-INJ-01", "name": "SQL injection error leakage", "category": "Injection",
        "refs": "WSTG-INPV-05 · API8:2023",
        "description": "Best-effort probe: SQL metacharacters in an argument should never surface DB errors.",
        "expected_pass": "No database error text; no timing anomaly.",
        "expected_fail": "SQL error text or sleep-based timing observed.",
        "requires_secondary": False, "build_requests": _sqli,
    },
    {
        "id": "TC-INJ-02", "name": "NoSQL / operator injection leakage", "category": "Injection",
        "refs": "WSTG-INPV-05",
        "description": "Best-effort probe: operator-style payloads should not surface NoSQL driver errors.",
        "expected_pass": "No driver error text.",
        "expected_fail": "Mongo/BSON/driver error text leaked.",
        "requires_secondary": False, "build_requests": _nosqli,
    },
    {
        "id": "TC-CSRF-01", "name": "GET-based query execution", "category": "CSRF",
        "refs": "OWASP GraphQL CS · WSTG-CSRF",
        "description": "Serving queries over GET enables CSRF and cache poisoning; mutations over GET are critical.",
        "expected_pass": "GET requests rejected for GraphQL.",
        "expected_fail": "Query executes over GET.",
        "requires_secondary": False, "build_requests": _csrf_get,
    },
    {
        "id": "TC-CSRF-02", "name": "Form-encoded content type", "category": "CSRF",
        "refs": "OWASP GraphQL CS",
        "description": "Accepting non-JSON content types lets a form POST CSRF the endpoint without a preflight.",
        "expected_pass": "Only application/json accepted.",
        "expected_fail": "Form-encoded body accepted and executed.",
        "requires_secondary": False, "build_requests": _csrf_form,
    },
    {
        "id": "TC-TLS-01", "name": "Security headers", "category": "Transport",
        "refs": "WSTG-CONF-07",
        "description": "HSTS / X-Content-Type-Options should be set; X-Powered-By / verbose Server banners should not leak.",
        "expected_pass": "Headers present, no version banners.",
        "expected_fail": "Missing hardening headers or leaked version banners.",
        "requires_secondary": False, "build_requests": _security_headers,
    },
    {
        "id": "TC-TLS-02", "name": "CORS misconfiguration", "category": "Transport",
        "refs": "WSTG-CLNT-07 · API8:2023",
        "description": "An attacker Origin should not be reflected, and wildcard + credentials must never combine.",
        "expected_pass": "Origin not reflected; no wildcard+credentials.",
        "expected_fail": "Attacker origin reflected or ACAO:* with credentials.",
        "requires_secondary": False, "build_requests": _cors,
    },
    {
        "id": "TC-AUTH-01", "name": "Unauthenticated access", "category": "Authentication",
        "refs": "API2:2023 · WSTG-ATHN",
        "description": "Stripping all credentials should not return data.",
        "expected_pass": "401/403 or auth error.",
        "expected_fail": "Schema/data returned with no credentials.",
        "requires_secondary": False, "build_requests": _unauthenticated,
    },
    {
        "id": "TC-AUTH-02", "name": "Tampered / unsigned token", "category": "Authentication",
        "refs": "API2:2023 · JWT best practices",
        "description": "alg=none and tampered-payload tokens must be rejected (requires a JWT bearer session).",
        "expected_pass": "Forged/none-signature token rejected.",
        "expected_fail": "Tampered token accepted (HTTP 200 with data).",
        "requires_secondary": False, "build_requests": _tampered_token,
    },
    {
        "id": "TC-AUTH-03", "name": "Expired token accepted", "category": "Authentication",
        "refs": "API2:2023",
        "description": "A backdated exp claim must be rejected (requires a JWT bearer session).",
        "expected_pass": "Expired token rejected.",
        "expected_fail": "Expired token still resolves data.",
        "requires_secondary": False, "build_requests": _expired_token,
    },
    {
        "id": "TC-AUTHZ-01", "name": "Cross-session isolation (BOLA harness)", "category": "Authorization",
        "refs": "API1:2023 · API5:2023",
        "description": "Runs the same query under both sessions so you can compare returned IDs/records in History. "
                       "Craft a tenant-specific query in Repeater and 'Send to both' for a real BOLA test.",
        "expected_pass": "Each session sees only its own records.",
        "expected_fail": "Identical private records returned to both sessions.",
        "requires_secondary": True, "build_requests": _cross_session,
    },
]

TC_BY_ID = {t["id"]: t for t in TEST_CASES}
