# Contributing to GraphRaider

Thanks for your interest in improving GraphRaider! Contributions of all kinds are
welcome — new test cases, bug fixes, docs, and UX polish.

By participating you agree to be respectful and constructive, and to use the tool only for
[authorized testing](SECURITY.md#authorized-use-only).

## Ways to contribute
- **New GraphQL test cases** (the most valuable contribution).
- Bug fixes and reliability improvements.
- Documentation and examples.
- UI / UX improvements to the dashboard or landing page.

## Development setup

```bash
git clone https://github.com/Satyam9927/GraphRaider.git
cd GraphRaider

# Windows
.\start.ps1

# macOS / Linux
chmod +x start.sh kill.sh && ./start.sh

# …or Docker (no local Python/Node)
docker compose up --build
```

- Backend: FastAPI + WebSocket on `:8000` (`backend/`)
- Frontend: static Express server on `:3000` (`frontend/`), landing at `/`, app at `/dashboard`
- Local config + request log are written to `storage/config.json` / `storage/request_log.json`
  and are **git-ignored** — never commit them (they contain tokens).

## Project layout
See the "Project layout" section in the [README](../README.md#project-layout).

## Adding a test case
1. Add an entry to `backend/test_cases.py` with: `id`, `name`, `category`, `refs`,
   `description`, `expected_pass`, `expected_fail`, `requires_secondary`, and a
   `build_requests(config)` function returning a list of request dicts.
2. Add a matching verdict branch in `RuleAgent3.evaluate` in `backend/agents.py`
   (keyed on the test `id`).
3. Restart the backend — the UI picks the case up automatically via `list_tests`.

Keep test cases **endpoint-agnostic** where possible (rely on universal GraphQL features
like `__typename`, introspection, aliasing, batching) so they run against any server.

## Before opening a PR
Run the same checks CI runs:

```bash
# Backend byte-compiles
python -m compileall -q backend

# Frontend JS parses
node --check frontend/server.js
node --check frontend/public/app.js
```

- Keep changes focused; one logical change per PR.
- Match the surrounding code style (no large reformatting).
- Update the [README](../README.md) / [CHANGELOG](../CHANGELOG.md) when behavior changes.
- Use ASCII hyphens (`-`) in PowerShell scripts — non-ASCII characters break Windows
  PowerShell 5.1 parsing.

## Commit & PR process
1. Fork and create a feature branch (`git checkout -b feat/my-change`).
2. Commit with clear messages.
3. Open a PR against `main` and fill in the PR template.
4. Make sure CI is green.

## Reporting bugs / requesting features
Use the [issue templates](https://github.com/Satyam9927/GraphRaider/issues/new/choose).
For security vulnerabilities **in GraphRaider**, follow [SECURITY.md](SECURITY.md) instead
of opening a public issue.
