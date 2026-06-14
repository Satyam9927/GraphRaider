## Summary
What does this PR do, and why?

Closes #<!-- issue number, if any -->

## Type of change
- [ ] Bug fix
- [ ] New test case
- [ ] New feature / enhancement
- [ ] Documentation
- [ ] Refactor / chore

## Checklist
- [ ] I read [CONTRIBUTING.md](CONTRIBUTING.md).
- [ ] Backend byte-compiles: `python -m compileall -q backend`
- [ ] Frontend JS parses: `node --check frontend/server.js && node --check frontend/public/app.js`
- [ ] No secrets committed (`config.json` / tokens / cookies stay out of git).
- [ ] PowerShell scripts use ASCII hyphens only (no `—`/non-ASCII).
- [ ] Updated README / CHANGELOG if behavior changed.

## New test case (if applicable)
- Added entry in `backend/test_cases.py` and a matching verdict branch in `backend/agents.py`.
- Test is endpoint-agnostic where possible.

## Screenshots / notes
Anything reviewers should see.
