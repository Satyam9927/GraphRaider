# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-06-15
### Added
- Initial release of **GraphRaider** — an open-source GraphQL security testing toolkit.
- **Runner**: 16 endpoint-agnostic automated test cases across 8 categories (Discovery,
  Denial of Service, Injection, Information Disclosure, CSRF, Transport, Authentication,
  Authorization) with a live console and PASS/FAIL verdicts.
- **Repeater**: Burp-style request editor with raw / headers-hidden views, session auth
  attach, proxy-aware dispatch, and saved requests.
- **History**: full request/response audit trail with one-click "Send to Repeater".
- **Checklist**: manual OWASP API Top 10 / WSTG methodology with notes and progress.
- **Settings**: Configuration, Evaluation, and Proxy sub-tabs.
- Three-agent evaluation framework (Sender / Validator / Critic) with `rule_based`,
  `hybrid`, and `full_claude` modes (Claude-assisted, with graceful fallback to rules).
- Flexible dual-session authentication: Bearer/JWT, Cookie, and Custom Header.
- Marketing landing page served at `/`; the tool runs at `/dashboard`.
- Docker support (`Dockerfile` + `docker-compose.yml`) and `start`/`kill` scripts for
  Windows (`.ps1`) and macOS/Linux (`.sh`).
- Persistent local config, results, history, saved requests, and checklist state.

[Unreleased]: https://github.com/Satyam9927/GraphRaider/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Satyam9927/GraphRaider/releases/tag/v1.0.0
