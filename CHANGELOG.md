# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-02-07

### Added
- **Webhook relay pipeline** — secure ingress for Telegram and WhatsApp messages
  - Input sanitization, prompt-injection detection, and response scanning
  - HMAC signature verification (Telegram bot token, WhatsApp app secret)
  - Rate limiting (per-sender sliding window) and replay protection (nonce + TTL)
  - Body-size enforcement before JSON parsing (10 MB limit) to prevent OOM
  - Audit logging with source attribution (`telegram` / `whatsapp`)
- **Governance wiring for webhooks** — webhook messages now pass through the governance layer (block/allow/require-approval) between sanitization and upstream forwarding
- **Quarantine seed file** — `config/quarantine-list.json` with bind-mount wiring in Docker Compose, replacing the unused named volume

### Changed
- **Auth middleware hardening** — replaced broad `/webhook/` prefix exemption with per-instance `frozenset` of registered webhook paths, preventing auth bypass on arbitrary `/webhook/*` URLs and cross-instance state leakage

### Fixed
- **Webhook body-size protection** — raw body length is now checked before `json.loads()` in both Telegram and WhatsApp handlers (previously only checked `message.text` inside the relay pipeline)
- **Plugin quarantine file mount** — Docker Compose now bind-mounts `config/quarantine-list.json` as a file instead of mounting a directory volume, matching what `plugins/prompt-guard/index.ts` expects

### Security
- Auth bypass on `/webhook/*` catch-all closed (per-instance allowlist instead of module-global mutable set)
- Governance evaluation enforced on webhook path (was accepted but never called)
- Pre-parse body-size limits prevent memory exhaustion via oversized webhook payloads
- Cross-instance auth state isolation via immutable `frozenset` constructor parameter

## [1.1.0] - 2026-02-06

### Added
- **Pre-execution governance layer** — comprehensive security framework for LLM tool execution
  - Intent classifier — categorizes tool calls (file read/write, network, code execution, system)
  - Plan generator — creates execution plans with risk assessment
  - Policy validator — evaluates plans against configurable rules (action, resource, sequence, rate policies)
  - Approval gate — human-in-the-loop approval for high-risk operations
  - Execution enforcer — validates tool calls against approved plans with HMAC-signed tokens
  - Session manager — tracks multi-turn conversations with rate limiting
  - SQLite-backed storage — persistent plans, approvals, and sessions with WAL mode
- **Governance configuration** — `config/governance-policies.json` and `config/intent-patterns.json`
- **214 new tests** — comprehensive coverage for all governance components (389 total tests)

### Security
- TOCTOU race condition prevention via atomic SQL operations with RETURNING clause
- HMAC-signed plan tokens with constant-time comparison
- Atomic compare-and-swap for approval state transitions
- Session-based rate limiting to prevent abuse

## [1.0.1] - 2026-02-04

### Changed
- **Refactored scanner rules** — extracted `ASTScanRule` base class to eliminate ~90 lines of duplicate code across `dangerous_api.py`, `fs_abuse.py`, and `network_exfil.py`
- **Consolidated test fixtures** — added factory functions (`make_audit_event()`, `make_scan_finding()`, `make_scan_report()`) to `conftest.py` for DRY test code

### Fixed
- **LSP compliance** — base class `_walk()` signature now includes `source_str` parameter, allowing proper polymorphism across all scanner rules

## [1.0.0] - 2026-02-03

### Added
- **Security audit script** (`scripts/audit.py`) — validates container hardening, network isolation, secret management, log integrity, skill security, and documentation completeness
- **Indirect prompt injection defense** — plugin-based sanitization of tool results via OpenClaw hooks
- **Caddy HTTPS reverse proxy** — TLS termination for Control UI with automatic certificate management
- **Telegram bot integration** — optional Telegram support for OpenClaw interactions
- **Egress DNS filtering** — CoreDNS-based domain allowlisting for network isolation
- **Skill scanner CLI** — tree-sitter AST-based analysis with quarantine management
- **SQLite-backed quarantine system** — persistent storage for flagged skills with admin override capability
- **JSON Lines audit logging** — append-only security event logging
- **Bearer token authentication** — constant-time comparison for API security
- **Quick start documentation** — user and developer guides in `docs/`

### Changed
- Replaced DNS allowlist with configurable forwarding
- Enabled OpenAI-compatible HTTP API (`chatCompletions` endpoint)
- Improved proxy to forward gateway token to upstream with SSE streaming support
- Updated Docker Compose configuration for better network isolation

### Fixed
- Token generation now strips base64 padding for compatibility
- Network configuration issues with proxy and internal services
- tmpfs size allocation for container operations

### Security
- All containers run with read-only filesystem, dropped capabilities, non-root user
- Network isolation via internal Docker networks
- AST-based code scanning before skill execution
- Regex-based prompt injection detection and sanitization

## [0.1.0] - 2026-01-31

### Added
- Initial release of OpenClaw Secure Stack
- Reverse proxy with authentication middleware
- Basic skill scanner with dangerous API detection
- Prompt sanitizer for injection pattern detection
- Docker Compose deployment configuration
- Comprehensive test suite (117 tests)
