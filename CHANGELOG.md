# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
