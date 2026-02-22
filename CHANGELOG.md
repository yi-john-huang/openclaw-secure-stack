# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.0] - 2026-02-22

### Added
- **Configurable upstream timeout** (`WEBHOOK_UPSTREAM_TIMEOUT`, default 120 s) — replaces the hardcoded 30 s limit; eliminates "Upstream unavailable" errors on long LLM completions (GPT-5.2 can take 30–60+ s for complex prompts)
- **HTTP connection pooling** — all three HTTP clients (`WebhookRelayPipeline`, `TelegramRelay`, `WhatsAppRelay`) now share persistent `httpx.AsyncClient` instances with keep-alive connections; eliminates the per-request TLS handshake overhead (~100–300 ms saved per message)
- **Parallel Telegram file downloads** — `build_attachments()` now downloads multiple attachments concurrently via `asyncio.gather()` instead of sequentially
- **Async PDF text extraction** — `pypdf` extraction is offloaded to a thread pool via `asyncio.to_thread()`, preventing CPU-bound work from blocking the async event loop
- **Configurable conversation history depth** (`WEBHOOK_HISTORY_MAX_TURNS`, default 20)
- **Graceful shutdown** — `@app.on_event("shutdown")` closes all pooled HTTP clients cleanly

### Fixed
- **WhatsApp `send_response` missing timeout** — added explicit `httpx.Timeout(connect=10 s, read=30 s, write=10 s)` to prevent hanging on slow Meta API responses
- **Conversation history eviction O(N) per message** — eviction scan now throttled to at most once per 60 s

### Changed
- Attachment-type extraction in `TelegramRelay` is now data-driven via a lookup table (`_ATTACHMENT_TYPES`), reducing ~70 lines of repetitive if-blocks to a single loop

## [1.5.2] - 2026-02-22

### Fixed
- **PDF content unreadable (root cause)** — replaced base64 binary forwarding with server-side text extraction via `pypdf`; the ~1.3 MB base64-encoded body was exceeding OpenClaw's gateway body limit and causing an immediate TCP reset (logged as `upstream_status: 502` in < 100 ms); extracted text is 10-100× smaller and allows Claude to actually read the document content
- **Dependency added**: `pypdf>=4.0.0`

## [1.5.1] - 2026-02-22

### Fixed
- **`send_response` ConnectTimeout** — Telegram `sendMessage` API calls now use an explicit `httpx.Timeout(connect=10s, read=30s)` instead of the default 5 s; eliminates `ConnectTimeout` errors when sending the bot reply back to users
- **PDF content unreadable by Claude** — changed PDF content block from the custom OpenAI `"file"` type to Anthropic-native `"document"` block (`{"type": "document", "source": {"type": "base64", "media_type": "application/pdf", ...}}`); Claude was ignoring the `"file"` block and responding that it couldn't see the attachment
- **Video/unsupported binary silent drop** — video and other non-image/non-PDF/non-audio attachments now send a `[video: filename]` text placeholder instead of silently omitting the content
- **`httpx.ReadError` unhandled in upstream forwarder** — added `httpx.ReadError` to the caught exceptions in `_forward_to_upstream`; previously a mid-response TCP reset caused an unhandled 500 and triggered Telegram's infinite retry loop
- **Replay protection returning 409** — changed duplicate-update response from `409 Conflict` to `200 OK` so Telegram marks the webhook delivered and advances to the next `update_id` instead of retrying indefinitely
- **File download read timeout** — increased Telegram binary download read timeout from default 5 s to 120 s; large files (e.g. ~1 MB PDFs on a slow link) were timing out mid-download

## [1.5.0] - 2026-02-21

### Added
- **Telegram file attachment support** — Telegram bot now processes images, PDFs, documents, audio, voice messages, video, and stickers instead of silently ignoring them
  - Two-step Telegram API download (`getFile` → binary fetch) with 20 MB cap pre- and post-download
  - Attachments forwarded to the upstream LLM as OpenAI multimodal content blocks (`image_url`, `input_audio`, `file`)
  - Captions on media messages are treated as the message text
  - `TelegramFileInfo` and `TelegramExtraction` dataclasses replacing the old tuple return from `extract_message()`
  - `download_file()` and `build_attachments()` methods on `TelegramRelay`; download failures are skipped gracefully with a warning log
  - `AttachmentType` enum and `Attachment` dataclass in `src/webhook/models.py`
  - `WEBHOOK_FILE_DOWNLOAD` audit event type for per-file download telemetry

### Fixed
- **Attachment filename prompt injection (P1)** — filenames from the Telegram payload (user-controlled) are now individually sanitized through `PromptSanitizer` before being appended to conversation history; filenames that trigger injection detection are replaced with their generic type label (e.g. `image`)
- **Silent drop on all-download-failure (P2)** — when a file-only Telegram message arrives but all attachment downloads fail, the bot now sends the user an actionable error message instead of silently returning HTTP 200
- **Body size check accuracy** — attachment size limit now uses the exact base64-encoded byte count `(n + 2) // 3 * 4` rather than raw byte length, correctly enforcing the 10 MB cap on the payload actually sent upstream (was ~33 % under-counted)
- **Dead code removed** — `_attachment_summary()` module-level function deleted; history summaries are built inline in `relay()` using the already-sanitized `safe_name`

## [1.4.2] - 2026-02-19

### Added
- **Per-session conversation history** (`src/webhook/history.py`) — multi-turn Telegram/WhatsApp conversations now accumulate message context sent on every upstream request; previously each relay was a cold single-message call
  - In-memory `ConversationHistory` store keyed by `{source}:{sender_id}` to prevent cross-channel ID collisions (Telegram vs WhatsApp)
  - Configurable `max_turns` truncation to bound prompt size
  - TTL-based session eviction (default 24 h) to prevent unbounded memory growth from sender churn

### Fixed
- **Docker Compose paths** — corrected `build.context` and `config/` volume path in `deploy/hybrid/docker-compose.hybrid.yml`; paths are relative to the compose file location but Dockerfile and `config/` live at the project root
- **Reproducible Docker builds** — `uv.lock` is now tracked in git (was gitignored), preventing `COPY pyproject.toml uv.lock ./` failures in Docker builds

## [1.4.1] - 2026-02-19

### Added
- **`plugins/prompt-guard/openclaw.plugin.json`** manifest added to source tree (required `id` and `configSchema` fields)
- **Telegram Bot Setup documentation** — new Part 5 in `docs/openclaw-cloudflare-tunnel-setup.md` covering BotFather registration, `.env` configuration, service restart, and `setWebhook` with `secret_token`
- **Installer health checks** — port-binding readiness check (`ss :3000`) and end-to-end proxy→OpenClaw connectivity test added to `deploy/hybrid/install-hybrid.sh`

### Fixed
- **systemd service** — use `gateway run` (foreground process) instead of `gateway start` (daemon installer) in `ExecStart`
- **Plugin config type** — write `plugins` config as `PluginsConfig` object (not array); wrong type crashed the gateway on startup
- **Gateway token** — installer now reads the actual generated token from `openclaw.json` after onboarding instead of using a placeholder
- **Dockerfile multi-arch** — removed arm64-pinned digest (broke x86_64 builds); switched to named `FROM` stage for BuildKit compatibility

## [1.4.0] - 2026-02-18

### Added
- **Hybrid deployment architecture (primary deployment method)** — combines native OpenClaw with containerized proxy
  - One-click installer (`deploy/hybrid/install-hybrid.sh`) with integrated Cloudflare Tunnel setup
  - Native OpenClaw (systemd) for better OAuth and plugin support
  - Docker proxy container for security isolation and easy updates
  - Stable release strategy (Git tags instead of main branch) to avoid TypeScript compilation errors
  - Interactive prompts for domain configuration and Cloudflare Tunnel
  - Automated pnpm installation and OpenClaw monorepo build
  - Health check verification for both services
  - Docker Compose configuration (`deploy/hybrid/docker-compose.hybrid.yml`)
  - Comprehensive documentation (`deploy/hybrid/README.md`)

### Changed
- **Simplified deployment options** — hybrid architecture is now the recommended and only supported production deployment method
- **Documentation updated** — all guides now reference hybrid deployment instead of native
  - Updated `docs/openclaw-cloudflare-tunnel-setup.md` with hybrid installer usage
  - Updated `docs/openclaw-quick-reference.md` with hybrid service management
  - Updated main `README.md` to promote hybrid as primary deployment

### Removed
- **Native deployment** (`deploy/native/`) — superseded by hybrid architecture
  - Fully-native deployment was more complex and had more failure points
  - Hybrid approach provides better balance of native benefits and containerization
  - Reduces maintenance burden of supporting multiple deployment methods

## [1.3.0] - 2026-02-17

### Added
- ~~**Native deployment for Ubuntu 24.04 LTS**~~ (deprecated in 1.4.0, use hybrid instead)

### Fixed
- ~~**Native installer critical bugs**~~ (moot - native deployment removed in 1.4.0)

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
