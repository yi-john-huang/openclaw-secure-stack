# Product Overview

## Product Description
**Project**: openclaw-secure-stack
**Version**: 0.1.0
**Type**: Security Sidecar / Reverse Proxy

OpenClaw Secure Stack is a hardened deployment wrapper for the OpenClaw AI agent. It wraps an unmodified OpenClaw instance with enterprise-grade security controls — authentication, prompt injection mitigation, skill supply-chain scanning, quarantine management, and network egress filtering — all without modifying a single line of OpenClaw code.

## Core Features
- **Bearer Token Authentication** — constant-time token validation on every request
- **Prompt Injection Sanitizer** — regex-based detection with strip/reject actions
- **Skill Supply-Chain Scanner** — tree-sitter AST analysis + pattern matching for dangerous APIs, network exfiltration, and filesystem abuse
- **Quarantine System** — SQLite-backed quarantine with force-override and audit trail
- **Egress Allowlist** — DNS-level filtering via CoreDNS sidecar (only approved domains resolve)
- **Audit Logging** — append-only JSON Lines log for all security events
- **One-Click Deployment** — `install.sh` generates tokens, validates prereqs, launches Docker Compose

## Target Use Case
Self-hosting OpenClaw in environments where security, auditability, and network isolation are required — small teams, enterprise pilots, regulated environments.

## Key Value Proposition
Run OpenClaw safely without trusting third-party skills or exposing your infrastructure. Zero modifications to OpenClaw itself — the security stack operates as a sidecar/proxy layer.

## Target Users
- DevOps engineers deploying OpenClaw for their team
- Security-conscious developers who want LLM agent tooling without open network access
- Organizations requiring audit trails for AI agent actions

## Success Metrics
- >= 95% detection rate on known-malicious skill patterns
- Zero hardcoded secrets in codebase
- Container image < 100MB (excluding OpenClaw)
- Clone-to-running in under 5 minutes

## Technical Advantages
- **Sidecar architecture** — no upstream modifications, easy to upgrade OpenClaw independently
- **Fail-closed design** — missing config = deny all, not allow all
- **Constant-time auth** — prevents timing-based token extraction
- **AST-based scanning** — catches obfuscated patterns that regex alone misses
- **DNS-level egress** — skills cannot resolve non-allowlisted domains at all
