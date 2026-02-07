# Product Overview

## Description
OpenClaw Secure Stack is a hardened deployment wrapper for OpenClaw that adds security controls without modifying upstream OpenClaw code. It provides authenticated API access, prompt-injection mitigation, skill scanning and quarantine, network egress controls, governance checks, and append-only audit logging.

**Current version:** 1.2.0

## Vision
Enable teams to self-host OpenClaw in production environments with a default-secure posture, clear operational controls, and auditable security decisions.

## Target Users
- **Primary:** Platform engineers and security-conscious developers deploying OpenClaw for internal tools or automation
- **Secondary:** DevOps/SRE teams responsible for runtime hardening, auditability, and incident response

## Core Features
1. Reverse proxy protection - Enforces bearer-token authentication and request sanitization before forwarding to OpenClaw.
2. Skill security pipeline - AST-based JS/TS scanner detects dangerous APIs, exfiltration patterns, and filesystem abuse; risky skills can be quarantined.
3. Prompt injection defense - Rule-based strip/reject actions for known prompt-injection patterns.
4. Governance layer - Tool-call intent classification, policy validation, plan/session tracking, and human approval gates.
5. Webhook integrations - Secure ingress for Telegram and WhatsApp messages with HMAC verification, rate limiting, replay protection, and full governance evaluation.
6. Network isolation and egress control - Docker network segmentation plus DNS allowlisting for outbound traffic.
7. Security audit trail - Append-only JSONL events for auth, sanitizer actions, scanner/governance outcomes, and webhook relay events.

## Key Value Propositions
- Adds defense-in-depth around OpenClaw while keeping upstream compatibility.
- Reduces risk from third-party skills and prompt-level attacks before they execute.
- Improves compliance and forensics with structured, persistent audit events.
- Supports practical operations through containerized deployment and scripted installation.

## Success Metrics
- Proxy blocks 100% of unauthenticated requests in integration tests.
- Scanner catches known malicious patterns across security test corpus.
- Audit log records all critical security events with no silent drops.
- Test suite and CI checks remain green with coverage at or above configured threshold.
- New OpenClaw releases remain adoptable without patching upstream source.
