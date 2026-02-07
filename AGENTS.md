# AGENTS.md — Spec-Driven Development (SDD)

This project uses the SDD workflow powered by `sdd-mcp-server`.

## Development Paths

### Simple Tasks
For small features, bug fixes, and quick enhancements — just start coding with best practices.

### Full SDD Workflow
For complex features requiring formal specification:

```
Initialize → Requirements → Design → Tasks → Implement
```

Each phase builds on the previous and requires review before proceeding.

## Installed Components

The SDD components are stored in `.claude/` directories. Read the referenced files for full details.

### Skills (`.claude/skills/`)

Workflow guidance invoked via slash commands:

| Skill | Description | Path |
|-------|-------------|------|
| sdd-commit | Guide commit message and PR creation for SDD workflow. Use when committing changes, creating pull requests, or documenting changes. Invoked via /sdd-commit. | `.claude/skills/sdd-commit/` |
| sdd-design | Create technical design specifications for SDD workflow. Use when designing architecture, defining components, or creating system design documents after requirements are approved. Invoked via /sdd-design <feature-name>. | `.claude/skills/sdd-design/` |
| sdd-implement | Implementation guidelines for SDD workflow. Use when implementing features, applying TDD, checking security, or ensuring code quality. Invoked via /sdd-implement <feature-name>. | `.claude/skills/sdd-implement/` |
| sdd-requirements | Generate EARS-formatted requirements for SDD workflow. Use when starting a new feature specification, creating requirements documents, or defining acceptance criteria. Invoked via /sdd-requirements <feature-name>. | `.claude/skills/sdd-requirements/` |
| sdd-review | Perform thorough Linus-style code review focusing on correctness, maintainability, and adherence to project conventions. Use after completing implementation to ensure code quality. Invoked via /sdd-review [file-path or PR-number]. | `.claude/skills/sdd-review/` |
| sdd-security-check | Perform OWASP-aligned security audit of code. Checks for common vulnerabilities including injection, authentication flaws, sensitive data exposure, and more. Invoked via /sdd-security-check [file-path or scope]. | `.claude/skills/sdd-security-check/` |
| sdd-steering | Create project-specific steering documents for SDD workflow. Use when setting up project context, documenting technology stack, or establishing project conventions. Invoked via /sdd-steering. | `.claude/skills/sdd-steering/` |
| sdd-steering-custom | Create custom steering documents for specialized contexts. Use when you need domain-specific guidance for particular file types, modules, or workflows. Invoked via /sdd-steering-custom. | `.claude/skills/sdd-steering-custom/` |
| sdd-tasks | Generate TDD task breakdown for SDD workflow. Use when breaking down design into implementable tasks with test-first approach. Invoked via /sdd-tasks <feature-name>. | `.claude/skills/sdd-tasks/` |
| sdd-test-gen | Generate comprehensive tests following TDD methodology. Creates unit tests, integration tests, and edge case coverage. Works with existing test frameworks in the project. Invoked via /sdd-test-gen [file-path or function-name]. | `.claude/skills/sdd-test-gen/` |
| simple-task | Implement simple features with best practices. Use when adding small features, bug fixes, or quick enhancements without the full SDD workflow. Invoked via /simple-task <description>. | `.claude/skills/simple-task/` |

### Rules (`.claude/rules/`)

Always-active coding standards:

| Rule | Description | Path |
|-------|-------------|------|
| coding-style | Enforce consistent TypeScript/JavaScript coding conventions and design principles | `.claude/rules/coding-style.md` |
| error-handling | Error handling patterns and best practices | `.claude/rules/error-handling.md` |
| git-workflow | Git commit and branching conventions | `.claude/rules/git-workflow.md` |
| sdd-workflow | Spec-Driven Development process rules | `.claude/rules/sdd-workflow.md` |
| security | Security best practices aligned with OWASP Top 10 | `.claude/rules/security.md` |
| testing | Testing requirements and best practices | `.claude/rules/testing.md` |

### Agents (`.claude/agents/`)

Specialized AI personas:

| Agent | Description | Path |
|-------|-------------|------|
| architect | System design and architecture specialist | `.claude/agents/architect.md` |
| implementer | Implementation-focused agent for writing quality code | `.claude/agents/implementer.md` |
| planner | Planning and roadmap agent for project organization | `.claude/agents/planner.md` |
| reviewer | Code reviewer with direct, Linus-style feedback applying 5-layer thinking | `.claude/agents/reviewer.md` |
| security-auditor | Security specialist for OWASP-aligned vulnerability assessment | `.claude/agents/security-auditor.md` |
| tdd-guide | TDD coaching agent for test-driven development methodology | `.claude/agents/tdd-guide.md` |

### Steering (`.spec/steering/`)

Project-specific context documents:

- `.spec/steering/product.md`
- `.spec/steering/structure.md`
- `.spec/steering/tech.md`

