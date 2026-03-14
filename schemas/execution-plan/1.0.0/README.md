# Execution Plan Schema v1.0.0

A machine-enforceable execution plan for deterministic, non-LLM execution.

This schema is not yet used by `PlanGenerator`. 
`PlanGenerator` currently uses config/execution-plan.json (legacy schema).

## Purpose

This schema defines the **single source of truth** for what an agent executor will perform. The plan is:

- **Generated** by an LLM planner (with injected context)
- **Validated** against this schema before execution
- **Executed** by a deterministic, non-LLM executor
- **Audited** for compliance and traceability

The executor does NOT re-interpret intent. It follows the plan exactly or refuses.

## Quick Start

Minimal valid plan:

```json
{
  "version": "1.0.0",
  "plan_id": "550e8400-e29b-41d4-a716-446655440000",
  "created_at": "2025-02-27T12:00:00Z",
  "execution_mode": "hybrid",
  "description_for_user": "Read the deployment status from Kubernetes",
  "surface_effects": {
    "touches": ["kubernetes/deployments/my-app"],
    "modifies": false,
    "creates": false,
    "deletes": false
  },
  "intent": {
    "summary": "Check current deployment status for my-app",
    "category": "read",
    "risk_level": "low",
    "five_w_one_h": {
      "who": "system",
      "what": "read deployment status",
      "where": "kubernetes cluster",
      "when": "immediate",
      "why": "user requested status check",
      "how": "kubectl get deployment"
    }
  },
  "scope": {
    "target_system": "kubernetes",
    "environment": "production"
  },
  "constraints": {
    "allow_unplanned": false,
    "max_total_operations": 1
  },
  "steps": [
    {
      "step": 1,
      "action": "Get deployment status",
      "inputs": {
        "required": [
          { "name": "deployment_name", "type": "string" }
        ],
        "optional": []
      },
      "do": {
        "tool": "k8s",
        "operation": "get",
        "target": "deployment/my-app",
        "parameters": { "namespace": "default" }
      },
      "verify": {
        "checks": [
          {
            "name": "response_received",
            "evidence": "API response status",
            "pass_condition": "response.status == 200"
          }
        ]
      },
      "on_fail": {
        "behavior": "abort_plan",
        "refuse_if": ["cluster_unreachable == true"]
      },
      "audit": {
        "record_outputs": [
          { "name": "deployment_status", "type": "object", "write_to": "log" }
        ]
      }
    }
  ],
  "abort_conditions": [
    {
      "condition": "cluster_unreachable == true",
      "reason": "Cannot reach Kubernetes cluster"
    }
  ]
}
```

## Field Provenance

Fields come from different sources during plan generation:

### LLM-Generated

These fields are produced by the planner LLM:

| Field | Description |
|-------|-------------|
| `steps[]` | The execution sequence |
| `intent.summary` | What the plan accomplishes |
| `intent.five_w_one_h` | Structured intent breakdown |
| `description_for_user` | User-facing confirmation text |
| `surface_effects` | What resources are touched/modified |
| `abort_conditions` | When to stop execution |

### Inherited / Injected

These fields come from policy, user profile, or session context:

| Field | Source |
|-------|--------|
| `user_context.*` | Authentication / session |
| `scope.environment` | Deployment context |
| `constraints.require_approval` | Policy |
| `constraints.data_sensitivity` | Policy |
| `constraints.forbidden_*` | Policy (base rules) |
| `invariants.refusal_conditions` | Policy |

### System-Generated

These fields are stamped by the runtime:

| Field | Description |
|-------|-------------|
| `version` | Schema version (always "1.0.0") |
| `plan_id` | UUID, generated at plan creation |
| `session_id` | Bound session identifier |
| `created_at` | Timestamp |
| `expires_at` | Plan TTL |

### Hybrid

These may have base values from policy, with LLM additions:

| Field | Notes |
|-------|-------|
| `constraints.forbidden_paths` | Policy sets base, LLM may add task-specific |
| `invariants.must_hold` | Policy sets base invariants, LLM adds task-specific |

## Key Concepts

### Execution Mode
 
`execution_mode` specifies how the execution engine interacts with the plan.

Allowed values:

| Mode | Description |
|-----|-------------|
| `governance_driven` | The executor strictly follows the plan. No agent decisions are allowed during execution. |
| `agent_guided` | The agent may participate during execution but must stay within the plan's constraints. |
| `hybrid` | Governance executor orchestrates execution while allowing limited agent participation. |

Most production environments should use `governance_driven`.

### Constraints

Hard limits the executor MUST enforce:

- `allow_unplanned: false` — Reject any tool call not in `steps[]`
- `max_total_operations` — Cap on total operations
- `require_sequential` — Force sequential execution
- `forbidden_*` — Global deny patterns

### Steps

Each step has:

- `do` — The actual operation (tool, operation, target, parameters)
- `verify` — How to check success (deterministic conditions)
- `on_fail` — What to do if it fails (abort, continue, etc.)
- `audit` — What to record

### Abort Conditions

Global conditions checked during execution. If any matches, the executor MUST stop immediately.

## Validation

Validate a plan against the schema:

```bash
# Using ajv-cli
ajv validate -s schema.json -d my-plan.json

# Using jsonschema (Python)
jsonschema -i my-plan.json schema.json
```

## Examples

See the `examples/` directory:

- `k8s-rollback.json` — Kubernetes rollback with approval
- `ml-deploy.json` — ML model deployment with canary
- `minimal.json` — Minimum valid plan

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) for version history.