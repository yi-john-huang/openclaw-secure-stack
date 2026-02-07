/**
 * OpenClaw plugin: Prompt Guard
 *
 * Registers two hooks:
 * - `tool_result_persist`: scans tool results for indirect prompt injection
 *   patterns before they enter the agent context.
 * - `before_tool_call`: defense-in-depth governance check that verifies
 *   governance headers are present before allowing high-risk tool calls.
 */

import { readFileSync, appendFileSync } from "fs";
import { join } from "path";

interface Rule {
  id: string;
  name: string;
  pattern: string;
  action: "strip" | "flag";
  description: string;
}

interface CompiledRule {
  rule: Rule;
  regex: RegExp;
}

interface Detection {
  ruleId: string;
  ruleName: string;
  action: string;
  timestamp: string;
}

interface ToolCallInput {
  name: string;
  arguments: object;
  context?: {
    headers?: Record<string, string>;
  };
}

interface BeforeToolCallResult {
  allow: boolean;
  reason?: string;
}

const RULES_PATH =
  process.env.INDIRECT_RULES_PATH ||
  join(__dirname, "../../config/indirect-injection-rules.json");

const LOG_PATH =
  process.env.PROMPT_GUARD_LOG_PATH ||
  join(
    process.env.HOME || "/tmp",
    ".openclaw/prompt-guard-detections.jsonl"
  );

// FR-4.4: Enforcement toggle — set to "false" to disable pre-execution blocking
const enforcementEnabled = process.env.PROMPT_GUARD_ENFORCEMENT !== "false";

// SEC-D-08: High-risk tool categories that require governance evaluation
const HIGH_RISK_PREFIXES = ["exec", "shell", "bash", "run_command", "file_write", "write_file", "delete", "rm"];

// FR-4.2: Quarantine list loaded from shared config
const QUARANTINE_LIST_PATH =
  process.env.QUARANTINE_LIST_PATH ||
  join(__dirname, "../../config/quarantine-list.json");

let compiledRules: CompiledRule[] = [];
let quarantineList: string[] = [];

function loadRules(): void {
  try {
    const raw = readFileSync(RULES_PATH, "utf-8");
    const rules: Rule[] = JSON.parse(raw);
    compiledRules = rules.map((rule) => ({
      rule,
      regex: new RegExp(rule.pattern, "gi"),
    }));
  } catch {
    console.error(`[prompt-guard] Failed to load rules from ${RULES_PATH}`);
    compiledRules = [];
  }
}

function loadQuarantineList(): void {
  try {
    const raw = readFileSync(QUARANTINE_LIST_PATH, "utf-8");
    quarantineList = JSON.parse(raw);
  } catch {
    quarantineList = [];
  }
}

function logDetection(detection: Detection): void {
  try {
    appendFileSync(LOG_PATH, JSON.stringify(detection) + "\n");
  } catch {
    // Best-effort logging — don't crash the hook
  }
}

/**
 * Scan and sanitize text against indirect injection rules.
 * Returns the cleaned text and any detections.
 */
function scanAndSanitize(text: string): { clean: string; detections: Detection[] } {
  let clean = text;
  const detections: Detection[] = [];

  for (const { rule, regex } of compiledRules) {
    // Reset lastIndex for global regex
    regex.lastIndex = 0;
    if (regex.test(clean)) {
      detections.push({
        ruleId: rule.id,
        ruleName: rule.name,
        action: rule.action,
        timestamp: new Date().toISOString(),
      });

      if (rule.action === "strip") {
        regex.lastIndex = 0;
        clean = clean.replace(regex, "").trim();
      }
      // "flag" action: log but don't modify
    }
  }

  return { clean, detections };
}

/**
 * Check if a tool name matches any high-risk prefix.
 */
function isHighRisk(toolName: string): boolean {
  const lower = toolName.toLowerCase();
  return HIGH_RISK_PREFIXES.some((prefix) => lower.startsWith(prefix));
}

/**
 * Local policy fallback when no governance headers are present.
 * Checks quarantine list first, then high-risk tool categories.
 */
function applyLocalPolicy(toolCall: ToolCallInput): BeforeToolCallResult {
  // FR-4.2: Check quarantine list
  if (quarantineList.includes(toolCall.name)) {
    logDetection({
      ruleId: "quarantine",
      ruleName: "Quarantined Skill",
      action: "block",
      timestamp: new Date().toISOString(),
    });
    return {
      allow: false,
      reason: `Skill '${toolCall.name}' is quarantined`,
    };
  }

  // SEC-D-08: Check high-risk tool categories
  if (isHighRisk(toolCall.name)) {
    logDetection({
      ruleId: "governance-missing",
      ruleName: "No Governance Token",
      action: "block",
      timestamp: new Date().toISOString(),
    });
    return {
      allow: false,
      reason: `Tool '${toolCall.name}' requires governance approval (no governance headers present)`,
    };
  }

  return { allow: true };
}

// --- Hook registration ---

loadRules();
loadQuarantineList();

export default {
  hooks: {
    before_tool_call(toolCall: ToolCallInput): BeforeToolCallResult {
      // FR-4.4: Skip enforcement if disabled
      if (!enforcementEnabled) {
        return { allow: true };
      }

      const headers = toolCall.context?.headers || {};
      const planId = headers["x-governance-plan-id"];
      const token = headers["x-governance-token"];

      // SEC-D-07: Presence-only check — if both headers are present and non-empty,
      // the proxy has already evaluated this request through full governance.
      if (planId && token) {
        return { allow: true };
      }

      // No governance headers — apply local policy fallback
      return applyLocalPolicy(toolCall);
    },

    tool_result_persist(toolResult: { content: string; tool?: string }): { content: string } {
      if (!toolResult.content || compiledRules.length === 0) {
        return toolResult;
      }

      const { clean, detections } = scanAndSanitize(toolResult.content);

      for (const d of detections) {
        logDetection(d);
        console.warn(
          `[prompt-guard] Detected ${d.ruleName} (${d.ruleId}) in tool result${toolResult.tool ? ` from ${toolResult.tool}` : ""}`
        );
      }

      return { ...toolResult, content: clean };
    },
  },
};
