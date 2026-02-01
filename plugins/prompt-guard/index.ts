/**
 * OpenClaw plugin: Prompt Guard
 *
 * Registers a `tool_result_persist` hook that scans tool results for
 * indirect prompt injection patterns before they enter the agent context.
 * Detected patterns are stripped from the content and logged.
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

const RULES_PATH =
  process.env.INDIRECT_RULES_PATH ||
  join(__dirname, "../../config/indirect-injection-rules.json");

const LOG_PATH =
  process.env.PROMPT_GUARD_LOG_PATH ||
  join(
    process.env.HOME || "/tmp",
    ".openclaw/prompt-guard-detections.jsonl"
  );

let compiledRules: CompiledRule[] = [];

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

// --- Hook registration ---

loadRules();

export default {
  hooks: {
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
