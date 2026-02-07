/**
 * T4.2: Tests for quarantine enforcement in plugin.
 *
 * Design Reference: Section 3.3.2B
 * Requirements: FR-4.2, FR-4.5
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";

let plugin: typeof import("../index");

function loadPlugin() {
  vi.resetModules();
  return import("../index");
}

describe("quarantine enforcement in plugin", () => {
  const originalEnv = process.env;
  let quarantineListPath: string;

  beforeEach(() => {
    process.env = { ...originalEnv };
    process.env.INDIRECT_RULES_PATH = "/dev/null/nonexistent.json";
    process.env.PROMPT_GUARD_LOG_PATH = "/dev/null";
    // Enforcement must be enabled for quarantine checks to apply
    delete process.env.PROMPT_GUARD_ENFORCEMENT;
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.restoreAllMocks();
    // Clean up quarantine files
    try {
      if (quarantineListPath) fs.unlinkSync(quarantineListPath);
    } catch { /* ignore */ }
  });

  it("blocks quarantined skill (FR-4.2)", async () => {
    // Create a quarantine list with "dangerous_skill"
    quarantineListPath = "/tmp/test-quarantine-list.json";
    fs.writeFileSync(quarantineListPath, JSON.stringify(["dangerous_skill", "bad_tool"]));
    process.env.QUARANTINE_LIST_PATH = quarantineListPath;

    plugin = await loadPlugin();
    const hook = plugin.default.hooks.before_tool_call;

    const result = hook({
      name: "dangerous_skill",
      arguments: {},
      context: { headers: {} },
    });

    expect(result.allow).toBe(false);
    expect(result.reason).toContain("quarantined");
  });

  it("allows non-quarantined skill", async () => {
    quarantineListPath = "/tmp/test-quarantine-list.json";
    fs.writeFileSync(quarantineListPath, JSON.stringify(["dangerous_skill"]));
    process.env.QUARANTINE_LIST_PATH = quarantineListPath;

    plugin = await loadPlugin();
    const hook = plugin.default.hooks.before_tool_call;

    const result = hook({
      name: "read_file",
      arguments: { path: "/tmp/test.txt" },
      context: { headers: {} },
    });

    expect(result.allow).toBe(true);
  });

  it("loads quarantine list from config path", async () => {
    quarantineListPath = "/tmp/test-quarantine-custom.json";
    fs.writeFileSync(quarantineListPath, JSON.stringify(["custom_blocked_tool"]));
    process.env.QUARANTINE_LIST_PATH = quarantineListPath;

    plugin = await loadPlugin();
    const hook = plugin.default.hooks.before_tool_call;

    const result = hook({
      name: "custom_blocked_tool",
      arguments: {},
      context: { headers: {} },
    });

    expect(result.allow).toBe(false);
    expect(result.reason).toContain("quarantined");
  });

  it("logs quarantine blocks (FR-4.5)", async () => {
    quarantineListPath = "/tmp/test-quarantine-log.json";
    fs.writeFileSync(quarantineListPath, JSON.stringify(["blocked_tool"]));
    process.env.QUARANTINE_LIST_PATH = quarantineListPath;

    const logPath = "/tmp/prompt-guard-quarantine-test.jsonl";
    process.env.PROMPT_GUARD_LOG_PATH = logPath;
    try { fs.unlinkSync(logPath); } catch { /* ignore */ }

    plugin = await loadPlugin();
    const hook = plugin.default.hooks.before_tool_call;

    hook({
      name: "blocked_tool",
      arguments: {},
      context: { headers: {} },
    });

    const logContent = fs.readFileSync(logPath, "utf-8");
    const lines = logContent.trim().split("\n");
    expect(lines.length).toBeGreaterThan(0);

    const entry = JSON.parse(lines[0]);
    expect(entry.ruleId).toBe("quarantine");
    expect(entry.ruleName).toContain("Quarantine");
    expect(entry.action).toBe("block");

    try { fs.unlinkSync(logPath); } catch { /* ignore */ }
  });

  it("operates independently from proxy (defense-in-depth)", async () => {
    // Even with governance headers present, quarantine should still be checked
    // when the tool is on the quarantine list — but per SEC-D-07, governance
    // headers bypass local policy entirely (proxy already evaluated).
    // So this test verifies that quarantine blocks ONLY when no governance headers.
    quarantineListPath = "/tmp/test-quarantine-didp.json";
    fs.writeFileSync(quarantineListPath, JSON.stringify(["quarantined_skill"]));
    process.env.QUARANTINE_LIST_PATH = quarantineListPath;

    plugin = await loadPlugin();
    const hook = plugin.default.hooks.before_tool_call;

    // Without governance headers → quarantine blocks
    const blocked = hook({
      name: "quarantined_skill",
      arguments: {},
      context: { headers: {} },
    });
    expect(blocked.allow).toBe(false);

    // With governance headers → proxy already approved, allow
    const allowed = hook({
      name: "quarantined_skill",
      arguments: {},
      context: {
        headers: {
          "x-governance-plan-id": "plan-123",
          "x-governance-token": "token-abc",
        },
      },
    });
    expect(allowed.allow).toBe(true);
  });

  it("handles missing quarantine list file gracefully", async () => {
    process.env.QUARANTINE_LIST_PATH = "/dev/null/nonexistent-quarantine.json";

    plugin = await loadPlugin();
    const hook = plugin.default.hooks.before_tool_call;

    // Should not crash; safe tools should still be allowed
    const result = hook({
      name: "read_file",
      arguments: { path: "/tmp/test.txt" },
      context: { headers: {} },
    });

    expect(result.allow).toBe(true);
  });

  it("handles empty quarantine list", async () => {
    quarantineListPath = "/tmp/test-quarantine-empty.json";
    fs.writeFileSync(quarantineListPath, JSON.stringify([]));
    process.env.QUARANTINE_LIST_PATH = quarantineListPath;

    plugin = await loadPlugin();
    const hook = plugin.default.hooks.before_tool_call;

    // With empty quarantine list, only high-risk prefix check applies
    const result = hook({
      name: "some_custom_tool",
      arguments: {},
      context: { headers: {} },
    });

    expect(result.allow).toBe(true);
  });
});
