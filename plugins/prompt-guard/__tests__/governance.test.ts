/**
 * T4.1: Tests for `before_tool_call` hook with governance check.
 *
 * Design Reference: Section 3.3.2A
 * Requirements: SEC-D-07, FR-4.3, FR-4.4, FR-4.5
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";

// We'll import the plugin after setting up env vars
let plugin: typeof import("../index");

function loadPlugin() {
  // Clear module cache to re-import with fresh env
  vi.resetModules();
  return import("../index");
}

describe("before_tool_call hook", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    // Point to non-existent rules file so compiledRules = [] (no indirect injection rules)
    process.env.INDIRECT_RULES_PATH = "/dev/null/nonexistent.json";
    // Suppress log file writes during tests
    process.env.PROMPT_GUARD_LOG_PATH = "/dev/null";
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.restoreAllMocks();
  });

  describe("when enforcement enabled", () => {
    beforeEach(() => {
      // Enforcement is enabled by default (PROMPT_GUARD_ENFORCEMENT !== "false")
      delete process.env.PROMPT_GUARD_ENFORCEMENT;
    });

    it("allows tool call with governance headers present (SEC-D-07)", async () => {
      plugin = await loadPlugin();
      const hook = plugin.default.hooks.before_tool_call;
      expect(hook).toBeDefined();

      const result = hook({
        name: "exec",
        arguments: { cmd: "ls" },
        context: {
          headers: {
            "x-governance-plan-id": "plan-123",
            "x-governance-token": "token-abc",
          },
        },
      });

      expect(result.allow).toBe(true);
    });

    it("blocks tool call without governance headers (FR-4.3)", async () => {
      plugin = await loadPlugin();
      const hook = plugin.default.hooks.before_tool_call;

      const result = hook({
        name: "exec",
        arguments: { cmd: "rm -rf /" },
        context: { headers: {} },
      });

      // Without governance headers and no local policy override, should block
      expect(result.allow).toBe(false);
      expect(result.reason).toBeDefined();
    });

    it("falls back to local policy when no governance headers (FR-4.1)", async () => {
      plugin = await loadPlugin();
      const hook = plugin.default.hooks.before_tool_call;

      // A safe, non-quarantined tool with no governance headers should still
      // go through local policy evaluation
      const result = hook({
        name: "read_file",
        arguments: { path: "/tmp/test.txt" },
        context: { headers: {} },
      });

      // Local policy should allow safe tools
      expect(result.allow).toBe(true);
    });

    it("blocks tool call with only plan-id but no token", async () => {
      plugin = await loadPlugin();
      const hook = plugin.default.hooks.before_tool_call;

      const result = hook({
        name: "exec",
        arguments: { cmd: "ls" },
        context: {
          headers: {
            "x-governance-plan-id": "plan-123",
            // Missing x-governance-token
          },
        },
      });

      // Both headers required for governance bypass
      expect(result.allow).toBe(false);
    });

    it("blocks tool call with empty governance headers", async () => {
      plugin = await loadPlugin();
      const hook = plugin.default.hooks.before_tool_call;

      const result = hook({
        name: "exec",
        arguments: { cmd: "ls" },
        context: {
          headers: {
            "x-governance-plan-id": "",
            "x-governance-token": "",
          },
        },
      });

      // Empty headers should not count as present
      expect(result.allow).toBe(false);
    });
  });

  describe("when enforcement disabled (FR-4.4)", () => {
    beforeEach(() => {
      process.env.PROMPT_GUARD_ENFORCEMENT = "false";
    });

    it("allows all tool calls when enforcement disabled", async () => {
      plugin = await loadPlugin();
      const hook = plugin.default.hooks.before_tool_call;

      const result = hook({
        name: "exec",
        arguments: { cmd: "rm -rf /" },
        context: { headers: {} },
      });

      expect(result.allow).toBe(true);
    });

    it("preserves existing tool_result_persist behavior (FR-4.4)", async () => {
      plugin = await loadPlugin();
      const persistHook = plugin.default.hooks.tool_result_persist;

      // tool_result_persist should still work regardless of enforcement setting
      expect(persistHook).toBeDefined();

      const result = persistHook({ content: "safe content" });
      expect(result.content).toBe("safe content");
    });
  });

  describe("with no context provided", () => {
    it("handles missing context gracefully", async () => {
      delete process.env.PROMPT_GUARD_ENFORCEMENT;
      plugin = await loadPlugin();
      const hook = plugin.default.hooks.before_tool_call;

      // No context at all — should fall through to local policy
      const result = hook({
        name: "read_file",
        arguments: { path: "/tmp/test.txt" },
      });

      expect(result.allow).toBe(true);
    });

    it("handles missing headers in context gracefully", async () => {
      delete process.env.PROMPT_GUARD_ENFORCEMENT;
      plugin = await loadPlugin();
      const hook = plugin.default.hooks.before_tool_call;

      const result = hook({
        name: "read_file",
        arguments: { path: "/tmp/test.txt" },
        context: {},
      });

      expect(result.allow).toBe(true);
    });
  });

  describe("logging (FR-4.5)", () => {
    it("logs enforcement actions to detection log", async () => {
      delete process.env.PROMPT_GUARD_ENFORCEMENT;
      const logPath = "/tmp/prompt-guard-test-detections.jsonl";
      process.env.PROMPT_GUARD_LOG_PATH = logPath;

      // Clean up any previous test log
      try { fs.unlinkSync(logPath); } catch { /* ignore */ }

      plugin = await loadPlugin();
      const hook = plugin.default.hooks.before_tool_call;

      // Trigger a block (high-risk tool, no governance headers)
      hook({
        name: "exec",
        arguments: { cmd: "ls" },
        context: { headers: {} },
      });

      // Check that something was logged
      const logContent = fs.readFileSync(logPath, "utf-8");
      const lines = logContent.trim().split("\n");
      expect(lines.length).toBeGreaterThan(0);

      const entry = JSON.parse(lines[0]);
      expect(entry.ruleId).toBeDefined();
      expect(entry.action).toBe("block");
      expect(entry.timestamp).toBeDefined();

      // Clean up
      try { fs.unlinkSync(logPath); } catch { /* ignore */ }
    });
  });
});
