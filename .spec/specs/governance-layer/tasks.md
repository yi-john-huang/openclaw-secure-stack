# Tasks: Governance Layer

## Overview

This document breaks down the Governance Layer implementation into TDD-based tasks following the Red-Green-Refactor cycle. Tasks are organized by component with dependencies mapped for optimal implementation order.

**Test Pyramid Target:** 70% Unit / 20% Integration / 10% E2E

---

## Task Groups

### 1. Foundation: Models & Database

#### 1.1 Create Governance Models
**Type:** Unit
**Estimated Effort:** M
**Dependencies:** None

**TDD Steps:**
1. **RED:** Write tests for all Pydantic models
   ```python
   # tests/unit/test_governance_models.py
   import pytest
   from src.governance.models import (
       IntentCategory, GovernanceDecision, ApprovalStatus,
       ToolCall, Intent, ExecutionPlan, PolicyRule, PolicyViolation,
   )

   class TestIntentCategory:
       def test_enum_values(self):
           assert IntentCategory.FILE_READ == "file_read"
           assert IntentCategory.CODE_EXECUTION == "code_execution"

   class TestToolCall:
       def test_frozen_model(self):
           tc = ToolCall(name="read_file", arguments={"path": "/tmp"})
           with pytest.raises(ValidationError):
               tc.name = "other"

       def test_optional_id(self):
           tc = ToolCall(name="read_file", arguments={})
           assert tc.id is None

   class TestExecutionPlan:
       def test_plan_id_uuid_format(self):
           # plan_id must be valid UUID4
           ...

       def test_request_hash_length(self):
           # request_hash must be 64 chars (SHA-256 hex)
           ...

       def test_actions_ordered_by_sequence(self):
           # actions must be ordered 0, 1, 2, ...
           ...
   ```
2. **GREEN:** Implement all models in `src/governance/models.py`
3. **REFACTOR:** Extract common validation logic if needed

**Acceptance Criteria:**
- [ ] All enums defined with correct values
- [ ] All models frozen (immutable)
- [ ] Model validation enforces invariants
- [ ] 100% test coverage on models

---

#### 1.2 Create GovernanceDB
**Type:** Unit
**Estimated Effort:** M
**Dependencies:** 1.1

**TDD Steps:**
1. **RED:** Write tests for database operations
   ```python
   # tests/unit/test_governance_db.py
   import pytest
   from src.governance.db import GovernanceDB

   class TestGovernanceDB:
       @pytest.fixture
       def db(self, tmp_path):
           return GovernanceDB(str(tmp_path / "test.db"))

       def test_init_creates_schema(self, db):
           # Verify all tables exist
           result = db.fetch_all("SELECT name FROM sqlite_master WHERE type='table'")
           tables = {r["name"] for r in result}
           assert "governance_plans" in tables
           assert "governance_approvals" in tables
           assert "governance_sessions" in tables

       def test_wal_mode_enabled(self, db):
           result = db.fetch_one("PRAGMA journal_mode")
           assert result[0] == "wal"

       def test_parameterized_query_prevents_injection(self, db):
           # Attempt SQL injection, verify it's safely handled
           ...

       def test_execute_with_params(self, db):
           db.execute("INSERT INTO governance_sessions VALUES (?, ?, ?, ?, ?)",
                      ("sess-1", "2024-01-01", "2024-01-01", 0, 0))
           result = db.fetch_one("SELECT * FROM governance_sessions WHERE session_id = ?", ("sess-1",))
           assert result is not None
   ```
2. **GREEN:** Implement `GovernanceDB` with schema initialization
3. **REFACTOR:** Extract schema DDL to separate file if large

**Acceptance Criteria:**
- [ ] WAL mode enabled
- [ ] All tables and indexes created
- [ ] Parameterized queries work correctly
- [ ] Connection properly managed

---

### 2. Core Pipeline: Classification

#### 2.1 Implement IntentClassifier - Tool Extraction
**Type:** Unit
**Estimated Effort:** S
**Dependencies:** 1.1

**TDD Steps:**
1. **RED:** Write tests for tool call extraction
   ```python
   # tests/unit/test_classifier.py
   class TestToolExtraction:
       def test_extract_from_openai_format(self, classifier):
           body = {
               "tools": [
                   {"type": "function", "function": {"name": "read_file", "arguments": '{"path": "/tmp"}'}}
               ]
           }
           tools = classifier._extract_tool_calls(body)
           assert len(tools) == 1
           assert tools[0].name == "read_file"

       def test_extract_multiple_tools(self, classifier):
           body = {"tools": [{"function": {"name": "a"}}, {"function": {"name": "b"}}]}
           tools = classifier._extract_tool_calls(body)
           assert len(tools) == 2

       def test_empty_body_returns_empty_list(self, classifier):
           tools = classifier._extract_tool_calls({})
           assert tools == []

       def test_malformed_tools_skipped(self, classifier):
           body = {"tools": [{"invalid": "format"}, {"function": {"name": "valid"}}]}
           tools = classifier._extract_tool_calls(body)
           assert len(tools) == 1
   ```
2. **GREEN:** Implement `_extract_tool_calls` method
3. **REFACTOR:** Handle edge cases gracefully

**Acceptance Criteria:**
- [ ] Extracts tools from OpenAI format
- [ ] Handles malformed input gracefully
- [ ] Returns empty list for no tools

---

#### 2.2 Implement IntentClassifier - Category Mapping
**Type:** Unit
**Estimated Effort:** S
**Dependencies:** 2.1

**TDD Steps:**
1. **RED:** Write tests for category mapping
   ```python
   class TestCategoryMapping:
       def test_known_tool_mapped(self, classifier):
           category = classifier._categorize_tool("read_file")
           assert category == IntentCategory.FILE_READ

       def test_unknown_tool_returns_unknown(self, classifier):
           category = classifier._categorize_tool("custom_tool_xyz")
           assert category == IntentCategory.UNKNOWN

       def test_case_insensitive_matching(self, classifier):
           assert classifier._categorize_tool("READ_FILE") == IntentCategory.FILE_READ

       def test_all_categories_have_mappings(self, classifier):
           # Verify patterns config covers all non-UNKNOWN categories
           ...
   ```
2. **GREEN:** Implement `_categorize_tool` with pattern loading
3. **REFACTOR:** Optimize pattern matching if needed

**Acceptance Criteria:**
- [ ] Maps known tools to correct categories
- [ ] Returns UNKNOWN for unrecognized tools
- [ ] Loads patterns from config file

---

#### 2.3 Implement IntentClassifier - Argument Analysis
**Type:** Unit
**Estimated Effort:** S
**Dependencies:** 2.2

**TDD Steps:**
1. **RED:** Write tests for sensitive pattern detection
   ```python
   class TestArgumentAnalysis:
       def test_detects_sensitive_path(self, classifier):
           signals = classifier._analyze_arguments({"path": "/etc/passwd"})
           assert any(s.details == "sensitive_path" for s in signals)

       def test_detects_external_url(self, classifier):
           signals = classifier._analyze_arguments({"url": "https://evil.com/exfil"})
           assert any(s.category == IntentCategory.NETWORK_REQUEST for s in signals)

       def test_safe_arguments_no_signals(self, classifier):
           signals = classifier._analyze_arguments({"path": "/tmp/safe.txt"})
           assert len(signals) == 0

       def test_nested_arguments_analyzed(self, classifier):
           signals = classifier._analyze_arguments({"config": {"file": "/etc/shadow"}})
           assert len(signals) > 0
   ```
2. **GREEN:** Implement `_analyze_arguments` with regex patterns
3. **REFACTOR:** Extract pattern matching to helper

**Acceptance Criteria:**
- [ ] Detects sensitive paths
- [ ] Detects external URLs
- [ ] Handles nested arguments

---

#### 2.4 Implement IntentClassifier - Full Classification
**Type:** Unit
**Estimated Effort:** M
**Dependencies:** 2.1, 2.2, 2.3

**TDD Steps:**
1. **RED:** Write tests for full classification flow
   ```python
   class TestClassify:
       def test_classify_returns_intent(self, classifier):
           body = {"tools": [{"function": {"name": "read_file", "arguments": '{"path": "/tmp"}'}}]}
           intent = classifier.classify(body)
           assert isinstance(intent, Intent)
           assert intent.primary_category == IntentCategory.FILE_READ

       def test_confidence_calculated(self, classifier):
           intent = classifier.classify({"tools": [{"function": {"name": "read_file"}}]})
           assert 0.0 <= intent.confidence <= 1.0

       def test_multiple_tools_aggregated(self, classifier):
           body = {"tools": [
               {"function": {"name": "read_file"}},
               {"function": {"name": "http_get"}},
           ]}
           intent = classifier.classify(body)
           assert len(intent.tool_calls) == 2

       def test_performance_under_10ms(self, classifier, benchmark):
           body = {"tools": [{"function": {"name": f"tool_{i}"}} for i in range(10)]}
           result = benchmark(classifier.classify, body)
           assert result.stats.mean < 0.010  # 10ms
   ```
2. **GREEN:** Implement `classify` method orchestrating sub-methods
3. **REFACTOR:** Optimize hot paths

**Acceptance Criteria:**
- [ ] Returns complete Intent object
- [ ] Calculates confidence score
- [ ] Completes within 10ms for 10 tools

---

### 3. Core Pipeline: Plan Generation

#### 3.1 Implement PlanGenerator - Action Building
**Type:** Unit
**Estimated Effort:** S
**Dependencies:** 1.1

**TDD Steps:**
1. **RED:** Write tests for action building
   ```python
   # tests/unit/test_planner.py
   class TestActionBuilding:
       def test_builds_ordered_actions(self, planner):
           tool_calls = [ToolCall(name="a", arguments={}), ToolCall(name="b", arguments={})]
           actions = planner._build_actions(tool_calls, [])
           assert actions[0].sequence == 0
           assert actions[1].sequence == 1

       def test_assigns_category_from_signals(self, planner):
           signals = [IntentSignal(category=IntentCategory.FILE_READ, confidence=0.9, source="tool")]
           actions = planner._build_actions([ToolCall(name="x", arguments={})], signals)
           assert actions[0].category == IntentCategory.FILE_READ

       def test_calculates_risk_score(self, planner):
           actions = planner._build_actions([ToolCall(name="delete_file", arguments={})], [])
           assert actions[0].risk_score > 0
   ```
2. **GREEN:** Implement `_build_actions`
3. **REFACTOR:** Extract risk calculation

**Acceptance Criteria:**
- [ ] Actions have sequential numbers
- [ ] Categories assigned from signals
- [ ] Risk scores calculated

---

#### 3.2 Implement PlanGenerator - Resource Extraction
**Type:** Unit
**Estimated Effort:** S
**Dependencies:** 3.1

**TDD Steps:**
1. **RED:** Write tests for resource extraction
   ```python
   class TestResourceExtraction:
       def test_extracts_file_path(self, planner):
           tc = ToolCall(name="read_file", arguments={"path": "/tmp/file.txt"})
           resources = planner._extract_resources(tc)
           assert any(r.type == "file" and r.path == "/tmp/file.txt" for r in resources)

       def test_extracts_url(self, planner):
           tc = ToolCall(name="http_get", arguments={"url": "https://api.example.com"})
           resources = planner._extract_resources(tc)
           assert any(r.type == "url" for r in resources)

       def test_determines_operation(self, planner):
           tc = ToolCall(name="write_file", arguments={"path": "/tmp/out.txt"})
           resources = planner._extract_resources(tc)
           assert resources[0].operation == "write"
   ```
2. **GREEN:** Implement `_extract_resources`
3. **REFACTOR:** Add more resource types as needed

**Acceptance Criteria:**
- [ ] Extracts file paths
- [ ] Extracts URLs
- [ ] Determines operation type

---

#### 3.3 Implement PlanGenerator - Risk Assessment
**Type:** Unit
**Estimated Effort:** S
**Dependencies:** 3.1

**TDD Steps:**
1. **RED:** Write tests for risk assessment
   ```python
   class TestRiskAssessment:
       def test_calculates_overall_score(self, planner):
           actions = [PlannedAction(sequence=0, risk_score=30, ...)]
           assessment = planner._assess_risk(actions)
           assert 0 <= assessment.overall_score <= 100

       def test_determines_risk_level(self, planner):
           high_risk = [PlannedAction(sequence=0, risk_score=80, ...)]
           assessment = planner._assess_risk(high_risk)
           assert assessment.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

       def test_identifies_risk_factors(self, planner):
           actions = [PlannedAction(category=IntentCategory.CODE_EXECUTION, ...)]
           assessment = planner._assess_risk(actions)
           assert "code_execution" in assessment.factors

       def test_caps_at_100(self, planner):
           extreme = [PlannedAction(risk_score=100, ...) for _ in range(10)]
           assessment = planner._assess_risk(extreme)
           assert assessment.overall_score == 100
   ```
2. **GREEN:** Implement `_assess_risk`
3. **REFACTOR:** Make risk calculation configurable

**Acceptance Criteria:**
- [ ] Score in range [0, 100]
- [ ] Risk level determined
- [ ] Factors identified
- [ ] Capped at maximum

---

#### 3.4 Implement PlanGenerator - Full Generation
**Type:** Unit
**Estimated Effort:** M
**Dependencies:** 3.1, 3.2, 3.3

**TDD Steps:**
1. **RED:** Write tests for full plan generation
   ```python
   class TestGenerate:
       def test_generates_plan_with_uuid(self, planner):
           intent = Intent(primary_category=IntentCategory.FILE_READ, tool_calls=[...], ...)
           plan = planner.generate(intent)
           assert uuid.UUID(plan.plan_id)  # Valid UUID

       def test_includes_request_hash(self, planner):
           plan = planner.generate(intent)
           assert len(plan.request_hash) == 64

       def test_includes_session_id(self, planner):
           plan = planner.generate(intent, session_id="sess-123")
           assert plan.session_id == "sess-123"

       def test_empty_intent_empty_actions(self, planner):
           empty = Intent(primary_category=IntentCategory.UNKNOWN, tool_calls=[], ...)
           plan = planner.generate(empty)
           assert plan.actions == []
   ```
2. **GREEN:** Implement `generate` method
3. **REFACTOR:** Ensure immutability

**Acceptance Criteria:**
- [ ] Generates valid UUID plan_id
- [ ] Computes request_hash
- [ ] Includes session context
- [ ] Handles empty intent

---

### 4. Core Pipeline: Policy Validation

#### 4.1 Implement PolicyValidator - Rule Loading
**Type:** Unit
**Estimated Effort:** S
**Dependencies:** 1.1

**TDD Steps:**
1. **RED:** Write tests for rule loading
   ```python
   # tests/unit/test_validator.py
   class TestRuleLoading:
       def test_loads_from_json(self, tmp_path):
           policies = [{"id": "GOV-001", "type": "action", "effect": "deny", ...}]
           path = tmp_path / "policies.json"
           path.write_text(json.dumps(policies))
           validator = PolicyValidator(str(path))
           assert len(validator.policies) == 1

       def test_sorts_by_priority(self, validator):
           # Higher priority first
           assert validator.policies[0].priority >= validator.policies[-1].priority

       def test_raises_on_missing_file(self):
           with pytest.raises(ConfigurationError):
               PolicyValidator("/nonexistent.json")

       def test_raises_on_invalid_format(self, tmp_path):
           path = tmp_path / "bad.json"
           path.write_text('{"not": "a list"}')
           with pytest.raises(ConfigurationError):
               PolicyValidator(str(path))
   ```
2. **GREEN:** Implement constructor with rule loading
3. **REFACTOR:** Add schema validation

**Acceptance Criteria:**
- [ ] Loads policies from JSON
- [ ] Sorts by priority
- [ ] Validates format

---

#### 4.2 Implement PolicyValidator - Action Policies
**Type:** Unit
**Estimated Effort:** M
**Dependencies:** 4.1

**TDD Steps:**
1. **RED:** Write tests for action policy evaluation
   ```python
   class TestActionPolicies:
       def test_deny_blocks_action(self, validator):
           action = PlannedAction(category=IntentCategory.FILE_DELETE, ...)
           violations = validator._check_action_policies(action)
           assert any(v.rule_id == "GOV-001" for v in violations)

       def test_allow_permits_action(self, validator):
           action = PlannedAction(category=IntentCategory.FILE_READ, ...)
           violations = validator._check_action_policies(action)
           assert len(violations) == 0

       def test_require_approval_flags(self, validator):
           action = PlannedAction(category=IntentCategory.CODE_EXECUTION, ...)
           violations = validator._check_action_policies(action)
           # Should have warning-level violation
           assert any(v.severity == Severity.MEDIUM for v in violations)
   ```
2. **GREEN:** Implement `_check_action_policies`
3. **REFACTOR:** Extract condition matching

**Acceptance Criteria:**
- [ ] Deny policies create violations
- [ ] Allow policies short-circuit
- [ ] Require_approval creates warning violations

---

#### 4.3 Implement PolicyValidator - Resource Policies
**Type:** Unit
**Estimated Effort:** M
**Dependencies:** 4.1

**TDD Steps:**
1. **RED:** Write tests for resource policy evaluation
   ```python
   class TestResourcePolicies:
       def test_blocks_external_url(self, validator):
           action = PlannedAction(resources=[ResourceAccess(type="url", path="https://evil.com", operation="read")])
           violations = validator._check_resource_policies(action)
           assert len(violations) > 0

       def test_allows_localhost(self, validator):
           action = PlannedAction(resources=[ResourceAccess(type="url", path="http://localhost:8080", operation="read")])
           violations = validator._check_resource_policies(action)
           assert len(violations) == 0

       def test_regex_pattern_matching(self, validator):
           action = PlannedAction(resources=[ResourceAccess(type="file", path="/etc/shadow", operation="read")])
           violations = validator._check_resource_policies(action)
           assert len(violations) > 0
   ```
2. **GREEN:** Implement `_check_resource_policies`
3. **REFACTOR:** Compile regex patterns once

**Acceptance Criteria:**
- [ ] Matches URL patterns
- [ ] Matches file path patterns
- [ ] Handles regex conditions

---

#### 4.4 Implement PolicyValidator - Sequence Policies
**Type:** Unit
**Estimated Effort:** M
**Dependencies:** 4.1

**TDD Steps:**
1. **RED:** Write tests for sequence policy evaluation
   ```python
   class TestSequencePolicies:
       def test_detects_forbidden_sequence(self, validator):
           plan = ExecutionPlan(actions=[
               PlannedAction(sequence=0, category=IntentCategory.FILE_READ),
               PlannedAction(sequence=1, category=IntentCategory.NETWORK_REQUEST),
           ])
           violations = validator._check_sequence_policies(plan)
           assert any("sequence" in v.message.lower() for v in violations)

       def test_within_window(self, validator):
           # Sequence spread beyond window should not trigger
           plan = ExecutionPlan(actions=[
               PlannedAction(sequence=0, category=IntentCategory.FILE_READ),
               PlannedAction(sequence=1, category=IntentCategory.FILE_WRITE),
               PlannedAction(sequence=2, category=IntentCategory.FILE_WRITE),
               PlannedAction(sequence=3, category=IntentCategory.FILE_WRITE),
               PlannedAction(sequence=4, category=IntentCategory.NETWORK_REQUEST),
           ])
           # If window is 3, this should NOT trigger
           violations = validator._check_sequence_policies(plan)
           assert len(violations) == 0

       def test_order_matters(self, validator):
           # network_request -> file_read should NOT trigger file_read -> network_request rule
           plan = ExecutionPlan(actions=[
               PlannedAction(sequence=0, category=IntentCategory.NETWORK_REQUEST),
               PlannedAction(sequence=1, category=IntentCategory.FILE_READ),
           ])
           violations = validator._check_sequence_policies(plan)
           assert len(violations) == 0
   ```
2. **GREEN:** Implement `_check_sequence_policies` with sliding window
3. **REFACTOR:** Optimize for large action lists

**Acceptance Criteria:**
- [ ] Detects forbidden sequences
- [ ] Respects window size
- [ ] Order-sensitive matching

---

#### 4.5 Implement PolicyValidator - Rate Policies
**Type:** Unit
**Estimated Effort:** S
**Dependencies:** 4.1

**TDD Steps:**
1. **RED:** Write tests for rate policy evaluation
   ```python
   class TestRatePolicies:
       def test_blocks_when_limit_exceeded(self, validator):
           session = Session(action_count=101, ...)
           violations = validator._check_rate_policies(session)
           assert any(v.rule_id == "GOV-005" for v in violations)

       def test_allows_within_limit(self, validator):
           session = Session(action_count=50, ...)
           violations = validator._check_rate_policies(session)
           assert len(violations) == 0

       def test_no_session_no_rate_check(self, validator):
           violations = validator._check_rate_policies(None)
           assert len(violations) == 0
   ```
2. **GREEN:** Implement `_check_rate_policies`
3. **REFACTOR:** Support per-minute rates

**Acceptance Criteria:**
- [ ] Enforces max_actions_per_session
- [ ] Handles missing session
- [ ] Supports multiple rate types

---

#### 4.6 Implement PolicyValidator - Full Validation
**Type:** Unit
**Estimated Effort:** M
**Dependencies:** 4.2, 4.3, 4.4, 4.5

**TDD Steps:**
1. **RED:** Write tests for full validation
   ```python
   class TestValidate:
       def test_returns_validation_result(self, validator):
           plan = ExecutionPlan(actions=[...])
           result = validator.validate(plan)
           assert isinstance(result, ValidationResult)

       def test_decision_block_on_deny(self, validator):
           plan = ExecutionPlan(actions=[PlannedAction(category=IntentCategory.FILE_DELETE)])
           result = validator.validate(plan)
           assert result.decision == GovernanceDecision.BLOCK

       def test_decision_require_approval(self, validator):
           plan = ExecutionPlan(actions=[PlannedAction(category=IntentCategory.CODE_EXECUTION)])
           result = validator.validate(plan)
           assert result.decision == GovernanceDecision.REQUIRE_APPROVAL

       def test_decision_allow_when_clean(self, validator):
           plan = ExecutionPlan(actions=[PlannedAction(category=IntentCategory.FILE_READ)])
           result = validator.validate(plan)
           assert result.decision == GovernanceDecision.ALLOW

       def test_performance_under_20ms(self, validator, benchmark):
           plan = ExecutionPlan(actions=[...] * 20)
           result = benchmark(validator.validate, plan)
           assert result.stats.mean < 0.020
   ```
2. **GREEN:** Implement `validate` method
3. **REFACTOR:** Early exit on blocking violations

**Acceptance Criteria:**
- [ ] Returns ValidationResult
- [ ] Correct decision based on violations
- [ ] Completes within 20ms

---

### 5. Storage & Tokens

#### 5.1 Implement PlanStore - Storage
**Type:** Unit
**Estimated Effort:** M
**Dependencies:** 1.2

**TDD Steps:**
1. **RED:** Write tests for plan storage
   ```python
   # tests/unit/test_store.py
   class TestPlanStorage:
       def test_store_returns_plan_id_and_token(self, store):
           plan = ExecutionPlan(...)
           plan_id, token = store.store(plan)
           assert uuid.UUID(plan_id)
           assert "." in token  # payload.signature format

       def test_lookup_returns_stored_plan(self, store):
           plan = ExecutionPlan(...)
           plan_id, _ = store.store(plan)
           stored = store.lookup(plan_id)
           assert stored.plan.plan_id == plan_id

       def test_lookup_nonexistent_returns_none(self, store):
           assert store.lookup("nonexistent-id") is None

       def test_initial_sequence_is_zero(self, store):
           plan_id, _ = store.store(ExecutionPlan(...))
           assert store.get_current_sequence(plan_id) == 0
   ```
2. **GREEN:** Implement `store` and `lookup`
3. **REFACTOR:** Add expiration cleanup

**Acceptance Criteria:**
- [ ] Stores plan in database
- [ ] Returns plan_id and token
- [ ] Lookup retrieves stored plan
- [ ] Sequence initialized to 0

---

#### 5.2 Implement PlanStore - Token Signing
**Type:** Unit
**Estimated Effort:** M
**Dependencies:** 5.1

**TDD Steps:**
1. **RED:** Write tests for token security
   ```python
   class TestTokenSigning:
       def test_token_format(self, store):
           plan_id, token = store.store(ExecutionPlan(...))
           parts = token.split(".")
           assert len(parts) == 2  # payload.signature

       def test_verify_valid_token(self, store):
           _, token = store.store(ExecutionPlan(...))
           result = store.verify_token(token)
           assert result.valid is True
           assert result.expired is False

       def test_verify_invalid_signature(self, store):
           _, token = store.store(ExecutionPlan(...))
           tampered = token[:-1] + "X"  # Corrupt signature
           result = store.verify_token(tampered)
           assert result.valid is False

       def test_verify_expired_token(self, store, freezer):
           _, token = store.store(ExecutionPlan(...))
           freezer.move_to(datetime.now() + timedelta(seconds=1000))
           result = store.verify_token(token)
           assert result.expired is True

       def test_constant_time_comparison(self, store):
           # Timing attack prevention - both should take similar time
           _, valid = store.store(ExecutionPlan(...))
           invalid = "totally.invalid"
           # Use timing assertions
   ```
2. **GREEN:** Implement `_issue_token` and `verify_token` with HMAC
3. **REFACTOR:** Use `hmac.compare_digest`

**Acceptance Criteria:**
- [ ] HMAC-SHA256 signing
- [ ] Constant-time comparison
- [ ] Expiration detection

---

#### 5.3 Implement PlanStore - Sequence Tracking
**Type:** Unit
**Estimated Effort:** S
**Dependencies:** 5.1

**TDD Steps:**
1. **RED:** Write tests for sequence tracking
   ```python
   class TestSequenceTracking:
       def test_advance_increments(self, store):
           plan_id, _ = store.store(ExecutionPlan(...))
           new_seq = store.advance_sequence(plan_id)
           assert new_seq == 1
           assert store.get_current_sequence(plan_id) == 1

       def test_advance_multiple_times(self, store):
           plan_id, _ = store.store(ExecutionPlan(...))
           store.advance_sequence(plan_id)
           store.advance_sequence(plan_id)
           assert store.get_current_sequence(plan_id) == 2

       def test_advance_nonexistent_raises(self, store):
           with pytest.raises(PlanNotFoundError):
               store.advance_sequence("nonexistent")
   ```
2. **GREEN:** Implement `advance_sequence` and `get_current_sequence`
3. **REFACTOR:** Add retry count tracking

**Acceptance Criteria:**
- [ ] Advances sequence correctly
- [ ] Persists across lookups
- [ ] Handles missing plan

---

### 6. Approval Flow

#### 6.1 Implement ApprovalGate - Request Creation
**Type:** Unit
**Estimated Effort:** M
**Dependencies:** 1.2

**TDD Steps:**
1. **RED:** Write tests for approval request creation
   ```python
   # tests/unit/test_approver.py
   class TestRequestCreation:
       def test_creates_approval_request(self, approver):
           plan = ExecutionPlan(...)
           violations = [PolicyViolation(...)]
           request = approver.create_request(plan, violations, "user-1", {"body": "data"})
           assert uuid.UUID(request.approval_id)
           assert request.status == ApprovalStatus.PENDING

       def test_stores_original_request(self, approver):
           request = approver.create_request(..., original_request={"key": "value"})
           assert request.original_request == {"key": "value"}

       def test_sets_expiration(self, approver):
           request = approver.create_request(...)
           expires = datetime.fromisoformat(request.expires_at)
           requested = datetime.fromisoformat(request.requested_at)
           assert expires > requested
   ```
2. **GREEN:** Implement `create_request`
3. **REFACTOR:** Extract timestamp handling

**Acceptance Criteria:**
- [ ] Creates unique approval_id
- [ ] Stores original request
- [ ] Sets expiration time

---

#### 6.2 Implement ApprovalGate - Approval/Rejection
**Type:** Unit
**Estimated Effort:** M
**Dependencies:** 6.1

**TDD Steps:**
1. **RED:** Write tests for approval/rejection
   ```python
   class TestApprovalRejection:
       def test_approve_updates_status(self, approver):
           request = approver.create_request(...)
           record = approver.approve(request.approval_id, "user-1", "I acknowledge")
           assert record.status == ApprovalStatus.APPROVED

       def test_approve_stores_acknowledgment(self, approver):
           request = approver.create_request(...)
           record = approver.approve(request.approval_id, "user-1", "I accept the risk")
           assert record.acknowledgment == "I accept the risk"

       def test_reject_updates_status(self, approver):
           request = approver.create_request(...)
           record = approver.reject(request.approval_id, "user-1", "Too risky")
           assert record.status == ApprovalStatus.REJECTED

       def test_reject_stores_reason(self, approver):
           record = approver.reject(..., reason="Not authorized")
           assert record.reason == "Not authorized"

       def test_approve_expired_raises(self, approver, freezer):
           request = approver.create_request(...)
           freezer.move_to(datetime.now() + timedelta(hours=2))
           with pytest.raises(ApprovalExpiredError):
               approver.approve(request.approval_id, "user-1", "ack")
   ```
2. **GREEN:** Implement `approve` and `reject`
3. **REFACTOR:** Extract status transition logic

**Acceptance Criteria:**
- [ ] Updates status correctly
- [ ] Stores acknowledgment/reason
- [ ] Rejects expired requests

---

#### 6.3 Implement ApprovalGate - Self-Approval Validation
**Type:** Unit
**Estimated Effort:** S
**Dependencies:** 6.2

**TDD Steps:**
1. **RED:** Write tests for self-approval validation
   ```python
   class TestSelfApproval:
       def test_approver_must_match_requester(self, approver):
           request = approver.create_request(..., requester_id="user-1")
           with pytest.raises(ApproverMismatchError):
               approver.approve(request.approval_id, "user-2", "ack")

       def test_same_user_can_approve(self, approver):
           request = approver.create_request(..., requester_id="user-1")
           record = approver.approve(request.approval_id, "user-1", "ack")
           assert record.status == ApprovalStatus.APPROVED

       def test_disabled_allows_any_approver(self, approver_no_self_check):
           request = approver_no_self_check.create_request(..., requester_id="user-1")
           record = approver_no_self_check.approve(request.approval_id, "admin", "ack")
           assert record.status == ApprovalStatus.APPROVED
   ```
2. **GREEN:** Implement `_validate_self_approval`
3. **REFACTOR:** Make configurable

**Acceptance Criteria:**
- [ ] Validates approver matches requester
- [ ] Configurable via settings
- [ ] Clear error on mismatch

---

### 7. Session Management

#### 7.1 Implement SessionManager - CRUD
**Type:** Unit
**Estimated Effort:** M
**Dependencies:** 1.2

**TDD Steps:**
1. **RED:** Write tests for session CRUD
   ```python
   # tests/unit/test_session.py
   class TestSessionCRUD:
       def test_get_or_create_new(self, session_mgr):
           session = session_mgr.get_or_create(None)
           assert uuid.UUID(session.session_id)
           assert session.action_count == 0

       def test_get_or_create_existing(self, session_mgr):
           s1 = session_mgr.get_or_create("sess-123")
           s2 = session_mgr.get_or_create("sess-123")
           assert s1.session_id == s2.session_id

       def test_record_action_increments_count(self, session_mgr):
           session = session_mgr.get_or_create("sess-1")
           session_mgr.record_action("sess-1", PlannedAction(...), GovernanceDecision.ALLOW)
           updated = session_mgr.get_or_create("sess-1")
           assert updated.action_count == 1

       def test_record_action_updates_risk(self, session_mgr):
           session_mgr.record_action("sess-1", PlannedAction(risk_score=30, ...), ...)
           updated = session_mgr.get_or_create("sess-1")
           assert updated.risk_accumulator == 30
   ```
2. **GREEN:** Implement `get_or_create` and `record_action`
3. **REFACTOR:** Batch updates

**Acceptance Criteria:**
- [ ] Creates new sessions
- [ ] Retrieves existing sessions
- [ ] Tracks action count and risk

---

#### 7.2 Implement SessionManager - History & Cleanup
**Type:** Unit
**Estimated Effort:** S
**Dependencies:** 7.1

**TDD Steps:**
1. **RED:** Write tests for history and cleanup
   ```python
   class TestHistoryCleanup:
       def test_get_history(self, session_mgr):
           session_mgr.record_action("sess-1", action1, ...)
           session_mgr.record_action("sess-1", action2, ...)
           history = session_mgr.get_history("sess-1")
           assert len(history) == 2

       def test_history_limit(self, session_mgr):
           for i in range(150):
               session_mgr.record_action("sess-1", action, ...)
           history = session_mgr.get_history("sess-1", limit=100)
           assert len(history) == 100

       def test_cleanup_expired(self, session_mgr, freezer):
           session_mgr.get_or_create("old-sess")
           freezer.move_to(datetime.now() + timedelta(hours=2))
           count = session_mgr.cleanup_expired()
           assert count == 1
           assert session_mgr.get_or_create("old-sess").action_count == 0  # New session
   ```
2. **GREEN:** Implement `get_history` and `cleanup_expired`
3. **REFACTOR:** Add background cleanup

**Acceptance Criteria:**
- [ ] Returns history with limit
- [ ] Cleans up expired sessions
- [ ] Returns cleanup count

---

### 8. Execution Enforcement

#### 8.1 Implement GovernanceEnforcer - Token Verification
**Type:** Unit
**Estimated Effort:** M
**Dependencies:** 5.2

**TDD Steps:**
1. **RED:** Write tests for enforcement token verification
   ```python
   # tests/unit/test_enforcer.py
   class TestTokenVerification:
       def test_missing_headers_blocked(self, enforcer):
           result = enforcer.verify(mock_request, None, None)
           assert result.blocked is True
           assert "missing" in result.reason.lower()

       def test_invalid_token_blocked(self, enforcer):
           result = enforcer.verify(mock_request, "plan-1", "invalid.token")
           assert result.blocked is True
           assert "invalid" in result.reason.lower()

       def test_expired_token_blocked(self, enforcer, freezer):
           _, token = store.store(plan)
           freezer.move_to(datetime.now() + timedelta(hours=1))
           result = enforcer.verify(mock_request, plan.plan_id, token)
           assert result.blocked is True
           assert "expired" in result.reason.lower()

       def test_valid_token_allowed(self, enforcer):
           plan_id, token = store.store(plan)
           result = enforcer.verify(mock_request, plan_id, token)
           assert result.allowed is True
   ```
2. **GREEN:** Implement token verification in `verify`
3. **REFACTOR:** Extract error messages

**Acceptance Criteria:**
- [ ] Blocks missing headers
- [ ] Blocks invalid tokens
- [ ] Blocks expired tokens
- [ ] Allows valid tokens

---

#### 8.2 Implement GovernanceEnforcer - Action Matching
**Type:** Unit
**Estimated Effort:** M
**Dependencies:** 8.1

**TDD Steps:**
1. **RED:** Write tests for action matching
   ```python
   class TestActionMatching:
       def test_matches_expected_action(self, enforcer):
           plan = ExecutionPlan(actions=[PlannedAction(tool_call=ToolCall(name="read_file", ...))])
           request = mock_request_with_skill("read_file")
           result = enforcer.verify(request, plan.plan_id, token)
           assert result.allowed is True

       def test_blocks_unexpected_action(self, enforcer):
           plan = ExecutionPlan(actions=[PlannedAction(tool_call=ToolCall(name="read_file", ...))])
           request = mock_request_with_skill("write_file")  # Different!
           result = enforcer.verify(request, plan.plan_id, token)
           assert result.blocked is True
           assert "unplanned" in result.reason.lower()

       def test_blocks_out_of_sequence(self, enforcer):
           plan = ExecutionPlan(actions=[
               PlannedAction(sequence=0, tool_call=ToolCall(name="a")),
               PlannedAction(sequence=1, tool_call=ToolCall(name="b")),
           ])
           # Try to execute "b" first
           request = mock_request_with_skill("b")
           result = enforcer.verify(request, plan.plan_id, token)
           assert result.blocked is True
           assert "sequence" in result.reason.lower()
   ```
2. **GREEN:** Implement `_extract_action` and `_match_action`
3. **REFACTOR:** Handle partial matches

**Acceptance Criteria:**
- [ ] Matches planned actions
- [ ] Blocks unplanned actions
- [ ] Enforces sequence order

---

#### 8.3 Implement GovernanceEnforcer - Retry Handling
**Type:** Unit
**Estimated Effort:** S
**Dependencies:** 8.2

**TDD Steps:**
1. **RED:** Write tests for retry handling
   ```python
   class TestRetryHandling:
       def test_retry_same_action_allowed(self, enforcer):
           plan_id, token = store.store(plan)
           request = mock_request_with_skill("action-0")
           enforcer.verify(request, plan_id, token)  # First attempt
           result = enforcer.verify(request, plan_id, token)  # Retry
           assert result.allowed is True

       def test_retry_limit_exceeded(self, enforcer):
           plan_id, token = store.store(plan)
           request = mock_request_with_skill("action-0")
           for _ in range(4):  # Exceed limit of 3
               enforcer.verify(request, plan_id, token)
           result = enforcer.verify(request, plan_id, token)
           assert result.blocked is True
           assert "retry" in result.reason.lower()

       def test_sequence_advances_after_success(self, enforcer):
           plan_id, token = store.store(plan)
           request0 = mock_request_with_skill("action-0")
           enforcer.verify(request0, plan_id, token)
           # Now action-1 should be expected
           request1 = mock_request_with_skill("action-1")
           result = enforcer.verify(request1, plan_id, token)
           assert result.allowed is True
   ```
2. **GREEN:** Implement `_is_retry` and retry counting
3. **REFACTOR:** Make retry limit configurable

**Acceptance Criteria:**
- [ ] Allows bounded retries
- [ ] Blocks after limit exceeded
- [ ] Advances sequence correctly

---

### 9. Orchestration

#### 9.1 Implement GovernanceMiddleware - Pipeline
**Type:** Unit
**Estimated Effort:** L
**Dependencies:** 2.4, 3.4, 4.6, 5.1, 6.1, 7.1

**TDD Steps:**
1. **RED:** Write tests for middleware pipeline
   ```python
   # tests/unit/test_governance_middleware.py
   class TestMiddlewarePipeline:
       def test_evaluate_returns_allow(self, middleware):
           body = {"tools": [{"function": {"name": "read_file"}}]}
           result = await middleware.evaluate(mock_request, body)
           assert result.decision == GovernanceDecision.ALLOW
           assert result.plan_id is not None
           assert result.token is not None

       def test_evaluate_returns_block(self, middleware):
           body = {"tools": [{"function": {"name": "delete_file"}}]}
           result = await middleware.evaluate(mock_request, body)
           assert result.decision == GovernanceDecision.BLOCK
           assert len(result.violations) > 0

       def test_evaluate_returns_require_approval(self, middleware):
           body = {"tools": [{"function": {"name": "execute_code"}}]}
           result = await middleware.evaluate(mock_request, body)
           assert result.decision == GovernanceDecision.REQUIRE_APPROVAL
           assert result.approval_id is not None

       def test_fail_closed_on_error(self, middleware_with_failing_classifier):
           result = await middleware_with_failing_classifier.evaluate(mock_request, {})
           assert result.decision == GovernanceDecision.BLOCK
   ```
2. **GREEN:** Implement `evaluate` method orchestrating all components
3. **REFACTOR:** Add metrics/timing

**Acceptance Criteria:**
- [ ] Orchestrates full pipeline
- [ ] Returns correct decisions
- [ ] Fail-closed on errors

---

#### 9.2 Implement GovernanceMiddleware - Audit Logging
**Type:** Unit
**Estimated Effort:** S
**Dependencies:** 9.1

**TDD Steps:**
1. **RED:** Write tests for audit logging
   ```python
   class TestAuditLogging:
       def test_logs_allow_decision(self, middleware, mock_audit_logger):
           await middleware.evaluate(mock_request, body)
           mock_audit_logger.log.assert_called()
           event = mock_audit_logger.log.call_args[0][0]
           assert event.event_type == AuditEventType.GOVERNANCE_ALLOW

       def test_logs_block_decision(self, middleware, mock_audit_logger):
           await middleware.evaluate(mock_request, blocked_body)
           event = mock_audit_logger.log.call_args[0][0]
           assert event.event_type == AuditEventType.GOVERNANCE_BLOCK

       def test_logs_include_plan_id(self, middleware, mock_audit_logger):
           await middleware.evaluate(mock_request, body)
           event = mock_audit_logger.log.call_args[0][0]
           assert "plan_id" in event.details

       def test_token_redacted_in_logs(self, middleware, mock_audit_logger):
           await middleware.evaluate(mock_request, body)
           event = mock_audit_logger.log.call_args[0][0]
           if "token" in event.details:
               assert len(event.details["token"]) <= 8  # Redacted
   ```
2. **GREEN:** Implement `_log_decision`
3. **REFACTOR:** Extract log formatting

**Acceptance Criteria:**
- [ ] Logs all decision types
- [ ] Includes plan_id
- [ ] Redacts sensitive data

---

### 10. API & Integration

#### 10.1 Implement GovernanceAPI Endpoints
**Type:** Integration
**Estimated Effort:** M
**Dependencies:** 6.2

**TDD Steps:**
1. **RED:** Write tests for API endpoints
   ```python
   # tests/integration/test_governance_api.py
   class TestGovernanceAPI:
       def test_get_approval(self, client, approver):
           request = approver.create_request(...)
           response = client.get(f"/governance/approvals/{request.approval_id}")
           assert response.status_code == 200
           assert response.json()["status"] == "pending"

       def test_approve_endpoint(self, client, approver):
           request = approver.create_request(...)
           response = client.post(
               f"/governance/approvals/{request.approval_id}/approve",
               json={"acknowledgment": "I accept"}
           )
           assert response.status_code == 200
           assert response.json()["status"] == "approved"

       def test_reject_endpoint(self, client, approver):
           request = approver.create_request(...)
           response = client.post(
               f"/governance/approvals/{request.approval_id}/reject",
               json={"reason": "Too risky"}
           )
           assert response.status_code == 200
           assert response.json()["status"] == "rejected"

       def test_not_found_returns_404(self, client):
           response = client.get("/governance/approvals/nonexistent")
           assert response.status_code == 404
   ```
2. **GREEN:** Implement `create_governance_router`
3. **REFACTOR:** Add request validation

**Acceptance Criteria:**
- [ ] GET returns approval status
- [ ] POST approve works
- [ ] POST reject works
- [ ] Returns 404 for missing

---

#### 10.2 Integrate with Proxy App
**Type:** Integration
**Estimated Effort:** L
**Dependencies:** 9.1, 8.3, 10.1

**TDD Steps:**
1. **RED:** Write integration tests for proxy
   ```python
   # tests/integration/test_governance_flow.py
   class TestGovernanceProxyIntegration:
       def test_allowed_request_forwarded(self, client):
           response = client.post("/v1/chat/completions", json={
               "tools": [{"function": {"name": "read_file"}}]
           })
           assert response.status_code == 200
           # Verify headers were injected (mock upstream)

       def test_blocked_request_returns_403(self, client):
           response = client.post("/v1/chat/completions", json={
               "tools": [{"function": {"name": "delete_file"}}]
           })
           assert response.status_code == 403
           assert "violations" in response.json()["error"]

       def test_approval_required_returns_202(self, client):
           response = client.post("/v1/chat/completions", json={
               "tools": [{"function": {"name": "execute_code"}}]
           })
           assert response.status_code == 202
           assert "approval_id" in response.json()

       def test_skill_invocation_enforced(self, client):
           # First, get a plan
           r1 = client.post("/v1/chat/completions", ...)
           plan_id = r1.headers["X-Governance-Plan-Id"]
           token = r1.headers["X-Governance-Token"]

           # Then invoke skill with headers
           r2 = client.post("/skills/read_file", headers={
               "X-Governance-Plan-Id": plan_id,
               "X-Governance-Token": token,
           })
           assert r2.status_code == 200

       def test_skill_without_headers_blocked(self, client):
           response = client.post("/skills/read_file")
           assert response.status_code == 403
   ```
2. **GREEN:** Modify `create_app` and `proxy` handler
3. **REFACTOR:** Extract governance handling

**Acceptance Criteria:**
- [ ] ALLOW → forward with headers
- [ ] BLOCK → 403 with violations
- [ ] REQUIRE_APPROVAL → 202
- [ ] Skills enforced

---

### 11. Configuration

#### 11.1 Create Configuration Files
**Type:** Unit
**Estimated Effort:** S
**Dependencies:** None

**TDD Steps:**
1. **RED:** Write validation tests
   ```python
   # tests/unit/test_config.py
   def test_governance_settings_schema():
       with open("config/governance-settings.json") as f:
           settings = json.load(f)
       assert "enabled" in settings
       assert "approval" in settings
       assert settings["approval"]["timeout_seconds"] > 0

   def test_governance_policies_schema():
       with open("config/governance-policies.json") as f:
           policies = json.load(f)
       assert isinstance(policies, list)
       for p in policies:
           assert "id" in p
           assert "type" in p
           assert "effect" in p

   def test_intent_patterns_schema():
       with open("config/intent-patterns.json") as f:
           patterns = json.load(f)
       assert "tool_categories" in patterns
       assert "risk_multipliers" in patterns
   ```
2. **GREEN:** Create config files with valid schemas
3. **REFACTOR:** Document config options

**Acceptance Criteria:**
- [ ] All config files valid
- [ ] Schemas documented
- [ ] Default values sensible

---

### 12. End-to-End & Security

#### 12.1 E2E: Full Governance Flow
**Type:** E2E
**Estimated Effort:** L
**Dependencies:** 10.2

**TDD Steps:**
1. **RED:** Write E2E test
   ```python
   # tests/integration/test_e2e_governance.py
   class TestE2EGovernance:
       def test_full_allow_flow(self, running_server):
           # 1. Send request with safe tools
           r1 = requests.post(f"{BASE}/v1/chat/completions", json=safe_body)
           assert r1.status_code == 200
           plan_id = r1.headers["X-Governance-Plan-Id"]

           # 2. Invoke skill
           r2 = requests.post(f"{BASE}/skills/read_file", headers={...})
           assert r2.status_code == 200

       def test_full_approval_flow(self, running_server):
           # 1. Send request requiring approval
           r1 = requests.post(f"{BASE}/v1/chat/completions", json=risky_body)
           assert r1.status_code == 202
           approval_id = r1.json()["approval_id"]

           # 2. Approve
           r2 = requests.post(f"{BASE}/governance/approvals/{approval_id}/approve", json={...})
           assert r2.status_code == 200

           # 3. Retry with approval token
           r3 = requests.post(f"{BASE}/v1/chat/completions", json=risky_body, headers={
               "X-Governance-Approval-Token": r2.json()["approval_token"]
           })
           assert r3.status_code == 200
   ```
2. **GREEN:** Ensure all components work together
3. **REFACTOR:** Add more scenarios

**Acceptance Criteria:**
- [ ] Full allow flow works
- [ ] Full approval flow works
- [ ] End-to-end timing acceptable

---

#### 12.2 Security: Token Tampering
**Type:** Security
**Estimated Effort:** M
**Dependencies:** 5.2

**TDD Steps:**
1. **RED:** Write security tests
   ```python
   # tests/security/test_token_security.py
   class TestTokenTampering:
       def test_modified_payload_rejected(self, store):
           _, token = store.store(plan)
           payload, sig = token.split(".")
           # Decode, modify, re-encode
           data = json.loads(base64.urlsafe_b64decode(payload))
           data["plan_id"] = "different-id"
           new_payload = base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
           tampered = f"{new_payload}.{sig}"
           result = store.verify_token(tampered)
           assert result.valid is False

       def test_signature_reuse_rejected(self, store):
           _, token1 = store.store(plan1)
           _, token2 = store.store(plan2)
           # Try to use signature from token2 with payload from token1
           p1, _ = token1.split(".")
           _, s2 = token2.split(".")
           mixed = f"{p1}.{s2}"
           result = store.verify_token(mixed)
           assert result.valid is False
   ```
2. **GREEN:** Ensure HMAC verification catches tampering
3. **REFACTOR:** Add more attack vectors

**Acceptance Criteria:**
- [ ] Payload tampering detected
- [ ] Signature reuse blocked
- [ ] Timing attacks mitigated

---

#### 12.3 Security: Self-Approval Bypass
**Type:** Security
**Estimated Effort:** S
**Dependencies:** 6.3

**TDD Steps:**
1. **RED:** Write bypass tests
   ```python
   class TestSelfApprovalBypass:
       def test_header_spoofing_blocked(self, approver):
           # Create request as user-1
           request = approver.create_request(..., requester_id="user-1")
           # Try to approve with spoofed header (should use auth context, not header)
           with pytest.raises(ApproverMismatchError):
               approver.approve(request.approval_id, "user-2", "ack")

       def test_null_requester_blocked(self, approver):
           request = approver.create_request(..., requester_id="user-1")
           with pytest.raises(ApproverMismatchError):
               approver.approve(request.approval_id, None, "ack")
   ```
2. **GREEN:** Ensure validation is robust
3. **REFACTOR:** Add audit for bypass attempts

**Acceptance Criteria:**
- [ ] Spoofing blocked
- [ ] Null values handled
- [ ] Bypass attempts logged

---

## Implementation Order

```
Phase 1: Foundation
[1.1] ──> [1.2]

Phase 2: Classification
[1.1] ──> [2.1] ──> [2.2] ──> [2.3] ──> [2.4]

Phase 3: Plan Generation
[1.1] ──> [3.1] ──> [3.2]
              └──> [3.3] ──> [3.4]

Phase 4: Validation
[1.1] ──> [4.1] ──> [4.2]
              ├──> [4.3]
              ├──> [4.4]
              └──> [4.5] ──> [4.6]

Phase 5: Storage & Tokens
[1.2] ──> [5.1] ──> [5.2] ──> [5.3]

Phase 6: Approval
[1.2] ──> [6.1] ──> [6.2] ──> [6.3]

Phase 7: Session
[1.2] ──> [7.1] ──> [7.2]

Phase 8: Enforcement
[5.2] ──> [8.1] ──> [8.2] ──> [8.3]

Phase 9: Orchestration
[2.4, 3.4, 4.6, 5.1, 6.1, 7.1] ──> [9.1] ──> [9.2]

Phase 10: API & Integration
[6.2] ──> [10.1]
[9.1, 8.3, 10.1] ──> [10.2]

Phase 11: Config
[11.1] (parallel)

Phase 12: E2E & Security
[10.2] ──> [12.1]
[5.2] ──> [12.2]
[6.3] ──> [12.3]
```

---

## Definition of Done

- [ ] All tests pass (`uv run pytest tests/ -q`)
- [ ] Code coverage >= 80% (`uv run pytest --cov=src/governance`)
- [ ] No lint errors (`uv run ruff check src/governance/`)
- [ ] No type errors (`uv run mypy src/governance/`)
- [ ] All acceptance criteria met
- [ ] Documentation updated if needed
- [ ] Security tests pass

---

## Test Summary

| Category | Test Files | Est. Tests | Coverage Target |
|----------|------------|------------|-----------------|
| **Unit** | 10 files | ~80 tests | 90% |
| **Integration** | 4 files | ~20 tests | 80% |
| **Security** | 3 files | ~10 tests | 100% of security paths |
| **Total** | 17 files | ~110 tests | 85% overall |

**Pyramid Ratio:** 73% Unit / 18% Integration / 9% Security ≈ 70/20/10
