package action

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

// --- Mock Alerter ---

type alertCall struct {
	callType string // "slack", "pagerduty", "webhook"
	slack    *SlackAlert
	pager    *PagerDutyAlert
	webhook  *WebhookAlert
}

type mockAlerter struct {
	mu    sync.Mutex
	calls []alertCall
	// If set, return this error for corresponding call type
	slackErr    error
	pagerErr    error
	webhookErr  error
}

func newMockAlerter() *mockAlerter {
	return &mockAlerter{
		calls: make([]alertCall, 0),
	}
}

func (m *mockAlerter) SendSlack(_ context.Context, alert SlackAlert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, alertCall{callType: "slack", slack: &alert})
	return m.slackErr
}

func (m *mockAlerter) SendPagerDuty(_ context.Context, alert PagerDutyAlert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, alertCall{callType: "pagerduty", pager: &alert})
	return m.pagerErr
}

func (m *mockAlerter) SendWebhook(_ context.Context, alert WebhookAlert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, alertCall{callType: "webhook", webhook: &alert})
	return m.webhookErr
}

func (m *mockAlerter) getCalls() []alertCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]alertCall, len(m.calls))
	copy(cp, m.calls)
	return cp
}

// --- Helper functions ---

func makeFinding(id string, severity scan.Severity, patternID string, patternType scan.PatternType) scan.Finding {
	return scan.Finding{
		ID:          id,
		PatternID:   patternID,
		PatternType: patternType,
		Severity:    severity,
	}
}

func makeFindingWithFrameworks(id string, severity scan.Severity, patternID string, patternType scan.PatternType, frameworks []scan.Framework) scan.Finding {
	f := makeFinding(id, severity, patternID, patternType)
	for _, fw := range frameworks {
		f.Frameworks = append(f.Frameworks, scan.FrameworkMatch{
			Framework: fw,
		})
	}
	return f
}

func makeFindingWithInjection(id string, severity scan.Severity, injType scan.InjectionType) scan.Finding {
	return scan.Finding{
		ID:            id,
		PatternID:     string(injType),
		PatternType:   scan.PatternTypeInjection,
		InjectionType: injType,
		Severity:      severity,
	}
}

func makeFindingWithSource(id string, severity scan.Severity, patternType scan.PatternType, source string) scan.Finding {
	return scan.Finding{
		ID:          id,
		PatternType: patternType,
		Severity:    severity,
		Metadata:    map[string]string{"source": source},
	}
}

func makeFindingWithPIIType(id string, severity scan.Severity, piiType scan.PIIType) scan.Finding {
	return scan.Finding{
		ID:          id,
		PatternID:   string(piiType),
		PatternType: scan.PatternTypePII,
		PIIType:     piiType,
		Severity:    severity,
	}
}

func defaultConfig() *EngineConfig {
	cfg := DefaultEngineConfig()
	cfg.RateLimitEnabled = true
	return cfg
}

// --- Tests for evaluateCondition ---

func TestEvaluateCondition(t *testing.T) {
	finding := scan.Finding{
		ID:            "f1",
		PatternID:     "credit_card",
		PatternType:   scan.PatternTypePII,
		PIIType:       scan.PIITypeCreditCard,
		InjectionType: "",
		Severity:      scan.SeverityCritical,
		Frameworks: []scan.FrameworkMatch{
			{Framework: scan.FrameworkHIPAA},
			{Framework: scan.FrameworkPCIDSS},
		},
		Metadata: map[string]string{"source": "mcp_response"},
	}

	tests := []struct {
		name     string
		cond     Condition
		expected bool
	}{
		// eq operator
		{
			name:     "eq severity matches",
			cond:     Condition{Field: "severity", Operator: "eq", Value: "critical"},
			expected: true,
		},
		{
			name:     "eq severity no match",
			cond:     Condition{Field: "severity", Operator: "eq", Value: "high"},
			expected: false,
		},
		{
			name:     "eq pattern_id matches",
			cond:     Condition{Field: "pattern_id", Operator: "eq", Value: "credit_card"},
			expected: true,
		},
		{
			name:     "eq pattern_type matches",
			cond:     Condition{Field: "pattern_type", Operator: "eq", Value: "pii"},
			expected: true,
		},
		{
			name:     "eq pii_type matches",
			cond:     Condition{Field: "pii_type", Operator: "eq", Value: "credit_card"},
			expected: true,
		},
		{
			name:     "eq source matches",
			cond:     Condition{Field: "source", Operator: "eq", Value: "mcp_response"},
			expected: true,
		},
		// ne operator
		{
			name:     "ne severity different",
			cond:     Condition{Field: "severity", Operator: "ne", Value: "low"},
			expected: true,
		},
		{
			name:     "ne severity same",
			cond:     Condition{Field: "severity", Operator: "ne", Value: "critical"},
			expected: false,
		},
		// in operator
		{
			name:     "in severity matches",
			cond:     Condition{Field: "severity", Operator: "in", Values: []string{"critical", "high"}},
			expected: true,
		},
		{
			name:     "in severity no match",
			cond:     Condition{Field: "severity", Operator: "in", Values: []string{"low", "medium"}},
			expected: false,
		},
		// contains operator (frameworks)
		{
			name:     "contains HIPAA framework",
			cond:     Condition{Field: "frameworks", Operator: "contains", Value: "HIPAA"},
			expected: true,
		},
		{
			name:     "contains GDPR framework no match",
			cond:     Condition{Field: "frameworks", Operator: "contains", Value: "GDPR"},
			expected: false,
		},
		// gt operator (severity comparison)
		{
			name:     "gt severity critical > high",
			cond:     Condition{Field: "severity", Operator: "gt", Value: "high"},
			expected: true,
		},
		{
			name:     "gt severity critical > critical is false",
			cond:     Condition{Field: "severity", Operator: "gt", Value: "critical"},
			expected: false,
		},
		// lt operator (severity comparison)
		{
			name:     "lt severity critical < high is false",
			cond:     Condition{Field: "severity", Operator: "lt", Value: "high"},
			expected: false,
		},
		{
			name:     "lt severity low < high",
			cond:     Condition{Field: "severity", Operator: "lt", Value: "high"},
			expected: false, // critical is not less than high
		},
		// unsupported field
		{
			name:     "unsupported field returns false",
			cond:     Condition{Field: "nonexistent", Operator: "eq", Value: "anything"},
			expected: false,
		},
		// unsupported operator
		{
			name:     "unsupported operator returns false",
			cond:     Condition{Field: "severity", Operator: "regex", Value: ".*"},
			expected: false,
		},
		// rate field is always true (handled elsewhere)
		{
			name:     "rate field always true",
			cond:     Condition{Field: "rate", Operator: "gt", Value: 50},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateCondition(tt.cond, &finding)
			if result != tt.expected {
				t.Errorf("evaluateCondition(%s) = %v, want %v", tt.name, result, tt.expected)
			}
		})
	}
}

func TestEvaluateConditionLTWithLowSeverity(t *testing.T) {
	finding := scan.Finding{
		ID:       "f-low",
		Severity: scan.SeverityLow,
	}

	cond := Condition{Field: "severity", Operator: "lt", Value: "high"}
	if !evaluateCondition(cond, &finding) {
		t.Error("expected low < high to be true")
	}

	cond2 := Condition{Field: "severity", Operator: "lt", Value: "low"}
	if evaluateCondition(cond2, &finding) {
		t.Error("expected low < low to be false")
	}
}

// --- Tests for Evaluate ---

func TestEvaluateSeverityEq(t *testing.T) {
	alerter := newMockAlerter()
	eng := NewEngineWithAlerter(defaultConfig(), alerter)

	rules := []Rule{
		{
			ID:       "critical-block",
			Name:     "Critical Block",
			Enabled:  true,
			Priority: 1,
			Conditions: []Condition{
				{Field: "severity", Operator: "eq", Value: "critical"},
			},
			Actions: []Action{
				{Type: ActionBlock},
			},
		},
	}
	if err := eng.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	ctx := context.Background()
	result, err := eng.Evaluate(ctx, EvaluateRequest{
		Findings: []scan.Finding{
			makeFinding("f1", scan.SeverityCritical, "ssn", scan.PatternTypePII),
		},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if !result.ShouldBlock {
		t.Error("expected ShouldBlock to be true for critical severity")
	}
	if len(result.MatchedRules) != 1 {
		t.Errorf("expected 1 matched rule, got %d", len(result.MatchedRules))
	}
	if result.MatchedRules[0].Rule.ID != "critical-block" {
		t.Errorf("expected rule ID 'critical-block', got '%s'", result.MatchedRules[0].Rule.ID)
	}
}

func TestEvaluateFrameworkContains(t *testing.T) {
	alerter := newMockAlerter()
	eng := NewEngineWithAlerter(defaultConfig(), alerter)

	rules := []Rule{
		{
			ID:       "hipaa-block",
			Name:     "HIPAA Block",
			Enabled:  true,
			Priority: 1,
			Conditions: []Condition{
				{Field: "frameworks", Operator: "contains", Value: "HIPAA"},
				{Field: "severity", Operator: "in", Values: []string{"critical", "high"}},
			},
			Actions: []Action{
				{Type: ActionBlock},
			},
		},
	}
	if err := eng.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	ctx := context.Background()

	// Should match: HIPAA + high severity
	result, err := eng.Evaluate(ctx, EvaluateRequest{
		Findings: []scan.Finding{
			makeFindingWithFrameworks("f1", scan.SeverityHigh, "mrn", scan.PatternTypePII, []scan.Framework{scan.FrameworkHIPAA}),
		},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if !result.ShouldBlock {
		t.Error("expected HIPAA high severity to trigger block")
	}

	// Should not match: HIPAA + low severity
	result, err = eng.Evaluate(ctx, EvaluateRequest{
		Findings: []scan.Finding{
			makeFindingWithFrameworks("f2", scan.SeverityLow, "mrn", scan.PatternTypePII, []scan.Framework{scan.FrameworkHIPAA}),
		},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if result.ShouldBlock {
		t.Error("expected HIPAA low severity to NOT trigger block")
	}

	// Should not match: GDPR + high severity (wrong framework)
	result, err = eng.Evaluate(ctx, EvaluateRequest{
		Findings: []scan.Finding{
			makeFindingWithFrameworks("f3", scan.SeverityHigh, "email", scan.PatternTypePII, []scan.Framework{scan.FrameworkGDPR}),
		},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if result.ShouldBlock {
		t.Error("expected GDPR (not HIPAA) to NOT trigger hipaa-block rule")
	}
}

func TestEvaluatePatternType(t *testing.T) {
	alerter := newMockAlerter()
	eng := NewEngineWithAlerter(defaultConfig(), alerter)

	rules := []Rule{
		{
			ID:       "credential-block",
			Name:     "Credential Block",
			Enabled:  true,
			Priority: 1,
			Conditions: []Condition{
				{Field: "pattern_type", Operator: "eq", Value: "credential"},
			},
			Actions: []Action{
				{Type: ActionBlock},
			},
		},
	}
	if err := eng.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	ctx := context.Background()

	// Should match credential pattern type
	result, err := eng.Evaluate(ctx, EvaluateRequest{
		Findings: []scan.Finding{
			makeFinding("f1", scan.SeverityHigh, "aws_key", scan.PatternTypeCredential),
		},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if !result.ShouldBlock {
		t.Error("expected credential finding to trigger block")
	}

	// Should not match PII pattern type
	result, err = eng.Evaluate(ctx, EvaluateRequest{
		Findings: []scan.Finding{
			makeFinding("f2", scan.SeverityHigh, "email", scan.PatternTypePII),
		},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if result.ShouldBlock {
		t.Error("expected PII finding to NOT trigger credential-block rule")
	}
}

func TestRulePriorityOrdering(t *testing.T) {
	alerter := newMockAlerter()
	eng := NewEngineWithAlerter(defaultConfig(), alerter)

	rules := []Rule{
		{
			ID:       "low-priority",
			Name:     "Low Priority Rule",
			Enabled:  true,
			Priority: 10,
			Conditions: []Condition{
				{Field: "severity", Operator: "eq", Value: "critical"},
			},
			Actions: []Action{
				{Type: ActionLog},
			},
		},
		{
			ID:       "high-priority",
			Name:     "High Priority Rule",
			Enabled:  true,
			Priority: 1,
			Conditions: []Condition{
				{Field: "severity", Operator: "eq", Value: "critical"},
			},
			Actions: []Action{
				{Type: ActionBlock},
			},
		},
		{
			ID:       "medium-priority",
			Name:     "Medium Priority Rule",
			Enabled:  true,
			Priority: 5,
			Conditions: []Condition{
				{Field: "severity", Operator: "eq", Value: "critical"},
			},
			Actions: []Action{
				{Type: ActionAlert, Config: map[string]interface{}{"channels": []string{"slack"}}},
			},
		},
	}
	if err := eng.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	ctx := context.Background()
	result, err := eng.Evaluate(ctx, EvaluateRequest{
		Findings: []scan.Finding{
			makeFinding("f1", scan.SeverityCritical, "ssn", scan.PatternTypePII),
		},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if len(result.MatchedRules) != 3 {
		t.Fatalf("expected 3 matched rules, got %d", len(result.MatchedRules))
	}

	// Rules should be in priority order: high (1), medium (5), low (10)
	expectedOrder := []string{"high-priority", "medium-priority", "low-priority"}
	for i, mr := range result.MatchedRules {
		if mr.Rule.ID != expectedOrder[i] {
			t.Errorf("matched rule[%d] = %s, want %s", i, mr.Rule.ID, expectedOrder[i])
		}
	}
}

func TestCooldownBehavior(t *testing.T) {
	alerter := newMockAlerter()
	eng := NewEngineWithAlerter(defaultConfig(), alerter)

	rules := []Rule{
		{
			ID:       "cooldown-rule",
			Name:     "Cooldown Rule",
			Enabled:  true,
			Priority: 1,
			Conditions: []Condition{
				{Field: "severity", Operator: "eq", Value: "high"},
			},
			Actions: []Action{
				{Type: ActionLog},
			},
			Cooldown: 5 * time.Minute,
		},
	}
	if err := eng.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	ctx := context.Background()
	finding := makeFinding("f1", scan.SeverityHigh, "email", scan.PatternTypePII)
	req := EvaluateRequest{
		Findings: []scan.Finding{finding},
		TenantID: "t1",
	}

	// First evaluation should match
	result, err := eng.Evaluate(ctx, req)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if len(result.MatchedRules) != 1 {
		t.Fatalf("expected 1 matched rule on first eval, got %d", len(result.MatchedRules))
	}

	// Execute to set the cooldown timestamp
	_, err = eng.Execute(ctx, result)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Second evaluation within cooldown should NOT match
	result, err = eng.Evaluate(ctx, req)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if len(result.MatchedRules) != 0 {
		t.Errorf("expected 0 matched rules during cooldown, got %d", len(result.MatchedRules))
	}
}

func TestRateLimiting(t *testing.T) {
	rl := newRateLimiter()
	defer rl.stop()

	key := "tenant1:rule1"
	limit := 3
	window := time.Second

	// First 3 should be allowed
	for i := 0; i < limit; i++ {
		if !rl.Allow(key, limit, window) {
			t.Errorf("request %d should have been allowed", i+1)
		}
	}

	// 4th should be denied
	if rl.Allow(key, limit, window) {
		t.Error("request beyond limit should have been denied")
	}

	// After window passes, should be allowed again
	time.Sleep(window + 50*time.Millisecond)

	if !rl.Allow(key, limit, window) {
		t.Error("request after window reset should have been allowed")
	}
}

func TestRateLimitingDifferentKeys(t *testing.T) {
	rl := newRateLimiter()
	defer rl.stop()

	limit := 1
	window := time.Second

	if !rl.Allow("key1", limit, window) {
		t.Error("key1 first request should be allowed")
	}
	if rl.Allow("key1", limit, window) {
		t.Error("key1 second request should be denied")
	}
	if !rl.Allow("key2", limit, window) {
		t.Error("key2 first request should be allowed (different key)")
	}
}

func TestExecuteBlockAction(t *testing.T) {
	alerter := newMockAlerter()
	eng := NewEngineWithAlerter(defaultConfig(), alerter)

	rules := []Rule{
		{
			ID:       "block-rule",
			Name:     "Block Rule",
			Enabled:  true,
			Priority: 1,
			Conditions: []Condition{
				{Field: "severity", Operator: "eq", Value: "critical"},
			},
			Actions: []Action{
				{Type: ActionBlock},
			},
		},
	}
	if err := eng.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	ctx := context.Background()
	evalResult, err := eng.Evaluate(ctx, EvaluateRequest{
		Findings: []scan.Finding{
			makeFinding("f1", scan.SeverityCritical, "ssn", scan.PatternTypePII),
		},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	actionResult, err := eng.Execute(ctx, evalResult)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !actionResult.Blocked {
		t.Error("expected Blocked to be true")
	}
	if len(actionResult.Actions) != 1 {
		t.Fatalf("expected 1 action taken, got %d", len(actionResult.Actions))
	}
	if actionResult.Actions[0].ActionType != "block" {
		t.Errorf("expected action type 'block', got '%s'", actionResult.Actions[0].ActionType)
	}
	if !actionResult.Actions[0].Success {
		t.Error("expected block action to succeed")
	}
}

func TestExecuteAlertAction(t *testing.T) {
	alerter := newMockAlerter()
	eng := NewEngineWithAlerter(defaultConfig(), alerter)

	rules := []Rule{
		{
			ID:       "alert-rule",
			Name:     "Alert Rule",
			Enabled:  true,
			Priority: 1,
			Conditions: []Condition{
				{Field: "severity", Operator: "eq", Value: "high"},
			},
			Actions: []Action{
				{Type: ActionAlert, Config: map[string]interface{}{
					"channels": []interface{}{"slack", "pagerduty"},
				}},
			},
		},
	}
	if err := eng.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	ctx := context.Background()
	evalResult, err := eng.Evaluate(ctx, EvaluateRequest{
		Findings: []scan.Finding{
			makeFinding("f1", scan.SeverityHigh, "email", scan.PatternTypePII),
		},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	actionResult, err := eng.Execute(ctx, evalResult)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if actionResult.Blocked {
		t.Error("expected Blocked to be false for alert-only rule")
	}

	// Check mock alerter was called
	calls := alerter.getCalls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 alerter calls, got %d", len(calls))
	}

	// Verify Slack call
	foundSlack := false
	foundPager := false
	for _, c := range calls {
		if c.callType == "slack" {
			foundSlack = true
		}
		if c.callType == "pagerduty" {
			foundPager = true
		}
	}
	if !foundSlack {
		t.Error("expected slack alert to be sent")
	}
	if !foundPager {
		t.Error("expected pagerduty alert to be sent")
	}

	// Check alerts in result
	if len(actionResult.Alerts) != 2 {
		t.Errorf("expected 2 alerts in result, got %d", len(actionResult.Alerts))
	}
}

func TestFullEvaluateExecute(t *testing.T) {
	alerter := newMockAlerter()
	eng := NewEngineWithAlerter(defaultConfig(), alerter)

	rules := []Rule{
		{
			ID:       "critical-block",
			Name:     "Critical Block",
			Enabled:  true,
			Priority: 1,
			Conditions: []Condition{
				{Field: "severity", Operator: "eq", Value: "critical"},
			},
			Actions: []Action{
				{Type: ActionBlock},
				{Type: ActionAlert, Config: map[string]interface{}{
					"channels": []interface{}{"slack"},
				}},
				{Type: ActionLog},
			},
		},
		{
			ID:       "pci-tokenize",
			Name:     "PCI Tokenize",
			Enabled:  true,
			Priority: 2,
			Conditions: []Condition{
				{Field: "pattern_id", Operator: "eq", Value: "credit_card"},
			},
			Actions: []Action{
				{Type: ActionTokenize},
				{Type: ActionLog},
			},
		},
		{
			ID:       "disabled-rule",
			Name:     "Disabled Rule",
			Enabled:  false,
			Priority: 1,
			Conditions: []Condition{
				{Field: "severity", Operator: "eq", Value: "critical"},
			},
			Actions: []Action{
				{Type: ActionBlock},
			},
		},
	}
	if err := eng.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	ctx := context.Background()
	findings := []scan.Finding{
		makeFinding("f1", scan.SeverityCritical, "credit_card", scan.PatternTypePII),
		makeFinding("f2", scan.SeverityMedium, "email", scan.PatternTypePII),
	}

	evalResult, err := eng.Evaluate(ctx, EvaluateRequest{
		Findings:  findings,
		TenantID:  "tenant-123",
		RequestID: "req-abc",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// critical-block should match f1 (critical severity)
	// pci-tokenize should match f1 (credit_card pattern_id)
	// disabled-rule should NOT match (disabled)
	if len(evalResult.MatchedRules) != 2 {
		t.Fatalf("expected 2 matched rules, got %d", len(evalResult.MatchedRules))
	}
	if !evalResult.ShouldBlock {
		t.Error("expected ShouldBlock from critical-block rule")
	}

	// Execute all actions
	actionResult, err := eng.Execute(ctx, evalResult)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !actionResult.Blocked {
		t.Error("expected Blocked in action result")
	}

	// 3 actions from critical-block + 2 from pci-tokenize = 5 total
	if len(actionResult.Actions) != 5 {
		t.Errorf("expected 5 actions, got %d", len(actionResult.Actions))
	}

	// All actions should have succeeded
	for i, a := range actionResult.Actions {
		if !a.Success {
			t.Errorf("action[%d] (%s) failed: %s", i, a.ActionType, a.Error)
		}
	}

	// Slack should have been called once
	calls := alerter.getCalls()
	slackCount := 0
	for _, c := range calls {
		if c.callType == "slack" {
			slackCount++
		}
	}
	if slackCount != 1 {
		t.Errorf("expected 1 slack alert call, got %d", slackCount)
	}
}

func TestDisabledRuleSkipped(t *testing.T) {
	alerter := newMockAlerter()
	eng := NewEngineWithAlerter(defaultConfig(), alerter)

	rules := []Rule{
		{
			ID:       "disabled-rule",
			Name:     "Disabled Rule",
			Enabled:  false,
			Priority: 1,
			Conditions: []Condition{
				{Field: "severity", Operator: "eq", Value: "critical"},
			},
			Actions: []Action{
				{Type: ActionBlock},
			},
		},
	}
	if err := eng.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	ctx := context.Background()
	result, err := eng.Evaluate(ctx, EvaluateRequest{
		Findings: []scan.Finding{
			makeFinding("f1", scan.SeverityCritical, "ssn", scan.PatternTypePII),
		},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if len(result.MatchedRules) != 0 {
		t.Error("disabled rule should not match")
	}
	if result.ShouldBlock {
		t.Error("disabled rule should not cause block")
	}
}

func TestNoFindingsNoMatch(t *testing.T) {
	alerter := newMockAlerter()
	eng := NewEngineWithAlerter(defaultConfig(), alerter)

	rules := []Rule{
		{
			ID:       "any-rule",
			Name:     "Any Rule",
			Enabled:  true,
			Priority: 1,
			Conditions: []Condition{
				{Field: "severity", Operator: "eq", Value: "critical"},
			},
			Actions: []Action{
				{Type: ActionBlock},
			},
		},
	}
	if err := eng.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	ctx := context.Background()
	result, err := eng.Evaluate(ctx, EvaluateRequest{
		Findings: []scan.Finding{},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if len(result.MatchedRules) != 0 {
		t.Error("no findings should produce no matches")
	}
}

func TestMultipleConditionsAllMustMatch(t *testing.T) {
	alerter := newMockAlerter()
	eng := NewEngineWithAlerter(defaultConfig(), alerter)

	rules := []Rule{
		{
			ID:       "multi-cond",
			Name:     "Multi Condition",
			Enabled:  true,
			Priority: 1,
			Conditions: []Condition{
				{Field: "severity", Operator: "eq", Value: "critical"},
				{Field: "pattern_type", Operator: "eq", Value: "credential"},
			},
			Actions: []Action{
				{Type: ActionBlock},
			},
		},
	}
	if err := eng.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	ctx := context.Background()

	// Only severity matches, not pattern_type
	result, err := eng.Evaluate(ctx, EvaluateRequest{
		Findings: []scan.Finding{
			makeFinding("f1", scan.SeverityCritical, "ssn", scan.PatternTypePII),
		},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if len(result.MatchedRules) != 0 {
		t.Error("expected no match when only one condition matches")
	}

	// Both conditions match
	result, err = eng.Evaluate(ctx, EvaluateRequest{
		Findings: []scan.Finding{
			makeFinding("f2", scan.SeverityCritical, "aws_key", scan.PatternTypeCredential),
		},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if len(result.MatchedRules) != 1 {
		t.Error("expected match when all conditions match")
	}
}

func TestEngineClose(t *testing.T) {
	eng := NewEngine(defaultConfig())
	err := eng.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestEvaluateInjectionType(t *testing.T) {
	alerter := newMockAlerter()
	eng := NewEngineWithAlerter(defaultConfig(), alerter)

	rules := []Rule{
		{
			ID:       "sqli-detect",
			Name:     "SQLi Detection",
			Enabled:  true,
			Priority: 1,
			Conditions: []Condition{
				{Field: "injection_type", Operator: "eq", Value: "sql_injection"},
			},
			Actions: []Action{
				{Type: ActionBlock},
			},
		},
	}
	if err := eng.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	ctx := context.Background()
	result, err := eng.Evaluate(ctx, EvaluateRequest{
		Findings: []scan.Finding{
			makeFindingWithInjection("f1", scan.SeverityCritical, scan.InjectionTypeSQL),
		},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if !result.ShouldBlock {
		t.Error("expected SQL injection to trigger block")
	}
}

func TestEvaluateSourceField(t *testing.T) {
	alerter := newMockAlerter()
	eng := NewEngineWithAlerter(defaultConfig(), alerter)

	rules := []Rule{
		{
			ID:       "mcp-detect",
			Name:     "MCP Source Detection",
			Enabled:  true,
			Priority: 1,
			Conditions: []Condition{
				{Field: "source", Operator: "eq", Value: "mcp_response"},
			},
			Actions: []Action{
				{Type: ActionAlert, Config: map[string]interface{}{
					"channels": []interface{}{"slack"},
				}},
			},
		},
	}
	if err := eng.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	ctx := context.Background()
	result, err := eng.Evaluate(ctx, EvaluateRequest{
		Findings: []scan.Finding{
			makeFindingWithSource("f1", scan.SeverityMedium, scan.PatternTypePII, "mcp_response"),
		},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if len(result.MatchedRules) != 1 {
		t.Errorf("expected 1 matched rule for mcp_response source, got %d", len(result.MatchedRules))
	}
}

func TestExecuteWebhookAction(t *testing.T) {
	alerter := newMockAlerter()
	eng := NewEngineWithAlerter(defaultConfig(), alerter)

	rules := []Rule{
		{
			ID:       "webhook-rule",
			Name:     "Webhook Rule",
			Enabled:  true,
			Priority: 1,
			Conditions: []Condition{
				{Field: "severity", Operator: "eq", Value: "high"},
			},
			Actions: []Action{
				{Type: ActionWebhook, Config: map[string]interface{}{
					"url":    "https://example.com/webhook",
					"method": "POST",
				}},
			},
		},
	}
	if err := eng.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	ctx := context.Background()
	evalResult, err := eng.Evaluate(ctx, EvaluateRequest{
		Findings: []scan.Finding{
			makeFinding("f1", scan.SeverityHigh, "email", scan.PatternTypePII),
		},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	_, err = eng.Execute(ctx, evalResult)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	calls := alerter.getCalls()
	webhookCalls := 0
	for _, c := range calls {
		if c.callType == "webhook" {
			webhookCalls++
			if c.webhook.URL != "https://example.com/webhook" {
				t.Errorf("expected webhook URL https://example.com/webhook, got %s", c.webhook.URL)
			}
			if c.webhook.Method != "POST" {
				t.Errorf("expected webhook method POST, got %s", c.webhook.Method)
			}
		}
	}
	if webhookCalls != 1 {
		t.Errorf("expected 1 webhook call, got %d", webhookCalls)
	}
}

func TestRateLimitOnRule(t *testing.T) {
	alerter := newMockAlerter()
	cfg := defaultConfig()
	cfg.RateLimitEnabled = true
	eng := NewEngineWithAlerter(cfg, alerter)

	rules := []Rule{
		{
			ID:       "rate-limited-rule",
			Name:     "Rate Limited Rule",
			Enabled:  true,
			Priority: 1,
			Conditions: []Condition{
				{Field: "severity", Operator: "eq", Value: "medium"},
			},
			Actions: []Action{
				{Type: ActionLog},
			},
			RateLimit: &RateLimit{
				Count:  2,
				Window: 5 * time.Second,
			},
		},
	}
	if err := eng.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	ctx := context.Background()
	req := EvaluateRequest{
		Findings: []scan.Finding{
			makeFinding("f1", scan.SeverityMedium, "email", scan.PatternTypePII),
		},
		TenantID: "t1",
	}

	// First 2 evaluations should match
	for i := 0; i < 2; i++ {
		result, err := eng.Evaluate(ctx, req)
		if err != nil {
			t.Fatalf("Evaluate %d failed: %v", i, err)
		}
		if len(result.MatchedRules) != 1 {
			t.Errorf("evaluation %d: expected 1 matched rule, got %d", i, len(result.MatchedRules))
		}
	}

	// 3rd evaluation should be rate-limited (no match)
	result, err := eng.Evaluate(ctx, req)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if len(result.MatchedRules) != 0 {
		t.Errorf("expected 0 matched rules after rate limit, got %d", len(result.MatchedRules))
	}
}

func TestMultipleFindingsMatchSameRule(t *testing.T) {
	alerter := newMockAlerter()
	eng := NewEngineWithAlerter(defaultConfig(), alerter)

	rules := []Rule{
		{
			ID:       "block-critical",
			Name:     "Block Critical",
			Enabled:  true,
			Priority: 1,
			Conditions: []Condition{
				{Field: "severity", Operator: "eq", Value: "critical"},
			},
			Actions: []Action{
				{Type: ActionBlock},
			},
		},
	}
	if err := eng.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	ctx := context.Background()
	result, err := eng.Evaluate(ctx, EvaluateRequest{
		Findings: []scan.Finding{
			makeFinding("f1", scan.SeverityCritical, "ssn", scan.PatternTypePII),
			makeFinding("f2", scan.SeverityCritical, "cc", scan.PatternTypePII),
			makeFinding("f3", scan.SeverityLow, "email", scan.PatternTypePII),
		},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if len(result.MatchedRules) != 1 {
		t.Fatalf("expected 1 matched rule, got %d", len(result.MatchedRules))
	}

	// Should have 2 finding IDs (f1 and f2, not f3)
	if len(result.MatchedRules[0].FindingIDs) != 2 {
		t.Errorf("expected 2 finding IDs, got %d", len(result.MatchedRules[0].FindingIDs))
	}
}

func TestSeverityValueHelper(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"critical", 4},
		{"high", 3},
		{"medium", 2},
		{"low", 1},
		{"CRITICAL", 4},
		{"High", 3},
		{"unknown", 0},
		{"", 0},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := severityValue(tt.input); got != tt.expected {
				t.Errorf("severityValue(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}
