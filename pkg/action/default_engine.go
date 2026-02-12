package action

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/types"
)

// defaultEngine is the standard implementation of the Engine interface.
type defaultEngine struct {
	mu          sync.RWMutex
	rules       []Rule
	alerter     Alerter
	rateLimiter *rateLimiter
	cooldowns   map[string]time.Time // ruleID -> last execution time
	config      *EngineConfig
}

// NewEngine creates a new action engine with the given configuration.
// It uses a no-op alerter by default.
func NewEngine(config *EngineConfig) Engine {
	if config == nil {
		config = DefaultEngineConfig()
	}
	return &defaultEngine{
		rules:       make([]Rule, 0),
		alerter:     NewHTTPAlerter(config.Alerting),
		rateLimiter: newRateLimiter(),
		cooldowns:   make(map[string]time.Time),
		config:      config,
	}
}

// NewEngineWithAlerter creates a new action engine with a custom alerter.
func NewEngineWithAlerter(config *EngineConfig, alerter Alerter) Engine {
	if config == nil {
		config = DefaultEngineConfig()
	}
	return &defaultEngine{
		rules:       make([]Rule, 0),
		alerter:     alerter,
		rateLimiter: newRateLimiter(),
		cooldowns:   make(map[string]time.Time),
		config:      config,
	}
}

// LoadRules loads the given rules into the engine, replacing any existing rules.
// Rules are sorted by priority (ascending -- lower number = higher priority).
func (e *defaultEngine) LoadRules(rules []Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Copy and sort by priority (ascending)
	sorted := make([]Rule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	e.rules = sorted
	return nil
}

// Evaluate evaluates all enabled rules against the findings in the request.
// It returns an EvaluateResult describing which rules matched and which actions to take.
func (e *defaultEngine) Evaluate(ctx context.Context, req EvaluateRequest) (*EvaluateResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := &EvaluateResult{
		MatchedRules: make([]MatchedRule, 0),
		Actions:      make([]ActionToTake, 0),
	}

	for i := range e.rules {
		rule := &e.rules[i]
		if !rule.Enabled {
			continue
		}

		// Check cooldown
		if e.isInCooldown(rule) {
			continue
		}

		// Check rate limit
		if rule.RateLimit != nil && e.config.RateLimitEnabled {
			key := req.TenantID + ":" + rule.ID
			if !e.rateLimiter.Allow(key, rule.RateLimit.Count, rule.RateLimit.Window) {
				continue
			}
		}

		// Check if ALL conditions match ANY finding
		matchedFindingIDs := e.matchRule(rule, req.Findings)
		if len(matchedFindingIDs) == 0 {
			continue
		}

		// Rule matched
		matched := MatchedRule{
			Rule:       rule,
			FindingIDs: matchedFindingIDs,
		}
		result.MatchedRules = append(result.MatchedRules, matched)

		// Build actions
		for _, action := range rule.Actions {
			att := ActionToTake{
				RuleID:     rule.ID,
				Type:       action.Type,
				Config:     action.Config,
				FindingIDs: matchedFindingIDs,
			}
			result.Actions = append(result.Actions, att)

			// Track block results
			if action.Type == ActionBlock {
				result.ShouldBlock = true
				if result.BlockReason == "" {
					result.BlockReason = fmt.Sprintf("Rule %s: %s", rule.ID, rule.Description)
				}
			}
		}
	}

	return result, nil
}

// Execute executes the actions described in an EvaluateResult.
func (e *defaultEngine) Execute(ctx context.Context, result *EvaluateResult) (*types.ActionResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	actionResult := &types.ActionResult{
		Blocked:      result.ShouldBlock,
		BlockReason:  result.BlockReason,
		RulesMatched: make([]string, 0),
		Actions:      make([]types.ActionTaken, 0),
		Alerts:       make([]types.AlertSent, 0),
	}

	// Collect unique rule IDs
	ruleIDSet := make(map[string]struct{})
	for _, mr := range result.MatchedRules {
		ruleIDSet[mr.Rule.ID] = struct{}{}
	}
	for id := range ruleIDSet {
		actionResult.RulesMatched = append(actionResult.RulesMatched, id)
	}

	// Execute each action
	for _, action := range result.Actions {
		taken := types.ActionTaken{
			RuleID:     action.RuleID,
			ActionType: string(action.Type),
			Success:    true,
		}

		switch action.Type {
		case ActionBlock:
			// Block is already reflected in ShouldBlock; mark success
			taken.Success = true

		case ActionAlert:
			alerts := e.executeAlert(ctx, action)
			actionResult.Alerts = append(actionResult.Alerts, alerts...)

		case ActionLog:
			// Log action is a no-op placeholder for now
			taken.Success = true

		case ActionWebhook:
			err := e.executeWebhook(ctx, action)
			if err != nil {
				taken.Success = false
				taken.Error = err.Error()
			}

		case ActionRedact, ActionTokenize, ActionIncident, ActionQuarantine, ActionMCPBlock:
			// These actions are tracked but not fully executed here.
			// The caller is responsible for implementing the actual logic.
			taken.Success = true

		default:
			taken.Success = false
			taken.Error = fmt.Sprintf("unknown action type: %s", action.Type)
		}

		actionResult.Actions = append(actionResult.Actions, taken)

		// Record cooldown for the rule
		e.cooldowns[action.RuleID] = time.Now()
	}

	return actionResult, nil
}

// Close releases resources held by the engine.
func (e *defaultEngine) Close() error {
	e.rateLimiter.stop()
	return nil
}

// matchRule checks if ALL conditions of a rule match at least one finding.
// Returns the IDs of all findings where all conditions matched.
func (e *defaultEngine) matchRule(rule *Rule, findings []scan.Finding) []string {
	var matchedIDs []string

	for i := range findings {
		finding := &findings[i]
		allMatch := true
		for _, cond := range rule.Conditions {
			if !evaluateCondition(cond, finding) {
				allMatch = false
				break
			}
		}
		if allMatch {
			matchedIDs = append(matchedIDs, finding.ID)
		}
	}

	return matchedIDs
}

// isInCooldown checks if a rule is currently in its cooldown period.
func (e *defaultEngine) isInCooldown(rule *Rule) bool {
	if rule.Cooldown <= 0 {
		return false
	}
	lastExec, ok := e.cooldowns[rule.ID]
	if !ok {
		return false
	}
	return time.Since(lastExec) < rule.Cooldown
}

// executeAlert sends alerts to configured channels based on the action config.
func (e *defaultEngine) executeAlert(ctx context.Context, action ActionToTake) []types.AlertSent {
	var alerts []types.AlertSent

	channels := getChannelsFromConfig(action.Config)

	for _, channel := range channels {
		alert := types.AlertSent{
			Channel:   channel,
			Timestamp: time.Now(),
			Success:   true,
		}

		var err error
		switch strings.ToLower(channel) {
		case "slack":
			err = e.alerter.SendSlack(ctx, SlackAlert{
				Title:   fmt.Sprintf("Gatekeeper Alert [Rule: %s]", action.RuleID),
				Message: fmt.Sprintf("Action triggered by rule %s for findings %v", action.RuleID, action.FindingIDs),
				Fields:  map[string]string{"rule_id": action.RuleID},
			})
		case "pagerduty":
			err = e.alerter.SendPagerDuty(ctx, PagerDutyAlert{
				Summary:  fmt.Sprintf("Gatekeeper Alert [Rule: %s]", action.RuleID),
				Severity: getUrgencyFromConfig(action.Config),
				Source:   "gatekeeper",
				Details: map[string]interface{}{
					"rule_id":     action.RuleID,
					"finding_ids": action.FindingIDs,
				},
			})
		default:
			err = fmt.Errorf("unknown alert channel: %s", channel)
		}

		if err != nil {
			alert.Success = false
			alert.Error = err.Error()
		}

		alerts = append(alerts, alert)
	}

	return alerts
}

// executeWebhook sends a webhook for the given action.
func (e *defaultEngine) executeWebhook(ctx context.Context, action ActionToTake) error {
	url := ""
	method := "POST"
	if action.Config != nil {
		if u, ok := action.Config["url"].(string); ok {
			url = u
		}
		if m, ok := action.Config["method"].(string); ok {
			method = m
		}
	}

	return e.alerter.SendWebhook(ctx, WebhookAlert{
		URL:    url,
		Method: method,
		Body: map[string]interface{}{
			"rule_id":     action.RuleID,
			"finding_ids": action.FindingIDs,
		},
	})
}

// getChannelsFromConfig extracts channel names from an action's config map.
func getChannelsFromConfig(config map[string]interface{}) []string {
	if config == nil {
		return []string{"slack"}
	}

	channelsRaw, ok := config["channels"]
	if !ok {
		return []string{"slack"}
	}

	switch v := channelsRaw.(type) {
	case []interface{}:
		channels := make([]string, 0, len(v))
		for _, ch := range v {
			if s, ok := ch.(string); ok {
				channels = append(channels, s)
			}
		}
		return channels
	case []string:
		return v
	default:
		return []string{"slack"}
	}
}

// getUrgencyFromConfig extracts the urgency/severity string from action config.
func getUrgencyFromConfig(config map[string]interface{}) string {
	if config == nil {
		return "warning"
	}
	if u, ok := config["urgency"].(string); ok {
		return u
	}
	return "warning"
}
