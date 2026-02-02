// Package action provides rule-based automated responses to findings.
package action

import (
	"context"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/pipeline"
	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

// Engine evaluates rules and executes actions based on findings
type Engine interface {
	// Evaluate evaluates all rules against findings and returns actions to take
	Evaluate(ctx context.Context, req EvaluateRequest) (*EvaluateResult, error)

	// Execute executes the determined actions
	Execute(ctx context.Context, result *EvaluateResult) (*pipeline.ActionResult, error)

	// LoadRules loads rules from configuration
	LoadRules(rules []Rule) error

	// Close releases resources
	Close() error
}

// EvaluateRequest contains inputs for rule evaluation
type EvaluateRequest struct {
	Findings    []scan.Finding
	ScanResult  *scan.ScanResult
	RequestID   string
	TenantID    string
	UserID      string
	Source      string
	MCPServerID string
}

// EvaluateResult contains the actions to be executed
type EvaluateResult struct {
	ShouldBlock  bool
	BlockReason  string
	MatchedRules []MatchedRule
	Actions      []ActionToTake
}

// MatchedRule represents a rule that matched findings
type MatchedRule struct {
	Rule       *Rule
	FindingIDs []string
}

// ActionToTake represents an action that should be executed
type ActionToTake struct {
	RuleID     string
	Type       ActionType
	Config     map[string]interface{}
	FindingIDs []string
}

// ActionType defines types of automated actions
type ActionType string

const (
	ActionBlock      ActionType = "block"
	ActionRedact     ActionType = "redact"
	ActionTokenize   ActionType = "tokenize"
	ActionAlert      ActionType = "alert"
	ActionLog        ActionType = "log"
	ActionWebhook    ActionType = "webhook"
	ActionIncident   ActionType = "create_incident"
	ActionQuarantine ActionType = "quarantine"
	ActionMCPBlock   ActionType = "block_mcp_server"
)

// Rule defines an action rule
type Rule struct {
	ID          string        `json:"id" yaml:"id"`
	Name        string        `json:"name" yaml:"name"`
	Description string        `json:"description" yaml:"description"`
	Enabled     bool          `json:"enabled" yaml:"enabled"`
	Priority    int           `json:"priority" yaml:"priority"` // Lower = higher priority
	Conditions  []Condition   `json:"conditions" yaml:"conditions"`
	Actions     []Action      `json:"actions" yaml:"actions"`
	RateLimit   *RateLimit    `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty"`
	Cooldown    time.Duration `json:"cooldown" yaml:"cooldown"`
}

// Condition defines a rule condition
type Condition struct {
	Field    string      `json:"field" yaml:"field"`       // "severity", "pattern_id", "frameworks", etc.
	Operator string      `json:"operator" yaml:"operator"` // "eq", "ne", "in", "contains", "gt", "lt"
	Value    interface{} `json:"value" yaml:"value"`
	Values   []string    `json:"values,omitempty" yaml:"values,omitempty"` // For "in" operator
	Window   string      `json:"window,omitempty" yaml:"window,omitempty"` // For rate conditions
}

// Action defines an action to take
type Action struct {
	Type   ActionType             `json:"type" yaml:"type"`
	Config map[string]interface{} `json:"config,omitempty" yaml:"config,omitempty"`
}

// RateLimit defines rate limiting for a rule
type RateLimit struct {
	Count  int           `json:"count" yaml:"count"`
	Window time.Duration `json:"window" yaml:"window"`
}

// Alerter sends alerts to external systems
type Alerter interface {
	// SendSlack sends an alert to Slack
	SendSlack(ctx context.Context, alert SlackAlert) error

	// SendPagerDuty sends an alert to PagerDuty
	SendPagerDuty(ctx context.Context, alert PagerDutyAlert) error

	// SendWebhook sends an alert to a webhook
	SendWebhook(ctx context.Context, alert WebhookAlert) error
}

// SlackAlert represents a Slack alert
type SlackAlert struct {
	Channel  string
	Title    string
	Message  string
	Severity scan.Severity
	Fields   map[string]string
}

// PagerDutyAlert represents a PagerDuty alert
type PagerDutyAlert struct {
	Summary  string
	Severity string // "critical", "error", "warning", "info"
	Source   string
	Details  map[string]interface{}
}

// WebhookAlert represents a webhook alert
type WebhookAlert struct {
	URL     string
	Method  string
	Headers map[string]string
	Body    interface{}
}

// EngineConfig configures the action engine
type EngineConfig struct {
	Enabled       bool          `json:"enabled"`
	RulesFile     string        `json:"rules_file"`
	MaxActions    int           `json:"max_actions"`
	DefaultAction ActionType    `json:"default_action"`
	Timeout       time.Duration `json:"timeout"`

	// Rate limiting
	RateLimitEnabled bool          `json:"rate_limit_enabled"`
	RateLimitWindow  time.Duration `json:"rate_limit_window"`
	RateLimitMax     int           `json:"rate_limit_max"`

	// Alerting
	Alerting AlertingConfig `json:"alerting"`
}

// AlertingConfig configures alert destinations
type AlertingConfig struct {
	Slack     SlackConfig     `json:"slack"`
	PagerDuty PagerDutyConfig `json:"pagerduty"`
	Webhook   WebhookConfig   `json:"webhook"`
}

// SlackConfig configures Slack alerting
type SlackConfig struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel"`
}

// PagerDutyConfig configures PagerDuty alerting
type PagerDutyConfig struct {
	Enabled    bool   `json:"enabled"`
	RoutingKey string `json:"routing_key"`
}

// WebhookConfig configures webhook alerting
type WebhookConfig struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
}

// DefaultEngineConfig returns default engine configuration
func DefaultEngineConfig() *EngineConfig {
	return &EngineConfig{
		Enabled:          true,
		MaxActions:       100,
		DefaultAction:    ActionLog,
		Timeout:          10 * time.Second,
		RateLimitEnabled: true,
		RateLimitWindow:  time.Minute,
		RateLimitMax:     1000,
	}
}
