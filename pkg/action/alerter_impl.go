package action

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

// httpAlerter implements the Alerter interface using HTTP calls to external services.
type httpAlerter struct {
	client *http.Client
	config AlertingConfig
}

// NewHTTPAlerter creates a new HTTP-based alerter with the given configuration.
func NewHTTPAlerter(config AlertingConfig) Alerter {
	return &httpAlerter{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		config: config,
	}
}

// SendSlack sends an alert to Slack via the configured incoming webhook URL.
func (a *httpAlerter) SendSlack(ctx context.Context, alert SlackAlert) error {
	if !a.config.Slack.Enabled {
		return fmt.Errorf("slack alerting is not enabled")
	}

	webhookURL := a.config.Slack.WebhookURL
	if webhookURL == "" {
		return fmt.Errorf("slack webhook URL is not configured")
	}

	// Build Slack message payload
	fields := make([]map[string]interface{}, 0, len(alert.Fields))
	for k, v := range alert.Fields {
		fields = append(fields, map[string]interface{}{
			"title": k,
			"value": v,
			"short": true,
		})
	}

	payload := map[string]interface{}{
		"channel": alert.Channel,
		"attachments": []map[string]interface{}{
			{
				"color":  slackColorForSeverity(alert.Severity),
				"title":  alert.Title,
				"text":   alert.Message,
				"fields": fields,
				"ts":     time.Now().Unix(),
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send slack alert: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}

	return nil
}

// SendPagerDuty sends an alert to PagerDuty using the Events API v2 format.
func (a *httpAlerter) SendPagerDuty(ctx context.Context, alert PagerDutyAlert) error {
	if !a.config.PagerDuty.Enabled {
		return fmt.Errorf("pagerduty alerting is not enabled")
	}

	routingKey := a.config.PagerDuty.RoutingKey
	if routingKey == "" {
		return fmt.Errorf("pagerduty routing key is not configured")
	}

	payload := map[string]interface{}{
		"routing_key":  routingKey,
		"event_action": "trigger",
		"payload": map[string]interface{}{
			"summary":        alert.Summary,
			"severity":       alert.Severity,
			"source":         alert.Source,
			"custom_details": alert.Details,
			"timestamp":      time.Now().Format(time.RFC3339),
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal pagerduty payload: %w", err)
	}

	const pagerDutyEventsURL = "https://events.pagerduty.com/v2/enqueue"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pagerDutyEventsURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create pagerduty request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send pagerduty alert: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("pagerduty returned status %d", resp.StatusCode)
	}

	return nil
}

// SendWebhook sends an alert to a configured webhook URL.
func (a *httpAlerter) SendWebhook(ctx context.Context, alert WebhookAlert) error {
	if !a.config.Webhook.Enabled {
		return fmt.Errorf("webhook alerting is not enabled")
	}

	url := alert.URL
	if url == "" {
		url = a.config.Webhook.URL
	}
	if url == "" {
		return fmt.Errorf("webhook URL is not configured")
	}

	method := alert.Method
	if method == "" {
		method = http.MethodPost
	}

	body, err := json.Marshal(alert.Body)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	for k, v := range alert.Headers {
		req.Header.Set(k, v)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// slackColorForSeverity returns a Slack attachment color based on severity.
func slackColorForSeverity(severity scan.Severity) string {
	switch severity {
	case scan.SeverityCritical:
		return "#FF0000" // Red
	case scan.SeverityHigh:
		return "#FF6600" // Orange
	case scan.SeverityMedium:
		return "#FFCC00" // Yellow
	case scan.SeverityLow:
		return "#36A64F" // Green
	default:
		return "#808080" // Gray
	}
}
