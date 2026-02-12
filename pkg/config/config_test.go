package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// repoRoot returns the absolute path to the repository root by walking up
// from the test file location until it finds go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repository root (go.mod)")
		}
		dir = parent
	}
}

// -----------------------------------------------------------------------
// TestLoadConfig - Parse configs/gatekeeper.yaml and verify key fields
// -----------------------------------------------------------------------

func TestLoadConfig(t *testing.T) {
	root := repoRoot(t)
	cfgPath := filepath.Join(root, "configs", "gatekeeper.yaml")

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig(%s): %v", cfgPath, err)
	}

	// Service section
	if cfg.Service.ID != "gatekeeper" {
		t.Errorf("service.id = %q, want %q", cfg.Service.ID, "gatekeeper")
	}
	if cfg.Service.Version != "1.0.0" {
		t.Errorf("service.version = %q, want %q", cfg.Service.Version, "1.0.0")
	}
	if cfg.Service.Environment != "development" {
		t.Errorf("service.environment = %q, want %q", cfg.Service.Environment, "development")
	}

	// Databunker section
	if cfg.Databunker.Timeout != 5*time.Second {
		t.Errorf("databunker.timeout = %v, want %v", cfg.Databunker.Timeout, 5*time.Second)
	}
	if cfg.Databunker.Retry.MaxAttempts != 3 {
		t.Errorf("databunker.retry.max_attempts = %d, want 3", cfg.Databunker.Retry.MaxAttempts)
	}
	if cfg.Databunker.Retry.Backoff != 100*time.Millisecond {
		t.Errorf("databunker.retry.backoff = %v, want %v", cfg.Databunker.Retry.Backoff, 100*time.Millisecond)
	}

	// Attestation section
	if cfg.Attestation.SigningKeyName != "tas-scan-signing-key" {
		t.Errorf("attestation.signing_key_name = %q, want %q", cfg.Attestation.SigningKeyName, "tas-scan-signing-key")
	}
	if cfg.Attestation.TTL != 5*time.Minute {
		t.Errorf("attestation.ttl = %v, want %v", cfg.Attestation.TTL, 5*time.Minute)
	}
	if cfg.Attestation.Algorithm != "HMAC-SHA256" {
		t.Errorf("attestation.algorithm = %q, want %q", cfg.Attestation.Algorithm, "HMAC-SHA256")
	}

	// Scanning section
	if cfg.Scanning.DefaultProfile != "full" {
		t.Errorf("scanning.default_profile = %q, want %q", cfg.Scanning.DefaultProfile, "full")
	}
	if !cfg.Scanning.HonorAttestations {
		t.Error("scanning.honor_attestations should be true")
	}
	if cfg.Scanning.MaxContentSize != 10485760 {
		t.Errorf("scanning.max_content_size = %d, want 10485760", cfg.Scanning.MaxContentSize)
	}
	if cfg.Scanning.Timeout != 30*time.Second {
		t.Errorf("scanning.timeout = %v, want %v", cfg.Scanning.Timeout, 30*time.Second)
	}

	// Trust tiers
	if cfg.Scanning.TrustTiers.Internal.ScanProfile != "injection_only" {
		t.Errorf("trust_tiers.internal.scan_profile = %q, want %q", cfg.Scanning.TrustTiers.Internal.ScanProfile, "injection_only")
	}
	if !cfg.Scanning.TrustTiers.Internal.SkipPII {
		t.Error("trust_tiers.internal.skip_pii should be true")
	}
	if cfg.Scanning.TrustTiers.Partner.ScanProfile != "full" {
		t.Errorf("trust_tiers.partner.scan_profile = %q, want %q", cfg.Scanning.TrustTiers.Partner.ScanProfile, "full")
	}

	// Patterns
	if cfg.Scanning.Patterns.BlockSize != 65536 {
		t.Errorf("patterns.block_size = %d, want 65536", cfg.Scanning.Patterns.BlockSize)
	}
	if cfg.Scanning.Patterns.ScratchPoolSize != 4 {
		t.Errorf("patterns.scratch_pool_size = %d, want 4", cfg.Scanning.Patterns.ScratchPoolSize)
	}
	if !cfg.Scanning.Patterns.Precompile {
		t.Error("patterns.precompile should be true")
	}

	// Redaction
	if cfg.Scanning.Redaction.Mode != "tokenize" {
		t.Errorf("redaction.mode = %q, want %q", cfg.Scanning.Redaction.Mode, "tokenize")
	}
	if len(cfg.Scanning.Redaction.TokenizeTypes) != 6 {
		t.Errorf("redaction.tokenize_types length = %d, want 6", len(cfg.Scanning.Redaction.TokenizeTypes))
	}
	if len(cfg.Scanning.Redaction.MaskTypes) != 4 {
		t.Errorf("redaction.mask_types length = %d, want 4", len(cfg.Scanning.Redaction.MaskTypes))
	}

	// Extraction
	if !cfg.Extraction.Enabled {
		t.Error("extraction.enabled should be true")
	}
	if cfg.Extraction.MinContentSize != 32768 {
		t.Errorf("extraction.min_content_size = %d, want 32768", cfg.Extraction.MinContentSize)
	}
	if cfg.Extraction.RelevanceThreshold != 0.3 {
		t.Errorf("extraction.relevance_threshold = %f, want 0.3", cfg.Extraction.RelevanceThreshold)
	}
	if cfg.Extraction.Embedding.Model != "all-MiniLM-L6-v2" {
		t.Errorf("extraction.embedding.model = %q, want %q", cfg.Extraction.Embedding.Model, "all-MiniLM-L6-v2")
	}
	if cfg.Extraction.Embedding.Dimensions != 384 {
		t.Errorf("extraction.embedding.dimensions = %d, want 384", cfg.Extraction.Embedding.Dimensions)
	}
	if cfg.Extraction.SLM.Model != "phi3.5" {
		t.Errorf("extraction.slm.model = %q, want %q", cfg.Extraction.SLM.Model, "phi3.5")
	}
	if cfg.Extraction.SLM.Timeout != 30*time.Second {
		t.Errorf("extraction.slm.timeout = %v, want %v", cfg.Extraction.SLM.Timeout, 30*time.Second)
	}
	if cfg.Extraction.SLM.MaxTokens != 4096 {
		t.Errorf("extraction.slm.max_tokens = %d, want 4096", cfg.Extraction.SLM.MaxTokens)
	}

	// Streaming
	if !cfg.Streaming.Enabled {
		t.Error("streaming.enabled should be true")
	}
	if len(cfg.Streaming.Kafka.Brokers) != 1 {
		t.Errorf("kafka.brokers length = %d, want 1", len(cfg.Streaming.Kafka.Brokers))
	}
	if cfg.Streaming.Kafka.Topics.Findings != "tas.compliance.findings" {
		t.Errorf("kafka.topics.findings = %q, want %q", cfg.Streaming.Kafka.Topics.Findings, "tas.compliance.findings")
	}
	if cfg.Streaming.Kafka.Topics.Critical != "tas.compliance.findings.critical" {
		t.Errorf("kafka.topics.critical = %q, want %q", cfg.Streaming.Kafka.Topics.Critical, "tas.compliance.findings.critical")
	}
	if cfg.Streaming.Kafka.Producer.BatchSize != 100 {
		t.Errorf("kafka.producer.batch_size = %d, want 100", cfg.Streaming.Kafka.Producer.BatchSize)
	}
	if cfg.Streaming.Kafka.Producer.FlushInterval != 1*time.Second {
		t.Errorf("kafka.producer.flush_interval = %v, want %v", cfg.Streaming.Kafka.Producer.FlushInterval, 1*time.Second)
	}
	if cfg.Streaming.Kafka.Producer.Compression != "snappy" {
		t.Errorf("kafka.producer.compression = %q, want %q", cfg.Streaming.Kafka.Producer.Compression, "snappy")
	}
	if cfg.Streaming.Kafka.Consumer.GroupID != "gatekeeper-consumers" {
		t.Errorf("kafka.consumer.group_id = %q, want %q", cfg.Streaming.Kafka.Consumer.GroupID, "gatekeeper-consumers")
	}

	// Actions
	if !cfg.Actions.Enabled {
		t.Error("actions.enabled should be true")
	}
	if cfg.Actions.RulesFile != "/configs/rules/action_rules.yaml" {
		t.Errorf("actions.rules_file = %q, want %q", cfg.Actions.RulesFile, "/configs/rules/action_rules.yaml")
	}
	if !cfg.Actions.RateLimit.Enabled {
		t.Error("actions.rate_limit.enabled should be true")
	}
	if cfg.Actions.RateLimit.Window != 1*time.Minute {
		t.Errorf("actions.rate_limit.window = %v, want %v", cfg.Actions.RateLimit.Window, 1*time.Minute)
	}
	if cfg.Actions.RateLimit.MaxActions != 1000 {
		t.Errorf("actions.rate_limit.max_actions = %d, want 1000", cfg.Actions.RateLimit.MaxActions)
	}
	if cfg.Actions.Alerting.Slack.Channel != "#security-alerts" {
		t.Errorf("alerting.slack.channel = %q, want %q", cfg.Actions.Alerting.Slack.Channel, "#security-alerts")
	}
	if cfg.Actions.Alerting.Slack.Enabled {
		t.Error("alerting.slack.enabled should be false")
	}

	// Cache
	if cfg.Cache.Redis.DB != 0 {
		t.Errorf("cache.redis.db = %d, want 0", cfg.Cache.Redis.DB)
	}
	if cfg.Cache.Redis.PoolSize != 10 {
		t.Errorf("cache.redis.pool_size = %d, want 10", cfg.Cache.Redis.PoolSize)
	}
	if cfg.Cache.Redis.MinIdleConns != 5 {
		t.Errorf("cache.redis.min_idle_conns = %d, want 5", cfg.Cache.Redis.MinIdleConns)
	}
	if cfg.Cache.Redis.DialTimeout != 5*time.Second {
		t.Errorf("cache.redis.dial_timeout = %v, want %v", cfg.Cache.Redis.DialTimeout, 5*time.Second)
	}
	if cfg.Cache.AttestationTTL != 5*time.Minute {
		t.Errorf("cache.attestation_ttl = %v, want %v", cfg.Cache.AttestationTTL, 5*time.Minute)
	}
	if cfg.Cache.RateLimitTTL != 1*time.Minute {
		t.Errorf("cache.rate_limit_ttl = %v, want %v", cfg.Cache.RateLimitTTL, 1*time.Minute)
	}

	// Server
	if cfg.Server.HTTP.Port != 8087 {
		t.Errorf("server.http.port = %d, want 8087", cfg.Server.HTTP.Port)
	}
	if cfg.Server.HTTP.ReadTimeout != 30*time.Second {
		t.Errorf("server.http.read_timeout = %v, want %v", cfg.Server.HTTP.ReadTimeout, 30*time.Second)
	}
	if cfg.Server.GRPC.Port != 8088 {
		t.Errorf("server.grpc.port = %d, want 8088", cfg.Server.GRPC.Port)
	}
	if cfg.Server.GRPC.MaxRecvMsgSize != 16777216 {
		t.Errorf("server.grpc.max_recv_msg_size = %d, want 16777216", cfg.Server.GRPC.MaxRecvMsgSize)
	}
	if cfg.Server.Metrics.Port != 9087 {
		t.Errorf("server.metrics.port = %d, want 9087", cfg.Server.Metrics.Port)
	}
	if cfg.Server.Metrics.Path != "/metrics" {
		t.Errorf("server.metrics.path = %q, want %q", cfg.Server.Metrics.Path, "/metrics")
	}

	// Logging (env var ${LOG_LEVEL:-info} defaults)
	if cfg.Logging.Level != "info" {
		t.Errorf("logging.level = %q, want %q (default)", cfg.Logging.Level, "info")
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("logging.format = %q, want %q", cfg.Logging.Format, "json")
	}
	if cfg.Logging.File.MaxSize != 100 {
		t.Errorf("logging.file.max_size = %d, want 100", cfg.Logging.File.MaxSize)
	}

	// Health
	if cfg.Health.LivePath != "/health/live" {
		t.Errorf("health.live_path = %q, want %q", cfg.Health.LivePath, "/health/live")
	}
	if cfg.Health.ReadyPath != "/health/ready" {
		t.Errorf("health.ready_path = %q, want %q", cfg.Health.ReadyPath, "/health/ready")
	}
	if cfg.Health.CheckInterval != 10*time.Second {
		t.Errorf("health.check_interval = %v, want %v", cfg.Health.CheckInterval, 10*time.Second)
	}

	// Compliance
	if len(cfg.Compliance.Frameworks) != 10 {
		t.Errorf("compliance.frameworks length = %d, want 10", len(cfg.Compliance.Frameworks))
	}
	if cfg.Compliance.RulesDir != "/configs/rules" {
		t.Errorf("compliance.rules_dir = %q, want %q", cfg.Compliance.RulesDir, "/configs/rules")
	}
}

// -----------------------------------------------------------------------
// TestEnvVarSubstitution
// -----------------------------------------------------------------------

func TestEnvVarSubstitution(t *testing.T) {
	t.Run("simple var replacement", func(t *testing.T) {
		t.Setenv("TEST_CFG_VAR", "hello-world")
		out := substituteEnvVars([]byte("value: ${TEST_CFG_VAR}"))
		if string(out) != "value: hello-world" {
			t.Errorf("got %q, want %q", string(out), "value: hello-world")
		}
	})

	t.Run("var with default when unset", func(t *testing.T) {
		// Ensure it's not set
		os.Unsetenv("TEST_CFG_UNSET")
		out := substituteEnvVars([]byte("value: ${TEST_CFG_UNSET:-fallback_value}"))
		if string(out) != "value: fallback_value" {
			t.Errorf("got %q, want %q", string(out), "value: fallback_value")
		}
	})

	t.Run("var with default when set", func(t *testing.T) {
		t.Setenv("TEST_CFG_SET", "override")
		out := substituteEnvVars([]byte("value: ${TEST_CFG_SET:-fallback}"))
		if string(out) != "value: override" {
			t.Errorf("got %q, want %q", string(out), "value: override")
		}
	})

	t.Run("unset var without default yields empty", func(t *testing.T) {
		os.Unsetenv("TEST_CFG_EMPTY")
		out := substituteEnvVars([]byte("value: ${TEST_CFG_EMPTY}"))
		if string(out) != "value: " {
			t.Errorf("got %q, want %q", string(out), "value: ")
		}
	})

	t.Run("multiple substitutions in same content", func(t *testing.T) {
		t.Setenv("TEST_A", "aaa")
		t.Setenv("TEST_B", "bbb")
		out := substituteEnvVars([]byte("${TEST_A} and ${TEST_B}"))
		if string(out) != "aaa and bbb" {
			t.Errorf("got %q, want %q", string(out), "aaa and bbb")
		}
	})

	t.Run("default with colon in value", func(t *testing.T) {
		os.Unsetenv("TEST_CFG_COLON")
		out := substituteEnvVars([]byte("url: ${TEST_CFG_COLON:-http://localhost:3000}"))
		if string(out) != "url: http://localhost:3000" {
			t.Errorf("got %q, want %q", string(out), "url: http://localhost:3000")
		}
	})

	t.Run("empty string env var uses default", func(t *testing.T) {
		t.Setenv("TEST_CFG_EMPTYVAL", "")
		out := substituteEnvVars([]byte("value: ${TEST_CFG_EMPTYVAL:-default_val}"))
		if string(out) != "value: default_val" {
			t.Errorf("got %q, want %q", string(out), "value: default_val")
		}
	})

	t.Run("no env vars leaves content unchanged", func(t *testing.T) {
		input := "plain: value without substitution"
		out := substituteEnvVars([]byte(input))
		if string(out) != input {
			t.Errorf("got %q, want %q", string(out), input)
		}
	})
}

// -----------------------------------------------------------------------
// TestLoadRulesDir
// -----------------------------------------------------------------------

func TestLoadRulesDir(t *testing.T) {
	root := repoRoot(t)
	rulesDir := filepath.Join(root, "configs", "rules")

	rules, err := LoadRulesDir(rulesDir)
	if err != nil {
		t.Fatalf("LoadRulesDir(%s): %v", rulesDir, err)
	}

	// We expect 13 rule files based on the configs/rules/ directory
	if len(rules) < 10 {
		t.Errorf("loaded %d rule files, want at least 10", len(rules))
	}

	// Build a map by name for easy lookup
	byName := make(map[string]RuleFile)
	for _, r := range rules {
		byName[r.Name] = r
	}

	// Check PII rule file
	pii, ok := byName["pii"]
	if !ok {
		t.Fatal("pii rule file not found")
	}
	if pii.Version != "1.0" {
		t.Errorf("pii.version = %q, want %q", pii.Version, "1.0")
	}
	if len(pii.Patterns) == 0 {
		t.Error("pii.patterns should not be empty")
	}

	// Check HIPAA rule file
	hipaa, ok := byName["hipaa"]
	if !ok {
		t.Fatal("hipaa rule file not found")
	}
	if hipaa.Framework == nil {
		t.Fatal("hipaa.framework should not be nil")
	}
	if hipaa.Framework.ID != "HIPAA" {
		t.Errorf("hipaa.framework.id = %q, want %q", hipaa.Framework.ID, "HIPAA")
	}
	if len(hipaa.Rules) == 0 {
		t.Error("hipaa.rules should not be empty")
	}

	// Check action rules file
	actions, ok := byName["action_rules"]
	if !ok {
		t.Fatal("action_rules file not found")
	}
	if len(actions.Rules) == 0 {
		t.Error("action_rules.rules should not be empty")
	}

	// Verify all rule files have a name and version
	for _, r := range rules {
		if r.Name == "" {
			t.Errorf("rule file has empty name: %+v", r)
		}
		if r.Version == "" {
			t.Errorf("rule file %q has empty version", r.Name)
		}
	}
}

// -----------------------------------------------------------------------
// TestLoadRulesDir_InvalidDir
// -----------------------------------------------------------------------

func TestLoadRulesDir_InvalidDir(t *testing.T) {
	_, err := LoadRulesDir("/nonexistent/directory")
	if err == nil {
		t.Error("expected error for nonexistent directory, got nil")
	}
}

// -----------------------------------------------------------------------
// TestValidation
// -----------------------------------------------------------------------

func TestValidation(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		err := Validate(nil)
		if err == nil {
			t.Error("expected error for nil config")
		}
	})

	t.Run("missing service id", func(t *testing.T) {
		cfg := &Config{}
		err := Validate(cfg)
		if err == nil {
			t.Error("expected error for missing service.id")
		}
	})

	t.Run("invalid scan profile", func(t *testing.T) {
		cfg := &Config{
			Service: ServiceConfig{ID: "test"},
			Scanning: ScanningConfig{
				DefaultProfile: "invalid_profile",
			},
		}
		err := Validate(cfg)
		if err == nil {
			t.Error("expected error for invalid scan profile")
		}
	})

	t.Run("invalid redaction mode", func(t *testing.T) {
		cfg := &Config{
			Service: ServiceConfig{ID: "test"},
			Scanning: ScanningConfig{
				Redaction: RedactionConfig{Mode: "bad_mode"},
			},
		}
		err := Validate(cfg)
		if err == nil {
			t.Error("expected error for invalid redaction mode")
		}
	})

	t.Run("invalid log level", func(t *testing.T) {
		cfg := &Config{
			Service: ServiceConfig{ID: "test"},
			Logging: LoggingConfig{Level: "verbose"},
		}
		err := Validate(cfg)
		if err == nil {
			t.Error("expected error for invalid log level")
		}
	})

	t.Run("invalid log format", func(t *testing.T) {
		cfg := &Config{
			Service: ServiceConfig{ID: "test"},
			Logging: LoggingConfig{Format: "xml"},
		}
		err := Validate(cfg)
		if err == nil {
			t.Error("expected error for invalid log format")
		}
	})

	t.Run("negative http port", func(t *testing.T) {
		cfg := &Config{
			Service: ServiceConfig{ID: "test"},
			Server: ServerConfig{
				HTTP: HTTPServerConfig{Port: -1},
			},
		}
		err := Validate(cfg)
		if err == nil {
			t.Error("expected error for negative http port")
		}
	})

	t.Run("invalid relevance threshold", func(t *testing.T) {
		cfg := &Config{
			Service: ServiceConfig{ID: "test"},
			Extraction: ExtractionConfig{
				RelevanceThreshold: 1.5,
			},
		}
		err := Validate(cfg)
		if err == nil {
			t.Error("expected error for relevance threshold > 1.0")
		}
	})

	t.Run("valid minimal config", func(t *testing.T) {
		cfg := &Config{
			Service: ServiceConfig{ID: "test"},
		}
		err := Validate(cfg)
		if err != nil {
			t.Errorf("unexpected error for valid config: %v", err)
		}
	})

	t.Run("valid full config", func(t *testing.T) {
		cfg := &Config{
			Service: ServiceConfig{ID: "gatekeeper", Version: "1.0.0"},
			Scanning: ScanningConfig{
				DefaultProfile: "full",
				Redaction:      RedactionConfig{Mode: "tokenize"},
			},
			Logging:    LoggingConfig{Level: "info", Format: "json"},
			Extraction: ExtractionConfig{RelevanceThreshold: 0.5},
		}
		err := Validate(cfg)
		if err != nil {
			t.Errorf("unexpected error for valid config: %v", err)
		}
	})
}

// -----------------------------------------------------------------------
// TestLoadConfig_FileNotFound
// -----------------------------------------------------------------------

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent config file")
	}
}

// -----------------------------------------------------------------------
// TestLoadConfig_InvalidYAML
// -----------------------------------------------------------------------

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.yaml")
	if err := os.WriteFile(path, []byte("{{invalid yaml"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

// -----------------------------------------------------------------------
// TestLoadConfig_EnvOverride
// -----------------------------------------------------------------------

func TestLoadConfig_EnvOverride(t *testing.T) {
	root := repoRoot(t)
	cfgPath := filepath.Join(root, "configs", "gatekeeper.yaml")

	t.Setenv("LOG_LEVEL", "debug")
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("logging.level = %q, want %q (from env override)", cfg.Logging.Level, "debug")
	}
}

// -----------------------------------------------------------------------
// TestLoadConfig_DatabunkerURLDefault
// -----------------------------------------------------------------------

func TestLoadConfig_DatabunkerURLDefault(t *testing.T) {
	root := repoRoot(t)
	cfgPath := filepath.Join(root, "configs", "gatekeeper.yaml")

	os.Unsetenv("DATABUNKER_URL")
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Databunker.URL != "http://tas-databunker-shared:3000" {
		t.Errorf("databunker.url = %q, want default %q", cfg.Databunker.URL, "http://tas-databunker-shared:3000")
	}
}
