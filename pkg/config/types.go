// Package config provides configuration loading and validation for the
// Gatekeeper content scanning library. It supports YAML configuration files
// with environment variable substitution.
package config

import "time"

// Config is the top-level configuration structure mirroring gatekeeper.yaml.
type Config struct {
	Service    ServiceConfig    `yaml:"service"`
	Databunker DatabunkerConfig `yaml:"databunker"`
	Attestation AttestationConfig `yaml:"attestation"`
	Scanning   ScanningConfig   `yaml:"scanning"`
	Extraction ExtractionConfig `yaml:"extraction"`
	Streaming  StreamingConfig  `yaml:"streaming"`
	Actions    ActionsConfig    `yaml:"actions"`
	Cache      CacheConfig      `yaml:"cache"`
	Server     ServerConfig     `yaml:"server"`
	Logging    LoggingConfig    `yaml:"logging"`
	Health     HealthConfig     `yaml:"health"`
	Compliance ComplianceConfig `yaml:"compliance"`
}

// ServiceConfig holds service identification metadata.
type ServiceConfig struct {
	ID          string `yaml:"id"`
	Version     string `yaml:"version"`
	Environment string `yaml:"environment"`
}

// DatabunkerConfig holds Databunker integration settings.
type DatabunkerConfig struct {
	URL    string        `yaml:"url"`
	APIKey string        `yaml:"api_key"`
	Timeout time.Duration `yaml:"timeout"`
	Retry  RetryConfig   `yaml:"retry"`
}

// RetryConfig holds retry policy settings.
type RetryConfig struct {
	MaxAttempts int           `yaml:"max_attempts"`
	Backoff     time.Duration `yaml:"backoff"`
}

// AttestationConfig holds attestation/deduplication settings.
type AttestationConfig struct {
	SigningKeyName string        `yaml:"signing_key_name"`
	TTL            time.Duration `yaml:"ttl"`
	ServiceID      string        `yaml:"service_id"`
	Algorithm      string        `yaml:"algorithm"`
}

// ScanningConfig holds scanning engine settings.
type ScanningConfig struct {
	DefaultProfile    string           `yaml:"default_profile"`
	HonorAttestations bool             `yaml:"honor_attestations"`
	MaxContentSize    int              `yaml:"max_content_size"`
	Timeout           time.Duration    `yaml:"timeout"`
	TrustTiers        TrustTiersConfig `yaml:"trust_tiers"`
	Patterns          PatternsConfig   `yaml:"patterns"`
	Redaction         RedactionConfig  `yaml:"redaction"`
}

// TrustTiersConfig holds per-tier scanning behavior.
type TrustTiersConfig struct {
	Internal TrustTierConfig `yaml:"internal"`
	Partner  TrustTierConfig `yaml:"partner"`
	External TrustTierConfig `yaml:"external"`
}

// TrustTierConfig configures behavior for a single trust tier.
type TrustTierConfig struct {
	ScanProfile string `yaml:"scan_profile"`
	SkipPII     bool   `yaml:"skip_pii"`
}

// PatternsConfig holds pattern matching engine settings.
type PatternsConfig struct {
	BlockSize       int  `yaml:"block_size"`
	ScratchPoolSize int  `yaml:"scratch_pool_size"`
	Precompile      bool `yaml:"precompile"`
}

// RedactionConfig holds redaction/masking settings.
type RedactionConfig struct {
	Mode          string   `yaml:"mode"`
	TokenizeTypes []string `yaml:"tokenize_types"`
	MaskTypes     []string `yaml:"mask_types"`
}

// ExtractionConfig holds content extraction settings for large documents.
type ExtractionConfig struct {
	Enabled            bool             `yaml:"enabled"`
	MinContentSize     int              `yaml:"min_content_size"`
	RelevanceThreshold float64          `yaml:"relevance_threshold"`
	Embedding          EmbeddingConfig  `yaml:"embedding"`
	SLM                SLMConfig        `yaml:"slm"`
}

// EmbeddingConfig holds embedding model settings.
type EmbeddingConfig struct {
	Model      string `yaml:"model"`
	Dimensions int    `yaml:"dimensions"`
	BatchSize  int    `yaml:"batch_size"`
}

// SLMConfig holds Small Language Model settings.
type SLMConfig struct {
	URL       string        `yaml:"url"`
	Model     string        `yaml:"model"`
	Timeout   time.Duration `yaml:"timeout"`
	MaxTokens int           `yaml:"max_tokens"`
}

// StreamingConfig holds Kafka streaming settings.
type StreamingConfig struct {
	Enabled bool        `yaml:"enabled"`
	Kafka   KafkaConfig `yaml:"kafka"`
}

// KafkaConfig holds Kafka connection and producer/consumer settings.
type KafkaConfig struct {
	Brokers  []string             `yaml:"brokers"`
	Topics   KafkaTopicsConfig    `yaml:"topics"`
	Producer KafkaProducerConfig  `yaml:"producer"`
	Consumer KafkaConsumerConfig  `yaml:"consumer"`
}

// KafkaTopicsConfig maps topic names to Kafka topic strings.
type KafkaTopicsConfig struct {
	Findings string `yaml:"findings"`
	Critical string `yaml:"critical"`
	HIPAA    string `yaml:"hipaa"`
	PCI      string `yaml:"pci"`
	NIST     string `yaml:"nist"`
	SOC2     string `yaml:"soc2"`
	EUAI     string `yaml:"eu_ai"`
	ISO27001 string `yaml:"iso27001"`
	Actions  string `yaml:"actions"`
	Audit    string `yaml:"audit"`
}

// KafkaProducerConfig holds Kafka producer settings.
type KafkaProducerConfig struct {
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	Compression   string        `yaml:"compression"`
	RequiredAcks  string        `yaml:"required_acks"`
}

// KafkaConsumerConfig holds Kafka consumer settings.
type KafkaConsumerConfig struct {
	GroupID         string `yaml:"group_id"`
	AutoOffsetReset string `yaml:"auto_offset_reset"`
}

// ActionsConfig holds action engine settings.
type ActionsConfig struct {
	Enabled   bool            `yaml:"enabled"`
	RulesFile string          `yaml:"rules_file"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	Alerting  AlertingConfig  `yaml:"alerting"`
}

// RateLimitConfig holds rate limiting settings for the action engine.
type RateLimitConfig struct {
	Enabled    bool          `yaml:"enabled"`
	Window     time.Duration `yaml:"window"`
	MaxActions int           `yaml:"max_actions"`
}

// AlertingConfig holds alerting integration settings.
type AlertingConfig struct {
	Slack     SlackConfig     `yaml:"slack"`
	PagerDuty PagerDutyConfig `yaml:"pagerduty"`
	Webhook   WebhookConfig   `yaml:"webhook"`
}

// SlackConfig holds Slack alerting settings.
type SlackConfig struct {
	WebhookURL string `yaml:"webhook_url"`
	Channel    string `yaml:"channel"`
	Enabled    bool   `yaml:"enabled"`
}

// PagerDutyConfig holds PagerDuty alerting settings.
type PagerDutyConfig struct {
	RoutingKey string `yaml:"routing_key"`
	Enabled    bool   `yaml:"enabled"`
}

// WebhookConfig holds generic webhook alerting settings.
type WebhookConfig struct {
	URL     string `yaml:"url"`
	Enabled bool   `yaml:"enabled"`
}

// CacheConfig holds Redis cache settings.
type CacheConfig struct {
	Redis          RedisCacheConfig `yaml:"redis"`
	AttestationTTL time.Duration    `yaml:"attestation_ttl"`
	RateLimitTTL   time.Duration    `yaml:"rate_limit_ttl"`
}

// RedisCacheConfig holds Redis connection settings.
type RedisCacheConfig struct {
	Addr         string        `yaml:"addr"`
	Password     string        `yaml:"password"`
	DB           int           `yaml:"db"`
	PoolSize     int           `yaml:"pool_size"`
	MinIdleConns int           `yaml:"min_idle_conns"`
	DialTimeout  time.Duration `yaml:"dial_timeout"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

// ServerConfig holds HTTP/gRPC/metrics server settings.
type ServerConfig struct {
	HTTP    HTTPServerConfig    `yaml:"http"`
	GRPC    GRPCServerConfig    `yaml:"grpc"`
	Metrics MetricsServerConfig `yaml:"metrics"`
}

// HTTPServerConfig holds HTTP server settings.
type HTTPServerConfig struct {
	Port         int           `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`
}

// GRPCServerConfig holds gRPC server settings.
type GRPCServerConfig struct {
	Port           int `yaml:"port"`
	MaxRecvMsgSize int `yaml:"max_recv_msg_size"`
	MaxSendMsgSize int `yaml:"max_send_msg_size"`
}

// MetricsServerConfig holds Prometheus metrics endpoint settings.
type MetricsServerConfig struct {
	Port int    `yaml:"port"`
	Path string `yaml:"path"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level  string          `yaml:"level"`
	Format string          `yaml:"format"`
	Output string          `yaml:"output"`
	File   LogFileConfig   `yaml:"file"`
}

// LogFileConfig holds log file rotation settings.
type LogFileConfig struct {
	Path       string `yaml:"path"`
	MaxSize    int    `yaml:"max_size"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"`
}

// HealthConfig holds health check endpoint settings.
type HealthConfig struct {
	LivePath      string        `yaml:"live_path"`
	ReadyPath     string        `yaml:"ready_path"`
	CheckInterval time.Duration `yaml:"check_interval"`
}

// ComplianceConfig holds compliance framework loading settings.
type ComplianceConfig struct {
	Frameworks []string `yaml:"frameworks"`
	RulesDir   string   `yaml:"rules_dir"`
}

// RuleFile represents a parsed YAML rule file from configs/rules/.
type RuleFile struct {
	Version     string              `yaml:"version"`
	Name        string              `yaml:"name"`
	Description string              `yaml:"description"`
	Framework   *FrameworkInfo      `yaml:"framework,omitempty"`
	Rules       []RuleDefinition    `yaml:"rules,omitempty"`
	Patterns    []PatternDefinition `yaml:"patterns,omitempty"`
}

// FrameworkInfo describes a compliance framework referenced in a rule file.
type FrameworkInfo struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Reference   string `yaml:"reference"`
}

// RuleDefinition represents a single compliance rule in a rule file.
type RuleDefinition struct {
	ID           string            `yaml:"id"`
	Name         string            `yaml:"name"`
	Description  string            `yaml:"description"`
	Severity     string            `yaml:"severity"`
	Required     bool              `yaml:"required"`
	Enabled      bool              `yaml:"enabled"`
	Priority     int               `yaml:"priority"`
	PIITypes     []string          `yaml:"pii_types,omitempty"`
	Conditions   interface{}       `yaml:"conditions,omitempty"`
	Actions      interface{}       `yaml:"actions,omitempty"`
	Remediation  []string          `yaml:"remediation,omitempty"`
	Cooldown     string            `yaml:"cooldown,omitempty"`
}

// PatternDefinition represents a detection pattern in a rule file (e.g., pii.yaml).
// The Patterns field uses interface{} because some rule files (like pii.yaml) use
// map[string]string while others (like injection.yaml) use []string.
type PatternDefinition struct {
	ID              string                 `yaml:"id"`
	Name            string                 `yaml:"name"`
	Type            string                 `yaml:"type"`
	Severity        string                 `yaml:"severity"`
	Description     string                 `yaml:"description"`
	Regex           string                 `yaml:"regex,omitempty"`
	Action          string                 `yaml:"action,omitempty"`
	Validation      map[string]interface{} `yaml:"validation,omitempty"`
	ConfidenceBoost map[string]float64     `yaml:"confidence_boost,omitempty"`
	Examples        []string               `yaml:"examples,omitempty"`
	RiskBase        float64                `yaml:"risk_base,omitempty"`
	Frameworks      []string               `yaml:"frameworks,omitempty"`
	Patterns        interface{}            `yaml:"patterns,omitempty"`
	UseNER          bool                   `yaml:"use_ner,omitempty"`
	KnownPrefixes   map[string]string      `yaml:"known_prefixes,omitempty"`
	ContextRequired []string               `yaml:"context_required,omitempty"`
}
