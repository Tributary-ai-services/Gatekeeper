package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// envVarPattern matches ${VAR} and ${VAR:-default} expressions.
var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}`)

// LoadConfig reads a YAML config file, performs environment variable
// substitution on the raw bytes, then unmarshals into a Config struct.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	data = substituteEnvVars(data)

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	if err := Validate(&cfg); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

// LoadRulesDir reads all .yaml and .yml files from the given directory and
// parses each into a RuleFile struct.
func LoadRulesDir(dir string) ([]RuleFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading rules directory %s: %w", dir, err)
	}

	var rules []RuleFile
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading rule file %s: %w", path, err)
		}

		data = substituteEnvVars(data)

		var rf RuleFile
		if err := yaml.Unmarshal(data, &rf); err != nil {
			return nil, fmt.Errorf("parsing rule file %s: %w", path, err)
		}
		rules = append(rules, rf)
	}

	return rules, nil
}

// substituteEnvVars replaces ${VAR} and ${VAR:-default} patterns in content
// with the corresponding environment variable values. If a variable is not
// set and no default is provided, the expression is replaced with an empty
// string.
func substituteEnvVars(content []byte) []byte {
	result := envVarPattern.ReplaceAllFunc(content, func(match []byte) []byte {
		groups := envVarPattern.FindSubmatch(match)
		if groups == nil {
			return match
		}

		varName := string(groups[1])
		defaultVal := ""
		hasDefault := len(groups) > 2 && groups[2] != nil
		if hasDefault {
			defaultVal = string(groups[2])
		}

		val, ok := os.LookupEnv(varName)
		if !ok || val == "" {
			if hasDefault {
				return []byte(defaultVal)
			}
			return []byte("")
		}
		return []byte(val)
	})
	return result
}

// Validate performs basic validation on a loaded Config. It checks that
// required fields are set and that values are within expected ranges.
func Validate(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}

	if cfg.Service.ID == "" {
		return fmt.Errorf("service.id is required")
	}

	// Validate scanning profile
	profile := cfg.Scanning.DefaultProfile
	if profile != "" {
		validProfiles := map[string]bool{
			"full": true, "compliance": true, "pii_only": true, "injection_only": true,
		}
		if !validProfiles[profile] {
			return fmt.Errorf("scanning.default_profile %q is not valid; must be one of: full, compliance, pii_only, injection_only", profile)
		}
	}

	// Validate redaction mode
	mode := cfg.Scanning.Redaction.Mode
	if mode != "" {
		validModes := map[string]bool{
			"mask": true, "tokenize": true, "replace": true, "remove": true,
		}
		if !validModes[mode] {
			return fmt.Errorf("scanning.redaction.mode %q is not valid; must be one of: mask, tokenize, replace, remove", mode)
		}
	}

	// Validate log level
	level := cfg.Logging.Level
	if level != "" {
		validLevels := map[string]bool{
			"debug": true, "info": true, "warn": true, "error": true,
		}
		if !validLevels[level] {
			return fmt.Errorf("logging.level %q is not valid; must be one of: debug, info, warn, error", level)
		}
	}

	// Validate log format
	format := cfg.Logging.Format
	if format != "" {
		if format != "json" && format != "text" {
			return fmt.Errorf("logging.format %q is not valid; must be json or text", format)
		}
	}

	// Validate server ports are positive when set
	if cfg.Server.HTTP.Port < 0 {
		return fmt.Errorf("server.http.port must be non-negative, got %d", cfg.Server.HTTP.Port)
	}
	if cfg.Server.GRPC.Port < 0 {
		return fmt.Errorf("server.grpc.port must be non-negative, got %d", cfg.Server.GRPC.Port)
	}
	if cfg.Server.Metrics.Port < 0 {
		return fmt.Errorf("server.metrics.port must be non-negative, got %d", cfg.Server.Metrics.Port)
	}

	// Validate extraction threshold
	if cfg.Extraction.RelevanceThreshold < 0 || cfg.Extraction.RelevanceThreshold > 1 {
		if cfg.Extraction.RelevanceThreshold != 0 {
			return fmt.Errorf("extraction.relevance_threshold must be between 0.0 and 1.0, got %f", cfg.Extraction.RelevanceThreshold)
		}
	}

	return nil
}
