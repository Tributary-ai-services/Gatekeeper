package scan

import (
	"strings"
	"sync"
)

// classifier implements the Classifier interface
type classifier struct {
	mu          sync.RWMutex
	rulesByType map[PIIType][]FrameworkRule
	rulesByFW   map[Framework][]FrameworkRule
}

// NewClassifier creates a new compliance classifier
func NewClassifier() Classifier {
	c := &classifier{
		rulesByType: make(map[PIIType][]FrameworkRule),
		rulesByFW:   make(map[Framework][]FrameworkRule),
	}
	c.loadDefaultRules()
	return c
}

// loadDefaultRules loads the default compliance framework rules
func (c *classifier) loadDefaultRules() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// PCI-DSS Rules (Payment Card Industry)
	c.addRule(PIITypeCreditCard, FrameworkRule{
		Framework:   FrameworkPCIDSS,
		RuleID:      "PCI-DSS-3.4",
		Severity:    SeverityCritical,
		Description: "Credit card numbers must be protected per PCI-DSS requirement 3.4",
	})
	c.addRule(PIITypeBankAccount, FrameworkRule{
		Framework:   FrameworkPCIDSS,
		RuleID:      "PCI-DSS-3.2",
		Severity:    SeverityHigh,
		Description: "Bank account data must be protected per PCI-DSS requirement 3.2",
	})

	// HIPAA Rules (Healthcare)
	c.addRule(PIITypeSSN, FrameworkRule{
		Framework:   FrameworkHIPAA,
		RuleID:      "HIPAA-164.514",
		Severity:    SeverityCritical,
		Description: "SSN is protected health information under HIPAA",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsHealthcare
		},
	})
	c.addRule(PIITypeMedicalRecordNumber, FrameworkRule{
		Framework:   FrameworkHIPAA,
		RuleID:      "HIPAA-164.514-MRN",
		Severity:    SeverityCritical,
		Description: "Medical record numbers are PHI under HIPAA",
	})
	c.addRule(PIITypeDateOfBirth, FrameworkRule{
		Framework:   FrameworkHIPAA,
		RuleID:      "HIPAA-164.514-DOB",
		Severity:    SeverityHigh,
		Description: "Date of birth is protected health information in healthcare context",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsHealthcare
		},
	})
	c.addRule(PIITypeName, FrameworkRule{
		Framework:   FrameworkHIPAA,
		RuleID:      "HIPAA-164.514-NAME",
		Severity:    SeverityMedium,
		Description: "Patient names are PHI in healthcare context",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsHealthcare
		},
	})
	c.addRule(PIITypeAddress, FrameworkRule{
		Framework:   FrameworkHIPAA,
		RuleID:      "HIPAA-164.514-ADDR",
		Severity:    SeverityMedium,
		Description: "Addresses are PHI in healthcare context",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsHealthcare
		},
	})

	// GDPR Rules (European Data Protection)
	c.addRule(PIITypeEmail, FrameworkRule{
		Framework:   FrameworkGDPR,
		RuleID:      "GDPR-4.1",
		Severity:    SeverityMedium,
		Description: "Email addresses are personal data under GDPR Article 4(1)",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsEUData
		},
	})
	c.addRule(PIITypeName, FrameworkRule{
		Framework:   FrameworkGDPR,
		RuleID:      "GDPR-4.1-NAME",
		Severity:    SeverityMedium,
		Description: "Names are personal data under GDPR Article 4(1)",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsEUData
		},
	})
	c.addRule(PIITypeIPAddress, FrameworkRule{
		Framework:   FrameworkGDPR,
		RuleID:      "GDPR-4.1-IP",
		Severity:    SeverityLow,
		Description: "IP addresses may constitute personal data under GDPR",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsEUData
		},
	})
	c.addRule(PIITypeDateOfBirth, FrameworkRule{
		Framework:   FrameworkGDPR,
		RuleID:      "GDPR-4.1-DOB",
		Severity:    SeverityMedium,
		Description: "Date of birth is personal data under GDPR",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsEUData
		},
	})

	// CCPA Rules (California Consumer Privacy Act)
	c.addRule(PIITypeSSN, FrameworkRule{
		Framework:   FrameworkCCPA,
		RuleID:      "CCPA-1798.140",
		Severity:    SeverityCritical,
		Description: "SSN is personal information under CCPA",
	})
	c.addRule(PIITypeEmail, FrameworkRule{
		Framework:   FrameworkCCPA,
		RuleID:      "CCPA-1798.140-EMAIL",
		Severity:    SeverityMedium,
		Description: "Email addresses are personal information under CCPA",
	})
	c.addRule(PIITypeDriversLicense, FrameworkRule{
		Framework:   FrameworkCCPA,
		RuleID:      "CCPA-1798.140-DL",
		Severity:    SeverityHigh,
		Description: "Driver's license numbers are personal information under CCPA",
	})

	// SOX Rules (Sarbanes-Oxley - Financial Records)
	c.addRule(PIITypeBankAccount, FrameworkRule{
		Framework:   FrameworkSOX,
		RuleID:      "SOX-302",
		Severity:    SeverityHigh,
		Description: "Financial account information must be protected per SOX requirements",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsFinancial
		},
	})
	c.addRule(PIITypeCreditCard, FrameworkRule{
		Framework:   FrameworkSOX,
		RuleID:      "SOX-404",
		Severity:    SeverityHigh,
		Description: "Credit card data handling must be controlled per SOX",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsFinancial
		},
	})

	// General PII Rules (always apply)
	c.addRule(PIITypeSSN, FrameworkRule{
		Framework:   FrameworkPII,
		RuleID:      "PII-SSN",
		Severity:    SeverityCritical,
		Description: "Social Security Numbers are highly sensitive PII",
	})
	c.addRule(PIITypeCreditCard, FrameworkRule{
		Framework:   FrameworkPII,
		RuleID:      "PII-CC",
		Severity:    SeverityCritical,
		Description: "Credit card numbers are highly sensitive financial data",
	})
	c.addRule(PIITypePassport, FrameworkRule{
		Framework:   FrameworkPII,
		RuleID:      "PII-PASSPORT",
		Severity:    SeverityHigh,
		Description: "Passport numbers are sensitive identity documents",
	})
	c.addRule(PIITypeDriversLicense, FrameworkRule{
		Framework:   FrameworkPII,
		RuleID:      "PII-DL",
		Severity:    SeverityHigh,
		Description: "Driver's license numbers are sensitive identity documents",
	})

	// Security Rules (credentials)
	c.addRule(PIITypeAWSAccessKey, FrameworkRule{
		Framework:   FrameworkSecurity,
		RuleID:      "SEC-AWS-KEY",
		Severity:    SeverityCritical,
		Description: "AWS access keys must not be exposed",
	})
	c.addRule(PIITypeAWSSecretKey, FrameworkRule{
		Framework:   FrameworkSecurity,
		RuleID:      "SEC-AWS-SECRET",
		Severity:    SeverityCritical,
		Description: "AWS secret keys must not be exposed",
	})
	c.addRule(PIITypeAPIKey, FrameworkRule{
		Framework:   FrameworkSecurity,
		RuleID:      "SEC-API-KEY",
		Severity:    SeverityHigh,
		Description: "API keys and tokens must not be exposed",
	})
}

// addRule adds a rule to the internal indexes
func (c *classifier) addRule(piiType PIIType, rule FrameworkRule) {
	c.rulesByType[piiType] = append(c.rulesByType[piiType], rule)
	c.rulesByFW[rule.Framework] = append(c.rulesByFW[rule.Framework], rule)
}

// Classify determines which frameworks a finding violates
func (c *classifier) Classify(finding *Finding, context ClassificationContext) []FrameworkMatch {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var matches []FrameworkMatch

	// Get rules for this PII type
	rules, ok := c.rulesByType[finding.PIIType]
	if !ok {
		return matches
	}

	for _, rule := range rules {
		// Check if condition applies (if any)
		if rule.Condition != nil && !rule.Condition(context) {
			continue
		}

		matches = append(matches, FrameworkMatch{
			Framework:   rule.Framework,
			RuleID:      rule.RuleID,
			Severity:    rule.Severity,
			Description: rule.Description,
		})
	}

	// Also check context hints for additional classification
	matches = c.applyContextHints(finding, context, matches)

	return matches
}

// applyContextHints applies context-aware classification
func (c *classifier) applyContextHints(finding *Finding, ctx ClassificationContext, matches []FrameworkMatch) []FrameworkMatch {
	for _, hint := range ctx.Hints {
		lowerHint := strings.ToLower(hint)

		// Healthcare context hints
		if strings.Contains(lowerHint, "health") ||
			strings.Contains(lowerHint, "medical") ||
			strings.Contains(lowerHint, "patient") ||
			strings.Contains(lowerHint, "hospital") {
			// Add HIPAA if not already present and relevant
			if !c.hasFramework(matches, FrameworkHIPAA) && c.isHIPAARelevant(finding.PIIType) {
				matches = append(matches, FrameworkMatch{
					Framework:   FrameworkHIPAA,
					RuleID:      "HIPAA-CONTEXT",
					Severity:    SeverityHigh,
					Description: "Healthcare context detected, HIPAA may apply",
				})
			}
		}

		// Financial context hints
		if strings.Contains(lowerHint, "finance") ||
			strings.Contains(lowerHint, "banking") ||
			strings.Contains(lowerHint, "payment") ||
			strings.Contains(lowerHint, "transaction") {
			if !c.hasFramework(matches, FrameworkPCIDSS) && c.isPCIDSSRelevant(finding.PIIType) {
				matches = append(matches, FrameworkMatch{
					Framework:   FrameworkPCIDSS,
					RuleID:      "PCI-CONTEXT",
					Severity:    SeverityHigh,
					Description: "Financial context detected, PCI-DSS may apply",
				})
			}
		}

		// EU/GDPR hints
		if strings.Contains(lowerHint, "europe") ||
			strings.Contains(lowerHint, "eu") ||
			strings.Contains(lowerHint, "gdpr") ||
			strings.Contains(lowerHint, "european") {
			if !c.hasFramework(matches, FrameworkGDPR) {
				matches = append(matches, FrameworkMatch{
					Framework:   FrameworkGDPR,
					RuleID:      "GDPR-CONTEXT",
					Severity:    SeverityMedium,
					Description: "European context detected, GDPR may apply",
				})
			}
		}
	}

	return matches
}

// hasFramework checks if a framework is already in the matches
func (c *classifier) hasFramework(matches []FrameworkMatch, fw Framework) bool {
	for _, m := range matches {
		if m.Framework == fw {
			return true
		}
	}
	return false
}

// isHIPAARelevant checks if a PII type is relevant to HIPAA
func (c *classifier) isHIPAARelevant(piiType PIIType) bool {
	hipaaTypes := map[PIIType]bool{
		PIITypeSSN:                 true,
		PIITypeName:               true,
		PIITypeDateOfBirth:        true,
		PIITypeAddress:            true,
		PIITypePhoneNumber:        true,
		PIITypeEmail:              true,
		PIITypeMedicalRecordNumber: true,
	}
	return hipaaTypes[piiType]
}

// isPCIDSSRelevant checks if a PII type is relevant to PCI-DSS
func (c *classifier) isPCIDSSRelevant(piiType PIIType) bool {
	pciTypes := map[PIIType]bool{
		PIITypeCreditCard:  true,
		PIITypeBankAccount: true,
	}
	return pciTypes[piiType]
}

// GetFrameworkRules returns rules for a specific framework
func (c *classifier) GetFrameworkRules(framework Framework) []FrameworkRule {
	c.mu.RLock()
	defer c.mu.RUnlock()

	rules := c.rulesByFW[framework]
	result := make([]FrameworkRule, len(rules))
	copy(result, rules)
	return result
}

// GetAllFrameworks returns all supported frameworks
func (c *classifier) GetAllFrameworks() []Framework {
	return []Framework{
		FrameworkPII,
		FrameworkHIPAA,
		FrameworkGDPR,
		FrameworkPCIDSS,
		FrameworkSOX,
		FrameworkCCPA,
		FrameworkSecurity,
	}
}

// ClassifyInjection classifies injection findings
func ClassifyInjection(finding *Finding) []FrameworkMatch {
	var matches []FrameworkMatch

	// All injection types map to Security framework
	matches = append(matches, FrameworkMatch{
		Framework:   FrameworkSecurity,
		RuleID:      "SEC-INJECTION",
		Severity:    SeverityCritical,
		Description: "Injection attack detected",
	})

	// Add specific rules based on injection type
	switch finding.InjectionType {
	case InjectionTypeSQL:
		matches = append(matches, FrameworkMatch{
			Framework:   FrameworkSecurity,
			RuleID:      "SEC-SQLI",
			Severity:    SeverityCritical,
			Description: "SQL injection attempt detected",
		})
	case InjectionTypeXSS:
		matches = append(matches, FrameworkMatch{
			Framework:   FrameworkSecurity,
			RuleID:      "SEC-XSS",
			Severity:    SeverityHigh,
			Description: "Cross-site scripting attempt detected",
		})
	case InjectionTypePrompt:
		matches = append(matches, FrameworkMatch{
			Framework:   FrameworkSecurity,
			RuleID:      "SEC-PROMPT-INJ",
			Severity:    SeverityHigh,
			Description: "LLM prompt injection attempt detected",
		})
	case InjectionTypeHTML:
		matches = append(matches, FrameworkMatch{
			Framework:   FrameworkSecurity,
			RuleID:      "SEC-HTML-INJ",
			Severity:    SeverityMedium,
			Description: "HTML injection attempt detected",
		})
	}

	return matches
}
