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
	c.addRule(PIITypeAzureKey, FrameworkRule{
		Framework:   FrameworkSecurity,
		RuleID:      "SEC-AZURE-KEY",
		Severity:    SeverityCritical,
		Description: "Azure credentials must not be exposed",
	})
	c.addRule(PIITypeGCPKey, FrameworkRule{
		Framework:   FrameworkSecurity,
		RuleID:      "SEC-GCP-KEY",
		Severity:    SeverityCritical,
		Description: "GCP credentials must not be exposed",
	})
	c.addRule(PIITypeJWTToken, FrameworkRule{
		Framework:   FrameworkSecurity,
		RuleID:      "SEC-JWT-TOKEN",
		Severity:    SeverityHigh,
		Description: "JWT tokens must not be exposed",
	})
	c.addRule(PIITypeOAuthToken, FrameworkRule{
		Framework:   FrameworkSecurity,
		RuleID:      "SEC-OAUTH-TOKEN",
		Severity:    SeverityHigh,
		Description: "OAuth credentials must not be exposed",
	})
	c.addRule(PIITypePrivateKey, FrameworkRule{
		Framework:   FrameworkSecurity,
		RuleID:      "SEC-PRIVATE-KEY",
		Severity:    SeverityCritical,
		Description: "Private keys must not be exposed",
	})
	c.addRule(PIITypeConnectionString, FrameworkRule{
		Framework:   FrameworkSecurity,
		RuleID:      "SEC-CONN-STRING",
		Severity:    SeverityCritical,
		Description: "Database connection strings with credentials must not be exposed",
	})

	// ========================================================================
	// NIST CSF Rules (Cybersecurity Framework)
	// ========================================================================

	// All credential types → NIST-CSF-PR.DS-1 (Data-at-rest protection)
	for _, credType := range c.allCredentialTypes() {
		c.addRule(credType, FrameworkRule{
			Framework:   FrameworkNISTCSF,
			RuleID:      "NIST-CSF-PR.DS-1",
			Severity:    SeverityCritical,
			Description: "Credential exposure violates NIST CSF PR.DS-1 (Data-at-rest protection)",
		})
	}
	// SSN, credit card → NIST-CSF-ID.AM-5 (Data classification)
	c.addRule(PIITypeSSN, FrameworkRule{
		Framework:   FrameworkNISTCSF,
		RuleID:      "NIST-CSF-ID.AM-5",
		Severity:    SeverityHigh,
		Description: "SSN exposure requires data classification per NIST CSF ID.AM-5",
	})
	c.addRule(PIITypeCreditCard, FrameworkRule{
		Framework:   FrameworkNISTCSF,
		RuleID:      "NIST-CSF-ID.AM-5",
		Severity:    SeverityHigh,
		Description: "Credit card exposure requires data classification per NIST CSF ID.AM-5",
	})
	// Email → conditional on government/critical infra
	c.addRule(PIITypeEmail, FrameworkRule{
		Framework:   FrameworkNISTCSF,
		RuleID:      "NIST-CSF-PR.AC-1",
		Severity:    SeverityMedium,
		Description: "Email exposure may violate NIST CSF PR.AC-1 (Access control) in government context",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsGovernment || ctx.IsCriticalInfra
		},
	})

	// ========================================================================
	// NIST AI RMF Rules (AI Risk Management Framework)
	// ========================================================================

	// SSN, email, name → conditional on AI context
	c.addRule(PIITypeSSN, FrameworkRule{
		Framework:   FrameworkNISTAIRMF,
		RuleID:      "NIST-AI-MAP-1.5",
		Severity:    SeverityHigh,
		Description: "SSN in AI context requires individual impact assessment per NIST AI RMF MAP-1.5",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsAIContext
		},
	})
	c.addRule(PIITypeEmail, FrameworkRule{
		Framework:   FrameworkNISTAIRMF,
		RuleID:      "NIST-AI-MAP-1.5",
		Severity:    SeverityMedium,
		Description: "Email in AI context may require impact assessment per NIST AI RMF MAP-1.5",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsAIContext
		},
	})
	c.addRule(PIITypeName, FrameworkRule{
		Framework:   FrameworkNISTAIRMF,
		RuleID:      "NIST-AI-MAP-1.5",
		Severity:    SeverityMedium,
		Description: "Name in AI context may require impact assessment per NIST AI RMF MAP-1.5",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsAIContext
		},
	})
	// Medical records, credit card → AI risk tracking
	c.addRule(PIITypeMedicalRecordNumber, FrameworkRule{
		Framework:   FrameworkNISTAIRMF,
		RuleID:      "NIST-AI-MANAGE-2.2",
		Severity:    SeverityCritical,
		Description: "Medical records in AI context require risk tracking per NIST AI RMF MANAGE-2.2",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsAIContext
		},
	})
	c.addRule(PIITypeCreditCard, FrameworkRule{
		Framework:   FrameworkNISTAIRMF,
		RuleID:      "NIST-AI-MANAGE-2.2",
		Severity:    SeverityHigh,
		Description: "Credit card in AI context requires risk tracking per NIST AI RMF MANAGE-2.2",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsAIContext
		},
	})

	// ========================================================================
	// SOC 2 Rules (Trust Service Criteria)
	// ========================================================================

	// All credential types → SOC2-CC6.1 (Logical access controls) - unconditional
	for _, credType := range c.allCredentialTypes() {
		c.addRule(credType, FrameworkRule{
			Framework:   FrameworkSOC2,
			RuleID:      "SOC2-CC6.1",
			Severity:    SeverityCritical,
			Description: "Credential exposure violates SOC 2 CC6.1 (Logical access controls)",
		})
	}
	// SSN, credit card → conditional on cloud service
	c.addRule(PIITypeSSN, FrameworkRule{
		Framework:   FrameworkSOC2,
		RuleID:      "SOC2-C1.1",
		Severity:    SeverityCritical,
		Description: "SSN exposure in cloud service violates SOC 2 C1.1 (Confidential information)",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsCloudService
		},
	})
	c.addRule(PIITypeCreditCard, FrameworkRule{
		Framework:   FrameworkSOC2,
		RuleID:      "SOC2-C1.1",
		Severity:    SeverityCritical,
		Description: "Credit card exposure in cloud service violates SOC 2 C1.1",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsCloudService
		},
	})
	// Email, name → privacy notice - conditional on cloud service
	c.addRule(PIITypeEmail, FrameworkRule{
		Framework:   FrameworkSOC2,
		RuleID:      "SOC2-P1.1",
		Severity:    SeverityMedium,
		Description: "Email in cloud service requires privacy notice per SOC 2 P1.1",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsCloudService
		},
	})
	c.addRule(PIITypeName, FrameworkRule{
		Framework:   FrameworkSOC2,
		RuleID:      "SOC2-P1.1",
		Severity:    SeverityMedium,
		Description: "Name in cloud service requires privacy notice per SOC 2 P1.1",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsCloudService
		},
	})
	// Bank account → SOC2-CC7.2
	c.addRule(PIITypeBankAccount, FrameworkRule{
		Framework:   FrameworkSOC2,
		RuleID:      "SOC2-CC7.2",
		Severity:    SeverityHigh,
		Description: "Bank account data requires incident monitoring per SOC 2 CC7.2",
	})

	// ========================================================================
	// EU AI Act Rules
	// ========================================================================

	// SSN → conditional on EU + AI context
	c.addRule(PIITypeSSN, FrameworkRule{
		Framework:   FrameworkEUAIAct,
		RuleID:      "EUAI-ART10",
		Severity:    SeverityCritical,
		Description: "SSN in EU AI context requires data governance per EU AI Act Article 10",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsEUData && ctx.IsAIContext
		},
	})
	// Name, email, DOB → conditional on EU + AI
	c.addRule(PIITypeName, FrameworkRule{
		Framework:   FrameworkEUAIAct,
		RuleID:      "EUAI-ART10",
		Severity:    SeverityHigh,
		Description: "Personal name in EU AI context requires data governance per EU AI Act Article 10",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsEUData && ctx.IsAIContext
		},
	})
	c.addRule(PIITypeEmail, FrameworkRule{
		Framework:   FrameworkEUAIAct,
		RuleID:      "EUAI-ART10",
		Severity:    SeverityHigh,
		Description: "Email in EU AI context requires data governance per EU AI Act Article 10",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsEUData && ctx.IsAIContext
		},
	})
	c.addRule(PIITypeDateOfBirth, FrameworkRule{
		Framework:   FrameworkEUAIAct,
		RuleID:      "EUAI-ART10",
		Severity:    SeverityHigh,
		Description: "DOB in EU AI context requires data governance per EU AI Act Article 10",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsEUData && ctx.IsAIContext
		},
	})
	// Medical records → special category
	c.addRule(PIITypeMedicalRecordNumber, FrameworkRule{
		Framework:   FrameworkEUAIAct,
		RuleID:      "EUAI-ART10-SPECIAL",
		Severity:    SeverityCritical,
		Description: "Medical data in EU AI context is special category per EU AI Act Article 10",
		Condition: func(ctx ClassificationContext) bool {
			return ctx.IsEUData && ctx.IsAIContext
		},
	})

	// ========================================================================
	// ISO 27001 Rules (Information Security Management)
	// ========================================================================

	// All credential types → ISO27001-A.9.4 (Access control) - unconditional
	for _, credType := range c.allCredentialTypes() {
		c.addRule(credType, FrameworkRule{
			Framework:   FrameworkISO27001,
			RuleID:      "ISO27001-A.9.4",
			Severity:    SeverityCritical,
			Description: "Credential exposure violates ISO 27001 A.9.4 (Access control)",
		})
	}
	// SSN, credit card, bank account → information classification
	c.addRule(PIITypeSSN, FrameworkRule{
		Framework:   FrameworkISO27001,
		RuleID:      "ISO27001-A.8.2",
		Severity:    SeverityHigh,
		Description: "SSN requires information classification per ISO 27001 A.8.2",
	})
	c.addRule(PIITypeCreditCard, FrameworkRule{
		Framework:   FrameworkISO27001,
		RuleID:      "ISO27001-A.8.2",
		Severity:    SeverityHigh,
		Description: "Credit card data requires information classification per ISO 27001 A.8.2",
	})
	c.addRule(PIITypeBankAccount, FrameworkRule{
		Framework:   FrameworkISO27001,
		RuleID:      "ISO27001-A.8.2",
		Severity:    SeverityHigh,
		Description: "Bank account data requires information classification per ISO 27001 A.8.2",
	})
	// All PII types → privacy/PII protection
	for _, piiType := range []PIIType{PIITypeSSN, PIITypeEmail, PIITypeName, PIITypeDateOfBirth, PIITypePhoneNumber, PIITypeAddress} {
		c.addRule(piiType, FrameworkRule{
			Framework:   FrameworkISO27001,
			RuleID:      "ISO27001-A.18.1.4",
			Severity:    SeverityMedium,
			Description: "PII exposure requires protection per ISO 27001 A.18.1.4 (Privacy and PII protection)",
		})
	}
}

// addRule adds a rule to the internal indexes (unexported, called during init).
func (c *classifier) addRule(piiType PIIType, rule FrameworkRule) {
	c.rulesByType[piiType] = append(c.rulesByType[piiType], rule)
	c.rulesByFW[rule.Framework] = append(c.rulesByFW[rule.Framework], rule)
}

// AddRule is the exported variant of addRule. It acquires the write lock and
// adds a rule mapping a PIIType to a FrameworkRule. This allows external
// callers (such as configuration loaders) to register additional rules
// alongside the built-in defaults without creating a circular dependency.
func (c *classifier) AddRule(piiType PIIType, rule FrameworkRule) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addRule(piiType, rule)
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

		// NIST CSF hints (government, critical infrastructure, cybersecurity)
		if strings.Contains(lowerHint, "nist") ||
			strings.Contains(lowerHint, "cybersecurity") ||
			strings.Contains(lowerHint, "critical infrastructure") ||
			strings.Contains(lowerHint, "government") ||
			strings.Contains(lowerHint, "federal") {
			if !c.hasFramework(matches, FrameworkNISTCSF) && c.isNISTCSFRelevant(finding.PIIType) {
				matches = append(matches, FrameworkMatch{
					Framework:   FrameworkNISTCSF,
					RuleID:      "NIST-CSF-CONTEXT",
					Severity:    SeverityHigh,
					Description: "Government/critical infrastructure context detected, NIST CSF may apply",
				})
			}
		}

		// AI context hints (NIST AI RMF and EU AI Act)
		if strings.Contains(lowerHint, "ai") ||
			strings.Contains(lowerHint, "machine learning") ||
			strings.Contains(lowerHint, "model") ||
			strings.Contains(lowerHint, "llm") ||
			strings.Contains(lowerHint, "training data") {
			if !c.hasFramework(matches, FrameworkNISTAIRMF) {
				matches = append(matches, FrameworkMatch{
					Framework:   FrameworkNISTAIRMF,
					RuleID:      "NIST-AI-CONTEXT",
					Severity:    SeverityMedium,
					Description: "AI context detected, NIST AI RMF may apply",
				})
			}
		}

		// SOC 2 hints (cloud, SaaS, trust services)
		if strings.Contains(lowerHint, "soc2") ||
			strings.Contains(lowerHint, "soc 2") ||
			strings.Contains(lowerHint, "cloud") ||
			strings.Contains(lowerHint, "saas") ||
			strings.Contains(lowerHint, "trust service") {
			if !c.hasFramework(matches, FrameworkSOC2) && c.isSOC2Relevant(finding.PIIType) {
				matches = append(matches, FrameworkMatch{
					Framework:   FrameworkSOC2,
					RuleID:      "SOC2-CONTEXT",
					Severity:    SeverityHigh,
					Description: "Cloud/SaaS context detected, SOC 2 may apply",
				})
			}
		}

		// ISO 27001 hints (ISMS, information security)
		if strings.Contains(lowerHint, "iso 27001") ||
			strings.Contains(lowerHint, "iso27001") ||
			strings.Contains(lowerHint, "isms") ||
			strings.Contains(lowerHint, "information security") {
			if !c.hasFramework(matches, FrameworkISO27001) {
				matches = append(matches, FrameworkMatch{
					Framework:   FrameworkISO27001,
					RuleID:      "ISO27001-CONTEXT",
					Severity:    SeverityHigh,
					Description: "Information security context detected, ISO 27001 may apply",
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

// isNISTCSFRelevant checks if a PII type is relevant to NIST CSF
func (c *classifier) isNISTCSFRelevant(piiType PIIType) bool {
	relevantTypes := map[PIIType]bool{
		PIITypeAWSAccessKey:     true,
		PIITypeAWSSecretKey:     true,
		PIITypeAPIKey:           true,
		PIITypeAzureKey:         true,
		PIITypeGCPKey:           true,
		PIITypeJWTToken:         true,
		PIITypeOAuthToken:       true,
		PIITypePrivateKey:       true,
		PIITypeConnectionString: true,
		PIITypeSSN:              true,
		PIITypeCreditCard:       true,
	}
	return relevantTypes[piiType]
}

// isSOC2Relevant checks if a PII type is relevant to SOC 2
func (c *classifier) isSOC2Relevant(piiType PIIType) bool {
	relevantTypes := map[PIIType]bool{
		PIITypeAWSAccessKey:     true,
		PIITypeAWSSecretKey:     true,
		PIITypeAPIKey:           true,
		PIITypeAzureKey:         true,
		PIITypeGCPKey:           true,
		PIITypeJWTToken:         true,
		PIITypeOAuthToken:       true,
		PIITypePrivateKey:       true,
		PIITypeConnectionString: true,
		PIITypeSSN:              true,
		PIITypeCreditCard:       true,
		PIITypeBankAccount:      true,
		PIITypeEmail:            true,
		PIITypeName:             true,
	}
	return relevantTypes[piiType]
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
		FrameworkNISTCSF,
		FrameworkNISTAIRMF,
		FrameworkSOC2,
		FrameworkEUAIAct,
		FrameworkISO27001,
	}
}

// allCredentialTypes returns all credential PIITypes
func (c *classifier) allCredentialTypes() []PIIType {
	return []PIIType{
		PIITypeAWSAccessKey,
		PIITypeAWSSecretKey,
		PIITypeAPIKey,
		PIITypeAzureKey,
		PIITypeGCPKey,
		PIITypeJWTToken,
		PIITypeOAuthToken,
		PIITypePrivateKey,
		PIITypeConnectionString,
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

	// NIST CSF — all injection types
	matches = append(matches, FrameworkMatch{
		Framework:   FrameworkNISTCSF,
		RuleID:      "NIST-CSF-DE.CM-1",
		Severity:    SeverityHigh,
		Description: "Injection attempt violates NIST CSF DE.CM-1 (Network monitoring)",
	})

	// SOC 2 — all injection types
	matches = append(matches, FrameworkMatch{
		Framework:   FrameworkSOC2,
		RuleID:      "SOC2-CC6.6",
		Severity:    SeverityHigh,
		Description: "Injection attempt violates SOC 2 CC6.6 (System boundary protection)",
	})

	// ISO 27001 — all injection types
	matches = append(matches, FrameworkMatch{
		Framework:   FrameworkISO27001,
		RuleID:      "ISO27001-A.14.2",
		Severity:    SeverityHigh,
		Description: "Injection attempt violates ISO 27001 A.14.2 (Security in development)",
	})

	// Prompt injection is unconditionally mapped to EU AI Act and NIST AI RMF
	if finding.InjectionType == InjectionTypePrompt {
		matches = append(matches, FrameworkMatch{
			Framework:   FrameworkEUAIAct,
			RuleID:      "EUAI-ART15",
			Severity:    SeverityCritical,
			Description: "Prompt injection violates EU AI Act Article 15 (Robustness)",
		})
		matches = append(matches, FrameworkMatch{
			Framework:   FrameworkNISTAIRMF,
			RuleID:      "NIST-AI-MEASURE-2.6",
			Severity:    SeverityHigh,
			Description: "Prompt injection violates NIST AI RMF MEASURE-2.6 (AI safety)",
		})
	}

	return matches
}
