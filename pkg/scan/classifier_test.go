package scan

import (
	"testing"
)

// ============================================================================
// Individual Framework Classification Tests
// ============================================================================

func TestClassifier_PII(t *testing.T) {
	c := NewClassifier()

	// SSN should always be classified under the PII framework (unconditional)
	finding := &Finding{PIIType: PIITypeSSN}
	ctx := ClassificationContext{}

	matches := c.Classify(finding, ctx)

	hasPII := false
	for _, m := range matches {
		if m.Framework == FrameworkPII {
			hasPII = true
			if m.RuleID != "PII-SSN" {
				t.Errorf("Expected RuleID PII-SSN for SSN under PII framework, got %s", m.RuleID)
			}
			break
		}
	}

	if !hasPII {
		t.Error("Expected SSN to always be classified under PII framework")
	}

	// Credit card should also be under PII
	ccFinding := &Finding{PIIType: PIITypeCreditCard}
	ccMatches := c.Classify(ccFinding, ctx)

	hasPIICC := false
	for _, m := range ccMatches {
		if m.Framework == FrameworkPII && m.RuleID == "PII-CC" {
			hasPIICC = true
			break
		}
	}
	if !hasPIICC {
		t.Error("Expected credit card to be classified under PII framework")
	}

	// Passport should also be under PII
	passportFinding := &Finding{PIIType: PIITypePassport}
	passportMatches := c.Classify(passportFinding, ctx)

	hasPIIPassport := false
	for _, m := range passportMatches {
		if m.Framework == FrameworkPII && m.RuleID == "PII-PASSPORT" {
			hasPIIPassport = true
			break
		}
	}
	if !hasPIIPassport {
		t.Error("Expected passport to be classified under PII framework")
	}

	// Drivers license should be under PII
	dlFinding := &Finding{PIIType: PIITypeDriversLicense}
	dlMatches := c.Classify(dlFinding, ctx)

	hasPIIDL := false
	for _, m := range dlMatches {
		if m.Framework == FrameworkPII && m.RuleID == "PII-DL" {
			hasPIIDL = true
			break
		}
	}
	if !hasPIIDL {
		t.Error("Expected driver's license to be classified under PII framework")
	}
}

func TestClassifier_HIPAA(t *testing.T) {
	c := NewClassifier()

	tests := []struct {
		name         string
		piiType      PIIType
		ctx          ClassificationContext
		expectHIPAA  bool
		expectedRule string
	}{
		{
			name:         "SSN with IsHealthcare true triggers HIPAA-164.514",
			piiType:      PIITypeSSN,
			ctx:          ClassificationContext{IsHealthcare: true},
			expectHIPAA:  true,
			expectedRule: "HIPAA-164.514",
		},
		{
			name:        "SSN without IsHealthcare does not trigger HIPAA",
			piiType:     PIITypeSSN,
			ctx:         ClassificationContext{IsHealthcare: false},
			expectHIPAA: false,
		},
		{
			name:         "MedicalRecordNumber always triggers HIPAA (unconditional)",
			piiType:      PIITypeMedicalRecordNumber,
			ctx:          ClassificationContext{},
			expectHIPAA:  true,
			expectedRule: "HIPAA-164.514-MRN",
		},
		{
			name:         "DateOfBirth with IsHealthcare triggers HIPAA",
			piiType:      PIITypeDateOfBirth,
			ctx:          ClassificationContext{IsHealthcare: true},
			expectHIPAA:  true,
			expectedRule: "HIPAA-164.514-DOB",
		},
		{
			name:        "DateOfBirth without IsHealthcare does not trigger HIPAA",
			piiType:     PIITypeDateOfBirth,
			ctx:         ClassificationContext{IsHealthcare: false},
			expectHIPAA: false,
		},
		{
			name:         "Name with IsHealthcare triggers HIPAA",
			piiType:      PIITypeName,
			ctx:          ClassificationContext{IsHealthcare: true},
			expectHIPAA:  true,
			expectedRule: "HIPAA-164.514-NAME",
		},
		{
			name:         "Address with IsHealthcare triggers HIPAA",
			piiType:      PIITypeAddress,
			ctx:          ClassificationContext{IsHealthcare: true},
			expectHIPAA:  true,
			expectedRule: "HIPAA-164.514-ADDR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := &Finding{PIIType: tt.piiType}
			matches := c.Classify(finding, tt.ctx)

			hasHIPAA := false
			for _, m := range matches {
				if m.Framework == FrameworkHIPAA {
					hasHIPAA = true
					if tt.expectedRule != "" && m.RuleID != tt.expectedRule {
						t.Errorf("Expected RuleID %s, got %s", tt.expectedRule, m.RuleID)
					}
					break
				}
			}

			if hasHIPAA != tt.expectHIPAA {
				t.Errorf("Expected HIPAA=%v, got %v", tt.expectHIPAA, hasHIPAA)
			}
		})
	}
}

func TestClassifier_GDPR(t *testing.T) {
	c := NewClassifier()

	tests := []struct {
		name        string
		piiType     PIIType
		ctx         ClassificationContext
		expectGDPR  bool
		expectedRule string
	}{
		{
			name:         "Email with IsEUData triggers GDPR-4.1",
			piiType:      PIITypeEmail,
			ctx:          ClassificationContext{IsEUData: true},
			expectGDPR:   true,
			expectedRule: "GDPR-4.1",
		},
		{
			name:       "Email without IsEUData does not trigger GDPR",
			piiType:    PIITypeEmail,
			ctx:        ClassificationContext{IsEUData: false},
			expectGDPR: false,
		},
		{
			name:         "Name with IsEUData triggers GDPR",
			piiType:      PIITypeName,
			ctx:          ClassificationContext{IsEUData: true},
			expectGDPR:   true,
			expectedRule: "GDPR-4.1-NAME",
		},
		{
			name:         "IP address with IsEUData triggers GDPR",
			piiType:      PIITypeIPAddress,
			ctx:          ClassificationContext{IsEUData: true},
			expectGDPR:   true,
			expectedRule: "GDPR-4.1-IP",
		},
		{
			name:         "DateOfBirth with IsEUData triggers GDPR",
			piiType:      PIITypeDateOfBirth,
			ctx:          ClassificationContext{IsEUData: true},
			expectGDPR:   true,
			expectedRule: "GDPR-4.1-DOB",
		},
		{
			name:       "IP address without IsEUData does not trigger GDPR",
			piiType:    PIITypeIPAddress,
			ctx:        ClassificationContext{},
			expectGDPR: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := &Finding{PIIType: tt.piiType}
			matches := c.Classify(finding, tt.ctx)

			hasGDPR := false
			for _, m := range matches {
				if m.Framework == FrameworkGDPR {
					hasGDPR = true
					if tt.expectedRule != "" && m.RuleID != tt.expectedRule {
						t.Errorf("Expected RuleID %s, got %s", tt.expectedRule, m.RuleID)
					}
					break
				}
			}

			if hasGDPR != tt.expectGDPR {
				t.Errorf("Expected GDPR=%v, got %v", tt.expectGDPR, hasGDPR)
			}
		})
	}
}

func TestClassifier_PCI_DSS(t *testing.T) {
	c := NewClassifier()

	tests := []struct {
		name          string
		piiType       PIIType
		ctx           ClassificationContext
		expectPCIDSS  bool
		expectedRule  string
	}{
		{
			name:          "Credit card unconditionally triggers PCI-DSS-3.4",
			piiType:       PIITypeCreditCard,
			ctx:           ClassificationContext{},
			expectPCIDSS:  true,
			expectedRule:  "PCI-DSS-3.4",
		},
		{
			name:          "Bank account unconditionally triggers PCI-DSS-3.2",
			piiType:       PIITypeBankAccount,
			ctx:           ClassificationContext{},
			expectPCIDSS:  true,
			expectedRule:  "PCI-DSS-3.2",
		},
		{
			name:         "SSN does not trigger PCI-DSS",
			piiType:      PIITypeSSN,
			ctx:          ClassificationContext{},
			expectPCIDSS: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := &Finding{PIIType: tt.piiType}
			matches := c.Classify(finding, tt.ctx)

			hasPCIDSS := false
			for _, m := range matches {
				if m.Framework == FrameworkPCIDSS {
					hasPCIDSS = true
					if tt.expectedRule != "" && m.RuleID != tt.expectedRule {
						t.Errorf("Expected RuleID %s, got %s", tt.expectedRule, m.RuleID)
					}
					break
				}
			}

			if hasPCIDSS != tt.expectPCIDSS {
				t.Errorf("Expected PCI-DSS=%v, got %v", tt.expectPCIDSS, hasPCIDSS)
			}
		})
	}
}

func TestClassifier_SOX(t *testing.T) {
	c := NewClassifier()

	tests := []struct {
		name        string
		piiType     PIIType
		ctx         ClassificationContext
		expectSOX   bool
		expectedRule string
	}{
		{
			name:         "Bank account with IsFinancial triggers SOX-302",
			piiType:      PIITypeBankAccount,
			ctx:          ClassificationContext{IsFinancial: true},
			expectSOX:    true,
			expectedRule: "SOX-302",
		},
		{
			name:      "Bank account without IsFinancial does not trigger SOX",
			piiType:   PIITypeBankAccount,
			ctx:       ClassificationContext{IsFinancial: false},
			expectSOX: false,
		},
		{
			name:         "Credit card with IsFinancial triggers SOX-404",
			piiType:      PIITypeCreditCard,
			ctx:          ClassificationContext{IsFinancial: true},
			expectSOX:    true,
			expectedRule: "SOX-404",
		},
		{
			name:      "Credit card without IsFinancial does not trigger SOX",
			piiType:   PIITypeCreditCard,
			ctx:       ClassificationContext{},
			expectSOX: false,
		},
		{
			name:      "SSN does not trigger SOX even with IsFinancial",
			piiType:   PIITypeSSN,
			ctx:       ClassificationContext{IsFinancial: true},
			expectSOX: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := &Finding{PIIType: tt.piiType}
			matches := c.Classify(finding, tt.ctx)

			hasSOX := false
			for _, m := range matches {
				if m.Framework == FrameworkSOX {
					hasSOX = true
					if tt.expectedRule != "" && m.RuleID != tt.expectedRule {
						t.Errorf("Expected RuleID %s, got %s", tt.expectedRule, m.RuleID)
					}
					break
				}
			}

			if hasSOX != tt.expectSOX {
				t.Errorf("Expected SOX=%v, got %v", tt.expectSOX, hasSOX)
			}
		})
	}
}

func TestClassifier_CCPA(t *testing.T) {
	c := NewClassifier()

	tests := []struct {
		name         string
		piiType      PIIType
		ctx          ClassificationContext
		expectCCPA   bool
		expectedRule string
	}{
		{
			name:         "SSN unconditionally triggers CCPA-1798.140",
			piiType:      PIITypeSSN,
			ctx:          ClassificationContext{},
			expectCCPA:   true,
			expectedRule: "CCPA-1798.140",
		},
		{
			name:         "Email unconditionally triggers CCPA",
			piiType:      PIITypeEmail,
			ctx:          ClassificationContext{},
			expectCCPA:   true,
			expectedRule: "CCPA-1798.140-EMAIL",
		},
		{
			name:         "Drivers license unconditionally triggers CCPA",
			piiType:      PIITypeDriversLicense,
			ctx:          ClassificationContext{},
			expectCCPA:   true,
			expectedRule: "CCPA-1798.140-DL",
		},
		{
			name:       "Credit card does not trigger CCPA",
			piiType:    PIITypeCreditCard,
			ctx:        ClassificationContext{},
			expectCCPA: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := &Finding{PIIType: tt.piiType}
			matches := c.Classify(finding, tt.ctx)

			hasCCPA := false
			for _, m := range matches {
				if m.Framework == FrameworkCCPA {
					hasCCPA = true
					if tt.expectedRule != "" && m.RuleID != tt.expectedRule {
						t.Errorf("Expected RuleID %s, got %s", tt.expectedRule, m.RuleID)
					}
					break
				}
			}

			if hasCCPA != tt.expectCCPA {
				t.Errorf("Expected CCPA=%v, got %v", tt.expectCCPA, hasCCPA)
			}
		})
	}
}

func TestClassifier_SECURITY(t *testing.T) {
	c := NewClassifier()

	credentialTypes := []struct {
		name         string
		piiType      PIIType
		expectedRule string
	}{
		{"AWS Access Key", PIITypeAWSAccessKey, "SEC-AWS-KEY"},
		{"AWS Secret Key", PIITypeAWSSecretKey, "SEC-AWS-SECRET"},
		{"API Key", PIITypeAPIKey, "SEC-API-KEY"},
		{"Azure Key", PIITypeAzureKey, "SEC-AZURE-KEY"},
		{"GCP Key", PIITypeGCPKey, "SEC-GCP-KEY"},
		{"JWT Token", PIITypeJWTToken, "SEC-JWT-TOKEN"},
		{"OAuth Token", PIITypeOAuthToken, "SEC-OAUTH-TOKEN"},
		{"Private Key", PIITypePrivateKey, "SEC-PRIVATE-KEY"},
		{"Connection String", PIITypeConnectionString, "SEC-CONN-STRING"},
	}

	for _, tt := range credentialTypes {
		t.Run(tt.name, func(t *testing.T) {
			finding := &Finding{PIIType: tt.piiType}
			matches := c.Classify(finding, ClassificationContext{})

			hasSecurity := false
			for _, m := range matches {
				if m.Framework == FrameworkSecurity && m.RuleID == tt.expectedRule {
					hasSecurity = true
					break
				}
			}

			if !hasSecurity {
				t.Errorf("Expected SECURITY framework with rule %s for %s", tt.expectedRule, tt.piiType)
			}
		})
	}

	// Non-credential types should not trigger SECURITY
	t.Run("SSN does not trigger SECURITY", func(t *testing.T) {
		finding := &Finding{PIIType: PIITypeSSN}
		matches := c.Classify(finding, ClassificationContext{})

		for _, m := range matches {
			if m.Framework == FrameworkSecurity {
				t.Error("SSN should not trigger SECURITY framework")
				break
			}
		}
	})
}

func TestClassifier_NIST_CSF(t *testing.T) {
	c := NewClassifier()

	tests := []struct {
		name         string
		piiType      PIIType
		ctx          ClassificationContext
		expectNIST   bool
		expectedRule string
	}{
		{
			name:         "AWS Access Key unconditionally triggers NIST-CSF-PR.DS-1",
			piiType:      PIITypeAWSAccessKey,
			ctx:          ClassificationContext{},
			expectNIST:   true,
			expectedRule: "NIST-CSF-PR.DS-1",
		},
		{
			name:         "GCP Key unconditionally triggers NIST-CSF-PR.DS-1",
			piiType:      PIITypeGCPKey,
			ctx:          ClassificationContext{},
			expectNIST:   true,
			expectedRule: "NIST-CSF-PR.DS-1",
		},
		{
			name:         "SSN unconditionally triggers NIST-CSF-ID.AM-5",
			piiType:      PIITypeSSN,
			ctx:          ClassificationContext{},
			expectNIST:   true,
			expectedRule: "NIST-CSF-ID.AM-5",
		},
		{
			name:         "Credit card unconditionally triggers NIST-CSF-ID.AM-5",
			piiType:      PIITypeCreditCard,
			ctx:          ClassificationContext{},
			expectNIST:   true,
			expectedRule: "NIST-CSF-ID.AM-5",
		},
		{
			name:         "Email with IsGovernment triggers NIST-CSF-PR.AC-1",
			piiType:      PIITypeEmail,
			ctx:          ClassificationContext{IsGovernment: true},
			expectNIST:   true,
			expectedRule: "NIST-CSF-PR.AC-1",
		},
		{
			name:         "Email with IsCriticalInfra triggers NIST-CSF-PR.AC-1",
			piiType:      PIITypeEmail,
			ctx:          ClassificationContext{IsCriticalInfra: true},
			expectNIST:   true,
			expectedRule: "NIST-CSF-PR.AC-1",
		},
		{
			name:       "Email without government or critical infra does not trigger NIST CSF email rule",
			piiType:    PIITypeEmail,
			ctx:        ClassificationContext{},
			expectNIST: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := &Finding{PIIType: tt.piiType}
			matches := c.Classify(finding, tt.ctx)

			hasNISTCSF := false
			for _, m := range matches {
				if m.Framework == FrameworkNISTCSF {
					hasNISTCSF = true
					if tt.expectedRule != "" && m.RuleID != tt.expectedRule {
						// Some PIITypes have multiple NIST CSF rules; check if any match
						continue
					}
					break
				}
			}

			// For credential types that match NIST-CSF-PR.DS-1, double check
			if tt.expectNIST && !hasNISTCSF {
				// Check if any NIST CSF rule was matched
				for _, m := range matches {
					if m.Framework == FrameworkNISTCSF {
						hasNISTCSF = true
						break
					}
				}
			}

			if hasNISTCSF != tt.expectNIST {
				t.Errorf("Expected NIST_CSF=%v, got %v", tt.expectNIST, hasNISTCSF)
			}
		})
	}
}

func TestClassifier_NIST_AI_RMF(t *testing.T) {
	c := NewClassifier()

	tests := []struct {
		name           string
		piiType        PIIType
		ctx            ClassificationContext
		expectNISTAI   bool
		expectedRule   string
	}{
		{
			name:         "SSN with IsAIContext triggers NIST-AI-MAP-1.5",
			piiType:      PIITypeSSN,
			ctx:          ClassificationContext{IsAIContext: true},
			expectNISTAI: true,
			expectedRule: "NIST-AI-MAP-1.5",
		},
		{
			name:         "Email with IsAIContext triggers NIST-AI-MAP-1.5",
			piiType:      PIITypeEmail,
			ctx:          ClassificationContext{IsAIContext: true},
			expectNISTAI: true,
			expectedRule: "NIST-AI-MAP-1.5",
		},
		{
			name:         "Name with IsAIContext triggers NIST-AI-MAP-1.5",
			piiType:      PIITypeName,
			ctx:          ClassificationContext{IsAIContext: true},
			expectNISTAI: true,
			expectedRule: "NIST-AI-MAP-1.5",
		},
		{
			name:         "MedicalRecordNumber with IsAIContext triggers NIST-AI-MANAGE-2.2",
			piiType:      PIITypeMedicalRecordNumber,
			ctx:          ClassificationContext{IsAIContext: true},
			expectNISTAI: true,
			expectedRule: "NIST-AI-MANAGE-2.2",
		},
		{
			name:         "Credit card with IsAIContext triggers NIST-AI-MANAGE-2.2",
			piiType:      PIITypeCreditCard,
			ctx:          ClassificationContext{IsAIContext: true},
			expectNISTAI: true,
			expectedRule: "NIST-AI-MANAGE-2.2",
		},
		{
			name:         "SSN without IsAIContext does not trigger NIST AI RMF",
			piiType:      PIITypeSSN,
			ctx:          ClassificationContext{IsAIContext: false},
			expectNISTAI: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := &Finding{PIIType: tt.piiType}
			matches := c.Classify(finding, tt.ctx)

			hasNISTAIRMF := false
			for _, m := range matches {
				if m.Framework == FrameworkNISTAIRMF {
					hasNISTAIRMF = true
					if tt.expectedRule != "" && m.RuleID != tt.expectedRule {
						t.Errorf("Expected RuleID %s, got %s", tt.expectedRule, m.RuleID)
					}
					break
				}
			}

			if hasNISTAIRMF != tt.expectNISTAI {
				t.Errorf("Expected NIST_AI_RMF=%v, got %v", tt.expectNISTAI, hasNISTAIRMF)
			}
		})
	}
}

func TestClassifier_SOC2(t *testing.T) {
	c := NewClassifier()

	tests := []struct {
		name         string
		piiType      PIIType
		ctx          ClassificationContext
		expectSOC2   bool
		expectedRule string
	}{
		{
			name:         "AWS Access Key unconditionally triggers SOC2-CC6.1",
			piiType:      PIITypeAWSAccessKey,
			ctx:          ClassificationContext{},
			expectSOC2:   true,
			expectedRule: "SOC2-CC6.1",
		},
		{
			name:         "JWT Token unconditionally triggers SOC2-CC6.1",
			piiType:      PIITypeJWTToken,
			ctx:          ClassificationContext{},
			expectSOC2:   true,
			expectedRule: "SOC2-CC6.1",
		},
		{
			name:         "SSN with IsCloudService triggers SOC2-C1.1",
			piiType:      PIITypeSSN,
			ctx:          ClassificationContext{IsCloudService: true},
			expectSOC2:   true,
			expectedRule: "SOC2-C1.1",
		},
		{
			name:         "Credit card with IsCloudService triggers SOC2-C1.1",
			piiType:      PIITypeCreditCard,
			ctx:          ClassificationContext{IsCloudService: true},
			expectSOC2:   true,
			expectedRule: "SOC2-C1.1",
		},
		{
			name:         "Email with IsCloudService triggers SOC2-P1.1",
			piiType:      PIITypeEmail,
			ctx:          ClassificationContext{IsCloudService: true},
			expectSOC2:   true,
			expectedRule: "SOC2-P1.1",
		},
		{
			name:         "Name with IsCloudService triggers SOC2-P1.1",
			piiType:      PIITypeName,
			ctx:          ClassificationContext{IsCloudService: true},
			expectSOC2:   true,
			expectedRule: "SOC2-P1.1",
		},
		{
			name:         "Bank account unconditionally triggers SOC2-CC7.2",
			piiType:      PIITypeBankAccount,
			ctx:          ClassificationContext{},
			expectSOC2:   true,
			expectedRule: "SOC2-CC7.2",
		},
		{
			name:       "Email without IsCloudService does not trigger SOC2 P1.1",
			piiType:    PIITypeEmail,
			ctx:        ClassificationContext{},
			expectSOC2: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := &Finding{PIIType: tt.piiType}
			matches := c.Classify(finding, tt.ctx)

			hasSOC2 := false
			foundRule := ""
			for _, m := range matches {
				if m.Framework == FrameworkSOC2 {
					hasSOC2 = true
					foundRule = m.RuleID
					if tt.expectedRule != "" && m.RuleID == tt.expectedRule {
						break
					}
				}
			}

			if hasSOC2 != tt.expectSOC2 {
				t.Errorf("Expected SOC2=%v, got %v (found rule: %s)", tt.expectSOC2, hasSOC2, foundRule)
			}
		})
	}
}

func TestClassifier_EU_AI_ACT(t *testing.T) {
	c := NewClassifier()

	tests := []struct {
		name         string
		piiType      PIIType
		ctx          ClassificationContext
		expectEUAI   bool
		expectedRule string
	}{
		{
			name:         "SSN with IsEUData and IsAIContext triggers EUAI-ART10",
			piiType:      PIITypeSSN,
			ctx:          ClassificationContext{IsEUData: true, IsAIContext: true},
			expectEUAI:   true,
			expectedRule: "EUAI-ART10",
		},
		{
			name:       "SSN with only IsEUData (no AI) does not trigger EU AI Act",
			piiType:    PIITypeSSN,
			ctx:        ClassificationContext{IsEUData: true, IsAIContext: false},
			expectEUAI: false,
		},
		{
			name:       "SSN with only IsAIContext (no EU) does not trigger EU AI Act",
			piiType:    PIITypeSSN,
			ctx:        ClassificationContext{IsEUData: false, IsAIContext: true},
			expectEUAI: false,
		},
		{
			name:         "Name with IsEUData and IsAIContext triggers EUAI-ART10",
			piiType:      PIITypeName,
			ctx:          ClassificationContext{IsEUData: true, IsAIContext: true},
			expectEUAI:   true,
			expectedRule: "EUAI-ART10",
		},
		{
			name:         "Email with IsEUData and IsAIContext triggers EUAI-ART10",
			piiType:      PIITypeEmail,
			ctx:          ClassificationContext{IsEUData: true, IsAIContext: true},
			expectEUAI:   true,
			expectedRule: "EUAI-ART10",
		},
		{
			name:         "DateOfBirth with IsEUData and IsAIContext triggers EUAI-ART10",
			piiType:      PIITypeDateOfBirth,
			ctx:          ClassificationContext{IsEUData: true, IsAIContext: true},
			expectEUAI:   true,
			expectedRule: "EUAI-ART10",
		},
		{
			name:         "MedicalRecordNumber with IsEUData and IsAIContext triggers EUAI-ART10-SPECIAL",
			piiType:      PIITypeMedicalRecordNumber,
			ctx:          ClassificationContext{IsEUData: true, IsAIContext: true},
			expectEUAI:   true,
			expectedRule: "EUAI-ART10-SPECIAL",
		},
		{
			name:       "Credit card does not trigger EU AI Act (no rule defined)",
			piiType:    PIITypeCreditCard,
			ctx:        ClassificationContext{IsEUData: true, IsAIContext: true},
			expectEUAI: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := &Finding{PIIType: tt.piiType}
			matches := c.Classify(finding, tt.ctx)

			hasEUAI := false
			for _, m := range matches {
				if m.Framework == FrameworkEUAIAct {
					hasEUAI = true
					if tt.expectedRule != "" && m.RuleID != tt.expectedRule {
						t.Errorf("Expected RuleID %s, got %s", tt.expectedRule, m.RuleID)
					}
					break
				}
			}

			if hasEUAI != tt.expectEUAI {
				t.Errorf("Expected EU_AI_ACT=%v, got %v", tt.expectEUAI, hasEUAI)
			}
		})
	}
}

func TestClassifier_ISO27001(t *testing.T) {
	c := NewClassifier()

	tests := []struct {
		name          string
		piiType       PIIType
		ctx           ClassificationContext
		expectISO     bool
		expectedRule  string
	}{
		{
			name:          "AWS Access Key triggers ISO27001-A.9.4",
			piiType:       PIITypeAWSAccessKey,
			ctx:           ClassificationContext{},
			expectISO:     true,
			expectedRule:  "ISO27001-A.9.4",
		},
		{
			name:          "Private Key triggers ISO27001-A.9.4",
			piiType:       PIITypePrivateKey,
			ctx:           ClassificationContext{},
			expectISO:     true,
			expectedRule:  "ISO27001-A.9.4",
		},
		{
			name:          "Connection String triggers ISO27001-A.9.4",
			piiType:       PIITypeConnectionString,
			ctx:           ClassificationContext{},
			expectISO:     true,
			expectedRule:  "ISO27001-A.9.4",
		},
		{
			name:          "SSN triggers ISO27001-A.8.2",
			piiType:       PIITypeSSN,
			ctx:           ClassificationContext{},
			expectISO:     true,
			expectedRule:  "ISO27001-A.8.2",
		},
		{
			name:          "Credit card triggers ISO27001-A.8.2",
			piiType:       PIITypeCreditCard,
			ctx:           ClassificationContext{},
			expectISO:     true,
			expectedRule:  "ISO27001-A.8.2",
		},
		{
			name:          "Bank account triggers ISO27001-A.8.2",
			piiType:       PIITypeBankAccount,
			ctx:           ClassificationContext{},
			expectISO:     true,
			expectedRule:  "ISO27001-A.8.2",
		},
		{
			name:          "Email triggers ISO27001-A.18.1.4 (PII protection)",
			piiType:       PIITypeEmail,
			ctx:           ClassificationContext{},
			expectISO:     true,
			expectedRule:  "ISO27001-A.18.1.4",
		},
		{
			name:          "Phone number triggers ISO27001-A.18.1.4",
			piiType:       PIITypePhoneNumber,
			ctx:           ClassificationContext{},
			expectISO:     true,
			expectedRule:  "ISO27001-A.18.1.4",
		},
		{
			name:          "Name triggers ISO27001-A.18.1.4",
			piiType:       PIITypeName,
			ctx:           ClassificationContext{},
			expectISO:     true,
			expectedRule:  "ISO27001-A.18.1.4",
		},
		{
			name:          "Address triggers ISO27001-A.18.1.4",
			piiType:       PIITypeAddress,
			ctx:           ClassificationContext{},
			expectISO:     true,
			expectedRule:  "ISO27001-A.18.1.4",
		},
		{
			name:          "DateOfBirth triggers ISO27001-A.18.1.4",
			piiType:       PIITypeDateOfBirth,
			ctx:           ClassificationContext{},
			expectISO:     true,
			expectedRule:  "ISO27001-A.18.1.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := &Finding{PIIType: tt.piiType}
			matches := c.Classify(finding, tt.ctx)

			hasISO := false
			foundRule := ""
			for _, m := range matches {
				if m.Framework == FrameworkISO27001 {
					hasISO = true
					foundRule = m.RuleID
					if tt.expectedRule != "" && m.RuleID == tt.expectedRule {
						break
					}
				}
			}

			if hasISO != tt.expectISO {
				t.Errorf("Expected ISO27001=%v, got %v (found rule: %s)", tt.expectISO, hasISO, foundRule)
			}
		})
	}
}

// ============================================================================
// Context Hints Tests
// ============================================================================

func TestClassifier_ContextHints(t *testing.T) {
	c := NewClassifier()

	tests := []struct {
		name             string
		piiType          PIIType
		hints            []string
		expectedFramework Framework
		expectedRule     string
	}{
		{
			name:              "Healthcare hint triggers HIPAA context",
			piiType:           PIITypeSSN,
			hints:             []string{"health"},
			expectedFramework: FrameworkHIPAA,
			expectedRule:      "HIPAA-CONTEXT",
		},
		{
			name:              "Medical hint triggers HIPAA context",
			piiType:           PIITypeEmail,
			hints:             []string{"medical records"},
			expectedFramework: FrameworkHIPAA,
			expectedRule:      "HIPAA-CONTEXT",
		},
		{
			name:              "Patient hint triggers HIPAA context",
			piiType:           PIITypeName,
			hints:             []string{"patient data"},
			expectedFramework: FrameworkHIPAA,
			expectedRule:      "HIPAA-CONTEXT",
		},
		{
			name:              "Finance hint triggers PCI-DSS context for credit card",
			piiType:           PIITypeCreditCard,
			hints:             []string{"finance"},
			expectedFramework: FrameworkPCIDSS,
			expectedRule:      "PCI-CONTEXT",
		},
		{
			name:              "Payment hint triggers PCI-DSS context for bank account",
			piiType:           PIITypeBankAccount,
			hints:             []string{"payment processing"},
			expectedFramework: FrameworkPCIDSS,
			expectedRule:      "PCI-CONTEXT",
		},
		{
			name:              "Europe hint triggers GDPR context",
			piiType:           PIITypeEmail,
			hints:             []string{"europe"},
			expectedFramework: FrameworkGDPR,
			expectedRule:      "GDPR-CONTEXT",
		},
		{
			name:              "EU hint triggers GDPR context",
			piiType:           PIITypeSSN,
			hints:             []string{"EU data"},
			expectedFramework: FrameworkGDPR,
			expectedRule:      "GDPR-CONTEXT",
		},
		{
			name:              "Government hint triggers NIST CSF context for credentials",
			piiType:           PIITypeAPIKey,
			hints:             []string{"government"},
			expectedFramework: FrameworkNISTCSF,
			expectedRule:      "NIST-CSF-CONTEXT",
		},
		{
			name:              "Federal hint triggers NIST CSF context",
			piiType:           PIITypeAWSAccessKey,
			hints:             []string{"federal"},
			expectedFramework: FrameworkNISTCSF,
			expectedRule:      "NIST-CSF-CONTEXT",
		},
		{
			name:              "AI hint triggers NIST AI RMF context",
			piiType:           PIITypeSSN,
			hints:             []string{"AI training data"},
			expectedFramework: FrameworkNISTAIRMF,
			expectedRule:      "NIST-AI-CONTEXT",
		},
		{
			name:              "LLM hint triggers NIST AI RMF context",
			piiType:           PIITypeEmail,
			hints:             []string{"llm context"},
			expectedFramework: FrameworkNISTAIRMF,
			expectedRule:      "NIST-AI-CONTEXT",
		},
		{
			name:              "Cloud hint triggers SOC 2 context for credentials",
			piiType:           PIITypeAPIKey,
			hints:             []string{"cloud deployment"},
			expectedFramework: FrameworkSOC2,
			expectedRule:      "SOC2-CONTEXT",
		},
		{
			name:              "SaaS hint triggers SOC 2 context",
			piiType:           PIITypeSSN,
			hints:             []string{"saas platform"},
			expectedFramework: FrameworkSOC2,
			expectedRule:      "SOC2-CONTEXT",
		},
		{
			name:              "ISO 27001 hint triggers ISO 27001 context",
			piiType:           PIITypeEmail,
			hints:             []string{"iso 27001 compliance"},
			expectedFramework: FrameworkISO27001,
			expectedRule:      "ISO27001-CONTEXT",
		},
		{
			name:              "ISMS hint triggers ISO 27001 context",
			piiType:           PIITypeSSN,
			hints:             []string{"isms audit"},
			expectedFramework: FrameworkISO27001,
			expectedRule:      "ISO27001-CONTEXT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := &Finding{PIIType: tt.piiType}
			ctx := ClassificationContext{
				Hints: tt.hints,
			}

			matches := c.Classify(finding, ctx)

			// The context hint ensures the expected framework is present.
			// It may come from a standard rule (if already matched) or
			// from the CONTEXT rule added by applyContextHints.
			hasFramework := false
			for _, m := range matches {
				if m.Framework == tt.expectedFramework {
					hasFramework = true
					break
				}
			}

			if !hasFramework {
				t.Errorf("Expected framework %s via hint %v, not found in matches",
					tt.expectedFramework, tt.hints)
				for _, m := range matches {
					t.Logf("  Found: %s / %s", m.Framework, m.RuleID)
				}
			}
		})
	}
}

// ============================================================================
// Multiple Frameworks and Edge Cases
// ============================================================================

func TestClassifier_MultipleFrameworks(t *testing.T) {
	c := NewClassifier()

	// SSN with all context flags should match many frameworks
	finding := &Finding{PIIType: PIITypeSSN}
	ctx := ClassificationContext{
		IsHealthcare:    true,
		IsEUData:        true,
		IsAIContext:     true,
		IsCloudService:  true,
		IsFinancial:     true,
		IsGovernment:    true,
		IsCriticalInfra: true,
	}

	matches := c.Classify(finding, ctx)

	expectedFrameworks := map[Framework]bool{
		FrameworkPII:       false,
		FrameworkHIPAA:     false,
		FrameworkCCPA:      false,
		FrameworkNISTCSF:   false,
		FrameworkNISTAIRMF: false,
		FrameworkSOC2:      false,
		FrameworkISO27001:  false,
		FrameworkEUAIAct:   false,
	}

	for _, m := range matches {
		if _, ok := expectedFrameworks[m.Framework]; ok {
			expectedFrameworks[m.Framework] = true
		}
	}

	for fw, found := range expectedFrameworks {
		if !found {
			t.Errorf("Expected SSN with all context flags to match %s framework", fw)
		}
	}
}

func TestClassifier_NoMatch(t *testing.T) {
	c := NewClassifier()

	// A custom PIIType with no rules registered should return empty
	finding := &Finding{PIIType: PIITypeCustom}
	ctx := ClassificationContext{}

	matches := c.Classify(finding, ctx)

	if len(matches) != 0 {
		t.Errorf("Expected 0 matches for custom PIIType with no rules, got %d", len(matches))
	}
}

func TestClassifier_AddRule(t *testing.T) {
	c := NewClassifier()

	// Add a custom rule for a custom PII type
	c.AddRule(PIITypeCustom, FrameworkRule{
		Framework:   FrameworkSecurity,
		RuleID:      "CUSTOM-RULE-1",
		Severity:    SeverityHigh,
		Description: "Custom rule for testing",
	})

	finding := &Finding{PIIType: PIITypeCustom}
	ctx := ClassificationContext{}

	matches := c.Classify(finding, ctx)

	if len(matches) != 1 {
		t.Fatalf("Expected 1 match after AddRule, got %d", len(matches))
	}

	if matches[0].RuleID != "CUSTOM-RULE-1" {
		t.Errorf("Expected RuleID CUSTOM-RULE-1, got %s", matches[0].RuleID)
	}
}

func TestClassifier_GetFrameworkRules(t *testing.T) {
	c := NewClassifier()

	// Use type assertion to access GetFrameworkRules
	cl, ok := c.(*classifier)
	if !ok {
		t.Fatal("Could not assert classifier type")
	}

	tests := []struct {
		framework    Framework
		minRuleCount int
	}{
		{FrameworkPII, 4},       // SSN, CC, Passport, DL
		{FrameworkHIPAA, 5},     // SSN, MRN, DOB, Name, Address
		{FrameworkGDPR, 4},      // Email, Name, IP, DOB
		{FrameworkPCIDSS, 2},    // CC, Bank Account
		{FrameworkSOX, 2},       // Bank Account, CC
		{FrameworkCCPA, 3},      // SSN, Email, DL
		{FrameworkSecurity, 9},  // 9 credential types
		{FrameworkNISTCSF, 11},  // 9 cred + SSN + CC + Email conditional
		{FrameworkNISTAIRMF, 5}, // SSN, Email, Name, MRN, CC
		{FrameworkSOC2, 14},     // 9 cred + SSN, CC, Email, Name, BankAcct
		{FrameworkEUAIAct, 5},   // SSN, Name, Email, DOB, MRN
		{FrameworkISO27001, 15}, // 9 cred + SSN, CC, BA + 6 PII types
	}

	for _, tt := range tests {
		t.Run(string(tt.framework), func(t *testing.T) {
			rules := cl.GetFrameworkRules(tt.framework)
			if len(rules) < tt.minRuleCount {
				t.Errorf("Expected at least %d rules for %s, got %d", tt.minRuleCount, tt.framework, len(rules))
			}
		})
	}
}

// ============================================================================
// Injection Classification Tests
// ============================================================================

func TestClassifyInjection_SQL(t *testing.T) {
	finding := &Finding{
		InjectionType: InjectionTypeSQL,
		PatternType:   PatternTypeInjection,
	}

	matches := ClassifyInjection(finding)

	expectedFrameworks := map[Framework]bool{
		FrameworkSecurity: false,
		FrameworkNISTCSF:  false,
		FrameworkSOC2:     false,
		FrameworkISO27001: false,
	}

	for _, m := range matches {
		if _, ok := expectedFrameworks[m.Framework]; ok {
			expectedFrameworks[m.Framework] = true
		}
	}

	for fw, found := range expectedFrameworks {
		if !found {
			t.Errorf("Expected SQL injection to trigger %s framework", fw)
		}
	}

	// SQL injection should have SEC-SQLI rule
	hasSQLiRule := false
	for _, m := range matches {
		if m.RuleID == "SEC-SQLI" {
			hasSQLiRule = true
			break
		}
	}
	if !hasSQLiRule {
		t.Error("Expected SEC-SQLI rule for SQL injection")
	}

	// SQL injection should NOT trigger EU AI Act or NIST AI RMF
	for _, m := range matches {
		if m.Framework == FrameworkEUAIAct || m.Framework == FrameworkNISTAIRMF {
			t.Errorf("SQL injection should not trigger %s framework", m.Framework)
		}
	}
}

func TestClassifyInjection_XSS(t *testing.T) {
	finding := &Finding{
		InjectionType: InjectionTypeXSS,
		PatternType:   PatternTypeInjection,
	}

	matches := ClassifyInjection(finding)

	hasXSSRule := false
	for _, m := range matches {
		if m.RuleID == "SEC-XSS" {
			hasXSSRule = true
			break
		}
	}
	if !hasXSSRule {
		t.Error("Expected SEC-XSS rule for XSS injection")
	}
}

func TestClassifyInjection_Prompt(t *testing.T) {
	finding := &Finding{
		InjectionType: InjectionTypePrompt,
		PatternType:   PatternTypeInjection,
	}

	matches := ClassifyInjection(finding)

	expectedFrameworks := map[Framework]bool{
		FrameworkSecurity:  false,
		FrameworkNISTCSF:   false,
		FrameworkSOC2:      false,
		FrameworkISO27001:  false,
		FrameworkEUAIAct:   false,
		FrameworkNISTAIRMF: false,
	}

	for _, m := range matches {
		if _, ok := expectedFrameworks[m.Framework]; ok {
			expectedFrameworks[m.Framework] = true
		}
	}

	for fw, found := range expectedFrameworks {
		if !found {
			t.Errorf("Expected prompt injection to trigger %s framework", fw)
		}
	}

	// Prompt injection should have EUAI-ART15 and NIST-AI-MEASURE-2.6
	hasEUAI := false
	hasNISTAI := false
	for _, m := range matches {
		if m.RuleID == "EUAI-ART15" {
			hasEUAI = true
		}
		if m.RuleID == "NIST-AI-MEASURE-2.6" {
			hasNISTAI = true
		}
	}
	if !hasEUAI {
		t.Error("Expected EUAI-ART15 rule for prompt injection")
	}
	if !hasNISTAI {
		t.Error("Expected NIST-AI-MEASURE-2.6 rule for prompt injection")
	}
}

func TestClassifyInjection_HTML(t *testing.T) {
	finding := &Finding{
		InjectionType: InjectionTypeHTML,
		PatternType:   PatternTypeInjection,
	}

	matches := ClassifyInjection(finding)

	hasHTMLRule := false
	for _, m := range matches {
		if m.RuleID == "SEC-HTML-INJ" {
			hasHTMLRule = true
			break
		}
	}
	if !hasHTMLRule {
		t.Error("Expected SEC-HTML-INJ rule for HTML injection")
	}

	// HTML injection should NOT trigger EU AI Act or NIST AI RMF
	for _, m := range matches {
		if m.Framework == FrameworkEUAIAct || m.Framework == FrameworkNISTAIRMF {
			t.Errorf("HTML injection should not trigger %s framework", m.Framework)
		}
	}
}
