// Package action provides rule-based automated responses to findings.
package action

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

// severityValue returns a numeric value for a severity string for comparison.
// critical=4, high=3, medium=2, low=1, unknown=0
func severityValue(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// getFieldValue extracts a string value from a finding for the given field name.
func getFieldValue(field string, finding *scan.Finding) (string, error) {
	switch field {
	case "severity":
		return string(finding.Severity), nil
	case "pattern_id":
		return finding.PatternID, nil
	case "pattern_type":
		return string(finding.PatternType), nil
	case "injection_type":
		return string(finding.InjectionType), nil
	case "pii_type":
		return string(finding.PIIType), nil
	case "source":
		if finding.Metadata != nil {
			return finding.Metadata["source"], nil
		}
		return "", nil
	default:
		return "", fmt.Errorf("unsupported field: %s", field)
	}
}

// evaluateCondition checks if a single condition matches a finding.
func evaluateCondition(cond Condition, finding *scan.Finding) bool {
	// Special handling for "frameworks" field since it is an array
	if cond.Field == "frameworks" {
		return evaluateFrameworksCondition(cond, finding)
	}

	// Special handling for "rate" field - skip, evaluated elsewhere
	if cond.Field == "rate" {
		return true
	}

	fieldVal, err := getFieldValue(cond.Field, finding)
	if err != nil {
		return false
	}

	condValue := fmt.Sprintf("%v", cond.Value)

	switch cond.Operator {
	case "eq":
		return strings.EqualFold(fieldVal, condValue)
	case "ne":
		return !strings.EqualFold(fieldVal, condValue)
	case "in":
		return evaluateIn(fieldVal, cond.Values)
	case "gt":
		return evaluateNumericGT(cond.Field, fieldVal, condValue)
	case "lt":
		return evaluateNumericLT(cond.Field, fieldVal, condValue)
	case "contains":
		return strings.Contains(strings.ToLower(fieldVal), strings.ToLower(condValue))
	default:
		return false
	}
}

// evaluateIn checks if fieldVal is one of the given values (case-insensitive).
func evaluateIn(fieldVal string, values []string) bool {
	for _, v := range values {
		if strings.EqualFold(fieldVal, v) {
			return true
		}
	}
	return false
}

// evaluateNumericGT performs greater-than comparison.
// For severity fields, uses severity ordinal values.
func evaluateNumericGT(field, fieldVal, condValue string) bool {
	if field == "severity" {
		return severityValue(fieldVal) > severityValue(condValue)
	}
	fv, err1 := strconv.ParseFloat(fieldVal, 64)
	cv, err2 := strconv.ParseFloat(condValue, 64)
	if err1 != nil || err2 != nil {
		return false
	}
	return fv > cv
}

// evaluateNumericLT performs less-than comparison.
// For severity fields, uses severity ordinal values.
func evaluateNumericLT(field, fieldVal, condValue string) bool {
	if field == "severity" {
		return severityValue(fieldVal) < severityValue(condValue)
	}
	fv, err1 := strconv.ParseFloat(fieldVal, 64)
	cv, err2 := strconv.ParseFloat(condValue, 64)
	if err1 != nil || err2 != nil {
		return false
	}
	return fv < cv
}

// evaluateFrameworksCondition checks framework-related conditions against a finding's frameworks.
func evaluateFrameworksCondition(cond Condition, finding *scan.Finding) bool {
	condValue := fmt.Sprintf("%v", cond.Value)

	switch cond.Operator {
	case "contains":
		for _, fm := range finding.Frameworks {
			if strings.EqualFold(string(fm.Framework), condValue) {
				return true
			}
		}
		return false
	case "eq":
		for _, fm := range finding.Frameworks {
			if strings.EqualFold(string(fm.Framework), condValue) {
				return true
			}
		}
		return false
	case "in":
		for _, fm := range finding.Frameworks {
			for _, v := range cond.Values {
				if strings.EqualFold(string(fm.Framework), v) {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
}
