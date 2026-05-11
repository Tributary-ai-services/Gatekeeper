package stream

import (
	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

// TopicRouter determines which topics a finding should be published to
type TopicRouter struct {
	topics Topics
}

// NewTopicRouter creates a new topic router with the given topic configuration
func NewTopicRouter(topics Topics) *TopicRouter {
	return &TopicRouter{
		topics: topics,
	}
}

// Route returns the list of topics this finding should be published to.
//
// Routing rules:
//   - ALL findings go to topics.Findings
//   - Critical severity findings also go to topics.Critical
//   - Findings carrying a compliance framework fan out to that framework's topic
//     (HIPAA, PCI_DSS, NIST_CSF/NIST_AI_RMF, SOC2, EU_AI_ACT, ISO_27001)
//
// A finding listing the same framework more than once will produce duplicate
// topics; callers that care should dedupe.
func (r *TopicRouter) Route(finding Finding) []string {
	topics := []string{r.topics.Findings}

	if finding.Severity == scan.SeverityCritical {
		topics = append(topics, r.topics.Critical)
	}

	for _, fw := range finding.Frameworks {
		switch fw {
		case string(scan.FrameworkHIPAA):
			topics = append(topics, r.topics.HIPAA)
		case string(scan.FrameworkPCIDSS):
			topics = append(topics, r.topics.PCI)
		case string(scan.FrameworkNISTCSF), string(scan.FrameworkNISTAIRMF):
			topics = append(topics, r.topics.NIST)
		case string(scan.FrameworkSOC2):
			topics = append(topics, r.topics.SOC2)
		case string(scan.FrameworkEUAIAct):
			topics = append(topics, r.topics.EUAI)
		case string(scan.FrameworkISO27001):
			topics = append(topics, r.topics.ISO27001)
		}
	}

	return topics
}
