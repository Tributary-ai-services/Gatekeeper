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
//   - Findings with HIPAA framework also go to topics.HIPAA
//   - Findings with PCI_DSS framework also go to topics.PCI
func (r *TopicRouter) Route(finding Finding) []string {
	topics := []string{r.topics.Findings}

	// Critical severity findings also go to the critical topic
	if finding.Severity == scan.SeverityCritical {
		topics = append(topics, r.topics.Critical)
	}

	// Check frameworks for HIPAA and PCI_DSS
	for _, fw := range finding.Frameworks {
		switch fw {
		case string(scan.FrameworkHIPAA):
			topics = append(topics, r.topics.HIPAA)
		case string(scan.FrameworkPCIDSS):
			topics = append(topics, r.topics.PCI)
		}
	}

	return topics
}
