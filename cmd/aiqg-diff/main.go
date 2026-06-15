// Command aiqg-diff scans a fixed, representative prompt corpus through the
// production Gatekeeper scanner (scan.NewScanner — the same registry
// tas-llm-router uses) and emits a deterministic, one-line-per-prompt JSON
// report of the findings each prompt produces (pattern_id + severity) plus the
// derived AIQG "assurance floor".
//
// Purpose: measure the downstream AIQG impact of matcher changes. Run it against
// a baseline checkout and against a candidate checkout, then diff the two
// outputs:
//
//	go run ./cmd/aiqg-diff > candidate.jsonl     # in the changed tree
//	go run ./cmd/aiqg-diff > baseline.jsonl      # in a clean baseline tree
//	diff baseline.jsonl candidate.jsonl
//
// Any differing line is a prompt whose production findings — and therefore its
// tag counts (tag_<pattern_id>), NIST characteristic (nist_<characteristic>),
// and Assurance score — would change. Identical output means zero downstream
// AIQG impact.
//
// The assurance floor mirrors the per-severity scoring documented in
// tas-llm-router/cmd/demo-traffic/catalog.go (the worst finding drives the
// Assurance dimension): critical=0, high=50, medium=80, low=95, and 100 when a
// prompt produces no findings. It is a faithful proxy for the dimension input,
// not the full clear.Compute aggregate.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/scan"
)

type findingRec struct {
	PatternID string `json:"pattern_id"`
	Severity  string `json:"severity"`
}

type report struct {
	ID             string       `json:"id"`
	Prompt         string       `json:"prompt"`
	Findings       []findingRec `json:"findings"`
	AssuranceFloor int          `json:"assurance_floor"`
}

// assurancePoints maps a finding severity to its Assurance contribution. The
// lowest value among a prompt's findings is the dimension input.
func assurancePoints(sev string) int {
	switch sev {
	case "critical":
		return 0
	case "high":
		return 50
	case "medium":
		return 80
	case "low":
		return 95
	default:
		return 100
	}
}

func main() {
	scanner := scan.NewScanner()
	ctx := context.Background()

	cases := corpus()
	sort.Slice(cases, func(i, j int) bool { return cases[i].id < cases[j].id })

	enc := json.NewEncoder(os.Stdout)
	for _, c := range cases {
		res, err := scanner.ScanString(ctx, c.text, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan error on %s: %v\n", c.id, err)
			os.Exit(1)
		}

		recs := make([]findingRec, 0, len(res.Findings))
		floor := 100
		for _, f := range res.Findings {
			sev := string(f.Severity)
			recs = append(recs, findingRec{PatternID: f.PatternID, Severity: sev})
			if p := assurancePoints(sev); p < floor {
				floor = p
			}
		}
		sort.Slice(recs, func(i, j int) bool {
			if recs[i].PatternID != recs[j].PatternID {
				return recs[i].PatternID < recs[j].PatternID
			}
			return recs[i].Severity < recs[j].Severity
		})

		if err := enc.Encode(report{ID: c.id, Prompt: c.text, Findings: recs, AssuranceFloor: floor}); err != nil {
			fmt.Fprintf(os.Stderr, "encode error on %s: %v\n", c.id, err)
			os.Exit(1)
		}
	}
}
