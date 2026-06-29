// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wirefeatures

import "encoding/json"

type RedactionReport struct {
	Passed   bool     `json:"passed"`
	Findings []string `json:"findings,omitempty"`
}

func ValidateRedaction(value any) RedactionReport {
	raw, err := json.Marshal(value)
	if err != nil {
		return RedactionReport{Passed: false, Findings: []string{"marshal_failed"}}
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return RedactionReport{Passed: false, Findings: []string{"invalid_json"}}
	}
	findings := []string{}
	scan(decoded, &findings)
	return RedactionReport{Passed: len(findings) == 0, Findings: findings}
}

func scan(value any, findings *[]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if unsafeText(key) {
				*findings = append(*findings, key)
			}
			if (key == "payload_logged" || key == "secret_logged") && child == true {
				*findings = append(*findings, key+"_true")
			}
			scan(child, findings)
		}
	case []any:
		for _, child := range v {
			scan(child, findings)
		}
	case string:
		if unsafeText(v) {
			*findings = append(*findings, v)
		}
	}
}
