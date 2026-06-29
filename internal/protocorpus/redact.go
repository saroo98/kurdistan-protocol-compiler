// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package protocorpus

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
	scan(decoded, "", &findings)
	return RedactionReport{Passed: len(findings) == 0, Findings: findings}
}

func scan(value any, key string, findings *[]string) {
	switch v := value.(type) {
	case map[string]any:
		for k, child := range v {
			if k != "payload_logged" && k != "secret_logged" && unsafeText(k) {
				*findings = append(*findings, k)
			}
			scan(child, k, findings)
		}
	case []any:
		for _, child := range v {
			scan(child, key, findings)
		}
	case string:
		if key == "kind" && (v == string(FieldPayload) || v == string(FieldAuthTagLike)) {
			return
		}
		if unsafeText(v) {
			*findings = append(*findings, v)
		}
	}
}
