// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase16receipt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
)

const Schema = "phase16-production-plan-receipt-v1"

var (
	ErrReceipt = errors.New("phase16 receipt rejected")
	hex64RE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex40RE    = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type Receipt struct {
	Schema                   string `json:"schema"`
	SubjectSHA               string `json:"subjectSha"`
	TreeSHA                  string `json:"treeSha"`
	PlanSHA256               string `json:"planSha256"`
	PlanJSONSHA256           string `json:"planJsonSha256"`
	PolicySHA256             string `json:"policySha256"`
	PolicyResultSHA256       string `json:"policyResultSha256"`
	TerraformVariablesSHA256 string `json:"terraformVariablesSha256"`
	WorkflowPath             string `json:"workflowPath"`
	WorkflowSHA256           string `json:"workflowSha256"`
	AuthorizationSHA256      string `json:"authorizationSha256"`
	OPAName                  string `json:"opaName"`
	OPAVersion               string `json:"opaVersion"`
	RunID                    uint64 `json:"runId"`
	RunAttempt               uint64 `json:"runAttempt"`
	CreatedAt                int64  `json:"createdAt"`
	ExpiresAt                int64  `json:"expiresAt"`
	Result                   string `json:"result"`
}

type Inputs struct {
	SubjectSHA, TreeSHA                                    string
	PlanPath, PlanJSONPath, PolicyPath, PolicyResultPath   string
	TerraformVariablesPath, WorkflowPath, WorkflowFilePath string
	AuthorizationID, OPAVersion                            string
	RunID, RunAttempt                                      uint64
	CreatedAt, ExpiresAt                                   int64
}

func Create(input Inputs) (Receipt, error) {
	receipt := Receipt{
		Schema: Schema, SubjectSHA: input.SubjectSHA, TreeSHA: input.TreeSHA,
		WorkflowPath: input.WorkflowPath, AuthorizationSHA256: digestBytes([]byte(input.AuthorizationID)),
		OPAName: "open-policy-agent", OPAVersion: input.OPAVersion,
		RunID: input.RunID, RunAttempt: input.RunAttempt,
		CreatedAt: input.CreatedAt, ExpiresAt: input.ExpiresAt, Result: "PASS",
	}
	var err error
	for path, destination := range map[string]*string{
		input.PlanPath:               &receipt.PlanSHA256,
		input.PlanJSONPath:           &receipt.PlanJSONSHA256,
		input.PolicyPath:             &receipt.PolicySHA256,
		input.PolicyResultPath:       &receipt.PolicyResultSHA256,
		input.TerraformVariablesPath: &receipt.TerraformVariablesSHA256,
		input.WorkflowFilePath:       &receipt.WorkflowSHA256,
	} {
		*destination, err = digestFile(path)
		if err != nil {
			return Receipt{}, ErrReceipt
		}
	}
	policyResult, err := os.ReadFile(input.PolicyResultPath)
	if err != nil || string(bytes.TrimSpace(policyResult)) != "0" || validate(receipt) != nil {
		return Receipt{}, ErrReceipt
	}
	return receipt, nil
}

func Verify(raw []byte, input Inputs, now int64) (Receipt, error) {
	var receipt Receipt
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, ErrReceipt
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || !uniqueJSONKeys(raw) {
		return Receipt{}, ErrReceipt
	}
	if input.CreatedAt == 0 && input.ExpiresAt == 0 {
		input.CreatedAt = receipt.CreatedAt
		input.ExpiresAt = receipt.ExpiresAt
	}
	expected, err := Create(input)
	if err != nil || receipt != expected || now < receipt.CreatedAt || now >= receipt.ExpiresAt {
		return Receipt{}, ErrReceipt
	}
	return receipt, nil
}

func Marshal(receipt Receipt) ([]byte, error) {
	if err := validate(receipt); err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return nil, ErrReceipt
	}
	return append(raw, '\n'), nil
}

func Digest(raw []byte) string { return digestBytes(raw) }

func validate(receipt Receipt) error {
	if receipt.Schema != Schema || !hex40RE.MatchString(receipt.SubjectSHA) || !hex40RE.MatchString(receipt.TreeSHA) ||
		receipt.SubjectSHA == "0000000000000000000000000000000000000000" ||
		receipt.TreeSHA == "0000000000000000000000000000000000000000" ||
		receipt.WorkflowPath != ".github/workflows/phase16-production-plan.yml" ||
		receipt.AuthorizationSHA256 == digestBytes(nil) || receipt.OPAName != "open-policy-agent" ||
		receipt.OPAVersion == "" || receipt.RunID == 0 || receipt.RunAttempt == 0 ||
		receipt.CreatedAt <= 0 || receipt.ExpiresAt <= receipt.CreatedAt ||
		receipt.ExpiresAt-receipt.CreatedAt > 3600 || receipt.Result != "PASS" {
		return ErrReceipt
	}
	for _, digest := range []string{receipt.PlanSHA256, receipt.PlanJSONSHA256, receipt.PolicySHA256,
		receipt.PolicyResultSHA256, receipt.TerraformVariablesSHA256, receipt.WorkflowSHA256,
		receipt.AuthorizationSHA256} {
		if !hex64RE.MatchString(digest) {
			return ErrReceipt
		}
	}
	return nil
}

func digestFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return "", fmt.Errorf("%w: file", ErrReceipt)
	}
	return digestBytes(raw), nil
}

func digestBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func uniqueJSONKeys(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var stack []map[string]struct{}
	expectingKey := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return len(stack) == 0
		}
		if err != nil {
			return false
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				stack = append(stack, make(map[string]struct{}))
				expectingKey = true
			case '}':
				if len(stack) == 0 {
					return false
				}
				stack = stack[:len(stack)-1]
				expectingKey = len(stack) > 0
			}
		case string:
			if expectingKey && len(stack) > 0 {
				if _, duplicate := stack[len(stack)-1][value]; duplicate {
					return false
				}
				stack[len(stack)-1][value] = struct{}{}
				expectingKey = false
			} else if len(stack) > 0 {
				expectingKey = true
			}
		default:
			if len(stack) > 0 {
				expectingKey = true
			}
		}
	}
}
