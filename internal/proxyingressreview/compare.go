// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingressreview

import "kurdistan/internal/proxyingress"

type ProxyIngressParityReport struct {
	ComparedContracts      int      `json:"compared_contracts"`
	ComparedChecklistItems int      `json:"compared_checklist_items"`
	ComparedFailureModes   int      `json:"compared_failure_modes"`
	ContractMatches        int      `json:"contract_matches"`
	ChecklistMatches       int      `json:"checklist_matches"`
	FailureMatrixMatches   int      `json:"failure_matrix_matches"`
	UnexpectedDifferences  []string `json:"unexpected_differences,omitempty"`
	PayloadLogged          bool     `json:"payload_logged"`
	SecretLogged           bool     `json:"secret_logged"`
	Conclusion             string   `json:"conclusion"`
}

func CompareParity(interpreted, generated ProxyIngressDesignReview, interpretedContract, generatedContract proxyingress.ProxyIngressContract) ProxyIngressParityReport {
	report := ProxyIngressParityReport{ComparedContracts: 1, ComparedChecklistItems: len(interpreted.ChecklistItems), ComparedFailureModes: len(interpreted.FailureModes), Conclusion: "passed"}
	if proxyingress.HashValue(interpretedContract) == proxyingress.HashValue(generatedContract) {
		report.ContractMatches = 1
	} else {
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "contract")
	}
	if proxyingress.HashValue(interpreted.ChecklistItems) == proxyingress.HashValue(generated.ChecklistItems) {
		report.ChecklistMatches = report.ComparedChecklistItems
	} else {
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "checklist")
	}
	if proxyingress.HashValue(interpreted.FailureModes) == proxyingress.HashValue(generated.FailureModes) {
		report.FailureMatrixMatches = report.ComparedFailureModes
	} else {
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "failure_matrix")
	}
	report.PayloadLogged = interpreted.PayloadLogged || generated.PayloadLogged
	report.SecretLogged = interpreted.SecretLogged || generated.SecretLogged
	if len(report.UnexpectedDifferences) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}
