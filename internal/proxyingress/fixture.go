// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingress

import (
	"context"
	"encoding/json"
	"os"
)

type ProxyIngressComparisonReport struct {
	Version               string   `json:"version"`
	OldContractID         string   `json:"old_contract_id"`
	NewContractID         string   `json:"new_contract_id"`
	ContractMatches       bool     `json:"contract_matches"`
	SupportedKindsMatch   bool     `json:"supported_kinds_match"`
	SupportedTargetsMatch bool     `json:"supported_targets_match"`
	UnexpectedDrift       []string `json:"unexpected_drift,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

func LoadContract(path string) (ProxyIngressContract, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ProxyIngressContract{}, err
	}
	var contract ProxyIngressContract
	if err := json.Unmarshal(raw, &contract); err != nil {
		return ProxyIngressContract{}, err
	}
	return contract, ValidateContract(contract)
}

func WriteContract(path string, contract ProxyIngressContract, force bool) error {
	if err := ValidateContract(contract); err != nil {
		return err
	}
	return WriteJSON(path, contract, force)
}

func CompareContractsOnly(oldContract, newContract ProxyIngressContract) ProxyIngressComparisonReport {
	report := ProxyIngressComparisonReport{Version: string(Version), OldContractID: oldContract.ContractID, NewContractID: newContract.ContractID, Conclusion: "passed"}
	report.ContractMatches = HashValue(oldContract) == HashValue(newContract)
	report.SupportedKindsMatch = HashValue(oldContract.SupportedKinds) == HashValue(newContract.SupportedKinds)
	report.SupportedTargetsMatch = HashValue(oldContract.SupportedTargetKinds) == HashValue(newContract.SupportedTargetKinds)
	report.PayloadLogged = oldContract.PayloadLogged || newContract.PayloadLogged
	report.SecretLogged = oldContract.SecretLogged || newContract.SecretLogged
	if !report.ContractMatches {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "contract")
	}
	if !report.SupportedKindsMatch {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "supported_kinds")
	}
	if !report.SupportedTargetsMatch {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "supported_target_kinds")
	}
	if len(report.UnexpectedDrift) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}

func VerifyContract(ctx context.Context, path string) (ProxyIngressComparisonReport, error) {
	_ = ctx
	oldContract, err := LoadContract(path)
	if err != nil {
		return ProxyIngressComparisonReport{Version: string(Version), Conclusion: "failed"}, err
	}
	report := CompareContractsOnly(oldContract, DefaultContract())
	if report.Conclusion != "passed" {
		return report, ErrInvalidComparison
	}
	return report, nil
}
