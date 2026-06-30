// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

import (
	"fmt"

	"kurdistan/internal/proxyingress"
)

func ValidateConfig(cfg LocalProxyIngressConfig) error {
	if cfg.Version != string(Version) || cfg.ContractID == "" || cfg.MaxConcurrentRequests <= 0 || cfg.MaxQueuedEvents <= 0 || cfg.MaxEventsPerRequest <= 0 {
		return ErrInvalidConfig
	}
	if cfg.MaxConcurrentRequests > 64 || cfg.MaxQueuedEvents > 512 || cfg.MaxEventsPerRequest > 128 || cfg.MaxSyntheticBytesBucket == "" || !cfg.TraceSafeSummaries {
		return fmt.Errorf("%w: unsafe bounds", ErrInvalidConfig)
	}
	return nil
}

func ValidateEvent(event SyntheticIngressEvent, contract proxyingress.ProxyIngressContract) error {
	if event.EventID == "" || event.RequestID == "" || !validEventKind(event.Kind) {
		return ErrInvalidEvent
	}
	if event.PayloadLogged || event.SecretLogged {
		return proxyingress.ErrUnsafeMetadata
	}
	if event.ByteCountBucket == "" || event.ChunkClass == "" || event.FlowClass == "" {
		return ErrInvalidEvent
	}
	if err := proxyingress.ValidateTargetDescriptor(event.Target, contract.Limits); err != nil {
		return err
	}
	if err := proxyingress.ScanForLeak(event); err != nil {
		return err
	}
	return nil
}

func ValidateSummary(summary LocalProxyIngressSummary) error {
	if summary.Version != string(Version) || summary.Scenario == "" || summary.ContractID == "" || summary.RequestCount < 0 {
		return ErrInvalidSummary
	}
	if summary.PayloadLogged || summary.SecretLogged {
		return proxyingress.ErrUnsafeMetadata
	}
	if summary.SummaryHash != "" && summary.SummaryHash != HashValue(summaryHashInput(summary)) {
		return fmt.Errorf("%w: hash mismatch", ErrInvalidSummary)
	}
	return nil
}
