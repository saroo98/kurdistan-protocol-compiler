// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

import (
	"context"
	"encoding/json"
	"os"

	"kurdistan/internal/localproxyingress"
)

type AdversarialFixtureSet struct {
	Version          string                                   `json:"version"`
	FixtureSetID     string                                   `json:"fixture_set_id"`
	Corpus           AdversarialIngressCorpus                 `json:"corpus"`
	DescriptorAbuse  DescriptorAbuseReport                    `json:"descriptor_abuse"`
	Lifecycle        LifecycleHardeningReport                 `json:"lifecycle"`
	Pressure         PressureHardeningReport                  `json:"pressure"`
	ResetError       ResetErrorIsolationReport                `json:"reset_error"`
	MappingCollapse  IngressMappingCollapseReport             `json:"mapping_collapse"`
	CollapsedControl IngressMappingCollapseReport             `json:"collapsed_control"`
	Parity           LocalProxyIngressAdversarialParityReport `json:"parity"`
	Readiness        ProxyIngressM27ReadinessReport           `json:"readiness"`
	FixtureSetHash   string                                   `json:"fixture_set_hash"`
	PayloadLogged    bool                                     `json:"payload_logged"`
	SecretLogged     bool                                     `json:"secret_logged"`
}

type AdversarialFixtureComparison struct {
	Version         string   `json:"version"`
	OldHash         string   `json:"old_hash"`
	NewHash         string   `json:"new_hash"`
	UnexpectedDrift []string `json:"unexpected_drift,omitempty"`
	Conclusion      string   `json:"conclusion"`
}

func GenerateAdversarialFixtureSet(ctx context.Context) (AdversarialFixtureSet, error) {
	_ = ctx
	corpus, err := BuildAdversarialCorpus()
	if err != nil {
		return AdversarialFixtureSet{}, err
	}
	descriptor := RunDescriptorAbuseHardening()
	lifecycle := RunLifecycleHardening()
	pressure := RunPressureHardening()
	resetError := RunResetErrorIsolation()
	localSet, err := localproxyingress.GenerateFixtureSet(context.Background(), localproxyingress.FullScenarios())
	if err != nil {
		return AdversarialFixtureSet{}, err
	}
	collapse := RunMappingCollapseHardening(localSet)
	control := RunCollapsedMappingControl()
	parity := CompareGeneratedInterpreted(corpus, descriptor, lifecycle, pressure, resetError, collapse)
	readiness := BuildM27ReadinessReport(descriptor, lifecycle, pressure, resetError, collapse, parity)
	set := AdversarialFixtureSet{
		Version:          Version,
		FixtureSetID:     "localproxyingressadv_fixture_v1",
		Corpus:           corpus,
		DescriptorAbuse:  descriptor,
		Lifecycle:        lifecycle,
		Pressure:         pressure,
		ResetError:       resetError,
		MappingCollapse:  collapse,
		CollapsedControl: control,
		Parity:           parity,
		Readiness:        readiness,
	}
	set.PayloadLogged = corpus.PayloadLogged || descriptor.PayloadLogged || lifecycle.PayloadLogged || pressure.PayloadLogged || resetError.PayloadLogged || collapse.PayloadLogged || parity.PayloadLogged || readiness.PayloadLogged
	set.SecretLogged = corpus.SecretLogged || descriptor.SecretLogged || lifecycle.SecretLogged || pressure.SecretLogged || resetError.SecretLogged || collapse.SecretLogged || parity.SecretLogged || readiness.SecretLogged
	set.FixtureSetHash = HashValue(fixtureSetHashInput(set))
	return set, ValidateAdversarialFixtureSet(set)
}

func ValidateAdversarialFixtureSet(set AdversarialFixtureSet) error {
	if set.Version != Version || set.FixtureSetID == "" || set.PayloadLogged || set.SecretLogged {
		return ErrInvalidReport
	}
	if err := ValidateCorpus(set.Corpus); err != nil {
		return err
	}
	if err := ValidateDescriptorAbuseReport(set.DescriptorAbuse); err != nil {
		return err
	}
	if err := ValidateLifecycleHardeningReport(set.Lifecycle); err != nil {
		return err
	}
	if err := ValidatePressureHardeningReport(set.Pressure); err != nil {
		return err
	}
	if err := ValidateResetErrorIsolationReport(set.ResetError); err != nil {
		return err
	}
	if err := ValidateMappingCollapseReport(set.MappingCollapse, true); err != nil {
		return err
	}
	if err := ValidateMappingCollapseReport(set.CollapsedControl, false); err != nil {
		return err
	}
	if err := ValidateParityReport(set.Parity); err != nil {
		return err
	}
	if err := ValidateReadinessReport(set.Readiness); err != nil {
		return err
	}
	if set.FixtureSetHash != "" && set.FixtureSetHash != HashValue(fixtureSetHashInput(set)) {
		return ErrInvalidReport
	}
	return scanSafeFixture(set)
}

func LoadAdversarialFixtureSet(path string) (AdversarialFixtureSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return AdversarialFixtureSet{}, err
	}
	var set AdversarialFixtureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return AdversarialFixtureSet{}, err
	}
	return set, ValidateAdversarialFixtureSet(set)
}

func CompareAdversarialFixtureSets(oldSet, newSet AdversarialFixtureSet) AdversarialFixtureComparison {
	report := AdversarialFixtureComparison{Version: Version, OldHash: oldSet.FixtureSetHash, NewHash: newSet.FixtureSetHash, Conclusion: "passed"}
	if oldSet.FixtureSetHash != newSet.FixtureSetHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "fixture_set_hash")
		report.Conclusion = "failed"
	}
	if oldSet.Corpus.CorpusHash != newSet.Corpus.CorpusHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "corpus_hash")
		report.Conclusion = "failed"
	}
	return report
}

func fixtureSetHashInput(set AdversarialFixtureSet) AdversarialFixtureSet {
	set.FixtureSetHash = ""
	return set
}
