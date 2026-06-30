// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingress

type ProxyIngressFixtureSet struct {
	Version       string                     `json:"version"`
	Contract      ProxyIngressContract       `json:"contract"`
	Requests      []SyntheticProxyRequest    `json:"requests"`
	Targets       []TargetDescriptor         `json:"targets"`
	Mappings      []RuntimeStreamMappingPlan `json:"mappings"`
	Lifecycle     []IngressLifecycleEvent    `json:"lifecycle"`
	PayloadLogged bool                       `json:"payload_logged"`
	SecretLogged  bool                       `json:"secret_logged"`
}

func GoldenFixtureSet() (ProxyIngressFixtureSet, error) {
	contract := DefaultContract()
	requests := ValidRequests()
	mappings, err := BuildMappingPlans(requests, contract)
	if err != nil {
		return ProxyIngressFixtureSet{}, err
	}
	return ProxyIngressFixtureSet{
		Version:   string(Version),
		Contract:  contract,
		Requests:  requests,
		Targets:   ValidTargetDescriptors(),
		Mappings:  mappings,
		Lifecycle: LifecycleGolden(requests),
	}, nil
}

func ValidateFixtureSet(set ProxyIngressFixtureSet) error {
	if set.Version != string(Version) || set.PayloadLogged || set.SecretLogged {
		return ErrInvalidContract
	}
	if err := ValidateContract(set.Contract); err != nil {
		return err
	}
	if err := ValidateRequests(set.Requests, set.Contract); err != nil {
		return err
	}
	for _, target := range set.Targets {
		if err := ValidateTargetDescriptor(target, set.Contract.Limits); err != nil {
			return err
		}
	}
	if err := ScanForLeak(set); err != nil {
		return err
	}
	return nil
}
