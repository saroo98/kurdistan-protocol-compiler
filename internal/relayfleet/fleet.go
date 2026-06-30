// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayfleet

import (
	"fmt"
	"sort"

	"kurdistan/internal/hostdetect"
	"kurdistan/internal/wireeval"
)

type RelayFleet struct {
	Version       string           `json:"version"`
	FleetID       string           `json:"fleet_id"`
	Relays        []SyntheticRelay `json:"relays"`
	Policy        FleetPolicy      `json:"policy"`
	FleetHash     string           `json:"fleet_hash"`
	PayloadLogged bool             `json:"payload_logged"`
	SecretLogged  bool             `json:"secret_logged"`
}

func BuildFleet(dataset wireeval.Dataset, hostSummary hostdetect.HostDetectSummary, opts Options) (RelayFleet, error) {
	opts = NormalizeOptions(opts)
	if err := ValidatePolicy(opts.Policy); err != nil {
		return RelayFleet{}, err
	}
	if len(dataset.Records) == 0 {
		return RelayFleet{}, ErrInvalidFleet
	}
	records := append([]wireeval.WireEvalRecord(nil), dataset.Records...)
	sort.Slice(records, func(i, j int) bool { return records[i].RecordID < records[j].RecordID })
	relays := make([]SyntheticRelay, 0, opts.RelayCount+3)
	for i := 0; i < opts.RelayCount; i++ {
		record := records[i%len(records)]
		class := RelayClassGenerated
		if record.Label == wireeval.LabelCorpusBaseline {
			class = RelayClassBaseline
		}
		seed := record.ProfileSeed
		if i < len(opts.ProfileSeeds) {
			seed = opts.ProfileSeeds[i]
		}
		state := RelayActive
		switch i % 6 {
		case 1:
			state = RelayCooling
		case 2:
			state = RelayRotating
		case 3:
			state = RelayMigrating
		case 4:
			state = RelayQuarantined
		case 5:
			state = RelayActive
		}
		risk := riskFromHostSummary(hostSummary, i, record.Label)
		relays = append(relays, SyntheticRelay{
			RelayID:          RelayID(fmt.Sprintf("relay_%04d", i+1)),
			RelayClass:       class,
			State:            state,
			ProfileID:        record.ProfileID,
			ProfileSeed:      seed,
			WirePolicyHash:   safeHash(record.FeatureHash + record.ByteShapeHash)[:16],
			SelectedFamily:   safeFamily(record.SelectedFamily, i),
			SyntheticHostID:  fmt.Sprintf("host_%04d", (i%max(1, hostSummary.ObservationSet.HostCount))+1),
			CreatedAtTick:    i,
			ActivatedAtTick:  i + 1,
			ObservationCount: 2 + (i % opts.Policy.MaxObservationsPerRelay),
			MigrationCount:   i % 3,
			RotationCount:    i % 4,
			BurnRiskBucket:   risk,
		})
	}
	if opts.IncludeControls {
		relays = append(relays, controlRelays(opts.RelayCount+1)...)
	}
	fleet := RelayFleet{
		Version: string(Version),
		FleetID: "fleet_" + safeHash(fmt.Sprintf("%s:%d:%d", opts.Policy.Name, opts.RelayCount, len(records)))[:12],
		Relays:  relays,
		Policy:  opts.Policy,
	}
	fleet.FleetHash = FleetHash(fleet)
	return fleet, ValidateFleet(fleet)
}

func controlRelays(start int) []SyntheticRelay {
	return []SyntheticRelay{
		{RelayID: RelayID(fmt.Sprintf("relay_%04d", start)), RelayClass: RelayClassControl, State: RelayActive, ProfileID: "control_fixed_profile", ProfileSeed: 9001, WirePolicyHash: "controlfixedhash", SelectedFamily: "control_fixed", SyntheticHostID: "host_control_0001", CreatedAtTick: 0, ActivatedAtTick: 1, ObservationCount: 18, BurnRiskBucket: RiskCritical},
		{RelayID: RelayID(fmt.Sprintf("relay_%04d", start+1)), RelayClass: RelayClassControl, State: RelayBurned, ProfileID: "control_burned_profile", ProfileSeed: 9001, WirePolicyHash: "controlfixedhash", SelectedFamily: "control_fixed", SyntheticHostID: "host_control_0002", CreatedAtTick: 0, ActivatedAtTick: 1, ObservationCount: 21, BurnRiskBucket: RiskCritical},
		{RelayID: RelayID(fmt.Sprintf("relay_%04d", start+2)), RelayClass: RelayClassControl, State: RelayActive, ProfileID: "control_padding_only", ProfileSeed: 9002, WirePolicyHash: "controlpaddinghash", SelectedFamily: "control_padding", SyntheticHostID: "host_control_0003", CreatedAtTick: 0, ActivatedAtTick: 1, ObservationCount: 15, BurnRiskBucket: RiskHigh},
	}
}

func riskFromHostSummary(summary hostdetect.HostDetectSummary, index int, label wireeval.WireEvalLabel) string {
	if label == wireeval.LabelControlCollapsed || label == wireeval.LabelControlFixedShape {
		return RiskCritical
	}
	if len(summary.Aggregates) > 0 {
		bucket := summary.Aggregates[index%len(summary.Aggregates)].RiskBucket
		if bucket != "" {
			return bucket
		}
	}
	switch index % 4 {
	case 0:
		return RiskLow
	case 1:
		return RiskMedium
	case 2:
		return RiskHigh
	default:
		return RiskLow
	}
}

func safeFamily(value string, index int) string {
	if value == "" {
		return fmt.Sprintf("family_%02d", index%5)
	}
	return value
}

func activeRelayCount(relays []SyntheticRelay) int {
	count := 0
	for _, relay := range relays {
		if relay.State == RelayActive {
			count++
		}
	}
	return count
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
