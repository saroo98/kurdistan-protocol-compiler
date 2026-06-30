// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

import (
	"fmt"
	"sort"

	"kurdistan/internal/wireeval"
)

type BuildOptions struct {
	AssignmentMode string
	Window         ObservationWindow
	HostCount      int
}

func DefaultBuildOptions() BuildOptions {
	return BuildOptions{AssignmentMode: AssignControlCollapsed, Window: WindowMedium, HostCount: 6}
}

func BuildObservations(dataset wireeval.Dataset, opts BuildOptions) (HostObservationSet, error) {
	if opts.AssignmentMode == "" {
		opts.AssignmentMode = AssignManyHostsUniform
	}
	if opts.Window == "" {
		opts.Window = WindowMedium
	}
	if opts.HostCount <= 0 {
		opts.HostCount = 6
	}
	if err := ValidateAssignmentMode(opts.AssignmentMode); err != nil {
		return HostObservationSet{}, err
	}
	if err := ValidateWindow(opts.Window); err != nil {
		return HostObservationSet{}, err
	}
	records := append([]wireeval.WireEvalRecord(nil), dataset.Records...)
	sort.Slice(records, func(i, j int) bool { return records[i].RecordID < records[j].RecordID })
	observations := make([]HostObservation, 0, len(records))
	for i, record := range records {
		host := AssignHost(record, i, opts)
		observation := HostObservation{
			Version:          string(Version),
			ObservationID:    ObservationID(record.RecordID, host, i),
			SyntheticHostID:  host,
			HostClass:        HostClassForLabel(record.Label),
			LogicalTime:      LogicalTime(i, opts.Window),
			DatasetRecordID:  record.RecordID,
			ProfileID:        record.ProfileID,
			ProfileSeed:      record.ProfileSeed,
			Scenario:         record.Scenario,
			SelectedFamily:   record.SelectedFamily,
			FeatureHash:      record.FeatureHash,
			FirstNShapeHash:  record.FirstNShapeHash,
			ByteShapeHash:    record.ByteShapeHash,
			MetadataExposure: record.MetadataExposure,
			FragmentRhythm:   record.FragmentRhythm,
			ControlRichness:  record.ControlRichness,
			Split:            string(record.Split),
			PayloadLogged:    record.PayloadLogged,
			SecretLogged:     record.SecretLogged,
		}
		observations = append(observations, observation)
	}
	sortObservations(observations)
	set := HostObservationSet{
		Version:          string(Version),
		GeneratedAt:      FixedGeneratedAt,
		AssignmentMode:   opts.AssignmentMode,
		Window:           opts.Window,
		HostCount:        countHosts(observations),
		ObservationCount: len(observations),
		DatasetHash:      ObservationSetHash(observations),
		Observations:     observations,
	}
	for _, observation := range observations {
		set.PayloadLogged = set.PayloadLogged || observation.PayloadLogged
		set.SecretLogged = set.SecretLogged || observation.SecretLogged
	}
	if err := ValidateObservationSet(set); err != nil {
		return HostObservationSet{}, err
	}
	return set, nil
}

func AssignHost(record wireeval.WireEvalRecord, index int, opts BuildOptions) SyntheticHostID {
	hostCount := opts.HostCount
	if hostCount <= 0 {
		hostCount = 6
	}
	switch opts.AssignmentMode {
	case AssignSingleLongLived:
		return "host_0001"
	case AssignManyHostsUniform:
		return hostID(index % hostCount)
	case AssignProfilePinned:
		return hostID(stableIndex(fmt.Sprint(record.ProfileSeed), hostCount))
	case AssignFamilyPinned:
		return hostID(stableIndex(record.SelectedFamily, hostCount))
	case AssignScenarioPinned:
		return hostID(stableIndex(record.Scenario, hostCount))
	case AssignRotatingProfile:
		return hostID((stableIndex(fmt.Sprint(record.ProfileSeed), hostCount) + index/4) % hostCount)
	case AssignMixedRotation:
		return hostID((stableIndex(record.SelectedFamily+"/"+record.Scenario, hostCount) + index/7) % hostCount)
	case AssignControlCollapsed:
		switch record.Label {
		case wireeval.LabelControlCollapsed, wireeval.LabelControlFixedShape:
			return "host_9000"
		case wireeval.LabelControlPaddingOnly:
			return "host_9001"
		case wireeval.LabelControlNoise:
			return "host_9002"
		case wireeval.LabelCorpusBaseline:
			return "host_8000"
		}
		return hostID(index % hostCount)
	default:
		return hostID(index % hostCount)
	}
}

func HostClassForLabel(label wireeval.WireEvalLabel) HostClass {
	switch label {
	case wireeval.LabelGeneratedKurdistan:
		return HostClassGeneratedRelay
	case wireeval.LabelCorpusBaseline:
		return HostClassCorpusBaseline
	case wireeval.LabelControlPaddingOnly:
		return HostClassControlPadding
	case wireeval.LabelControlNoise:
		return HostClassControlNoise
	default:
		return HostClassControlFixed
	}
}

func ValidateAssignmentMode(mode string) error {
	for _, allowed := range FullAssignmentModes() {
		if mode == allowed {
			return nil
		}
	}
	return ErrInvalidAssignment
}

func hostID(index int) SyntheticHostID {
	return SyntheticHostID(fmt.Sprintf("host_%04d", index+1))
}

func stableIndex(value string, modulo int) int {
	if modulo <= 0 {
		return 0
	}
	sum := 0
	for _, r := range value {
		sum += int(r)
	}
	return sum % modulo
}

func sortObservations(observations []HostObservation) {
	sort.Slice(observations, func(i, j int) bool {
		a, b := observations[i], observations[j]
		if a.LogicalTime != b.LogicalTime {
			return a.LogicalTime < b.LogicalTime
		}
		return a.ObservationID < b.ObservationID
	})
}

func countHosts(observations []HostObservation) int {
	seen := map[SyntheticHostID]bool{}
	for _, observation := range observations {
		seen[observation.SyntheticHostID] = true
	}
	return len(seen)
}
