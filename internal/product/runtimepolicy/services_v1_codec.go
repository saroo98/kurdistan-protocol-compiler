// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimepolicy

import "github.com/fxamacker/cbor/v2"

func servicesMap(s *ServicesV1) map[uint64]any {
	proxy, probes, update := make([]any, 0, 1), make([]any, 0, 1), make([]any, 0, 1)
	if p := s.Proxy; p != nil {
		ports := make([]any, len(p.DestinationPorts))
		for i, v := range p.DestinationPorts {
			ports[i] = map[uint64]any{1: v.First, 2: v.Last}
		}
		proxy = append(proxy, map[uint64]any{1: serviceValues(p.AddressKinds), 2: prefixMaps(p.DestinationCIDRs), 3: ports, 4: p.MaxConcurrentStreams, 5: p.MaxBufferBytes, 6: p.ConnectTimeoutMillis, 7: p.IdleTimeoutSeconds, 8: p.MaxQueuedBytesPerDirection})
	}
	if p := s.Probes; p != nil {
		targets := make([]any, len(p.Targets))
		for i, v := range p.Targets {
			targets[i] = map[uint64]any{1: v.ID, 2: v.Address, 3: v.Port, 4: serviceValues(v.Methods), 5: serviceValues(v.Modes), 6: v.TimeoutMillis}
		}
		probes = append(probes, map[uint64]any{1: targets, 2: p.MaxConcurrentOperations, 3: p.MaxSamplesPerOperation, 4: p.MinAttemptIntervalMillis, 5: p.MaxAttemptsPerMinute, 6: p.MaxOperationMillis})
	}
	if u := s.Update; u != nil {
		update = append(update, map[uint64]any{1: u.URL, 2: u.ProfileID, 3: u.MaxArtifactBytes, 4: u.TimeoutMillis, 5: u.MinCheckIntervalSeconds})
	}
	return map[uint64]any{1: s.Version, 2: proxy, 3: probes, 4: update}
}

// uint8 slices otherwise marshal as byte strings, not integer arrays.
func serviceValues(values []uint8) []uint64 {
	out := make([]uint64, len(values))
	for i, v := range values {
		out[i] = uint64(v)
	}
	return out
}

func serviceArray(raw []byte, min, max int) ([]cbor.RawMessage, error) {
	var result []cbor.RawMessage
	if len(raw) == 0 || raw[0]>>5 != 4 || decode(raw, &result) != nil || len(result) < min || len(result) > max {
		return nil, fail(ErrorSchema)
	}
	return result, nil
}

func serviceMap(raw []byte, count int) (map[uint64]cbor.RawMessage, error) {
	if len(raw) == 0 || raw[0]>>5 != 5 {
		return nil, fail(ErrorSchema)
	}
	fields, err := rawMap(raw, count)
	if err != nil {
		return nil, err
	}
	for _, value := range fields {
		if len(value) == 0 || value[0] == 0xf6 || value[0] == 0xf7 {
			return nil, fail(ErrorSchema)
		}
	}
	return fields, nil
}

func serviceField(raw []byte, destination any) error {
	var major byte
	switch destination.(type) {
	case *uint8, *uint16, *uint32, *uint64:
		major = 0
	case *[]byte:
		major = 2
	case *string:
		major = 3
	default:
		return fail(ErrorSchema)
	}
	if len(raw) == 0 || raw[0]>>5 != major || decode(raw, destination) != nil {
		return fail(ErrorSchema)
	}
	return nil
}

func decodeServiceValues(raw []byte, max int) ([]uint8, error) {
	values, err := serviceArray(raw, 1, max)
	if err != nil {
		return nil, err
	}
	result := make([]uint8, len(values))
	for i, v := range values {
		if err := serviceField(v, &result[i]); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func decodeServices(raw []byte) (*ServicesV1, error) {
	if len(raw) > MaxServicesEncodedBytes {
		return nil, fail(ErrorSize)
	}
	fields, err := serviceMap(raw, 4)
	if err != nil {
		return nil, err
	}
	s := new(ServicesV1)
	if err := serviceField(fields[1], &s.Version); err != nil {
		return nil, err
	}
	for label := uint64(2); label <= 4; label++ {
		values, err := serviceArray(fields[label], 0, 1)
		if err != nil {
			return nil, err
		}
		if len(values) == 0 {
			continue
		}
		switch label {
		case 2:
			s.Proxy, err = decodeProxy(values[0])
		case 3:
			s.Probes, err = decodeProbes(values[0])
		case 4:
			s.Update, err = decodeUpdate(values[0])
		}
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

func decodeProxy(raw []byte) (*ProxyV1, error) {
	fields, err := serviceMap(raw, 8)
	if err != nil {
		return nil, err
	}
	p := new(ProxyV1)
	if p.AddressKinds, err = decodeServiceValues(fields[1], 3); err != nil {
		return nil, err
	}
	cidrs, err := serviceArray(fields[2], 1, 64)
	if err != nil {
		return nil, err
	}
	p.DestinationCIDRs = make([]PrefixV2, len(cidrs))
	for i, raw := range cidrs {
		m, err := serviceMap(raw, 2)
		if err != nil {
			return nil, err
		}
		if serviceField(m[1], &p.DestinationCIDRs[i].Address) != nil || serviceField(m[2], &p.DestinationCIDRs[i].PrefixLen) != nil {
			return nil, fail(ErrorSchema)
		}
	}
	ports, err := serviceArray(fields[3], 1, 16)
	if err != nil {
		return nil, err
	}
	p.DestinationPorts = make([]PortRangeV1, len(ports))
	for i, raw := range ports {
		m, err := serviceMap(raw, 2)
		if err != nil {
			return nil, err
		}
		if serviceField(m[1], &p.DestinationPorts[i].First) != nil || serviceField(m[2], &p.DestinationPorts[i].Last) != nil {
			return nil, fail(ErrorSchema)
		}
	}
	destinations := []any{&p.MaxConcurrentStreams, &p.MaxBufferBytes, &p.ConnectTimeoutMillis, &p.IdleTimeoutSeconds, &p.MaxQueuedBytesPerDirection}
	for i, d := range destinations {
		if err := serviceField(fields[uint64(i+4)], d); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func decodeProbes(raw []byte) (*ProbesV1, error) {
	fields, err := serviceMap(raw, 6)
	if err != nil {
		return nil, err
	}
	p := new(ProbesV1)
	targets, err := serviceArray(fields[1], 1, 16)
	if err != nil {
		return nil, err
	}
	p.Targets = make([]ProbeTargetV1, len(targets))
	for i, raw := range targets {
		m, err := serviceMap(raw, 6)
		if err != nil {
			return nil, err
		}
		t := &p.Targets[i]
		if serviceField(m[1], &t.ID) != nil || serviceField(m[2], &t.Address) != nil || serviceField(m[3], &t.Port) != nil || serviceField(m[6], &t.TimeoutMillis) != nil {
			return nil, fail(ErrorSchema)
		}
		if t.Methods, err = decodeServiceValues(m[4], 1); err != nil {
			return nil, err
		}
		if t.Modes, err = decodeServiceValues(m[5], 2); err != nil {
			return nil, err
		}
	}
	destinations := []any{&p.MaxConcurrentOperations, &p.MaxSamplesPerOperation, &p.MinAttemptIntervalMillis, &p.MaxAttemptsPerMinute, &p.MaxOperationMillis}
	for i, d := range destinations {
		if err := serviceField(fields[uint64(i+2)], d); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func decodeUpdate(raw []byte) (*UpdateV1, error) {
	fields, err := serviceMap(raw, 5)
	if err != nil {
		return nil, err
	}
	u := new(UpdateV1)
	destinations := []any{&u.URL, &u.ProfileID, &u.MaxArtifactBytes, &u.TimeoutMillis, &u.MinCheckIntervalSeconds}
	for i, d := range destinations {
		if err := serviceField(fields[uint64(i+1)], d); err != nil {
			return nil, err
		}
	}
	return u, nil
}
