// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimepolicy

import (
	"github.com/fxamacker/cbor/v2"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/protocol/liveprogram"
)

// PreflightRuntimeResourcesV1 checks only typed shape and source resource caps.
// It does not authenticate policy, parse X.509, consult time, or verify a digest.
func PreflightRuntimeResourcesV1(encoded []byte) error {
	if len(encoded) == 0 || len(encoded) > MaxEncodedBytes {
		return fail(ErrorSize)
	}
	var fields map[uint64]cbor.RawMessage
	if decode(encoded, &fields) != nil || len(fields) < 25 || len(fields) > 26 {
		return fail(ErrorSchema)
	}
	var version uint64
	if serviceField(fields[1], &version) != nil || version != SchemaVersionV2 && version != SchemaVersionV3 {
		return fail(ErrorSchema)
	}
	want := 25
	if version == SchemaVersionV3 {
		want = 26
	}
	if len(fields) != want {
		return fail(ErrorSchema)
	}
	for i := uint64(1); i <= uint64(want); i++ {
		if _, ok := fields[i]; !ok {
			return fail(ErrorSchema)
		}
	}
	var p PolicyV2
	defer func() { clear(p.LiveProgram); clear(p.TLSLeafDER) }()
	decodeField := func(raw []byte, destination any) error {
		// The existing canonical encoder represents absent optional family
		// addresses as null. This scalar is not an array-to-bstr conversion.
		switch destination {
		case &p.ClientIPv4, &p.DNSIPv4, &p.ClientIPv6, &p.DNSIPv6:
			if len(raw) == 1 && raw[0] == 0xf6 {
				return decode(raw, destination)
			}
		}
		return decodeResourceFieldV1(raw, destination)
	}
	if err := decodePolicyFields(fields, &p, decodeField); err != nil {
		return err
	}
	if len(p.LiveProgram) == 0 || len(p.LiveProgram) > liveprogram.MaxEncodedBytes || len(p.TLSLeafDER) == 0 || len(p.TLSLeafDER) > 4096 || len(p.TLSServerName) == 0 || len(p.TLSServerName) > 253 || len(p.ClientAuthKeyID) > 32 || len(p.RelayAuthKeyID) > 32 {
		return fail(ErrorSize)
	}
	if len(p.AllowedIPModes) == 0 || len(p.AllowedIPModes) > 3 || len(p.AllowedProtocols) < 2 || len(p.AllowedProtocols) > 4 || len(p.DNSServers) > 2 || len(p.Fallback.EndpointIndexes) == 0 || len(p.Fallback.EndpointIndexes) > len(p.Endpoints) {
		return fail(ErrorSize)
	}
	for _, address := range [][]byte{p.ClientIPv4, p.DNSIPv4} {
		if len(address) != 0 && len(address) != 4 {
			return fail(ErrorSize)
		}
	}
	for _, address := range [][]byte{p.ClientIPv6, p.DNSIPv6} {
		if len(address) != 0 && len(address) != 16 {
			return fail(ErrorSize)
		}
	}
	for _, e := range p.Endpoints {
		if len(e.Address) != 4 && len(e.Address) != 16 {
			return fail(ErrorSize)
		}
	}
	for _, r := range p.Routes {
		if len(r.Address) != 4 && len(r.Address) != 16 {
			return fail(ErrorSize)
		}
	}
	for _, address := range p.DNSServers {
		if len(address) != 4 && len(address) != 16 {
			return fail(ErrorSize)
		}
	}
	if version == SchemaVersionV3 {
		var err error
		p.Services, err = decodeServices(fields[26])
		if err != nil {
			return err
		}
		if err := preflightServiceLeavesV1(p.Services); err != nil {
			return err
		}
	}
	return liveprogram.PreflightResourcesV1(p.LiveProgram)
}

// All resource-mode field decoding shares the legacy extraction body. The
// original direct types are checked before typed decoding can coerce them.
func decodeResourceFieldV1(raw []byte, destination any) error {
	if len(raw) == 0 {
		return fail(ErrorSchema)
	}
	var major byte
	switch destination.(type) {
	case *uint8, *uint16, *uint32, *uint64:
		major = 0
	case *[]byte:
		major = 2
	case *string:
		major = 3
	case *[]cbor.RawMessage:
		major = 4
	case *[][]byte, *[]string:
		values, err := serviceArray(raw, 0, 64)
		if err != nil {
			return err
		}
		defer func() {
			for _, value := range values {
				clear(value)
			}
		}()
		leafMajor := byte(3)
		if _, bytes := destination.(*[][]byte); bytes {
			leafMajor = 2
		}
		for _, value := range values {
			if len(value) == 0 || value[0]>>5 != leafMajor {
				return fail(ErrorSchema)
			}
		}
		major = 4
	default:
		return fail(ErrorSchema)
	}
	if raw[0]>>5 != major {
		return fail(ErrorSchema)
	}
	return decode(raw, destination)
}

func preflightServiceLeavesV1(s *ServicesV1) error {
	if p := s.Proxy; p != nil {
		for _, r := range p.DestinationCIDRs {
			if len(r.Address) != 4 && len(r.Address) != 16 {
				return fail(ErrorSize)
			}
		}
	}
	if p := s.Probes; p != nil {
		for _, target := range p.Targets {
			if len(target.Address) != 4 && len(target.Address) != 16 {
				return fail(ErrorSize)
			}
		}
	}
	if u := s.Update; u != nil {
		if len(u.URL) == 0 || len(u.URL) > 2048 || len(u.ProfileID) == 0 || len(u.ProfileID) > envelope.MaxCanonicalIDBytes {
			return fail(ErrorSize)
		}
	}
	return nil
}
