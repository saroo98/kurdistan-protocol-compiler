// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sort"
	"time"
)

const (
	addressFamilyIPv4 uint8 = 4
	addressFamilyIPv6 uint8 = 6
	addressQuarantine       = maxProfileValidity + 24*time.Hour
)

func defaultAddressPools() (addressPoolV1, addressPoolV1) {
	return addressPoolV1{
			Family: addressFamilyIPv4, Network: []byte{10, 77, 0, 0}, PrefixLength: 16,
			ServerDNS: []byte{10, 77, 0, 1}, Enabled: true, NextHostOffset: 2,
		}, addressPoolV1{
			Family: addressFamilyIPv6, Network: netip.MustParseAddr("fd4b:7572:6400::").AsSlice(), PrefixLength: 64,
			ServerDNS: netip.MustParseAddr("fd4b:7572:6400::1").AsSlice(), Enabled: false, NextHostOffset: 2,
		}
}

func validateAddressPool(pool addressPoolV1) error {
	address, ok := netip.AddrFromSlice(pool.Network)
	if !ok || address.Is4In6() || uint8(address.BitLen()) != familyBits(pool.Family) ||
		pool.Family == addressFamilyIPv4 && pool.PrefixLength != 16 && pool.PrefixLength != 24 || pool.Family == addressFamilyIPv6 && pool.PrefixLength != 64 {
		return ErrStateCorrupt
	}
	prefix := netip.PrefixFrom(address, int(pool.PrefixLength)).Masked()
	if !prefix.IsValid() || prefix.Addr() != address {
		return ErrStateCorrupt
	}
	server, ok := netip.AddrFromSlice(pool.ServerDNS)
	if !ok || server.Is4In6() || uint8(server.BitLen()) != familyBits(pool.Family) || !prefix.Contains(server) || server == address {
		return ErrStateCorrupt
	}
	if pool.NextHostOffset < 2 || pool.NextHostOffset > maxHostOffset(pool) {
		return ErrStateCorrupt
	}
	return nil
}

func allocateAddress(pool *addressPoolV1, assignments []addressAssignmentV1, now int64) ([]byte, error) {
	if pool == nil || !pool.Enabled || now <= 0 || validateAddressPool(*pool) != nil {
		return nil, ErrAddressExhausted
	}
	start := pool.NextHostOffset
	offset := start
	for {
		if usableHostOffset(*pool, offset) {
			address, err := addressAtOffset(*pool, offset)
			if err != nil {
				return nil, err
			}
			if addressAvailable(pool.Family, address, assignments, now) {
				pool.NextHostOffset = nextHostOffset(*pool, offset)
				return address, nil
			}
		}
		offset = nextHostOffset(*pool, offset)
		if offset == start {
			return nil, ErrAddressExhausted
		}
	}
}

func quarantineProfileAssignments(assignments []addressAssignmentV1, profileID string, transitionAt int64) []addressAssignmentV1 {
	result := cloneAssignments(assignments)
	for index := range result {
		if result[index].ProfileID == profileID && result[index].State == addressStateActive {
			result[index].State = addressStateQuarantined
			result[index].ReleaseAt = transitionAt + int64(addressQuarantine/time.Second)
		}
	}
	return result
}

func sweepExpiredAssignments(assignments []addressAssignmentV1, now int64) []addressAssignmentV1 {
	result := cloneAssignments(assignments)
	for index := range result {
		if result[index].State == addressStateActive && result[index].ProfileValidUntil <= now {
			result[index].State = addressStateQuarantined
			result[index].ReleaseAt = result[index].ProfileValidUntil + int64(addressQuarantine/time.Second)
		}
	}
	return result
}

func pruneReleasedAssignments(assignments []addressAssignmentV1, now int64) []addressAssignmentV1 {
	result := make([]addressAssignmentV1, 0, len(assignments))
	for _, assignment := range assignments {
		if assignment.State == addressStateQuarantined && assignment.ReleaseAt <= now {
			continue
		}
		copy := assignment
		copy.Address = append([]byte(nil), assignment.Address...)
		result = append(result, copy)
	}
	return result
}

func validateAssignments(state persistedState) error {
	assignments := cloneAssignments(state.Assignments)
	profiles := make(map[string]profileRecord, len(state.Profiles))
	for _, record := range state.Profiles {
		profiles[record.ProfileID] = record
	}
	sort.Slice(assignments, func(i, j int) bool {
		if assignments[i].Family != assignments[j].Family {
			return assignments[i].Family < assignments[j].Family
		}
		return bytes.Compare(assignments[i].Address, assignments[j].Address) < 0
	})
	activeByProfile := make(map[string]map[uint8]bool)
	for index, assignment := range assignments {
		if assignment.Family != state.Assignments[index].Family || !bytes.Equal(assignment.Address, state.Assignments[index].Address) {
			return ErrStateCorrupt
		}
		if assignment.Family != addressFamilyIPv4 && assignment.Family != addressFamilyIPv6 || !validID(assignment.ProfileID) || !validID(assignment.ContentID) || assignment.Generation == 0 ||
			assignment.AssignedAt <= 0 || assignment.ProfileValidUntil <= assignment.AssignedAt || assignment.State != addressStateActive && assignment.State != addressStateQuarantined {
			return ErrStateCorrupt
		}
		address, ok := netip.AddrFromSlice(assignment.Address)
		if !ok || address.Is4In6() || uint8(address.BitLen()) != familyBits(assignment.Family) {
			return ErrStateCorrupt
		}
		if index > 0 && assignment.Family == assignments[index-1].Family && bytes.Equal(assignment.Address, assignments[index-1].Address) {
			return ErrStateCorrupt
		}
		pool := state.IPv4Pool
		if assignment.Family == addressFamilyIPv6 {
			pool = state.IPv6Pool
		}
		prefixAddress, _ := netip.AddrFromSlice(pool.Network)
		prefix := netip.PrefixFrom(prefixAddress, int(pool.PrefixLength))
		server, _ := netip.AddrFromSlice(pool.ServerDNS)
		if !prefix.Contains(address) || address == prefixAddress || address == server || assignment.Family == addressFamilyIPv4 && !usableHostOffset(pool, hostOffset(pool, address)) {
			return ErrStateCorrupt
		}
		if assignment.State == addressStateActive {
			record, found := profiles[assignment.ProfileID]
			if assignment.ReleaseAt != 0 || !found || record.Mode != profileModeLive || record.Revoked ||
				record.ContentID != assignment.ContentID || record.Generation != assignment.Generation || record.ValidUntil != assignment.ProfileValidUntil ||
				assignment.Family == addressFamilyIPv4 && !bytes.Equal(record.AssignedIPv4, assignment.Address) ||
				assignment.Family == addressFamilyIPv6 && !bytes.Equal(record.AssignedIPv6, assignment.Address) {
				return ErrStateCorrupt
			}
			if activeByProfile[assignment.ProfileID] == nil {
				activeByProfile[assignment.ProfileID] = make(map[uint8]bool)
			}
			if activeByProfile[assignment.ProfileID][assignment.Family] {
				return ErrStateCorrupt
			}
			activeByProfile[assignment.ProfileID][assignment.Family] = true
		} else if assignment.ReleaseAt <= assignment.ProfileValidUntil {
			return ErrStateCorrupt
		}
	}
	return nil
}

func addressAvailable(family uint8, address []byte, assignments []addressAssignmentV1, now int64) bool {
	for _, assignment := range assignments {
		if assignment.Family != family || !bytes.Equal(assignment.Address, address) {
			continue
		}
		return assignment.State == addressStateQuarantined && now >= assignment.ReleaseAt
	}
	return true
}

func addressAtOffset(pool addressPoolV1, offset uint64) ([]byte, error) {
	base, ok := netip.AddrFromSlice(pool.Network)
	if !ok {
		return nil, ErrStateCorrupt
	}
	if pool.Family == addressFamilyIPv4 {
		value := base.As4()
		baseValue := uint64(binary.BigEndian.Uint32(value[:]))
		if offset > uint64(^uint32(0))-baseValue {
			return nil, ErrStateCorrupt
		}
		binary.BigEndian.PutUint32(value[:], uint32(baseValue+offset))
		return append([]byte(nil), value[:]...), nil
	}
	value := base.As16()
	for index := 15; index >= 8; index-- {
		value[index] = byte(offset)
		offset >>= 8
	}
	return append([]byte(nil), value[:]...), nil
}

func hostOffset(pool addressPoolV1, address netip.Addr) uint64 {
	if pool.Family == addressFamilyIPv4 {
		baseAddress, ok := netip.AddrFromSlice(pool.Network)
		if !ok {
			return 0
		}
		base := baseAddress.As4()
		value := address.As4()
		return uint64(binary.BigEndian.Uint32(value[:]) - binary.BigEndian.Uint32(base[:]))
	}
	value := address.As16()
	var result uint64
	for index := 8; index < 16; index++ {
		result = result<<8 | uint64(value[index])
	}
	return result
}

func usableHostOffset(pool addressPoolV1, offset uint64) bool {
	if offset < 2 || offset > maxHostOffset(pool) {
		return false
	}
	return pool.Family != addressFamilyIPv4 || offset < maxHostOffset(pool)
}

func nextHostOffset(pool addressPoolV1, offset uint64) uint64 {
	offset++
	if offset > maxHostOffset(pool) || !usableHostOffset(pool, offset) {
		return 2
	}
	return offset
}

func maxHostOffset(pool addressPoolV1) uint64 {
	hostBits := uint64(familyBits(pool.Family) - pool.PrefixLength)
	if hostBits >= 64 {
		return ^uint64(0)
	}
	return uint64(1)<<hostBits - 1
}

func familyBits(family uint8) uint8 {
	if family == addressFamilyIPv4 {
		return 32
	}
	if family == addressFamilyIPv6 {
		return 128
	}
	return 0
}

func cloneAssignments(values []addressAssignmentV1) []addressAssignmentV1 {
	result := make([]addressAssignmentV1, len(values))
	for index := range values {
		result[index] = values[index]
		result[index].Address = append([]byte(nil), values[index].Address...)
	}
	return result
}
