// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestIPv4PoolAllocatesBeyondLegacy24Boundary(t *testing.T) {
	ipv4, _ := defaultAddressPools()
	var assignments []addressAssignmentV1
	for offset := 2; offset <= 300; offset++ {
		address, err := allocateAddress(&ipv4, assignments, 100)
		if err != nil {
			t.Fatalf("offset %d: %v", offset, err)
		}
		if got := hostOffset(ipv4, mustAddrFromBytes(t, address)); got != uint64(offset) {
			t.Fatalf("address=%v offset=%d want=%d", address, got, offset)
		}
		assignments = append(assignments, addressAssignmentV1{Family: addressFamilyIPv4, Address: address, ProfileID: "profiles.fixture", ContentID: "content.fixture", Generation: uint64(offset), State: addressStateActive, AssignedAt: 1, ProfileValidUntil: 200})
	}
	if ipv4.PrefixLength != 16 {
		t.Fatalf("default IPv4 prefix=%d want=16", ipv4.PrefixLength)
	}
}

func TestLegacyIPv4PoolStillValidatesAndExhausts(t *testing.T) {
	ipv4, _ := defaultAddressPools()
	ipv4.PrefixLength = 24
	var assignments []addressAssignmentV1
	for offset := 2; offset <= 254; offset++ {
		address, err := allocateAddress(&ipv4, assignments, 100)
		if err != nil {
			t.Fatalf("offset %d: %v", offset, err)
		}
		assignments = append(assignments, addressAssignmentV1{Family: addressFamilyIPv4, Address: address, ProfileID: "profiles.fixture", ContentID: "content.fixture", Generation: uint64(offset), State: addressStateActive, AssignedAt: 1, ProfileValidUntil: 200})
	}
	if _, err := allocateAddress(&ipv4, assignments, 100); !errors.Is(err, ErrAddressExhausted) {
		t.Fatalf("exhaustion error=%v", err)
	}
}

func mustAddrFromBytes(t *testing.T, value []byte) netip.Addr {
	t.Helper()
	address, ok := netip.AddrFromSlice(value)
	if !ok {
		t.Fatalf("invalid address bytes=%v", value)
	}
	return address
}

func TestAddressQuarantineBoundaryAndDisabledIPv6(t *testing.T) {
	ipv4, ipv6 := defaultAddressPools()
	if _, err := allocateAddress(&ipv6, nil, 100); !errors.Is(err, ErrAddressExhausted) {
		t.Fatalf("disabled IPv6 error=%v", err)
	}
	address := []byte{10, 77, 0, 2}
	assignments := []addressAssignmentV1{{Family: addressFamilyIPv4, Address: address, ProfileID: "profiles.fixture", ContentID: "content.fixture", Generation: 1, State: addressStateQuarantined, AssignedAt: 1, ProfileValidUntil: 2, ReleaseAt: 100}}
	if got, err := allocateAddress(&ipv4, assignments, 99); err != nil || bytes.Equal(got, address) {
		t.Fatalf("early reuse got=%v err=%v", got, err)
	}
	ipv4.NextHostOffset = 2
	if got, err := allocateAddress(&ipv4, assignments, 100); err != nil || !bytes.Equal(got, address) {
		t.Fatalf("boundary reuse got=%v err=%v", got, err)
	}
	if retained := pruneReleasedAssignments(assignments, 99); len(retained) != 1 {
		t.Fatalf("early prune retained=%d", len(retained))
	}
	if retained := pruneReleasedAssignments(assignments, 100); len(retained) != 0 {
		t.Fatalf("released assignment retained=%d", len(retained))
	}
}

func TestStateRejectsDuplicateAndAuthorityOnlyActiveAssignments(t *testing.T) {
	dataDir, recovery, passphrase := initializedV2TestState(t)
	now := time.Unix(1_760_000_100, 0).UTC()
	if err := ConfirmRecovery(dataDir, recovery, passphrase, now); err != nil {
		t.Fatal(err)
	}
	issued, err := CreateProfile(dataDir, CreateProfileOptions{Name: "authority-only", ValidFor: time.Hour, Now: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	state, master, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(master)
	record := state.Profiles[profileIndex(state.Profiles, issued.ProfileID)]
	assignment := addressAssignmentV1{
		Family: addressFamilyIPv4, Address: []byte{10, 77, 0, 2}, ProfileID: record.ProfileID, ContentID: record.ContentID,
		Generation: record.Generation, State: addressStateActive, AssignedAt: record.CreatedAt, ProfileValidUntil: record.ValidUntil,
	}
	state.Assignments = []addressAssignmentV1{assignment}
	if err := saveState(dataDir, master, state); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("authority-only active assignment accepted: %v", err)
	}
	assignment.State = addressStateQuarantined
	assignment.ReleaseAt = record.ValidUntil + int64(addressQuarantine/time.Second)
	state.Assignments = []addressAssignmentV1{assignment, assignment}
	if err := saveState(dataDir, master, state); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("duplicate assignment accepted: %v", err)
	}
}
