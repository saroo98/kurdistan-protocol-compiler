// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package sessionplan

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestRelayAdmissionPrefaceV1RoundTripRebuildsExactPlan(t *testing.T) {
	now := time.Now().UTC()
	request := fixtureRequestV2(t)
	request.Profile.ValidFrom = now.Add(-time.Minute).Unix()
	request.Profile.ValidUntil = now.Add(time.Hour).Unix()
	request.Requested.EndpointIndexes = []uint8{1}
	request.Requested.MaxQueuePackets = 4
	request.Requested.MaxIncompleteOps = 2
	request.Requested.MaxReconnectAttempts = 1
	plan, err := BuildV2At(request, now)
	if err != nil {
		t.Fatal(err)
	}
	preface, err := NewRelayAdmissionPrefaceV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRelayAdmissionPrefaceV1(preface)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRelayAdmissionPrefaceV1(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := EncodeRelayAdmissionPrefaceV1(decoded)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		t.Fatal("relay admission preface was not canonical")
	}
	authority := RelayAuthorityV2{
		ProfileContentID:  request.Profile.ContentID,
		ProfileGeneration: request.Profile.Generation,
		ValidFrom:         request.Profile.ValidFrom,
		ValidUntil:        request.Profile.ValidUntil,
		RuntimePolicy:     request.RuntimePolicy,
		StrategyIDs:       request.Profile.StrategyIDs,
		RelayIDs:          request.Profile.RelayIDs,
	}
	rebuilt, err := BuildRelayV2At(authority, decoded, now)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Digest != plan.Digest || !reflect.DeepEqual(rebuilt, plan) {
		t.Fatal("relay did not independently rebuild the exact client plan")
	}

	decoded.Requested.EndpointIndexes[0] = 0
	decoded.Requested.Routes[0].Address[0] ^= 1
	again, err := DecodeRelayAdmissionPrefaceV1(encoded)
	if err != nil || again.Requested.EndpointIndexes[0] != 1 || again.Requested.Routes[0].Address[0] != 0 {
		t.Fatal("relay admission preface retained mutable caller storage")
	}
}

func TestBuildRelayV2AtRejectsEveryUnverifiedClaim(t *testing.T) {
	now := time.Now().UTC()
	request := fixtureRequestV2(t)
	request.Profile.ValidFrom = now.Add(-time.Minute).Unix()
	request.Profile.ValidUntil = now.Add(time.Hour).Unix()
	plan, err := BuildV2At(request, now)
	if err != nil {
		t.Fatal(err)
	}
	preface, err := NewRelayAdmissionPrefaceV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	authority := RelayAuthorityV2{
		ProfileContentID:  request.Profile.ContentID,
		ProfileGeneration: request.Profile.Generation,
		ValidFrom:         request.Profile.ValidFrom,
		ValidUntil:        request.Profile.ValidUntil,
		RuntimePolicy:     request.RuntimePolicy,
		StrategyIDs:       request.Profile.StrategyIDs,
		RelayIDs:          request.Profile.RelayIDs,
	}

	for name, mutate := range map[string]func(*RelayAuthorityV2, *RelayAdmissionPrefaceV1){
		"content":     func(_ *RelayAuthorityV2, p *RelayAdmissionPrefaceV1) { p.ProfileContentID += "x" },
		"generation":  func(_ *RelayAuthorityV2, p *RelayAdmissionPrefaceV1) { p.ProfileGeneration++ },
		"receipt":     func(_ *RelayAuthorityV2, p *RelayAdmissionPrefaceV1) { p.ActivationReceiptDigest[0] ^= 1 },
		"plan digest": func(_ *RelayAuthorityV2, p *RelayAdmissionPrefaceV1) { p.PlanDigest[0] ^= 1 },
		"route widening": func(_ *RelayAuthorityV2, p *RelayAdmissionPrefaceV1) {
			p.Requested.Routes[0].Address = []byte{10, 0, 0, 0}
			p.Requested.Routes[0].PrefixLen = 8
		},
		"limit widening": func(_ *RelayAuthorityV2, p *RelayAdmissionPrefaceV1) { p.Requested.MaxQueuePackets = 65535 },
		"expired":        func(a *RelayAuthorityV2, _ *RelayAdmissionPrefaceV1) { a.ValidUntil = now.Add(-time.Second).Unix() },
		"wrong relay":    func(a *RelayAuthorityV2, _ *RelayAdmissionPrefaceV1) { a.RelayIDs = []string{"relay.0000000000000000"} },
	} {
		t.Run(name, func(t *testing.T) {
			candidateAuthority := authority.Clone()
			candidatePreface := preface.Clone()
			mutate(&candidateAuthority, &candidatePreface)
			if got, err := BuildRelayV2At(candidateAuthority, candidatePreface, now); err == nil || !reflect.DeepEqual(got, PlanV2{}) {
				t.Fatalf("unverified relay claim accepted: plan=%+v err=%v", got, err)
			}
		})
	}
}

func TestRelayAdmissionPrefaceV1RejectsMalformedOrNonCanonicalBytes(t *testing.T) {
	request := fixtureRequestV2(t)
	plan, err := BuildV2(request)
	if err != nil {
		t.Fatal(err)
	}
	preface, err := NewRelayAdmissionPrefaceV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRelayAdmissionPrefaceV1(preface)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"empty":      nil,
		"truncated":  encoded[:len(encoded)-1],
		"oversized":  make([]byte, MaxRelayAdmissionPrefaceBytesV1+1),
		"indefinite": {0x9f, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := DecodeRelayAdmissionPrefaceV1(candidate); err == nil || !reflect.DeepEqual(got, RelayAdmissionPrefaceV1{}) {
				t.Fatalf("malformed preface accepted: %+v err=%v", got, err)
			}
		})
	}
	mutated := preface.Clone()
	mutated.PlanDigest = [32]byte{}
	if _, err := EncodeRelayAdmissionPrefaceV1(mutated); !errors.Is(err, ErrRelayAdmissionV1) {
		t.Fatalf("zero plan digest err=%v", err)
	}
}

func TestRelayAdmissionPrefaceStreamV1IsLengthBounded(t *testing.T) {
	request := fixtureRequestV2(t)
	plan, err := BuildV2(request)
	if err != nil {
		t.Fatal(err)
	}
	preface, err := NewRelayAdmissionPrefaceV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	var stream bytes.Buffer
	if err := WriteRelayAdmissionPrefaceV1(&stream, preface); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadRelayAdmissionPrefaceV1(&stream)
	if err != nil || !reflect.DeepEqual(decoded, preface) {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	for name, wire := range map[string][]byte{
		"zero":      {0, 0, 0, 0},
		"oversized": append(binary.BigEndian.AppendUint32(nil, MaxRelayAdmissionPrefaceBytesV1+1), 0),
		"truncated": {0, 0, 0, 4, 1, 2},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := ReadRelayAdmissionPrefaceV1(bytes.NewReader(wire)); err == nil || !reflect.DeepEqual(got, RelayAdmissionPrefaceV1{}) {
				t.Fatalf("stream accepted: %+v err=%v", got, err)
			}
		})
	}
}
