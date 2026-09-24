// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"runtime"
	"testing"
	"unsafe"

	"kurdistan/internal/product/envelope"
)

func TestResourcePreflightBundleAndPublicationBounds(t *testing.T) {
	issued, _, _, now, _ := resourceRecipientFixture(t, nil)
	b, err := decodeLiveBundleWithResourceMode(issued.Artifact, liveResourceTypedFirstV1)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := decodeLiveBundle(issued.Artifact)
	if err != nil || !bytes.Equal(b.SealedProfile, legacy.SealedProfile) {
		t.Fatal("bundle changed")
	}
	if _, err := decodeLiveBundleWithResourceMode(issued.Artifact, liveResourceMode(255)); err == nil {
		t.Fatal("unknown mode admitted")
	}
	for _, mutate := range []func(*liveProfileBundleV2){
		func(b *liveProfileBundleV2) { b.Root.Keys = append(b.Root.Keys, b.Root.Keys[0]) },
		func(b *liveProfileBundleV2) {
			b.Delegation.Scope.ProfileNamespace = string(bytes.Repeat([]byte{'a'}, 128))
		},
		func(b *liveProfileBundleV2) { b.Revocations.RevokedContentIDs = make([]string, 257) },
		func(b *liveProfileBundleV2) { b.RootPublicDER = make([]byte, 92) },
		func(b *liveProfileBundleV2) { b.SealedProfile = []byte{0xa0} },
	} {
		bad := legacy
		mutate(&bad)
		encoded, _ := encodeCanonical(bad)
		if _, err := decodeLiveBundleWithResourceMode(encoded, liveResourceTypedFirstV1); err == nil {
			t.Fatal("bad bundle shape admitted")
		}
	}
	s := publicationSnapshot{Version: 1, Revision: 1, GeneratedAt: now.Unix(), DeploymentID: b.DeploymentID, RootFingerprint: b.RootFingerprint, Root: b.Root, RootPublicDER: b.RootPublicDER, Revocations: b.Revocations, RevocationPayload: b.RevocationPayload, RevocationSignature: b.RevocationSignature, Profiles: make([][]byte, 4096)}
	for i := range s.Profiles {
		s.Profiles[i] = []byte{0xff}
	} // opaque, not individually admitted
	encoded, _ := encodeCanonical(s)
	decoded, err := decodePublicationSnapshotWithResourceMode(encoded, liveResourceTypedFirstV1)
	if err != nil || len(decoded.Profiles) != 4096 {
		t.Fatalf("4096 publication: %v", err)
	}
	s.Profiles = append(s.Profiles, []byte{0xff})
	encoded, _ = encodeCanonical(s)
	if _, err := decodePublicationSnapshotWithResourceMode(encoded, liveResourceTypedFirstV1); err == nil {
		t.Fatal("4097 publication admitted")
	}
	s.Profiles = [][]byte{make([]byte, maxStateBytes-2048)}
	s.Revocations.RevokedContentIDs = nil
	encoded, _ = encodeCanonical(s)
	decoded, err = decodePublicationSnapshotWithResourceMode(encoded, liveResourceTypedFirstV1)
	if err != nil || len(decoded.Profiles) != 1 || len(decoded.Profiles[0]) != maxStateBytes-2048 {
		t.Fatalf("near-limit opaque publication: %v", err)
	}
	t.Logf("%s/%s near-publication input=%d returned-profile-cap=%d slice-cap=%d snapshot=%d bundle=%d opener=%d", runtime.Version(), runtime.GOARCH, len(encoded), cap(decoded.Profiles[0]), cap(decoded.Profiles), unsafe.Sizeof(s), unsafe.Sizeof(b), unsafe.Sizeof(liveResourceRecipientOpener{}))
	if _, err := decodePublicationSnapshotWithResourceMode(make([]byte, maxStateBytes+1), liveResourceTypedFirstV1); err == nil {
		t.Fatal("aggregate publication overflow admitted")
	}
	for _, count := range []int{256, 257} {
		s.Profiles = nil
		s.Revocations.RevokedContentIDs = make([]string, count)
		for i := range s.Revocations.RevokedContentIDs {
			s.Revocations.RevokedContentIDs[i] = "content.shape-only"
		}
		encoded, _ = encodeCanonical(s)
		_, err := decodePublicationSnapshotWithResourceMode(encoded, liveResourceTypedFirstV1)
		if (count == 256) != (err == nil) {
			t.Fatalf("revocation list %d: %v", count, err)
		}
	}
	if _, err := decodeLiveBundleWithResourceMode(make([]byte, envelope.MaxTotalInputBytes+1), liveResourceTypedFirstV1); err == nil {
		t.Fatal("oversize bundle admitted")
	}
}
