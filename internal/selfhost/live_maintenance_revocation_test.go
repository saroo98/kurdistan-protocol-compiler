// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
)

func TestLiveMaintenanceNegativeEvidenceCategories(t *testing.T) {
	o, _, next, now, dir := maintenanceFixtureFull(t)
	state, master, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(master)
	root, err := recoveryRootForState(state, filepath.Join(filepath.Dir(dir), "recovery.kurd-recovery"), []byte("state v2 test recovery passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	sign := func(s *publicationSnapshot) {
		s.RevocationPayload, err = profile.EncodeRevocationSetV1(s.Revocations)
		if err != nil {
			t.Fatal(err)
		}
		s.RevocationSignature, err = (p256Signer{keyID: s.Root.Keys[0].KeyID, key: root}).Sign(s.Root.Keys[0], s.RevocationPayload)
		if err != nil {
			t.Fatal(err)
		}
	}
	b, err := decodeLiveBundle(next.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*publicationSnapshot)
		want   LiveMaintenanceFailureV1
		proof  bool
	}{
		{"emergency", func(s *publicationSnapshot) {
			s.Revocations.RevokedContentIDs = nil
			s.Revocations.EmergencyDenied = true
		}, 0, true},
		{"issuer", func(s *publicationSnapshot) {
			s.Revocations.RevokedContentIDs = nil
			s.Revocations.RevokedIssuerKeyIDs = []string{o.bundle.IssuerKey.KeyID}
		}, 0, true},
		{"equal-epoch-split-view", func(s *publicationSnapshot) { s.Revocations.Epoch = o.bundle.Revocations.Epoch }, LiveMaintenanceRollback, false},
		{"scope", func(s *publicationSnapshot) { s.Revocations.Scope += "x" }, LiveMaintenanceProfileMismatch, false},
		{"root", func(s *publicationSnapshot) { s.Root.ViewID += "x" }, LiveMaintenanceRootRotationRejected, false},
		{"stale", func(s *publicationSnapshot) {
			s.Revocations.IssuedAt = now.Unix() - 3600
			s.Revocations.MaxOfflineStalenessSecs = 1
		}, LiveMaintenanceExpired, false},
		{"future-publication", func(s *publicationSnapshot) { s.GeneratedAt = now.Unix() + 301 }, LiveMaintenanceExpired, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := publicationSnapshot{Version: 1, Revision: 1, GeneratedAt: now.Unix(), DeploymentID: b.DeploymentID, RootFingerprint: b.RootFingerprint, Root: b.Root, RootPublicDER: b.RootPublicDER, Revocations: b.Revocations}
			tc.mutate(&s)
			sign(&s)
			raw, err := encodeCanonical(s)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := o.VerifyCurrentRevocationAt(raw, now)
			if tc.proof {
				if err != nil || !o.IsCurrentRevocationAt(proof, now) {
					t.Fatalf("signed denial not proven: %v", err)
				}
			} else if maintenanceReason(t, err) != tc.want || o.IsCurrentRevocationAt(proof, now) {
				t.Fatalf("wrong negative category: %v", err)
			}
			if o.RevalidateAt(now) != nil {
				t.Fatal("negative evidence mutated accepted current")
			}
		})
	}
	denied := maintenanceRewrite(t, o, next.Artifact, dir, func(_ *envelope.CanonicalProfileV1, b *liveProfileBundleV2) {
		s := publicationSnapshot{Root: b.Root, Revocations: b.Revocations}
		s.Revocations.EmergencyDenied = true
		sign(&s)
		b.Revocations, b.RevocationPayload, b.RevocationSignature = s.Revocations, s.RevocationPayload, s.RevocationSignature
	})
	if c, noChange, err := o.VerifyCandidateAt(denied, now); c != nil || noChange || maintenanceReason(t, err) != LiveMaintenanceRevoked {
		t.Fatal("candidate self-denial classification")
	}
	if o.RevalidateAt(now) != nil || o.IsCurrentRevocationAt(VerifiedLiveCurrentRevocation{}, now) {
		t.Fatal("candidate self-denial became current retirement")
	}
}

func TestLiveMaintenanceNegativeProofIsIndependentAndOwnerBound(t *testing.T) {
	owner, _, next, now := maintenanceFixture(t)
	b, err := decodeLiveBundle(next.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	publication := publicationSnapshot{Version: 1, Revision: 1, GeneratedAt: now.Unix(), DeploymentID: b.DeploymentID, RootFingerprint: b.RootFingerprint, Root: b.Root, RootPublicDER: b.RootPublicDER, Revocations: b.Revocations, RevocationPayload: b.RevocationPayload, RevocationSignature: b.RevocationSignature}
	encoded, err := encodeCanonical(publication)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := owner.VerifyCurrentRevocationAt(encoded, now)
	if err != nil || !owner.IsCurrentRevocationAt(proof, now) {
		t.Fatalf("authenticated predecessor denial not proven: %v", err)
	}
	if (&LiveMaintenanceAdmission{}).IsCurrentRevocationAt(proof, now) || owner.IsCurrentRevocationAt(VerifiedLiveCurrentRevocation{}, now) {
		t.Fatal("unbound proof accepted")
	}
	if owner.IsCurrentRevocationAt(proof, owner.AuthorityDeadline()) {
		t.Fatal("expired proof accepted")
	}
	if err := owner.RevalidateAt(now); err != nil {
		t.Fatal("negative operation changed current accepted authority")
	}
	publication.RevocationSignature = append([]byte(nil), publication.RevocationSignature...)
	publication.RevocationSignature[0] ^= 1
	bad, _ := encodeCanonical(publication)
	if p, err := owner.VerifyCurrentRevocationAt(bad, now); maintenanceReason(t, err) != LiveMaintenanceSignatureInvalid || owner.IsCurrentRevocationAt(p, now) {
		t.Fatal("tampered publication yielded proof")
	}
	current := owner.bundle
	publication.Revocations = current.Revocations
	publication.RevocationPayload = current.RevocationPayload
	publication.RevocationSignature = current.RevocationSignature
	clean, _ := encodeCanonical(publication)
	priorClock := owner.lastNow
	if p, err := owner.VerifyCurrentRevocationAt(clean, now.Add(time.Second)); !errors.Is(err, ErrNoCurrentRevocation) || owner.IsCurrentRevocationAt(p, now) {
		t.Fatal("clean evidence became proof or update no-change")
	}
	if owner.lastNow != priorClock {
		t.Fatal("non-denial evidence advanced owner timestamp")
	}
	owner.Destroy()
	if owner.IsCurrentRevocationAt(proof, now) {
		t.Fatal("destroyed owner retained negative proof")
	}
}
