// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"errors"
	"math"
	"testing"
	"time"
)

func TestRelayRevocationV3SameLoadEmergencyAndContentProvenance(t *testing.T) {
	for _, mode := range []string{"emergency", "content", "drained"} {
		t.Run(mode, func(t *testing.T) {
			dir, recovery, pass := initializedV2TestState(t)
			now := time.Unix(1_760_000_010, 0).UTC()
			if err := ConfirmRecovery(dir, recovery, pass, now); err != nil {
				t.Fatal(err)
			}
			issued, request, _ := createForServicesV3(t, dir, "negative-view", now, servicesForIssuanceV3())
			old, err := OpenRelayRuntimeSnapshotV1(dir, now)
			if err != nil {
				t.Fatal(err)
			}
			admission, ok := old.AdmissionByClientKeyIDV1(request.ClientAuthKeyID)
			if !ok || !admission.RevocationSubjectV3.valid {
				t.Fatal("missing admitted subject")
			}
			previous := old.VerifiedRevocationsV3()
			old.Close()
			switch mode {
			case "emergency":
				err = SetDeploymentDisabled(dir, true, RecoveryActionOptions{RecoveryPath: recovery, RecoveryPassphrase: pass, Now: now.Add(time.Second)})
			case "content":
				err = RevokeProfile(dir, RevokeProfileOptions{ProfileID: issued.ProfileID, RecoveryPath: recovery, RecoveryPassphrase: pass, Now: now.Add(time.Second)})
			default:
				err = SetDrained(dir, true, now.Add(time.Second))
			}
			if err != nil {
				t.Fatal(err)
			}
			next, loadErr := OpenRelayRuntimeSnapshotV1(dir, now.Add(2*time.Second))
			var view *RelayRevocationViewV3
			if next != nil {
				view = next.VerifiedRevocationsV3()
				defer next.Close()
			} else {
				var source RelayRevocationSourceV3
				if !errors.As(loadErr, &source) {
					t.Fatalf("same-load error lost verified negative view: %v", loadErr)
				}
				view = source.VerifiedRevocationsV3()
			}
			if mode == "emergency" && !errors.Is(loadErr, ErrRelayRuntimeUnavailable) {
				t.Fatal("legacy emergency error changed")
			}
			if mode == "drained" && !errors.Is(loadErr, ErrDrained) {
				t.Fatal("legacy drained error changed")
			}
			if view == nil || view.RevokesV3(admission.RevocationSubjectV3, now.Add(2*time.Second)) != (mode != "drained") {
				t.Fatal("negative provenance classification wrong")
			}
			if mode != "drained" && view.CompareV3(previous) != RelayRevocationNewerV3 {
				t.Fatal("signed epoch did not advance")
			}
			if view.RevokesV3(RelayRevocationSubjectV3{}, now) {
				t.Fatal("zero subject fabricated revocation")
			}
			if view.OwnedBytesV3() == 0 {
				t.Fatal("unaccounted view")
			}
		})
	}
}

func TestRelayRevocationV3ExactIdentityFreshnessAndHighWater(t *testing.T) {
	dir, recovery, pass := initializedV2TestState(t)
	now := time.Unix(1_760_000_010, 0).UTC()
	if err := ConfirmRecovery(dir, recovery, pass, now); err != nil {
		t.Fatal(err)
	}
	_, request, _ := createForServicesV3(t, dir, "boundaries", now, servicesForIssuanceV3())
	snapshot, err := OpenRelayRuntimeSnapshotV1(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	a, _ := snapshot.AdmissionByClientKeyIDV1(request.ClientAuthKeyID)
	base := snapshot.VerifiedRevocationsV3()
	if base == nil {
		t.Fatal("view unavailable")
	}
	issuer := *base
	issuer.issuerCount = 1
	issuer.issuers[0] = a.RevocationSubjectV3.issuer.KeyID
	if !issuer.RevokesV3(a.RevocationSubjectV3, now) {
		t.Fatal("captured retired issuer lost after content compaction")
	}
	for _, mode := range []string{"scope", "root", "suite", "epoch", "view", "conflict", "expired", "future"} {
		t.Run(mode, func(t *testing.T) {
			view := issuer
			switch mode {
			case "scope":
				view.root.scope += "x"
			case "root":
				view.root.public[0] ^= 1
			case "suite":
				view.root.key.SuiteID++
			case "epoch":
				view.epoch--
			case "view":
				view.root.view += "x"
			case "conflict":
				view.digest[0] ^= 1
			case "expired":
				view.freshUntil = now.Unix()
			case "future":
				view.issued = now.Unix() + 1
			}
			if view.RevokesV3(a.RevocationSubjectV3, now) {
				t.Fatal("mismatched or stale evidence revoked session")
			}
		})
	}
	same := *base
	if same.CompareV3(base) != RelayRevocationSameV3 {
		t.Fatal("same epoch changed")
	}
	same.digest[0] ^= 1
	if same.CompareV3(base) != RelayRevocationConflictV3 {
		t.Fatal("equal epoch conflict admitted")
	}
	same.epoch++
	if same.CompareV3(base) != RelayRevocationNewerV3 {
		t.Fatal("newer epoch rejected")
	}
	if base.CompareV3(&same) != RelayRevocationOlderV3 {
		t.Fatal("high-water rollback admitted")
	}
	cutoff, ok := freshCutoffV3(100, 1000, 10)
	if !ok || cutoff != 111 {
		t.Fatal("inclusive freshness cutoff changed")
	}
	for _, input := range []struct {
		issued, expiry int64
		stale          uint64
	}{{-1, 100, 1}, {math.MaxInt64 - 1, math.MaxInt64, 2}, {100, 1000, math.MaxUint64}} {
		if _, ok = freshCutoffV3(input.issued, input.expiry, input.stale); ok {
			t.Fatal("negative/overflow freshness admitted")
		}
	}
	state, master, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(master)
	if verifiedRelayRevocationsV3(state, time.Unix(state.Revocations.ExpiresAt, 0)) != nil {
		t.Fatal("expired verified view exposed")
	}
	state.RevocationSig[0] ^= 1
	if verifiedRelayRevocationsV3(state, now) != nil {
		t.Fatal("invalid signature exposed view")
	}
}
