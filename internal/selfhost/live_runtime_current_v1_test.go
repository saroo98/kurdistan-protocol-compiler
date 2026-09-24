// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
)

func TestLiveRuntimeCurrentRetainsExactProofAndIndependentBacking(t *testing.T) {
	old, first, _, now := maintenanceFixture(t)
	current := old.admission.CurrentState()
	artifactBefore := bytes.Clone(first.Artifact)
	secretBefore := bytes.Clone(old.private.RecipientPrivate)
	v, err := VerifyLiveRuntimeCurrentForRecipient(first.Artifact, now, current, old.request, old.private, old.limits)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Destroy()
	if !bytes.Equal(first.Artifact, artifactBefore) || !bytes.Equal(old.private.RecipientPrivate, secretBefore) {
		t.Fatal("constructor mutated caller storage")
	}
	bounds, err := v.BoundsV1()
	if err != nil || bounds.RetainedBytes == 0 || bounds.RetainedBytes > bounds.PeakReservedBytes || bounds.PeakReservedBytes > bounds.BudgetBytes {
		t.Fatalf("invalid retained reservation: %+v %v", bounds, err)
	}
	old.Destroy()
	clear(first.Artifact)
	var borrowed []byte
	if err := v.WithVerifiedV1(func(got profile.OfflineVerifiedArtifact, state lifecycle.VerifiedState, policy runtimepolicy.PolicyV2, end time.Time) error {
		if !bytes.Equal(got.ExactArtifact, artifactBefore) || state != current || policy.Services == nil || len(policy.LiveProgram) == 0 || !end.After(now) {
			t.Fatal("retained proof lost original inputs")
		}
		borrowed = got.ExactArtifact
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := v.CheckAtV1(now); err != nil {
		t.Fatal(err)
	}
	v.Destroy()
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("owned artifact not wiped")
	}
	if v.CheckAtV1(now) == nil {
		t.Fatal("destroyed owner checked")
	}
	if _, err := v.BoundsV1(); err == nil {
		t.Fatal("destroyed diagnostic accepted")
	}
}

func TestLiveRuntimeCurrentRejectsUnadmittedAndChangedCurrent(t *testing.T) {
	old, first, _, now := maintenanceFixture(t)
	current := old.admission.CurrentState()
	cases := []struct {
		name   string
		change func(*lifecycle.VerifiedState)
	}{
		{"absent", func(s *lifecycle.VerifiedState) { *s = lifecycle.VerifiedState{} }},
		{"zero-generation", func(s *lifecycle.VerifiedState) { s.Generation = 0 }},
		{"future-generation", func(s *lifecycle.VerifiedState) { s.Generation++ }},
		{"receipt", func(s *lifecycle.VerifiedState) { s.Receipt = lifecycle.VerifiedReceipt{} }},
		{"profile", func(s *lifecycle.VerifiedState) { s.ProfileID = "other" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := current
			tc.change(&state)
			v, err := VerifyLiveRuntimeCurrentForRecipient(first.Artifact, now, state, old.request, old.private, old.limits)
			if v != nil {
				v.Destroy()
				t.Fatal("invalid state escaped")
			}
			if err == nil {
				t.Fatal("invalid current admitted")
			}
		})
	}
	for _, at := range []time.Time{{}, time.Unix(0, 0), now.Add(-24 * time.Hour), now.Add(365 * 24 * time.Hour)} {
		v, err := VerifyLiveRuntimeCurrentForRecipient(first.Artifact, at, current, old.request, old.private, old.limits)
		if v != nil {
			v.Destroy()
		}
		if err == nil {
			t.Fatal("invalid verification time accepted")
		}
	}
}

func TestLiveRuntimeCurrentSingleBorrowRetirement(t *testing.T) {
	old, first, _, now := maintenanceFixture(t)
	for _, mode := range []string{"return", "error", "panic", "concurrent"} {
		t.Run(mode, func(t *testing.T) {
			v, err := VerifyLiveRuntimeCurrentForRecipient(first.Artifact, now, old.admission.CurrentState(), old.request, old.private, old.limits)
			if err != nil {
				t.Fatal(err)
			}
			defer v.Destroy()
			sentinel := errors.New("callback failure")
			var backing []byte
			run := func() (err error) {
				defer func() {
					if got := recover(); got != nil {
						if mode != "panic" || got != sentinel {
							panic(got)
						}
						err = sentinel
					}
				}()
				return v.WithVerifiedV1(func(got profile.OfflineVerifiedArtifact, _ lifecycle.VerifiedState, _ runtimepolicy.PolicyV2, _ time.Time) error {
					backing = got.ExactArtifact
					if v.CheckAtV1(now) == nil {
						t.Fatal("check raced borrowed input")
					}
					if v.WithVerifiedV1(func(profile.OfflineVerifiedArtifact, lifecycle.VerifiedState, runtimepolicy.PolicyV2, time.Time) error {
						return nil
					}) == nil {
						t.Fatal("reentrant borrow accepted")
					}
					if _, err := v.BoundsV1(); err != nil {
						t.Fatal("open diagnostic unavailable during borrow")
					}
					if mode == "concurrent" {
						done := make(chan struct{})
						go func() { v.Destroy(); close(done) }()
						<-done
					} else {
						v.Destroy()
					}
					if !bytes.Equal(backing, first.Artifact) {
						t.Fatal("retirement cleared active borrowed backing")
					}
					if _, err := v.BoundsV1(); err == nil {
						t.Fatal("closing diagnostic accepted")
					}
					if v.CheckAtV1(now) == nil {
						t.Fatal("closing check accepted")
					}
					if mode == "panic" {
						panic(sentinel)
					}
					if mode == "error" {
						return sentinel
					}
					return nil
				})
			}
			err = run()
			if (mode == "error" || mode == "panic") && err != sentinel {
				t.Fatal("callback outcome lost")
			}
			if (mode == "return" || mode == "concurrent") && err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(backing, make([]byte, len(backing))) {
				t.Fatal("pending destruction did not finish on callback unwind")
			}
			if v.WithVerifiedV1(nil) == nil {
				t.Fatal("destroyed borrow accepted")
			}
		})
	}
}

func TestLiveRuntimeCurrentTimeAndZeroOwner(t *testing.T) {
	var zero LiveRuntimeCurrentV1
	if zero.CheckAtV1(time.Now()) == nil || zero.WithVerifiedV1(nil) == nil {
		t.Fatal("zero owner admitted")
	}
	if _, err := zero.BoundsV1(); err == nil {
		t.Fatal("zero owner diagnostic admitted")
	}
	zero.Destroy()
	old, first, _, now := maintenanceFixture(t)
	v, err := VerifyLiveRuntimeCurrentForRecipient(first.Artifact, now, old.admission.CurrentState(), old.request, old.private, old.limits)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Destroy()
	if v.WithVerifiedV1(nil) == nil {
		t.Fatal("nil callback admitted")
	}
	sentinel := errors.New("borrow callback refused")
	if err := v.WithVerifiedV1(func(profile.OfflineVerifiedArtifact, lifecycle.VerifiedState, runtimepolicy.PolicyV2, time.Time) error {
		bounds, err := v.BoundsV1()
		if err != nil || bounds.OperationReservedBytes != uint64(unsafe.Sizeof(liveRuntimeCurrentBorrowV1{})) {
			t.Fatal("active argument holder not reserved")
		}
		return sentinel
	}); err != sentinel {
		t.Fatal("callback failure lost")
	}
	if bounds, err := v.BoundsV1(); err != nil || bounds.OperationReservedBytes != 0 {
		t.Fatal("failed callback retained its borrow reservation")
	}
	if err := v.CheckAtV1(now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{{}, time.Unix(0, 0), now} {
		if v.CheckAtV1(at) == nil {
			t.Fatal("zero or rollback time accepted")
		}
	}
	if err := v.WithVerifiedV1(func(_ profile.OfflineVerifiedArtifact, _ lifecycle.VerifiedState, _ runtimepolicy.PolicyV2, end time.Time) error {
		if !end.After(now) {
			t.Fatal("missing deadline")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := v.CheckAtV1(now.Add(365 * 24 * time.Hour)); err == nil {
		t.Fatal("expired proof accepted")
	}
}

func TestLiveRuntimeCurrentSingleCoreAndFailureOwnership(t *testing.T) {
	old, first, _, now := maintenanceFixture(t)
	current := old.admission.CurrentState()
	for _, mode := range []string{"success", "core-error", "projection-error", "admission-error"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			var bundleBacking, verifiedBacking, policyBacking []byte
			var opener *liveResourceRecipientOpener
			core := func(encoded []byte, at time.Time, floor uint64, r enrollment.PublicRequestV1, p enrollment.PrivateBundleV1, expected ...*envelope.CanonicalProfileV1) (liveProfileBundleV2, profile.OfflineVerifiedArtifact, *liveResourceRecipientOpener, profile.RecipientResolver, error) {
				calls++
				b, v, o, resolver, err := maintenanceVerifyCore(encoded, at, floor, r, p, expected...)
				if err != nil {
					return b, v, o, resolver, err
				}
				bundleBacking, verifiedBacking, policyBacking, opener = b.SealedProfile, v.ExactArtifact, v.Profile.Policy, o
				if mode == "core-error" {
					err = maintenanceFailure(LiveMaintenanceInternalFailure)
				}
				// The actual core/proof remain real. Corrupt only its temporary projection
				// input to force the failure after actual activation admission succeeded.
				if mode == "projection-error" {
					b.Revocations.IssuedAt = 0
				}
				if mode == "admission-error" {
					o.Destroy()
				}
				return b, v, o, resolver, err
			}
			artifactBefore := bytes.Clone(first.Artifact)
			privateBefore := bytes.Clone(old.private.RecipientPrivate)
			v, err := verifyLiveRuntimeCurrentForRecipientV1(first.Artifact, now, current, old.request, old.private, old.limits, core)
			if calls != 1 {
				t.Fatalf("core passes=%d", calls)
			}
			if opener == nil || opener.opener != nil || !bytes.Equal(bundleBacking, make([]byte, len(bundleBacking))) {
				t.Fatal("temporary provider ownership survived continuation")
			}
			if !bytes.Equal(first.Artifact, artifactBefore) || !bytes.Equal(old.private.RecipientPrivate, privateBefore) {
				t.Fatal("partial cleanup wiped caller buffers")
			}
			if mode == "success" {
				if err != nil || v == nil {
					t.Fatalf("real proof failed: %v", err)
				}
				if !bytes.Equal(verifiedBacking, first.Artifact) {
					t.Fatal("moved output destroyed by temporary cleanup")
				}
				v.Destroy()
			} else if err == nil || v != nil {
				if v != nil {
					v.Destroy()
				}
				t.Fatal("injected failure escaped")
			}
			if !bytes.Equal(verifiedBacking, make([]byte, len(verifiedBacking))) || !bytes.Equal(policyBacking, make([]byte, len(policyBacking))) {
				t.Fatal("partial result ownership not wiped")
			}
		})
	}
}

func TestLiveRuntimeCurrentExactReservationAndLayouts(t *testing.T) {
	old, first, _, now := maintenanceFixture(t)
	calls := 0
	core := func(encoded []byte, at time.Time, floor uint64, r enrollment.PublicRequestV1, p enrollment.PrivateBundleV1, expected ...*envelope.CanonicalProfileV1) (liveProfileBundleV2, profile.OfflineVerifiedArtifact, *liveResourceRecipientOpener, profile.RecipientResolver, error) {
		calls++
		return maintenanceVerifyCore(encoded, at, floor, r, p, expected...)
	}
	limits := old.limits
	reserved := maintenanceVerificationWorkspace(limits) + uint64(unsafe.Sizeof(LiveRuntimeCurrentV1{})) + uint64(unsafe.Sizeof(liveRuntimeCurrentBorrowV1{}))
	limits.OwnedBudgetBytes = reserved - 1
	for _, encoded := range [][]byte{first.Artifact, {0xff}} {
		v, err := verifyLiveRuntimeCurrentForRecipientV1(encoded, now, old.admission.CurrentState(), old.request, old.private, limits, core)
		if v != nil || maintenanceReason(t, err) != LiveMaintenanceResourceLimit || calls != 0 {
			t.Fatal("one-under reserve entered expensive verification")
		}
	}
	limits.OwnedBudgetBytes = reserved
	v, err := verifyLiveRuntimeCurrentForRecipientV1(first.Artifact, now, old.admission.CurrentState(), old.request, old.private, limits, core)
	if err != nil || calls != 1 {
		t.Fatalf("exact reserve refused: %v calls=%d", err, calls)
	}
	defer v.Destroy()
	bounds, _ := v.BoundsV1()
	if bounds.PeakReservedBytes != reserved {
		t.Fatal("exact selected reserve lost")
	}
	if v, err := verifyLiveRuntimeCurrentForRecipientV1([]byte{0xff}, now, old.admission.CurrentState(), old.request, old.private, limits, core); v != nil || maintenanceReason(t, err) != LiveMaintenanceInvalidRequest || calls != 2 {
		t.Fatal("reserved malformed input not rejected by actual core")
	}
	t.Logf("layout root=%d shared-temporary=%d core-function-slot=%d mutex=%d verified=%d activation=%d policy=%d profile=%d state=%d", unsafe.Sizeof(*v), unsafe.Sizeof(liveCurrentVerificationV1{}), unsafe.Sizeof(liveCurrentCoreVerifierV1(nil)), unsafe.Sizeof(v.mu), unsafe.Sizeof(v.verified), unsafe.Sizeof(v.admission), unsafe.Sizeof(v.policy), unsafe.Sizeof(v.verified.Profile), unsafe.Sizeof(old.admission.CurrentState()))
	t.Logf("workspace=%d production-reserve=%d retained=%d policy-backing=%d opaque-envelope=%d", maintenanceVerificationWorkspace(limits), reserved, bounds.RetainedBytes, maintenanceRuntimePolicyBackingV1(v.policy), maintenanceOpaqueCharge(len(v.verified.ExactArtifact), len(v.verified.ExactSignedObject), v.verified.Profile))
	t.Logf("borrow-holder=%d endpoint=%d prefix=%d services=%d update=%d default80MiB-headroom=%d", unsafe.Sizeof(liveRuntimeCurrentBorrowV1{}), unsafe.Sizeof(runtimepolicy.EndpointV2{}), unsafe.Sizeof(runtimepolicy.PrefixV2{}), unsafe.Sizeof(runtimepolicy.ServicesV1{}), unsafe.Sizeof(runtimepolicy.UpdateV1{}), uint64(80<<20)-reserved)
	limits.OwnedBudgetBytes = 80 << 20
	atDefault, err := VerifyLiveRuntimeCurrentForRecipient(first.Artifact, now, old.admission.CurrentState(), old.request, old.private, limits)
	if err != nil {
		t.Fatalf("standalone default cap refused: %v", err)
	}
	atDefault.Destroy()
}

func TestLiveRuntimeCurrentCopiedOwnerAndConcurrentBorrow(t *testing.T) {
	old, first, _, now := maintenanceFixture(t)
	v, err := VerifyLiveRuntimeCurrentForRecipient(first.Artifact, now, old.admission.CurrentState(), old.request, old.private, old.limits)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Destroy()
	var copied LiveRuntimeCurrentV1
	// Deliberately emulate an invalid copy without invoking go vet's ordinary
	// copylocks diagnostic. No operation is active while this test makes it.
	reflect.ValueOf(&copied).Elem().Set(reflect.ValueOf(v).Elem())
	copied.Destroy()
	if copied.CheckAtV1(now) == nil {
		t.Fatal("copied owner accepted")
	}
	if _, err := copied.BoundsV1(); err == nil {
		t.Fatal("copied owner bounds accepted")
	}
	if copied.WithVerifiedV1(func(profile.OfflineVerifiedArtifact, lifecycle.VerifiedState, runtimepolicy.PolicyV2, time.Time) error {
		return nil
	}) == nil {
		t.Fatal("copied borrow accepted")
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- v.WithVerifiedV1(func(got profile.OfflineVerifiedArtifact, _ lifecycle.VerifiedState, _ runtimepolicy.PolicyV2, _ time.Time) error {
			close(entered)
			<-release
			if !bytes.Equal(got.ExactArtifact, first.Artifact) {
				return errors.New("active backing cleared")
			}
			return nil
		})
	}()
	<-entered
	if v.CheckAtV1(now) == nil {
		t.Fatal("concurrent check accepted")
	}
	if v.WithVerifiedV1(func(profile.OfflineVerifiedArtifact, lifecycle.VerifiedState, runtimepolicy.PolicyV2, time.Time) error {
		return nil
	}) == nil {
		t.Fatal("concurrent borrow accepted")
	}
	v.Destroy()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if v.WithVerifiedV1(func(profile.OfflineVerifiedArtifact, lifecycle.VerifiedState, runtimepolicy.PolicyV2, time.Time) error {
		return nil
	}) == nil {
		t.Fatal("retired owner reused")
	}
}

func TestLiveRuntimeCurrentEachSignedDeadline(t *testing.T) {
	old, first, _, now, dir := maintenanceFixtureFull(t)
	state, master, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(master)
	root, err := recoveryRootForState(state, filepath.Join(filepath.Dir(dir), "recovery.kurd-recovery"), []byte("state v2 test recovery passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	end := now.Add(5 * time.Minute)
	for _, source := range []string{"profile", "root", "delegation", "revocation", "staleness", "tls"} {
		t.Run(source, func(t *testing.T) {
			encoded := maintenanceRewrite(t, old, first.Artifact, dir, func(p *envelope.CanonicalProfileV1, b *liveProfileBundleV2) {
				switch source {
				case "profile":
					p.ValidUntil = end.Unix()
				case "root":
					b.Root.ValidUntil = end.Unix()
				case "delegation":
					b.Delegation.ValidUntil = end.Unix()
					b.DelegationPayload, err = profile.EncodeIssuerDelegationV1(b.Delegation)
					if err != nil {
						t.Fatal(err)
					}
					b.DelegationSignature, err = (p256Signer{keyID: b.Root.Keys[0].KeyID, key: root}).Sign(b.Root.Keys[0], b.DelegationPayload)
					if err != nil {
						t.Fatal(err)
					}
				case "revocation", "staleness":
					if source == "revocation" {
						b.Revocations.ExpiresAt = end.Unix()
					} else {
						b.Revocations.MaxOfflineStalenessSecs = uint64(end.Unix() - b.Revocations.IssuedAt - 1)
					}
					b.RevocationPayload, err = profile.EncodeRevocationSetV1(b.Revocations)
					if err != nil {
						t.Fatal(err)
					}
					b.RevocationSignature, err = (p256Signer{keyID: b.Root.Keys[0].KeyID, key: root}).Sign(b.Root.Keys[0], b.RevocationPayload)
					if err != nil {
						t.Fatal(err)
					}
				case "tls":
					policy, e := runtimepolicy.DecodeRuntimeAt(p.Policy, now)
					if e != nil {
						t.Fatal(e)
					}
					defer destroyMaintenancePolicy(&policy)
					_, key, e := ed25519.GenerateKey(rand.Reader)
					if e != nil {
						t.Fatal(e)
					}
					defer clear(key)
					cert := &x509.Certificate{SerialNumber: big.NewInt(71), DNSNames: []string{policy.TLSServerName}, NotBefore: now.Add(-time.Hour), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
					if ip := net.ParseIP(policy.TLSServerName); ip != nil {
						cert.IPAddresses = []net.IP{ip}
					}
					policy.TLSLeafDER, e = x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
					if e != nil {
						t.Fatal(e)
					}
					policy.TLSLeafSHA256 = sha256.Sum256(policy.TLSLeafDER)
					policy.RelayAdmissionDigest, e = runtimepolicy.RelayAdmissionDigestRuntimeAt(policy, now)
					if e != nil {
						t.Fatal(e)
					}
					p.Policy, e = runtimepolicy.EncodeRuntimeAt(policy, now)
					if e != nil {
						t.Fatal(e)
					}
				}
			})
			defer clear(encoded)
			// Rewritten signed bytes receive a genuine new activation receipt. Never
			// fabricate a successful current state merely to test the deadline check.
			b, verified, opener, resolver, e := maintenanceVerifyCore(encoded, now, 1, old.request, old.private)
			if e != nil {
				t.Fatal(e)
			}
			defer destroyMaintenanceBundle(&b)
			defer destroyLiveMaintenanceOffline(&verified)
			defer opener.Destroy()
			var diagnostic liveMaintenanceDiagnostic
			a, e := liveActivationRequestFromVerified(encoded, now, lifecycle.VerifiedState{}, resolver, opener, liveResourceTypedFirstV1, &diagnostic, verified)
			if e != nil {
				t.Fatal(e)
			}
			defer diagnostic.destroyRequest()
			initial, e := profile.VerifyInitialActivationAdmission(a)
			if e != nil {
				t.Fatal(e)
			}
			defer initial.Destroy()
			v, e := VerifyLiveRuntimeCurrentForRecipient(encoded, now, initial.CurrentState(), old.request, old.private, old.limits)
			if e != nil {
				t.Fatal(e)
			}
			defer v.Destroy()
			if e = v.WithVerifiedV1(func(_ profile.OfflineVerifiedArtifact, _ lifecycle.VerifiedState, _ runtimepolicy.PolicyV2, got time.Time) error {
				if !got.Equal(end) {
					t.Fatalf("%s end=%v want=%v", source, got, end)
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			if v.CheckAtV1(end.Add(-time.Nanosecond)) != nil || v.CheckAtV1(end) == nil {
				t.Fatal("exclusive earliest deadline lost")
			}
		})
	}
}

func TestLiveRuntimeCurrentRetainedChargeExcludesEmbeddedHolders(t *testing.T) {
	old, first, _, now := maintenanceFixture(t)
	v, err := VerifyLiveRuntimeCurrentForRecipient(first.Artifact, now, old.admission.CurrentState(), old.request, old.private, old.limits)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Destroy()
	p := v.verified.Profile
	// Root already physically embeds OfflineVerifiedArtifact.Profile and
	// VerifiedActivationAdmission.record.Profile. Only their backing is extra.
	want := uint64(unsafe.Sizeof(*v)) + uint64(cap(v.verified.ExactArtifact)+cap(v.verified.ExactSignedObject))
	want += maintenanceProfileCharge(p) - uint64(unsafe.Sizeof(p))
	want += maintenanceOpaqueCharge(len(v.verified.ExactArtifact), len(v.verified.ExactSignedObject), p) - uint64(unsafe.Sizeof(v.admission)) - uint64(unsafe.Sizeof(p))
	want += uint64(len(v.verified.Metadata.Class)+len(v.verified.Metadata.AudienceClass)+len(v.verified.Metadata.RecipientHint)) + maintenanceRuntimePolicyBackingV1(v.policy)
	if v.retainedChargeV1() != want {
		t.Fatalf("embedded holder charged twice: got=%d want=%d", v.retainedChargeV1(), want)
	}
}

func TestLiveRuntimeCurrentPolicyCapacityAndPrivateGraph(t *testing.T) {
	p := runtimepolicy.PolicyV2{
		LiveProgram: make([]byte, 1, 9), TLSLeafDER: make([]byte, 1, 10),
		ClientIPv4: make([]byte, 1, 11), DNSIPv4: make([]byte, 1, 12), ClientIPv6: make([]byte, 1, 13), DNSIPv6: make([]byte, 1, 14),
		Endpoints: make([]runtimepolicy.EndpointV2, 1, 2), Routes: make([]runtimepolicy.PrefixV2, 1, 3), DNSServers: make([][]byte, 1, 4),
		AllowedIPModes: make([]runtimepolicy.IPModeV2, 1, 5), AllowedProtocols: make([]runtimepolicy.PayloadProtocolV2, 1, 6),
		Fallback:     runtimepolicy.FallbackV2{EndpointIndexes: make([]uint8, 1, 15)},
		WireProtocol: "aa", CarrierFamily: "bbb", ClientAuthKeyID: "cccc", RelayAuthKeyID: "ddddd", TLSServerName: "eeeeee",
		Services: &runtimepolicy.ServicesV1{Update: &runtimepolicy.UpdateV1{URL: "abc", ProfileID: "defg"}},
	}
	p.Endpoints[0].Address = make([]byte, 1, 16)
	p.Routes[0].Address = make([]byte, 1, 17)
	p.DNSServers[0] = make([]byte, 1, 18)
	p.AllowedIPModes[0] = "hello"
	p.AllowedProtocols[0] = "world!"
	// amd64 layouts are checked freshly above: endpoint40, prefix32, slice24,
	// string16. This independent capacity total catches len-only omissions.
	want := uint64(9+10+11+12+13+14+15+16+17+18+2+3+4+5+6+5+6+2*40+3*32+4*24+5*16+6*16) + uint64(unsafe.Sizeof(runtimepolicy.ServicesV1{})) + uint64(unsafe.Sizeof(runtimepolicy.UpdateV1{})) + 7
	if got := maintenanceRuntimePolicyBackingV1(p); got != want {
		t.Fatalf("capacity backing got=%d want=%d", got, want)
	}
	fallback, program, endpoint, mode := p.Fallback.EndpointIndexes, p.LiveProgram, p.Endpoints[0].Address, p.AllowedIPModes
	fallback[0], program[0], endpoint[0] = 1, 2, 3
	destroyMaintenancePolicy(&p)
	if fallback[0] != 0 || program[0] != 0 || endpoint[0] != 0 || mode[0] != "" {
		t.Fatal("owned policy backing not cleared")
	}
	forbidden := map[reflect.Type]bool{
		reflect.TypeFor[enrollment.PrivateBundleV1](): true, reflect.TypeFor[enrollment.PublicRequestV1](): true,
		reflect.TypeFor[liveProfileBundleV2](): true, reflect.TypeFor[liveResourceRecipientOpener](): true,
		reflect.TypeFor[profile.RecipientResolver](): true,
	}
	seen := map[reflect.Type]bool{}
	var inspect func(reflect.Type)
	inspect = func(typ reflect.Type) {
		if forbidden[typ] {
			t.Fatalf("private credential/provider graph retained: %v", typ)
		}
		if seen[typ] {
			return
		}
		seen[typ] = true
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			inspect(typ.Elem())
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				inspect(typ.Field(i).Type)
			}
		}
	}
	inspect(reflect.TypeFor[LiveRuntimeCurrentV1]())
}
