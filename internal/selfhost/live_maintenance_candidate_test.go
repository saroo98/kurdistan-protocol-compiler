// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"kurdistan/internal/crypto/profilehpke"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
)

func maintenanceFixture(t *testing.T) (*LiveMaintenanceAdmission, IssuedProfile, IssuedProfile, time.Time) {
	o, a, b, now, _ := maintenanceFixtureFull(t)
	return o, a, b, now
}

func TestLiveMaintenancePerInputWorkspacePreservesLargerCandidateLimit(t *testing.T) {
	previous, first, next, now := maintenanceFixture(t)
	if len(next.Artifact) <= len(first.Artifact) {
		t.Fatal("fixture must exercise a larger legitimate successor", len(first.Artifact), len(next.Artifact))
	}
	limits := previous.limits
	// This is the verifier's residual, not the outer Android owner's budget.
	// Its native/C/Java backing is already retained outside this proof.
	limits.OwnedBudgetBytes = 40 << 20
	owner, err := NewLiveMaintenanceAdmissionForRecipient(first.Artifact, now, previous.admission.CurrentState(), previous.request, previous.private, limits)
	if err != nil {
		t.Fatal("actual current under40MiB residual", err)
	}
	defer owner.Destroy()
	if owner.limits != limits || owner.limits.MaxArtifactBytes <= uint32(len(next.Artifact)) {
		t.Fatal("current size replaced future cap")
	}
	if err := owner.RevalidateAt(now); err != nil {
		t.Fatal("current revalidation under40MiB residual", err)
	}
	candidate, noChange, err := owner.VerifyCandidateAt(next.Artifact, now)
	if err != nil || candidate == nil || noChange {
		t.Fatal("larger authenticated successor under40MiB residual", err)
	}
	if candidate.ArtifactLength() != len(next.Artifact) {
		t.Fatal("candidate bytes truncated")
	}
	candidate.Destroy()
	if owner.limits != limits {
		t.Fatal("candidate sizing mutated future limits")
	}
	oversize := make([]byte, int(min(limits.MaxArtifactBytes, owner.services.Update.MaxArtifactBytes))+1)
	defer clear(oversize)
	if c, _, err := owner.VerifyCandidateAt(oversize, now); c != nil || maintenanceReason(t, err) != LiveMaintenanceSizeLimit {
		t.Fatal("original/signed maximum bypassed")
	}
}

func maintenanceFixtureFull(t *testing.T, rotateIssuer ...bool) (*LiveMaintenanceAdmission, IssuedProfile, IssuedProfile, time.Time, string) {
	t.Helper()
	dir, recovery, passphrase := initializedV2TestState(t)
	now := time.Unix(1760000010, 0).UTC()
	if err := ConfirmRecovery(dir, recovery, passphrase, now); err != nil {
		t.Fatal(err)
	}
	first, request, private := createForServicesV3(t, dir, "maintenance", now, servicesForIssuanceV3())
	_, _, resolver, opener, err := liveRecipientProvidersWithResourceMode(first.Artifact, now, 1, request, private, liveResourceTypedFirstV1)
	if err != nil {
		t.Fatal(err)
	}
	defer opener.Destroy()
	a, err := liveActivationRequestWithResourceMode(first.Artifact, now, lifecycle.VerifiedState{}, resolver, opener, liveResourceTypedFirstV1)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := profile.VerifyInitialActivationAdmission(a)
	if err != nil {
		t.Fatal(err)
	}
	defer admitted.Destroy()
	owner, err := NewLiveMaintenanceAdmissionForRecipient(first.Artifact, now, admitted.CurrentState(), request, private, LiveMaintenanceLimits{128 << 20, envelope.MaxTotalInputBytes, 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Destroy)
	next, err := RotateProfile(dir, RotateProfileOptions{ProfileID: first.ProfileID, RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now.Add(time.Minute), ValidFor: 24 * time.Hour, LiveProgram: testLiveProgramV1(t, 1702), RegistryDir: filepath.Join(filepath.Dir(dir), "registry")})
	if err != nil {
		t.Fatal(err)
	}
	if len(rotateIssuer) > 0 && rotateIssuer[0] {
		if _, err := RotateIssuer(dir, RecoveryActionOptions{RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		state, master, err := loadState(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(master)
		next.Artifact = maintenanceRewrite(t, owner, next.Artifact, dir, func(p *envelope.CanonicalProfileV1, b *liveProfileBundleV2) {
			b.IssuerKey, b.IssuerPublicDER = state.IssuerKey, state.IssuerPublicDER
			b.Delegation, b.DelegationPayload, b.DelegationSignature = state.Delegation, state.DelegationPayload, state.DelegationSig
			b.Revocations, b.RevocationPayload, b.RevocationSignature = state.Revocations, state.RevocationPayload, state.RevocationSig
			p.RevocationEpoch = state.Revocations.Epoch
		})
	}
	return owner, first, next, now.Add(time.Minute), dir
}

func TestLiveMaintenanceSameRootIssuerAndActiveReplacementCurrent(t *testing.T) {
	o, _, next, now, _ := maintenanceFixtureFull(t, true)
	c, _, err := o.VerifyCandidateAt(next.Artifact, now)
	if err != nil {
		t.Fatal(err)
	}
	preview, _ := c.PreviewV1()
	if preview.RotationFlags&1 == 0 || preview.ChangedCategories[0] != 1 {
		t.Fatal("same-root verified issuer change missing")
	}
	b, v, opener, resolver, err := maintenanceVerifyCore(next.Artifact, now, 1, o.request, o.private)
	if err != nil {
		t.Fatal(err)
	}
	defer opener.Destroy()
	defer destroyLiveMaintenanceOffline(&v)
	defer destroyMaintenanceBundle(&b)
	var d liveMaintenanceDiagnostic
	a, err := liveActivationRequestFromVerified(next.Artifact, now, o.admission.CurrentState(), resolver, opener, liveResourceTypedFirstV1, &d, v)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := profile.VerifyReplacementActivationAdmission(o.admission, a)
	if err != nil {
		t.Fatal(err)
	}
	defer proof.Destroy()
	active, err := NewLiveMaintenanceAdmissionForRecipient(next.Artifact, now, proof.CurrentState(), o.request, o.private, o.limits)
	if err != nil {
		t.Fatalf("already-active replacement reconstruction: %v", err)
	}
	defer active.Destroy()
	if active.admission.CurrentState() != proof.CurrentState() || active.RevalidateAt(now) != nil {
		t.Fatal("replacement current identity changed")
	}
	checked, bounds, err := VerifyLiveMaintenanceCurrentForRecipient(next.Artifact, now, next.Generation, o.request, o.private, o.limits)
	if err != nil || !bytes.Equal(checked.ExactArtifact, next.Artifact) || bounds.RetainedBytes == 0 || bounds.OperationReservedBytes != 0 {
		t.Fatalf("fresh bounded check failed: %v", err)
	}
	wantRetained := uint64(unsafe.Sizeof(checked)+uintptr(cap(checked.ExactArtifact)+cap(checked.ExactSignedObject))) + maintenanceProfileCharge(checked.Profile) + uint64(len(checked.Metadata.Class)+len(checked.Metadata.AudienceClass)+len(checked.Metadata.RecipientHint))
	if bounds.RetainedBytes != wantRetained {
		t.Fatal("fresh result metadata backing omitted")
	}
	destroyLiveMaintenanceOffline(&checked)
}

func maintenanceRewrite(t *testing.T, o *LiveMaintenanceAdmission, encoded []byte, dir string, mutate func(*envelope.CanonicalProfileV1, *liveProfileBundleV2)) []byte {
	t.Helper()
	b, err := decodeLiveBundle(encoded)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := envelope.ParseSealedProfileOpaque(b.SealedProfile)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := profilehpke.NewOpener(o.binding, o.private.RecipientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer opener.Close()
	plain, err := opener.OpenOffline(o.binding, sealed.Protected, sealed.Encapsulation, sealed.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	signed, err := envelope.ParseSignedProfileOpaque(plain)
	if err != nil {
		t.Fatal(err)
	}
	p, err := envelope.DecodeCanonicalProfileV1(signed.Payload)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&p, &b)
	payload, err := envelope.EncodeCanonicalProfileV1(p)
	if err != nil {
		t.Fatal(err)
	}
	context, err := envelope.DecodeSignedProtectedContextV1(signed.Protected)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := envelope.BuildSignedProtectedHeaders([]byte(b.IssuerKey.KeyID), context.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	structure, err := envelope.BuildCOSESigStructure(protected, payload)
	if err != nil {
		t.Fatal(err)
	}
	state, master, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(master)
	der, err := openWithKey(master, state.IssuerSecret, []byte(state.DeploymentID+"|"+state.IssuerKey.KeyID))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	issuer, err := parseP256Private(der)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := (p256Signer{keyID: b.IssuerKey.KeyID, key: issuer}).Sign(b.IssuerKey, structure)
	if err != nil {
		t.Fatal(err)
	}
	object, err := envelope.BuildTaggedCOSESign1(protected, payload, signature)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := profilehpke.NewSealer(o.binding, o.request.RecipientPublic)
	if err != nil {
		t.Fatal(err)
	}
	enc, cipher, err := sealer.SealOffline(o.binding, sealed.Protected, object)
	if err != nil {
		t.Fatal(err)
	}
	b.SealedProfile, err = envelope.BuildSealedFrame(sealed.Protected, enc, cipher)
	if err != nil {
		t.Fatal(err)
	}
	out, err := encodeLiveBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLiveMaintenanceSignedCandidateFailures(t *testing.T) {
	o, _, next, now, dir := maintenanceFixtureFull(t)
	for _, tc := range []struct {
		name   string
		mutate func(*envelope.CanonicalProfileV1, *liveProfileBundleV2)
		want   LiveMaintenanceFailureV1
	}{
		{"profile", func(p *envelope.CanonicalProfileV1, _ *liveProfileBundleV2) { p.ProfileID += "x" }, LiveMaintenanceProfileMismatch},
		{"scope", func(p *envelope.CanonicalProfileV1, _ *liveProfileBundleV2) { p.RevocationScope += "x" }, LiveMaintenanceProfileMismatch},
		{"lineage", func(p *envelope.CanonicalProfileV1, _ *liveProfileBundleV2) { p.LineageID += "x" }, LiveMaintenanceProfileMismatch},
		{"contract", func(p *envelope.CanonicalProfileV1, _ *liveProfileBundleV2) { p.ContractVersion += "x" }, LiveMaintenanceProfileMismatch},
		{"predecessor", func(p *envelope.CanonicalProfileV1, _ *liveProfileBundleV2) { p.PreviousContentID = "wrong" }, LiveMaintenanceRollback},
		{"generation-gap", func(p *envelope.CanonicalProfileV1, _ *liveProfileBundleV2) { p.Generation++ }, LiveMaintenanceRollback},
		{"expired", func(p *envelope.CanonicalProfileV1, _ *liveProfileBundleV2) {
			p.ValidFrom = now.Unix() - 1
			p.ValidUntil = now.Unix()
		}, LiveMaintenanceExpired},
		{"future", func(p *envelope.CanonicalProfileV1, _ *liveProfileBundleV2) { p.ValidFrom = now.Unix() + 1 }, LiveMaintenanceExpired},
		{"root-view", func(_ *envelope.CanonicalProfileV1, b *liveProfileBundleV2) { b.Root.ViewID += "x" }, LiveMaintenanceRootRotationRejected},
		{"tls-time", func(p *envelope.CanonicalProfileV1, _ *liveProfileBundleV2) {
			policy, err := runtimepolicy.DecodeRuntimeAt(p.Policy, now)
			if err != nil {
				t.Fatal(err)
			}
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
			cert := &x509.Certificate{SerialNumber: big.NewInt(77), DNSNames: []string{policy.TLSServerName}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(-time.Second), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			if ip := net.ParseIP(policy.TLSServerName); ip != nil {
				cert.DNSNames = nil
				cert.IPAddresses = []net.IP{ip}
			}
			policy.TLSLeafDER, err = x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
			if err != nil {
				t.Fatal(err)
			}
			policy.TLSLeafSHA256 = sha256.Sum256(policy.TLSLeafDER)
			at := now.Add(-time.Minute)
			policy.RelayAdmissionDigest, err = runtimepolicy.RelayAdmissionDigestRuntimeAt(policy, at)
			if err != nil {
				t.Fatal(err)
			}
			p.Policy, err = runtimepolicy.EncodeRuntimeAt(policy, at)
			if err != nil {
				t.Fatal(err)
			}
		}, LiveMaintenanceExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := maintenanceRewrite(t, o, next.Artifact, dir, tc.mutate)
			c, noChange, err := o.VerifyCandidateAt(raw, now)
			if c != nil || noChange || maintenanceReason(t, err) != tc.want {
				t.Fatalf("wrong categorical failure: %v", err)
			}
			if o.Bounds().CandidateBytes != 0 || o.RevalidateAt(now) != nil {
				t.Fatal("candidate failure changed current authority")
			}
		})
	}
}

func TestLiveMaintenanceNonidenticalCurrentAndRecipientFailure(t *testing.T) {
	o, first, next, now, dir := maintenanceFixtureFull(t)
	raw := maintenanceRewrite(t, o, first.Artifact, dir, func(*envelope.CanonicalProfileV1, *liveProfileBundleV2) {})
	if bytes.Equal(raw, first.Artifact) {
		t.Fatal("fixture did not change sealed outer bytes")
	}
	if c, noChange, err := o.VerifyCandidateAt(raw, now); c != nil || noChange || maintenanceReason(t, err) != LiveMaintenanceRollback {
		t.Fatal("different current-generation bytes became no-change")
	}
	b, err := decodeLiveBundle(next.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := envelope.ParseSealedProfileOpaque(b.SealedProfile)
	if err != nil {
		t.Fatal(err)
	}
	sealed.Ciphertext[0] ^= 1
	b.SealedProfile, err = envelope.BuildSealedFrame(sealed.Protected, sealed.Encapsulation, sealed.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = encodeLiveBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	if c, noChange, err := o.VerifyCandidateAt(raw, now); c != nil || noChange || maintenanceReason(t, err) != LiveMaintenanceWrongRecipient {
		t.Fatal("failed recipient open misclassified")
	}
	// Narrow arithmetic boundary check. No fabricated owner is admitted by a
	// public constructor: this exercises the nonwrapping private guard itself.
	original := o.value.Generation
	o.value.Generation = envelope.MaxCanonicalGeneration
	if _, _, _, err := o.verifyCandidate([]byte{0xff}, now); maintenanceReason(t, err) != LiveMaintenanceRollback {
		t.Fatal("maximum-generation guard did not precede increment/decode")
	}
	o.value.Generation = original
}

func TestLiveMaintenanceCandidateExactNoChangeAndOwnership(t *testing.T) {
	owner, first, next, now := maintenanceFixture(t)
	if c, noChange, err := owner.VerifyCandidateAt(first.Artifact, now); err != nil || c != nil || !noChange {
		t.Fatalf("verified identical bytes: %v %v", noChange, err)
	}
	c, noChange, err := owner.VerifyCandidateAt(next.Artifact, now)
	if err != nil || c == nil || noChange {
		t.Fatalf("predecessor-revoking replacement rejected: %v", err)
	}
	preview, ok := c.PreviewV1()
	if !ok || !preview.DeploymentMatch || preview.Generation != next.Generation || preview.ArtifactLength != uint32(len(next.Artifact)) {
		t.Fatal("candidate preview not authenticated exact metadata")
	}
	if other, _, err := owner.VerifyCandidateAt(next.Artifact, now); other != nil || maintenanceReason(t, err) != LiveMaintenanceInvalidState {
		t.Fatal("competing candidate discarded live slot")
	}
	short := bytes.Repeat([]byte{0xa5}, len(next.Artifact)-1)
	if n, err := owner.CopyCandidateInto(c, short); n != 0 || maintenanceReason(t, err) != LiveMaintenanceSizeLimit || !bytes.Equal(short, bytes.Repeat([]byte{0xa5}, len(short))) {
		t.Fatal("short copy changed output or consumed")
	}
	if err := owner.RevalidateCandidateAt(c, now); err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, c.ArtifactLength())
	if n, err := owner.CopyCandidateInto(c, dst); err != nil || n != len(next.Artifact) || !bytes.Equal(dst, next.Artifact) {
		t.Fatal("candidate lost complete exact bundle")
	}
	foreign := &LiveMaintenanceAdmission{}
	if _, err := foreign.CopyCandidateInto(c, dst); maintenanceReason(t, err) != LiveMaintenanceInvalidState {
		t.Fatal("foreign owner consumed candidate")
	}
	charge := owner.Bounds().CandidateBytes
	if charge == 0 {
		t.Fatal("candidate uncharged")
	}
	owned := c.artifact
	c.Destroy()
	c.Destroy()
	if _, ok := c.PreviewV1(); ok || c.ArtifactLength() != 0 || !c.AuthorityDeadline().IsZero() || owner.Bounds().CandidateBytes != 0 || !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("candidate release retained authority/backing")
	}
}
