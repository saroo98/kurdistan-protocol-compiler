// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
)

func TestLiveMaintenanceFirstDiagnosticAndReset(t *testing.T) {
	issued, request, private, now, _ := resourceRecipientFixture(t, nil)
	b, _, resolver, opener, err := liveRecipientProvidersWithResourceMode(issued.Artifact, now, 1, request, private, liveResourceTypedFirstV1)
	if err != nil {
		t.Fatal(err)
	}
	defer opener.Destroy()
	b.DelegationSignature[0] ^= 1
	b.RevocationSignature[0] ^= 1
	bad, err := encodeLiveBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	var diagnostic liveMaintenanceDiagnostic
	_, err = verifyLiveAndroidArtifactCore(bad, now, 1, resolver, opener, liveResourceTypedFirstV1, &diagnostic)
	if err == nil || diagnostic.reason != LiveMaintenanceSignatureInvalid || diagnostic.rejection.Stage != profile.VerificationStageDelegation {
		t.Fatalf("first signature fact lost: %v %+v", err, diagnostic)
	}
	opener.failure = liveResourceFailureSize
	_, err = verifyLiveAndroidArtifactCore(bad, time.Time{}, 1, resolver, opener, liveResourceTypedFirstV1, &diagnostic)
	if err == nil || diagnostic.reason != LiveMaintenanceExpired || opener.failure != liveResourceFailureNone {
		t.Fatalf("stale diagnostic survived next operation: %v %+v", err, diagnostic)
	}
	_, err = verifyLiveAndroidArtifactCore(issued.Artifact, now, 1, resolver, opener, liveResourceTypedFirstV1, &diagnostic)
	if err != nil || diagnostic.reason != 0 {
		t.Fatalf("healthy verification inherited failure: %v %+v", err, diagnostic)
	}
}

func TestLiveMaintenanceCurrentOwnershipAndBudget(t *testing.T) {
	issued, request, private, now, _ := resourceRecipientFixture(t, servicesForIssuanceV3())
	_, _, resolver, opener, err := liveRecipientProvidersWithResourceMode(issued.Artifact, now, 1, request, private, liveResourceTypedFirstV1)
	if err != nil {
		t.Fatal(err)
	}
	defer opener.Destroy()
	a, err := liveActivationRequestWithResourceMode(issued.Artifact, now, lifecycle.VerifiedState{}, resolver, opener, liveResourceTypedFirstV1)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := profile.VerifyInitialActivationAdmission(a)
	if err != nil {
		t.Fatal(err)
	}
	defer admitted.Destroy()
	limits := LiveMaintenanceLimits{OwnedBudgetBytes: 128 << 20, MaxArtifactBytes: envelope.MaxTotalInputBytes, MaxPublicationBytes: 8 << 20}
	if owner, err := NewLiveMaintenanceAdmissionForRecipient(issued.Artifact, now, lifecycle.VerifiedState{}, request, private, limits); owner != nil || maintenanceReason(t, err) != LiveMaintenanceInvalidState {
		t.Fatal("fabricated absent state became current")
	}
	owner, err := NewLiveMaintenanceAdmissionForRecipient(issued.Artifact, now, admitted.CurrentState(), request, private, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Destroy()
	bounds := owner.Bounds()
	workspace, err := maintenanceInputWorkspaceV1(issued.Artifact, limits)
	if err != nil {
		t.Fatal(err)
	}
	exact, ok := maintenanceAdd(workspace, uint64(reflect.TypeOf(LiveMaintenanceAdmission{}).Size()))
	if !ok || exact != bounds.PeakReservedBytes {
		t.Fatalf("constructor peak does not match input workspace plus owned layout: got %d want %d", bounds.PeakReservedBytes, exact)
	}
	if bounds.RetainedBytes == 0 || bounds.PeakReservedBytes <= bounds.RetainedBytes || bounds.OperationReservedBytes != 0 || bounds.PeakReservedBytes > limits.OwnedBudgetBytes {
		t.Fatalf("incorrect reservation: %+v", bounds)
	}
	limits.OwnedBudgetBytes = bounds.PeakReservedBytes - 1
	if other, err := NewLiveMaintenanceAdmissionForRecipient(issued.Artifact, now, admitted.CurrentState(), request, private, limits); other != nil || maintenanceReason(t, err) != LiveMaintenanceResourceLimit {
		t.Fatal("one-under constructor entered verification")
	}
	limits.OwnedBudgetBytes++
	other, err := NewLiveMaintenanceAdmissionForRecipient(issued.Artifact, now, admitted.CurrentState(), request, private, limits)
	if err != nil {
		t.Fatal(err)
	}
	other.Destroy()
	before := bytes.Clone(owner.artifact)
	clear(issued.Artifact)
	clear(private.RecipientPrivate)
	clear(request.Nonce)
	if !bytes.Equal(owner.artifact, before) || owner.RevalidateAt(now) != nil {
		t.Fatal("owner retained borrowed capability")
	}
	deadline := owner.AuthorityDeadline()
	if !deadline.After(now) || owner.RevalidateAt(deadline) == nil {
		t.Fatal("authority outlived exclusive deadline")
	}
	owned := owner.artifact
	owner.Destroy()
	owner.Destroy()
	if !bytes.Equal(owned, make([]byte, len(owned))) || !owner.AuthorityDeadline().IsZero() || owner.Bounds().RetainedBytes != 0 {
		t.Fatal("destroyed owner retained storage/authority")
	}
}

func maintenanceReason(t *testing.T, err error) LiveMaintenanceFailureV1 {
	t.Helper()
	var failure *LiveMaintenanceVerificationError
	if !errors.As(err, &failure) {
		t.Fatalf("missing categorical error: %v", err)
	}
	return failure.Reason()
}

func TestLiveMaintenanceDirectAdmissionExactReopenDiagnostic(t *testing.T) {
	issued, request, private, now, _ := resourceRecipientFixture(t, nil)
	_, _, resolver, opener, err := liveRecipientProvidersWithResourceMode(issued.Artifact, now, 1, request, private, liveResourceTypedFirstV1)
	if err != nil {
		t.Fatal(err)
	}
	defer opener.Destroy()
	var diagnostic liveMaintenanceDiagnostic
	a, err := liveActivationRequestCore(issued.Artifact, now, lifecycle.VerifiedState{}, resolver, opener, liveResourceTypedFirstV1, &diagnostic)
	if err != nil {
		t.Fatal(err)
	}
	opener.failure = liveResourceFailureSize
	diagnostic.reason = LiveMaintenanceSizeLimit
	resetLiveMaintenanceAdmissionDiagnostic(&diagnostic, opener)
	a.Artifact = []byte{0xff}
	if _, err := profile.VerifyActivationAdmission(a); err == nil || diagnostic.reason != LiveMaintenanceInvalidRequest || opener.failure != liveResourceFailureNone {
		t.Fatalf("pre-open rejection used stale fact: %v %+v", err, diagnostic)
	}
	resetLiveMaintenanceAdmissionDiagnostic(&diagnostic, opener)
	a.Artifact = issued.Artifact
	verified, err := profile.VerifyActivationAdmission(a)
	if err != nil || diagnostic.reason != 0 {
		t.Fatalf("original exact bytes no longer admit: %v %+v", err, diagnostic)
	}
	verified.Destroy()
}

func TestLiveMaintenanceRequestCleanupIsLocal(t *testing.T) {
	issued, request, private, now, _ := resourceRecipientFixture(t, nil)
	b, v, opener, resolver, err := maintenanceVerifyCore(issued.Artifact, now, 1, request, private)
	if err != nil {
		t.Fatal(err)
	}
	defer opener.Destroy()
	defer destroyMaintenanceBundle(&b)
	defer destroyLiveMaintenanceOffline(&v)
	var d liveMaintenanceDiagnostic
	a, err := liveActivationRequestFromVerified(issued.Artifact, now, lifecycle.VerifiedState{}, resolver, opener, liveResourceTypedFirstV1, &d, v)
	if err != nil {
		t.Fatal(err)
	}
	owned := a.Delegation.Payload
	proof, err := profile.VerifyActivationAdmission(a)
	if err != nil {
		t.Fatal(err)
	}
	defer proof.Destroy()
	d.destroyRequest()
	if !bytes.Equal(owned, make([]byte, len(owned))) || !bytes.Equal(proof.ExactArtifact(), issued.Artifact) || !bytes.Equal(v.ExactArtifact, issued.Artifact) {
		t.Fatal("operation request backing not retired independently")
	}
}
