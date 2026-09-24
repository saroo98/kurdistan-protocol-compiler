// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"math"
	"testing"
	"unsafe"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/runtimepolicy"
)

func TestLiveMaintenanceReservationBeforeMalformedDecode(t *testing.T) {
	o, first, next, now := maintenanceFixture(t)
	limits := o.limits
	limits.OwnedBudgetBytes = maintenanceVerificationWorkspace(limits) - 1
	if _, _, err := VerifyLiveMaintenanceCurrentForRecipient([]byte{0xff}, now, 1, o.request, o.private, limits); maintenanceReason(t, err) != LiveMaintenanceResourceLimit {
		t.Fatal("malformed input decoded before reservation")
	}
	limits.OwnedBudgetBytes++
	if _, _, err := VerifyLiveMaintenanceCurrentForRecipient([]byte{0xff}, now, 1, o.request, o.private, limits); maintenanceReason(t, err) != LiveMaintenanceInvalidRequest {
		t.Fatal("reserved malformed input lost structural failure")
	}
	limits.MaxArtifactBytes = uint32(len(first.Artifact) - 1)
	if _, _, err := VerifyLiveMaintenanceCurrentForRecipient(first.Artifact, now, 1, o.request, o.private, limits); maintenanceReason(t, err) != LiveMaintenanceSizeLimit {
		t.Fatal("selected cap ignored")
	}
	if _, ok := maintenanceAdd(math.MaxUint64, 1); ok {
		t.Fatal("reservation addition wrapped")
	}
	original := o.limits.OwnedBudgetBytes
	// Operation input was already checked against retained/signed maxima.
	// Keep the standalone maximum-input tests above unchanged; only this
	// candidate's actual reservation uses its local input-sized limits copy.
	operationLimits := o.limits
	operationLimits.MaxArtifactBytes = uint32(len(next.Artifact))
	o.limits.OwnedBudgetBytes = o.bounds.RetainedBytes + maintenanceVerificationWorkspace(operationLimits) - 1
	if c, noChange, err := o.VerifyCandidateAt(next.Artifact, now); c != nil || noChange || maintenanceReason(t, err) != LiveMaintenanceResourceLimit {
		t.Fatal("one-under operation acquired candidate")
	}
	if o.Bounds().OperationReservedBytes != 0 || o.Bounds().CandidateBytes != 0 {
		t.Fatal("failed reservation retained ownership")
	}
	o.limits.OwnedBudgetBytes++
	exact, _, err := o.VerifyCandidateAt(next.Artifact, now)
	if err != nil || exact == nil {
		t.Fatal("exact per-input operation reservation rejected", err)
	}
	exact.Destroy()
	o.limits.OwnedBudgetBytes = original
	c, _, err := o.VerifyCandidateAt(next.Artifact, now)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Destroy()
	if o.Bounds().RetainedBytes < o.Bounds().CandidateBytes || o.Bounds().PeakReservedBytes > original {
		t.Fatal("candidate overlap uncharged")
	}
	t.Logf("maximum selected artifact=%d publication=%d workspace=%d constructor=%d retained-with-candidate=%d candidate=%d peak=%d", envelope.MaxTotalInputBytes, 8<<20, maintenanceVerificationWorkspace(o.limits), maintenanceVerificationWorkspace(o.limits)+uint64(unsafe.Sizeof(*o)), o.Bounds().RetainedBytes, o.Bounds().CandidateBytes, o.Bounds().PeakReservedBytes)
	t.Logf("fixed owner=%d candidate=%d preview=%d diagnostic=%d bundle=%d publication=%d negative-proof=%d update-op=%d update-policy=%d probe-state=%d services=%d", unsafe.Sizeof(*o), unsafe.Sizeof(*c), unsafe.Sizeof(LiveMaintenancePreviewV1{}), unsafe.Sizeof(liveMaintenanceDiagnostic{}), unsafe.Sizeof(liveProfileBundleV2{}), unsafe.Sizeof(publicationSnapshot{}), unsafe.Sizeof(VerifiedLiveCurrentRevocation{}), unsafe.Sizeof(LiveMaintenanceUpdateOperationV1{}), unsafe.Sizeof(LiveMaintenanceUpdatePolicyV1{}), unsafe.Sizeof(liveMaintenanceProbeState{}), unsafe.Sizeof(runtimepolicy.ServicesV1{}))
}

func TestMaintenanceWorkspaceFactoringPreservesExactPreviousEquation(t *testing.T) {
	for _, size := range []uint32{1, 65536, envelope.MaxTotalInputBytes} {
		n := uint64(size)
		s := min(n, uint64(envelope.MaxSignedObjectBytes))
		p := min(s, uint64(envelope.MaxPayloadBytes))
		r, g := uint64(65536), uint64(49152)
		expected := 4*(2*n+8*1024+uint64(unsafe.Sizeof(liveProfileBundleV2{}))+3*256*24) + 6*maintenanceClone(n) + 6*maintenanceClone(s) + maintenanceClone(p) + maintenanceClone(r) +
			3*(2*p+8*4096) + 7*(2*r+8*2048) + 3*(2*g+8*512) + 4*128*((256+128)*65+512) + 3*(2*2048*24+50*64*96) + 2048*24 +
			3*(maintenanceClone(n)+maintenanceClone(s)+maintenanceProfileMaximum()) + 4*(2*(512*128)+2*512*16+1024) +
			4*maintenanceClone(n) + 2*maintenanceClone(r) + 2*maintenanceClone(g) + 1703936 + 4141 + 4140 + 32*1024 +
			uint64(unsafe.Sizeof(liveCurrentVerificationV1{})) + uint64(unsafe.Sizeof(liveCurrentCoreVerifierV1(nil)))
		actual := maintenanceVerificationWorkspace(LiveMaintenanceLimits{MaxArtifactBytes: size})
		if actual != expected {
			t.Fatalf("full workspace changed at %d: got %d want %d", size, actual, expected)
		}
	}
}
