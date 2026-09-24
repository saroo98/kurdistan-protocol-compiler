// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"math"
	"reflect"
	"time"
	"unsafe"

	"kurdistan/internal/product/profile"
)

var ErrNoCurrentRevocation = errors.New("selfhost: verified evidence does not revoke current admission")

// VerifiedLiveCurrentRevocation is only an owner-bound negative fact. It does
// not accept remote authority, advance floors, or hold a protected revision.
type VerifiedLiveCurrentRevocation struct {
	owner                *LiveMaintenanceAdmission
	verifiedAt, deadline time.Time
}

func (o *LiveMaintenanceAdmission) VerifyCurrentRevocationAt(encoded []byte, now time.Time) (VerifiedLiveCurrentRevocation, error) {
	if o == nil || len(o.artifact) == 0 {
		return VerifiedLiveCurrentRevocation{}, maintenanceFailure(LiveMaintenanceInvalidState)
	}
	if now.Before(o.lastNow) || !now.Before(o.deadline) {
		return VerifiedLiveCurrentRevocation{}, maintenanceFailure(LiveMaintenanceExpired)
	}
	if len(encoded) == 0 || uint64(len(encoded)) > uint64(o.limits.MaxPublicationBytes) {
		return VerifiedLiveCurrentRevocation{}, maintenanceFailure(LiveMaintenanceSizeLimit)
	}
	// Typed snapshot leaves and canonical output, possible pre-guard4096 root
	// and both revocation lists plus Profiles, then signed-set result/accessor
	// copies. No profile admission or publication history exists in this path.
	u := uint64(o.limits.MaxPublicationBytes)
	workspace := 2*u + 8*(4*4096) + maintenanceClone(u) + 4*4096*24 + 4*(2*512*128+512*16+1024) + 131072 + uint64(unsafe.Sizeof(publicationSnapshot{})) + uint64(unsafe.Sizeof(VerifiedLiveCurrentRevocation{}))
	total, ok := maintenanceAdd(o.bounds.RetainedBytes, workspace)
	if !ok || total > o.limits.OwnedBudgetBytes {
		return VerifiedLiveCurrentRevocation{}, maintenanceFailure(LiveMaintenanceResourceLimit)
	}
	o.bounds.OperationReservedBytes = workspace
	o.bounds.PeakReservedBytes = max(o.bounds.PeakReservedBytes, total)
	defer func() { o.bounds.OperationReservedBytes = 0 }()
	fail := func(reason LiveMaintenanceFailureV1) (VerifiedLiveCurrentRevocation, error) {
		return VerifiedLiveCurrentRevocation{}, maintenanceFailure(reason)
	}
	s, err := decodePublicationSnapshotWithResourceMode(encoded, liveResourceTypedFirstV1)
	if err != nil {
		var d liveMaintenanceDiagnostic
		d.resource(err)
		return fail(d.reason)
	}
	defer func() {
		clear(s.RootPublicDER)
		clear(s.RevocationPayload)
		clear(s.RevocationSignature)
		for _, p := range s.Profiles {
			clear(p)
		}
	}()
	if now.Unix() <= 0 || now.Unix() > math.MaxInt64-300 || s.GeneratedAt > now.Unix()+300 {
		return fail(LiveMaintenanceExpired)
	}
	if !bytes.Equal(s.RootPublicDER, o.bundle.RootPublicDER) || !reflect.DeepEqual(s.Root, o.bundle.Root) {
		return fail(LiveMaintenanceRootRotationRejected)
	}
	if s.DeploymentID != o.bundle.DeploymentID || s.RootFingerprint != o.bundle.RootFingerprint || s.Revocations.Scope != o.value.RevocationScope {
		return fail(LiveMaintenanceProfileMismatch)
	}
	key, err := parseP256Public(o.bundle.RootPublicDER)
	if err != nil {
		return fail(LiveMaintenanceInternalFailure)
	}
	var d liveMaintenanceDiagnostic
	verified, err := profile.VerifySignedRevocationSetWithRejection(o.bundle.Root, profile.SignedRevocationSetV1{Set: s.Revocations, RootKey: o.bundle.Root.Keys[0], Payload: s.RevocationPayload, Signature: s.RevocationSignature}, p256Verifier{keys: map[string]*ecdsa.PublicKey{o.bundle.Root.Keys[0].KeyID: key}}, now.Unix(), d.sink(nil))
	if err != nil {
		return fail(d.reason)
	}
	if s.Revocations.Epoch < o.bundle.Revocations.Epoch {
		return fail(LiveMaintenanceRollback)
	}
	if s.Revocations.Epoch == o.bundle.Revocations.Epoch && !bytes.Equal(s.RevocationPayload, o.bundle.RevocationPayload) {
		return fail(LiveMaintenanceRollback)
	}
	if !verified.RevokesContent(o.value.ContentID) && !contains(s.Revocations.RevokedIssuerKeyIDs, o.bundle.IssuerKey.KeyID) {
		return VerifiedLiveCurrentRevocation{}, ErrNoCurrentRevocation
	}
	r := s.Revocations
	if r.IssuedAt <= 0 || r.MaxOfflineStalenessSecs > uint64(math.MaxInt64-r.IssuedAt-1) {
		return fail(LiveMaintenanceExpired)
	}
	deadline := time.Unix(min(r.ExpiresAt, r.IssuedAt+int64(r.MaxOfflineStalenessSecs)+1), 0)
	if o.deadline.Before(deadline) {
		deadline = o.deadline
	}
	return VerifiedLiveCurrentRevocation{owner: o, verifiedAt: now, deadline: deadline}, nil
}

func (o *LiveMaintenanceAdmission) IsCurrentRevocationAt(p VerifiedLiveCurrentRevocation, now time.Time) bool {
	return o != nil && len(o.artifact) > 0 && p.owner == o && !p.verifiedAt.IsZero() && !now.Before(p.verifiedAt) && !now.Before(o.lastNow) && now.Before(p.deadline) && now.Before(o.deadline)
}
