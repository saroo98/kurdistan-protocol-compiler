// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"reflect"
	"time"
	"unsafe"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
)

// Candidate ownership is serialized with its exact parent. Preview is cached
// verification-time information, not a fresh authority or publication lease.
type LiveMaintenanceCandidate struct {
	owner    *LiveMaintenanceAdmission
	artifact []byte
	deadline time.Time
	preview  LiveMaintenancePreviewV1
	charge   uint64
}

func (c *LiveMaintenanceCandidate) live() bool {
	return c != nil && c.owner != nil && len(c.owner.artifact) > 0 && c.owner.candidate == c && len(c.artifact) > 0
}
func (c *LiveMaintenanceCandidate) ArtifactLength() int {
	if !c.live() {
		return 0
	}
	return len(c.artifact)
}
func (c *LiveMaintenanceCandidate) AuthorityDeadline() time.Time {
	if !c.live() {
		return time.Time{}
	}
	return c.deadline
}
func (c *LiveMaintenanceCandidate) PreviewV1() (LiveMaintenancePreviewV1, bool) {
	if !c.live() {
		return LiveMaintenancePreviewV1{}, false
	}
	return c.preview, true
}
func (c *LiveMaintenanceCandidate) Destroy() {
	if c == nil {
		return
	}
	if c.owner != nil && c.owner.candidate == c {
		c.owner.candidate = nil
		c.owner.bounds.CandidateBytes = 0
		c.owner.bounds.RetainedBytes -= c.charge
	}
	clear(c.artifact)
	*c = LiveMaintenanceCandidate{}
}

func (o *LiveMaintenanceAdmission) VerifyCandidateAt(encoded []byte, now time.Time) (*LiveMaintenanceCandidate, bool, error) {
	if o == nil || len(o.artifact) == 0 || o.candidate != nil {
		return nil, false, maintenanceFailure(LiveMaintenanceInvalidState)
	}
	if err := o.RevalidateAt(now); err != nil {
		return nil, false, err
	}
	if o.services == nil || o.services.Update == nil || o.services.Update.ProfileID != o.value.ProfileID {
		return nil, false, maintenanceFailure(LiveMaintenanceNotAdmitted)
	}
	if len(encoded) == 0 || uint64(len(encoded)) > uint64(min(o.limits.MaxArtifactBytes, o.services.Update.MaxArtifactBytes)) {
		return nil, false, maintenanceFailure(LiveMaintenanceSizeLimit)
	}
	if bytes.Equal(encoded, o.artifact) {
		return nil, true, nil
	}
	artifact, deadline, preview, err := o.verifyCandidate(encoded, now)
	if err != nil {
		return nil, false, err
	}
	c := &LiveMaintenanceCandidate{owner: o, artifact: artifact, deadline: deadline, preview: preview}
	c.charge = uint64(unsafe.Sizeof(*c)) + uint64(cap(artifact))
	o.candidate = c
	o.bounds.CandidateBytes = c.charge
	o.bounds.RetainedBytes += c.charge
	return c, false, nil
}

func (o *LiveMaintenanceAdmission) verifyCandidate(encoded []byte, now time.Time) ([]byte, time.Time, LiveMaintenancePreviewV1, error) {
	fail := func(reason LiveMaintenanceFailureV1) ([]byte, time.Time, LiveMaintenancePreviewV1, error) {
		return nil, time.Time{}, LiveMaintenancePreviewV1{}, maintenanceFailure(reason)
	}
	if o.value.Generation == envelope.MaxCanonicalGeneration {
		return fail(LiveMaintenanceRollback)
	}
	workspace, err := maintenanceInputWorkspaceV1(encoded, o.limits)
	if err != nil {
		return nil, time.Time{}, LiveMaintenancePreviewV1{}, err
	}
	total, ok := maintenanceAdd(o.bounds.RetainedBytes, workspace)
	if !ok || total > o.limits.OwnedBudgetBytes {
		return fail(LiveMaintenanceResourceLimit)
	}
	o.bounds.OperationReservedBytes = workspace
	o.bounds.PeakReservedBytes = max(o.bounds.PeakReservedBytes, total)
	defer func() { o.bounds.OperationReservedBytes = 0 }()
	b, err := decodeLiveBundleWithResourceMode(encoded, liveResourceTypedFirstV1)
	if err != nil {
		var d liveMaintenanceDiagnostic
		d.resource(err)
		return fail(d.reason)
	}
	defer destroyMaintenanceBundle(&b)
	if !bytes.Equal(b.RootPublicDER, o.bundle.RootPublicDER) || !reflect.DeepEqual(b.Root, o.bundle.Root) {
		return fail(LiveMaintenanceRootRotationRejected)
	}
	verifiedBundle, verified, opener, resolver, err := maintenanceVerifyCore(encoded, now, o.value.Generation+1, o.request, o.private, &o.value)
	if err != nil {
		return nil, time.Time{}, LiveMaintenancePreviewV1{}, err
	}
	defer opener.Destroy()
	defer destroyMaintenanceBundle(&verifiedBundle)
	defer destroyLiveMaintenanceOffline(&verified)
	if resolver.(liveRecipientResolver).binding != o.binding {
		return fail(LiveMaintenanceWrongRecipient)
	}
	p := verified.Profile
	if p.ProfileID != o.value.ProfileID || p.ProviderID != o.value.ProviderID || p.LineageID != o.value.LineageID || p.ContractVersion != o.value.ContractVersion || p.RevocationScope != o.value.RevocationScope {
		return fail(LiveMaintenanceProfileMismatch)
	}
	if p.UpdateKind != "replacement" || p.Generation != o.value.Generation+1 || p.PreviousContentID != o.value.ContentID || p.PreviousProviderID != "" || p.RequiredSafetyFloor < o.value.RequiredSafetyFloor || p.RevocationEpoch < o.value.RevocationEpoch {
		return fail(LiveMaintenanceRollback)
	}
	var d liveMaintenanceDiagnostic
	a, err := liveActivationRequestFromVerified(encoded, now, o.admission.CurrentState(), resolver, opener, liveResourceTypedFirstV1, &d, verified)
	defer d.destroyRequest()
	if err != nil {
		return fail(d.reason)
	}
	a.ContractVersion = o.value.ContractVersion
	a.MinSafetyFloor = o.value.RequiredSafetyFloor
	a.MinRootEpoch = o.value.RootEpoch
	a.MinRevocationEpoch = o.value.RevocationEpoch
	resetLiveMaintenanceAdmissionDiagnostic(&d, opener)
	proof, err := profile.VerifyReplacementActivationAdmission(o.admission, a)
	if err != nil {
		return fail(d.reason)
	}
	defer proof.Destroy()
	deadline, services, _, err := maintenanceAuthority(p, b, now)
	destroyMaintenanceServices(services)
	if err != nil {
		return nil, time.Time{}, LiveMaintenancePreviewV1{}, err
	}
	if o.deadline.Before(deadline) {
		deadline = o.deadline
	}
	preview, err := maintenancePreview(o.value, o.bundle, p, b, len(encoded), now)
	if err != nil {
		return nil, time.Time{}, LiveMaintenancePreviewV1{}, err
	}
	artifact := verified.ExactArtifact
	verified.ExactArtifact = nil
	return artifact, deadline, preview, nil
}

func (o *LiveMaintenanceAdmission) RevalidateCandidateAt(c *LiveMaintenanceCandidate, now time.Time) error {
	if !c.live() || c.owner != o {
		return maintenanceFailure(LiveMaintenanceInvalidState)
	}
	if err := o.RevalidateAt(now); err != nil {
		return err
	}
	if !now.Before(c.deadline) {
		return maintenanceFailure(LiveMaintenanceExpired)
	}
	artifact, deadline, preview, err := o.verifyCandidate(c.artifact, now)
	clear(artifact)
	if err != nil {
		return err
	}
	if deadline.Before(c.deadline) {
		c.deadline = deadline
	}
	c.preview = preview
	return nil
}

// CopyCandidateInto is nonconsuming. Only the later protected parent fence may
// combine fresh verification with atomic copy/consume into release output.
func (o *LiveMaintenanceAdmission) CopyCandidateInto(c *LiveMaintenanceCandidate, dst []byte) (int, error) {
	if !c.live() || c.owner != o {
		return 0, maintenanceFailure(LiveMaintenanceInvalidState)
	}
	if len(dst) < len(c.artifact) {
		return 0, maintenanceFailure(LiveMaintenanceSizeLimit)
	}
	return copy(dst, c.artifact), nil
}
