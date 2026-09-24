// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"math"
	"time"
	"unsafe"

	"kurdistan/internal/runtime"
)

type LiveMaintenanceUpdatePolicyV1 struct {
	URL                     string
	MaxArtifactBytes        uint32
	TimeoutMillis           uint16
	MinCheckIntervalSeconds uint32
	IPFamilies              uint8
	Scope                   runtime.AuthenticatedProbeScopeV1
	Deadline                time.Time
}
type LiveMaintenanceUpdateOperationV1 struct {
	owner      *LiveMaintenanceAdmission
	policy     LiveMaintenanceUpdatePolicyV1
	admittedAt time.Time
}

// SnapshotV1 borrows the immutable owner-retained signed URL. It grants no
// fresh-time authority: the consumer must use IsUpdateOperationAt before use
// and cannot retain any snapshot beyond the joined owner lifetime.
func (u LiveMaintenanceUpdateOperationV1) SnapshotV1() (LiveMaintenanceUpdatePolicyV1, bool) {
	if u.owner == nil || len(u.owner.artifact) == 0 || !u.owner.lastNow.Before(u.policy.Deadline) {
		return LiveMaintenanceUpdatePolicyV1{}, false
	}
	return u.policy, true
}

func (o *LiveMaintenanceAdmission) AdmitUpdateAt(timeout uint16, now time.Time) (LiveMaintenanceUpdateOperationV1, error) {
	if err := o.RevalidateAt(now); err != nil {
		return LiveMaintenanceUpdateOperationV1{}, err
	}
	if timeout < 1000 || timeout > 30000 {
		return LiveMaintenanceUpdateOperationV1{}, maintenanceFailure(LiveMaintenanceInvalidRequest)
	}
	if o.services == nil || o.services.Update == nil || o.services.Update.ProfileID != o.value.ProfileID {
		return LiveMaintenanceUpdateOperationV1{}, maintenanceFailure(LiveMaintenanceNotAdmitted)
	}
	p := o.services.Update
	if uint32(timeout) > p.TimeoutMillis {
		return LiveMaintenanceUpdateOperationV1{}, maintenanceFailure(LiveMaintenanceInvalidRequest)
	}
	if err := o.reserveService(uint64(unsafe.Sizeof(LiveMaintenanceUpdateOperationV1{})) + uint64(unsafe.Sizeof(LiveMaintenanceUpdatePolicyV1{}))); err != nil {
		return LiveMaintenanceUpdateOperationV1{}, err
	}
	defer func() { o.bounds.OperationReservedBytes = 0 }()
	deadline, err := o.serviceDeadline(now, timeout)
	if err != nil {
		return LiveMaintenanceUpdateOperationV1{}, err
	}
	scope, err := runtime.NewAuthenticatedProbeScopeV1(o.value)
	if err != nil {
		return LiveMaintenanceUpdateOperationV1{}, maintenanceFailure(LiveMaintenanceInternalFailure)
	}
	return LiveMaintenanceUpdateOperationV1{owner: o, admittedAt: now, policy: LiveMaintenanceUpdatePolicyV1{URL: p.URL, MaxArtifactBytes: p.MaxArtifactBytes, TimeoutMillis: timeout, MinCheckIntervalSeconds: p.MinCheckIntervalSeconds, IPFamilies: o.families, Scope: scope, Deadline: deadline}}, nil
}

func (o *LiveMaintenanceAdmission) IsUpdateOperationAt(u LiveMaintenanceUpdateOperationV1, now time.Time) bool {
	return o != nil && len(o.artifact) > 0 && u.owner == o && !now.Before(u.admittedAt) && !now.Before(o.lastNow) && now.Before(u.policy.Deadline) && now.Before(o.deadline)
}

type LiveMaintenanceProbeOperationV1 struct{ state *liveMaintenanceProbeState }
type liveMaintenanceProbeState struct {
	owner                *LiveMaintenanceAdmission
	admission            runtime.ProbeAdmissionV1
	scope                runtime.AuthenticatedProbeScopeV1
	admittedAt, deadline time.Time
	charge               uint64
}

func (p LiveMaintenanceProbeOperationV1) live() bool {
	return p.state != nil && p.state.owner != nil && len(p.state.owner.artifact) > 0 && p.state.owner.probe == p.state
}

// AdmissionV1 returns a borrowed selected-target value. Join every consumer
// before Destroy; Target() creates a separate defensive copy for the dialer.
func (p LiveMaintenanceProbeOperationV1) AdmissionV1() (runtime.ProbeAdmissionV1, runtime.AuthenticatedProbeScopeV1, bool) {
	if !p.live() || !p.state.owner.lastNow.Before(p.state.deadline) {
		return runtime.ProbeAdmissionV1{}, runtime.AuthenticatedProbeScopeV1{}, false
	}
	return p.state.admission, p.state.scope, true
}
func (p LiveMaintenanceProbeOperationV1) Deadline() time.Time {
	if !p.live() {
		return time.Time{}
	}
	return p.state.deadline
}
func (p *LiveMaintenanceProbeOperationV1) Destroy() {
	if p == nil || p.state == nil {
		return
	}
	s := p.state
	if s.owner != nil && s.owner.probe == s {
		s.owner.probe = nil
		s.owner.bounds.RetainedBytes -= s.charge
	}
	s.admission.Destroy()
	*s = liveMaintenanceProbeState{}
	p.state = nil
}

func (o *LiveMaintenanceAdmission) AdmitDisconnectedProbeAt(request runtime.ProbeRequestV1, now time.Time) (LiveMaintenanceProbeOperationV1, error) {
	if o == nil || o.probe != nil {
		return LiveMaintenanceProbeOperationV1{}, maintenanceFailure(LiveMaintenanceInvalidState)
	}
	if err := o.RevalidateAt(now); err != nil {
		return LiveMaintenanceProbeOperationV1{}, err
	}
	if o.services == nil || o.services.Probes == nil {
		return LiveMaintenanceProbeOperationV1{}, maintenanceFailure(LiveMaintenanceNotAdmitted)
	}
	// Selected target maximum backing plus Target's one defensive-copy overlap.
	charge := uint64(unsafe.Sizeof(liveMaintenanceProbeState{})) + 2*(maintenanceClone(16)+maintenanceClone(1)+maintenanceClone(2))
	if err := o.reserveService(charge); err != nil {
		return LiveMaintenanceProbeOperationV1{}, err
	}
	defer func() { o.bounds.OperationReservedBytes = 0 }()
	a, err := runtime.AdmitProbePolicyV1(o.services.Probes, request, runtime.ProbeDisconnectedDefaultV1, 1)
	if err != nil {
		reason := LiveMaintenanceNotAdmitted
		if err == runtime.ServiceInvalidRequestV1 {
			reason = LiveMaintenanceInvalidRequest
		}
		return LiveMaintenanceProbeOperationV1{}, maintenanceFailure(reason)
	}
	deadline, err := o.serviceDeadline(now, request.TotalTimeoutMillis)
	if err != nil {
		a.Destroy()
		return LiveMaintenanceProbeOperationV1{}, err
	}
	scope, err := runtime.NewAuthenticatedProbeScopeV1(o.value)
	if err != nil {
		a.Destroy()
		return LiveMaintenanceProbeOperationV1{}, maintenanceFailure(LiveMaintenanceInternalFailure)
	}
	s := &liveMaintenanceProbeState{owner: o, admission: a, scope: scope, admittedAt: now, deadline: deadline, charge: charge}
	o.probe = s
	o.bounds.RetainedBytes += charge
	return LiveMaintenanceProbeOperationV1{state: s}, nil
}

func (o *LiveMaintenanceAdmission) IsProbeOperationAt(p LiveMaintenanceProbeOperationV1, now time.Time) bool {
	return p.live() && p.state.owner == o && !now.Before(p.state.admittedAt) && !now.Before(o.lastNow) && now.Before(p.state.deadline) && now.Before(o.deadline)
}

func (o *LiveMaintenanceAdmission) serviceDeadline(now time.Time, millis uint16) (time.Time, error) {
	if now.Unix() <= 0 || now.Unix() > math.MaxInt64-30 {
		return time.Time{}, maintenanceFailure(LiveMaintenanceExpired)
	}
	d := now.Add(time.Duration(millis) * time.Millisecond)
	if o.deadline.Before(d) {
		d = o.deadline
	}
	if !now.Before(d) {
		return time.Time{}, maintenanceFailure(LiveMaintenanceExpired)
	}
	return d, nil
}
func (o *LiveMaintenanceAdmission) reserveService(valueBytes uint64) error {
	// Three bounded profile-scope strings, SHA256 state/output and fixed values.
	workspace := valueBytes + 3*128 + 1024
	total, ok := maintenanceAdd(o.bounds.RetainedBytes, workspace)
	if !ok || total > o.limits.OwnedBudgetBytes {
		return maintenanceFailure(LiveMaintenanceResourceLimit)
	}
	o.bounds.OperationReservedBytes = workspace
	o.bounds.PeakReservedBytes = max(o.bounds.PeakReservedBytes, total)
	return nil
}
