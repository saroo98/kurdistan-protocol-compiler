// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"context"
	"errors"
	"io"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/relay/tun"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
	"strings"
	"time"
	"unsafe"
)

type RelayServiceOwnerV3 interface {
	TrySubmitReturnPacketV3([]byte) error
	CancelWithReason(error)
}
type SessionDeviceConfigV3 struct {
	Context           context.Context
	MaxPacketBytes    uint32
	AuthorityDeadline time.Time
	BudgetBytes       uint64
	PayloadProtocols  []runtimepolicy.PayloadProtocolV2
	subjectV3         selfhost.RelayRevocationSubjectV3 // trusted node projection only
}
type SessionDeviceBoundsV3 struct{ OwnedBytes, QueuedPayloadBytes uint64 }

// All mutable lifetime state is protected by registry.mu. There is no reverse
// device-to-registry lock order and no lock held across an owner or TUN call.
type SessionDeviceV3 struct {
	registry                            *SessionRegistry
	record                              *sessionRecord
	writer                              tun.ContextPacketWriterV3
	owner                               RelayServiceOwnerV3
	ctx                                 context.Context
	cancel                              context.CancelFunc
	stopHook                            func() bool
	done                                chan struct{}
	deadline                            time.Time
	authorityDeadline                   time.Time
	maximum                             uint32
	protocols                           uint8
	owned                               uint64
	refs                                int
	stopped, attached, ingress, writing bool
	attemptUsed, attemptHeld            bool
	reason                              error
	subjectV3                           selfhost.RelayRevocationSubjectV3
	stopNext                            *SessionDeviceV3
}

// Qualified Go1.26.6 64-bit source envelopes: timer cell covers timerCtx,
// runtime timer, done channel, one child-map group and closure; callback cell
// covers afterFuncCtx, child registration, stop closure and completion channel.
// Four timers cover session/handshake/device/write (Prepare is earlier), two
// callbacks cover device cancellation and the sole TUN write. The remaining
// two channels and four small closures are adapter-owned. No packet backing,
// runtime goroutine stack, kernel/TLS storage or heap/RSS claim is included.
const adapterTimerCellBytesV3 uint64 = 768
const adapterCallbackCellBytesV3 uint64 = 512
const adapterChannelCellBytesV3 uint64 = 128
const adapterClosureCellBytesV3 uint64 = 64
const deviceContextBytesV3 uint64 = 4*adapterTimerCellBytesV3 + 2*adapterCallbackCellBytesV3 + 2*adapterChannelCellBytesV3 + 4*adapterClosureCellBytesV3

func deviceOwnedBytesV3(spec SessionSpec) uint64 {
	// The opaque subject retains seven canonical identity strings, each bounded
	// by the existing 128-byte canonical-ID validators (not a profile/view copy).
	return uint64(unsafe.Sizeof(SessionDeviceV3{})) + uint64(unsafe.Sizeof(sessionRecord{})) + uint64(len(spec.ID)+len(spec.ProfileID)+len(spec.ClientKeyID)) + 7*128 + deviceContextBytesV3
}

func protocolMaskV3(protocols []runtimepolicy.PayloadProtocolV2) (uint8, bool) {
	if len(protocols) < 1 || len(protocols) > 4 {
		return 0, false
	}
	var mask uint8
	for i, p := range protocols {
		if i > 0 && protocols[i-1] >= p {
			return 0, false
		}
		switch p {
		case runtimepolicy.PayloadProtocolICMP:
			mask |= 1
		case runtimepolicy.PayloadProtocolICMPv6:
			mask |= 2
		case runtimepolicy.PayloadProtocolTCP:
			mask |= 4
		case runtimepolicy.PayloadProtocolUDP:
			mask |= 8
		default:
			return 0, false
		}
	}
	return mask, true
}

func (r *SessionRegistry) conflictV3(spec SessionSpec) bool {
	return r.sessions[spec.ID] != nil || r.profiles[spec.ProfileID] != "" || r.clients[spec.ClientKeyID] != "" || spec.AssignedIPv4 != ([4]byte{}) && r.ipv4[spec.AssignedIPv4] != "" || spec.AssignedIPv6 != ([16]byte{}) && r.ipv6[spec.AssignedIPv6] != ""
}

func (r *SessionRegistry) RegisterV3(spec SessionSpec, c SessionDeviceConfigV3) (*SessionDeviceV3, error) {
	mask, valid := protocolMaskV3(c.PayloadProtocols)
	if r == nil || !boundedSessionIDV1(spec.ID) || !boundedSessionIDV1(spec.ProfileID) || !boundedSessionIDV1(spec.ClientKeyID) || !validSessionAddressAuthorityV1(spec) || !valid || c.Context == nil || c.MaxPacketBytes == 0 || c.MaxPacketBytes > 65535 {
		return nil, ErrRegistryConfig
	}
	parentDeadline, ok := c.Context.Deadline()
	if !ok || c.Context.Err() != nil || !parentDeadline.After(time.Now()) || !c.AuthorityDeadline.After(time.Now()) {
		return nil, ErrRegistryConfig
	}
	owned := deviceOwnedBytesV3(spec)
	if c.BudgetBytes < owned || c.BudgetBytes > 128<<20 {
		return nil, ErrSessionLimit
	}
	writer, ok := r.tun.(tun.ContextPacketWriterV3)
	if !ok {
		return nil, ErrRegistryConfig
	}
	control, ok := r.tun.(tun.PacketWriteControlV3)
	if !ok || control.WriteFailureV3() == nil {
		return nil, ErrRegistryConfig
	}
	select {
	case <-control.WriteFailureV3():
		return nil, tun.ErrWriteHealthV3
	default:
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, ErrRegistryClosed
	}
	if len(r.sessions)+r.preparingV3+r.drainingV3 >= r.max {
		r.mu.Unlock()
		return nil, ErrSessionLimit
	}
	if r.conflictV3(spec) {
		r.mu.Unlock()
		return nil, ErrSessionConflict
	}
	r.preparingV3++
	r.mu.Unlock()
	deadline := c.AuthorityDeadline
	if parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	prepare, cancelPrepare := context.WithDeadline(c.Context, deadline)
	prepareErr := control.PreparePacketWriteV3(prepare)
	cancelPrepare()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.preparingV3--
	if r.closed {
		return nil, ErrRegistryClosed
	}
	if prepareErr != nil {
		return nil, ErrRegistryConfig
	}
	select {
	case <-control.WriteFailureV3():
		return nil, tun.ErrWriteHealthV3
	default:
	}
	if c.Context.Err() != nil || !deadline.After(time.Now()) {
		return nil, ErrRegistryConfig
	}
	if r.conflictV3(spec) {
		return nil, ErrSessionConflict
	}
	// Reservation already owns these exact cloned bytes and context metadata.
	spec.ID = strings.Clone(spec.ID)
	spec.ProfileID = strings.Clone(spec.ProfileID)
	spec.ClientKeyID = strings.Clone(spec.ClientKeyID)
	record := &sessionRecord{spec: spec, closed: make(chan struct{})}
	ctx, cancel := context.WithDeadline(c.Context, deadline)
	d := &SessionDeviceV3{registry: r, record: record, writer: writer, ctx: ctx, cancel: cancel, done: make(chan struct{}), deadline: deadline, authorityDeadline: c.AuthorityDeadline, maximum: c.MaxPacketBytes, protocols: mask, owned: owned, refs: 1, subjectV3: c.subjectV3}
	record.v3 = d
	d.stopHook = context.AfterFunc(ctx, func() { _ = d.Close(); d.releaseV3() })
	r.sessions[spec.ID] = record
	r.profiles[spec.ProfileID] = spec.ID
	r.clients[spec.ClientKeyID] = spec.ID
	if spec.AssignedIPv4 != ([4]byte{}) {
		r.ipv4[spec.AssignedIPv4] = spec.ID
	}
	if spec.AssignedIPv6 != ([16]byte{}) {
		r.ipv6[spec.AssignedIPv6] = spec.ID
	}
	r.stats.ActiveSessions = uint64(len(r.sessions))
	return d, nil
}

// The handler, not PacketIO.Close, witnesses the pump's actual Done and all
// caller-owned cleanup. This one-shot reference has no waiter or callback.
func (d *SessionDeviceV3) holdAttemptV3() error {
	if d == nil {
		return ErrRegistryConfig
	}
	d.registry.mu.Lock()
	defer d.registry.mu.Unlock()
	if err := d.authorityLockedV3(time.Now()); err != nil {
		return err
	}
	if d.attemptUsed {
		return ErrSessionConflict
	}
	d.attemptUsed = true
	d.attemptHeld = true
	d.refs++
	return nil
}
func (d *SessionDeviceV3) releaseAttemptV3() {
	if d == nil {
		return
	}
	d.registry.mu.Lock()
	defer d.registry.mu.Unlock()
	if d.attemptHeld {
		d.attemptHeld = false
		d.releaseLockedV3()
	}
}

func (d *SessionDeviceV3) genericReasonV3() error {
	if !d.authorityDeadline.After(time.Now()) {
		return kruntime.ServiceAuthorityExpiredV1
	}
	return kruntime.ServiceCancelledV1
}

func (d *SessionDeviceV3) authorityLockedV3(now time.Time) error {
	if d.reason != nil {
		return d.reason
	}
	if !d.authorityDeadline.After(now) {
		return kruntime.ServiceAuthorityExpiredV1
	}
	if !d.deadline.After(now) {
		return kruntime.ServiceCancelledV1
	}
	if d.stopped || d.ctx.Err() != nil || d.registry.closed || d.registry.sessions[d.record.spec.ID] != d.record {
		return d.genericReasonV3()
	}
	return nil
}

func (d *SessionDeviceV3) checkAuthorityV3(now time.Time) error {
	d.registry.mu.RLock()
	defer d.registry.mu.RUnlock()
	return d.authorityLockedV3(now)
}

func (d *SessionDeviceV3) AttachReturnIngressV3(owner RelayServiceOwnerV3) error {
	if d == nil || owner == nil {
		return ErrRegistryConfig
	}
	r := d.registry
	r.mu.Lock()
	if err := d.authorityLockedV3(time.Now()); err != nil {
		r.mu.Unlock()
		owner.CancelWithReason(err)
		return err
	}
	if d.attached {
		r.mu.Unlock()
		return ErrSessionConflict
	}
	d.owner = owner
	d.attached = true
	r.mu.Unlock()
	return nil
}

func (d *SessionDeviceV3) BoundsV3() SessionDeviceBoundsV3 {
	if d == nil {
		return SessionDeviceBoundsV3{}
	}
	return SessionDeviceBoundsV3{OwnedBytes: d.owned}
}
func (d *SessionDeviceV3) Done() <-chan struct{} {
	if d == nil {
		return nil
	}
	return d.done
}
func (d *SessionDeviceV3) Read([]byte) (int, error) { return 0, ErrPacketRejected }
func (d *SessionDeviceV3) StopCodeV1() SessionStopCodeV1 {
	if d == nil {
		return SessionStopNoneV1
	}
	d.registry.mu.RLock()
	defer d.registry.mu.RUnlock()
	return d.record.stopCode
}

func (d *SessionDeviceV3) Close() error {
	if d == nil {
		return nil
	}
	r := d.registry
	r.mu.Lock()
	action := r.stopLocked(d.record, SessionStopLocalV1)
	r.mu.Unlock()
	runDeviceStopsV3(action)
	return nil
}

// Intrusive stop actions use already reserved exact-record storage, not an
// append-grown callback list. Each detached record can enter this list once.
func runDeviceStopsV3(d *SessionDeviceV3) {
	for d != nil {
		next := d.stopNext
		d.stopNext = nil
		if d.owner != nil {
			d.owner.CancelWithReason(d.reason)
		}
		d.cancel()
		if d.record.spec.Cancel != nil {
			d.record.spec.Cancel()
		}
		if d.stopHook() {
			d.releaseV3()
		}
		d.releaseV3()
		d = next
	}
}

func (d *SessionDeviceV3) releaseV3() {
	d.registry.mu.Lock()
	d.releaseLockedV3()
	d.registry.mu.Unlock()
}
func (d *SessionDeviceV3) releaseLockedV3() {
	d.refs--
	if d.stopped && d.refs == 0 {
		d.registry.drainingV3--
		d.owner = nil
		d.writer = nil
		d.stopHook = nil
		d.cancel = nil
		d.ctx = nil
		d.record.spec.Cancel = nil
		d.subjectV3 = selfhost.RelayRevocationSubjectV3{}
		close(d.done)
	}
}

func (r *SessionRegistry) routeReturnV3Locked(d *SessionDeviceV3, packet []byte) error {
	if d.authorityLockedV3(time.Now()) != nil || !d.attached || d.ingress {
		r.mu.Unlock()
		return ErrPacketRejected
	}
	d.ingress = true
	d.refs++
	owner := d.owner
	r.mu.Unlock()
	err := owner.TrySubmitReturnPacketV3(packet)
	r.mu.Lock()
	current := d.authorityLockedV3(time.Now()) == nil
	var action *SessionDeviceV3
	if err != nil && current {
		code := SessionStopLocalV1
		if errors.Is(err, kruntime.ServiceResourceLimitV1) {
			code = SessionStopQueueV1
			r.stats.QueueDrops++
		}
		action = r.stopLocked(d.record, code)
	}
	d.ingress = false
	d.releaseLockedV3()
	r.mu.Unlock()
	runDeviceStopsV3(action)
	if errors.Is(err, kruntime.ServiceResourceLimitV1) {
		return ErrSessionQueueFull
	}
	if err != nil || !current {
		return ErrPacketRejected
	}
	return nil
}

func (d *SessionDeviceV3) Write(packet []byte) (int, error) {
	if d == nil || len(packet) == 0 || uint64(len(packet)) > uint64(d.maximum) {
		return 0, ErrPacketRejected
	}
	r := d.registry
	r.mu.Lock()
	if d.authorityLockedV3(time.Now()) != nil || d.writing {
		r.mu.Unlock()
		return 0, ErrPacketRejected
	}
	d.writing = true
	d.refs++
	writer := d.writer
	parent := d.ctx
	spec := d.record.spec
	r.mu.Unlock()
	defer func() { r.mu.Lock(); d.writing = false; d.releaseLockedV3(); r.mu.Unlock() }()
	info, err := kruntime.ValidateRelayOutboundIPPacketV1(packet, spec.AssignedIPv4, spec.DNSIPv4, spec.AssignedIPv6, spec.DNSIPv6)
	var bit uint8
	switch info.Protocol {
	case 1:
		bit = 1
	case 58:
		bit = 2
	case 6:
		bit = 4
	case 17:
		bit = 8
	}
	if err != nil || bit == 0 || d.protocols&bit == 0 {
		return 0, ErrPacketRejected
	}
	deadline := time.Now().Add(30 * time.Second)
	if d.deadline.Before(deadline) {
		deadline = d.deadline
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	n, err := writer.WritePacketContextV3(ctx, packet)
	r.mu.RLock()
	current := d.authorityLockedV3(time.Now()) == nil
	r.mu.RUnlock()
	if err != nil || n != len(packet) || ctx.Err() != nil || !deadline.After(time.Now()) || !current {
		return 0, ErrPacketRejected
	}
	return n, nil
}

var _ io.ReadWriteCloser = (*SessionDeviceV3)(nil)
