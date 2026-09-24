//go:build cgo

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

/*
#include "android_callbacks_v1.h"
*/
import "C"

import (
	"bytes"
	"context"
	"kurdistan/internal/androidbridge"
	runtimeengine "kurdistan/internal/runtime"
	"math"
	"net/netip"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

type androidSignalV1 struct {
	id, epoch, attempt uint64
	kind               uint8
	sink               func() androidbridge.ErrorCode
	done               chan struct{}
	running, fired     bool
	result             androidbridge.ErrorCode
}
type androidPlatformStateV1 struct {
	platform       *androidPlatformV1
	signals        [2]androidSignalV1
	busy, terminal bool
	failure        androidbridge.ErrorCode
	stagingBytes   uint64
	call           androidCallV1
	revision       *androidRevisionV1
	publication    *androidPublicationV1
	transport      any
}
type androidNetworkFactsV1 struct {
	mode     runtimeengine.ProbeModeV1
	families uint8
	count    int
	dns      [4]netip.AddrPort
}
type androidNetworkV1 struct {
	platform   *androidPlatformV1
	id, signal uint64
	done       <-chan struct{}
	facts      androidNetworkFactsV1
	closed     bool
}
type androidSocketV1 struct {
	platform          *androidPlatformV1
	expected          *androidbridge.ProductionSocketExpectationV1
	id, signal        uint64
	done              <-chan struct{}
	bindingRequired   bool
	confirmed, closed bool
}
type androidRevisionV1 struct {
	platform *androidPlatformV1
	id       uint64
	closed   bool
}
type androidPublicationV1 struct {
	revision *androidRevisionV1
	id       uint64
	closed   bool
}
type androidCallV1 struct {
	id       uint64
	ctx      context.Context
	hookDone chan struct{}
}

var androidPlatformsV1 struct {
	sync.Mutex
	next  uint64
	slots [64]androidPlatformStateV1
}

type androidPlatformV1 struct {
	table *C.kvpn_android_callbacks_v1
	owner uint64
	kind  uint8
	slot  uint8
}

// The trusted JNI producer supplies measured C/Java primitive-capacity backing,
// not a value from KPO1/KCT1. Nonzero is a shape check, not proof of completeness.
// Runtime/VM allocation headers and reference counts remain separately inventoried.
func androidCaptureBackingV1() uint64 {
	// withCaptureV1 owns one bounded backing, its two length arrays, rows and
	// the match caller's expected rows/maxima. Original/got/before preserve
	// four complete output structures. The busy bit prevents overlap on this
	// holder; this is not multiplied by ordinary output-frame count.
	return 2721543 + uint64(unsafe.Sizeof(C.kvpn_cb_capture_sizes_v1{})+
		2*unsafe.Sizeof([5]uint32{})+2*unsafe.Sizeof([5][]byte{})+
		unsafe.Sizeof([5]int{})+unsafe.Sizeof(runtime.Pinner{})+
		4*unsafe.Sizeof(C.kvpn_cb_capture_output_v1{})+unsafe.Sizeof([]byte{}))
}

func androidPlatformBackingV1(kind uint8) uint64 {
	child := unsafe.Sizeof(androidNetworkV1{})
	if kind == 1 {
		child = unsafe.Sizeof(androidSocketV1{})
	}
	return uint64(unsafe.Sizeof(androidPlatformV1{})+unsafe.Sizeof(androidPlatformStateV1{})+
		unsafe.Sizeof(androidRevisionV1{})+unsafe.Sizeof(androidPublicationV1{})+child) + cOutputObserverBackingV1() + androidCaptureBackingV1()
}

// Additional Go payload for the trusted facade's actual admitted frame count.
// androidPlatformBackingV1 already includes the selected embedded state and
// the opening observer retained by the native parent. Add the rest of the one
// shared registry, then one reconstructed observer per admitted frame. A typed
// receipt-discard trampoline runs only after the ordinary trampoline returned,
// so it replaces that frame's observer rather than adding a simultaneous one.
// Invocation/interface fields are charged by the native scoped operation.
// Unreachable objects awaiting GC are not claimed to be synchronously freed.
func androidOutputOverlapBackingV1(frames uint64) (uint64, androidbridge.ErrorCode) {
	if frames == 0 {
		return 0, androidbridge.CodeInvalidArgument
	}
	shared := uint64(unsafe.Sizeof(androidPlatformsV1) - unsafe.Sizeof(androidPlatformStateV1{}))
	// The fixed native handle/retirement/scope registry has no per-owner
	// charge. Include its actual full backing once, not an estimated delta.
	nativeRegistry := uint64(unsafe.Sizeof(registry))
	if nativeRegistry > math.MaxUint64-shared {
		return 0, androidbridge.CodeResourceLimit
	}
	shared += nativeRegistry
	// Existing process-wide update rate history survives all parent lifetimes.
	if productionProcessUpdateRatesStatusV1 != androidbridge.MaintenanceSuccess || productionProcessUpdateRatesV1 == nil {
		return 0, androidbridge.CodeResourceLimit
	}
	updateRates := productionProcessUpdateRatesV1.OwnedBytes()
	if updateRates > math.MaxUint64-shared {
		return 0, androidbridge.CodeResourceLimit
	}
	shared += updateRates
	observer := cOutputObserverBackingV1()
	if observer != 0 && frames > (math.MaxUint64-shared)/observer {
		return 0, androidbridge.CodeResourceLimit
	}
	return shared + frames*observer, androidbridge.CodeOK
}
func androidProductionRuntimeConfigV1(p *androidPlatformV1, external uint64) (androidbridge.ProductionSessionConfigV1, androidbridge.ErrorCode) {
	var empty androidbridge.ProductionSessionConfigV1
	if p == nil || p.kind != 1 || external == 0 || productionProcessProbeRatesErrorV1 != nil {
		return empty, androidbridge.CodeInvalidArgument
	}
	backing := androidPlatformBackingV1(1)
	if external > math.MaxUint64-backing {
		return empty, androidbridge.CodeResourceLimit
	}
	config := productionRuntimeConfigV1(p)
	config.OutputMetadataBytes = external + backing
	return config, androidbridge.CodeOK
}
func androidMaintenanceRuntimeConfigV1(p *androidPlatformV1, config androidbridge.MaintenanceConfigV1, external uint64) (androidbridge.MaintenanceConfigV1, androidbridge.ErrorCode) {
	var empty androidbridge.MaintenanceConfigV1
	if p == nil || p.kind != 2 || external == 0 || productionProcessProbeRatesErrorV1 != nil || productionProcessUpdateRatesStatusV1 != androidbridge.MaintenanceSuccess {
		return empty, androidbridge.CodeInvalidArgument
	}
	backing := androidPlatformBackingV1(2)
	if external > math.MaxUint64-backing {
		return empty, androidbridge.CodeResourceLimit
	}
	config = productionMaintenanceConfigV1(config)
	config.Transport = p
	config.OutputMetadataBytes = external + backing
	return config, androidbridge.CodeOK
}

// Finalization only after the actual native parent and canonical C output End.
// The real table callback validates the remaining C/JNI ownership before success.
func (p *androidPlatformV1) closeOwnedV1() androidbridge.ErrorCode {
	androidPlatformsV1.Lock()
	state := p.stateV1()
	if state == nil {
		androidPlatformsV1.Unlock()
		return androidbridge.CodeStateCorrupt
	}
	invalid := state.busy || state.failure != 0 || state.stagingBytes != 0 || state.call.id != 0 ||
		state.revision != nil || state.publication != nil || state.transport != nil ||
		state.signals[0].id != 0 || state.signals[1].id != 0
	if invalid {
		state.terminal = true
		state.failure = androidbridge.CodeStateCorrupt
		androidPlatformsV1.Unlock()
		return androidbridge.CodeStateCorrupt
	}
	state.busy = true
	state.terminal = true
	androidPlatformsV1.Unlock()
	result := androidBridgeStatusV1(C.kvpn_android_owner_close_v1(p.table, C.uint64_t(p.owner)))
	androidPlatformsV1.Lock()
	state = p.stateV1()
	if result == 0 && state != nil && state.failure == 0 {
		*state = androidPlatformStateV1{}
	} else {
		result = androidbridge.CodeStateCorrupt
		if state != nil {
			state.busy = false
			state.failure = result
		}
	}
	androidPlatformsV1.Unlock()
	return result
}

// The caller holds the exact C post-End finalization claim. Never interpret a
// missing or previously finalized Go holder as proof of platform cleanup.
func finalizeAndroidPlatformV1(owner uint64, kind uint8) androidbridge.ErrorCode {
	if owner == 0 || (kind != 1 && kind != 2) {
		return androidbridge.CodeStateCorrupt
	}
	androidPlatformsV1.Lock()
	var found *androidPlatformV1
	for i := range androidPlatformsV1.slots {
		p := androidPlatformsV1.slots[i].platform
		if p != nil && p.owner == owner && p.kind == kind {
			found = p
			break
		}
	}
	androidPlatformsV1.Unlock()
	if found == nil {
		return androidbridge.CodeStateCorrupt
	}
	return found.closeOwnedV1()
}

//export kvpn_go_android_platform_finalize_v1
func kvpn_go_android_platform_finalize_v1(owner C.uint64_t, kind C.uint8_t) C.int32_t {
	return C.int32_t(finalizeAndroidPlatformV1(uint64(owner), uint8(kind)))
}

func newAndroidPlatformV1(table *C.kvpn_android_callbacks_v1, owner uint64, kind uint8) (*androidPlatformV1, androidbridge.ErrorCode) {
	if owner == 0 || (kind != 1 && kind != 2) || C.kvpn_android_table_valid_v1(table) != 1 {
		return nil, androidbridge.CodeInvalidArgument
	}
	androidPlatformsV1.Lock()
	defer androidPlatformsV1.Unlock()
	free := -1
	for i := range androidPlatformsV1.slots {
		state := &androidPlatformsV1.slots[i]
		if state.platform != nil && state.platform.owner == owner {
			return nil, androidbridge.CodeStateCorrupt
		}
		if state.platform == nil && free < 0 {
			free = i
		}
	}
	if free < 0 {
		return nil, androidbridge.CodeResourceLimit
	}
	p := &androidPlatformV1{table: table, owner: owner, kind: kind, slot: uint8(free)}
	androidPlatformsV1.slots[free] = androidPlatformStateV1{platform: p}
	return p, androidbridge.CodeOK
}

// Requires the fixed table guard. Pointer identity also rejects a stale wrapper.
func (p *androidPlatformV1) stateV1() *androidPlatformStateV1 {
	if p == nil || p.slot >= 64 {
		return nil
	}
	state := &androidPlatformsV1.slots[p.slot]
	if state.platform != p {
		return nil
	}
	return state
}
func (p *androidPlatformV1) failV1() {
	androidPlatformsV1.Lock()
	if state := p.stateV1(); state != nil {
		state.terminal = true
		if state.failure == androidbridge.CodeOK {
			state.failure = androidbridge.CodeStateCorrupt
		}
	}
	androidPlatformsV1.Unlock()
}
func (p *androidPlatformV1) beginV1() bool {
	androidPlatformsV1.Lock()
	defer androidPlatformsV1.Unlock()
	state := p.stateV1()
	if state == nil || state.busy || state.terminal || state.failure != 0 {
		return false
	}
	state.busy = true
	return true
}
func (p *androidPlatformV1) endV1() {
	androidPlatformsV1.Lock()
	if state := p.stateV1(); state != nil {
		state.busy = false
		state.stagingBytes = 0
	}
	androidPlatformsV1.Unlock()
}
func androidBridgeStatusV1(status C.int32_t) androidbridge.ErrorCode {
	if status < 0 || status > 25 {
		return androidbridge.CodeStateCorrupt
	}
	return androidbridge.ErrorCode(status)
}
func (p *androidPlatformV1) maintenanceStatusV1(status int32) androidbridge.MaintenanceResultV1 {
	if status < 0 || status > 23 {
		p.failV1()
		return androidbridge.MaintenanceInternalFailure
	}
	return androidbridge.MaintenanceResultV1(status)
}
func (p *androidPlatformV1) withCallV1(ctx context.Context, invoke func(uint64) int32) (status int32, failure androidbridge.ErrorCode) {
	if ctx == nil || invoke == nil {
		return 0, androidbridge.CodeInvalidArgument
	}
	if ctx.Err() != nil {
		return 0, androidbridge.CodeCancelled
	}
	if !p.beginV1() {
		return 0, androidbridge.CodeStateCorrupt
	}
	androidPlatformsV1.Lock()
	state := p.stateV1()
	if androidPlatformsV1.next == math.MaxUint64 {
		state.terminal = true
		state.failure = androidbridge.CodeResourceLimit
		androidPlatformsV1.Unlock()
		p.endV1()
		return 0, androidbridge.CodeResourceLimit
	}
	androidPlatformsV1.next++
	id := androidPlatformsV1.next
	done := make(chan struct{})
	state.call = androidCallV1{id: id, ctx: ctx, hookDone: done}
	androidPlatformsV1.Unlock()
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		defer func() {
			if recover() != nil {
				p.failV1()
			}
		}()
		// A refused/failed hook is not a successful interruption of Binder/JCA.
		// The ordinary callback and this hook remain owned until both return.
		if result := C.kvpn_android_cancel_call_v1(p.table, C.uint64_t(p.owner), C.uint64_t(id)); result != 0 && result != 6 {
			p.failV1()
		}
	})
	defer func() {
		if recover() != nil {
			p.failV1()
			failure = androidbridge.CodeStateCorrupt
		}
		if !stop() {
			<-done
		}
		androidPlatformsV1.Lock()
		state := p.stateV1()
		if state == nil || state.call.id != id {
			failure = androidbridge.CodeStateCorrupt
		} else {
			if state.failure != 0 {
				failure = state.failure
			} else if ctx.Err() != nil {
				failure = androidbridge.CodeCancelled
			} else if state.terminal {
				failure = androidbridge.CodeStateCorrupt
			}
			state.call = androidCallV1{}
		}
		androidPlatformsV1.Unlock()
		p.endV1()
	}()
	if ctx.Err() != nil {
		return 0, androidbridge.CodeCancelled
	}
	return invoke(id), androidbridge.CodeOK
}
func androidCallContextV1(owner, id uint64) (context.Context, bool) {
	androidPlatformsV1.Lock()
	defer androidPlatformsV1.Unlock()
	if owner == 0 || id == 0 {
		return nil, false
	}
	for i := range androidPlatformsV1.slots {
		state := &androidPlatformsV1.slots[i]
		if state.platform != nil && state.platform.owner == owner && state.busy && state.call.id == id && state.call.ctx != nil {
			return state.call.ctx, true
		}
	}
	return nil, false
}

//export kvpn_android_call_cancelled_v1
func kvpn_android_call_cancelled_v1(owner C.uint64_t, call C.uint64_t, out *C.uint8_t) C.int32_t {
	if out == nil {
		return 1
	}
	*out = 0
	ctx, ok := androidCallContextV1(uint64(owner), uint64(call))
	if !ok {
		return 25
	}
	if ctx.Err() != nil {
		*out = 1
	}
	return 0
}

//export kvpn_android_call_remaining_millis_v1
func kvpn_android_call_remaining_millis_v1(owner C.uint64_t, call C.uint64_t, present *C.uint8_t, remaining *C.uint64_t) C.int32_t {
	if present == nil || remaining == nil {
		return 1
	}
	*present = 0
	*remaining = 0
	ctx, ok := androidCallContextV1(uint64(owner), uint64(call))
	if !ok {
		return 25
	}
	if deadline, has := ctx.Deadline(); has {
		*present = 1
		left := time.Until(deadline).Milliseconds()
		if left > 0 {
			*remaining = C.uint64_t(left)
		}
	}
	return 0
}
func (p *androidPlatformV1) withCaptureV1(accept func([5][]byte) bool) (result androidbridge.ErrorCode) {
	if accept == nil || !p.beginV1() {
		return androidbridge.CodeStateCorrupt
	}
	defer p.endV1()
	defer func() {
		if recover() != nil {
			p.failV1()
			result = androidbridge.CodeStateCorrupt
		}
	}()
	var sizes C.kvpn_cb_capture_sizes_v1
	if s := androidBridgeStatusV1(C.kvpn_android_capture_sizes_v1(p.table, C.uint64_t(p.owner), &sizes)); s != 0 {
		return s
	}
	lengths := [5]uint32{uint32(sizes.verify_request), uint32(sizes.activation_record),
		uint32(sizes.recipient_request), uint32(sizes.recipient_private), uint32(sizes.settings)}
	maxima := [5]uint32{1405996, 1118299, 512, 128, 196608}
	total := uint64(0)
	for i, n := range lengths {
		if n == 0 || n > maxima[i] || total > 2721543-uint64(n) {
			p.failV1()
			return androidbridge.CodeSizeLimit
		}
		total += uint64(n)
	}
	// Reserve the entire live destination capacity before creating its one backing.
	androidPlatformsV1.Lock()
	state := p.stateV1()
	if state == nil || state.terminal || state.failure != 0 {
		androidPlatformsV1.Unlock()
		return androidbridge.CodeStateCorrupt
	}
	state.stagingBytes = total
	androidPlatformsV1.Unlock()
	backing := make([]byte, int(total))
	defer clear(backing)
	var pin runtime.Pinner
	pin.Pin(&backing[0])
	defer pin.Unpin()
	var rows [5][]byte
	at := 0
	for i, n := range lengths {
		end := at + int(n)
		rows[i] = backing[at:end:end]
		at = end
	}
	span := func(b []byte) C.kvpn_cb_output_v1 {
		return C.kvpn_cb_output_v1{data: (*C.uint8_t)(unsafe.Pointer(&b[0])), capacity: C.uint32_t(len(b))}
	}
	output := C.kvpn_cb_capture_output_v1{verify_request: span(rows[0]), activation_record: span(rows[1]),
		recipient_request: span(rows[2]), recipient_private: span(rows[3]), settings: span(rows[4])}
	original := output
	status := androidBridgeStatusV1(C.kvpn_android_capture_copy_into_v1(p.table, C.uint64_t(p.owner), &output))
	got := [5]C.kvpn_cb_output_v1{output.verify_request, output.activation_record, output.recipient_request, output.recipient_private, output.settings}
	before := [5]C.kvpn_cb_output_v1{original.verify_request, original.activation_record, original.recipient_request, original.recipient_private, original.settings}
	for i := range got {
		if got[i].data != before[i].data || got[i].capacity != before[i].capacity ||
			(status == 0 && got[i].written != before[i].capacity) || got[i].written > before[i].capacity {
			p.failV1()
			return androidbridge.CodeStateCorrupt
		}
	}
	if status != 0 {
		return status
	}
	androidPlatformsV1.Lock()
	state = p.stateV1()
	live := state != nil && !state.terminal && state.failure == 0
	androidPlatformsV1.Unlock()
	if !live || !accept(rows) {
		return androidbridge.CodeVerificationRejected
	}
	return androidbridge.CodeOK
}

func (p *androidPlatformV1) matchProductionV1(expected *androidbridge.ProductionCurrentExpectationV1) androidbridge.ErrorCode {
	if expected == nil || p == nil || p.kind != 1 {
		return androidbridge.CodeInvalidArgument
	}
	return p.withCaptureV1(func(rows [5][]byte) bool {
		current := androidbridge.MaintenanceCurrentInputV1{VerifyRequest: rows[0], ActivationRecord: rows[1],
			RecipientRequest: rows[2], RecipientPrivate: rows[3]}
		return expected.MatchesV1(current) && expected.MatchesSettingsV1(rows[4])
	})
}

// The private owning opener must call this on the same bounded input passed to
// native OpenMaintenanceV1. Maintenance has no production expectation object.
func (p *androidPlatformV1) MatchMaintenanceCaptureV1(current androidbridge.MaintenanceCurrentInputV1, settings []byte) int32 {
	code := p.matchMaintenanceV1(current, settings)
	if code == androidbridge.CodeOK {
		return 0
	}
	if code == androidbridge.CodeVerificationRejected {
		return 22
	}
	return bridgeFailureP1V1(code, nil)
}

func (p *androidPlatformV1) matchMaintenanceV1(current androidbridge.MaintenanceCurrentInputV1, settings []byte) androidbridge.ErrorCode {
	if p == nil || p.kind != 2 {
		return androidbridge.CodeInvalidArgument
	}
	expected := [5][]byte{current.VerifyRequest, current.ActivationRecord, current.RecipientRequest, current.RecipientPrivate, settings}
	maxima := [5]int{1405996, 1118299, 512, 128, 196608}
	for i, row := range expected {
		if len(row) == 0 || len(row) > maxima[i] {
			return androidbridge.CodeSizeLimit
		}
	}
	return p.withCaptureV1(func(rows [5][]byte) bool {
		for i, row := range rows {
			if !bytes.Equal(row, expected[i]) {
				return false
			}
		}
		return true
	})
}
func (p *androidPlatformV1) reserveRevisionV1(epoch uint64, sink func() androidbridge.ErrorCode) (uint64, androidbridge.ErrorCode) {
	androidPlatformsV1.Lock()
	defer androidPlatformsV1.Unlock()
	state := p.stateV1()
	if state == nil || state.terminal || state.failure != 0 || epoch == 0 || sink == nil || state.signals[0].id != 0 {
		return 0, androidbridge.CodeStateCorrupt
	}
	if androidPlatformsV1.next == math.MaxUint64 {
		state.terminal = true
		state.failure = androidbridge.CodeResourceLimit
		return 0, androidbridge.CodeResourceLimit
	}
	androidPlatformsV1.next++
	signal := &state.signals[0]
	*signal = androidSignalV1{id: androidPlatformsV1.next, epoch: epoch, kind: 1, sink: sink}
	return signal.id, androidbridge.CodeOK
}

func (p *androidPlatformV1) RegisterProductionCurrentV1(epoch uint64, expected *androidbridge.ProductionCurrentExpectationV1, sink func() androidbridge.ErrorCode) (androidbridge.MaintenanceRevisionRegistrationV1, androidbridge.ErrorCode) {
	if status := p.matchProductionV1(expected); status != 0 {
		return nil, status
	}
	return p.registerCurrentV1(epoch, sink)
}
func (p *androidPlatformV1) Register(epoch uint64, sink func() androidbridge.ErrorCode) (androidbridge.MaintenanceRevisionRegistrationV1, androidbridge.ErrorCode) {
	if p == nil || p.kind != 2 {
		return nil, androidbridge.CodeInvalidArgument
	}
	return p.registerCurrentV1(epoch, sink)
}
func (p *androidPlatformV1) registerCurrentV1(epoch uint64, sink func() androidbridge.ErrorCode) (androidbridge.MaintenanceRevisionRegistrationV1, androidbridge.ErrorCode) {
	signal, status := p.reserveRevisionV1(epoch, sink)
	if status != 0 {
		return nil, status
	}
	if !p.beginV1() {
		return nil, androidbridge.CodeStateCorrupt
	}
	var id C.uint64_t
	if p.kind == 1 {
		status = androidBridgeStatusV1(C.kvpn_android_production_current_register_v1(p.table, C.uint64_t(p.owner), C.uint64_t(epoch), C.uint64_t(signal), &id))
	} else {
		status = androidBridgeStatusV1(C.kvpn_android_maintenance_current_register_v1(p.table, C.uint64_t(p.owner), C.uint64_t(epoch), C.uint64_t(signal), &id))
	}
	var registration *androidRevisionV1
	androidPlatformsV1.Lock()
	state := p.stateV1()
	if id != 0 {
		registration = &androidRevisionV1{platform: p, id: uint64(id)}
		state.revision = registration // Adopt partial ownership before checking the result.
	}
	if state.terminal || state.failure != 0 || (registration == nil && status == 0) {
		status = androidbridge.CodeStateCorrupt
	}
	androidPlatformsV1.Unlock()
	p.endV1()
	if status != 0 {
		if registration != nil && registration.Close() != 0 {
			p.failV1()
		}
		return nil, status
	}
	return registration, androidbridge.CodeOK
}
func (p *androidPlatformV1) beginCleanupV1() bool {
	androidPlatformsV1.Lock()
	defer androidPlatformsV1.Unlock()
	state := p.stateV1()
	if state == nil || state.busy {
		return false
	}
	state.busy = true
	return true
}
func bridgeFailureM1V1(status androidbridge.ErrorCode, ctx context.Context) androidbridge.MaintenanceResultV1 {
	if status == androidbridge.CodeCancelled {
		if ctx != nil && ctx.Err() == context.DeadlineExceeded {
			return androidbridge.MaintenanceTimeout
		}
		return androidbridge.MaintenanceCancelled
	}
	if status == androidbridge.CodeResourceLimit {
		return androidbridge.MaintenanceResourceLimit
	}
	return androidbridge.MaintenanceInternalFailure
}
func (r *androidRevisionV1) liveV1() bool {
	androidPlatformsV1.Lock()
	defer androidPlatformsV1.Unlock()
	state := r.platform.stateV1()
	return !r.closed && state != nil && state.revision == r && !state.terminal && state.failure == 0
}
func (r *androidRevisionV1) Revalidate(ctx context.Context) androidbridge.MaintenanceResultV1 {
	if !r.liveV1() {
		return androidbridge.MaintenanceInvalidState
	}
	p := r.platform
	status, failure := p.withCallV1(ctx, func(call uint64) int32 {
		return int32(C.kvpn_android_revision_revalidate_v1(p.table, C.uint64_t(p.owner), C.uint64_t(r.id), C.uint64_t(call)))
	})
	if failure != 0 {
		return bridgeFailureM1V1(failure, ctx)
	}
	return p.maintenanceStatusV1(status)
}
func (r *androidRevisionV1) AcquirePublication(ctx context.Context) (androidbridge.MaintenancePublicationLeaseV1, androidbridge.MaintenanceResultV1) {
	if !r.liveV1() {
		return nil, androidbridge.MaintenanceInvalidState
	}
	p := r.platform
	androidPlatformsV1.Lock()
	state := p.stateV1()
	occupied := state == nil || state.publication != nil
	androidPlatformsV1.Unlock()
	if occupied {
		return nil, androidbridge.MaintenanceResourceLimit
	}
	var id C.uint64_t
	var publication *androidPublicationV1
	status, failure := p.withCallV1(ctx, func(call uint64) int32 {
		androidPlatformsV1.Lock()
		state := p.stateV1()
		occupied := state == nil || state.publication != nil || state.revision != r || r.closed
		androidPlatformsV1.Unlock()
		if occupied {
			return int32(androidbridge.MaintenanceResourceLimit)
		}
		result := C.kvpn_android_publication_acquire_v1(p.table, C.uint64_t(p.owner), C.uint64_t(r.id), C.uint64_t(call), &id)
		androidPlatformsV1.Lock()
		if id != 0 {
			publication = &androidPublicationV1{revision: r, id: uint64(id)}
			p.stateV1().publication = publication
		}
		androidPlatformsV1.Unlock()
		return int32(result)
	})
	result := p.maintenanceStatusV1(status)
	if failure != 0 {
		result = bridgeFailureM1V1(failure, ctx)
	}
	if publication == nil && result == 0 {
		p.failV1()
		result = androidbridge.MaintenanceInternalFailure
	}
	if result != 0 {
		if publication != nil && publication.Close() != 0 {
			p.failV1()
		}
		return nil, result
	}
	return publication, androidbridge.MaintenanceSuccess
}
func (r *androidRevisionV1) Close() androidbridge.ErrorCode {
	p := r.platform
	androidPlatformsV1.Lock()
	if r.closed {
		androidPlatformsV1.Unlock()
		return androidbridge.CodeOK
	}
	state := p.stateV1()
	invalid := state == nil || state.revision != r || state.signals[0].running || state.publication != nil
	androidPlatformsV1.Unlock()
	if invalid || !p.beginCleanupV1() {
		p.failV1()
		return androidbridge.CodeStateCorrupt
	}
	defer p.endV1()
	result := androidBridgeStatusV1(C.kvpn_android_revision_close_v1(p.table, C.uint64_t(p.owner), C.uint64_t(r.id)))
	androidPlatformsV1.Lock()
	state = p.stateV1()
	if result != 0 || state == nil || state.failure != 0 || state.signals[0].running {
		if state != nil {
			state.terminal = true
			if state.failure == 0 {
				state.failure = androidbridge.CodeStateCorrupt
			}
		}
		result = androidbridge.CodeStateCorrupt
	} else {
		r.closed = true
		state.revision = nil
		state.signals[0] = androidSignalV1{}
		state.terminal = true
	}
	androidPlatformsV1.Unlock()
	return result
}
func (v *androidPublicationV1) IsCurrent() bool {
	p := v.revision.platform
	androidPlatformsV1.Lock()
	state := p.stateV1()
	valid := state != nil && !v.closed && !v.revision.closed && state.revision == v.revision && state.publication == v && !state.terminal && state.failure == 0
	androidPlatformsV1.Unlock()
	if !valid || !p.beginV1() {
		return false
	}
	defer p.endV1()
	var current C.uint8_t
	result := androidBridgeStatusV1(C.kvpn_android_publication_is_current_v1(p.table, C.uint64_t(p.owner), C.uint64_t(v.revision.id), C.uint64_t(v.id), &current))
	if result != 0 || current > 1 {
		p.failV1()
		return false
	}
	androidPlatformsV1.Lock()
	state = p.stateV1()
	valid = state != nil && state.publication == v && !state.terminal && state.failure == 0 && !v.closed
	androidPlatformsV1.Unlock()
	return valid && current == 1
}
func (v *androidPublicationV1) Close() androidbridge.ErrorCode {
	p := v.revision.platform
	androidPlatformsV1.Lock()
	if v.closed {
		androidPlatformsV1.Unlock()
		return androidbridge.CodeOK
	}
	state := p.stateV1()
	valid := state != nil && state.publication == v && state.revision == v.revision
	androidPlatformsV1.Unlock()
	if !valid || !p.beginCleanupV1() {
		p.failV1()
		return androidbridge.CodeStateCorrupt
	}
	defer p.endV1()
	result := androidBridgeStatusV1(C.kvpn_android_publication_close_v1(p.table, C.uint64_t(p.owner), C.uint64_t(v.revision.id), C.uint64_t(v.id)))
	androidPlatformsV1.Lock()
	state = p.stateV1()
	if result != 0 || state == nil || state.failure != 0 {
		if state != nil {
			state.terminal = true
			if state.failure == 0 {
				state.failure = androidbridge.CodeStateCorrupt
			}
		}
		result = androidbridge.CodeStateCorrupt
	} else {
		v.closed = true
		state.publication = nil
	}
	androidPlatformsV1.Unlock()
	return result
}

func (p *androidPlatformV1) reserveLossV1(kind uint8, epoch, attempt uint64) (uint64, <-chan struct{}, androidbridge.ErrorCode) {
	androidPlatformsV1.Lock()
	defer androidPlatformsV1.Unlock()
	state := p.stateV1()
	if state == nil || state.terminal || state.failure != 0 || state.transport != nil || state.signals[1].id != 0 ||
		epoch == 0 || (kind == 2 && (p.kind != 1 || attempt == 0)) || (kind == 3 && p.kind != 2) || (kind != 2 && kind != 3) {
		return 0, nil, androidbridge.CodeStateCorrupt
	}
	if androidPlatformsV1.next == math.MaxUint64 {
		state.terminal = true
		state.failure = androidbridge.CodeResourceLimit
		return 0, nil, androidbridge.CodeResourceLimit
	}
	androidPlatformsV1.next++
	done := make(chan struct{})
	state.signals[1] = androidSignalV1{id: androidPlatformsV1.next, kind: kind, epoch: epoch, attempt: attempt, done: done}
	return androidPlatformsV1.next, done, androidbridge.CodeOK
}

func (p *androidPlatformV1) productionStatusV1(status int32) int32 {
	if status < 0 || status > 26 {
		p.failV1()
		return 18
	}
	return status
}
func bridgeFailureP1V1(status androidbridge.ErrorCode, ctx context.Context) int32 {
	if status == androidbridge.CodeCancelled {
		if ctx != nil && ctx.Err() == context.DeadlineExceeded {
			return 8
		}
		return 7
	}
	if status == androidbridge.CodeResourceLimit {
		return 5
	}
	return 18
}
func (p *androidPlatformV1) RegisterProductionSocketV1(ctx context.Context, e *androidbridge.ProductionSocketExpectationV1) (androidbridge.ProductionSocketRegistrationV1, int32) {
	if p == nil || p.kind != 1 || ctx == nil {
		return nil, 1
	}
	epoch, attempt, token, fd, valid := e.IdentityV1()
	explicit, has, network := e.SelectionV1()
	if !valid || epoch == 0 || attempt == 0 || token == 0 || fd < 0 || fd > math.MaxInt32 || has > 1 || (has == 0 && network != 0) || (has == 1 && network == 0) {
		return nil, 1
	}
	if ctx.Err() != nil {
		return nil, bridgeFailureP1V1(androidbridge.CodeCancelled, ctx)
	}
	androidPlatformsV1.Lock()
	state := p.stateV1()
	registered := state != nil && state.revision != nil && state.signals[0].epoch == epoch
	androidPlatformsV1.Unlock()
	if !registered {
		return nil, 3
	}
	signal, done, failure := p.reserveLossV1(2, epoch, attempt)
	if failure != 0 {
		return nil, bridgeFailureP1V1(failure, ctx)
	}
	var socket *androidSocketV1
	raw, failure := p.withCallV1(ctx, func(call uint64) int32 {
		input := C.kvpn_cb_socket_expectation_v1{parent_epoch: C.uint64_t(epoch), attempt: C.uint64_t(attempt), socket_token: C.uint64_t(token), fd: C.int32_t(fd), has_network: C.uint8_t(has), network: C.uint64_t(network)}
		if explicit {
			input.selection_explicit = 1
		}
		before := input
		var id C.uint64_t
		var binding C.uint8_t
		result := int32(C.kvpn_android_socket_register_v1(p.table, C.uint64_t(p.owner), C.uint64_t(call), &input, C.uint64_t(signal), &id, &binding))
		if id != 0 {
			socket = &androidSocketV1{platform: p, expected: e, id: uint64(id), signal: signal, done: done, bindingRequired: binding == 1}
			androidPlatformsV1.Lock()
			p.stateV1().transport = socket
			androidPlatformsV1.Unlock()
		}
		if input != before || binding > 1 {
			p.failV1()
			return 18
		}
		return result
	})
	result := p.productionStatusV1(raw)
	if failure != 0 {
		result = bridgeFailureP1V1(failure, ctx)
	}
	if result == 0 && (socket == nil || !socket.localCurrentV1()) {
		result = 9
	}
	if result != 0 {
		if socket != nil && socket.CloseV1() != 0 {
			p.failV1()
		}
		return nil, result
	}
	return socket, 0
}
func (s *androidSocketV1) localCurrentV1() bool {
	androidPlatformsV1.Lock()
	expected := s.expected
	closed := s.closed
	androidPlatformsV1.Unlock()
	if closed {
		return false
	}
	epoch, attempt, _, _, valid := expected.IdentityV1()
	if !valid {
		return false
	}
	androidPlatformsV1.Lock()
	defer androidPlatformsV1.Unlock()
	state := s.platform.stateV1()
	return state != nil && state.transport == s && !s.closed && !state.terminal && state.failure == 0 &&
		state.signals[1].id == s.signal && !state.signals[1].fired && state.signals[1].epoch == epoch && state.signals[1].attempt == attempt
}
func (s *androidSocketV1) BindingRequiredV1() bool { return s.bindingRequired }
func (s *androidSocketV1) DoneV1() <-chan struct{} { return s.done }
func (s *androidSocketV1) ConfirmV1(protected, has uint8, network uint64) int32 {
	if protected > 1 || has > 1 || (has == 0 && network != 0) || (has == 1 && network == 0) {
		return 1
	}
	if !s.localCurrentV1() {
		return 9
	}
	p := s.platform
	if !p.beginV1() {
		return 3
	}
	defer p.endV1()
	androidPlatformsV1.Lock()
	repeated := s.confirmed
	s.confirmed = true
	androidPlatformsV1.Unlock()
	if repeated {
		return 3
	}
	if protected == 0 {
		return 16
	}
	androidPlatformsV1.Lock()
	expected := s.expected
	androidPlatformsV1.Unlock()
	_, wantHas, wantNetwork := expected.SelectionV1()
	if has != wantHas || network != wantNetwork {
		return 9
	}
	result := p.productionStatusV1(int32(C.kvpn_android_socket_confirm_v1(p.table, C.uint64_t(p.owner), C.uint64_t(s.id), C.uint8_t(protected), C.uint8_t(has), C.uint64_t(network))))
	if result == 0 && !s.localCurrentV1() {
		return 9
	}
	return result
}
func (s *androidSocketV1) CloseV1() int32 {
	p := s.platform
	androidPlatformsV1.Lock()
	if s.closed {
		androidPlatformsV1.Unlock()
		return 0
	}
	state := p.stateV1()
	valid := state != nil && state.transport == s && state.signals[1].id == s.signal
	androidPlatformsV1.Unlock()
	if !valid || !p.beginCleanupV1() {
		p.failV1()
		return 18
	}
	defer p.endV1()
	result := p.productionStatusV1(int32(C.kvpn_android_socket_close_v1(p.table, C.uint64_t(p.owner), C.uint64_t(s.id))))
	androidPlatformsV1.Lock()
	state = p.stateV1()
	if result != 0 || state == nil || state.failure != 0 {
		if state != nil {
			state.terminal = true
			if state.failure == 0 {
				state.failure = androidbridge.CodeStateCorrupt
			}
		}
		result = 18
	} else {
		signal := &state.signals[1]
		if !signal.fired {
			close(signal.done)
		}
		*signal = androidSignalV1{}
		s.closed = true
		s.expected = nil
		state.transport = nil
	}
	androidPlatformsV1.Unlock()
	return result
}
func androidLossSignalV1(owner, id uint64, kind uint8) androidbridge.ErrorCode {
	androidPlatformsV1.Lock()
	defer androidPlatformsV1.Unlock()
	if owner == 0 || id == 0 || (kind != 2 && kind != 3) {
		return androidbridge.CodeStateCorrupt
	}
	for i := range androidPlatformsV1.slots {
		state := &androidPlatformsV1.slots[i]
		if state.platform == nil || state.platform.owner != owner {
			continue
		}
		signal := &state.signals[1]
		if signal.id != id || signal.kind != kind || signal.done == nil {
			return androidbridge.CodeStateCorrupt
		}
		if !signal.fired {
			signal.fired = true
			close(signal.done)
		}
		return androidbridge.CodeOK
	}
	return androidbridge.CodeStateCorrupt
}

//export kvpn_android_socket_lost_v1
func kvpn_android_socket_lost_v1(owner C.uint64_t, signal C.uint64_t) C.int32_t {
	return C.int32_t(androidLossSignalV1(uint64(owner), uint64(signal), 2))
}

//export kvpn_android_maintenance_network_lost_v1
func kvpn_android_maintenance_network_lost_v1(owner C.uint64_t, signal C.uint64_t) C.int32_t {
	return C.int32_t(androidLossSignalV1(uint64(owner), uint64(signal), 3))
}
func (p *androidPlatformV1) networkFactsV1(id uint64) (androidNetworkFactsV1, androidbridge.MaintenanceResultV1) {
	var raw C.kvpn_cb_network_snapshot_v1
	status := p.maintenanceStatusV1(int32(C.kvpn_android_maintenance_network_snapshot_v1(p.table, C.uint64_t(p.owner), C.uint64_t(id), &raw)))
	var facts androidNetworkFactsV1
	if status != 0 {
		return facts, status
	}
	if raw.mode < 1 || raw.mode > 2 || raw.families < 1 || raw.families > 3 || raw.dns_count < 1 || raw.dns_count > 4 {
		p.failV1()
		return facts, androidbridge.MaintenanceInternalFailure
	}
	facts.mode = runtimeengine.ProbeModeV1(raw.mode)
	facts.families = uint8(raw.families)
	facts.count = int(raw.dns_count)
	for i := 0; i < 4; i++ {
		row := raw.dns[i]
		if i >= facts.count {
			if row.family != 0 || row.port != 0 {
				p.failV1()
				return androidNetworkFactsV1{}, androidbridge.MaintenanceInternalFailure
			}
			for _, b := range row.address {
				if b != 0 {
					p.failV1()
					return androidNetworkFactsV1{}, androidbridge.MaintenanceInternalFailure
				}
			}
			continue
		}
		var address netip.Addr
		if row.family == 4 {
			var bytes [4]byte
			for j := 0; j < 4; j++ {
				bytes[j] = byte(row.address[j])
			}
			for j := 4; j < 16; j++ {
				if row.address[j] != 0 {
					p.failV1()
					return androidNetworkFactsV1{}, androidbridge.MaintenanceInternalFailure
				}
			}
			address = netip.AddrFrom4(bytes)
		} else if row.family == 6 {
			var bytes [16]byte
			for j := range bytes {
				bytes[j] = byte(row.address[j])
			}
			address = netip.AddrFrom16(bytes)
		}
		if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.Is4In6() || row.port != 53 {
			p.failV1()
			return androidNetworkFactsV1{}, androidbridge.MaintenanceInternalFailure
		}
		facts.dns[i] = netip.AddrPortFrom(address, 53)
		for j := 0; j < i; j++ {
			if facts.dns[j] == facts.dns[i] {
				p.failV1()
				return androidNetworkFactsV1{}, androidbridge.MaintenanceInternalFailure
			}
		}
	}
	return facts, androidbridge.MaintenanceSuccess
}
func (p *androidPlatformV1) AcquireNetwork(ctx context.Context) (androidbridge.MaintenanceNetworkLeaseV1, androidbridge.MaintenanceResultV1) {
	if p == nil || p.kind != 2 {
		return nil, androidbridge.MaintenanceInvalidRequest
	}
	if ctx == nil {
		return nil, androidbridge.MaintenanceInvalidRequest
	}
	if ctx.Err() != nil {
		return nil, bridgeFailureM1V1(androidbridge.CodeCancelled, ctx)
	}
	androidPlatformsV1.Lock()
	state := p.stateV1()
	epoch := uint64(0)
	if state != nil && state.revision != nil {
		epoch = state.signals[0].epoch
	}
	androidPlatformsV1.Unlock()
	signal, done, failure := p.reserveLossV1(3, epoch, 0)
	if failure != 0 {
		return nil, bridgeFailureM1V1(failure, ctx)
	}
	var lease *androidNetworkV1
	raw, failure := p.withCallV1(ctx, func(call uint64) int32 {
		var id C.uint64_t
		status := int32(C.kvpn_android_maintenance_network_acquire_v1(p.table, C.uint64_t(p.owner), C.uint64_t(call), C.uint64_t(signal), &id))
		if id != 0 {
			lease = &androidNetworkV1{platform: p, id: uint64(id), signal: signal, done: done}
			androidPlatformsV1.Lock()
			p.stateV1().transport = lease
			androidPlatformsV1.Unlock()
		}
		if status == 0 && lease != nil {
			var result androidbridge.MaintenanceResultV1
			lease.facts, result = p.networkFactsV1(lease.id)
			status = int32(result)
		}
		return status
	})
	result := p.maintenanceStatusV1(raw)
	if failure != 0 {
		result = bridgeFailureM1V1(failure, ctx)
	}
	if result == 0 && (lease == nil || !lease.localCurrentV1()) {
		result = androidbridge.MaintenanceNetworkUnavailable
	}
	if result != 0 {
		if lease != nil && lease.Close() != 0 {
			p.failV1()
		}
		return nil, result
	}
	return lease, androidbridge.MaintenanceSuccess
}

func (p *androidPlatformV1) SystemRootsInto(ctx context.Context, dst []byte) (n int, result androidbridge.MaintenanceResultV1) {
	result = androidbridge.MaintenanceInvalidRequest
	defer func() {
		if recover() != nil {
			p.failV1()
			result = androidbridge.MaintenanceInternalFailure
		}
		if result != 0 {
			clear(dst)
			n = 0
		}
	}()
	if p == nil || p.kind != 2 || len(dst) == 0 || len(dst) > 1048576 {
		return 0, result
	}
	clear(dst)
	var pin runtime.Pinner
	pin.Pin(&dst[0])
	defer pin.Unpin()
	out := C.kvpn_cb_output_v1{data: (*C.uint8_t)(unsafe.Pointer(&dst[0])), capacity: C.uint32_t(len(dst))}
	original := out
	raw, failure := p.withCallV1(ctx, func(call uint64) int32 {
		return int32(C.kvpn_android_system_roots_into_v1(p.table, C.uint64_t(p.owner), C.uint64_t(call), &out))
	})
	if out.data != original.data || out.capacity != original.capacity || out.written > original.capacity {
		p.failV1()
		return 0, androidbridge.MaintenanceInternalFailure
	}
	if failure != 0 {
		return 0, bridgeFailureM1V1(failure, ctx)
	}
	result = p.maintenanceStatusV1(raw)
	if result != 0 {
		return 0, result
	}
	if out.written < 8 {
		p.failV1()
		return 0, androidbridge.MaintenanceInternalFailure
	}
	return int(out.written), androidbridge.MaintenanceSuccess
}
func (n *androidNetworkV1) localCurrentV1() bool {
	androidPlatformsV1.Lock()
	defer androidPlatformsV1.Unlock()
	state := n.platform.stateV1()
	return state != nil && state.transport == n && !n.closed && !state.terminal && state.failure == 0 &&
		state.signals[1].id == n.signal && !state.signals[1].fired
}
func (n *androidNetworkV1) Mode() runtimeengine.ProbeModeV1 { return n.facts.mode }
func (n *androidNetworkV1) IPFamilies() uint8               { return n.facts.families }
func (n *androidNetworkV1) Done() <-chan struct{}           { return n.done }
func (n *androidNetworkV1) DNSServersInto(out *[4]netip.AddrPort) (int, androidbridge.MaintenanceResultV1) {
	if out == nil {
		return 0, androidbridge.MaintenanceInvalidRequest
	}
	*out = [4]netip.AddrPort{}
	if !n.localCurrentV1() {
		return 0, androidbridge.MaintenanceNetworkUnavailable
	}
	*out = n.facts.dns
	return n.facts.count, androidbridge.MaintenanceSuccess
}
func (n *androidNetworkV1) IsCurrent() bool {
	p := n.platform
	if !n.localCurrentV1() || !p.beginV1() {
		return false
	}
	defer p.endV1()
	var current C.uint8_t
	status := p.maintenanceStatusV1(int32(C.kvpn_android_maintenance_network_is_current_v1(p.table, C.uint64_t(p.owner), C.uint64_t(n.id), &current)))
	if status != 0 || current > 1 {
		p.failV1()
		return false
	}
	if current == 0 {
		androidLossSignalV1(p.owner, n.signal, 3)
		return false
	}
	facts, status := p.networkFactsV1(n.id)
	if status != 0 || facts != n.facts {
		androidLossSignalV1(p.owner, n.signal, 3)
		return false
	}
	return n.localCurrentV1()
}
func (n *androidNetworkV1) BindSocket(fd uintptr) androidbridge.MaintenanceResultV1 {
	if fd > math.MaxInt32 {
		return androidbridge.MaintenanceInvalidRequest
	}
	p := n.platform
	if !n.localCurrentV1() || !p.beginV1() {
		return androidbridge.MaintenanceNetworkUnavailable
	}
	defer p.endV1()
	status := p.maintenanceStatusV1(int32(C.kvpn_android_maintenance_network_bind_socket_v1(p.table, C.uint64_t(p.owner), C.uint64_t(n.id), C.int32_t(fd))))
	if status == 0 && !n.localCurrentV1() {
		return androidbridge.MaintenanceNetworkUnavailable
	}
	return status
}
func (n *androidNetworkV1) Close() androidbridge.ErrorCode {
	p := n.platform
	androidPlatformsV1.Lock()
	if n.closed {
		androidPlatformsV1.Unlock()
		return 0
	}
	state := p.stateV1()
	valid := state != nil && state.transport == n && state.signals[1].id == n.signal
	androidPlatformsV1.Unlock()
	if !valid || !p.beginCleanupV1() {
		p.failV1()
		return androidbridge.CodeStateCorrupt
	}
	defer p.endV1()
	result := androidBridgeStatusV1(C.kvpn_android_maintenance_network_close_v1(p.table, C.uint64_t(p.owner), C.uint64_t(n.id)))
	androidPlatformsV1.Lock()
	state = p.stateV1()
	if result != 0 || state == nil || state.failure != 0 {
		if state != nil {
			state.terminal = true
			if state.failure == 0 {
				state.failure = androidbridge.CodeStateCorrupt
			}
		}
		result = androidbridge.CodeStateCorrupt
	} else {
		signal := &state.signals[1]
		if !signal.fired {
			close(signal.done)
		}
		*signal = androidSignalV1{}
		n.closed = true
		state.transport = nil
	}
	androidPlatformsV1.Unlock()
	return result
}
func androidRevisionSignalV1(owner, id uint64) (result androidbridge.ErrorCode) {
	androidPlatformsV1.Lock()
	var state *androidPlatformStateV1
	for i := range androidPlatformsV1.slots {
		candidate := &androidPlatformsV1.slots[i]
		if candidate.platform != nil && candidate.platform.owner == owner {
			state = candidate
			break
		}
	}
	if state == nil || id == 0 || state.signals[0].id != id || state.signals[0].kind != 1 {
		androidPlatformsV1.Unlock()
		return androidbridge.CodeStateCorrupt
	}
	signal := &state.signals[0]
	state.terminal = true
	if signal.running || signal.fired {
		if state.failure == 0 {
			state.failure = androidbridge.CodeStateCorrupt
		}
		androidPlatformsV1.Unlock()
		return androidbridge.CodeStateCorrupt
	}
	signal.running = true
	sink := signal.sink
	androidPlatformsV1.Unlock()
	result = androidbridge.CodeStateCorrupt
	defer func() {
		if recover() != nil {
			result = androidbridge.CodeStateCorrupt
		}
		if result > 25 {
			result = androidbridge.CodeStateCorrupt
		}
		androidPlatformsV1.Lock()
		signal.running = false
		signal.fired = true
		signal.result = result
		if result != 0 && state.failure == 0 {
			state.failure = result
		}
		if state.failure != 0 {
			result = state.failure
		}
		androidPlatformsV1.Unlock()
	}()
	return sink()
}

//export kvpn_android_revision_invalidated_v1
func kvpn_android_revision_invalidated_v1(owner C.uint64_t, signal C.uint64_t) C.int32_t {
	return C.int32_t(androidRevisionSignalV1(uint64(owner), uint64(signal)))
}
