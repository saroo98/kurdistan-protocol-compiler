//go:build cgo

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

/*
#include "production_scoped_exports_v1.h"
*/
import "C"

import (
	"kurdistan/internal/androidbridge"
	"unsafe"
)

//export kvpn_go_prod_submit_packet_v1
func kvpn_go_prod_submit_packet_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent C.uint64_t, input *C.uint8_t, length C.uint32_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	if input == nil || length == 0 {
		return 2
	}
	if length > 65535 {
		return 4
	}
	return C.int32_t(androidbridge.SubmitProductionPacketV1Scoped(&registry, androidbridge.Handle(parent),
		unsafe.Slice((*byte)(unsafe.Pointer(input)), int(length)), inv))
}

//export kvpn_go_prod_retired_result_v1
func kvpn_go_prod_retired_result_v1(parent C.uint64_t) C.int32_t {
	result, _ := androidbridge.RetiredProductionParentResultV1(&registry, androidbridge.Handle(parent))
	return C.int32_t(result)
}

//export kvpn_go_prod_retirement_publish_v1
func kvpn_go_prod_retirement_publish_v1(parent C.uint64_t, result C.int32_t) {
	androidbridge.PublishRetiredProductionParentResultV1(&registry, androidbridge.Handle(parent), int32(result))
}

//export kvpn_go_prod_cancel_v1
func kvpn_go_prod_cancel_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent C.uint64_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	return C.int32_t(androidbridge.CancelProductionV1Scoped(&registry, androidbridge.Handle(parent), inv))
}

//export kvpn_go_prod_close_v1
func kvpn_go_prod_close_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent C.uint64_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	return C.int32_t(androidbridge.CloseProductionV1Scoped(&registry, androidbridge.Handle(parent), inv))
}

//export kvpn_go_output_overlap_backing_v1
func kvpn_go_output_overlap_backing_v1(frames C.uint64_t, out *C.uint64_t) C.int32_t {
	if out == nil {
		return 2
	}
	*out = 0
	bytes, code := androidOutputOverlapBackingV1(uint64(frames))
	if code != androidbridge.CodeOK {
		return C.int32_t(bridgeFailureP1V1(code, nil))
	}
	*out = C.uint64_t(bytes)
	return 0
}

//export kvpn_go_prod_open_v1
func kvpn_go_prod_open_v1(table *C.kvpn_output_callbacks_v1, platformTable *C.kvpn_android_callbacks_v1,
	owner, call, epoch C.uint64_t, request *C.uint8_t, requestLength C.uint32_t, output *C.uint8_t, capacity C.uint32_t,
	external C.uint64_t, parent *C.uint64_t, written *C.uint32_t, holderState *C.uint8_t) C.int32_t {
	if parent == nil || written == nil || holderState == nil {
		return 2
	}
	*parent, *written, *holderState = 0, 0, 0
	if request == nil || output == nil || requestLength == 0 || requestLength > 2721575 || capacity != 32768 || epoch != 0 || external == 0 {
		return 2
	}
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), 0)
	if status != 0 {
		return C.int32_t(status)
	}
	p, code := newAndroidPlatformV1(platformTable, uint64(owner), 1)
	if code != androidbridge.CodeOK {
		// A duplicate/stale holder is uncertainty, not positive absence.
		if code == androidbridge.CodeStateCorrupt {
			*holderState = 2
		}
		return C.int32_t(bridgeFailureP1V1(code, nil))
	}
	*holderState = 1
	config, code := androidProductionRuntimeConfigV1(p, uint64(external))
	if code != androidbridge.CodeOK {
		return C.int32_t(bridgeFailureP1V1(code, nil))
	}
	h, n, status := androidbridge.OpenProductionV1Scoped(&registry,
		unsafe.Slice((*byte)(unsafe.Pointer(request)), int(requestLength)),
		unsafe.Slice((*byte)(unsafe.Pointer(output)), int(capacity)), config, inv)
	// Preserve actual receipt identity even if later private metadata validation
	// refuses publication. Only the owning retained C core may discard it.
	*parent = C.uint64_t(h)
	if n >= 0 && uint64(n) <= uint64(capacity) {
		*written = C.uint32_t(n)
	} else {
		return 18
	}
	return C.int32_t(status)
}

//export kvpn_go_discard_prod_parent_v1
func kvpn_go_discard_prod_parent_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent C.uint64_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	return C.int32_t(androidbridge.DiscardProductionParentOutputV1(inv, androidbridge.Handle(parent)))
}

//export kvpn_go_prod_run_probe_v1
func kvpn_go_prod_run_probe_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent C.uint64_t, request *C.uint8_t, length C.uint32_t, output *C.uint8_t, written *C.uint32_t) C.int32_t {
	if written == nil {
		return 2
	}
	*written = 0
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	if request == nil || length != 9 || output == nil {
		return 2
	}
	n, status := androidbridge.RunProductionProbeV1Scoped(&registry, androidbridge.Handle(parent), unsafe.Slice((*byte)(unsafe.Pointer(request)), 9), unsafe.Slice((*byte)(unsafe.Pointer(output)), 21), inv)
	if n < 0 || n > 21 {
		return 18
	}
	*written = C.uint32_t(n)
	return C.int32_t(status)
}

//export kvpn_go_prod_receive_packet_v1
func kvpn_go_prod_receive_packet_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent C.uint64_t, output *C.uint8_t, capacity C.uint32_t, written *C.uint32_t, token *C.uint64_t) C.int32_t {
	if written == nil || token == nil {
		return 2
	}
	*written, *token = 0, 0
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	if output == nil || capacity == 0 || capacity > 65535 {
		return 2
	}
	n, delivery, status := androidbridge.ReceiveProductionPacketV1Scoped(&registry, androidbridge.Handle(parent), unsafe.Slice((*byte)(unsafe.Pointer(output)), int(capacity)), inv)
	*token = C.uint64_t(delivery)
	if n < 0 || uint64(n) > uint64(capacity) {
		return 18
	}
	*written = C.uint32_t(n)
	return C.int32_t(status)
}

//export kvpn_go_discard_prod_packet_v1
func kvpn_go_discard_prod_packet_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent, token C.uint64_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	return C.int32_t(androidbridge.DiscardProductionPacketOutputV1(inv, androidbridge.Handle(parent), uint64(token)))
}

//export kvpn_go_prod_next_control_v1
func kvpn_go_prod_next_control_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent C.uint64_t, output *C.uint8_t, capacity C.uint32_t, written *C.uint32_t) C.int32_t {
	if written == nil {
		return 2
	}
	*written = 0
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	if output == nil || capacity == 0 || capacity > 32800 {
		return 2
	}
	n, status := androidbridge.NextProductionControlV1Scoped(&registry, androidbridge.Handle(parent), unsafe.Slice((*byte)(unsafe.Pointer(output)), int(capacity)), inv)
	if n < 0 || uint64(n) > uint64(capacity) || (status != 0 && n != 0) {
		return 18
	}
	*written = C.uint32_t(n)
	return C.int32_t(status)
}

//export kvpn_go_prod_confirm_socket_v1
func kvpn_go_prod_confirm_socket_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch C.uint64_t, parent C.uint64_t, token C.uint64_t, protected_ok C.uint8_t, has_network C.uint8_t, network C.uint64_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	return C.int32_t(androidbridge.ConfirmProductionSocketV1Scoped(&registry, androidbridge.Handle(parent), uint64(token), uint8(protected_ok), uint8(has_network), uint64(network), inv))
}

//export kvpn_go_prod_confirm_packet_v1
func kvpn_go_prod_confirm_packet_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch C.uint64_t, parent C.uint64_t, token C.uint64_t, length C.uint32_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	return C.int32_t(androidbridge.ConfirmProductionPacketV1Scoped(&registry, androidbridge.Handle(parent), uint64(token), uint32(length), inv))
}

//export kvpn_go_prod_reject_packet_v1
func kvpn_go_prod_reject_packet_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch C.uint64_t, parent C.uint64_t, token C.uint64_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	return C.int32_t(androidbridge.RejectProductionPacketV1Scoped(&registry, androidbridge.Handle(parent), uint64(token), inv))
}

//export kvpn_go_prod_handover_v1
func kvpn_go_prod_handover_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch C.uint64_t, parent C.uint64_t, has_network C.uint8_t, network C.uint64_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	return C.int32_t(androidbridge.HandoverProductionV1Scoped(&registry, androidbridge.Handle(parent), uint8(has_network), uint64(network), inv))
}

//export kvpn_go_prod_reconnect_v1
func kvpn_go_prod_reconnect_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent C.uint64_t, reason C.uint8_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	return C.int32_t(androidbridge.ReconnectProductionV1Scoped(&registry, androidbridge.Handle(parent), uint8(reason), inv))
}
