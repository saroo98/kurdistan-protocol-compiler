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

//export kvpn_go_prod_open_stream_v1
func kvpn_go_prod_open_stream_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent C.uint64_t, input *C.uint8_t, length C.uint32_t, child *C.uint64_t) C.int32_t {
	if child == nil {
		return 2
	}
	*child = 0
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	if input == nil || length < 7 || length > 259 {
		return 2
	}
	h, status := androidbridge.OpenProductionStreamV1Scoped(&registry, androidbridge.Handle(parent), unsafe.Slice((*byte)(unsafe.Pointer(input)), int(length)), inv)
	*child = C.uint64_t(h)
	return C.int32_t(status)
}

//export kvpn_go_discard_prod_stream_v1
func kvpn_go_discard_prod_stream_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent, child C.uint64_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	return C.int32_t(androidbridge.DiscardProductionStreamOutputV1(inv, androidbridge.Handle(parent), uint64(child)))
}

//export kvpn_go_stream_receive_v1
func kvpn_go_stream_receive_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent, child C.uint64_t, output *C.uint8_t, capacity C.uint32_t, written *C.uint32_t, token *C.uint64_t) C.int32_t {
	if written == nil || token == nil {
		return 2
	}
	*written, *token = 0, 0
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	if output == nil || capacity == 0 || capacity > 16384 {
		return 2
	}
	n, delivery, status := androidbridge.ReceiveProductionStreamV1Scoped(&registry, androidbridge.Handle(parent), uint64(child), unsafe.Slice((*byte)(unsafe.Pointer(output)), int(capacity)), inv)
	*token = C.uint64_t(delivery)
	if n < 0 || uint64(n) > uint64(capacity) {
		return 18
	}
	*written = C.uint32_t(n)
	return C.int32_t(status)
}

//export kvpn_go_discard_stream_delivery_v1
func kvpn_go_discard_stream_delivery_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent, child, token C.uint64_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	return C.int32_t(androidbridge.DiscardProductionStreamDeliveryOutputV1(inv, androidbridge.Handle(parent), uint64(child), uint64(token)))
}

//export kvpn_go_stream_send_v1
func kvpn_go_stream_send_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent, child C.uint64_t, input *C.uint8_t, length C.uint32_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	if input == nil || length == 0 {
		return 2
	}
	if length > 16384 {
		return 4
	}
	return C.int32_t(androidbridge.SendProductionStreamV1Scoped(&registry, androidbridge.Handle(parent), uint64(child),
		unsafe.Slice((*byte)(unsafe.Pointer(input)), int(length)), inv))
}

//export kvpn_go_stream_confirm_v1
func kvpn_go_stream_confirm_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch C.uint64_t, parent C.uint64_t, child C.uint64_t, token C.uint64_t, length C.uint32_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	return C.int32_t(androidbridge.ConfirmProductionStreamV1Scoped(&registry, androidbridge.Handle(parent), uint64(child), uint64(token), uint32(length), inv))
}

//export kvpn_go_stream_reject_v1
func kvpn_go_stream_reject_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch C.uint64_t, parent C.uint64_t, child C.uint64_t, token C.uint64_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	return C.int32_t(androidbridge.RejectProductionStreamV1Scoped(&registry, androidbridge.Handle(parent), uint64(child), uint64(token), inv))
}

//export kvpn_go_stream_half_close_v1
func kvpn_go_stream_half_close_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch C.uint64_t, parent C.uint64_t, child C.uint64_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	return C.int32_t(androidbridge.HalfCloseProductionStreamV1Scoped(&registry, androidbridge.Handle(parent), uint64(child), inv))
}

//export kvpn_go_stream_cancel_v1
func kvpn_go_stream_cancel_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch C.uint64_t, parent C.uint64_t, child C.uint64_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	return C.int32_t(androidbridge.CancelProductionStreamV1Scoped(&registry, androidbridge.Handle(parent), uint64(child), inv))
}

//export kvpn_go_stream_close_v1
func kvpn_go_stream_close_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch C.uint64_t, parent C.uint64_t, child C.uint64_t) C.int32_t {
	inv, status := newProductionCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if status != 0 {
		return C.int32_t(status)
	}
	return C.int32_t(androidbridge.CloseProductionStreamV1Scoped(&registry, androidbridge.Handle(parent), uint64(child), inv))
}
