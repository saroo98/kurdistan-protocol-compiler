//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

/*
#include <stdint.h>
*/
import "C"

import "kurdistan/internal/androidbridge"

//export kvpn_phase11_roundtrip
func kvpn_phase11_roundtrip(
	input *C.uint8_t,
	inputLength C.uint32_t,
	output *C.uint8_t,
	capacity C.uint32_t,
	outputLength *C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	encoded, code := inputBytes(input, inputLength, phase11MaximumPayloadBytes)
	if code != androidbridge.CodeOK || len(encoded) == 0 {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	defer clear(encoded)
	roundTripped, code := phase11RoundTrip(encoded)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	defer clear(roundTripped)
	return C.int32_t(writeBytes(roundTripped, output, capacity, outputLength))
}

//export kvpn_runtime_session_roundtrip
func kvpn_runtime_session_roundtrip(
	handle C.uint64_t,
	input *C.uint8_t,
	inputLength C.uint32_t,
	output *C.uint8_t,
	capacity C.uint32_t,
	outputLength *C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	encoded, code := inputBytes(input, inputLength, androidbridge.MaxRuntimePayloadBytes)
	if code != androidbridge.CodeOK || len(encoded) == 0 {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	defer clear(encoded)
	roundTripped, code := androidbridge.RuntimeSessionRoundTrip(
		&registry,
		androidbridge.Handle(handle),
		encoded,
		phase11RoundTrip,
	)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	defer clear(roundTripped)
	return C.int32_t(writeBytes(roundTripped, output, capacity, outputLength))
}
