// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"strconv"

	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/liveprogramcompile"
)

var liveProgramCapabilitiesV1 = []string{
	"multi_stream", "proxy_semantics", "carrier_abstraction", "adapter_interface", "carrier_loss_recovery",
	"carrier_backpressure", "generated_backend", "transcript_binding", "replay_window", "nonce_schedule",
}

const maxLiveProgramCompileAttemptsV1 = 8

type liveProgramCandidateCompilerV1 func(seed int64) (encoded []byte, forbiddenCollision bool, err error)

// compileLiveProgramV1 is the owner-only conversion boundary. Release
// consumers receive only canonical live-program bytes and never import the
// model IR or its compiler.
func compileLiveProgramV1() ([]byte, error) {
	return compileLiveProgramWithV1(rand.Reader, compileLiveProgramCandidateV1)
}

func compileLiveProgramWithV1(random io.Reader, compile liveProgramCandidateCompilerV1) ([]byte, error) {
	if random == nil || compile == nil {
		return nil, errCLIInvalidInput
	}
	for attempt := 0; attempt < maxLiveProgramCompileAttemptsV1; attempt++ {
		var seedBytes [8]byte
		if _, err := io.ReadFull(random, seedBytes[:]); err != nil {
			return nil, err
		}
		seed := int64(binary.BigEndian.Uint64(seedBytes[:]) & ((1 << 63) - 1))
		if seed == 0 {
			seed = 1
		}
		encoded, forbiddenCollision, err := compile(seed)
		if err != nil {
			return nil, err
		}
		if forbiddenCollision {
			continue
		}
		if len(encoded) == 0 {
			return nil, errCLIInvalidInput
		}
		return encoded, nil
	}
	return nil, errCLIInvalidInput
}

func compileLiveProgramCandidateV1(seed int64) ([]byte, bool, error) {
	model, err := compiler.Generate(seed)
	if err != nil || compiler.ValidateDeterministic(model) != nil || ir.Validate(model) != nil {
		return nil, false, errCLIInvalidInput
	}
	canonicalHash, err := ir.CanonicalHash(model)
	if err != nil || canonicalHash != model.GenerationHash || !equalStringsV1(ir.SecurityCapabilities(), liveProgramCapabilitiesV1) {
		return nil, false, errCLIInvalidInput
	}
	program, err := liveprogramcompile.CompileV1(liveprogramcompile.InputV1{
		Profile: model, ClientMandatoryFeatures: append([]string(nil), liveProgramCapabilitiesV1[:2]...),
		RelayMandatoryFeatures: append([]string(nil), liveProgramCapabilitiesV1[:2]...), SelectedFeatures: append([]string(nil), liveProgramCapabilitiesV1...),
	})
	if err != nil || liveprogram.ValidateV1(program) != nil {
		return nil, false, errCLIInvalidInput
	}
	encoded, err := liveprogram.EncodeV1(program)
	if err != nil {
		return nil, false, errCLIInvalidInput
	}
	decoded, err := liveprogram.DecodeV1(encoded)
	if err != nil || liveprogram.ValidateV1(decoded) != nil {
		return nil, false, errCLIInvalidInput
	}
	reencoded, err := liveprogram.EncodeV1(decoded)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		return nil, false, errCLIInvalidInput
	}
	return encoded, containsModelMaterialV1(model, encoded), nil
}

func containsModelMaterialV1(model *ir.Profile, encoded []byte) bool {
	if model == nil {
		return true
	}
	values := []string{
		model.ID, strconv.FormatInt(model.Seed, 10), model.Carrier.Type,
		model.Auth.Mode, model.Auth.KeyID, model.Auth.TestKeyHex,
		"lab_tcp", "hmac-sha256-transcript-test-only", "test-only-",
	}
	for _, value := range values {
		if value != "" && bytes.Contains(encoded, []byte(value)) {
			return true
		}
	}
	return false
}

func equalStringsV1(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
