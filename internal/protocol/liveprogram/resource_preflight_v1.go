// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package liveprogram

import "github.com/fxamacker/cbor/v2"

// PreflightResourcesV1 admits typed, bounded program shape without generic CBOR
// decoding, canonical re-encoding, compilation, or semantic authority validation.
func PreflightResourcesV1(encoded []byte) error {
	if len(encoded) == 0 || len(encoded) > MaxEncodedBytes {
		return fail(ErrorSize)
	}
	p, err := decodeProgramFieldsWithDecoderV1(encoded, decodeResourceFieldV1)
	if err != nil {
		return err
	}
	defer clear(p.Frame.Compiled.DataTypeTag)
	defer clear(p.Frame.Compiled.PaddingTypeTag)
	if len(p.Frame.HeaderOrder) != 4 || len(p.Frame.Compiled.DataTypeTag) == 0 || len(p.Frame.Compiled.DataTypeTag) > 255 || len(p.Frame.Compiled.PaddingTypeTag) == 0 || len(p.Frame.Compiled.PaddingTypeTag) > 255 {
		return fail(ErrorSize)
	}
	for _, m := range p.Messages {
		if len(m.WireSymbol) == 0 || len(m.WireSymbol) > 96 {
			return fail(ErrorSize)
		}
	}
	for _, values := range [][]string{p.Security.ClientMandatoryCapabilities, p.Security.RelayMandatoryCapabilities, p.Security.SelectedCapabilities} {
		if len(values) == 0 || len(values) > 32 {
			return fail(ErrorSize)
		}
	}
	// Other scalar/string leaves have the aggregate encoded-byte ceiling. Their
	// semantic enumerations and canonical numeric spelling remain legacy checks.
	return nil
}

func decodeResourceFieldV1(raw []byte, destination any) error {
	if len(raw) == 0 {
		return fail(ErrorSchema)
	}
	var major byte
	switch destination.(type) {
	case *[]byte:
		major = 2
	case *string:
		major = 3
	case *uint32:
		major = 0
	case *int:
		if raw[0]>>5 > 1 {
			return fail(ErrorSchema)
		}
		major = raw[0] >> 5
	case *float64:
		if raw[0] != 0xf9 && raw[0] != 0xfa && raw[0] != 0xfb {
			return fail(ErrorSchema)
		}
		major = 7
	case *[]cbor.RawMessage:
		major = 4
	case *[]string:
		if raw[0]>>5 != 4 {
			return fail(ErrorSchema)
		}
		var values []cbor.RawMessage
		if decode(raw, &values) != nil {
			return fail(ErrorSchema)
		}
		defer func() {
			for _, value := range values {
				clear(value)
			}
		}()
		for _, value := range values {
			if len(value) == 0 || value[0]>>5 != 3 {
				return fail(ErrorSchema)
			}
		}
		major = 4
	default:
		return fail(ErrorSchema)
	}
	if raw[0]>>5 != major {
		return fail(ErrorSchema)
	}
	return decode(raw, destination)
}
