// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

func encodeCanonical(value any) ([]byte, error) {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return mode.Marshal(value)
}

func decodeCanonical(encoded []byte, destination any, maxBytes int) error {
	if err := decodeCanonicalFields(encoded, destination, maxBytes, maxStateArrayElements); err != nil {
		return err
	}
	canonical, err := encodeCanonical(destination)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return errors.Join(ErrInvalidInput, errors.New("non-canonical encoding"))
	}
	return nil
}

func decodeCanonicalFields(encoded []byte, destination any, maxBytes, maxArray int) error {
	if len(encoded) == 0 || len(encoded) > maxBytes {
		return ErrInvalidInput
	}
	options := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		MaxArrayElements:  maxArray,
		MaxMapPairs:       256,
		MaxNestedLevels:   16,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		UTF8:              cbor.UTF8RejectInvalid,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}
	mode, err := options.DecMode()
	if err != nil || mode.Unmarshal(encoded, destination) != nil {
		return ErrInvalidInput
	}
	return nil
}
