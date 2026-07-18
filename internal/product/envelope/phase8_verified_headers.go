// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package envelope

import (
	"errors"

	"github.com/fxamacker/cbor/v2"
)

type SignedProtectedContextV1 struct {
	KeyID       []byte
	SuiteID     SuiteID
	ContentType string
	Metadata    ArtifactMetadata
}

func DecodeSignedProtectedContextV1(protected []byte) (SignedProtectedContextV1, error) {
	metadataBytes, err := signedMetadataBytes(protected)
	if err != nil {
		return SignedProtectedContextV1{}, err
	}
	var headers map[int64]cbor.RawMessage
	if err := unmarshalStrict(protected, &headers); err != nil {
		return SignedProtectedContextV1{}, errors.New("envelope: signed protected context is invalid")
	}
	var keyID []byte
	var suiteID uint64
	var contentType string
	if err := unmarshalStrict(headers[COSEHeaderKeyID], &keyID); err != nil || unmarshalStrict(headers[COSEHeaderProfileSuiteID], &suiteID) != nil || unmarshalStrict(headers[COSEHeaderContent], &contentType) != nil {
		return SignedProtectedContextV1{}, errors.New("envelope: signed protected context is invalid")
	}
	metadata, err := decodeArtifactMetadata(metadataBytes)
	if err != nil {
		return SignedProtectedContextV1{}, err
	}
	return SignedProtectedContextV1{KeyID: append([]byte(nil), keyID...), SuiteID: SuiteID(suiteID), ContentType: contentType, Metadata: metadata}, nil
}

type SealProtectedContextV1 struct {
	SuiteID     SuiteID
	ContentType string
	Metadata    ArtifactMetadata
}

func DecodeSealProtectedContextV1(protected []byte) (SealProtectedContextV1, error) {
	metadataBytes, err := outerMetadataBytes(protected)
	if err != nil {
		return SealProtectedContextV1{}, err
	}
	var headers map[uint64]cbor.RawMessage
	if err := unmarshalStrict(protected, &headers); err != nil {
		return SealProtectedContextV1{}, errors.New("envelope: seal protected context is invalid")
	}
	var suiteID uint64
	var contentType string
	if err := unmarshalStrict(headers[2], &suiteID); err != nil || unmarshalStrict(headers[3], &contentType) != nil {
		return SealProtectedContextV1{}, errors.New("envelope: seal protected context is invalid")
	}
	metadata, err := decodeArtifactMetadata(metadataBytes)
	if err != nil {
		return SealProtectedContextV1{}, err
	}
	return SealProtectedContextV1{SuiteID: SuiteID(suiteID), ContentType: contentType, Metadata: metadata}, nil
}
