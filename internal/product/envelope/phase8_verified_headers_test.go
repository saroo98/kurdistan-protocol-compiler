// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package envelope

import "testing"

func TestDecodeSignedProtectedContextV1(t *testing.T) {
	metadata := ArtifactMetadata{Class: ArtifactSignedPublic, AudienceClass: AudiencePublic}
	protected, err := BuildSignedProtectedHeaders([]byte("issuer-key-1"), metadata)
	if err != nil {
		t.Fatal(err)
	}
	context, err := DecodeSignedProtectedContextV1(protected)
	if err != nil {
		t.Fatal(err)
	}
	if string(context.KeyID) != "issuer-key-1" || context.SuiteID != SuiteClassicalV1 || context.Metadata != metadata || context.ContentType != SignedPayloadContentType {
		t.Fatalf("unexpected signed context: %+v", context)
	}
}

func TestDecodeSealProtectedContextV1(t *testing.T) {
	metadata := ArtifactMetadata{Class: ArtifactDeviceRecipient, AudienceClass: AudienceProvisionedDevice, RecipientHint: "device-hint-1", RecipientEpoch: 2}
	protected, err := BuildSealProtected(metadata)
	if err != nil {
		t.Fatal(err)
	}
	context, err := DecodeSealProtectedContextV1(protected)
	if err != nil {
		t.Fatal(err)
	}
	if context.SuiteID != SuiteClassicalV1 || context.Metadata != metadata || context.ContentType != SignedObjectContentType {
		t.Fatalf("unexpected sealed context: %+v", context)
	}
}
