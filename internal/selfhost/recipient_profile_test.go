// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"kurdistan/internal/product/enrollment"
)

func TestEnrollmentRequestMapsToExactRetainedRecipientCapability(t *testing.T) {
	dataDir, _, _ := initializedV2TestState(t)
	state, master, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	zero(master)
	request, private, err := enrollment.Generate(time.Unix(1_760_000_010, 0), time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for index := range private.RecipientPrivate {
			private.RecipientPrivate[index] = 0
		}
		for index := range private.ClientAuthSeed {
			private.ClientAuthSeed[index] = 0
		}
	}()
	record, recipientPublic, clientKeyID, clientPublic, err := recipientCapabilityFromRequest(state, request, 1)
	if err != nil {
		t.Fatal(err)
	}
	if record.Hint != request.RequestID || record.KeyID != request.RecipientKeyID || record.Epoch != 1 ||
		record.ProviderID != state.Delegation.Scope.ProviderID || record.LineageID != state.Delegation.Scope.LineageID || record.Namespace != state.Delegation.Scope.ProfileNamespace ||
		clientKeyID != request.ClientAuthKeyID || !bytes.Equal(recipientPublic, request.RecipientPublic) || !bytes.Equal(clientPublic, request.ClientAuthPublic) {
		t.Fatalf("mapped capability=%+v", record)
	}
	request.RecipientPublic[0] ^= 1
	request.ClientAuthPublic[0] ^= 1
	if bytes.Equal(recipientPublic, request.RecipientPublic) || bytes.Equal(clientPublic, request.ClientAuthPublic) {
		t.Fatal("stored public capabilities alias request memory")
	}
}
