// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	runtimeengine "kurdistan/internal/runtime"
	"testing"
)

func TestProductionPacketPolicyRejectionIsNotASessionFailure(t *testing.T) {
	for _, err := range []error{runtimeengine.ErrPacketInvalid, runtimeengine.ErrPacketFamily,
		runtimeengine.ErrPacketProtocol, runtimeengine.ErrPacketSource, runtimeengine.ErrPacketDestination,
		runtimeengine.ErrPacketFragmented} {
		if got := productionOperationStatusV1(err); got != 10 {
			t.Errorf("packet refusal mapped to session failure: %v status=%d", err, got)
		}
	}
}

func TestProductionOperationV1PeerRevocationIsNotVerifierProof(t *testing.T) {
	if s := productionOperationStatusV1(runtimeengine.ServiceAuthorityRevokedV1); s != 7 {
		t.Fatal("peer category fabricated native revocation", s)
	}
	if s := productionOperationStatusV1(runtimeengine.ServiceUnreachableV1); s != 11 {
		t.Fatal("service result namespace", s)
	}
}

func TestProductionPacketV1UnpublishedParentCannotReachPort(t *testing.T) {
	r := new(HandleRegistry)
	if s := SubmitProductionPacketV1(r, 0, []byte{1}); s != 3 {
		t.Fatal(s)
	}
	if n, token, s := ReceiveProductionPacketV1(r, 0, make([]byte, 40)); n != 0 || token != 0 || s != 3 {
		t.Fatal(n, token, s)
	}
	if s := ConfirmProductionPacketV1(r, 0, 1, 1); s != 3 {
		t.Fatal(s)
	}
	if s := RejectProductionPacketV1(r, 0, 1); s != 3 {
		t.Fatal(s)
	}
}
