// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"bytes"
	"testing"
)

func FuzzActivateVerifiedProfileStateMachine(f *testing.F) {
	seed, _ := validActivationRequest(f)
	f.Add(seed.Artifact)
	f.Add([]byte{0xff})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, artifact []byte) {
		request, store := validActivationRequest(t)
		priorActive, priorLKG := cloneActivationRecord(store.active), cloneActivationRecord(store.lkg)
		request.Artifact = append([]byte(nil), artifact...)
		record, err := ActivateVerifiedProfile(request)
		if err == nil {
			if !bytes.Equal(artifact, seed.Artifact) || !bytes.Equal(record.Artifact, artifact) || !bytes.Equal(store.active.Artifact, artifact) {
				t.Fatal("unrecognized or non-byte-exact artifact activated")
			}
			if store.marked || !activationRecordEqual(store.candidate, ActivationRecord{}) {
				t.Fatal("successful activation left transaction residue")
			}
			return
		}
		if !activationRecordEqual(store.active, priorActive) || !activationRecordEqual(store.lkg, priorLKG) || store.marked || !activationRecordEqual(store.candidate, ActivationRecord{}) {
			t.Fatal("rejected fuzz input changed committed or transactional state")
		}
	})
}
