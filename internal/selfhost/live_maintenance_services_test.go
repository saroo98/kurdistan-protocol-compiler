// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"testing"
	"time"

	"kurdistan/internal/runtime"
)

func TestLiveMaintenanceOpaqueServiceOperations(t *testing.T) {
	owner, _, _, now := maintenanceFixture(t)
	u, err := owner.AdmitUpdateAt(1000, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, ok := u.SnapshotV1()
	if !ok || snapshot.URL != "https://updates.example/profile" || snapshot.TimeoutMillis != 1000 || snapshot.IPFamilies != 1 || !snapshot.Deadline.Equal(now.Add(time.Second)) || !owner.IsUpdateOperationAt(u, now) {
		t.Fatal("incorrect signed update capability")
	}
	snapshot.URL = "https://attacker.invalid"
	again, _ := u.SnapshotV1()
	if again.URL != "https://updates.example/profile" {
		t.Fatal("snapshot mutation rewrote operation authority")
	}
	if owner.IsUpdateOperationAt(u, now.Add(time.Second)) || (&LiveMaintenanceAdmission{}).IsUpdateOperationAt(u, now) {
		t.Fatal("expired/foreign update accepted")
	}
	if _, err := owner.AdmitUpdateAt(1001, now); maintenanceReason(t, err) != LiveMaintenanceInvalidRequest {
		t.Fatal("signed timeout widened")
	}
	r := runtime.ProbeRequestV1{TargetID: 1, Method: 1, AttemptTimeoutMillis: 1000, TotalTimeoutMillis: 1000, Samples: 1}
	p, err := owner.AdmitDisconnectedProbeAt(r, now)
	if err != nil {
		t.Fatal(err)
	}
	a, scope, ok := p.AdmissionV1()
	if !ok || scope != again.Scope || !owner.IsProbeOperationAt(p, now) || len(a.Target().Address) != 4 {
		t.Fatal("probe scope/target authority missing")
	}
	copyOfOperation := p
	p.Destroy()
	p.Destroy()
	if _, _, ok := copyOfOperation.AdmissionV1(); ok || owner.IsProbeOperationAt(copyOfOperation, now) {
		t.Fatal("destroyed borrowed operation retained authority")
	}
	owner.Destroy()
	if _, ok := u.SnapshotV1(); ok {
		t.Fatal("update outlived its owner")
	}
}
