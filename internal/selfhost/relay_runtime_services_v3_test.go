// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"testing"
	"time"
)

func TestRelayRuntimeV3ProjectsVerifiedScopeAndDeadline(t *testing.T) {
	dir, recovery, pass := initializedV2TestState(t)
	now := time.Unix(1_760_000_010, 0).UTC()
	if err := ConfirmRecovery(dir, recovery, pass, now); err != nil {
		t.Fatal(err)
	}
	issued, request, _ := createForServicesV3(t, dir, "projection", now, servicesForIssuanceV3())
	snapshot, err := OpenRelayRuntimeSnapshotV1(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	a, ok := snapshot.AdmissionByClientKeyIDV1(request.ClientAuthKeyID)
	if !ok || a.ProviderID == "" || a.LineageID == "" || !a.ServiceAuthorityDeadlineV3.After(now) || a.ServiceAuthorityDeadlineV3.After(time.Unix(issued.ValidUntil, 0)) {
		t.Fatal("current verified V3 scope/deadline not projected")
	}
}
