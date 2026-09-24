// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"testing"
	"time"

	"kurdistan/internal/selfhost"
)

func TestMaintenanceCandidateDeadlineAndPreviewAreClosed(t *testing.T) {
	now := time.Unix(1_780_000_000, 0).UTC()
	deadline, ok := maintenanceCandidateDeadlineV1(now, now.Add(2*time.Hour), now.Add(90*time.Second))
	if !ok || !deadline.Equal(now.Add(60*time.Second)) {
		t.Fatalf("deadline=%v ok=%t", deadline, ok)
	}
	deadline, ok = maintenanceCandidateDeadlineV1(now, now.Add(30*time.Second), now.Add(90*time.Second))
	if !ok || !deadline.Equal(now.Add(30*time.Second)) {
		t.Fatalf("authority deadline=%v ok=%t", deadline, ok)
	}
	if _, ok := maintenanceCandidateDeadlineV1(now, now, now.Add(time.Minute)); ok {
		t.Fatal("accepted exhausted current authority")
	}
	preview := selfhost.LiveMaintenancePreviewV1{DeploymentMatch: true, Generation: 2, ArtifactLength: 10}
	if !validMaintenancePreviewV1(preview) {
		t.Fatal("valid preview rejected")
	}
	preview.RotationFlags = 2
	if validMaintenancePreviewV1(preview) {
		t.Fatal("recipient migration flag accepted")
	}
	preview.RotationFlags = 0
	preview.ChangedCategories[3] = 2
	if validMaintenancePreviewV1(preview) {
		t.Fatal("non-closed changed category accepted")
	}
}

func TestMaintenanceCandidateIDNeverWraps(t *testing.T) {
	owner := maintenanceAuthorityV1{nextChildID: ^MaintenanceCandidateID(0) - 1}
	owner.mu.Lock()
	id, ok := owner.allocateCandidateIDLocked()
	if !ok || id != ^MaintenanceCandidateID(0) {
		owner.mu.Unlock()
		t.Fatalf("last id=%d ok=%t", id, ok)
	}
	id, ok = owner.allocateCandidateIDLocked()
	owner.mu.Unlock()
	if ok || id != 0 || owner.nextChildID != ^MaintenanceCandidateID(0) {
		t.Fatalf("wrapped id=%d ok=%t next=%d", id, ok, owner.nextChildID)
	}
}
