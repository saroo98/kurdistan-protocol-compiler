// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"crypto/rand"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"kurdistan/internal/product/enrollment"
)

func TestRecipientUseLedgerRejectsDuplicateCapabilities(t *testing.T) {
	dataDir, _, _ := initializedV2TestState(t)
	state, master, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(master)
	request, private, err := enrollment.Generate(time.Unix(1_760_000_010, 0), time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivate(private)
	record := recipientUseRecord(request, "profiles.one", 1_760_000_011)
	state.RecipientUses = recipientUseLedgerV1{RegistryID: "registry.0011223344556677", Records: []recipientUseRecordV1{record}}
	if err := validateState(state, master); err != nil {
		t.Fatalf("valid ledger rejected: %v", err)
	}
	duplicate := record
	duplicate.ProfileID = "profiles.two"
	duplicate.RequestTag = recipientUseTag("request", []byte("different-request"))
	state.RecipientUses.Records = append(state.RecipientUses.Records, duplicate)
	if err := validateState(state, master); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("duplicate recipient capability accepted: %v", err)
	}
}

func TestOwnerRecipientRegistryRejectsReplayAndRequiresExactCrossDeploymentConfirmation(t *testing.T) {
	registryDir := filepath.Join(t.TempDir(), "registry")
	now := time.Unix(1_760_000_010, 0)
	request, private, err := enrollment.Generate(now, time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivate(private)

	first, err := reserveOwnerRecipientUse(registryDir, "", "deployment.one", "profiles.one", request, now.Unix(), "")
	if err != nil {
		t.Fatal(err)
	}
	if first.RegistryID == "" || first.Record.ProfileID != "profiles.one" {
		t.Fatalf("unexpected reservation: %+v", first)
	}
	if _, err := reserveOwnerRecipientUse(registryDir, first.RegistryID, "deployment.one", "profiles.two", request, now.Add(time.Second).Unix(), "recipient-reuse"); !errors.Is(err, ErrRecipientReplay) {
		t.Fatalf("same-deployment replay error=%v", err)
	}
	if _, err := reserveOwnerRecipientUse(registryDir, "", "deployment.two", "profiles.two", request, now.Add(2*time.Second).Unix(), "wrong"); !errors.Is(err, ErrRecipientReplay) {
		t.Fatalf("cross-deployment reuse without exact confirmation error=%v", err)
	}
	second, err := reserveOwnerRecipientUse(registryDir, "", "deployment.two", "profiles.two", request, now.Add(3*time.Second).Unix(), "recipient-reuse")
	if err != nil {
		t.Fatal(err)
	}
	if second.RegistryID != first.RegistryID || second.Record.RequestTag != first.Record.RequestTag {
		t.Fatalf("cross-deployment reservation mismatch: first=%+v second=%+v", first, second)
	}
}

func TestOwnerRecipientRegistryFailsClosedAfterLossOrIdentityMismatch(t *testing.T) {
	registryDir := filepath.Join(t.TempDir(), "registry")
	now := time.Unix(1_760_000_010, 0)
	request, private, err := enrollment.Generate(now, time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivate(private)
	reservation, err := reserveOwnerRecipientUse(registryDir, "", "deployment.one", "profiles.one", request, now.Unix(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reserveOwnerRecipientUse(filepath.Join(t.TempDir(), "missing"), reservation.RegistryID, "deployment.one", "profiles.two", request, now.Add(time.Second).Unix(), ""); !errors.Is(err, ErrRecipientRegistry) {
		t.Fatalf("missing registry error=%v", err)
	}
	if _, err := reserveOwnerRecipientUse(registryDir, "registry.ffffffffffffffff", "deployment.one", "profiles.two", request, now.Add(2*time.Second).Unix(), ""); !errors.Is(err, ErrRecipientRegistry) {
		t.Fatalf("registry identity mismatch error=%v", err)
	}
}

func TestOwnerRecipientRegistrySerializesConcurrentReservation(t *testing.T) {
	registryDir := filepath.Join(t.TempDir(), "registry")
	now := time.Unix(1_760_000_010, 0)
	request, private, err := enrollment.Generate(now, time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivate(private)

	const workers = 12
	start := make(chan struct{})
	results := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			<-start
			_, reserveErr := reserveOwnerRecipientUse(registryDir, "", "deployment.one", "profiles.concurrent", request, now.Add(time.Duration(index)*time.Second).Unix(), "")
			results <- reserveErr
		}(index)
	}
	close(start)
	group.Wait()
	close(results)

	successes := 0
	for result := range results {
		switch {
		case result == nil:
			successes++
		case errors.Is(result, ErrBusy), errors.Is(result, ErrRecipientReplay):
		default:
			t.Fatalf("unexpected reservation result: %v", result)
		}
	}
	if successes != 1 {
		t.Fatalf("successful reservations=%d, want 1", successes)
	}
	registry, key, err := loadOrInitializeOwnerRecipientRegistry(registryDir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer zero(key)
	if len(registry.Records) != 1 {
		t.Fatalf("registry records=%d, want 1", len(registry.Records))
	}
}

func clearEnrollmentPrivate(bundle enrollment.PrivateBundleV1) {
	clear(bundle.RecipientPrivate)
	clear(bundle.ClientAuthSeed)
}
