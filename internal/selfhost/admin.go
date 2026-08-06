// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const staleLockMinimumAge = 5 * time.Minute

type DoctorCheck struct {
	Name, Status, Detail string
}

type DoctorReport struct {
	Schema, Overall string
	Checks          []DoctorCheck
}

type RedactedAudit struct {
	Schema, DeploymentFingerprint, Head string
	Entries                             []RedactedAuditEntry
}

type RedactedAuditEntry struct {
	Sequence uint64
	At       int64
	Action   string
}

func Doctor(dataDir string, now time.Time) (DoctorReport, error) {
	report := DoctorReport{Schema: "kurd-selfhost-doctor-v1", Overall: "PASS", Checks: []DoctorCheck{}}
	add := func(name string, err error, detail string) {
		status := "PASS"
		if err != nil {
			status, report.Overall = "FAIL", "FAIL"
		}
		report.Checks = append(report.Checks, DoctorCheck{Name: name, Status: status, Detail: detail})
	}
	state, master, err := loadState(dataDir)
	if err != nil {
		add("state-integrity", err, "authenticated state could not be opened")
		return report, err
	}
	zero(master)
	add("state-integrity", nil, "authenticated state and audit chain verified")
	add("clock-health", validateClockTransition(state.LastObservedAt, now.UTC().Unix()), "local clock is within the persisted ordering window")
	if _, err := os.Stat(filepath.Join(dataDir, lockDirectoryName)); err == nil {
		add("transaction-lock", ErrBusy, "a transaction lock exists; confirm no kurdctl process is active before repair")
	} else {
		add("transaction-lock", nil, "no stale transaction lock detected")
	}
	for _, name := range []string{masterKeyFileName, stateFileName} {
		info, statErr := os.Stat(filepath.Join(dataDir, name))
		if statErr == nil && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			statErr = errors.New("permissions are broader than owner-only")
		}
		add("permissions-"+name, statErr, "sensitive local state is owner-only")
	}
	add("recovery-confirmed", boolError(!state.RecoveryConfirmed), "offline root recovery was confirmed")
	add("deployment-enabled", boolError(state.Revocations.EmergencyDenied), "deployment-local deny is not active")
	delivery, deliveryErr := PublicationDeliveryStatus(dataDir)
	deliveryDetail := "publication cursor is authenticated"
	if deliveryErr == nil && delivery.Pending {
		deliveryDetail = "publication outbox is pending and will be retried"
	}
	add("publication-outbox", deliveryErr, deliveryDetail)
	return report, nil
}

func ExportRedactedAudit(dataDir, destination string) error {
	if destination == "" || recoveryInsideDataDir(dataDir, destination) {
		return ErrInvalidInput
	}
	state, master, err := loadState(dataDir)
	if err != nil {
		return err
	}
	zero(master)
	value := RedactedAudit{Schema: "kurd-selfhost-redacted-audit-v1", DeploymentFingerprint: state.RootFingerprint, Head: state.Audit[len(state.Audit)-1].Digest}
	for _, entry := range state.Audit {
		value.Entries = append(value.Entries, RedactedAuditEntry{Sequence: entry.Sequence, At: entry.At, Action: entry.Action})
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	return writeExclusive(destination, encoded, 0o600)
}

// RepairStaleLock removes an abandoned transaction lock only after the caller
// supplies the exact confirmation token and the lock has remained untouched for
// long enough that a normal transaction cannot still own it. The authenticated
// state is opened before removal so this operation cannot turn corrupt state
// into an apparently healthy deployment.
func RepairStaleLock(dataDir, confirmation string, now time.Time) error {
	if dataDir == "" || confirmation != "stale-lock" || now.IsZero() {
		return ErrInvalidInput
	}
	lockPath := filepath.Join(dataDir, lockDirectoryName)
	info, err := os.Stat(lockPath)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil || !info.IsDir() {
		return ErrBusy
	}
	if age := now.UTC().Sub(info.ModTime().UTC()); age < staleLockMinimumAge || age < 0 {
		return ErrBusy
	}
	entries, err := os.ReadDir(lockPath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".") {
			return ErrBusy
		}
	}
	state, master, err := loadState(dataDir)
	if err != nil {
		return err
	}
	zero(master)
	if state.Revision == 0 {
		return ErrStateCorrupt
	}
	return os.Remove(lockPath)
}

func boolError(value bool) error {
	if value {
		return ErrInvalidInput
	}
	return nil
}
