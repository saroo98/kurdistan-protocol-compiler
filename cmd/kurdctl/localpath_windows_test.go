// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateOutputIsProtectedAtCreation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private-output")
	if err := createWindowsPrivateDirectory(root); err != nil {
		t.Fatal(err)
	}
	if err := verifyWindowsPrivatePath(root, true); err != nil {
		t.Fatalf("created directory was not born private: %v", err)
	}
	file := filepath.Join(root, "artifact")
	if err := createWindowsPrivateFile(file, []byte("artifact")); err != nil {
		t.Fatal(err)
	}
	if err := verifyWindowsPrivatePath(file, false); err != nil {
		t.Fatalf("created file was not born private: %v", err)
	}
	if value, err := os.ReadFile(file); err != nil || string(value) != "artifact" {
		t.Fatalf("value=%q err=%v", value, err)
	}
}

func TestProtectPrivatePathPreservesOwnerWithoutOwnerReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(path, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	ownerBefore := windowsPathOwnerForTest(t, path)
	restrictWindowsPathWithoutWriteOwnerForKurdctlTest(t, path, ownerBefore)
	if err := openWindowsPathAccessForKurdctlTest(path, windows.WRITE_DAC); err != nil {
		t.Fatalf("fixture lacks WRITE_DAC: %v", err)
	}
	if err := openWindowsPathAccessForKurdctlTest(path, windows.WRITE_OWNER); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("nonprivileged fixture WRITE_OWNER error=%v, want ERROR_ACCESS_DENIED", err)
	}
	if err := protectPrivatePath(path, false); err != nil {
		t.Fatalf("DACL-only publication failed: %v", err)
	}
	ownerAfter := windowsPathOwnerForTest(t, path)
	if !ownerAfter.Equals(ownerBefore) {
		t.Fatal("private-path publication changed the existing owner")
	}
	if err := verifyWindowsPrivatePath(path, false); err != nil {
		t.Fatalf("final owner/DACL verification failed: %v", err)
	}
}

func TestProtectPrivatePathOwnerValidationRejectsUnexpectedOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	operations := defaultPrivatePathProtectionOperations()
	setCalls, closeCalls := 0, 0
	operations.verifyOwner = func(windows.Handle, *windows.SID) error {
		return windows.ERROR_INVALID_OWNER
	}
	operations.setDACL = func(windows.Handle, *windows.ACL) error {
		setCalls++
		return nil
	}
	operations.close = func(handle windows.Handle) error {
		closeCalls++
		return windows.CloseHandle(handle)
	}
	err := protectPrivatePathWithOperations(path, false, operations)
	if !errors.Is(err, windows.ERROR_INVALID_OWNER) || !strings.Contains(err.Error(), "verify private path owner") {
		t.Fatalf("owner validation error=%v", err)
	}
	if errors.Is(err, errUnsupportedFilesystem) {
		t.Fatalf("owner validation error lost its actionable category: %v", err)
	}
	if setCalls != 0 || closeCalls != 1 {
		t.Fatalf("setCalls=%d closeCalls=%d, want 0/1", setCalls, closeCalls)
	}
	assertKurdctlPrivateFileContent(t, path, []byte("previous"))
}

func TestProtectPrivatePathDACLFailuresRemainFailClosed(t *testing.T) {
	tests := []struct {
		name         string
		operation    string
		setError     error
		verifyError  error
		wantSetCalls int
		wantVerifies int
	}{
		{name: "application", operation: "set private DACL", setError: windows.ERROR_ACCESS_DENIED, wantSetCalls: 1},
		{name: "verification", operation: "verify private DACL", verifyError: windows.ERROR_INVALID_SECURITY_DESCR, wantSetCalls: 1, wantVerifies: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private")
			want := []byte("previous-valid-output")
			if err := os.WriteFile(path, want, 0o600); err != nil {
				t.Fatal(err)
			}
			operations := defaultPrivatePathProtectionOperations()
			setCalls, verifyCalls, closeCalls := 0, 0, 0
			operations.setDACL = func(handle windows.Handle, dacl *windows.ACL) error {
				setCalls++
				if test.setError != nil {
					return test.setError
				}
				return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
			}
			operations.verify = func(windows.Handle, bool, *windows.SID) error {
				verifyCalls++
				return test.verifyError
			}
			operations.close = func(handle windows.Handle) error {
				closeCalls++
				return windows.CloseHandle(handle)
			}
			err := protectPrivatePathWithOperations(path, false, operations)
			wantError := test.setError
			if wantError == nil {
				wantError = test.verifyError
			}
			if !errors.Is(err, wantError) || !strings.Contains(err.Error(), test.operation) {
				t.Fatalf("error=%v, want operation %q and error %v", err, test.operation, wantError)
			}
			if errors.Is(err, errUnsupportedFilesystem) {
				t.Fatalf("actionable ACL error translated to unsupported filesystem: %v", err)
			}
			if setCalls != test.wantSetCalls || verifyCalls != test.wantVerifies || closeCalls != 1 {
				t.Fatalf("set=%d verify=%d close=%d, want %d/%d/1", setCalls, verifyCalls, closeCalls, test.wantSetCalls, test.wantVerifies)
			}
			assertKurdctlPrivateFileContent(t, path, want)
			renamed := path + ".renamed"
			if err := os.Rename(path, renamed); err != nil {
				t.Fatalf("private path handle leaked after failure: %v", err)
			}
		})
	}
}

func TestProtectPrivateHandleOwnerRejectsDifferentSID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(path, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	handle := openKurdctlPrivatePathHandleForTest(t, path, false, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL)
	defer windows.CloseHandle(handle)
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateHandleOwner(handle, localSystem); err == nil {
		t.Fatal("unexpected owner was accepted")
	}
}

func TestOwnerAndDACLPublicationRequiresWriteOwnerInNonprivilegedFixture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(path, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	owner := windowsPathOwnerForTest(t, path)
	restrictWindowsPathWithoutWriteOwnerForKurdctlTest(t, path, owner)
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(owner),
		},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil)
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("owner-plus-DACL publication error=%v, want ERROR_ACCESS_DENIED", err)
	}
}

func windowsPathOwnerForTest(t *testing.T, path string) *windows.SID {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		t.Fatalf("read owner: %v", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		t.Fatalf("decode owner: %v", err)
	}
	return owner
}

func openWindowsPathAccessForKurdctlTest(path string, access uint32) error {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(pointer, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	return windows.CloseHandle(handle)
}

func restrictWindowsPathWithoutWriteOwnerForKurdctlTest(t *testing.T, path string, owner *windows.SID) {
	t.Helper()
	if owner == nil || !owner.IsValid() {
		t.Fatal("invalid fixture owner")
	}
	permissions := windows.ACCESS_MASK(windows.SPECIFIC_RIGHTS_ALL | windows.DELETE | windows.READ_CONTROL | windows.WRITE_DAC | windows.SYNCHRONIZE)
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: permissions,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(owner),
		},
	}}, nil)
	if err != nil {
		t.Fatalf("construct constrained fixture DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatalf("publish constrained fixture DACL: %v", err)
	}
}

func openKurdctlPrivatePathHandleForTest(t *testing.T, path string, directory bool, access uint32) windows.Handle {
	t.Helper()
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	attributes := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		attributes |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(pointer, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, attributes, 0)
	if err != nil {
		t.Fatal(err)
	}
	return handle
}

func assertKurdctlPrivateFileContent(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("private file changed: got=%q err=%v", got, err)
	}
}
