// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package selfhost

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestProtectSelfhostPrivatePathCanReplaceInheritedDACLWithoutOwnerRewrite(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "inherited")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "authority.cbor")
	if err := os.WriteFile(path, []byte("authority"), 0o600); err != nil {
		t.Fatal(err)
	}
	restrictWindowsPathWithoutWriteOwnerForSelfhostTest(t, path)
	if err := openWindowsPathAccessForTest(path, windows.WRITE_DAC); err != nil {
		t.Fatalf("fixture lacks WRITE_DAC: %v", err)
	}
	if err := openWindowsPathAccessForTest(path, windows.WRITE_OWNER); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("fixture WRITE_OWNER error=%v, want ERROR_ACCESS_DENIED", err)
	}
	if err := protectSelfhostPrivatePath(path, false); err != nil {
		t.Fatalf("owner-verified DACL protection failed: %v", err)
	}
	if err := verifySelfhostPrivatePath(path, false); err != nil {
		t.Fatalf("protected path verification failed: %v", err)
	}
}

func TestSelfhostPrivatePathOwnerAdmissionAllowsOnlyTokenUserOrDefaultOwner(t *testing.T) {
	user, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	defaultOwner, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	if !selfhostPrivatePathOwnerAllowed(user, user, defaultOwner) {
		t.Fatal("token user owner was rejected")
	}
	if !selfhostPrivatePathOwnerAllowed(defaultOwner, user, defaultOwner) {
		t.Fatal("token default owner was rejected")
	}
	if selfhostPrivatePathOwnerAllowed(unrelated, user, defaultOwner) {
		t.Fatal("unrelated owner was accepted")
	}
}

func TestApplyRestorePublishesPrivateWindowsTreeBeforeRecovery(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	restored := filepath.Join(root, "restored")
	recovery := filepath.Join(root, "offline", "recovery")
	backup := filepath.Join(root, "offline", "backup")
	passphrase := []byte("private publication regression")
	now := time.Unix(1_800_200_000, 0).UTC()
	if _, err := Initialize(InitOptions{DataDir: source, DeploymentName: "private-publication", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := ConfirmRecovery(source, recovery, passphrase, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	summary, err := CreateBackup(BackupOptions{DataDir: source, Destination: backup, Passphrase: passphrase, Now: now.Add(2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyRestore(RestoreOptions{BackupPath: backup, DataDir: restored, ExpectedDigest: summary.Digest, Passphrase: passphrase, Now: now.Add(3 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct {
		name      string
		path      string
		directory bool
	}{
		{name: "restored directory", path: restored, directory: true},
		{name: "restored master key", path: filepath.Join(restored, masterKeyFileName)},
		{name: "restored state", path: filepath.Join(restored, stateFileName)},
	} {
		if err := verifySelfhostPrivatePath(target.path, target.directory); err != nil {
			t.Fatalf("%s was published without the private Windows descriptor: %v", target.name, err)
		}
	}
	if err := ConfirmRecovery(restored, recovery, passphrase, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("restored authority publication failed: %v", err)
	}
	if err := verifySelfhostPrivatePath(filepath.Join(restored, recipientAuthorityFileName), false); err != nil {
		t.Fatalf("restored recipient authority is not private: %v", err)
	}
}

func TestProtectSelfhostPrivatePathFailureRetainsWindowsErrorAndClosesHandleOnce(t *testing.T) {
	for _, test := range []struct {
		name              string
		setError          error
		verificationError error
		wantSetCalls      int
		wantVerifyCalls   int
	}{
		{name: "DACL application", setError: windows.ERROR_ACCESS_DENIED, wantSetCalls: 1},
		{name: "DACL verification", verificationError: windows.ERROR_INVALID_SECURITY_DESCR, wantSetCalls: 1, wantVerifyCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "authority.cbor")
			if err := os.WriteFile(path, []byte("authority"), 0o600); err != nil {
				t.Fatal(err)
			}
			setCalls, verifyCalls, closeCalls := 0, 0, 0
			operations := selfhostPrivatePathProtectionOperations{
				verifyOwner: func(windows.Handle, *windows.SID, *windows.SID) error { return nil },
				setDACL: func(handle windows.Handle, dacl *windows.ACL) error {
					setCalls++
					if test.setError != nil {
						return test.setError
					}
					return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
				},
				verify: func(windows.Handle, bool, *windows.SID, *windows.SID) error {
					verifyCalls++
					return test.verificationError
				},
				close: func(handle windows.Handle) error {
					closeCalls++
					return windows.CloseHandle(handle)
				},
			}
			err := protectSelfhostPrivatePathWithOperations(path, false, operations)
			wantWindowsError := test.setError
			if wantWindowsError == nil {
				wantWindowsError = test.verificationError
			}
			if !errors.Is(err, ErrRecipientRegistry) || !errors.Is(err, wantWindowsError) {
				t.Fatalf("error=%v, want recipient-registry and %v", err, wantWindowsError)
			}
			if setCalls != test.wantSetCalls || verifyCalls != test.wantVerifyCalls || closeCalls != 1 {
				t.Fatalf("set=%d verify=%d close=%d, want set=%d verify=%d close=1", setCalls, verifyCalls, closeCalls, test.wantSetCalls, test.wantVerifyCalls)
			}
			renamed := path + ".renamed"
			if err := os.Rename(path, renamed); err != nil {
				t.Fatalf("path handle leaked after failure: %v", err)
			}
			if err := os.Remove(renamed); err != nil {
				t.Fatalf("renamed path could not be removed: %v", err)
			}
		})
	}
}

func TestProtectSelfhostPrivatePathRejectsInvalidSubjectsBeforeDACLMutation(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		path      string
		directory bool
	}{
		{name: "missing", path: filepath.Join(root, "missing")},
		{name: "file-as-directory", path: file, directory: true},
		{name: "directory-as-file", path: root},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := protectSelfhostPrivatePath(test.path, test.directory); !errors.Is(err, ErrRecipientRegistry) {
				t.Fatalf("error=%v, want recipient-registry rejection", err)
			}
		})
	}

	setCalls, closeCalls := 0, 0
	err := protectSelfhostPrivatePathWithOperations(file, false, selfhostPrivatePathProtectionOperations{
		verifyOwner: func(windows.Handle, *windows.SID, *windows.SID) error { return ErrRecipientRegistry },
		setDACL: func(windows.Handle, *windows.ACL) error {
			setCalls++
			return nil
		},
		verify: func(windows.Handle, bool, *windows.SID, *windows.SID) error { return nil },
		close: func(handle windows.Handle) error {
			closeCalls++
			return windows.CloseHandle(handle)
		},
	})
	if !errors.Is(err, ErrRecipientRegistry) || setCalls != 0 || closeCalls != 1 {
		t.Fatalf("wrong-owner error=%v set=%d close=%d", err, setCalls, closeCalls)
	}
}

func TestPrepareRestoreStagingFailsClosedBeforeSensitiveContent(t *testing.T) {
	root := t.TempDir()
	previousAuthority := filepath.Join(root, "previous-authority")
	previousBytes := []byte("previous valid authority")
	if err := os.WriteFile(previousAuthority, previousBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "DACL application failure", err: windows.ERROR_ACCESS_DENIED},
		{name: "DACL verification failure", err: windows.ERROR_INVALID_SECURITY_DESCR},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := filepath.Join(root, strings.ReplaceAll(test.name, " ", "-"))
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			protectCalls, removeCalls := 0, 0
			staging, err := prepareRestoreStagingWithOperations(
				parent,
				func(path string, directory bool) error {
					protectCalls++
					if !directory {
						t.Fatal("restore staging protection was not classified as a directory")
					}
					entries, readErr := os.ReadDir(path)
					if readErr != nil || len(entries) != 0 {
						t.Fatalf("sensitive content existed before DACL protection: entries=%d err=%v", len(entries), readErr)
					}
					return test.err
				},
				func(path string) error {
					removeCalls++
					return os.RemoveAll(path)
				},
			)
			if staging != "" || !errors.Is(err, test.err) {
				t.Fatalf("staging=%q error=%v, want empty staging and %v", staging, err, test.err)
			}
			if protectCalls != 1 || removeCalls != 1 {
				t.Fatalf("protect=%d remove=%d, want exactly once", protectCalls, removeCalls)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed staging remained visible: entries=%d err=%v", len(entries), err)
			}
			actual, err := os.ReadFile(previousAuthority)
			if err != nil || string(actual) != string(previousBytes) {
				t.Fatalf("previous authority changed: len=%d err=%v", len(actual), err)
			}
		})
	}
}

func TestPrepareRestoreStagingIsPrivateAndEmptyBeforeUse(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	protectCalls, removeCalls := 0, 0
	staging, err := prepareRestoreStagingWithOperations(
		parent,
		func(path string, directory bool) error {
			protectCalls++
			if entries, err := os.ReadDir(path); err != nil || len(entries) != 0 {
				t.Fatalf("staging was not empty before protection: entries=%d err=%v", len(entries), err)
			}
			return protectSelfhostPrivatePath(path, directory)
		},
		func(path string) error {
			removeCalls++
			return os.RemoveAll(path)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(staging)
	if protectCalls != 1 || removeCalls != 0 {
		t.Fatalf("protect=%d remove=%d, want protect=1 remove=0", protectCalls, removeCalls)
	}
	if err := verifySelfhostPrivatePath(staging, true); err != nil {
		t.Fatalf("prepared staging directory is not private: %v", err)
	}
}

func TestRepeatedWindowsRestoreAndRollbackRemainDeterministic(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	recovery := filepath.Join(root, "offline", "recovery")
	backup := filepath.Join(root, "offline", "backup")
	passphrase := []byte("repeatable restore regression")
	now := time.Unix(1_800_300_000, 0).UTC()
	if _, err := Initialize(InitOptions{DataDir: source, DeploymentName: "repeatable", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := ConfirmRecovery(source, recovery, passphrase, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	summary, err := CreateBackup(BackupOptions{DataDir: source, Destination: backup, Passphrase: passphrase, Now: now.Add(2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	var firstState []byte
	for index := 0; index < 2; index++ {
		destination := filepath.Join(root, "restored-"+string(rune('a'+index)))
		options := RestoreOptions{BackupPath: backup, DataDir: destination, ExpectedDigest: summary.Digest, Passphrase: passphrase, Now: now.Add(3 * time.Minute)}
		if err := ApplyRestore(options); err != nil {
			t.Fatalf("restore %d: %v", index, err)
		}
		state, err := os.ReadFile(filepath.Join(destination, stateFileName))
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			firstState = state
		} else if string(state) != string(firstState) {
			t.Fatal("identical restore inputs produced different durable state")
		}
		if err := ConfirmRecovery(destination, recovery, passphrase, now.Add(4*time.Minute)); err != nil {
			t.Fatalf("confirm restore %d: %v", index, err)
		}
		if _, err := PreviewRestore(RestoreOptions{BackupPath: backup, DataDir: destination, Passphrase: passphrase, Now: now.Add(5 * time.Minute)}); !errors.Is(err, ErrRollback) {
			t.Fatalf("restore %d rollback error=%v", index, err)
		}
	}
}

func openWindowsPathAccessForTest(path string, access uint32) error {
	pointer, err := windows.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(pointer, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	return windows.CloseHandle(handle)
}

func restrictWindowsPathWithoutWriteOwnerForSelfhostTest(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		t.Fatalf("read fixture owner: %v", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		t.Fatalf("decode fixture owner: %v", err)
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
