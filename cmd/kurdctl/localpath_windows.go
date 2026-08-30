// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func localPathRoot(path string) (string, error) {
	cleaned := strings.ReplaceAll(path, "/", "\\")
	volume := filepath.VolumeName(cleaned)
	if !filepath.IsAbs(path) || strings.HasPrefix(cleaned, "\\\\") || strings.HasPrefix(cleaned, "\\?\\") || strings.HasPrefix(cleaned, "\\.\\") || strings.HasPrefix(volume, "\\") || len(volume) != 2 || volume[1] != ':' {
		return "", errors.New("absolute local drive path required")
	}
	return volume + string(os.PathSeparator), nil
}

type privatePathProtectionOperations struct {
	verifyOwner func(windows.Handle, *windows.SID) error
	setDACL     func(windows.Handle, *windows.ACL) error
	verify      func(windows.Handle, bool, *windows.SID) error
	close       func(windows.Handle) error
}

func defaultPrivatePathProtectionOperations() privatePathProtectionOperations {
	return privatePathProtectionOperations{
		verifyOwner: verifyPrivateHandleOwner,
		setDACL: func(handle windows.Handle, dacl *windows.ACL) error {
			return windows.SetSecurityInfo(
				handle,
				windows.SE_FILE_OBJECT,
				windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
				nil,
				nil,
				dacl,
				nil,
			)
		},
		verify: verifyPrivateHandle,
		close:  windows.CloseHandle,
	}
}

func protectPrivatePath(path string, directory bool) error {
	return protectPrivatePathWithOperations(path, directory, defaultPrivatePathProtectionOperations())
}

func protectPrivatePathWithOperations(path string, directory bool, operations privatePathProtectionOperations) (result error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || directory != info.IsDir() || !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("%w: unsafe path type", errUnsupportedFilesystem)
	}
	if operations.verifyOwner == nil || operations.setDACL == nil || operations.verify == nil || operations.close == nil {
		return fmt.Errorf("%w: incomplete private-path operations", errUnsupportedFilesystem)
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return privatePathFailure("open current process token", err)
	}
	defer func() {
		if closeErr := token.Close(); closeErr != nil {
			result = errors.Join(result, privatePathFailure("close current process token", closeErr))
		}
	}()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return privatePathFailure("read current process owner", err)
	}
	var pinner runtime.Pinner
	pinner.Pin(user.User.Sid)
	defer pinner.Unpin()
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
		},
	}}, nil)
	if err != nil {
		return privatePathFailure("construct private DACL", err)
	}
	pointer, err := windows.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return privatePathFailure("encode private path", err)
	}
	attributes := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		attributes |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		attributes,
		0,
	)
	if err != nil {
		return privatePathFailure("open private path", err)
	}
	defer func() {
		if closeErr := operations.close(handle); closeErr != nil {
			result = errors.Join(result, privatePathFailure("close private path handle", closeErr))
		}
	}()
	if err := verifyPrivateHandleType(handle, directory); err != nil {
		return privatePathFailure("verify private path type", err)
	}
	if err := operations.verifyOwner(handle, user.User.Sid); err != nil {
		return privatePathFailure("verify private path owner", err)
	}
	if err := operations.setDACL(handle, acl); err != nil {
		return privatePathFailure("set private DACL", err)
	}
	if err := operations.verify(handle, directory, user.User.Sid); err != nil {
		return privatePathFailure("verify private DACL", err)
	}
	return nil
}

func privatePathFailure(operation string, err error) error {
	if err == nil {
		return fmt.Errorf("%w: %s", errUnsupportedFilesystem, operation)
	}
	return fmt.Errorf("kurdctl private path: %s: %w", operation, err)
}

func verifyPrivateHandleType(handle windows.Handle, directory bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || directory != (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
		return errUnsupportedFilesystem
	}
	return nil
}

func verifyPrivateHandleOwner(handle windows.Handle, currentUser *windows.SID) error {
	if currentUser == nil || !currentUser.IsValid() {
		return errUnsupportedFilesystem
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return privatePathFailure("read private path owner", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(currentUser) {
		return privatePathFailure("compare private path owner", err)
	}
	return nil
}

func verifyPrivateHandle(handle windows.Handle, directory bool, currentUser *windows.SID) error {
	if err := verifyPrivateHandleType(handle, directory); err != nil {
		return err
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return privatePathFailure("read private security descriptor", err)
	}
	return verifyPrivateSecurityDescriptor(descriptor, currentUser)
}

func verifyWindowsPrivatePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || directory != info.IsDir() || !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("%w: unsafe path type", errUnsupportedFilesystem)
	}
	currentUser, err := currentWindowsUserSID()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return privatePathFailure("read private security descriptor", err)
	}
	return verifyPrivateSecurityDescriptor(descriptor, currentUser)
}

func verifyPrivateSecurityDescriptor(descriptor *windows.SECURITY_DESCRIPTOR, currentUser *windows.SID) error {
	if descriptor == nil || currentUser == nil || !currentUser.IsValid() {
		return errUnsupportedFilesystem
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(currentUser) {
		return fmt.Errorf("%w: unexpected owner", errUnsupportedFilesystem)
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%w: unprotected dacl", errUnsupportedFilesystem)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 || dacl.AceCount > 2 {
		return fmt.Errorf("%w: unexpected ace count", errUnsupportedFilesystem)
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace == nil {
			return fmt.Errorf("%w: unreadable ace", errUnsupportedFilesystem)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask == 0 {
			return fmt.Errorf("%w: unexpected ace type=%d mask=%x", errUnsupportedFilesystem, ace.Header.AceType, uint32(ace.Mask))
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !aceSID.IsValid() || !aceSID.Equals(currentUser) {
			return fmt.Errorf("%w: unexpected trustee", errUnsupportedFilesystem)
		}
	}
	return nil
}

func syncLocalDirectory(string) error { return nil }

func currentWindowsUserSID() (*windows.SID, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, fmt.Errorf("%w: token", errUnsupportedFilesystem)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return nil, fmt.Errorf("%w: user sid", errUnsupportedFilesystem)
	}
	return user.User.Sid, nil
}

func windowsPrivateSecurityAttributes(directory bool) (*windows.SecurityAttributes, error) {
	sid, err := currentWindowsUserSID()
	if err != nil {
		return nil, err
	}
	flags := ""
	if directory {
		flags = "OICI"
	}
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;" + flags + ";FA;;;" + sid.String() + ")")
	if err != nil {
		return nil, fmt.Errorf("%w: security descriptor", errUnsupportedFilesystem)
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}, nil
}

func rejectWindowsReparseComponents(path string, includeFinal bool) error {
	anchor, err := localPathRoot(path)
	if err != nil {
		return errUnsupportedFilesystem
	}
	cleaned := filepath.Clean(path)
	relative, err := filepath.Rel(anchor, cleaned)
	if err != nil || !filepath.IsLocal(relative) {
		return errUnsupportedFilesystem
	}
	parts := strings.Split(relative, string(os.PathSeparator))
	if !includeFinal && len(parts) > 0 {
		parts = parts[:len(parts)-1]
	}
	current := anchor
	for _, part := range parts {
		current = filepath.Join(current, part)
		pointer, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return errUnsupportedFilesystem
		}
		attributes, err := windows.GetFileAttributes(pointer)
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errUnsupportedFilesystem
		}
	}
	return nil
}

func createWindowsPrivateDirectory(path string) error {
	if path == "" || rejectWindowsReparseComponents(path, false) != nil {
		return errUnsupportedFilesystem
	}
	security, err := windowsPrivateSecurityAttributes(true)
	if err != nil {
		return err
	}
	pointer, err := windows.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return errUnsupportedFilesystem
	}
	if err := windows.CreateDirectory(pointer, security); err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return errOutputExists
		}
		return errOutputIncomplete
	}
	if err := rejectWindowsReparseComponents(path, true); err != nil || verifyWindowsPrivatePath(path, true) != nil {
		_ = os.Remove(path)
		return errUnsupportedFilesystem
	}
	return nil
}

func createWindowsPrivateFile(path string, value []byte) error {
	if path == "" || len(value) == 0 || rejectWindowsReparseComponents(path, false) != nil {
		return errOutputIncomplete
	}
	security, err := windowsPrivateSecurityAttributes(false)
	if err != nil {
		return err
	}
	pointer, err := windows.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return errUnsupportedFilesystem
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_WRITE|windows.READ_CONTROL, 0, security, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return errOutputExists
		}
		return errOutputIncomplete
	}
	file := os.NewFile(uintptr(handle), path)
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := verifyWindowsPrivatePath(path, false); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errOutputIncomplete
	}
	if written, err := file.Write(value); err != nil || written != len(value) || file.Sync() != nil || file.Close() != nil {
		return errOutputIncomplete
	}
	remove = false
	return nil
}

func createPrivateOutputRoot(path string) (*privateOutputRoot, error) {
	if err := createWindowsPrivateDirectory(path); err != nil {
		return nil, err
	}
	return &privateOutputRoot{path: filepath.Clean(path)}, nil
}

func writePrivateFile(root *privateOutputRoot, name string, value []byte) error {
	if root == nil || !filepath.IsLocal(name) || filepath.Base(name) != name {
		return errOutputIncomplete
	}
	return createWindowsPrivateFile(filepath.Join(root.path, name), value)
}
