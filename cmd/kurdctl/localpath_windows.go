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

func protectPrivatePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || directory != info.IsDir() || !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("%w: unsafe path type", errUnsupportedFilesystem)
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("%w: token", errUnsupportedFilesystem)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("%w: user sid", errUnsupportedFilesystem)
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
		return fmt.Errorf("%w: acl", errUnsupportedFilesystem)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return fmt.Errorf("%w: set dacl", errUnsupportedFilesystem)
	}
	return verifyWindowsPrivatePath(path, directory)
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
		return fmt.Errorf("%w: read dacl", errUnsupportedFilesystem)
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
