// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package selfhost

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func protectSelfhostPrivatePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || directory != info.IsDir() || !directory && !info.Mode().IsRegular() {
		return ErrRecipientRegistry
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return ErrRecipientRegistry
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return ErrRecipientRegistry
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
	if err != nil || windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user.User.Sid, nil, acl, nil) != nil {
		return ErrRecipientRegistry
	}
	return verifySelfhostPrivatePath(path, directory)
}

func verifySelfhostPrivatePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || directory != info.IsDir() || !directory && !info.Mode().IsRegular() {
		return ErrRecipientRegistry
	}
	currentUser, err := selfhostWindowsUserSID()
	if err != nil {
		return ErrRecipientRegistry
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return ErrRecipientRegistry
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(currentUser) {
		return ErrRecipientRegistry
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return ErrRecipientRegistry
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 || dacl.AceCount > 2 {
		return ErrRecipientRegistry
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, uint32(index), &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask == 0 {
			return ErrRecipientRegistry
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || !sid.Equals(currentUser) {
			return ErrRecipientRegistry
		}
	}
	return nil
}

func selfhostWindowsUserSID() (*windows.SID, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return nil, ErrRecipientRegistry
	}
	return user.User.Sid, nil
}

func selfhostWindowsSecurityAttributes(directory bool) (*windows.SecurityAttributes, error) {
	sid, err := selfhostWindowsUserSID()
	if err != nil {
		return nil, ErrRecipientRegistry
	}
	flags := ""
	if directory {
		flags = "OICI"
	}
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;" + flags + ";FA;;;" + sid.String() + ")")
	if err != nil {
		return nil, ErrRecipientRegistry
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}, nil
}

func selfhostWindowsLocalPath(path string) bool {
	cleaned := strings.ReplaceAll(path, "/", "\\")
	volume := filepath.VolumeName(cleaned)
	return filepath.IsAbs(path) && !strings.HasPrefix(cleaned, "\\\\") && !strings.HasPrefix(cleaned, "\\?\\") && !strings.HasPrefix(cleaned, "\\.\\") && !strings.HasPrefix(volume, "\\") && len(volume) == 2 && volume[1] == ':'
}

func rejectSelfhostWindowsReparseComponents(path string, includeFinal bool) error {
	if !selfhostWindowsLocalPath(path) {
		return ErrRecipientRegistry
	}
	cleaned := filepath.Clean(path)
	anchor := filepath.VolumeName(cleaned) + string(os.PathSeparator)
	relative, err := filepath.Rel(anchor, cleaned)
	if err != nil || !filepath.IsLocal(relative) {
		return ErrRecipientRegistry
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
			return ErrRecipientRegistry
		}
		attributes, err := windows.GetFileAttributes(pointer)
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return ErrRecipientRegistry
		}
	}
	return nil
}

func createSelfhostPrivateDirectory(path string) error {
	if rejectSelfhostWindowsReparseComponents(path, false) != nil {
		return ErrRecipientRegistry
	}
	security, err := selfhostWindowsSecurityAttributes(true)
	if err != nil {
		return ErrRecipientRegistry
	}
	pointer, err := windows.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return ErrRecipientRegistry
	}
	if err := windows.CreateDirectory(pointer, security); err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return ErrBusy
		}
		return ErrRecipientRegistry
	}
	if rejectSelfhostWindowsReparseComponents(path, true) != nil || verifySelfhostPrivatePath(path, true) != nil {
		return ErrRecipientRegistry
	}
	return nil
}

func ensureSelfhostPrivateDirectory(path string) error {
	err := createSelfhostPrivateDirectory(path)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrBusy) {
		return ErrRecipientRegistry
	}
	info, statErr := os.Lstat(path)
	if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || rejectSelfhostWindowsReparseComponents(path, true) != nil {
		return ErrRecipientRegistry
	}
	return verifySelfhostPrivatePath(path, true)
}

func writeSelfhostPrivateFileExclusive(path string, value []byte) error {
	if len(value) == 0 || rejectSelfhostWindowsReparseComponents(path, false) != nil {
		return ErrRecipientRegistry
	}
	security, err := selfhostWindowsSecurityAttributes(false)
	if err != nil {
		return ErrRecipientRegistry
	}
	pointer, err := windows.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return ErrRecipientRegistry
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_WRITE|windows.READ_CONTROL, 0, security, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
	if err != nil {
		return ErrRecipientRegistry
	}
	file := os.NewFile(uintptr(handle), path)
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if verifySelfhostPrivatePath(path, false) != nil {
		return ErrRecipientRegistry
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ErrRecipientRegistry
	}
	if written, err := file.Write(value); err != nil || written != len(value) || file.Sync() != nil || file.Close() != nil {
		return ErrRecipientRegistry
	}
	remove = false
	return nil
}
