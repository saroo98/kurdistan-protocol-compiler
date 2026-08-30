// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package selfhost

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

type selfhostPrivatePathProtectionOperations struct {
	verifyOwner func(windows.Handle, *windows.SID, *windows.SID) error
	setDACL     func(windows.Handle, *windows.ACL) error
	verify      func(windows.Handle, bool, *windows.SID, *windows.SID) error
	close       func(windows.Handle) error
}

func defaultSelfhostPrivatePathProtectionOperations() selfhostPrivatePathProtectionOperations {
	return selfhostPrivatePathProtectionOperations{
		verifyOwner: verifySelfhostPrivateHandleOwner,
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
		verify: verifySelfhostPrivateHandle,
		close:  windows.CloseHandle,
	}
}

func protectSelfhostPrivatePath(path string, directory bool) error {
	return protectSelfhostPrivatePathWithOperations(path, directory, defaultSelfhostPrivatePathProtectionOperations())
}

func protectSelfhostPrivatePathWithOperations(path string, directory bool, operations selfhostPrivatePathProtectionOperations) (result error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || directory != info.IsDir() || !directory && !info.Mode().IsRegular() {
		return ErrRecipientRegistry
	}
	if operations.verifyOwner == nil || operations.setDACL == nil || operations.verify == nil || operations.close == nil {
		return ErrRecipientRegistry
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return selfhostPrivatePathFailure("open current process token", err)
	}
	defer func() {
		if closeErr := token.Close(); closeErr != nil {
			result = errors.Join(result, selfhostPrivatePathFailure("close current process token", closeErr))
		}
	}()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return selfhostPrivatePathFailure("read current process owner", err)
	}
	userSID, err := user.User.Sid.Copy()
	if err != nil {
		return selfhostPrivatePathFailure("copy current process owner", err)
	}
	defaultOwner, err := selfhostWindowsTokenOwnerSID(token)
	if err != nil {
		return selfhostPrivatePathFailure("read current process default owner", err)
	}
	var pinner runtime.Pinner
	pinner.Pin(userSID)
	pinner.Pin(defaultOwner)
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
			TrusteeValue: windows.TrusteeValueFromSID(userSID),
		},
	}}, nil)
	if err != nil {
		return selfhostPrivatePathFailure("construct private DACL", err)
	}
	pointer, err := windows.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return selfhostPrivatePathFailure("encode private path", err)
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
		return selfhostPrivatePathFailure("open private path", err)
	}
	defer func() {
		if closeErr := operations.close(handle); closeErr != nil {
			result = errors.Join(result, selfhostPrivatePathFailure("close private path handle", closeErr))
		}
	}()
	if err := verifySelfhostPrivateHandleType(handle, directory); err != nil {
		return selfhostPrivatePathFailure("verify private path type", err)
	}
	if err := operations.verifyOwner(handle, userSID, defaultOwner); err != nil {
		return selfhostPrivatePathFailure("verify private path owner", err)
	}
	if err := operations.setDACL(handle, acl); err != nil {
		return selfhostPrivatePathFailure("set private DACL", err)
	}
	if err := operations.verify(handle, directory, userSID, defaultOwner); err != nil {
		return selfhostPrivatePathFailure("verify private DACL", err)
	}
	return nil
}

func selfhostPrivatePathFailure(operation string, err error) error {
	if err == nil {
		return ErrRecipientRegistry
	}
	return errors.Join(ErrRecipientRegistry, fmt.Errorf("selfhost: %s: %w", operation, err))
}

func verifySelfhostPrivateHandleType(handle windows.Handle, directory bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || directory != (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
		return ErrRecipientRegistry
	}
	return nil
}

func verifySelfhostPrivateHandleOwner(handle windows.Handle, currentUser, defaultOwner *windows.SID) error {
	if currentUser == nil || !currentUser.IsValid() || defaultOwner == nil || !defaultOwner.IsValid() {
		return ErrRecipientRegistry
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return selfhostPrivatePathFailure("read private path owner", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || !selfhostPrivatePathOwnerAllowed(owner, currentUser, defaultOwner) {
		return selfhostPrivatePathFailure("compare private path owner", err)
	}
	return nil
}

func verifySelfhostPrivateHandle(handle windows.Handle, directory bool, currentUser, defaultOwner *windows.SID) error {
	if err := verifySelfhostPrivateHandleType(handle, directory); err != nil {
		return err
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return selfhostPrivatePathFailure("read private security descriptor", err)
	}
	return verifySelfhostPrivateSecurityDescriptor(descriptor, currentUser, defaultOwner)
}

func verifySelfhostPrivateSecurityDescriptor(descriptor *windows.SECURITY_DESCRIPTOR, currentUser, defaultOwner *windows.SID) error {
	if descriptor == nil || currentUser == nil || !currentUser.IsValid() || defaultOwner == nil || !defaultOwner.IsValid() {
		return ErrRecipientRegistry
	}
	owner, _, err := descriptor.Owner()
	if err != nil || !selfhostPrivatePathOwnerAllowed(owner, currentUser, defaultOwner) {
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

func verifySelfhostPrivatePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || directory != info.IsDir() || !directory && !info.Mode().IsRegular() {
		return ErrRecipientRegistry
	}
	currentUser, defaultOwner, err := selfhostWindowsSecuritySIDs()
	if err != nil {
		return ErrRecipientRegistry
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return ErrRecipientRegistry
	}
	return verifySelfhostPrivateSecurityDescriptor(descriptor, currentUser, defaultOwner)
}

func selfhostWindowsUserSID() (*windows.SID, error) {
	user, _, err := selfhostWindowsSecuritySIDs()
	return user, err
}

func selfhostWindowsSecuritySIDs() (*windows.SID, *windows.SID, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, nil, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return nil, nil, ErrRecipientRegistry
	}
	userSID, err := user.User.Sid.Copy()
	if err != nil {
		return nil, nil, err
	}
	defaultOwner, err := selfhostWindowsTokenOwnerSID(token)
	if err != nil {
		return nil, nil, err
	}
	return userSID, defaultOwner, nil
}

type selfhostWindowsTokenOwner struct {
	owner *windows.SID
}

func selfhostWindowsTokenOwnerSID(token windows.Token) (*windows.SID, error) {
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &size)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || size < uint32(unsafe.Sizeof(selfhostWindowsTokenOwner{})) {
		return nil, ErrRecipientRegistry
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &buffer[0], size, &size); err != nil {
		return nil, err
	}
	owner := (*selfhostWindowsTokenOwner)(unsafe.Pointer(&buffer[0])).owner
	if owner == nil || !owner.IsValid() {
		return nil, ErrRecipientRegistry
	}
	copy, err := owner.Copy()
	runtime.KeepAlive(buffer)
	return copy, err
}

func selfhostPrivatePathOwnerAllowed(owner, currentUser, defaultOwner *windows.SID) bool {
	return owner != nil && owner.IsValid() && currentUser != nil && currentUser.IsValid() &&
		defaultOwner != nil && defaultOwner.IsValid() && (owner.Equals(currentUser) || owner.Equals(defaultOwner))
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
