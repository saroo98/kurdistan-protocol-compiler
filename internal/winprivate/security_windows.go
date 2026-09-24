// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package winprivate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type privatePathProtectionOperations struct {
	verifyOwner func(windows.Handle, *windows.SID, *windows.SID) error
	setDACL     func(windows.Handle, *windows.ACL) error
	verify      func(windows.Handle, bool, *windows.SID, *windows.SID) error
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

func Protect(path string, directory bool) error {
	return protectPrivatePathWithOperations(path, directory, defaultPrivatePathProtectionOperations())
}

func protectPrivatePathWithOperations(path string, directory bool, operations privatePathProtectionOperations) (result error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || directory != info.IsDir() || !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("%w: unsafe path type", ErrUnsafe)
	}
	if operations.verifyOwner == nil || operations.setDACL == nil || operations.verify == nil || operations.close == nil {
		return fmt.Errorf("%w: incomplete private-path operations", ErrUnsafe)
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return operationFailure("open current process token", err)
	}
	defer func() {
		if closeErr := token.Close(); closeErr != nil {
			result = errors.Join(result, operationFailure("close current process token", closeErr))
		}
	}()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return operationFailure("read current process owner", err)
	}
	userSID, err := user.User.Sid.Copy()
	if err != nil {
		return operationFailure("copy current process owner", err)
	}
	defaultOwner, err := windowsTokenOwnerSID(token)
	if err != nil {
		return operationFailure("read current process default owner", err)
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
		return operationFailure("construct private DACL", err)
	}
	pointer, err := windows.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return operationFailure("encode private path", err)
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
		return operationFailure("open private path", err)
	}
	defer func() {
		if closeErr := operations.close(handle); closeErr != nil {
			result = errors.Join(result, operationFailure("close private path handle", closeErr))
		}
	}()
	if err := verifyPrivateHandleType(handle, directory); err != nil {
		return operationFailure("verify private path type", err)
	}
	if err := operations.verifyOwner(handle, userSID, defaultOwner); err != nil {
		return operationFailure("verify private path owner", err)
	}
	if err := operations.setDACL(handle, acl); err != nil {
		return operationFailure("set private DACL", err)
	}
	if err := operations.verify(handle, directory, userSID, defaultOwner); err != nil {
		return operationFailure("verify private DACL", err)
	}
	return nil
}

func operationFailure(operation string, err error) error {
	return &OpError{Op: operation, Err: err}
}

func verifyPrivateHandleType(handle windows.Handle, directory bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || directory != (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
		return ErrUnsafe
	}
	return nil
}

func verifyPrivateHandleOwner(handle windows.Handle, currentUser, defaultOwner *windows.SID) error {
	if currentUser == nil || !currentUser.IsValid() || defaultOwner == nil || !defaultOwner.IsValid() {
		return ErrUnsafe
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return operationFailure("read private path owner", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || !privatePathOwnerAllowed(owner, currentUser, defaultOwner) {
		return operationFailure("compare private path owner", err)
	}
	return nil
}

func verifyPrivateHandle(handle windows.Handle, directory bool, currentUser, defaultOwner *windows.SID) error {
	if err := verifyPrivateHandleType(handle, directory); err != nil {
		return err
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return operationFailure("read private security descriptor", err)
	}
	return verifyPrivateSecurityDescriptor(descriptor, currentUser, defaultOwner)
}

func Verify(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || directory != info.IsDir() || !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("%w: unsafe path type", ErrUnsafe)
	}
	currentUser, defaultOwner, err := currentWindowsSecuritySIDs()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return operationFailure("read private security descriptor", err)
	}
	return verifyPrivateSecurityDescriptor(descriptor, currentUser, defaultOwner)
}

func verifyPrivateSecurityDescriptor(descriptor *windows.SECURITY_DESCRIPTOR, currentUser, defaultOwner *windows.SID) error {
	if descriptor == nil || currentUser == nil || !currentUser.IsValid() || defaultOwner == nil || !defaultOwner.IsValid() {
		return ErrUnsafe
	}
	owner, _, err := descriptor.Owner()
	if err != nil || !privatePathOwnerAllowed(owner, currentUser, defaultOwner) {
		return fmt.Errorf("%w: unexpected owner", ErrUnsafe)
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%w: unprotected dacl", ErrUnsafe)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 || dacl.AceCount > 2 {
		return fmt.Errorf("%w: unexpected ace count", ErrUnsafe)
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace == nil {
			return fmt.Errorf("%w: unreadable ace", ErrUnsafe)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask == 0 {
			return fmt.Errorf("%w: unexpected ace type=%d mask=%x", ErrUnsafe, ace.Header.AceType, uint32(ace.Mask))
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !aceSID.IsValid() || !aceSID.Equals(currentUser) {
			return fmt.Errorf("%w: unexpected trustee", ErrUnsafe)
		}
	}
	return nil
}

func currentWindowsUserSID() (*windows.SID, error) {
	user, _, err := currentWindowsSecuritySIDs()
	return user, err
}

func currentWindowsSecuritySIDs() (*windows.SID, *windows.SID, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: token", ErrUnsafe)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return nil, nil, fmt.Errorf("%w: user sid", ErrUnsafe)
	}
	userSID, err := user.User.Sid.Copy()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: copy user sid", ErrUnsafe)
	}
	defaultOwner, err := windowsTokenOwnerSID(token)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: token owner", ErrUnsafe)
	}
	return userSID, defaultOwner, nil
}

type windowsTokenOwner struct {
	owner *windows.SID
}

func windowsTokenOwnerSID(token windows.Token) (*windows.SID, error) {
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &size)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || size < uint32(unsafe.Sizeof(windowsTokenOwner{})) {
		return nil, ErrUnsafe
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &buffer[0], size, &size); err != nil {
		return nil, err
	}
	owner := (*windowsTokenOwner)(unsafe.Pointer(&buffer[0])).owner
	if owner == nil || !owner.IsValid() {
		return nil, ErrUnsafe
	}
	copy, err := owner.Copy()
	runtime.KeepAlive(buffer)
	return copy, err
}

func privatePathOwnerAllowed(owner, currentUser, defaultOwner *windows.SID) bool {
	return owner != nil && owner.IsValid() && currentUser != nil && currentUser.IsValid() &&
		defaultOwner != nil && defaultOwner.IsValid() && (owner.Equals(currentUser) || owner.Equals(defaultOwner))
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
		return nil, fmt.Errorf("%w: security descriptor", ErrUnsafe)
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}, nil
}
