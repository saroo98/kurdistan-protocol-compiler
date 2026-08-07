// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build js || plan9

package main

func localPathRoot(string) (string, error)  { return "", errUnsupportedFilesystem }
func protectPrivatePath(string, bool) error { return errUnsupportedFilesystem }
func syncLocalDirectory(string) error       { return errUnsupportedFilesystem }
func createPrivateOutputRoot(string) (*privateOutputRoot, error) {
	return nil, errUnsupportedFilesystem
}
func writePrivateFile(*privateOutputRoot, string, []byte) error { return errUnsupportedFilesystem }
