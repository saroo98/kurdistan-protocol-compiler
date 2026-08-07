// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build js || plan9

package selfhost

func protectSelfhostPrivatePath(string, bool) error { return ErrRecipientRegistry }
func createSelfhostPrivateDirectory(string) error   { return ErrRecipientRegistry }
func ensureSelfhostPrivateDirectory(string) error   { return ErrRecipientRegistry }
func writeSelfhostPrivateFileExclusive(string, []byte) error {
	return ErrRecipientRegistry
}
