// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import "kurdistan/internal/androidbridge"

type bridgeEnvironment interface {
	androidbridge.VerificationEnvironment
	androidbridge.ActivationEnvironment
	androidbridge.BackupEnvironment
}
