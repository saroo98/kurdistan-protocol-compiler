//go:build windows

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

func preserveOwnership(_, _ string) error { return nil }
