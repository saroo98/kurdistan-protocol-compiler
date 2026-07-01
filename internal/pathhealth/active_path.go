// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

func IsActivePathSynthetic(active ActivePath) bool {
	return active.ActivePathID != "" && !active.PayloadLogged && !active.SecretLogged
}
