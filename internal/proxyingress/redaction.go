// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingress

func RedactError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case err == ErrUnsafeMetadata:
		return "unsafe_metadata"
	case err == ErrInvalidTarget:
		return "invalid_target"
	case err == ErrInvalidRequest:
		return "invalid_request"
	case err == ErrInvalidContract:
		return "invalid_contract"
	default:
		return "proxy_ingress_rejected"
	}
}
