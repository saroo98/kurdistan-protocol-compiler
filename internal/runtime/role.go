// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import "fmt"

type Role string

const (
	RoleClient Role = "client"
	RoleServer Role = "server"
)

func (r Role) Valid() bool {
	return r == RoleClient || r == RoleServer
}

func ValidateRole(r Role) error {
	if !r.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidRole, r)
	}
	return nil
}

func oppositeRole(r Role) Role {
	if r == RoleClient {
		return RoleServer
	}
	return RoleClient
}
