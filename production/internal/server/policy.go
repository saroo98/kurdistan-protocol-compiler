// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package server

import "kurdistan/production/internal/authz"

// ProductionActionRoles is the runtime projection of
// config/production/actions.json plus the read-only API actions. The Phase 16
// verifier binds both surfaces so a policy change cannot silently widen the
// deployed API.
func ProductionActionRoles() map[string]map[authz.Phase][]string {
	readers := []string{"viewer", "auditor", "requester", "approver", "executor", "publisher", "recovery", "emergency", "deployer"}
	result := map[string]map[authz.Phase][]string{
		"operation.read":   {authz.PhaseRead: append([]string(nil), readers...)},
		"profile.read":     {authz.PhaseRead: append([]string(nil), readers...)},
		"publication.read": {authz.PhaseRead: append([]string(nil), readers...)},
		"revocation.read":  {authz.PhaseRead: append([]string(nil), readers...)},
	}
	for _, action := range []string{"profile.issue", "profile.rotate", "profile.revoke", "key.issuer.rotate", "key.root.rotate", "key.destroy.schedule"} {
		result[action] = map[authz.Phase][]string{
			authz.PhaseRequest: {"requester"}, authz.PhaseApprove: {"approver"}, authz.PhaseExecute: {"executor"},
		}
	}
	result["retention.lock"] = map[authz.Phase][]string{
		authz.PhaseRequest: {"requester"}, authz.PhaseApprove: {"approver"}, authz.PhaseExecute: {"deployer"},
	}
	result["publication.publish"] = map[authz.Phase][]string{
		authz.PhaseRequest: {"publisher"}, authz.PhaseApprove: {"approver"}, authz.PhaseExecute: {"publisher"},
	}
	result["audit.anchor"] = map[authz.Phase][]string{
		authz.PhaseRequest: {"auditor"}, authz.PhaseApprove: {"approver"}, authz.PhaseExecute: {"auditor"},
	}
	result["recovery.prepare"] = map[authz.Phase][]string{
		authz.PhaseRequest: {"recovery"}, authz.PhaseApprove: {"approver"}, authz.PhaseExecute: {"recovery"},
	}
	result["emergency.deny"] = map[authz.Phase][]string{
		authz.PhaseRequest: {"emergency"}, authz.PhaseApprove: {"approver"}, authz.PhaseExecute: {"emergency"},
	}
	return result
}
