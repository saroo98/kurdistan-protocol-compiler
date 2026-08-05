// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package authz

import (
	"errors"
	"sort"

	"kurdistan/production/internal/authn"
)

var ErrForbidden = errors.New("authz: forbidden")

type Phase string

const (
	PhaseRead    Phase = "read"
	PhaseRequest Phase = "request"
	PhaseApprove Phase = "approve"
	PhaseExecute Phase = "execute"
)

type OperationContext struct {
	RequesterActorID string
	ApproverActorIDs []string
}

type Authorizer struct {
	allowed map[string]map[Phase]map[string]struct{}
}

func New(actionRoles map[string]map[Phase][]string) (*Authorizer, error) {
	if len(actionRoles) == 0 {
		return nil, ErrForbidden
	}
	authorizer := &Authorizer{allowed: make(map[string]map[Phase]map[string]struct{}, len(actionRoles))}
	for action, phases := range actionRoles {
		if action == "" || len(phases) == 0 {
			return nil, ErrForbidden
		}
		authorizer.allowed[action] = make(map[Phase]map[string]struct{}, len(phases))
		for phase, roles := range phases {
			if phase != PhaseRead && phase != PhaseRequest && phase != PhaseApprove && phase != PhaseExecute || len(roles) == 0 {
				return nil, ErrForbidden
			}
			authorizer.allowed[action][phase] = make(map[string]struct{}, len(roles))
			for _, role := range roles {
				if role == "" {
					return nil, ErrForbidden
				}
				authorizer.allowed[action][phase][role] = struct{}{}
			}
		}
	}
	return authorizer, nil
}

func (authorizer *Authorizer) Authorize(identity authn.Identity, action string, phase Phase, operation OperationContext) error {
	phases, ok := authorizer.allowed[action]
	if !ok {
		return ErrForbidden
	}
	allowed, ok := phases[phase]
	if !ok {
		return ErrForbidden
	}
	permitted := false
	for _, role := range identity.Roles {
		if _, ok := allowed[role]; ok {
			permitted = true
			break
		}
	}
	if !permitted {
		return ErrForbidden
	}
	if phase == PhaseApprove && identity.ActorID == operation.RequesterActorID {
		return ErrForbidden
	}
	if phase == PhaseExecute {
		if identity.ActorID == operation.RequesterActorID || contains(operation.ApproverActorIDs, identity.ActorID) {
			return ErrForbidden
		}
	}
	return nil
}

func contains(values []string, target string) bool {
	values = append([]string(nil), values...)
	sort.Strings(values)
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}
