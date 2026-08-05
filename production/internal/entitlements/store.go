// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package entitlements

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"kurdistan/production/internal/authn"
)

const MaxEntitlementBytes = 256 << 10

type Document struct {
	Schema      string       `json:"schema"`
	Environment string       `json:"environment"`
	Version     string       `json:"version"`
	Assignments []Assignment `json:"assignments"`
}

type Assignment struct {
	ActorID string   `json:"actor_id"`
	Roles   []string `json:"roles"`
}

type Store struct {
	mu          sync.RWMutex
	environment string
	version     string
	actors      map[string][]string
}

func New(environment string, raw []byte) (*Store, error) {
	store := &Store{environment: environment}
	if err := store.Reload(raw); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *Store) Reload(raw []byte) error {
	document, err := decode(raw)
	if err != nil {
		return err
	}
	if document.Environment != store.environment {
		return errors.New("entitlements: environment mismatch")
	}
	actors := make(map[string][]string, len(document.Assignments))
	for _, assignment := range document.Assignments {
		actors[assignment.ActorID] = append([]string(nil), assignment.Roles...)
	}
	store.mu.Lock()
	store.version = document.Version
	store.actors = actors
	store.mu.Unlock()
	return nil
}

func (store *Store) Resolve(_ context.Context, actorID string) (authn.Entitlement, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	roles, ok := store.actors[actorID]
	if !ok {
		return authn.Entitlement{}, errors.New("entitlements: actor not entitled")
	}
	return authn.Entitlement{Version: store.version, Roles: append([]string(nil), roles...)}, nil
}

func decode(raw []byte) (Document, error) {
	if len(raw) == 0 || len(raw) > MaxEntitlementBytes || bytes.Contains(raw, []byte("@")) {
		return Document{}, errors.New("entitlements: invalid document")
	}
	var document Document
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return Document{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Document{}, errors.New("entitlements: trailing JSON")
	}
	if document.Schema != "phase16-entitlements-v1" || len(document.Environment) < 3 || len(document.Environment) > 64 ||
		len(document.Version) < 3 || len(document.Version) > 128 || len(document.Assignments) == 0 || len(document.Assignments) > 4096 {
		return Document{}, errors.New("entitlements: invalid identity")
	}
	seen := make(map[string]struct{}, len(document.Assignments))
	for index := range document.Assignments {
		assignment := &document.Assignments[index]
		if !strings.HasPrefix(assignment.ActorID, "actor-") || len(assignment.ActorID) != 38 ||
			len(assignment.Roles) == 0 || len(assignment.Roles) > 9 {
			return Document{}, fmt.Errorf("entitlements: invalid assignment %d", index)
		}
		if _, duplicate := seen[assignment.ActorID]; duplicate {
			return Document{}, errors.New("entitlements: duplicate actor")
		}
		seen[assignment.ActorID] = struct{}{}
		sort.Strings(assignment.Roles)
		for roleIndex, role := range assignment.Roles {
			if !validRole(role) || roleIndex > 0 && role == assignment.Roles[roleIndex-1] {
				return Document{}, errors.New("entitlements: invalid role")
			}
		}
		if forbiddenCombination(assignment.Roles) {
			return Document{}, errors.New("entitlements: forbidden role combination")
		}
	}
	return document, nil
}

func validRole(role string) bool {
	switch role {
	case "viewer", "requester", "approver", "executor", "publisher", "auditor", "recovery", "emergency", "deployer":
		return true
	default:
		return false
	}
}

func forbiddenCombination(roles []string) bool {
	set := make(map[string]bool, len(roles))
	for _, role := range roles {
		set[role] = true
	}
	for _, pair := range [][2]string{
		{"approver", "emergency"}, {"approver", "executor"}, {"approver", "recovery"},
		{"auditor", "publisher"}, {"deployer", "publisher"}, {"deployer", "recovery"},
	} {
		if set[pair[0]] && set[pair[1]] {
			return true
		}
	}
	return false
}
