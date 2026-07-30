// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package loopbackresolver resolves opaque admitted relay references against a
// closed local registry. It permits only literal loopback TCP endpoints.
package loopbackresolver

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"kurdistan/internal/product/livecarrier"
	"kurdistan/internal/product/sessionplan"
)

const maxEntries = 32

var ErrResolution = errors.New("loopbackresolver: resolution rejected")

type Entry struct {
	Reference  string
	Address    string
	ServerName string
}

type Registry struct {
	entries map[string]Entry
}

func New(entries []Entry) (*Registry, error) {
	if len(entries) == 0 || len(entries) > maxEntries {
		return nil, ErrResolution
	}
	result := &Registry{entries: make(map[string]Entry, len(entries))}
	for _, entry := range entries {
		if !validEntry(entry) {
			return nil, ErrResolution
		}
		if _, exists := result.entries[entry.Reference]; exists {
			return nil, ErrResolution
		}
		result.entries[entry.Reference] = entry
	}
	return result, nil
}

func validEntry(entry Entry) bool {
	if !strings.HasPrefix(entry.Reference, "relayref:") || len(entry.Reference) > 256 ||
		entry.ServerName == "" || len(entry.ServerName) > 253 ||
		strings.TrimSpace(entry.ServerName) != entry.ServerName {
		return false
	}
	host, portText, err := net.SplitHostPort(entry.Address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	port, err := strconv.ParseUint(portText, 10, 16)
	return err == nil && port != 0 && ip != nil && ip.IsLoopback()
}

func (registry *Registry) Resolve(plan sessionplan.Plan) (Entry, error) {
	if registry == nil || plan.Version != sessionplan.Version || plan.Digest == ([32]byte{}) ||
		!plan.LoopbackOnly || plan.CarrierFamily != livecarrier.FamilyKurdTLS13TCP {
		return Entry{}, ErrResolution
	}
	entry, ok := registry.entries[plan.EndpointReference]
	if !ok {
		return Entry{}, ErrResolution
	}
	return entry, nil
}

// DialContext opens only the exact literal loopback TCP endpoint authorized by
// the supplied immutable plan and closed registry.
func (registry *Registry) DialContext(ctx context.Context, plan sessionplan.Plan) (net.Conn, string, error) {
	if ctx == nil {
		return nil, "", ErrResolution
	}
	entry, err := registry.Resolve(plan)
	if err != nil {
		return nil, "", err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, "", ErrResolution
	}
	planDeadline := time.Now().Add(time.Duration(plan.DialTimeoutMs) * time.Millisecond)
	if planDeadline.Before(deadline) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, planDeadline)
		defer cancel()
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", entry.Address)
	if err != nil {
		return nil, "", ErrResolution
	}
	return connection, entry.ServerName, nil
}
