// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestDNSReadinessRequiresBothOwnedTunnelResolvers(t *testing.T) {
	seen := make([]string, 0, 2)
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			t.Fatalf("network=%q", network)
		}
		seen = append(seen, address)
		return &dnsProbeConnectionV1{}, nil
	}
	if !probeOwnedDNSV1(context.Background(), dial) {
		t.Fatal("healthy owned resolvers were rejected")
	}
	want := []string{"10.77.0.1:53", "[fd4b:7572:6400::1]:53"}
	if len(seen) != len(want) || seen[0] != want[0] || seen[1] != want[1] {
		t.Fatalf("seen=%v want=%v", seen, want)
	}
}

func TestDNSReadinessFailsClosedOnMissingResolverOrContext(t *testing.T) {
	calls := 0
	dial := func(_ context.Context, _, _ string) (net.Conn, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("resolver unavailable")
		}
		return &dnsProbeConnectionV1{}, nil
	}
	if probeOwnedDNSV1(context.Background(), dial) {
		t.Fatal("partial resolver readiness was accepted")
	}
	if probeOwnedDNSV1(nil, dial) {
		t.Fatal("nil context was accepted")
	}
	if probeOwnedDNSV1(context.Background(), nil) {
		t.Fatal("nil dialer was accepted")
	}
}

type dnsProbeConnectionV1 struct{ net.Conn }

func (*dnsProbeConnectionV1) Close() error { return nil }
