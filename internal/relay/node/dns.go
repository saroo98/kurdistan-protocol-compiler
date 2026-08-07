// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"context"
	"net"
)

var ownedDNSAddressesV1 = [...]string{
	"10.77.0.1:53",
	"[fd4b:7572:6400::1]:53",
}

type dnsDialV1 func(context.Context, string, string) (net.Conn, error)

// OwnedDNSReadyV1 verifies that both owner-local tunnel resolvers accept TCP.
// It sends no DNS query and exposes no resolver detail through returned errors.
func OwnedDNSReadyV1(ctx context.Context) bool {
	dialer := &net.Dialer{}
	return probeOwnedDNSV1(ctx, dialer.DialContext)
}

func probeOwnedDNSV1(ctx context.Context, dial dnsDialV1) bool {
	if ctx == nil || dial == nil {
		return false
	}
	for _, address := range ownedDNSAddressesV1 {
		if ctx.Err() != nil {
			return false
		}
		connection, err := dial(ctx, "tcp", address)
		if err != nil || connection == nil {
			if connection != nil {
				_ = connection.Close()
			}
			return false
		}
		if err := connection.Close(); err != nil {
			return false
		}
	}
	return true
}
