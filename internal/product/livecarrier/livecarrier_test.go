// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package livecarrier

import (
	"errors"
	"testing"

	"kurdistan/internal/contracts/carrier/carrierreview"
)

func TestResolveClosedLiveCarrierMapping(t *testing.T) {
	got, err := Resolve(carrierreview.FamilyHTTPSLikeTCP)
	if err != nil || got.Version != Version || got.StrategyFamily != carrierreview.FamilyHTTPSLikeTCP ||
		got.ImplementationFamily != FamilyKurdTLS13TCP || !got.LoopbackConformanceOnly {
		t.Fatalf("authority=%+v err=%v", got, err)
	}
	for _, value := range []string{"", carrierreview.FamilyRelayBridgeRotation, carrierreview.FamilyDNSSurvival, FamilyKurdTLS13TCP, "unknown"} {
		if got, err := Resolve(value); !errors.Is(err, ErrNotAuthorized) || got != (Authority{}) {
			t.Fatalf("value=%q authority=%+v err=%v", value, got, err)
		}
	}
}
