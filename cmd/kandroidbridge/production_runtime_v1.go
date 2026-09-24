// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"kurdistan/internal/androidbridge"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
	"time"
)

// One physical process owner. Neither session close nor maintenance recreation
// replaces this registry or refunds authenticated per-profile rate history.
var productionProcessProbeRatesV1, productionProcessProbeRatesErrorV1 = runtime.NewProbeRateRegistryV1(64)
var productionProcessUpdateRatesV1, productionProcessUpdateRatesStatusV1 = androidbridge.NewMaintenanceUpdateRateRegistryV1(64)

func productionRuntimeConfigV1(platform androidbridge.ProductionSessionPlatformV1) androidbridge.ProductionSessionConfigV1 {
	return androidbridge.ProductionSessionConfigV1{Environment: selfHostedBridgeEnvironment{}, Platform: platform, Factory: productionNetworkFactoryV1{}, ProbeRates: productionProcessProbeRatesV1, Now: time.Now, MonotonicNow: time.Now, Limits: selfhost.LiveMaintenanceLimits{MaxArtifactBytes: envelope.MaxTotalInputBytes, MaxPublicationBytes: 8 << 20}}
}

func productionMaintenanceConfigV1(config androidbridge.MaintenanceConfigV1) androidbridge.MaintenanceConfigV1 {
	config.ProbeRates = productionProcessProbeRatesV1
	config.UpdateRates = productionProcessUpdateRatesV1
	return config
}
