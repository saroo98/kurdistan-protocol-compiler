//go:build phase18productiontest

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"context"
	"time"

	runtimeengine "kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
)

// NewProductionAttemptFixtureV1 is a cross-package test harness, absent from
// default/release source selection. It invokes the actual settings decoder,
// signed-current environment, private parent/admission and attempt constructors.
// It neither creates verification receipts nor fabricates handshake results.
func NewProductionAttemptFixtureV1(input MaintenanceCurrentInputV1, settingsWire []byte, environment productionCurrentEnvironmentV1, platform ProductionPlatformOwnerV1, now time.Time) (*ProductionAttemptAdmissionV1, func() int32, int32) {
	settings, status := decodeProductionSettingsV1(settingsWire)
	if status != productionSuccessV1 {
		return nil, nil, int32(status)
	}
	ticket, s := reserveProductionSlotV1(&HandleRegistry{})
	if s != 0 {
		return nil, nil, s
	}
	p, s := newProductionParentV1(ticket, 80<<20, time.Time{})
	if s != 0 {
		return nil, nil, s
	}
	opening, s := p.beginUseV1(productionUseOpeningV1, productionBudgetChargeV1{})
	if s != 0 {
		return nil, nil, s
	}
	rates, err := runtimeengine.NewProbeRateRegistryV1(64)
	if err != nil {
		p.finishUseV1(opening)
		return nil, nil, 18
	}
	o, s := newProductionAdmissionV1(p, opening, input, settings, environment, platform, func() time.Time { return now }, time.Now, rates,
		selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 80 << 20, MaxArtifactBytes: 1 << 20, MaxPublicationBytes: 1 << 20})
	p.finishUseV1(opening)
	if s != 0 {
		if p.admission != nil {
			p.admission.closeV1(context.Background())
		}
		return nil, nil, s
	}
	use, s := p.beginUseV1(productionUseAttemptV1, productionBudgetChargeV1{})
	if s != 0 {
		o.closeV1(context.Background())
		return nil, nil, s
	}
	a, s := newProductionAttemptAdmissionV1(o, o.resources, 0, use)
	if s != 0 {
		p.finishUseV1(use)
		o.closeV1(context.Background())
		return nil, nil, s
	}
	cleanup := func() int32 {
		if a.transport != nil {
			a.transport.CloseWakeV1()
			if s := a.transport.FinishV1(); s != 0 {
				return s
			}
			<-a.transport.DoneV1()
		}
		if a.borrow != nil {
			if s := a.borrow.FinishOwnedV1(); s != 0 {
				return s
			}
		} else {
			b, s := a.BorrowV1()
			if s != 0 {
				return s
			}
			if s = b.FinishOwnedV1(); s != 0 {
				return s
			}
		}
		if s := o.resources.destroyV1(); s != 0 {
			return s
		}
		if s := p.finishUseV1(use); s != 0 {
			return s
		}
		return o.closeV1(context.Background())
	}
	return a, cleanup, 0
}
