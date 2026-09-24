// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"testing"
)

func TestServicePreparationV1SourceOverlapAndProvenance(t *testing.T) {
	plan, _ := pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
	defer plan.Destroy()
	facts, ok := plan.ConstructionFactsV2()
	if !ok {
		t.Fatal("missing facts")
	}
	b, ok := sessionplan.AdmittedCalculationBoundsV2(facts.ProfileBytes)
	if !ok {
		t.Fatal("invalid dependency")
	}
	s, err := ServicePreparationBoundsForPlanV1(plan, true)
	t.Logf("profile=%d decoder=%d policy=%d program=%d scratch=%d admission-max=%d", facts.ProfileBytes, b.DecoderBytes, b.PolicyBytes, b.ProgramBytes, s.OwnedBytes, s.RetainedAdmissionBytes)
	if err != nil || s.OwnedBytes != b.DecoderBytes+b.PolicyBytes+b.ProgramBytes || s.ProxyAttributedBytes != s.OwnedBytes || s.RetainedAdmissionBytes != serviceAdmissionMaximumBytesV1() {
		t.Fatal("scratch must be additional to retained endpoint/admission", s, err)
	}
	raw, err := ServicePreparationBoundsForPlanV1(plan, false)
	if err != nil || raw.OwnedBytes != s.OwnedBytes || raw.ProxyAttributedBytes != 0 {
		t.Fatal("raw scratch missing or proxy attributed")
	}
	if _, err := ServicePreparationBoundsForPlanV1(sessionplan.PlanV2{}, false); err != ServiceResourceLimitV1 {
		t.Fatal("absent provenance did not fail closed")
	}
}

func TestServicePreparationV1StandaloneSixteenMiBRefusesBeforeSecret(t *testing.T) {
	result, plan, cfg, _ := pumpClientFixtureV1(t)
	cfg.BufferBudget = 16 << 20
	if pump, err := NewClientServicePumpV1(result, plan, cfg); pump != nil || err != ServiceResourceLimitV1 {
		if pump != nil {
			pump.Close()
		}
		t.Fatal("unfunded decoder construction accepted", err)
	}
	if _, ok := result.ContextSnapshotV1(); !ok {
		t.Fatal("resource refusal consumed secret")
	}
	if _, ok := serviceAddBytesV1(^uint64(0), 1); ok {
		t.Fatal("capacity overflow accepted")
	}
	lowSigned, _ := pumpPlanPolicyFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1}, func(p *runtimepolicy.PolicyV2) { p.Services.Proxy.MaxBufferBytes = 16 << 20 })
	defer lowSigned.Destroy()
	if f, ok := lowSigned.ConstructionFactsV2(); !ok || f.ProxyBufferBytes != 16<<20 {
		t.Fatal("signed proxy provenance lost")
	}
	for _, budget := range []uint64{16 << 20, 64 << 20} {
		cfg.BufferBudget = budget
		if pump, err := NewClientServicePumpV1(result, lowSigned, cfg); pump != nil || err != ServiceResourceLimitV1 {
			t.Fatal("signed ceiling widened", err)
		}
	}
}
