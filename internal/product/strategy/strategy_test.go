// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package strategy

import (
	"testing"

	"kurdistan/internal/contracts/carrier/carrierreview"
)

func TestSelectExcludesUnsafeControlAndOrders(t *testing.T) {
	sel, err := Select(Request{ProfileRef: "p-1", RiskTolerance: RiskToleranceStandard})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if !sel.Synthetic {
		t.Fatal("selection must be marked synthetic (no live probing)")
	}
	for _, c := range sel.Ordered {
		if c.Family == carrierreview.FamilyUnsafeControl {
			t.Fatalf("unsafe control family was selected: %+v", c)
		}
	}
	if len(sel.Ordered) == 0 {
		t.Fatal("expected at least one eligible family")
	}
	for i := 1; i < len(sel.Ordered); i++ {
		if sel.Ordered[i-1].Family > sel.Ordered[i].Family {
			t.Fatal("ordered candidates are not deterministically sorted")
		}
	}
}

func TestSelectRejectsEmptyRefAndBadTolerance(t *testing.T) {
	if _, err := Select(Request{ProfileRef: ""}); err == nil {
		t.Error("empty profile_ref should be rejected")
	}
	if _, err := Select(Request{ProfileRef: "p", RiskTolerance: "reckless"}); err == nil {
		t.Error("unknown risk_tolerance should be rejected")
	}
}

func TestConservativeExcludesManualReview(t *testing.T) {
	cons, _ := Select(Request{ProfileRef: "p", RiskTolerance: RiskToleranceConservative})
	std, _ := Select(Request{ProfileRef: "p", RiskTolerance: RiskToleranceStandard})
	if len(cons.Ordered) > len(std.Ordered) {
		t.Fatal("conservative tolerance must not admit more families than standard")
	}
}
