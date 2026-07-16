// SPDX-License-Identifier: AGPL-3.0-or-later
package lifecycle

import "testing"

func d(a Action, g uint64, e string) Decision {
	return Decision{Action: a, ProfileID: "p", Scope: "r", Generation: g, EvidenceReference: e}
}
func TestLifecycleMonotonicAndRecovery(t *testing.T) {
	s, err := Apply(State{}, d(Admit, 1, "a"))
	if err != nil || s.Status != Admitted {
		t.Fatal(s, err)
	}
	if got, err := Apply(s, d(Admit, 1, "a")); err != nil || got != s {
		t.Fatal(got, err)
	}
	r, err := Apply(s, d(Revoke, 2, "r"))
	if err != nil || r.Status != Revoked {
		t.Fatal(r, err)
	}
	if _, err := Apply(r, d(Admit, 1, "old")); err == nil {
		t.Fatal("stale recovery accepted")
	}
	recovered, err := Apply(r, d(Admit, 3, "new"))
	if err != nil || recovered.Status != Admitted {
		t.Fatal(recovered, err)
	}
}
func TestRejectsConflictPartialAndScopeChange(t *testing.T) {
	s, _ := Apply(State{}, d(Admit, 2, "a"))
	for name, x := range map[string]Decision{"equal conflict": d(Revoke, 2, "b"), "partial": {Action: Revoke, Generation: 3}, "scope": {Action: Revoke, ProfileID: "p", Scope: "global", Generation: 3, EvidenceReference: "b"}} {
		t.Run(name, func(t *testing.T) {
			got, err := Apply(s, x)
			if err == nil || got != s {
				t.Fatal(got, err)
			}
		})
	}
}
func TestDisableIsFailClosed(t *testing.T) {
	s, _ := Apply(State{}, d(Disable, 4, "off"))
	if s.Status != Disabled {
		t.Fatal(s)
	}
	if _, err := Apply(s, d(Admit, 4, "same")); err == nil {
		t.Fatal("equal generation re-enabled")
	}
}

func TestSupersessionAndReplacementAdmission(t *testing.T) {
	admitted, err := Apply(State{}, d(Admit, 1, "admission"))
	if err != nil {
		t.Fatal(err)
	}
	superseded, err := Apply(admitted, d(Supersede, 2, "supersession"))
	if err != nil || superseded.Status != Superseded {
		t.Fatal(superseded, err)
	}
	if got, err := Apply(superseded, d(Supersede, 2, "supersession")); err != nil || got != superseded {
		t.Fatal(got, err)
	}
	replacement, err := Apply(superseded, d(Admit, 3, "replacement"))
	if err != nil || replacement.Status != Admitted || replacement.Generation != 3 {
		t.Fatal(replacement, err)
	}
}

func TestSupersessionRejectsInvalidSourceAndConflicts(t *testing.T) {
	admitted, _ := Apply(State{}, d(Admit, 2, "admission"))
	superseded, _ := Apply(admitted, d(Supersede, 3, "supersession"))

	tests := map[string]struct {
		current  State
		decision Decision
	}{
		"absent source":      {State{Status: Absent}, d(Supersede, 1, "supersession")},
		"already superseded": {superseded, d(Supersede, 4, "again")},
		"stale replacement":  {superseded, d(Admit, 2, "replacement")},
		"equal conflict":     {superseded, d(Admit, 3, "replacement")},
		"direct replacement": {admitted, d(Admit, 3, "replacement")},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Apply(tc.current, tc.decision)
			if err == nil || got != tc.current {
				t.Fatal(got, err)
			}
		})
	}
}

func TestUnknownCurrentStatusFailsClosed(t *testing.T) {
	current := State{Status: Status("corrupt"), ProfileID: "p", Scope: "r", Generation: 2, EvidenceReference: "old"}
	got, err := Apply(current, d(Revoke, 3, "new"))
	if err == nil || got != current {
		t.Fatalf("unknown current status changed state: got=%+v err=%v", got, err)
	}
}

func TestUnknownEqualGenerationActionFailsClosed(t *testing.T) {
	current, err := Apply(State{}, d(Admit, 2, "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	decision := d(Action("unknown"), current.Generation, current.EvidenceReference)
	got, err := Apply(current, decision)
	if err == nil || got != current {
		t.Fatalf("unknown equal-generation action changed state: got=%+v err=%v", got, err)
	}
}

func TestMalformedAbsentStateFailsClosed(t *testing.T) {
	current := State{Status: Absent, ProfileID: "p", Scope: "r", Generation: 1, EvidenceReference: "evidence"}
	got, err := Apply(current, d(Admit, 2, "replacement"))
	if err == nil || got != current {
		t.Fatalf("malformed absent state changed state: got=%+v err=%v", got, err)
	}
}
