package fsm

import (
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func TestValidGeneratedHandshakeReachesRelayReady(t *testing.T) {
	p, _ := compiler.Generate(42)
	path, err := RunFirstContactPath(p)
	if err != nil {
		t.Fatal(err)
	}
	if path[len(path)-1] != p.FirstContact.RelayReadyState {
		t.Fatal("path did not end at relay-ready")
	}
}

func TestInvalidFirstMessageFails(t *testing.T) {
	p, _ := compiler.Generate(42)
	i, _ := New(p, ir.RoleClient)
	if err := i.Apply("wrong"); err == nil {
		t.Fatal("expected wrong message to fail")
	}
}

func TestWrongRoleTransitionFails(t *testing.T) {
	p, _ := compiler.Generate(42)
	i, _ := New(p, ir.RoleServer)
	firstClientStep := p.FirstContact.Steps[0]
	if err := i.Apply(firstClientStep.Message); err == nil {
		t.Fatal("expected wrong role to fail")
	}
}

func TestWrongProfileFails(t *testing.T) {
	a, _ := compiler.Generate(42)
	b, _ := compiler.Generate(43)
	i, _ := New(a, ir.RoleClient)
	if err := i.Apply(b.FirstContact.Steps[0].Message); err == nil {
		t.Fatal("expected wrong profile message to fail")
	}
}

func TestDifferentGeneratedProfilesHaveDifferentStatePaths(t *testing.T) {
	a, _ := compiler.Generate(42)
	b, _ := compiler.Generate(43)
	pathA, _ := RunFirstContactPath(a)
	pathB, _ := RunFirstContactPath(b)
	if len(pathA) == len(pathB) && pathA[1] == pathB[1] {
		t.Fatal("expected generated state paths to differ")
	}
}
