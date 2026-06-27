package fsm

import (
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func FuzzFSMTransition(f *testing.F) {
	f.Add("not-a-message", "not-a-state", byte(0))
	f.Add("session_close", "", byte(1))
	f.Fuzz(func(t *testing.T, message, fromState string, roleByte byte) {
		if len(message) > 1024 || len(fromState) > 1024 {
			return
		}
		p, err := compiler.Generate(702)
		if err != nil {
			t.Fatal(err)
		}
		role := ir.RoleClient
		if roleByte%2 == 1 {
			role = ir.RoleServer
		}
		i, err := New(p, role)
		if err != nil {
			t.Fatal(err)
		}
		if fromState != "" {
			_ = i.SetStateForPeer(fromState)
		}
		_ = i.Apply(message)

		malformed := *p
		malformed.GenerationHash = ""
		malformed.Transitions = append([]ir.Transition(nil), p.Transitions...)
		if len(malformed.Transitions) > 0 {
			malformed.Transitions[0].From = fromState
			_, _ = New(&malformed, role)
		}
	})
}
