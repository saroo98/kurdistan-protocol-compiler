// SPDX-License-Identifier: AGPL-3.0-or-later
package security

import (
	"bytes"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kurdistan/internal/protocol/ir"
)

const (
	frozenApplicationCiphertextV1 = "89152cecf7ec6c45a6c04a7e55f9f74567da3b33"
	frozenControlCiphertextV1     = "645f6773feb3092029eee5728fb9696ef98658"
)

func TestAuthenticatedOpenV1FrozenExactVectors(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	context := envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 64, "metadata_authenticated")
	client, relay := envelopePairV1(t, schedule, context)
	application, err := client.SealApplicationV1(3, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	control, err := client.SealControlV1(2, []byte("ack"), []byte("control-aad"))
	if err != nil {
		t.Fatal(err)
	}
	if application.RecordType != 1 || application.Epoch != 0 || application.Direction != DirectionClientToRelayV1 || application.Slot != 3 || application.Sequence != 0 || application.SealedLength != 20 {
		t.Fatalf("application frozen header=%+v", application)
	}
	if control.RecordType != 2 || control.Epoch != 0 || control.Direction != DirectionClientToRelayV1 || control.Slot != 0 || control.Sequence != 1 || control.SealedLength != 19 {
		t.Fatalf("control frozen header=%+v", control)
	}
	for name, vector := range map[string]struct {
		record EnvelopeRecordV1
		want   string
	}{
		"application": {record: application, want: frozenApplicationCiphertextV1},
		"control":     {record: control, want: frozenControlCiphertextV1},
	} {
		if got := hex.EncodeToString(vector.record.Ciphertext); got != vector.want {
			t.Errorf("%s ciphertext=%s", name, got)
		}
	}
	plaintext, applicationReplay, err := relay.AuthenticateApplicationV1(application)
	if err != nil || !bytes.Equal(plaintext, []byte("body")) {
		t.Fatalf("application prepared vector=%x %v", plaintext, err)
	}
	clear(plaintext)
	if err := applicationReplay.Commit(); err != nil {
		t.Fatal(err)
	}
	plaintext, controlReplay, err := relay.AuthenticateControlV1(control, []byte("control-aad"))
	if err != nil || !bytes.Equal(plaintext, []byte("ack")) {
		t.Fatalf("control prepared vector=%x %v", plaintext, err)
	}
	clear(plaintext)
	if err := controlReplay.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyMatrixEnvelopeClassRuntimeEnforcementBypassGuardSentinelV1(t *testing.T) {
	type row struct {
		name, mode string
		class      uint16
	}
	for _, tc := range []row{
		{"metadata/class1", "metadata_authenticated", RecordClassApplicationV1},
		{"synthetic/class2", "synthetic_aead_test", RecordClassSyntheticV1},
		{"full-context/class1", "full_context_bound_envelope", RecordClassApplicationV1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			schedule := mustNonceScheduleV1(t)
			defer schedule.Destroy()
			client, relay := envelopePairV1(t, schedule, envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 4, tc.mode))
			if class, err := client.ExpectedClassV1(); err != nil || class != tc.class {
				t.Fatalf("valid class=%d err=%v", class, err)
			}
			record, err := client.SealApplicationV1(3, []byte("body"))
			if err != nil {
				t.Fatal(err)
			}
			if plaintext, err := relay.OpenApplicationV1(record); err != nil || !bytes.Equal(plaintext, []byte("body")) {
				t.Fatalf("valid owner output=%q err=%v", plaintext, err)
			}
			freshClient, freshRelay := envelopePairV1(t, schedule, envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 4, tc.mode))
			bad, err := freshClient.SealApplicationV1(3, []byte("body"))
			if err != nil {
				t.Fatal(err)
			}
			mutations := 0
			bad.Ciphertext[0] ^= 1
			mutations++
			plaintext, actual := freshRelay.OpenApplicationV1(bad)
			if mutations != 1 || plaintext != nil || actual == nil || !errors.Is(actual, ErrAuthenticationFailed) || actual.Error() != "authentication_failed" {
				t.Fatalf("mutations=%d plaintext=%q error=%v", mutations, plaintext, actual)
			}
		})
	}

	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	client, _ := envelopePairV1(t, schedule, envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 64, "metadata_authenticated"))
	application, err := client.SealApplicationV1(3, []byte("body"))
	if err != nil || hex.EncodeToString(application.Ciphertext) != frozenApplicationCiphertextV1 {
		t.Fatalf("frozen application=%x err=%v", application.Ciphertext, err)
	}
	control, err := client.SealControlV1(2, []byte("ack"), []byte("control-aad"))
	if err != nil || hex.EncodeToString(control.Ciphertext) != frozenControlCiphertextV1 {
		t.Fatalf("frozen control=%x err=%v", control.Ciphertext, err)
	}
}

func TestAuthenticatedReplayV1MalformedRetargetMatrix(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	context := envelopeContextFixtureV1(NonceModeStreamPartitionedCounterV1, ReplayPolicyWindowedReplayV1, 8, "metadata_authenticated")
	client, relay := envelopePairV1(t, schedule, context)
	_, otherRelay := envelopePairV1(t, schedule, context)
	record, err := client.SealApplicationV1(7, []byte("retarget"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, capability, err := relay.AuthenticateApplicationV1(record)
	if err != nil {
		t.Fatal(err)
	}
	clear(plaintext)
	base := capability.state
	makeState := func() *authenticatedReplayStateV1 {
		state := &authenticatedReplayStateV1{codec: base.codec, owner: base.owner, slot: base.slot, sequence: base.sequence, grant: base.grant}
		state.self = state
		return state
	}
	cases := map[string]func(*authenticatedReplayStateV1){
		"wrong-self":    func(state *authenticatedReplayStateV1) { state.self = base },
		"nil-codec":     func(state *authenticatedReplayStateV1) { state.codec = nil },
		"other-codec":   func(state *authenticatedReplayStateV1) { state.codec = otherRelay },
		"nil-owner":     func(state *authenticatedReplayStateV1) { state.owner = nil },
		"other-owner":   func(state *authenticatedReplayStateV1) { state.owner = otherRelay.state },
		"retarget-slot": func(state *authenticatedReplayStateV1) { state.slot++ },
		"retarget-seq":  func(state *authenticatedReplayStateV1) { state.sequence++ },
		"missing-grant": func(state *authenticatedReplayStateV1) { state.grant = nil },
		"foreign-grant": func(state *authenticatedReplayStateV1) { state.grant = &authenticatedReplayGrantV1{} },
		"wrong-authority": func(state *authenticatedReplayStateV1) {
			state.grant = &authenticatedReplayGrantV1{authority: otherRelay.state.replayAuthority, codec: state.codec, owner: state.owner, slot: state.slot, sequence: state.sequence}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			state := makeState()
			mutate(state)
			if err := (AuthenticatedReplayV1{state: state}).Commit(); !errors.Is(err, ErrReplay) {
				t.Fatalf("malformed capability committed: %v", err)
			}
			if len(relay.state.replay) != 0 || len(otherRelay.state.replay) != 0 {
				t.Fatal("malformed capability mutated replay")
			}
		})
	}
	if err := capability.Discard(); err != nil {
		t.Fatal(err)
	}
	plaintext, err = relay.OpenApplicationV1(record)
	if err != nil || string(plaintext) != "retarget" {
		t.Fatalf("malformed matrix consumed valid replay: %q %v", plaintext, err)
	}
	clear(plaintext)
}

func TestAuthenticatedOpenV1InputOwnership(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	client, relay := envelopePairV1(t, schedule, envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 8, "metadata_authenticated"))
	aad := []byte("owned-aad")
	record, err := client.SealControlV1(2, []byte("owned-plaintext"), aad)
	if err != nil {
		t.Fatal(err)
	}
	original := cloneEnvelopeRecordV1(record)
	plaintext, capability, err := relay.AuthenticateControlV1(record, aad)
	if err != nil {
		t.Fatal(err)
	}
	record.RecordType = 99
	record.Epoch++
	record.Direction = 0
	record.Slot = 9
	record.Sequence++
	record.SealedLength = 0
	clear(record.Ciphertext)
	clear(aad)
	if string(plaintext) != "owned-plaintext" {
		t.Fatalf("caller mutation changed plaintext: %q", plaintext)
	}
	clear(plaintext)
	if err := capability.Commit(); err != nil {
		t.Fatalf("caller mutation retargeted capability: %v", err)
	}
	if plaintext, _, err = relay.AuthenticateControlV1(original, []byte("owned-aad")); plaintext != nil || !errors.Is(err, ErrReplayDuplicate) {
		t.Fatalf("owned input did not commit exact record: %q %v", plaintext, err)
	}
}

func TestAuthenticatedReplayV1PolicyNonceDomainMatrix(t *testing.T) {
	for _, mode := range []string{NonceModeCounterXORBaseV1, NonceModeCounterAppendBaseV1, NonceModeDirectionalCounterV1, NonceModeStreamPartitionedCounterV1} {
		for _, policy := range []string{ReplayPolicyOrderedOnlyV1, ReplayPolicyBoundedReorderV1, ReplayPolicyWindowedReplayV1} {
			t.Run(mode+"/"+policy, func(t *testing.T) {
				schedule := mustNonceScheduleV1(t)
				defer schedule.Destroy()
				client, relay := envelopePairV1(t, schedule, envelopeContextFixtureV1(mode, policy, 8, "metadata_authenticated"))
				first, err := client.SealApplicationV1(1, []byte("first"))
				if err != nil {
					t.Fatal(err)
				}
				second, err := client.SealApplicationV1(1, []byte("second"))
				if err != nil {
					t.Fatal(err)
				}
				secondPlaintext, secondReplay, err := relay.AuthenticateApplicationV1(second)
				if policy == ReplayPolicyOrderedOnlyV1 {
					if secondPlaintext != nil || secondReplay.state != nil || !errors.Is(err, ErrReplayOutOfOrder) || len(relay.state.replay) != 0 {
						t.Fatalf("ordered out-of-order prepare=%q %#v %v", secondPlaintext, secondReplay, err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				clear(secondPlaintext)
				firstPlaintext, firstReplay, err := relay.AuthenticateApplicationV1(first)
				if err != nil {
					t.Fatal(err)
				}
				clear(firstPlaintext)
				if err := firstReplay.Commit(); err != nil {
					t.Fatal(err)
				}
				if policy == ReplayPolicyOrderedOnlyV1 {
					secondPlaintext, secondReplay, err = relay.AuthenticateApplicationV1(second)
					if err != nil {
						t.Fatal(err)
					}
					clear(secondPlaintext)
				}
				if err := secondReplay.Discard(); err != nil {
					t.Fatal(err)
				}
				opened, err := relay.OpenApplicationV1(second)
				if err != nil || string(opened) != "second" {
					t.Fatalf("out-of-order prepared token changed replay: %q %v", opened, err)
				}
				clear(opened)
				control, err := client.SealControlV1(2, []byte("control"), []byte("aad"))
				if err != nil {
					t.Fatal(err)
				}
				controlPlaintext, controlReplay, err := relay.AuthenticateControlV1(control, []byte("aad"))
				if err != nil {
					t.Fatal(err)
				}
				clear(controlPlaintext)
				if err := controlReplay.Commit(); err != nil {
					t.Fatal(err)
				}
				if mode == NonceModeStreamPartitionedCounterV1 {
					other, err := client.SealApplicationV1(2, []byte("other-domain"))
					if err != nil {
						t.Fatal(err)
					}
					otherPlaintext, otherReplay, err := relay.AuthenticateApplicationV1(other)
					if err != nil {
						t.Fatal(err)
					}
					clear(otherPlaintext)
					if err := otherReplay.Commit(); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

func TestAuthenticatedReplayV1MixedDomainRaceBounded(t *testing.T) {
	for iteration := 0; iteration < 16; iteration++ {
		schedule := mustNonceScheduleV1(t)
		client, relay := envelopePairV1(t, schedule, envelopeContextFixtureV1(NonceModeStreamPartitionedCounterV1, ReplayPolicyWindowedReplayV1, 16, "metadata_authenticated"))
		appOne, err := client.SealApplicationV1(1, []byte("one"))
		if err != nil {
			t.Fatal(err)
		}
		appTwo, err := client.SealApplicationV1(2, []byte("two"))
		if err != nil {
			t.Fatal(err)
		}
		control, err := client.SealControlV1(2, []byte("control"), []byte("aad"))
		if err != nil {
			t.Fatal(err)
		}
		plainOne, tokenOne, err := relay.AuthenticateApplicationV1(appOne)
		if err != nil {
			t.Fatal(err)
		}
		clear(plainOne)
		plainTwo, tokenTwo, err := relay.AuthenticateApplicationV1(appTwo)
		if err != nil {
			t.Fatal(err)
		}
		clear(plainTwo)
		plainControl, tokenControl, err := relay.AuthenticateControlV1(control, []byte("aad"))
		if err != nil {
			t.Fatal(err)
		}
		clear(plainControl)
		tokens := []AuthenticatedReplayV1{tokenOne, tokenTwo, tokenControl}
		var successes [3]atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for index, capability := range tokens {
			for attempt := 0; attempt < 16; attempt++ {
				wg.Add(1)
				go func(index, attempt int, copyCapability AuthenticatedReplayV1) {
					defer wg.Done()
					<-start
					var err error
					if attempt%2 == 0 {
						err = copyCapability.Commit()
					} else {
						err = copyCapability.Discard()
					}
					if err == nil {
						successes[index].Add(1)
					}
				}(index, attempt, capability)
			}
		}
		close(start)
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("mixed-domain race timed out")
		}
		for index := range successes {
			if successes[index].Load() != 1 {
				t.Fatal("mixed-domain token decided more than once")
			}
		}
		schedule.Destroy()
	}
}

func TestAuthenticatedReplayV1CapabilitySurfaceAST(t *testing.T) {
	typeOf := reflect.TypeOf(AuthenticatedReplayV1{})
	if typeOf.NumField() != 1 || typeOf.Field(0).PkgPath == "" {
		t.Fatal("capability exposes forgeable public state")
	}
	for _, methodName := range []string{"Commit", "Discard"} {
		method, ok := typeOf.MethodByName(methodName)
		if !ok || method.Type.NumIn() != 1 || method.Type.NumOut() != 1 || method.Type.Out(0) != reflect.TypeOf((*error)(nil)).Elem() {
			t.Fatalf("capability method surface %s: %#v", methodName, method)
		}
	}
	_, filename, _, _ := runtime.Caller(0)
	filename = strings.Replace(filename, "envelope_v1_test.go", "envelope.go", 1)
	file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, specification := range general.Specs {
			typeSpec, ok := specification.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != "AuthenticatedReplayV1" {
				continue
			}
			structure, ok := typeSpec.Type.(*ast.StructType)
			if !ok || len(structure.Fields.List) != 1 {
				t.Fatal("capability is not one opaque state handle")
			}
			for _, field := range structure.Fields.List {
				for _, name := range field.Names {
					if name.IsExported() {
						t.Fatalf("exported capability field %s", name.Name)
					}
				}
			}
		}
	}
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, forbidden := range []string{"func (capability AuthenticatedReplayV1) Commit(", "func (capability AuthenticatedReplayV1) Discard("} {
		if strings.Count(source, forbidden) != 1 {
			t.Fatalf("unexpected capability surface for %q", forbidden)
		}
	}
}

func TestAuthenticatedOpenV1DefersReplayAndPreservesVectors(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	context := envelopeContextFixtureV1(NonceModeCounterXORBaseV1, ReplayPolicyWindowedReplayV1, 4, "full_context_bound_envelope")
	client, relay := envelopePairV1(t, schedule, context)

	application, err := client.SealApplicationV1(3, []byte("application-vector"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, capability, err := relay.AuthenticateApplicationV1(application)
	if err != nil || string(plaintext) != "application-vector" || len(relay.state.replay) != 0 {
		t.Fatalf("prepared application open=%q replay=%d err=%v", plaintext, len(relay.state.replay), err)
	}
	clear(plaintext)
	if err := capability.Discard(); err != nil {
		t.Fatal(err)
	}
	if plaintext, err = relay.OpenApplicationV1(application); err != nil || string(plaintext) != "application-vector" {
		t.Fatalf("discard consumed application replay: %q %v", plaintext, err)
	}
	clear(plaintext)

	control, err := client.SealControlV1(RecordClassSyntheticV1, []byte("control-vector"), []byte("record-aad"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, capability, err = relay.AuthenticateControlV1(control, []byte("record-aad"))
	if err != nil || string(plaintext) != "control-vector" {
		t.Fatalf("prepared control open=%q err=%v", plaintext, err)
	}
	clear(plaintext)
	if err := capability.Commit(); err != nil {
		t.Fatal(err)
	}
	if plaintext, _, err = relay.AuthenticateControlV1(control, []byte("record-aad")); plaintext != nil || !errors.Is(err, ErrReplayDuplicate) {
		t.Fatalf("committed control replay=%q err=%v", plaintext, err)
	}
}

func TestAuthenticatedReplayV1OneShotCopyDiscardAndForgery(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	client, relay := envelopePairV1(t, schedule, envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 64, "metadata_authenticated"))
	record, err := client.SealApplicationV1(1, []byte("one-shot"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, capability, err := relay.AuthenticateApplicationV1(record)
	if err != nil {
		t.Fatal(err)
	}
	clear(plaintext)
	copyCapability := capability
	forgedState := &authenticatedReplayStateV1{
		self: capability.state, codec: capability.state.codec, owner: capability.state.owner,
		slot: capability.state.slot, sequence: capability.state.sequence,
	}
	forged := AuthenticatedReplayV1{state: forgedState}
	if err := forged.Commit(); !errors.Is(err, ErrReplay) {
		t.Fatalf("forged capability committed: %v", err)
	}
	if err := (AuthenticatedReplayV1{}).Commit(); !errors.Is(err, ErrReplay) {
		t.Fatalf("zero capability committed: %v", err)
	}
	if err := capability.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := copyCapability.Commit(); !errors.Is(err, ErrReplay) {
		t.Fatalf("copied capability committed twice: %v", err)
	}
	if err := capability.Discard(); !errors.Is(err, ErrReplay) {
		t.Fatalf("commit-then-discard succeeded: %v", err)
	}

	second, err := client.SealApplicationV1(1, []byte("discard"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, discarded, err := relay.AuthenticateApplicationV1(second)
	if err != nil {
		t.Fatal(err)
	}
	clear(plaintext)
	discardedCopy := discarded
	if err := discarded.Discard(); err != nil {
		t.Fatal(err)
	}
	if err := discardedCopy.Commit(); !errors.Is(err, ErrReplay) {
		t.Fatalf("discard-then-commit succeeded: %v", err)
	}
	plaintext, err = relay.OpenApplicationV1(second)
	if err != nil || string(plaintext) != "discard" {
		t.Fatalf("discard mutated replay: %q %v", plaintext, err)
	}
	clear(plaintext)
}

func TestAuthenticatedReplayV1ConcurrentCopiesCommitOnce(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	client, relay := envelopePairV1(t, schedule, envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 64, "metadata_authenticated"))
	record, err := client.SealApplicationV1(1, []byte("concurrent"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, capability, err := relay.AuthenticateApplicationV1(record)
	if err != nil {
		t.Fatal(err)
	}
	clear(plaintext)
	const attempts = 32
	var successes atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(copyCapability AuthenticatedReplayV1) {
			defer wg.Done()
			<-start
			if copyCapability.Commit() == nil {
				successes.Add(1)
			}
		}(capability)
	}
	close(start)
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("capability commits=%d", successes.Load())
	}
}

func TestAuthenticatedReplayV1IndependentTokensAndCodecCopies(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	client, relay := envelopePairV1(t, schedule, envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 64, "metadata_authenticated"))
	record, err := client.SealApplicationV1(1, []byte("independent"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, first, err := relay.AuthenticateApplicationV1(record)
	if err != nil {
		t.Fatal(err)
	}
	clear(plaintext)
	codecCopy := *relay
	plaintext, second, err := codecCopy.AuthenticateApplicationV1(record)
	if err != nil {
		t.Fatal(err)
	}
	clear(plaintext)
	var successes atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, capability := range []AuthenticatedReplayV1{first, second} {
		wg.Add(1)
		go func(capability AuthenticatedReplayV1) {
			defer wg.Done()
			<-start
			if capability.Commit() == nil {
				successes.Add(1)
			}
		}(capability)
	}
	close(start)
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("independent same-sequence commits=%d", successes.Load())
	}
	if plaintext, err := relay.OpenApplicationV1(record); plaintext != nil || !errors.Is(err, ErrReplayDuplicate) {
		t.Fatalf("codec copy did not share replay authority: %q %v", plaintext, err)
	}
}

func TestAuthenticatedReplayV1CopiedCommitDiscardRace(t *testing.T) {
	for iteration := 0; iteration < 32; iteration++ {
		schedule := mustNonceScheduleV1(t)
		client, relay := envelopePairV1(t, schedule, envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 4, "metadata_authenticated"))
		record, err := client.SealApplicationV1(1, []byte("race"))
		if err != nil {
			t.Fatal(err)
		}
		plaintext, capability, err := relay.AuthenticateApplicationV1(record)
		if err != nil {
			t.Fatal(err)
		}
		clear(plaintext)
		start := make(chan struct{})
		results := make(chan string, 2)
		go func(copyCapability AuthenticatedReplayV1) {
			<-start
			if copyCapability.Commit() == nil {
				results <- "commit"
			} else {
				results <- ""
			}
		}(capability)
		go func(copyCapability AuthenticatedReplayV1) {
			<-start
			if copyCapability.Discard() == nil {
				results <- "discard"
			} else {
				results <- ""
			}
		}(capability)
		close(start)
		firstResult, secondResult := <-results, <-results
		winner := firstResult + secondResult
		if winner != "commit" && winner != "discard" {
			t.Fatalf("commit/discard results=%q/%q", firstResult, secondResult)
		}
		opened, openErr := relay.OpenApplicationV1(record)
		if winner == "commit" {
			if opened != nil || !errors.Is(openErr, ErrReplayDuplicate) {
				t.Fatalf("commit winner left replay open: %q %v", opened, openErr)
			}
		} else if openErr != nil || string(opened) != "race" {
			t.Fatalf("discard winner mutated replay: %q %v", opened, openErr)
		}
		clear(opened)
		schedule.Destroy()
	}
}

func TestAuthenticatedOpenV1FailureReturnsNoAuthorityAndAPIBoundary(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	client, relay := envelopePairV1(t, schedule, envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 4, "metadata_authenticated"))
	record, err := client.SealApplicationV1(1, []byte("authenticated"))
	if err != nil {
		t.Fatal(err)
	}
	record.Ciphertext[0] ^= 1
	plaintext, capability, err := relay.AuthenticateApplicationV1(record)
	if plaintext != nil || capability.state != nil || !errors.Is(err, ErrAuthenticationFailed) || len(relay.state.replay) != 0 {
		t.Fatalf("authentication failure leaked authority: %q %#v %v", plaintext, capability, err)
	}
	typeOf := reflect.TypeOf((*EnvelopeCodecV1)(nil))
	for _, methodName := range []string{"AuthenticateApplicationV1", "AuthenticateControlV1"} {
		method, ok := typeOf.MethodByName(methodName)
		if !ok {
			t.Fatalf("missing %s", methodName)
		}
		signature := strings.ToLower(method.Type.String())
		for _, forbidden := range []string{"nonce", "direction", "replaykey", "replay_key", "policy", "callback"} {
			if strings.Contains(signature, forbidden) {
				t.Fatalf("caller authority in %s: %s", methodName, signature)
			}
		}
	}
}

func TestEnvelopeV1SequenceZeroMatrix(t *testing.T) {
	modes := []string{NonceModeCounterXORBaseV1, NonceModeCounterAppendBaseV1, NonceModeDirectionalCounterV1, NonceModeStreamPartitionedCounterV1}
	policies := []string{ReplayPolicyOrderedOnlyV1, ReplayPolicyBoundedReorderV1, ReplayPolicyWindowedReplayV1}
	envelopes := []string{"metadata_authenticated", "synthetic_aead_test", "full_context_bound_envelope"}
	for _, mode := range modes {
		for _, policy := range policies {
			for _, window := range []int{2, 4, 4096} {
				for _, envelope := range envelopes {
					for _, application := range []bool{false, true} {
						schedule := mustNonceScheduleV1(t)
						context := envelopeContextFixtureV1(mode, policy, window, envelope)
						client, relay := envelopePairV1(t, schedule, context)
						var record EnvelopeRecordV1
						var err error
						if application {
							record, err = client.SealApplicationV1(1, []byte("payload"))
						} else {
							record, err = client.SealControlV1(2, []byte("payload"), []byte("aad"))
						}
						if err != nil || record.Sequence != 0 || record.Direction != DirectionClientToRelayV1 || record.Epoch != schedule.Epoch {
							t.Fatalf("first strict record mismatch mode=%s policy=%s envelope=%s app=%v: %+v %v", mode, policy, envelope, application, record, err)
						}
						var plaintext []byte
						if application {
							plaintext, err = relay.OpenApplicationV1(record)
						} else {
							plaintext, err = relay.OpenControlV1(record, []byte("aad"))
						}
						if err != nil || string(plaintext) != "payload" {
							t.Fatalf("open mismatch: %q %v", plaintext, err)
						}
						if application {
							plaintext, err = relay.OpenApplicationV1(record)
						} else {
							plaintext, err = relay.OpenControlV1(record, []byte("aad"))
						}
						if plaintext != nil || !errors.Is(err, ErrReplayDuplicate) {
							t.Fatalf("duplicate returned plaintext/category: %q %v", plaintext, err)
						}
						schedule.Destroy()
					}
				}
			}
		}
	}
}

func TestDirectionV1ExpectedNonceEnvelopeV1(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	client, relay := envelopePairV1(t, schedule, envelopeContextFixtureV1(NonceModeCounterXORBaseV1, ReplayPolicyWindowedReplayV1, 4, "metadata_authenticated"))
	record, err := client.SealApplicationV1(7, []byte("zero"))
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*EnvelopeRecordV1){
		func(v *EnvelopeRecordV1) { v.Direction = 0 },
		func(v *EnvelopeRecordV1) { v.Direction = DirectionRelayToClientV1 },
		func(v *EnvelopeRecordV1) { v.Epoch++ },
		func(v *EnvelopeRecordV1) { v.Slot = 0 },
		func(v *EnvelopeRecordV1) { v.RecordType = 0 },
	}
	for _, mutate := range mutations {
		bad := cloneEnvelopeRecordV1(record)
		mutate(&bad)
		if plaintext, err := relay.OpenApplicationV1(bad); plaintext != nil || !errors.Is(err, ErrNonceMismatch) {
			t.Fatalf("clear mismatch returned %q %v", plaintext, err)
		}
	}
	plaintext, err := relay.OpenApplicationV1(record)
	if err != nil || string(plaintext) != "zero" {
		t.Fatalf("valid zero after clear rejects: %q %v", plaintext, err)
	}
	reverse, err := relay.SealControlV1(2, []byte("reverse"), nil)
	if err != nil || reverse.Direction != DirectionRelayToClientV1 {
		t.Fatalf("relay direction: %+v %v", reverse, err)
	}
	if plaintext, err = client.OpenControlV1(reverse, nil); err != nil || string(plaintext) != "reverse" {
		t.Fatalf("reverse open: %q %v", plaintext, err)
	}
	freshSchedule := mustNonceScheduleV1(t)
	defer freshSchedule.Destroy()
	freshClient, freshRelay := envelopePairV1(t, freshSchedule, envelopeContextFixtureV1(NonceModeCounterXORBaseV1, ReplayPolicyWindowedReplayV1, 4, "metadata_authenticated"))
	fresh, err := freshClient.SealApplicationV1(1, []byte("fresh"))
	if err != nil {
		t.Fatal(err)
	}
	forged := cloneEnvelopeRecordV1(fresh)
	forged.Sequence++
	if plaintext, err := freshRelay.OpenApplicationV1(forged); plaintext != nil || !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("derived nonce forgery: %q %v", plaintext, err)
	}
	if plaintext, err := freshRelay.OpenApplicationV1(fresh); err != nil || string(plaintext) != "fresh" {
		t.Fatalf("valid zero after derived forgery: %q %v", plaintext, err)
	}
}

func TestEnvelopeV1ExactErrorSentinels(t *testing.T) {
	for err, want := range map[error]string{
		ErrPolicyInvalid: "policy_invalid", ErrAEADInvalid: "aead_invalid", ErrNonceMismatch: "nonce_mismatch",
		ErrNonceExhausted: "nonce_exhausted", ErrEnvelopeContextInvalid: "envelope_context_invalid",
		ErrEnvelopeModeRejected: "envelope_mode_rejected", ErrAuthenticationFailed: "authentication_failed",
		ErrReplayDuplicate: "replay_duplicate", ErrReplayStale: "replay_stale", ErrReplayOutOfOrder: "replay_out_of_order",
		ErrReplayTooFarFuture: "replay_too_far_future", ErrReplayExhausted: "replay_exhausted",
	} {
		if err.Error() != want {
			t.Fatalf("sentinel got %q want %q", err.Error(), want)
		}
	}
}

func TestEnvelopeModeAndErrorPathV1(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	for mode, want := range map[string]uint16{"metadata_authenticated": 1, "synthetic_aead_test": 2, "full_context_bound_envelope": 1} {
		client, _ := envelopePairV1(t, schedule, envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 4, mode))
		if got, err := client.ExpectedClassV1(); err != nil || got != want {
			t.Fatalf("mode %s class %d %v", mode, got, err)
		}
	}
	badContext := envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 4, "full_context_bound_envelope")
	badContext.FramingHash = [32]byte{}
	if _, err := NewClientEnvelopeV1(schedule, badContext); !errors.Is(err, ErrEnvelopeContextInvalid) {
		t.Fatalf("missing full context: %v", err)
	}
	context := envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 4, "full_context_bound_envelope")
	client, relay := envelopePairV1(t, schedule, context)
	record, err := client.SealControlV1(2, []byte("authenticated"), []byte("record"))
	if err != nil {
		t.Fatal(err)
	}
	bad := cloneEnvelopeRecordV1(record)
	bad.Ciphertext[0] ^= 1
	if plaintext, err := relay.OpenControlV1(bad, []byte("record")); plaintext != nil || !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tamper result: %q %v", plaintext, err)
	}
	if plaintext, err := relay.OpenControlV1(record, []byte("record")); err != nil || string(plaintext) != "authenticated" {
		t.Fatalf("valid after forged record: %q %v", plaintext, err)
	}
}

func TestEnvelopeV1ConcurrentAndExhaustionErrorPath(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	client, relay := envelopePairV1(t, schedule, envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 64, "metadata_authenticated"))
	const count = 32
	records := make(chan EnvelopeRecordV1, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(copyCodec EnvelopeCodecV1) {
			defer wg.Done()
			record, err := copyCodec.SealApplicationV1(1, []byte("x"))
			if err == nil {
				records <- record
			}
		}(*client)
	}
	wg.Wait()
	close(records)
	seen := make(map[uint64]bool)
	for record := range records {
		if seen[record.Sequence] {
			t.Fatalf("duplicate sequence %d", record.Sequence)
		}
		seen[record.Sequence] = true
	}
	if len(seen) != count {
		t.Fatalf("only %d concurrent allocations", len(seen))
	}
	one, err := client.SealControlV1(2, []byte("once"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var success atomic.Int32
	type openResult struct {
		plaintext []byte
		err       error
	}
	openResults := make(chan openResult, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(copyCodec EnvelopeCodecV1) {
			defer wg.Done()
			plaintext, err := copyCodec.OpenControlV1(one, nil)
			openResults <- openResult{plaintext: plaintext, err: err}
			if err == nil && string(plaintext) == "once" {
				success.Add(1)
			}
		}(*relay)
	}
	wg.Wait()
	close(openResults)
	if success.Load() != 1 {
		t.Fatalf("concurrent opens accepted %d", success.Load())
	}
	replayRejects := 0
	for result := range openResults {
		if result.err == nil {
			continue
		}
		if result.plaintext != nil || !errors.Is(result.err, ErrReplayDuplicate) {
			t.Fatalf("concurrent reject returned plaintext/category: %q %v", result.plaintext, result.err)
		}
		replayRejects++
	}
	if replayRejects != count-1 {
		t.Fatalf("concurrent replay rejects=%d want=%d", replayRejects, count-1)
	}

	failOnce := true
	client.state.sealFail = func() error {
		if failOnce {
			failOnce = false
			return errors.New("injected")
		}
		return nil
	}
	if _, err := client.SealApplicationV1(1, nil); !errors.Is(err, ErrAEADInvalid) {
		t.Fatalf("injected seal: %v", err)
	}
	afterFailure, err := client.SealApplicationV1(1, nil)
	if err != nil || afterFailure.Sequence != count+2 {
		t.Fatalf("failed seal did not burn: seq=%d err=%v", afterFailure.Sequence, err)
	}

	owner, err := NewClientNonceOwnerV1(schedule, NonceModeDirectionalCounterV1)
	if err != nil {
		t.Fatal(err)
	}
	owner.outbound.sequences[0] = nonceSequenceStateV1{next: math.MaxUint64}
	client.state.nonces.allocateControl = owner.AllocateOutboundControlV1
	last, err := client.SealControlV1(2, nil, nil)
	if err != nil || last.Sequence != math.MaxUint64 {
		t.Fatalf("last sequence: %d %v", last.Sequence, err)
	}
	if _, err := client.SealControlV1(2, nil, nil); !errors.Is(err, ErrNonceExhausted) {
		t.Fatalf("post-max allocation: %v", err)
	}
}

func envelopeContextFixtureV1(nonceMode, replayPolicy string, window int, envelopeMode string) EnvelopeContextV1 {
	fill := func(value byte) (out [32]byte) {
		for i := range out {
			out[i] = value
		}
		return out
	}
	return EnvelopeContextV1{
		EffectivePolicy:     ir.EffectiveSecurityPolicy{AEADSuite: "aead_aes_256_gcm", NonceMode: nonceMode, ReplayPolicy: replayPolicy, ReplayWindowSize: window, SecureEnvelopeMode: envelopeMode},
		MaxEnvelopeBytes:    4096,
		EffectivePolicyHash: fill(1), TranscriptHash: fill(2), CapabilityHash: fill(3), ProfileHash: fill(4), FramingHash: fill(5), CarrierContextHash: fill(6),
	}
}

func envelopePairV1(t *testing.T, schedule KeySchedule, context EnvelopeContextV1) (*EnvelopeCodecV1, *EnvelopeCodecV1) {
	t.Helper()
	client, err := NewClientEnvelopeV1(schedule, context)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := NewRelayEnvelopeV1(schedule, context)
	if err != nil {
		t.Fatal(err)
	}
	return client, relay
}

func cloneEnvelopeRecordV1(record EnvelopeRecordV1) EnvelopeRecordV1 {
	record.Ciphertext = append([]byte(nil), record.Ciphertext...)
	return record
}
