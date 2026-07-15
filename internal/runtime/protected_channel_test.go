// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/runtime/labfault"
)

func newProtectedChannelWithRuntimeLabFaultV1(t *testing.T, seed int64, mode string) (*ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, *strictProtectedChannelV1) {
	t.Helper()
	_, client, relay := newAuthenticatingFirstRecordPairV1(t, seed, "message_lifetime_bound", 32, 32)
	token, err := labfault.NewTokenV1(mode)
	if err != nil {
		t.Fatal(err)
	}
	channel, err := newStrictProtectedChannelWithLabFaultV1(client, relay, token)
	if err != nil {
		t.Fatal(err)
	}
	return client, relay, channel
}

func TestReusedNonceFaultCausalRedGreenV1(t *testing.T) {
	_, _, _, normal := newProtectedChannelV1(t, 8260, "message_lifetime_bound", 32)
	if _, _, err := normal.sealClientApplicationV1(1, []byte("normal-one")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := normal.sealClientApplicationV1(1, []byte("normal-two")); err != nil {
		t.Fatal(err)
	}
	if got := normal.nonceSummaryV1(); got.Collisions != 0 {
		t.Fatalf("normal collisions=%d", got.Collisions)
	}
	_, _, fault := newProtectedChannelWithRuntimeLabFaultV1(t, 8261, "reused_nonce")
	firstRecord, _, err := fault.sealClientApplicationV1(1, []byte("fault-one"))
	if err != nil {
		t.Fatal(err)
	}
	secondRecord, _, err := fault.sealClientApplicationV1(1, []byte("fault-two"))
	if err != nil {
		t.Fatal(err)
	}
	firstHeader, _, err := parseApplicationRecordV1(firstRecord, applicationDirectionClientV1, fault.context.MaxEnvelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	secondHeader, _, err := parseApplicationRecordV1(secondRecord, applicationDirectionClientV1, fault.context.MaxEnvelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	if firstHeader.Epoch != secondHeader.Epoch || firstHeader.StreamSlot != secondHeader.StreamSlot || firstHeader.Sequence != secondHeader.Sequence {
		t.Fatalf("fault coordinates differ: %+v %+v", firstHeader, secondHeader)
	}
	if got := fault.nonceSummaryV1(); got.Collisions != 1 || got.Allocations != 1 {
		t.Fatalf("fault summary=%+v", got)
	}
}

func TestSecurityReplayFaultCausalRedGreenV1(t *testing.T) {
	_, _, _, normal := newProtectedChannelV1(t, 8262, "message_lifetime_bound", 32)
	record, _, err := normal.sealClientApplicationV1(1, []byte("security-replay"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := normal.openClientApplicationV1(record); err != nil || string(got) != "security-replay" {
		t.Fatalf("first=%q err=%v", got, err)
	}
	if got, _, err := normal.openClientApplicationV1(record); err != security.ErrReplayDuplicate || got != nil {
		t.Fatalf("normal replay=%q err=%v", got, err)
	}
	_, _, fault := newProtectedChannelWithRuntimeLabFaultV1(t, 8263, "accepts_replay")
	record, _, err = fault.sealClientApplicationV1(1, []byte("security-replay"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if got, _, err := fault.openClientApplicationV1(record); err != nil || string(got) != "security-replay" {
			t.Fatalf("fault %d=%q err=%v", i, got, err)
		}
	}
}

func TestRuntimeReplayFaultCausalRedGreenV1(t *testing.T) {
	_, _, _, normal := newProtectedChannelV1(t, 8264, "message_lifetime_bound", 32)
	record, id, err := normal.sealClientApplicationV1(1, []byte("runtime-replay"))
	if err != nil {
		t.Fatal(err)
	}
	first, ack, err := normal.openClientApplicationV1(record)
	if err != nil || string(first) != "runtime-replay" {
		t.Fatal(err)
	}
	retry, err := normal.retryClientApplicationV1(id, []byte("runtime-replay"))
	if err != nil {
		t.Fatal(err)
	}
	second, cached, err := normal.openClientApplicationV1(retry)
	if err != nil || second != nil || cached != ack || normal.relay.state.life.receiveCompleted != 1 {
		t.Fatalf("normal second=%q ack=%+v/%+v count=%d err=%v", second, cached, ack, normal.relay.state.life.receiveCompleted, err)
	}
	_, relay, fault := newProtectedChannelWithRuntimeLabFaultV1(t, 8265, "runtime_accepts_replay")
	record, id, err = fault.sealClientApplicationV1(1, []byte("runtime-replay"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := fault.openClientApplicationV1(record); err != nil || string(got) != "runtime-replay" {
		t.Fatal(err)
	}
	retry, err = fault.retryClientApplicationV1(id, []byte("runtime-replay"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := fault.openClientApplicationV1(retry); err != nil || string(got) != "runtime-replay" || relay.state.life.receiveCompleted != 1 {
		t.Fatalf("fault second=%q count=%d err=%v", got, relay.state.life.receiveCompleted, err)
	}
}

func TestStateValidationFaultCausalRedGreenV1(t *testing.T) {
	check := func(t *testing.T, fault bool) {
		var client *ClientAuthenticatedEndpointV1
		var channel *strictProtectedChannelV1
		if fault {
			client, _, channel = newProtectedChannelWithRuntimeLabFaultV1(t, 8267, "runtime_no_state_validation")
		} else {
			_, client, _, channel = newProtectedChannelV1(t, 8266, "message_lifetime_bound", 32)
		}
		first, _, err := channel.sealClientApplicationV1(1, []byte("establish-relay"))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := channel.openClientApplicationV1(first); err != nil {
			t.Fatal(err)
		}
		record, _, err := channel.sealRelayApplicationV1(1, []byte("prohibited-state"))
		if err != nil {
			t.Fatal(err)
		}
		client.state.life.state = auth.StateAuthenticating
		got, _, err := channel.openRelayApplicationV1(record)
		if fault {
			if err != nil || string(got) != "prohibited-state" {
				t.Fatalf("fault=%q err=%v", got, err)
			}
		} else if err != ErrLifecycle || got != nil || client.state.life.receiveCompleted != 0 {
			t.Fatalf("normal=%q count=%d err=%v", got, client.state.life.receiveCompleted, err)
		}
	}
	t.Run("NormalChannelNoFault", func(t *testing.T) { check(t, false) })
	t.Run("RuntimeLabFault", func(t *testing.T) { check(t, true) })
}

func newProtectedChannelV1(t *testing.T, seed int64, rotation string, maxKey int) (*HandshakeRuntime, *ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, *strictProtectedChannelV1) {
	return newProtectedChannelLimitsV1(t, seed, rotation, 32, maxKey)
}

func newProtectedChannelLimitsV1(t *testing.T, seed int64, rotation string, maxSession, maxKey int) (*HandshakeRuntime, *ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, *strictProtectedChannelV1) {
	t.Helper()
	owner, client, relay := newAuthenticatingFirstRecordPairV1(t, seed, rotation, maxSession, maxKey)
	channel, err := newStrictProtectedChannelV1(client, relay)
	if err != nil {
		t.Fatal(err)
	}
	return owner, client, relay, channel
}

func TestAuthenticatedContextPolicyMatrixMutationResistanceV1(t *testing.T) {
	_, client, _, channel := newProtectedChannelV1(t, 7800, "message_lifetime_bound", 8)
	want := channel.retainedPolicyTupleV1()
	client.state.coordinator.mu.Lock()
	client.state.coordinator.context.EffectivePolicy.NonceMode = "future_nonce_mode"
	client.state.coordinator.context.EffectivePolicy.ProfileCompatibilityPolicy = "future_compatibility"
	client.state.coordinator.context.EffectivePolicy.ConfigValidationPolicy = "future_config"
	client.state.coordinator.mu.Unlock()
	if got := channel.retainedPolicyTupleV1(); got != want {
		t.Fatalf("retained authenticated policy changed after post-construction mutation: got=%+v want=%+v", got, want)
	}
}

func TestAuthenticatedContextOriginalSourceSubstitutionV1(t *testing.T) {
	known := sortedStringsV1(ir.SecurityCapabilities())
	floor := append([]string(nil), known[:2]...)
	fixture := newStrictSupportFixturePolicyWithSetsV1(t, security.TranscriptCanonicalV1, "strict_capabilities", "strict_required", "full_policy_binding", "strict_profile_bound", floor, floor, known, known, floor)
	input := lifecyclePairInputV1(t, fixture)
	input.ClientControls.QueueCeiling = fixture.view.ClientModeBinding.LimitBlock.CarrierMaxQueueDepth
	input.RelayControls.QueueCeiling = fixture.view.ServerModeBinding.LimitBlock.CarrierMaxQueueDepth
	runtime := lifecycleRuntimeV1(t, fixture)
	client, relay, err := runtime.NewAuthenticatedChannelPair(input)
	if err != nil {
		t.Fatal(err)
	}
	channel, err := newStrictProtectedChannelV1(client, relay)
	if err != nil {
		t.Fatal(err)
	}
	want := channel.retainedPolicyTupleV1()
	input.FirstContactInput.Client.OfferPolicy.NonceMode = "future_nonce"
	input.FirstContactInput.Server.ProfileHash[0] ^= 1
	input.FirstContactInput.SelectedPolicy.ProfileCompatibilityPolicy = "schema_and_feature"
	input.ClientConfig.value.ProfileHash[0] ^= 1
	input.RelayConfig.value.ConfigPolicyHash[0] ^= 1
	if got := channel.retainedPolicyTupleV1(); got != want {
		t.Fatalf("post-handshake source substitution changed retained policy: got=%+v want=%+v", got, want)
	}
	execute := func() error { _, _, err := channel.sealClientApplicationV1(1, []byte("retained-source")); return err }
	if err := execute(); err != nil {
		t.Fatalf("mutated original sources influenced retained channel: %v", err)
	}
}

func executePolicyOwnerProtectedRoundTripV1(t *testing.T, seed int64) {
	t.Helper()
	_, _, _, channel := newProtectedChannelV1(t, seed, "message_lifetime_bound", 8)
	record, operationID, err := channel.sealClientApplicationV1(1, []byte("policy-owner"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, ack, err := channel.openClientApplicationV1(record)
	if err != nil || !bytes.Equal(plaintext, []byte("policy-owner")) || ack.OperationID != operationID {
		t.Fatalf("private seal/open owner plaintext=%q ack=%+v err=%v", plaintext, ack, err)
	}
}

func TestPolicyMatrixCoveringSeedsProtectedChannelProductionV1(t *testing.T) {
	for _, seed := range policyCoveringArraySeedsV1 {
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			fixture, effective := generatedPolicyRuntimeFixtureV1(t, seed)
			owner := lifecycleRuntimeV1(t, fixture)
			input := lifecyclePairInputV1(t, fixture)
			if effective.ConfigValidationPolicy == "strict_profile_bound" {
				input.ClientControls.QueueCeiling = fixture.view.ClientModeBinding.LimitBlock.CarrierMaxQueueDepth
				input.RelayControls.QueueCeiling = fixture.view.ServerModeBinding.LimitBlock.CarrierMaxQueueDepth
			}
			client, relay, err := owner.NewAuthenticatedChannelPair(input)
			if err != nil {
				t.Fatalf("policy=%+v: %v", effective, err)
			}
			t.Cleanup(client.Close)
			channel, err := newStrictProtectedChannelV1(client, relay)
			if err != nil {
				t.Fatal(err)
			}
			want := policyMatrixTupleFromPolicyV1(irSecurityPolicyProjectionV1(effective))
			if got := channel.retainedPolicyTupleV1(); got != want {
				t.Fatalf("effective tuple got=%+v want=%+v", got, want)
			}
			class, err := applicationExpectedClassV1(channel.context)
			if err != nil {
				t.Fatal(err)
			}
			wantClass := uint16(RecordClassApplicationV1)
			if effective.SecureEnvelopeMode == "synthetic_aead_test" {
				wantClass = RecordClassSyntheticV1
			}
			if class != wantClass {
				t.Fatalf("envelope mode=%s class=%d want=%d", effective.SecureEnvelopeMode, class, wantClass)
			}
			record, operationID, err := channel.sealClientApplicationV1(1, []byte("covering-seed"))
			if err != nil {
				t.Fatal(err)
			}
			plaintext, ack, err := channel.openClientApplicationV1(record)
			if err != nil || !bytes.Equal(plaintext, []byte("covering-seed")) || ack.OperationID != operationID {
				t.Fatalf("roundtrip plaintext=%q ack=%+v err=%v", plaintext, ack, err)
			}
		})
	}
}

func TestPolicyMatrixPrivateEntrypointCausalBypassSentinelV1(t *testing.T) {
	type lifecycleCase struct {
		id  string
		run func(*testing.T, string)
	}
	lifecycleCases := []lifecycleCase{
		{"pm-owner:rotation/session_only", func(t *testing.T, id string) {
			_, _, _, channel := newProtectedChannelLimitsV1(t, 8801, "session_only", 2, 1)
			if _, _, err := channel.sealClientApplicationV1(1, []byte(id)); err != nil {
				t.Fatal(err)
			}
			_, _, err := channel.sealClientApplicationV1(1, []byte(id))
			if mutations := 1; mutations != 1 || !errors.Is(err, ErrKeyLifetimeExhausted) || err.Error() != ErrKeyLifetimeExhausted.Error() {
				t.Fatalf("%s boundary mutations=%d err=%v", id, mutations, err)
			}
		}},
		{"pm-owner:rotation/message_lifetime_bound", func(t *testing.T, id string) {
			_, _, _, channel := newProtectedChannelLimitsV1(t, 8802, "message_lifetime_bound", 2, 1)
			if _, _, err := channel.sealClientApplicationV1(1, []byte(id)); err != nil {
				t.Fatal(err)
			}
			record, _, err := channel.sealClientApplicationV1(1, []byte(id))
			header, _, parseErr := parseApplicationRecordV1(record, applicationDirectionClientV1, channel.context.MaxEnvelopeBytes)
			if mutations := 1; mutations != 1 || err != nil || parseErr != nil || header.Epoch != 1 {
				t.Fatalf("%s rekey mutation=%d header=%+v err=%v parse=%v", id, mutations, header, err, parseErr)
			}
		}},
		{"pm-owner:rotation/profile_lifetime_bound", func(t *testing.T, id string) {
			owner, _, _, channel := newProtectedChannelLimitsV1(t, 8803, "profile_lifetime_bound", 2, 1)
			owner.profileMu.Lock()
			owner.profileGeneration++
			owner.profileMu.Unlock()
			_, _, err := channel.sealClientApplicationV1(1, []byte(id))
			if mutations := 1; mutations != 1 || !errors.Is(err, ErrProfileRotationRequired) || err.Error() != ErrProfileRotationRequired.Error() {
				t.Fatalf("%s generation mutations=%d err=%v", id, mutations, err)
			}
		}},
		{"pm-owner:max_session/1", func(t *testing.T, id string) {
			_, _, _, channel := newProtectedChannelLimitsV1(t, 8804, "session_only", 1, 1)
			if _, _, err := channel.sealClientApplicationV1(1, []byte(id)); err != nil {
				t.Fatal(err)
			}
			_, _, err := channel.sealClientApplicationV1(1, []byte(id))
			if mutations := 1; mutations != 1 || !errors.Is(err, ErrSessionMessageLimit) || err.Error() != ErrSessionMessageLimit.Error() {
				t.Fatalf("%s operation mutations=%d err=%v", id, mutations, err)
			}
		}},
		{"pm-owner:max_session/16777216", func(t *testing.T, id string) {
			_, client, _, channel := newProtectedChannelLimitsV1(t, 8805, "session_only", 16777216, 16777216)
			client.state.life.sendCompleted = client.state.life.config.MaxSessionMessages
			_, _, err := channel.sealClientApplicationV1(1, []byte(id))
			if mutations := 1; mutations != 1 || !errors.Is(err, ErrSessionMessageLimit) || err.Error() != ErrSessionMessageLimit.Error() {
				t.Fatalf("%s boundary mutations=%d err=%v", id, mutations, err)
			}
		}},
		{"pm-owner:max_key/1", func(t *testing.T, id string) {
			_, _, _, channel := newProtectedChannelLimitsV1(t, 8806, "session_only", 2, 1)
			if _, _, err := channel.sealClientApplicationV1(1, []byte(id)); err != nil {
				t.Fatal(err)
			}
			_, _, err := channel.sealClientApplicationV1(1, []byte(id))
			if mutations := 1; mutations != 1 || !errors.Is(err, ErrKeyLifetimeExhausted) || err.Error() != ErrKeyLifetimeExhausted.Error() {
				t.Fatalf("%s operation mutations=%d err=%v", id, mutations, err)
			}
		}},
		{"pm-owner:max_key/16777216", func(t *testing.T, id string) {
			_, client, _, channel := newProtectedChannelLimitsV1(t, 8807, "session_only", 16777216, 16777216)
			client.state.life.outKeyAttempts = client.state.life.config.MaxKeyLifetimeMessages
			_, _, err := channel.sealClientApplicationV1(1, []byte(id))
			if mutations := 1; mutations != 1 || !errors.Is(err, ErrKeyLifetimeExhausted) || err.Error() != ErrKeyLifetimeExhausted.Error() {
				t.Fatalf("%s boundary mutations=%d err=%v", id, mutations, err)
			}
		}},
	}
	for _, item := range lifecycleCases {
		item := item
		t.Run(item.id, func(t *testing.T) { item.run(t, item.id) })
	}
	tests := []struct {
		name   string
		mutate func([]byte) []byte
		open   func(*strictProtectedChannelV1, []byte) error
		want   error
	}{
		{"wrong-direction", func(record []byte) []byte { return record }, func(channel *strictProtectedChannelV1, record []byte) error {
			_, _, err := channel.openRelayApplicationV1(record)
			return err
		}, ErrRecordInvalid},
		{"ciphertext-tamper", func(record []byte) []byte {
			clone := append([]byte(nil), record...)
			clone[len(clone)-1] ^= 1
			return clone
		}, func(channel *strictProtectedChannelV1, record []byte) error {
			_, _, err := channel.openClientApplicationV1(record)
			return err
		}, security.ErrAuthenticationFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, channel := newProtectedChannelV1(t, 7801, "message_lifetime_bound", 8)
			record, _, err := channel.sealClientApplicationV1(1, []byte("bypass-causal"))
			if err != nil {
				t.Fatal(err)
			}
			mutated := test.mutate(record)
			mutations := 0
			if test.name == "wrong-direction" {
				mutations = 1
			} else if !bytes.Equal(mutated, record) {
				mutations = 1
			}
			err = test.open(channel, mutated)
			if mutations != 1 || !errors.Is(err, test.want) || err.Error() != test.want.Error() {
				t.Fatalf("mutations=%d err=%v want exact %v", mutations, err, test.want)
			}
		})
	}
}

func TestProtectedChannelEndToEndSingleFragmentAckCloseV1(t *testing.T) {
	_, client, relay, channel := newProtectedChannelV1(t, 7801, "message_lifetime_bound", 8)
	payload := []byte("single-fragment-private-payload")
	record, operationID, err := channel.sealClientApplicationV1(7, payload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(record, payload) || bytes.Contains(record, payload) {
		t.Fatal("complete plaintext appeared at protected transport seam")
	}
	delivered, ack, err := channel.openClientApplicationV1(record)
	if err != nil || !bytes.Equal(delivered, payload) || ack.OperationID != operationID || relay.State() != auth.StateEstablished {
		t.Fatalf("application delivery=%q ack=%+v state=%s err=%v", delivered, ack, relay.State(), err)
	}
	ackRecord, err := channel.sealRelayAckV1(operationID, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ackRecord) != controlHeaderBytesV1+operationAckSealedBytesV1 || bytes.Contains(ackRecord, operationID[:]) {
		t.Fatal("Ack transport seam did not carry one complete opaque record")
	}
	if err := channel.openRelayAckV1(ackRecord); err != nil {
		t.Fatal(err)
	}
	closeRecord, err := channel.sealClientCloseV1()
	if err != nil {
		t.Fatal(err)
	}
	if len(closeRecord) != controlHeaderBytesV1+closeSealedBytesV1 {
		t.Fatalf("close length=%d", len(closeRecord))
	}
	if err := channel.openClientCloseV1(closeRecord); err != nil || client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
		t.Fatalf("close states=%s/%s err=%v", client.State(), relay.State(), err)
	}
	summary := channel.nonceSummaryV1()
	if summary.Domains != 2 || summary.Allocations != 3 || summary.Collisions != 0 {
		t.Fatalf("nonce observer=%+v", summary)
	}
}

func TestProtectedChannelMultiFragmentPendingHasNoDeliveryV1(t *testing.T) {
	_, _, relay, channel := newProtectedChannelV1(t, 7802, "message_lifetime_bound", 8)
	channel.mu.Lock()
	transmission, err := channel.client.state.life.beginOperationV1(3)
	if err != nil {
		channel.mu.Unlock()
		t.Fatal(err)
	}
	fragment := ApplicationFragmentV1{OperationID: transmission.operationID, FragmentCount: 2, OperationLength: 8, Fragment: []byte("half")}
	record, err := (ClientApplicationCodecV1{}).SealApplicationFragmentV1(channel.context, 3, fragment, func(slot uint16, body []byte) (security.EnvelopeRecordV1, error) {
		return channel.clientEnvelope.SealApplicationV1(slot, body)
	})
	channel.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	beforeReplay := relay.state.life.receiveCompleted
	if delivered, ack, err := channel.openClientApplicationV1(record); err != nil || delivered != nil || ack != (OperationAckV1{}) {
		t.Fatalf("pending multi fragment delivery=%q ack=%+v err=%v", delivered, ack, err)
	}
	if relay.State() != auth.StateAuthenticating || relay.state.life.receiveCompleted != beforeReplay || len(relay.state.life.completed) != 0 {
		t.Fatal("authenticated multi-fragment mutated lifecycle or established relay")
	}
	if _, _, err := channel.openClientApplicationV1(record); !errors.Is(err, security.ErrReplay) {
		t.Fatalf("committed pending fragment replay was not rejected: %v", err)
	}
}

func sealCustomClientFragmentsV1(t *testing.T, channel *strictProtectedChannelV1, slot uint16, fragments []ApplicationFragmentV1) ([][]byte, [32]byte) {
	t.Helper()
	channel.mu.Lock()
	defer channel.mu.Unlock()
	life := channel.client.state.life
	first, err := life.beginOperationV1(slot)
	if err != nil {
		t.Fatal(err)
	}
	records := make([][]byte, 0, len(fragments))
	for index := range fragments {
		transmission := first
		if index > 0 {
			transmission, err = channel.reserveAdditionalFragmentV1(life, first.operationID)
			if err != nil {
				t.Fatal(err)
			}
		}
		fragments[index].OperationID = first.operationID
		record, err := channel.sealPreparedApplicationFragmentLockedV1(true, life, transmission, fragments[index])
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records, first.operationID
}

func sealUncheckedClientFragmentV1(t *testing.T, channel *strictProtectedChannelV1, slot uint16, fragment ApplicationFragmentV1) []byte {
	t.Helper()
	channel.mu.Lock()
	defer channel.mu.Unlock()
	life := channel.client.state.life
	transmission, err := life.beginOperationV1(slot)
	if err != nil {
		t.Fatal(err)
	}
	fragment.OperationID = transmission.operationID
	class, err := applicationExpectedClassV1(channel.context)
	if err != nil {
		t.Fatal(err)
	}
	body := encodeApplicationBodyV1(class, fragment)
	defer clear(body)
	if _, err := channel.ensureEnvelopeForLifeV1(life, true); err != nil {
		t.Fatal(err)
	}
	envelope, err := channel.clientEnvelope.SealApplicationV1(slot, body)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(envelope.Ciphertext)
	if envelope.Epoch != transmission.recordEpoch || envelope.Sequence != transmission.recordSequence {
		t.Fatal("unchecked fragment used unexpected reservation")
	}
	header := encodeApplicationHeaderV1(ApplicationHeaderV1{
		Version: ApplicationRecordVersionV1, Type: RecordTypeApplicationFragmentV1, Epoch: envelope.Epoch,
		Direction: envelope.Direction, StreamSlot: envelope.Slot, Sequence: envelope.Sequence, SealedLength: envelope.SealedLength,
	})
	record := append([]byte(nil), header[:]...)
	return append(record, envelope.Ciphertext...)
}

func prepareExternalApplicationReplayV1(t *testing.T, channel *strictProtectedChannelV1, record []byte) security.AuthenticatedReplayV1 {
	t.Helper()
	header, sealed, err := parseApplicationRecordV1(record, applicationDirectionClientV1, channel.context.MaxEnvelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	body, capability, err := channel.relayEnvelope.AuthenticateApplicationV1(security.EnvelopeRecordV1{
		RecordType: header.Type, Epoch: header.Epoch, Direction: header.Direction, Slot: header.StreamSlot,
		Sequence: header.Sequence, SealedLength: header.SealedLength, Ciphertext: append([]byte(nil), sealed...),
	})
	clear(body)
	if err != nil {
		t.Fatal(err)
	}
	return capability
}

func TestProtectedChannelMultiFragmentExactCoverageV1(t *testing.T) {
	_, client, relay, channel := newProtectedChannelV1(t, 7880, "message_lifetime_bound", 8)
	payload := []byte("authenticated-fragment-coverage")
	records, operationID, err := channel.sealClientMultiFragmentV1(4, payload, []uint32{5, 9, uint32(len(payload) - 14)})
	if err != nil {
		t.Fatal(err)
	}
	operation := client.state.life.outstanding[operationID]
	if operation == nil || operation.attempts != 1 || client.state.life.sendCompleted != 0 || len(records) != 3 {
		t.Fatalf("fragment reservation operation=%+v sends=%d records=%d", operation, client.state.life.sendCompleted, len(records))
	}
	for index := 0; index < len(records)-1; index++ {
		delivered, ack, err := channel.openClientApplicationV1(records[index])
		if err != nil || delivered != nil || ack != (OperationAckV1{}) || relay.State() != auth.StateAuthenticating || relay.state.life.receiveCompleted != 0 {
			t.Fatalf("pending fragment %d delivery=%q ack=%+v state=%s receive=%d err=%v", index, delivered, ack, relay.State(), relay.state.life.receiveCompleted, err)
		}
	}
	delivered, ack, err := channel.openClientApplicationV1(records[len(records)-1])
	if err != nil || !bytes.Equal(delivered, payload) || ack.OperationID != operationID || ack.CompletedCount != 1 || relay.State() != auth.StateEstablished || relay.state.life.receiveCompleted != 1 {
		t.Fatalf("completion delivery=%q ack=%+v state=%s receive=%d err=%v", delivered, ack, relay.State(), relay.state.life.receiveCompleted, err)
	}
	channel.reassembly.mu.Lock()
	pending := len(channel.reassembly.entries)
	channel.reassembly.mu.Unlock()
	if pending != 0 {
		t.Fatalf("completed operation retained %d entries", pending)
	}
}

func TestFragmentCoverageAndBoundsV1(t *testing.T) {
	tests := []struct {
		name      string
		fragments []ApplicationFragmentV1
	}{
		{"overlap", []ApplicationFragmentV1{{FragmentIndex: 0, FragmentCount: 2, OperationLength: 6, FragmentOffset: 0, Fragment: []byte("abcd")}, {FragmentIndex: 1, FragmentCount: 2, OperationLength: 6, FragmentOffset: 3, Fragment: []byte("def")}}},
		{"gap", []ApplicationFragmentV1{{FragmentIndex: 0, FragmentCount: 2, OperationLength: 6, FragmentOffset: 0, Fragment: []byte("ab")}, {FragmentIndex: 1, FragmentCount: 2, OperationLength: 6, FragmentOffset: 3, Fragment: []byte("def")}}},
		{"conflicting-count", []ApplicationFragmentV1{{FragmentIndex: 0, FragmentCount: 2, OperationLength: 6, FragmentOffset: 0, Fragment: []byte("abc")}, {FragmentIndex: 1, FragmentCount: 3, OperationLength: 6, FragmentOffset: 3, Fragment: []byte("def")}}},
		{"conflicting-length", []ApplicationFragmentV1{{FragmentIndex: 0, FragmentCount: 2, OperationLength: 6, FragmentOffset: 0, Fragment: []byte("abc")}, {FragmentIndex: 1, FragmentCount: 2, OperationLength: 7, FragmentOffset: 3, Fragment: []byte("def")}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, relay, channel := newProtectedChannelV1(t, 7890+int64(len(test.name)), "message_lifetime_bound", 8)
			records, _ := sealCustomClientFragmentsV1(t, channel, 2, test.fragments)
			if delivered, _, err := channel.openClientApplicationV1(records[0]); err != nil || delivered != nil {
				t.Fatalf("first fragment delivery=%q err=%v", delivered, err)
			}
			if delivered, ack, err := channel.openClientApplicationV1(records[1]); !errors.Is(err, ErrRecordInvalid) || delivered != nil || ack != (OperationAckV1{}) {
				t.Fatalf("invalid completion delivery=%q ack=%+v err=%v", delivered, ack, err)
			}
			if relay.state.life.receiveCompleted != 0 || relay.State() != auth.StateAuthenticating {
				t.Fatal("invalid coverage committed logical operation")
			}
		})
	}

	t.Run("oversized", func(t *testing.T) {
		_, _, relay, channel := newProtectedChannelV1(t, 7900, "message_lifetime_bound", 8)
		length := channel.reassembly.maxOperation + 1
		records, _ := sealCustomClientFragmentsV1(t, channel, 2, []ApplicationFragmentV1{{FragmentIndex: 0, FragmentCount: 2, OperationLength: length, Fragment: []byte("x")}})
		if delivered, _, err := channel.openClientApplicationV1(records[0]); !errors.Is(err, ErrRecordInvalid) || delivered != nil || relay.state.life.receiveCompleted != 0 {
			t.Fatalf("oversized delivery=%q err=%v", delivered, err)
		}
	})

	t.Run("first-fragment-out-of-bounds", func(t *testing.T) {
		_, _, relay, channel := newProtectedChannelV1(t, 7901, "message_lifetime_bound", 8)
		record := sealUncheckedClientFragmentV1(t, channel, 2, ApplicationFragmentV1{FragmentIndex: 0, FragmentCount: 2, OperationLength: 4, FragmentOffset: 3, Fragment: []byte("xx")})
		channel.reassembly.mu.Lock()
		beforeTick := channel.reassembly.tick
		channel.reassembly.mu.Unlock()
		for attempt := 0; attempt < 2; attempt++ {
			if delivered, ack, err := channel.openClientApplicationV1(record); !errors.Is(err, ErrRecordInvalid) || errors.Is(err, security.ErrReplay) || delivered != nil || ack != (OperationAckV1{}) {
				t.Fatalf("attempt %d delivery=%q ack=%+v err=%v", attempt, delivered, ack, err)
			}
		}
		channel.reassembly.mu.Lock()
		pending, afterTick := len(channel.reassembly.entries), channel.reassembly.tick
		channel.reassembly.mu.Unlock()
		if pending != 0 || afterTick != beforeTick || relay.state.life.receiveCompleted != 0 {
			t.Fatalf("out-of-bounds state pending=%d tick=%d/%d receive=%d", pending, beforeTick, afterTick, relay.state.life.receiveCompleted)
		}
	})
}

func TestFragmentBoundsEpochCrossingReservationRejectedAtomicallyV1(t *testing.T) {
	_, client, relay, channel := newProtectedChannelV1(t, 7902, "message_lifetime_bound", 1)
	records, operationID, err := channel.sealClientMultiFragmentV1(1, []byte("pair"), []uint32{2, 2})
	if !errors.Is(err, ErrRecordInvalid) || records != nil || operationID != ([32]byte{}) {
		t.Fatalf("epoch crossing records=%x operation=%x err=%v", records, operationID, err)
	}
	if channel.nonceSummaryV1().Allocations != 0 || len(client.state.life.outstanding) != 0 || len(client.state.life.issuedOperations) != 0 ||
		client.State() != auth.StateEstablished || relay.State() != auth.StateAuthenticating {
		t.Fatalf("epoch rejection allocations=%d outstanding=%d issued=%d states=%s/%s", channel.nonceSummaryV1().Allocations, len(client.state.life.outstanding), len(client.state.life.issuedOperations), client.State(), relay.State())
	}
}

func TestFragmentReassemblyReplayFailureLeavesStateV1(t *testing.T) {
	t.Run("non-final", func(t *testing.T) {
		_, _, relay, channel := newProtectedChannelV1(t, 7910, "message_lifetime_bound", 8)
		records, _, err := channel.sealClientMultiFragmentV1(1, []byte("eight888"), []uint32{4, 4})
		if err != nil {
			t.Fatal(err)
		}
		external := prepareExternalApplicationReplayV1(t, channel, records[0])
		channel.beforeFragmentCommit = func() { channel.beforeFragmentCommit = nil; _ = external.Commit() }
		if delivered, _, err := channel.openClientApplicationV1(records[0]); !errors.Is(err, security.ErrReplay) || delivered != nil {
			t.Fatalf("non-final replay race delivery=%q err=%v", delivered, err)
		}
		channel.reassembly.mu.Lock()
		pending := len(channel.reassembly.entries)
		channel.reassembly.mu.Unlock()
		if pending != 0 || relay.state.life.receiveCompleted != 0 {
			t.Fatal("non-final replay failure mutated state")
		}
	})

	t.Run("completing", func(t *testing.T) {
		_, _, relay, channel := newProtectedChannelV1(t, 7911, "message_lifetime_bound", 8)
		records, operationID, err := channel.sealClientMultiFragmentV1(1, []byte("eight888"), []uint32{4, 4})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := channel.openClientApplicationV1(records[0]); err != nil {
			t.Fatal(err)
		}
		external := prepareExternalApplicationReplayV1(t, channel, records[1])
		channel.beforeFragmentCommit = func() { channel.beforeFragmentCommit = nil; _ = external.Commit() }
		if delivered, _, err := channel.openClientApplicationV1(records[1]); !errors.Is(err, security.ErrReplay) || delivered != nil {
			t.Fatalf("final replay race delivery=%q err=%v", delivered, err)
		}
		channel.reassembly.mu.Lock()
		pending, fragments := len(channel.reassembly.entries), len(channel.reassembly.entries[operationID].fragments)
		channel.reassembly.mu.Unlock()
		if pending != 1 || fragments != 1 || relay.state.life.receiveCompleted != 0 {
			t.Fatalf("final replay failure pending=%d fragments=%d receive=%d", pending, fragments, relay.state.life.receiveCompleted)
		}
	})
}

func TestFragmentBoundsCapacityV1(t *testing.T) {
	_, _, relay, channel := newProtectedChannelV1(t, 7920, "message_lifetime_bound", 16)
	for index := 0; index < strictFragmentMaxOperationsV1; index++ {
		records, _ := sealCustomClientFragmentsV1(t, channel, uint16(index+1), []ApplicationFragmentV1{{FragmentIndex: 0, FragmentCount: 2, OperationLength: 4, FragmentOffset: 0, Fragment: []byte("pa")}})
		if delivered, _, err := channel.openClientApplicationV1(records[0]); err != nil || delivered != nil {
			t.Fatalf("pending operation %d delivery=%q err=%v", index, delivered, err)
		}
	}
	records, _ := sealCustomClientFragmentsV1(t, channel, 20, []ApplicationFragmentV1{{FragmentIndex: 0, FragmentCount: 2, OperationLength: 4, FragmentOffset: 0, Fragment: []byte("la")}})
	if delivered, ack, err := channel.openClientApplicationV1(records[0]); !errors.Is(err, ErrRecordInvalid) || delivered != nil || ack != (OperationAckV1{}) {
		t.Fatalf("capacity delivery=%q ack=%+v err=%v", delivered, ack, err)
	}
	channel.reassembly.mu.Lock()
	pending := len(channel.reassembly.entries)
	channel.reassembly.mu.Unlock()
	if pending != strictFragmentMaxOperationsV1 || relay.state.life.receiveCompleted != 0 {
		t.Fatalf("capacity retained=%d receive=%d", pending, relay.state.life.receiveCompleted)
	}
}

func TestFragmentReassemblyExpiryUsesAcceptedTicksV1(t *testing.T) {
	_, _, _, channel := newProtectedChannelV1(t, 7930, "message_lifetime_bound", 16)
	stale, staleID := sealCustomClientFragmentsV1(t, channel, 1, []ApplicationFragmentV1{{FragmentIndex: 0, FragmentCount: 2, OperationLength: 5, FragmentOffset: 0, Fragment: []byte("st")}})
	if _, _, err := channel.openClientApplicationV1(stale[0]); err != nil {
		t.Fatal(err)
	}
	channel.reassembly.mu.Lock()
	before := channel.reassembly.tick
	channel.reassembly.mu.Unlock()
	if _, _, err := channel.openClientApplicationV1(stale[0]); !errors.Is(err, security.ErrReplay) {
		t.Fatalf("rejected replay err=%v", err)
	}
	channel.reassembly.mu.Lock()
	afterRejected := channel.reassembly.tick
	channel.reassembly.mu.Unlock()
	if afterRejected != before {
		t.Fatalf("rejected input advanced tick %d -> %d", before, afterRejected)
	}
	channel.reassembly.mu.Lock()
	channel.reassembly.tickStep = strictFragmentLifetimeTicksV1
	channel.reassembly.mu.Unlock()
	advance, _ := sealCustomClientFragmentsV1(t, channel, 2, []ApplicationFragmentV1{{FragmentIndex: 0, FragmentCount: 2, OperationLength: 4, FragmentOffset: 0, Fragment: []byte("li")}})
	if _, _, err := channel.openClientApplicationV1(advance[0]); err != nil {
		t.Fatal(err)
	}
	probe, _ := sealCustomClientFragmentsV1(t, channel, 3, []ApplicationFragmentV1{{FragmentIndex: 0, FragmentCount: 2, OperationLength: 4, FragmentOffset: 0, Fragment: []byte("pr")}})
	if _, _, err := channel.openClientApplicationV1(probe[0]); err != nil {
		t.Fatal(err)
	}
	channel.reassembly.mu.Lock()
	_, retained := channel.reassembly.entries[staleID]
	channel.reassembly.mu.Unlock()
	if retained {
		t.Fatal("expired fragment operation remained buffered")
	}
}

func TestFragmentConcurrentFinalAtMostOnceV1(t *testing.T) {
	_, _, relay, channel := newProtectedChannelV1(t, 7940, "message_lifetime_bound", 8)
	records, _, err := channel.sealClientMultiFragmentV1(1, []byte("concurrent-final"), []uint32{5, 11})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := channel.openClientApplicationV1(records[0]); err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for index := 0; index < 24; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if delivered, _, err := channel.openClientApplicationV1(append([]byte(nil), records[1]...)); err == nil && string(delivered) == "concurrent-final" {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || relay.state.life.receiveCompleted != 1 {
		t.Fatalf("final deliveries=%d receive=%d", successes.Load(), relay.state.life.receiveCompleted)
	}
}

func TestFragmentConcurrentFinalSurvivesExpiryInterleavingV1(t *testing.T) {
	_, _, relay, channel := newProtectedChannelV1(t, 7941, "message_lifetime_bound", 8)
	payload := []byte("expiry-final")
	records, _, err := channel.sealClientMultiFragmentV1(1, payload, []uint32{6, uint32(len(payload) - 6)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := channel.openClientApplicationV1(records[0]); err != nil {
		t.Fatal(err)
	}
	channel.beforeFragmentCommit = func() {
		channel.beforeFragmentCommit = nil
		channel.reassembly.mu.Lock()
		channel.reassembly.tick += strictFragmentLifetimeTicksV1
		channel.reassembly.expireLockedV1()
		channel.reassembly.mu.Unlock()
	}
	delivered, _, err := channel.openClientApplicationV1(records[1])
	if err != nil || !bytes.Equal(delivered, payload) || relay.state.life.receiveCompleted != 1 {
		t.Fatalf("expiry interleaving delivery=%q receive=%d err=%v", delivered, relay.state.life.receiveCompleted, err)
	}
	channel.reassembly.mu.Lock()
	pending := len(channel.reassembly.entries)
	channel.reassembly.mu.Unlock()
	if pending != 0 {
		t.Fatalf("finalized entry retained after expiry interleaving: %d", pending)
	}
}

func TestFragmentConcurrentFinalLoserDiscardsCapabilityV1(t *testing.T) {
	_, client, relay, channel := newProtectedChannelV1(t, 7942, "message_lifetime_bound", 8)
	payload := []byte("retry-final")
	records, operationID, err := channel.sealClientMultiFragmentV1(1, payload, []uint32{5, uint32(len(payload) - 5)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := channel.openClientApplicationV1(records[0]); err != nil {
		t.Fatal(err)
	}
	header, _, err := parseApplicationRecordV1(records[1], applicationDirectionClientV1, channel.context.MaxEnvelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	transmission, ok := lookupIssuedOperationV1(client.state.life, header.StreamSlot, header.Epoch, header.Sequence)
	if !ok {
		t.Fatal("final transmission missing")
	}
	finalFragment := ApplicationFragmentV1{
		OperationID: operationID, FragmentIndex: 1, FragmentCount: 2, OperationLength: uint32(len(payload)),
		FragmentOffset: 5, Fragment: append([]byte(nil), payload[5:]...),
	}
	defer clear(finalFragment.Fragment)
	firstCapability := prepareExternalApplicationReplayV1(t, channel, records[1])
	loserCapability := prepareExternalApplicationReplayV1(t, channel, records[1])
	entered := make(chan struct{})
	release := make(chan struct{})
	channel.beforeFragmentCommit = func() {
		close(entered)
		<-release
	}
	firstResult := make(chan error, 1)
	go func() {
		_, _, err := channel.acceptMultiFragmentV1(relay.state.life, transmission, header, finalFragment, firstCapability)
		firstResult <- err
	}()
	<-entered
	if delivered, ack, err := channel.acceptMultiFragmentV1(relay.state.life, transmission, header, finalFragment, loserCapability); !errors.Is(err, ErrRecordInvalid) || errors.Is(err, security.ErrReplay) || delivered != nil || ack != (OperationAckV1{}) {
		t.Fatalf("concurrent loser delivery=%q ack=%+v err=%v", delivered, ack, err)
	}
	key := recordReservationKeyV1{streamSlot: header.StreamSlot, epoch: header.Epoch, sequence: header.Sequence}
	life := client.state.life
	if !life.lockV1() {
		t.Fatal("sender lifecycle unavailable")
	}
	issued, ok := life.issuedOperations[key]
	if !ok || issued.operationID != operationID {
		life.coordinator.mu.Unlock()
		t.Fatal("final reservation missing")
	}
	delete(life.issuedOperations, key)
	life.coordinator.mu.Unlock()
	channel.beforeFragmentCommit = nil
	close(release)
	if err := <-firstResult; !errors.Is(err, ErrLifecycle) || errors.Is(err, security.ErrReplay) {
		t.Fatalf("forced first final failure=%v", err)
	}
	if !life.lockV1() {
		t.Fatal("sender lifecycle unavailable for restore")
	}
	life.issuedOperations[key] = issued
	life.coordinator.mu.Unlock()
	retryCapability := prepareExternalApplicationReplayV1(t, channel, records[1])
	delivered, ack, err := channel.acceptMultiFragmentV1(relay.state.life, transmission, header, finalFragment, retryCapability)
	if err != nil || !bytes.Equal(delivered, payload) || ack.OperationID != operationID || relay.state.life.receiveCompleted != 1 {
		t.Fatalf("retry delivery=%q ack=%+v receive=%d err=%v", delivered, ack, relay.state.life.receiveCompleted, err)
	}
	channel.reassembly.mu.Lock()
	pending := len(channel.reassembly.entries)
	channel.reassembly.mu.Unlock()
	if pending != 0 {
		t.Fatalf("retry left %d reassembly entries", pending)
	}
}

func TestFragmentCloseClearsBufferedAliasesV1(t *testing.T) {
	_, client, relay, channel := newProtectedChannelV1(t, 7950, "message_lifetime_bound", 8)
	records, _, err := channel.sealClientMultiFragmentV1(1, []byte("secret-buffer"), []uint32{6, 7})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := channel.openClientApplicationV1(records[0]); err != nil {
		t.Fatal(err)
	}
	channel.reassembly.mu.Lock()
	var alias []byte
	for _, entry := range channel.reassembly.entries {
		alias = entry.fragments[0].data
	}
	channel.reassembly.mu.Unlock()
	client.Close()
	channel.reassembly.mu.Lock()
	destroyed, pending, pendingBytes := channel.reassembly.destroyed, len(channel.reassembly.entries), channel.reassembly.pendingBytes
	channel.reassembly.mu.Unlock()
	if !destroyed || pending != 0 || pendingBytes != 0 || client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
		t.Fatalf("cleanup destroyed=%v pending=%d bytes=%d states=%s/%s", destroyed, pending, pendingBytes, client.State(), relay.State())
	}
	for index, value := range alias {
		if value != 0 {
			t.Fatalf("buffer alias byte %d not cleared", index)
		}
	}
}

func TestChannelTamperMatrixAuthenticatedClassV1(t *testing.T) {
	_, _, relay, channel := newProtectedChannelV1(t, 7803, "message_lifetime_bound", 8)
	channel.mu.Lock()
	transmission, err := channel.client.state.life.beginOperationV1(5)
	if err != nil {
		channel.mu.Unlock()
		t.Fatal(err)
	}
	fragment := ApplicationFragmentV1{OperationID: transmission.operationID, FragmentCount: 1, OperationLength: 5, Fragment: []byte("class")}
	body := encodeApplicationBodyV1(RecordClassSyntheticV1, fragment)
	envelope, err := channel.clientEnvelope.SealApplicationV1(5, body)
	clear(body)
	channel.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	header := encodeApplicationHeaderV1(ApplicationHeaderV1{Version: ApplicationRecordVersionV1, Type: RecordTypeApplicationFragmentV1, Epoch: envelope.Epoch, Direction: envelope.Direction, StreamSlot: envelope.Slot, Sequence: envelope.Sequence, SealedLength: envelope.SealedLength})
	record := append(header[:], envelope.Ciphertext...)
	clear(envelope.Ciphertext)
	if delivered, ack, err := channel.openClientApplicationV1(record); !errors.Is(err, security.ErrEnvelopeModeRejected) || delivered != nil || ack != (OperationAckV1{}) {
		t.Fatalf("class mutation delivery=%q ack=%+v err=%v", delivered, ack, err)
	}
	if relay.State() != auth.StateAuthenticating || relay.state.life.receiveCompleted != 0 {
		t.Fatal("authenticated class rejection mutated lifecycle")
	}
}

func TestChannelTamperMatrixAndTerminalCloseV1(t *testing.T) {
	t.Run("application-tag", func(t *testing.T) {
		_, _, relay, channel := newProtectedChannelV1(t, 7810, "message_lifetime_bound", 8)
		record, _, err := channel.sealClientApplicationV1(1, []byte("authenticated-only"))
		if err != nil {
			t.Fatal(err)
		}
		wrongDirection := append([]byte(nil), record...)
		wrongDirection[13] = byte(applicationDirectionRelayV1)
		if delivered, _, err := channel.openClientApplicationV1(wrongDirection); !errors.Is(err, ErrRecordInvalid) || delivered != nil || relay.State() != auth.StateAuthenticating {
			t.Fatalf("app direction delivered=%q state=%s err=%v", delivered, relay.State(), err)
		}
		wrongLength := append([]byte(nil), record...)
		wrongLength[27]++
		if delivered, _, err := channel.openClientApplicationV1(wrongLength); !errors.Is(err, ErrRecordInvalid) || delivered != nil || relay.State() != auth.StateAuthenticating {
			t.Fatalf("app length delivered=%q state=%s err=%v", delivered, relay.State(), err)
		}
		record[len(record)-1] ^= 1
		if delivered, _, err := channel.openClientApplicationV1(record); !errors.Is(err, security.ErrAuthenticationFailed) || delivered != nil || relay.State() != auth.StateAuthenticating {
			t.Fatalf("app tamper delivered=%q state=%s err=%v", delivered, relay.State(), err)
		}
	})

	t.Run("Ack-tag", func(t *testing.T) {
		_, client, _, channel := newProtectedChannelV1(t, 7811, "message_lifetime_bound", 8)
		record, id, err := channel.sealClientApplicationV1(1, []byte("ack-target"))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := channel.openClientApplicationV1(record); err != nil {
			t.Fatal(err)
		}
		ackRecord, err := channel.sealRelayAckV1(id, false)
		if err != nil {
			t.Fatal(err)
		}
		wrongDirection := append([]byte(nil), ackRecord...)
		wrongDirection[13] = byte(controlDirectionClientV1)
		if err := channel.openRelayAckV1(wrongDirection); !errors.Is(err, ErrOperationAckInvalid) || client.state.life.sendCompleted != 0 {
			t.Fatalf("Ack direction err=%v sends=%d", err, client.state.life.sendCompleted)
		}
		ackRecord[len(ackRecord)-1] ^= 1
		err = channel.openRelayAckV1(ackRecord)
		if !errors.Is(err, ErrOperationAckInvalid) || !errors.Is(err, security.ErrAuthenticationFailed) || client.state.life.sendCompleted != 0 || len(client.state.life.outstanding) != 1 {
			t.Fatalf("Ack tamper err=%v sends=%d outstanding=%d", err, client.state.life.sendCompleted, len(client.state.life.outstanding))
		}
	})

	t.Run("close-tag-terminal", func(t *testing.T) {
		_, client, relay, channel := newProtectedChannelV1(t, 7812, "message_lifetime_bound", 8)
		closeRecord, err := channel.sealClientCloseV1()
		if err != nil {
			t.Fatal(err)
		}
		closeRecord[len(closeRecord)-1] ^= 1
		if err := channel.openClientCloseV1(closeRecord); err != security.ErrAuthenticationFailed {
			t.Fatalf("close public category=%v", err)
		}
		if client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
			t.Fatalf("tampered close states=%s/%s", client.State(), relay.State())
		}
		if _, _, err := channel.sealClientApplicationV1(1, []byte("must-not-send")); err == nil {
			t.Fatal("terminal pair accepted later application")
		}
	})
}

func TestRuntimeNonceCompositionRekeyRetryAndSealFailureV1(t *testing.T) {
	_, _, relay, channel := newProtectedChannelV1(t, 7820, "message_lifetime_bound", 1)
	channel.afterSeal = func() error { return errors.New("injected post-allocation seal failure") }
	failed, operationID, err := channel.sealClientApplicationV1(4, []byte("retry-bytes"))
	if !errors.Is(err, security.ErrAEADInvalid) || failed != nil || operationID == [32]byte{} {
		t.Fatalf("seal failure record=%x id=%x err=%v", failed, operationID, err)
	}
	channel.afterSeal = nil
	retry, err := channel.retryClientApplicationV1(operationID, []byte("retry-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	header, _, err := parseApplicationRecordV1(retry, applicationDirectionClientV1, channel.context.MaxEnvelopeBytes)
	if err != nil || header.Epoch != 1 || header.Sequence != 0 {
		t.Fatalf("retry header=%+v err=%v", header, err)
	}
	if delivered, _, err := channel.openClientApplicationV1(retry); err != nil || string(delivered) != "retry-bytes" || relay.state.life.keyEpoch != 1 {
		t.Fatalf("retry delivery=%q epoch=%d err=%v", delivered, relay.state.life.keyEpoch, err)
	}
	if summary := channel.nonceSummaryV1(); summary.Collisions != 0 || summary.Allocations != 2 {
		t.Fatalf("nonce composition=%+v", summary)
	}
}

func TestProtectedChannelProfileGenerationClosesBeforeSendV1(t *testing.T) {
	owner, client, relay, channel := newProtectedChannelV1(t, 7830, "profile_lifetime_bound", 8)
	owner.profileMu.Lock()
	owner.profileGeneration++
	owner.profileMu.Unlock()
	if _, _, err := channel.sealClientApplicationV1(1, []byte("stale")); !errors.Is(err, ErrProfileRotationRequired) {
		t.Fatalf("stale send err=%v", err)
	}
	if client.State() != auth.StateClosed || relay.State() != auth.StateClosed || channel.nonceSummaryV1().Allocations != 0 {
		t.Fatal("stale profile did not close before nonce allocation")
	}
}

func TestProtectedChannelConcurrentDeliveryAtMostOnceV1(t *testing.T) {
	_, _, relay, channel := newProtectedChannelV1(t, 7840, "message_lifetime_bound", 8)
	record, _, err := channel.sealClientApplicationV1(1, []byte("concurrent"))
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := channel.openClientApplicationV1(append([]byte(nil), record...)); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || relay.state.life.receiveCompleted != 1 {
		t.Fatalf("concurrent deliveries=%d receive=%d", successes.Load(), relay.state.life.receiveCompleted)
	}
}

func TestProtectedChannelAckRetryFreshNonceConvergesV1(t *testing.T) {
	_, client, _, channel := newProtectedChannelV1(t, 7841, "message_lifetime_bound", 1)
	record, id, err := channel.sealClientApplicationV1(1, []byte("ack-retry"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := channel.openClientApplicationV1(record); err != nil {
		t.Fatal(err)
	}
	first, err := channel.sealRelayAckV1(id, false)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := channel.sealRelayAckV1(id, true)
	if err != nil {
		t.Fatal(err)
	}
	firstHeader, _, _ := parseControlRecordV1(first, controlDirectionRelayV1, RecordTypeOperationAckV1)
	retryHeader, _, _ := parseControlRecordV1(retry, controlDirectionRelayV1, RecordTypeOperationAckV1)
	if firstHeader.Epoch == retryHeader.Epoch && firstHeader.Sequence == retryHeader.Sequence {
		t.Fatal("Ack retry reused its control nonce coordinates")
	}
	if err := channel.openRelayAckV1(retry); err != nil || client.state.life.sendCompleted != 1 {
		t.Fatalf("Ack retry convergence sends=%d err=%v", client.state.life.sendCompleted, err)
	}
	if err := channel.openRelayAckV1(first); err == nil || client.state.life.sendCompleted != 1 {
		t.Fatalf("late Ack committed twice err=%v sends=%d", err, client.state.life.sendCompleted)
	}
}

func TestRuntimeNonceCompositionBothDirectionsV1(t *testing.T) {
	_, _, _, channel := newProtectedChannelV1(t, 7842, "message_lifetime_bound", 8)
	clientRecord, _, err := channel.sealClientApplicationV1(1, []byte("client"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := channel.openClientApplicationV1(clientRecord); err != nil {
		t.Fatal(err)
	}
	relayRecord, _, err := channel.sealRelayApplicationV1(2, []byte("relay"))
	if err != nil {
		t.Fatal(err)
	}
	if delivered, _, err := channel.openRelayApplicationV1(relayRecord); err != nil || string(delivered) != "relay" {
		t.Fatalf("relay delivery=%q err=%v", delivered, err)
	}
	if summary := channel.nonceSummaryV1(); summary.Allocations != 2 || summary.Collisions != 0 {
		t.Fatalf("bidirectional nonce summary=%+v", summary)
	}
}

func TestProtectedChannelProfileGenerationClosesBeforeOpenAndRekeyV1(t *testing.T) {
	t.Run("open", func(t *testing.T) {
		owner, client, relay, channel := newProtectedChannelV1(t, 7843, "profile_lifetime_bound", 8)
		record, _, err := channel.sealClientApplicationV1(1, []byte("stale-open"))
		if err != nil {
			t.Fatal(err)
		}
		owner.profileMu.Lock()
		owner.profileGeneration++
		owner.profileMu.Unlock()
		if _, _, err := channel.openClientApplicationV1(record); !errors.Is(err, ErrProfileRotationRequired) {
			t.Fatalf("stale open err=%v", err)
		}
		if client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
			t.Fatal("stale open did not close pair")
		}
	})
	t.Run("rekey", func(t *testing.T) {
		owner, client, relay, channel := newProtectedChannelV1(t, 7844, "profile_lifetime_bound", 1)
		record, _, err := channel.sealClientApplicationV1(1, []byte("first"))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := channel.openClientApplicationV1(record); err != nil {
			t.Fatal(err)
		}
		owner.profileMu.Lock()
		owner.profileGeneration++
		owner.profileMu.Unlock()
		if _, _, err := channel.sealClientApplicationV1(1, []byte("rekey")); !errors.Is(err, ErrProfileRotationRequired) {
			t.Fatalf("stale rekey err=%v", err)
		}
		if client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
			t.Fatal("stale rekey did not close pair")
		}
	})
}

func TestProtectedChannelConcurrentCloseAndRestartV1(t *testing.T) {
	t.Run("endpoint-close", func(t *testing.T) {
		_, client, _, channel := newProtectedChannelV1(t, 7845, "message_lifetime_bound", 8)
		record, _, err := channel.sealClientApplicationV1(1, []byte("close-race"))
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _, _ = channel.openClientApplicationV1(record) }()
		go func() { defer wg.Done(); client.Close() }()
		wg.Wait()
	})

	t.Run("explicit-restart", func(t *testing.T) {
		fixture := newLifecycleFixtureV1(t, 7846, "message_lifetime_bound", 8, 8)
		owner := lifecycleRuntimeV1(t, fixture)
		input := lifecyclePairInputV1(t, fixture)
		client, relay, err := owner.NewAuthenticatedChannelPair(input)
		if err != nil {
			t.Fatal(err)
		}
		channel, err := newStrictProtectedChannelV1(client, relay)
		if err != nil {
			t.Fatal(err)
		}
		record, _, err := channel.sealClientApplicationV1(1, []byte("restart-race"))
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _, _ = channel.openClientApplicationV1(record) }()
		go func() {
			defer wg.Done()
			fresh, freshClient, freshRelay, _ := owner.restartAuthenticatedChannelPairV1(client, relay, input)
			if freshClient != nil {
				freshClient.Close()
			}
			_ = fresh
			_ = freshRelay
		}()
		wg.Wait()
	})
}

func TestRuntimeNonceCompositionExplicitRestartObserverV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7847, "message_lifetime_bound", 8, 8)
	owner := lifecycleRuntimeV1(t, fixture)
	input := lifecyclePairInputV1(t, fixture)
	client, relay, err := owner.NewAuthenticatedChannelPair(input)
	if err != nil {
		t.Fatal(err)
	}
	observer := &strictNonceObserverV1{seen: make(map[strictNonceObservationV1]struct{}), domains: make(map[uint8]struct{})}
	first, err := newStrictProtectedChannelWithObserverV1(client, relay, observer)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.sealClientApplicationV1(1, []byte("before-restart")); err != nil {
		t.Fatal(err)
	}
	fresh, freshClient, freshRelay, err := owner.restartAuthenticatedChannelPairV1(client, relay, input)
	if err != nil {
		t.Fatal(err)
	}
	defer freshClient.Close()
	second, err := newStrictProtectedChannelWithObserverV1(freshClient, freshRelay, observer)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := second.sealClientApplicationV1(1, []byte("after-restart")); err != nil {
		t.Fatal(err)
	}
	if summary := second.nonceSummaryV1(); summary.Allocations != 2 || summary.Collisions != 0 {
		t.Fatalf("restart observer=%+v fresh=%v", summary, fresh != nil)
	}
}

func TestProtectedChannelPublicationGateRejectsConcurrentCloseV1(t *testing.T) {
	for _, kind := range []string{"application", "Ack", "Close"} {
		t.Run(kind, func(t *testing.T) {
			_, client, _, channel := newProtectedChannelV1(t, 7860+int64(len(kind)), "message_lifetime_bound", 8)
			var operationID [32]byte
			if kind == "Ack" {
				record, id, err := channel.sealClientApplicationV1(1, []byte("prepare-Ack"))
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := channel.openClientApplicationV1(record); err != nil {
					t.Fatal(err)
				}
				operationID = id
			}
			channel.beforePublish = func() {
				channel.beforePublish = nil
				client.Close()
			}
			var record []byte
			var err error
			switch kind {
			case "application":
				record, _, err = channel.sealClientApplicationV1(1, []byte("half-open"))
			case "Ack":
				record, err = channel.sealRelayAckV1(operationID, false)
			case "Close":
				record, err = channel.sealClientCloseV1()
			}
			if err == nil || record != nil {
				t.Fatalf("retired %s exposed record=%x err=%v", kind, record, err)
			}
		})
	}
}

func TestProtectedChannelPublicationGateRejectsConcurrentRestartV1(t *testing.T) {
	for _, kind := range []string{"application", "Ack", "Close"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newLifecycleFixtureV1(t, 7870+int64(len(kind)), "message_lifetime_bound", 16, 8)
			owner := lifecycleRuntimeV1(t, fixture)
			input := lifecyclePairInputV1(t, fixture)
			client, relay, err := owner.NewAuthenticatedChannelPair(input)
			if err != nil {
				t.Fatal(err)
			}
			channel, err := newStrictProtectedChannelV1(client, relay)
			if err != nil {
				t.Fatal(err)
			}
			var operationID [32]byte
			if kind == "Ack" {
				record, id, err := channel.sealClientApplicationV1(1, []byte("prepare-restart-Ack"))
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := channel.openClientApplicationV1(record); err != nil {
					t.Fatal(err)
				}
				operationID = id
			}
			var freshClient *ClientAuthenticatedEndpointV1
			var freshRelay *RelayAuthenticatedEndpointV1
			var restartErr error
			channel.beforePublish = func() {
				channel.beforePublish = nil
				_, freshClient, freshRelay, restartErr = owner.restartAuthenticatedChannelPairV1(client, relay, input)
			}
			var oldRecord []byte
			switch kind {
			case "application":
				oldRecord, _, err = channel.sealClientApplicationV1(1, []byte("retired-application"))
			case "Ack":
				oldRecord, err = channel.sealRelayAckV1(operationID, false)
			case "Close":
				oldRecord, err = channel.sealClientCloseV1()
			}
			if restartErr != nil || freshClient == nil || freshRelay == nil {
				t.Fatalf("restart %s fresh=%v/%v err=%v", kind, freshClient, freshRelay, restartErr)
			}
			defer freshClient.Close()
			if err == nil || oldRecord != nil {
				t.Fatalf("restarted %s exposed old record=%x err=%v", kind, oldRecord, err)
			}
			freshChannel, err := newStrictProtectedChannelV1(freshClient, freshRelay)
			if err != nil {
				t.Fatal(err)
			}
			freshRecord, _, err := freshChannel.sealClientApplicationV1(1, []byte("fresh-isolated"))
			if err != nil {
				t.Fatal(err)
			}
			if delivered, _, err := freshChannel.openClientApplicationV1(freshRecord); err != nil || string(delivered) != "fresh-isolated" {
				t.Fatalf("fresh pair after %s delivery=%q err=%v", kind, delivered, err)
			}
		})
	}
}

func TestProtectedChannelCandidateCallPathV1(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(strings.Replace(filename, "protected_channel_test.go", "protected_channel.go", 1))
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, forbidden := range []string{".OpenApplicationV1(", ".OpenControlV1(", "postAuthenticationCommitV1", "commitAuthenticatedOperationAckV1", "NewSecureChannel(", "RunAdapterBoundary(", "NewRuntime(", "NewManager(", "NewSession(", "NewStreamManager("} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("strict candidate calls forbidden path %s", forbidden)
		}
	}
	typeOf := reflect.TypeOf(strictProtectedChannelV1{})
	for i := 0; i < typeOf.NumField(); i++ {
		if typeOf.Field(i).PkgPath == "" {
			t.Fatalf("strict channel exported field %s", typeOf.Field(i).Name)
		}
	}
}
