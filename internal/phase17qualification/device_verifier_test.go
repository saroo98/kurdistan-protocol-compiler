// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package phase17qualification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// EV-14: this oracle does not call ComputeDeviceEvidence, SignDeviceTerminal,
// deviceDigest, signatureMessage or the canonical serializer to construct its
// expected result/ledger. The fixed synthetic input is the same received fixture;
// the expected conclusions, JSON field order and signature domain are literal.
// Standard SHA-256 and Ed25519 are the independent cryptographic primitives.
func TestDeviceTerminalIndependentLiteralGoldenPassAndFail(t *testing.T) {
	for _, test := range []struct{ outcome, raw, head, result, ledger string }{
		{"PASS", "2819a41736d0fad5f7e0fca38c3356c7ab3398f93aad94e4b51546f40aa34028", "6fc6aaf50a489fcfedbf545bed160770a1adb847e3892a02ea77a506ab5fec21", "28c2a82ecb43596f3805216416f9f84f1318bd6a0b552f69b9f357d06eb273b1", "362c53aed41d8202075f7eff420257b7bb6bd8c858caff902fe46a65cee037d1"},
		{"FAIL", "78c87709d003eb803f57d60991966a3cd3ed9c0cd16a8d9e669d9d7841826d6e", "92257098a7b8d0a6a9de8f7d61216d4139dc7ae4722411437e76ca7427909586", "6efa11c1a90dcd5c8bb6844a5d3cf5c439dc3b27f0269fba2aa75967e0a9af3b", "706d41ccd400e796e126daf23abd09dbaff63466b6cc80db51c5b40fc045930c"},
	} {
		t.Run(test.outcome, func(t *testing.T) {
			f := newDeviceFixture(t)
			if test.outcome == "FAIL" {
				for i, event := range f.events {
					if packet, ok := event.fact.(DevicePacketFact); ok {
						packet.DestinationRole = "CONTROLLED_PROBE"
						f.events[i].fact = packet
					}
				}
			}
			evidence := f.evidence(t)
			hash := func(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
			// No map sorting or reordering of the signed received sequence.
			received := make([][]byte, len(evidence.Received))
			for i, raw := range evidence.Received {
				received[i] = raw
			}
			rawInput := []byte(fmt.Sprintf(`{"schema":"kurdistan-phase17-device-raw-v1","subjectSha256":%q,"authorizationSha256":%q,"received":[%s]}`,
				f.auth.SubjectSHA256, f.authorizationDigest, bytes.Join(received, []byte(","))))
			rawDigest := hash(rawInput)
			headDigest := hash(evidence.Received[len(evidence.Received)-1])
			subjectJSON, err := json.Marshal(f.subject)
			if err != nil {
				t.Fatal(err)
			}
			failures, missing := `[]`, `[]`
			tiers := `[{"tier":"CONTROLLED_PROBE","outcome":"PASS","missing":[]},{"tier":"ROUTE_TUN","outcome":"PASS","missing":[]},{"tier":"DNS_TRANSACTION","outcome":"INCOMPLETE","missing":["REQUIRED_RAW_OBSERVATIONS_MISSING"]},{"tier":"PER_UID","outcome":"INCOMPLETE","missing":["PRIVILEGED_PER_PACKET_ATTRIBUTION_UNAVAILABLE"]},{"tier":"DEVICE_WIDE","outcome":"INCOMPLETE","missing":["PRIVILEGED_PER_PACKET_ATTRIBUTION_UNAVAILABLE"]}]`
			if test.outcome == "FAIL" {
				failures = `["DIRECT_OR_UNEXPECTED_EGRESS"]`
				missing = `["AUTHORIZED_TIER_INCOMPLETE"]`
				tiers = `[{"tier":"CONTROLLED_PROBE","outcome":"FAIL","missing":[]},{"tier":"ROUTE_TUN","outcome":"FAIL","missing":[]},{"tier":"DNS_TRANSACTION","outcome":"FAIL","missing":[]},{"tier":"PER_UID","outcome":"INCOMPLETE","missing":["PRIVILEGED_PER_PACKET_ATTRIBUTION_UNAVAILABLE"]},{"tier":"DEVICE_WIDE","outcome":"INCOMPLETE","missing":["PRIVILEGED_PER_PACKET_ATTRIBUTION_UNAVAILABLE"]}]`
			}
			expectedResult := []byte(fmt.Sprintf(`{"schema":"kurdistan-phase17-device-verifier-result-v1","verifierVersion":"phase17-device-core-1","subject":%s,"subjectSha256":%q,"authorizationSha256":%q,"invocationId":"00000000000000000000000000000002","journeyId":"FIXTURE_CORE","bootId":"00000000000000000000000000000003","sessionId":"00000000000000000000000000000004","provenance":"SYNTHETIC","requiredTiers":["CONTROLLED_PROBE","ROUTE_TUN"],"rawEvidenceSha256":%q,"receivedHeadSha256":%q,"firstReceivedMonoMs":111,"lastReceivedMonoMs":301,"outcome":%q,"processDeaths":[],"failures":%s,"missing":%s,"tiers":%s}`,
				subjectJSON, f.auth.SubjectSHA256, f.authorizationDigest, rawDigest, headDigest, test.outcome, failures, missing, tiers))
			resultDigest := hash(expectedResult)
			terminal := []byte(fmt.Sprintf(`{"schema":"kurdistan-phase17-device-terminal-v1","subjectSha256":%q,"authorizationSha256":%q,"invocationId":"00000000000000000000000000000002","journeyId":"FIXTURE_CORE","bootId":"00000000000000000000000000000003","sessionId":"00000000000000000000000000000004","rawEvidenceSha256":%q,"receivedHeadSha256":%q,"verifierVersion":"phase17-device-core-1","resultSha256":%q,"outcome":%q,"terminalMonoMs":9000}`,
				f.auth.SubjectSHA256, f.authorizationDigest, rawDigest, headDigest, resultDigest, test.outcome))
			message := append([]byte("KURDISTAN-PHASE17-QUALIFICATION-V1\x00DEVICE_TERMINAL\x00"), terminal...)
			private := ed25519.PrivateKey(f.keys["LEDGER"])
			signature := ed25519.Sign(private, message)
			ledger := []byte(fmt.Sprintf(`{"schema":"kurdistan-phase17-qualification-envelope-v1","statementType":"DEVICE_TERMINAL","keyId":%q,"payload":%s,"signature":%q}`,
				hash(private.Public().(ed25519.PublicKey)), terminal, hex.EncodeToString(signature)))
			if rawDigest != test.raw || headDigest != test.head || resultDigest != test.result || hash(ledger) != test.ledger {
				t.Fatalf("independent literal vector mismatch: raw=%s head=%s result=%s ledger=%s", rawDigest, headDigest, resultDigest, hash(ledger))
			}
			evidence.Terminal = ledger
			encoded, err := json.Marshal(evidence)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := VerifyDeviceEvidence(encoded, f.subject, f.trust)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := json.Marshal(verified.Result())
			if err != nil || !bytes.Equal(expectedResult, actual) || verified.ResultSHA256() != test.result {
				t.Fatal("verifier disagrees with independent fixed result and terminal")
			}
			if verified.AllowsOperationalTier("CONTROLLED_PROBE") {
				t.Fatal("synthetic golden opened operational gate")
			}
		})
	}
}

type deviceFixtureEvent struct {
	role, kind string
	fact       any
}

func TestDeviceServiceActionRequiresOSObservationAndExactInstalledComponent(t *testing.T) {
	f := newDeviceFixture(t)
	vpn := f.events[2].fact.(DeviceProcess)
	fact := DeviceServiceFact{Process: vpn, Component: f.subject.AppPackage + "/org.kurdistanvpn.runtime.android.KurdVpnService",
		Method: "ON_START_COMMAND", Action: "android.net.VpnService", StartID: 1, CallerUID: 1000,
		Flags: 0, DispatchID: deviceID(201), Marker: "ABSENT"}
	encoded := deviceBytes(t, fact)
	decoded, err := decodeDeviceFact("SERVICE", encoded)
	if err != nil || !deviceRoleAllows("OS", "SERVICE", decoded) {
		t.Fatal("bounded OS lifecycle observation rejected")
	}
	for _, role := range []string{"DEFAULT", "VPN", "HOST", "CONTROLLER", "GATEWAY"} {
		if deviceRoleAllows(role, "SERVICE", decoded) {
			t.Fatal("non-OS observer supplied service action")
		}
	}
	f.events = append(f.events[:3], append([]deviceFixtureEvent{{"OS", "SERVICE", fact}}, f.events[3:]...)...)
	computed, err := ComputeDeviceEvidence(f.evidence(t), f.subject, f.trust)
	if err != nil || computed.verification.result.Outcome != "PASS" {
		t.Fatalf("coherent observation rejected: %v", err)
	}
	bad := fact
	bad.Component = "org.synthetic.unrelated/Service"
	f.events[3].fact = bad
	computed, err = ComputeDeviceEvidence(f.evidence(t), f.subject, f.trust)
	if err != nil || !containsExact(computed.verification.result.Failures, "SERVICE_IDENTITY_MISMATCH") {
		t.Fatal("wrong installed component accepted")
	}
	bad = fact
	bad.Process.Epoch = deviceID(202)
	f.events[3].fact = bad
	computed, err = ComputeDeviceEvidence(f.evidence(t), f.subject, f.trust)
	if err != nil || !containsExact(computed.verification.result.Failures, "SERVICE_PROCESS_NOT_PRESENT") {
		t.Fatal("wrong epoch accepted")
	}
}

type deviceFixture struct {
	subject             DeviceEvidenceSubject
	manifest            []byte
	keys                map[string][]byte
	roster              []DeviceObserverKey
	trust               DeviceEvidenceTrust
	auth                DeviceAuthorization
	authorization       []byte
	authorizationDigest string
	events              []deviceFixtureEvent
}

func deviceID(n int) string { return fmt.Sprintf("%032x", n) }
func deviceBytes(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := MarshalCanonical(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func newDeviceFixture(t *testing.T) *deviceFixture {
	t.Helper()
	root := t.TempDir()
	subjects := []SubjectManifest{}
	for _, name := range []string{"PQS", "QHS", "QWS", "OVS"} {
		paths := []string{name + "/fixture.bin"}
		if name == "PQS" {
			paths = []string{"PQS/app.apk", "PQS/test.apk"}
		}
		for _, path := range paths {
			writeSubjectFixture(t, root, path, "SYNTHETIC "+path)
		}
		subject, err := BuildSubjectManifest(name, root, paths)
		if err != nil {
			t.Fatal(err)
		}
		subjects = append(subjects, subject)
	}
	source := SourceProvenance{"owner/repository", strings.Repeat("1", 40), strings.Repeat("2", 40), strings.Repeat("3", 40), strings.Repeat("4", 64), strings.Repeat("5", 64), strings.Repeat("6", 64)}
	manifest, err := NewCandidateManifest(source, strings.Repeat("7", 64), subjects)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalCandidateManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := CandidateIdentityFromManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	f := &deviceFixture{manifest: raw, keys: map[string][]byte{}, roster: []DeviceObserverKey{}, events: []deviceFixtureEvent{}}
	f.subject = DeviceEvidenceSubject{candidate, deviceDigest(raw), "org.kurdistanvpn", "org.kurdistanvpn.test", subjects[0].Entries[0], subjects[0].Entries[1], strings.Repeat("8", 64), strings.Repeat("9", 64), deviceID(1), 1000, 1}
	roles := []string{"CONTROLLER", "CUSTODY", "LEDGER", "HOST", "OS", "DEFAULT", "VPN", "GATEWAY", "REMOTE", "DNS"}
	for index, role := range roles {
		private, public := receiptKeyPair(byte(index + 101))
		f.keys[role] = private
		f.roster = append(f.roster, DeviceObserverKey{role, public, deviceID(2)})
	}
	f.auth = DeviceAuthorization{Schema: DeviceAuthorizationSchema, SubjectSHA256: deviceDigest(deviceBytes(t, f.subject)), InvocationID: deviceID(2), JourneyID: "FIXTURE_CORE", BootID: deviceID(3), SessionID: deviceID(4), IssuedAt: "2026-08-26T12:00:00Z", IssuedMonoMS: 90, ControllerSequence: 1, StartMonoMS: 100, EndMonoMS: 10000, Provenance: "SYNTHETIC", Egress: []DeviceEgress{{deviceID(5), 4, "WIFI", true}}, RequiredTiers: []string{"CONTROLLED_PROBE", "ROUTE_TUN"}, Calibrations: []DeviceCalibration{}}
	for index, role := range roles[3:] {
		id, _ := KeyID(f.roster[index+3].PublicKey)
		clock := DeviceClockReceipt{DeviceClockSchema, f.auth.SubjectSHA256, f.auth.InvocationID, f.auth.SessionID, deviceID(index + 10), deviceID(index + 30), 100}
		signed, err := SignDeviceClock(f.keys[role], clock)
		if err != nil {
			t.Fatal(err)
		}
		f.auth.Calibrations = append(f.auth.Calibrations, DeviceCalibration{id, clock.ObserverBootID, 100, 100, 0, signed})
	}
	f.trust, err = NewSyntheticDeviceEvidenceTrust(raw, f.roster)
	if err != nil {
		t.Fatal(err)
	}
	f.authorize(t)
	def := DeviceProcess{"DEFAULT", f.subject.AppPackage, 1000, 101, 1, deviceID(50), "PRESENT"}
	vpn := DeviceProcess{"VPN", f.subject.AppPackage + ":vpn", 1000, 102, 2, deviceID(51), "PRESENT"}
	add := func(role, kind string, fact any) { f.events = append(f.events, deviceFixtureEvent{role, kind, fact}) }
	s := f.subject
	add("OS", "INSTALL", DeviceInstallFact{s.InstallID, s.AppPackage, s.TestPackage, s.AppAPK.SHA256, s.TestAPK.SHA256, s.AppCertificateSHA256, s.TestCertificateSHA256, s.AppUID, s.VersionCode})
	add("HOST", "PROCESS", def)
	add("HOST", "PROCESS", vpn)
	add("OS", "EGRESS", DeviceEgressInventory{"BEFORE", f.auth.Egress})
	add("GATEWAY", "CAPTURE", DeviceCaptureFact{CaptureID: deviceID(52), EgressID: deviceID(5), Family: 4, Stage: "OPEN", InterfaceRevision: 1})
	runtime := DeviceRuntimeFact{Process: def, VPNEpoch: vpn.Epoch, RequestID: deviceID(53), Generation: 1, Revision: 2, CapabilityChannelID: deviceID(54), FrameChannelID: deviceID(55), DescriptorID: deviceID(56)}
	for _, step := range []struct{ role, stage, purpose string }{{"DEFAULT", "REQUEST", "FULL_AUTHORITY"}, {"DEFAULT", "REVISION_READ", "PRE_DESCRIPTOR"}, {"DEFAULT", "DESCRIPTOR_WRITE", "FULL_AUTHORITY"}, {"VPN", "ADMIT", "FULL_AUTHORITY"}, {"VPN", "NATIVE_AUTHENTICATED", "FULL_AUTHORITY"}, {"DEFAULT", "REVISION_READ", "PRE_ACTIVE"}, {"VPN", "ACTIVE", "FULL_AUTHORITY"}} {
		event := runtime
		event.Stage = step.stage
		event.Purpose = step.purpose
		if step.role == "VPN" {
			event.Process = vpn
		}
		if step.stage == "NATIVE_AUTHENTICATED" || step.stage == "ACTIVE" {
			event.NativeSessionID = deviceID(57)
			event.VPNSessionID = deviceID(58)
			event.TunID = deviceID(59)
		}
		add(step.role, "RUNTIME", event)
	}
	add("OS", "TUN", DeviceTunFact{Process: vpn, TunID: deviceID(59), InterfaceID: deviceID(60), MTU: 1280, State: "PRESENT"})
	route := DeviceRouteFact{vpn, deviceID(59), deviceID(60), 4, "BEFORE", "0.0.0.0/0", 1280, []string{"10.0.0.2/32"}, []string{"APP_UID_TUN"}, []uint64{}, []uint64{}}
	add("OS", "ROUTE", route)
	add("GATEWAY", "PACKET", DevicePacketFact{deviceID(52), deviceID(5), 4, 1, "OUTBOUND", "UDP", "TUNNEL_GATEWAY", 128, deviceID(61), deviceID(62), deviceID(57), deviceID(63), ""})
	probe := DeviceProbeFact{deviceID(61), deviceID(62), deviceID(57), deviceID(63), 4, "UDP", "RECEIVED", 64}
	add("REMOTE", "PROBE", probe)
	probe.Stage = "RESPONDED"
	add("REMOTE", "PROBE", probe)
	route.Stage = "AFTER"
	add("OS", "ROUTE", route)
	add("OS", "EGRESS", DeviceEgressInventory{"AFTER", f.auth.Egress})
	add("GATEWAY", "CAPTURE", DeviceCaptureFact{CaptureID: deviceID(52), EgressID: deviceID(5), Family: 4, Stage: "CLOSE", PacketCount: 1, InterfaceRevision: 1})
	return f
}
func (f *deviceFixture) authorize(t *testing.T) {
	t.Helper()
	var err error
	f.authorization, err = SignDeviceAuthorization(f.keys["CONTROLLER"], f.auth)
	if err != nil {
		t.Fatal(err)
	}
	f.authorizationDigest = deviceDigest(f.authorization)
}
func (f *deviceFixture) evidence(t *testing.T) DeviceEvidence {
	t.Helper()
	result := DeviceEvidence{DeviceEvidenceSchema, f.subject, f.authorization, []json.RawMessage{}, json.RawMessage("null")}
	sequences := map[string]uint64{}
	previous := ""
	for index, event := range f.events {
		sequences[event.role]++
		observation := DeviceObservation{Schema: DeviceObservationSchema, ContextSHA256: f.authorizationDigest, ObserverSequence: sequences[event.role], ObservedMonoMS: uint64(110 + index*10), EventType: event.kind, Data: deviceBytes(t, event.fact)}
		for keyIndex, key := range f.roster {
			if key.Role == event.role {
				observation.ObserverBootID = deviceID(keyIndex + 7)
				id, _ := KeyID(key.PublicKey)
				for _, clock := range f.auth.Calibrations {
					if clock.KeyID == id {
						observation.ObserverBootID = clock.ObserverBootID
					}
				}
			}
		}
		raw, err := SignDeviceObservation(f.keys[event.role], observation)
		if err != nil {
			t.Fatal(err)
		}
		received := DeviceReceived{DeviceReceivedSchema, f.authorizationDigest, uint64(index + 1), previous, f.auth.BootID, observation.ObservedMonoMS + 1, raw}
		signed, err := SignDeviceReceived(f.keys["CUSTODY"], received)
		if err != nil {
			t.Fatal(err)
		}
		result.Received = append(result.Received, signed)
		previous = deviceDigest(signed)
	}
	return result
}
func (f *deviceFixture) bundle(t *testing.T) []byte {
	t.Helper()
	evidence := f.evidence(t)
	computed, err := ComputeDeviceEvidence(evidence, f.subject, f.trust)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Terminal, err = SignDeviceTerminal(f.keys["LEDGER"], computed, 9000)
	if err != nil {
		t.Fatal(err)
	}
	return deviceBytes(t, evidence)
}
func TestDeviceVerifierDerivesSyntheticTiersButCannotOpenGate(t *testing.T) {
	f := newDeviceFixture(t)
	verified, err := VerifyDeviceEvidence(f.bundle(t), f.subject, f.trust)
	if err != nil {
		t.Fatal(err)
	}
	result := verified.Result()
	if result.Outcome != "PASS" {
		t.Fatalf("outcome=%s missing=%v failures=%v tiers=%v", result.Outcome, result.Missing, result.Failures, result.Tiers)
	}
	if verified.AllowsOperationalTier("CONTROLLED_PROBE") || (DeviceVerification{}).AllowsOperationalTier("CONTROLLED_PROBE") {
		t.Fatal("synthetic/zero opened gate")
	}
	if result.Tiers[3].Outcome != "INCOMPLETE" || result.Tiers[4].Outcome != "INCOMPLETE" {
		t.Fatal("gateway capture promoted to per-UID/device-wide")
	}
	result.Tiers[0].Outcome = "FAIL"
	if verified.Result().Tiers[0].Outcome != "PASS" {
		t.Fatal("result escaped mutable ownership")
	}
	if verified.ResultSHA256() != deviceDigest(deviceBytes(t, verified.Result())) {
		t.Fatal("result digest not recomputed")
	}
}
func TestDeviceVerifierSignedContradictionProducesBoundFailTerminal(t *testing.T) {
	f := newDeviceFixture(t)
	for i, event := range f.events {
		if p, ok := event.fact.(DevicePacketFact); ok {
			p.DestinationRole = "CONTROLLED_PROBE"
			f.events[i].fact = p
		}
	}
	verified, err := VerifyDeviceEvidence(f.bundle(t), f.subject, f.trust)
	if err != nil {
		t.Fatal(err)
	}
	r := verified.Result()
	if r.Outcome != "FAIL" || !containsExact(r.Failures, "DIRECT_OR_UNEXPECTED_EGRESS") || verified.ResultSHA256() != deviceDigest(deviceBytes(t, r)) {
		t.Fatalf("contradiction not bound: %+v", r)
	}
}
func TestDeviceVerifierRejectsReceivedReorderAndForgedTerminalDigest(t *testing.T) {
	f := newDeviceFixture(t)
	original := f.bundle(t)
	for _, mutation := range []string{"order", "result", "raw", "outcome", "signature", "subject"} {
		t.Run(mutation, func(t *testing.T) {
			evidence, err := DecodeDeviceEvidence(bytes.NewReader(original))
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "order":
				evidence.Received[0], evidence.Received[1] = evidence.Received[1], evidence.Received[0]
			case "subject":
				evidence.Subject.InstallID = deviceID(999)
			default:
				var envelope Envelope
				_ = json.Unmarshal(evidence.Terminal, &envelope)
				var terminal DeviceTerminal
				_ = json.Unmarshal(envelope.Payload, &terminal)
				if mutation == "result" {
					terminal.ResultSHA256 = strings.Repeat("0", 64)
				}
				if mutation == "raw" {
					terminal.RawEvidenceSHA256 = strings.Repeat("0", 64)
				}
				if mutation == "outcome" {
					terminal.Outcome = "FAIL"
				}
				evidence.Terminal, err = deviceSign(f.keys["LEDGER"], "DEVICE_TERMINAL", terminal)
				if err != nil {
					t.Fatal(err)
				}
				if mutation == "signature" {
					evidence.Terminal = bytes.Replace(evidence.Terminal, []byte(`"signature":"`), []byte(`"signature":"00`), 1)
				}
			}
			v, err := VerifyDeviceEvidence(deviceBytes(t, evidence), f.subject, f.trust)
			if err == nil || v.AllowsOperationalTier("CONTROLLED_PROBE") || v.Result().Outcome != "INCOMPLETE" {
				t.Fatal("tampered bundle accepted")
			}
		})
	}
}
func TestDeviceVerifierMissingCaptureAndRemoteReceiptCannotPass(t *testing.T) {
	for _, remove := range []string{"CAPTURE_CLOSE", "PROBE_RECEIVED", "PROBE_RESPONDED", "TUN", "ROUTE_AFTER"} {
		t.Run(remove, func(t *testing.T) {
			f := newDeviceFixture(t)
			kept := []deviceFixtureEvent{}
			for _, e := range f.events {
				kind := e.kind
				switch p := e.fact.(type) {
				case DeviceCaptureFact:
					kind += "_" + p.Stage
				case DeviceProbeFact:
					kind += "_" + p.Stage
				case DeviceRouteFact:
					kind += "_" + p.Stage
				}
				if kind != remove {
					kept = append(kept, e)
				}
			}
			f.events = kept
			v, err := VerifyDeviceEvidence(f.bundle(t), f.subject, f.trust)
			if err != nil {
				t.Fatal(err)
			}
			if v.Result().Outcome == "PASS" {
				t.Fatalf("missing %s passed", remove)
			}
		})
	}
}
func TestDeviceVerifierUnderspecifiedD01RemainsIncomplete(t *testing.T) {
	f := newDeviceFixture(t)
	f.auth.JourneyID = "D01"
	f.auth.Provenance = "AUTHORIZED_DEVICE"
	f.authorize(t)
	var err error
	f.trust, err = NewAuthorizedDeviceEvidenceTrust(f.manifest, f.roster)
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyDeviceEvidence(f.bundle(t), f.subject, f.trust)
	if err != nil {
		t.Fatal(err)
	}
	if !containsExact(v.Result().Missing, "D01_COLD_SERVICE_OBSERVATION_MISSING") || v.AllowsOperationalTier("CONTROLLED_PROBE") {
		t.Fatal("underspecified D01 opened gate")
	}
}

// D01 must be derived from signed OS/HOST/GATEWAY/REMOTE observations.  The
// DEFAULT/VPN runtime records are only correlation inputs, never the proof of
// cold service delivery or protected traffic.
func TestDeviceVerifierAuthorizedD01FullTracePassesAndMissingServiceStaysIncomplete(t *testing.T) {
	for _, test := range []struct {
		name           string
		includeService bool
		want           string
	}{
		{"complete", true, "PASS"},
		{"missing_service", false, "INCOMPLETE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newDeviceFixture(t)
			f.auth.JourneyID = "D01"
			f.auth.Provenance = "AUTHORIZED_DEVICE"
			if test.includeService {
				vpn := f.events[2].fact.(DeviceProcess)
				service := DeviceServiceFact{Process: vpn, Component: f.subject.AppPackage + "/org.kurdistanvpn.runtime.android.KurdVpnService",
					Method: "ON_START_COMMAND", Action: "android.net.VpnService", StartID: 1, CallerUID: 1000,
					Flags: 0, DispatchID: deviceID(201), Marker: "ABSENT"}
				cold := DeviceLifecycleFact{Action: "SERVICE_START", RequestID: deviceID(53), Process: vpn, CurrentBootID: f.auth.BootID}
				f.events = append(f.events[:3], append([]deviceFixtureEvent{{"OS", "SERVICE", service}, {"OS", "LIFECYCLE", cold}}, f.events[3:]...)...)
			}
			f.authorize(t)
			var err error
			f.trust, err = NewAuthorizedDeviceEvidenceTrust(f.manifest, f.roster)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := VerifyDeviceEvidence(f.bundle(t), f.subject, f.trust)
			if err != nil {
				t.Fatal(err)
			}
			if got := verified.Result().Outcome; got != test.want {
				t.Fatalf("outcome=%s missing=%v failures=%v", got, verified.Result().Missing, verified.Result().Failures)
			}
			if test.want == "PASS" && !verified.AllowsOperationalTier("CONTROLLED_PROBE") {
				t.Fatal("authorized D01 did not open its proven tier")
			}
		})
	}
}

func TestDeviceVerifierEveryOriginalJourneyRejectsAnUnderspecifiedTrace(t *testing.T) {
	for _, journey := range []string{"D01", "D02", "D03", "D04", "D05", "D06", "D07", "D08"} {
		t.Run(journey, func(t *testing.T) {
			f := newDeviceFixture(t)
			f.auth.JourneyID = journey
			f.auth.Provenance = "AUTHORIZED_DEVICE"
			f.authorize(t)
			var err error
			f.trust, err = NewAuthorizedDeviceEvidenceTrust(f.manifest, f.roster)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := VerifyDeviceEvidence(f.bundle(t), f.subject, f.trust)
			if err != nil {
				t.Fatal(err)
			}
			if verified.Result().Outcome != "INCOMPLETE" || verified.AllowsOperationalTier("CONTROLLED_PROBE") {
				t.Fatalf("underspecified %s opened gate: %+v", journey, verified.Result())
			}
		})
	}
}

func TestDeviceVerifierD04AndD08RequireEveryFixedControllerCaseBinding(t *testing.T) {
	for _, journey := range []string{"D04", "D08"} {
		t.Run(journey, func(t *testing.T) {
			f := newDeviceFixture(t)
			f.auth.JourneyID = journey
			f.auth.Provenance = "AUTHORIZED_DEVICE"
			f.authorize(t)
			trust, err := NewAuthorizedDeviceEvidenceTrust(f.manifest, f.roster)
			if err != nil {
				t.Fatal(err)
			}
			f.trust = trust
			verified, err := VerifyDeviceEvidence(f.bundle(t), f.subject, trust)
			if err != nil {
				t.Fatal(err)
			}
			if !containsExact(verified.Result().Missing, journey+"_CASE_MISSING_BINDING") {
				t.Fatalf("missing fixed-case admission marker: %v", verified.Result().Missing)
			}
		})
	}
}

func newDeviceCaseMatrixFixture(t *testing.T, journey string) *deviceFixture {
	t.Helper()
	f := newDeviceFixture(t)
	contracts := deviceD04Contracts
	if journey == "D08" {
		contracts = deviceD08Contracts
	}
	f.auth.JourneyID = journey
	f.auth.Provenance = "AUTHORIZED_DEVICE"
	f.auth.RequiredTiers = []string{"PER_UID"}
	instrumentationPrivate, instrumentationPublic := receiptKeyPair(121)
	f.keys["INSTRUMENTATION"] = instrumentationPrivate
	f.roster = append(f.roster, DeviceObserverKey{"INSTRUMENTATION", instrumentationPublic, f.auth.InvocationID})
	for index, role := range []string{"CONTROLLER", "INSTRUMENTATION"} {
		var public []byte
		for _, candidate := range f.roster {
			if candidate.Role == role {
				public = candidate.PublicKey
				break
			}
		}
		keyID, _ := KeyID(public)
		clock := DeviceClockReceipt{DeviceClockSchema, f.auth.SubjectSHA256, f.auth.InvocationID, f.auth.SessionID, deviceID(900 + index), deviceID(910 + index), 100}
		signed, err := SignDeviceClock(f.keys[role], clock)
		if err != nil {
			t.Fatal(err)
		}
		f.auth.Calibrations = append(f.auth.Calibrations, DeviceCalibration{keyID, clock.ObserverBootID, 100, 100, 0, signed})
	}
	def := f.events[1].fact.(DeviceProcess)
	vpn := f.events[2].fact.(DeviceProcess)
	f.events = append([]deviceFixtureEvent{}, f.events[:3]...)
	f.events = append(f.events, deviceFixtureEvent{"OS", "EGRESS", DeviceEgressInventory{"BEFORE", f.auth.Egress}})
	for index, contract := range contracts {
		base := 1000 + index*50
		requestID := deviceID(base)
		traceID := deviceID(base + 1)
		captureID := deviceID(base + 2)
		interfaceID := deviceID(base + 3)
		caseFact := DeviceCaseFact{CaseID: contract.ID, RequestID: requestID, FaultStage: contract.Stage, FaultMode: contract.Fault,
			FixtureSHA256: fmt.Sprintf("%064x", base+4), ActionSHA256: fmt.Sprintf("%064x", base+5)}
		f.events = append(f.events, deviceFixtureEvent{"CONTROLLER", "CASE", caseFact})
		action, marker := "android.net.VpnService", "ABSENT"
		if contract.ID == "D04_NULL_INTENT" {
			action = ""
		} else if contract.ID == "D04_UNKNOWN_ACTION" {
			action = "org.kurdistanvpn.action.UNKNOWN"
		} else if contract.ID == "D04_UNAUTHORIZED_MARKER" {
			marker = "MALFORMED"
		}
		service := DeviceCommandFact{CaseID: contract.ID, Process: vpn, RequestID: requestID, Component: f.subject.AppPackage + "/org.kurdistanvpn.runtime.android.KurdVpnService",
			Method: "ON_START_COMMAND", Action: action, StartID: uint64(index + 1), CallerUID: 1000, DispatchID: deviceID(base + 6), Marker: marker}
		f.events = append(f.events,
			deviceFixtureEvent{"OS", "COMMAND", service},
			deviceFixtureEvent{"OS", "LIFECYCLE", DeviceLifecycleFact{Action: "SERVICE_START", RequestID: requestID, Process: vpn, CurrentBootID: f.auth.BootID}},
			deviceFixtureEvent{"INSTRUMENTATION", "TRACE", DeviceTraceFact{CaseID: contract.ID, RequestID: requestID, TraceID: traceID, Process: vpn, Stage: "OPEN"}},
		)
		ordinal := uint64(1)
		f.events = append(f.events, deviceFixtureEvent{"INSTRUMENTATION", "BOUNDARY", DeviceBoundaryFact{CaseID: contract.ID, RequestID: requestID, TraceID: traceID, Process: vpn, Ordinal: ordinal, Stage: contract.Stage, Event: "ENTER", Code: "NONE"}})
		ordinal++
		resourceIDs := make([]string, 0, len(contract.Resources))
		for resourceIndex, kind := range contract.Resources {
			resourceID := deviceID(base + 10 + resourceIndex)
			resourceIDs = append(resourceIDs, resourceID)
			f.events = append(f.events, deviceFixtureEvent{"INSTRUMENTATION", "RESOURCE", DeviceResourceFact{CaseID: contract.ID, RequestID: requestID, TraceID: traceID, Process: vpn, Ordinal: ordinal, ResourceKind: kind, ResourceID: resourceID, Operation: "ACQUIRE"}})
			ordinal++
		}
		f.events = append(f.events, deviceFixtureEvent{"INSTRUMENTATION", "BOUNDARY", DeviceBoundaryFact{CaseID: contract.ID, RequestID: requestID, TraceID: traceID, Process: vpn, Ordinal: ordinal, Stage: contract.Stage, Event: contract.TerminalEvent, Code: contract.TerminalCode}})
		ordinal++
		for resourceIndex := len(contract.Resources) - 1; resourceIndex >= 0; resourceIndex-- {
			if contract.AllowsUnproven && resourceIndex == len(contract.Resources)-1 {
				continue
			}
			kind := contract.Resources[resourceIndex]
			operation := "CLOSE"
			if kind == "SENSITIVE_BUFFER" {
				operation = "WIPE"
			} else if containsExact([]string{"CALLBACK", "NOTIFICATION", "HEALTH_MONITOR"}, kind) {
				operation = "REMOVE"
			}
			f.events = append(f.events, deviceFixtureEvent{"INSTRUMENTATION", "RESOURCE", DeviceResourceFact{CaseID: contract.ID, RequestID: requestID, TraceID: traceID, Process: vpn, Ordinal: ordinal, ResourceKind: kind, ResourceID: resourceIDs[resourceIndex], Operation: operation}})
			ordinal++
		}
		f.events = append(f.events, deviceFixtureEvent{"INSTRUMENTATION", "TRACE", DeviceTraceFact{CaseID: contract.ID, RequestID: requestID, TraceID: traceID, Process: vpn, Stage: "CLOSE", EventCount: ordinal - 1}})
		if journey == "D08" {
			f.events = append(f.events, deviceFixtureEvent{"OS", "STATUS", DeviceStatusFact{CaseID: contract.ID, RequestID: requestID, Process: vpn, Surface: "FOREGROUND_NOTIFICATION", State: "CONNECTING", Identity: deviceID(base + 30)}})
		}
		terminalState := "ABSENT"
		if journey == "D08" {
			terminalState = "FAILED"
		}
		if contract.AllowsUnproven {
			terminalState = "CLEANUP_UNPROVEN"
		}
		f.events = append(f.events, deviceFixtureEvent{"OS", "STATUS", DeviceStatusFact{CaseID: contract.ID, RequestID: requestID, Process: vpn, Surface: "RUNTIME_PUBLICATION", State: terminalState, Identity: deviceID(base + 31)}})
		if contract.RequiresTunRemoval {
			tunID := deviceID(base + 33)
			f.events = append(f.events,
				deviceFixtureEvent{"OS", "TUN", DeviceTunFact{Process: vpn, TunID: tunID, InterfaceID: interfaceID, MTU: 1280, State: "PRESENT"}},
				deviceFixtureEvent{"OS", "STATUS", DeviceStatusFact{CaseID: contract.ID, RequestID: requestID, Process: vpn, Surface: "VPN_REGISTRATION", State: "ACTIVE", Identity: tunID}},
				deviceFixtureEvent{"OS", "LIFECYCLE", DeviceLifecycleFact{Action: "TUN_REMOVED", RequestID: requestID, Process: vpn, CurrentBootID: f.auth.BootID}},
				deviceFixtureEvent{"OS", "TUN", DeviceTunFact{Process: vpn, TunID: tunID, InterfaceID: interfaceID, MTU: 1280, State: "ABSENT"}},
				deviceFixtureEvent{"OS", "STATUS", DeviceStatusFact{CaseID: contract.ID, RequestID: requestID, Process: vpn, Surface: "VPN_REGISTRATION", State: "ABSENT", Identity: tunID}},
			)
		} else {
			f.events = append(f.events, deviceFixtureEvent{"OS", "STATUS", DeviceStatusFact{CaseID: contract.ID, RequestID: requestID, Process: vpn, Surface: "VPN_REGISTRATION", State: "ABSENT", Identity: deviceID(base + 32)}})
		}
		f.events = append(f.events,
			deviceFixtureEvent{"OS", "INTERFACE", DeviceInterfaceFact{InterfaceID: interfaceID, EgressID: deviceID(5), Family: 4, State: "PRESENT"}},
			deviceFixtureEvent{"OS", "ROUTE", DeviceRouteFact{Process: vpn, TunID: deviceID(base + 38), InterfaceID: interfaceID, Family: 4, Stage: "BEFORE", DestinationPrefix: "0.0.0.0/0", MTU: 1280, AddressPrefixes: []string{"10.0.0.2/32"}, PolicyRules: []string{"DENY_UID_SET"}, AllowedUIDs: []uint64{}, DisallowedUIDs: []uint64{f.subject.AppUID}}},
			deviceFixtureEvent{"GATEWAY", "CAPTURE", DeviceCaptureFact{CaptureID: captureID, EgressID: deviceID(5), Family: 4, Stage: "OPEN", InterfaceRevision: uint64(index + 2)}},
			deviceFixtureEvent{"OS", "FLOW", DeviceFlowFact{FlowID: deviceID(base + 34), RequestID: requestID, CaptureID: captureID, EgressID: deviceID(5), InterfaceID: interfaceID, Direction: "OUTBOUND", Protocol: "TCP", DestinationRole: "CONTROLLED_PROBE", CorrelationID: deviceID(base + 35), RouteRule: "DENY_UID_SET", RouteAction: "LOOKUP_DENY", UID: f.subject.AppUID, Family: 4}},
			deviceFixtureEvent{"OS", "FLOW", DeviceFlowFact{FlowID: deviceID(base + 36), RequestID: requestID, CaptureID: captureID, EgressID: deviceID(5), InterfaceID: interfaceID, Direction: "OUTBOUND", Protocol: "DNS", DestinationRole: "DIRECT_RESOLVER", CorrelationID: deviceID(base + 37), RouteRule: "DENY_UID_SET", RouteAction: "LOOKUP_DENY", UID: f.subject.AppUID, Family: 4}},
			deviceFixtureEvent{"GATEWAY", "CAPTURE", DeviceCaptureFact{CaptureID: captureID, EgressID: deviceID(5), Family: 4, Stage: "CLOSE", InterfaceRevision: uint64(index + 2)}},
		)
	}
	f.events = append(f.events, deviceFixtureEvent{"OS", "EGRESS", DeviceEgressInventory{"AFTER", f.auth.Egress}})
	f.authorize(t)
	var err error
	f.trust, err = NewAuthorizedDeviceEvidenceTrust(f.manifest, f.roster)
	if err != nil {
		t.Fatal(err)
	}
	_ = def
	return f
}

func TestDeviceVerifierD04AndD08DeriveOnlyFromCompleteRawCaseMatrices(t *testing.T) {
	for _, journey := range []string{"D04", "D08"} {
		t.Run(journey+"_complete", func(t *testing.T) {
			f := newDeviceCaseMatrixFixture(t, journey)
			verified, err := VerifyDeviceEvidence(f.bundle(t), f.subject, f.trust)
			if err != nil {
				t.Fatal(err)
			}
			if got := verified.Result().Outcome; got != "PASS" {
				t.Fatalf("outcome=%s missing=%v failures=%v", got, verified.Result().Missing, verified.Result().Failures)
			}
			if verified.Result().Tiers[3].Outcome != "PASS" {
				t.Fatalf("per-UID denial evidence did not pass: %+v", verified.Result().Tiers[3])
			}
		})
		t.Run(journey+"_missing_dns", func(t *testing.T) {
			f := newDeviceCaseMatrixFixture(t, journey)
			for i, event := range f.events {
				if flow, ok := event.fact.(DeviceFlowFact); ok && flow.Protocol == "DNS" {
					f.events = append(f.events[:i], f.events[i+1:]...)
					break
				}
			}
			verified, err := VerifyDeviceEvidence(f.bundle(t), f.subject, f.trust)
			if err != nil {
				t.Fatal(err)
			}
			if verified.Result().Outcome != "INCOMPLETE" || !containsExact(verified.Result().Missing, journey+"_TRAFFIC_DNS_OR_NO_DIRECT_FALLBACK_MISSING") {
				t.Fatalf("missing DNS route observation was accepted: %+v", verified.Result())
			}
		})
		t.Run(journey+"_active_contradiction", func(t *testing.T) {
			f := newDeviceCaseMatrixFixture(t, journey)
			for i, event := range f.events {
				if status, ok := event.fact.(DeviceStatusFact); ok && status.Surface == "RUNTIME_PUBLICATION" {
					status.State = "ACTIVE"
					f.events[i].fact = status
					break
				}
			}
			verified, err := VerifyDeviceEvidence(f.bundle(t), f.subject, f.trust)
			if err != nil {
				t.Fatal(err)
			}
			if verified.Result().Outcome != "FAIL" || !containsExact(verified.Result().Failures, journey+"_ACTIVE_PUBLISHED_FOR_FAILED_CASE") {
				t.Fatalf("ACTIVE contradiction was accepted: %+v", verified.Result())
			}
		})
	}
}
func TestDeviceVerifierWrongRoleCannotAssertHostProcess(t *testing.T) {
	f := newDeviceFixture(t)
	f.events[1].role = "DEFAULT"
	if _, err := ComputeDeviceEvidence(f.evidence(t), f.subject, f.trust); err == nil {
		t.Fatal("app signed host fact accepted")
	}
}
func (f *deviceFixture) addDNS() {
	tail := append([]deviceFixtureEvent{}, f.events[len(f.events)-3:]...)
	f.events = f.events[:len(f.events)-3]
	packet := DevicePacketFact{CaptureID: deviceID(52), EgressID: deviceID(5), Family: 4, Ordinal: 2, Direction: "OUTBOUND", Protocol: "UDP", DestinationRole: "TUNNEL_GATEWAY", Length: 160, NativeSessionID: deviceID(57), DNSTransactionID: deviceID(70)}
	query := DeviceDNSFact{deviceID(70), deviceID(71), 4, "OUTBOUND", "PROTECTED_RESOLVER", "UDP", "A", 0, 0, false, "NONE", deviceID(57), deviceID(52), deviceID(5), 2, "QUERY"}
	response := query
	response.Direction = "INBOUND"
	response.AnswerFamily = 4
	response.PacketOrdinal = 3
	response.Stage = "RESPONSE"
	f.events = append(f.events, deviceFixtureEvent{"GATEWAY", "PACKET", packet}, deviceFixtureEvent{"GATEWAY", "DNS", query}, deviceFixtureEvent{"DNS", "DNS_RECEIPT", response})
	packet.Ordinal = 3
	packet.Direction = "INBOUND"
	f.events = append(f.events, deviceFixtureEvent{"GATEWAY", "PACKET", packet}, deviceFixtureEvent{"GATEWAY", "DNS", response})
	close := tail[2].fact.(DeviceCaptureFact)
	close.PacketCount = 3
	tail[2].fact = close
	f.events = append(f.events, tail...)
	f.auth.RequiredTiers = append(f.auth.RequiredTiers, "DNS_TRANSACTION")
}
func TestDeviceVerifierDNSNeedsPacketsAndIndependentMatchingReceipt(t *testing.T) {
	for _, mutation := range []string{"valid", "missing_receipt", "invented_packet", "wrong_query", "direct", "fallback_claim"} {
		t.Run(mutation, func(t *testing.T) {
			f := newDeviceFixture(t)
			f.addDNS()
			f.authorize(t)
			kept := []deviceFixtureEvent{}
			for _, e := range f.events {
				if mutation == "missing_receipt" && e.kind == "DNS_RECEIPT" {
					continue
				}
				if p, ok := e.fact.(DeviceDNSFact); ok && e.kind == "DNS_RECEIPT" {
					switch mutation {
					case "invented_packet":
						p.PacketOrdinal = 99
					case "wrong_query":
						p.QueryToken = deviceID(99)
					case "direct":
						p.ResolverRole = "DIRECT_RESOLVER"
					case "fallback_claim":
						p.Truncated = true
						p.Fallback = "TCP_COMPLETED"
					}
					e.fact = p
				}
				kept = append(kept, e)
			}
			f.events = kept
			v, err := VerifyDeviceEvidence(f.bundle(t), f.subject, f.trust)
			if err != nil {
				t.Fatal(err)
			}
			if (v.Result().Outcome == "PASS") != (mutation == "valid") {
				t.Fatalf("%s outcome=%s missing=%v failures=%v", mutation, v.Result().Outcome, v.Result().Missing, v.Result().Failures)
			}
		})
	}
}
func TestDeviceVerifierProcessDeathRequiresExitIdentityAndChronologicalBirth(t *testing.T) {
	for _, mutation := range []string{"valid", "same_pid", "same_epoch", "older_birth", "wrong_uid", "missing_exit"} {
		t.Run(mutation, func(t *testing.T) {
			f := newDeviceFixture(t)
			old := f.events[1].fact.(DeviceProcess)
			exit := old
			exit.State = "ABSENT"
			born := old
			born.PID = 201
			born.StartTimeMS = 20
			born.Epoch = deviceID(201)
			switch mutation {
			case "same_pid":
				born.PID = old.PID
			case "same_epoch":
				born.Epoch = old.Epoch
			case "older_birth":
				born.StartTimeMS = old.StartTimeMS
			case "wrong_uid":
				born.UID++
			}
			if mutation != "missing_exit" {
				f.events = append(f.events, deviceFixtureEvent{"HOST", "PROCESS", exit})
			}
			f.events = append(f.events, deviceFixtureEvent{"HOST", "PROCESS", born})
			v, err := VerifyDeviceEvidence(f.bundle(t), f.subject, f.trust)
			if err != nil {
				t.Fatal(err)
			}
			r := v.Result()
			if mutation == "valid" {
				if !containsExact(r.ProcessDeaths, "DEFAULT") || r.Outcome != "INCOMPLETE" {
					t.Fatalf("valid death not derived: %+v", r)
				}
			} else if r.Outcome != "FAIL" {
				t.Fatalf("invalid death accepted: %+v", r)
			}
		})
	}
}
func TestDeviceVerifierGenerationIsEpochLocalAndSameCommittedRevisionIsAllowed(t *testing.T) {
	f := newDeviceFixture(t)
	old := f.events[2].fact.(DeviceProcess)
	exit := old
	exit.State = "ABSENT"
	born := old
	born.PID = 202
	born.StartTimeMS = 20
	born.Epoch = deviceID(202)
	f.events = append(f.events, deviceFixtureEvent{"HOST", "PROCESS", exit}, deviceFixtureEvent{"HOST", "PROCESS", born})
	originals := append([]deviceFixtureEvent{}, f.events...)
	for _, event := range originals {
		p, ok := event.fact.(DeviceRuntimeFact)
		if !ok {
			continue
		}
		p.VPNEpoch = born.Epoch
		p.RequestID = deviceID(203)
		p.CapabilityChannelID = deviceID(204)
		p.FrameChannelID = deviceID(205)
		p.DescriptorID = deviceID(206)
		if p.Process.Role == "VPN" {
			p.Process = born
		}
		if p.NativeSessionID != "" {
			p.NativeSessionID = deviceID(207)
			p.VPNSessionID = deviceID(208)
			p.TunID = deviceID(209)
		}
		f.events = append(f.events, deviceFixtureEvent{event.role, event.kind, p})
	}
	v, err := VerifyDeviceEvidence(f.bundle(t), f.subject, f.trust)
	if err != nil {
		t.Fatal(err)
	}
	r := v.Result()
	if len(r.Failures) != 0 || !containsExact(r.ProcessDeaths, "VPN") {
		t.Fatalf("epoch-local generation/same revision rejected: %v", r.Failures)
	}
	if r.Outcome != "INCOMPLETE" {
		t.Fatal("missing old-session teardown or fresh traffic passed")
	}
}
func TestDeviceVerifierLossRevisionRollbackAndAuthorityReuseFailClosed(t *testing.T) {
	for _, mutation := range []string{"loss", "install", "vpn_epoch", "authority", "revision", "sequence"} {
		t.Run(mutation, func(t *testing.T) {
			f := newDeviceFixture(t)
			for i, e := range f.events {
				switch p := e.fact.(type) {
				case DeviceCaptureFact:
					if mutation == "loss" && p.Stage == "CLOSE" {
						p.DropCount = 1
						f.events[i].fact = p
					}
				case DeviceInstallFact:
					if mutation == "install" {
						p.AppUID++
						f.events[i].fact = p
					}
				case DeviceRuntimeFact:
					if p.Stage == "ADMIT" {
						switch mutation {
						case "vpn_epoch":
							p.VPNEpoch = deviceID(900)
						case "authority":
							p.DescriptorID = deviceID(901)
						case "revision":
							p.Revision = 4
						}
						f.events[i].fact = p
					}
				}
			}
			if mutation == "sequence" {
				f.events = append(f.events, f.events[5])
			}
			v, err := VerifyDeviceEvidence(f.bundle(t), f.subject, f.trust)
			if err != nil {
				t.Fatal(err)
			}
			if v.Result().Outcome == "PASS" {
				t.Fatal("signed contradiction passed")
			}
		})
	}
}
func TestDeviceVerifierDigestIsStableAcrossRepeatedMapTraversal(t *testing.T) {
	f := newDeviceFixture(t)
	f.addDNS()
	f.auth.RequiredTiers = append(f.auth.RequiredTiers, "PER_UID")
	f.authorize(t)
	evidence := f.evidence(t)
	first := ""
	for i := 0; i < 30; i++ {
		c, err := ComputeDeviceEvidence(evidence, f.subject, f.trust)
		if err != nil {
			t.Fatal(err)
		}
		if first == "" {
			first = c.ResultSHA256()
		} else if first != c.ResultSHA256() {
			t.Fatal("noncanonical map-derived conclusion order")
		}
	}
}

func TestDeviceVerifierClockScopeAndCustodyReplayAreRejected(t *testing.T) {
	for _, mutation := range []string{"observer_boot", "future_observation", "wrong_invocation", "custody_replay", "missing_clock", "drift_overflow"} {
		t.Run(mutation, func(t *testing.T) {
			f := newDeviceFixture(t)
			if mutation == "wrong_invocation" {
				f.roster[3].InvocationID = deviceID(999)
				var err error
				f.trust, err = NewSyntheticDeviceEvidenceTrust(f.manifest, f.roster)
				if err != nil {
					t.Fatal(err)
				}
			}
			if mutation == "missing_clock" {
				f.auth.Calibrations = f.auth.Calibrations[1:]
				f.authorize(t)
			}
			if mutation == "drift_overflow" {
				f.auth.Calibrations[0].DriftPPM = 1001
				f.authorize(t)
			}
			evidence := f.evidence(t)
			if mutation == "observer_boot" || mutation == "future_observation" || mutation == "custody_replay" {
				var env Envelope
				_ = json.Unmarshal(evidence.Received[0], &env)
				var received DeviceReceived
				_ = json.Unmarshal(env.Payload, &received)
				if mutation == "custody_replay" {
					received.ReceivedSequence = 2
				} else {
					var observerEnvelope Envelope
					_ = json.Unmarshal(received.Observation, &observerEnvelope)
					var observation DeviceObservation
					_ = json.Unmarshal(observerEnvelope.Payload, &observation)
					if mutation == "observer_boot" {
						observation.ObserverBootID = deviceID(999)
					} else {
						observation.ObservedMonoMS = f.auth.EndMonoMS + 1
					}
					var err error
					received.Observation, err = SignDeviceObservation(f.keys["OS"], observation)
					if err != nil {
						t.Fatal(err)
					}
				}
				var err error
				evidence.Received[0], err = deviceSign(f.keys["CUSTODY"], "DEVICE_RECEIVED", received)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := ComputeDeviceEvidence(evidence, f.subject, f.trust); err == nil {
				t.Fatal("signed clock/custody contradiction accepted")
			}
		})
	}
}

func TestDeviceVerifierSecondInterfaceMustSpanEntireObservationWindow(t *testing.T) {
	f := newDeviceFixture(t)
	extra := DeviceEgress{deviceID(800), 4, "CELLULAR", true}
	f.auth.Egress = append(f.auth.Egress, extra)
	f.authorize(t)
	for i, e := range f.events {
		if p, ok := e.fact.(DeviceEgressInventory); ok {
			p.Interfaces = f.auth.Egress
			f.events[i].fact = p
		}
	}
	// A genuine zero-packet capture after the successful probe cannot prove that
	// the second interface was quiet during that probe.
	f.events = append(f.events,
		deviceFixtureEvent{"GATEWAY", "CAPTURE", DeviceCaptureFact{CaptureID: deviceID(801), EgressID: extra.ID, Family: 4, Stage: "OPEN", InterfaceRevision: 1}},
		deviceFixtureEvent{"GATEWAY", "CAPTURE", DeviceCaptureFact{CaptureID: deviceID(801), EgressID: extra.ID, Family: 4, Stage: "CLOSE", InterfaceRevision: 1}},
	)
	v, err := VerifyDeviceEvidence(f.bundle(t), f.subject, f.trust)
	if err != nil {
		t.Fatal(err)
	}
	if v.Result().Outcome == "PASS" || !containsExact(v.Result().Missing, "CAPTURE_WINDOW_INCOMPLETE") {
		t.Fatal("late second-interface capture proved false continuity")
	}
}
