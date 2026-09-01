// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package phase17qualification

import (
	"bytes"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestDeviceEvidenceRejectsUnknownDuplicateTrailingAndUnboundedInput(t *testing.T) {
	fixture := newDeviceFixture(t)
	raw := fixture.bundle(t)
	for name, candidate := range map[string][]byte{
		"unknown":   bytes.Replace(raw, []byte(`"schema":`), []byte(`"passedChecks":["PASS"],"schema":`), 1),
		"duplicate": bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"x","schema":`), 1),
		"trailing":  append(append([]byte{}, raw...), '\n'),
		"oversized": bytes.Repeat([]byte{' '}, MaxDeviceEvidenceBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeDeviceEvidence(bytes.NewReader(candidate)); err == nil {
				t.Fatal("ambiguous evidence accepted")
			}
		})
	}
}

func TestDeviceRawCanonicalProcessGolden(t *testing.T) {
	// Exact UTF-8 bytes, with the SHA-256 independently checked by .NET SHA256.
	expected := `{"role":"VPN","name":"org.kurdistanvpn:vpn","uid":1000,"pid":102,"startTimeMs":2,"epoch":"00000000000000000000000000000033","state":"PRESENT"}`
	value := DeviceProcess{"VPN", "org.kurdistanvpn:vpn", 1000, 102, 2, deviceID(51), "PRESENT"}
	if raw := deviceBytes(t, value); string(raw) != expected {
		t.Fatalf("canonical process changed: %s", raw)
	}
	if deviceDigest([]byte(expected)) != "fab9ee977db89ad9d0dda670543d9f96891b6ba6eb84382d5e944576cc4344ca" {
		t.Fatal("independent canonical byte digest changed")
	}
	reordered := []byte(`{"name":"org.kurdistanvpn:vpn","role":"VPN","uid":1000,"pid":102,"startTimeMs":2,"epoch":"00000000000000000000000000000033","state":"PRESENT"}`)
	if _, err := decodeDeviceFact("PROCESS", reordered); err == nil {
		t.Fatal("noncanonical field order accepted")
	}
}

func TestDeviceNumericBoundsAreCheckedWithoutNarrowing(t *testing.T) {
	f := newDeviceFixture(t)
	var base DeviceRuntimeFact
	for _, event := range f.events {
		if p, ok := event.fact.(DeviceRuntimeFact); ok {
			base = p
			break
		}
	}
	for _, test := range []struct {
		name                 string
		generation, revision uint64
		valid                bool
	}{
		{"maximum", uint64(1<<63) - 1, uint64(1<<63) - 2, true}, {"zero_generation", 0, 2, false}, {"zero_revision", 1, 0, false}, {"odd_revision", 1, 3, false},
		{"overflow_generation", uint64(1 << 63), 2, false}, {"overflow_revision", 1, uint64(1 << 63), false}, {"unsigned_max", ^uint64(0), ^uint64(0), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := base
			p.Generation = test.generation
			p.Revision = test.revision
			_, err := decodeDeviceFact("RUNTIME", deviceBytes(t, p))
			if (err == nil) != test.valid {
				t.Fatalf("numeric admission=%v", err)
			}
		})
	}
	p := DeviceProcess{"VPN", "org.kurdistanvpn:vpn", 0xffffffff, 1, 1, deviceID(1), "PRESENT"}
	if _, err := decodeDeviceFact("PROCESS", deviceBytes(t, p)); err == nil {
		t.Fatal("reserved/overflow UID accepted")
	}
	auth := f.auth
	auth.EndMonoMS = maxDeviceMono + 1
	if _, err := SignDeviceAuthorization(f.keys["CONTROLLER"], auth); err == nil {
		t.Fatal("clock precision boundary accepted")
	}
	auth = f.auth
	auth.Egress = append(auth.Egress, auth.Egress[0])
	if _, err := SignDeviceAuthorization(f.keys["CONTROLLER"], auth); err == nil {
		t.Fatal("duplicate egress accepted")
	}
}

func TestDeviceSchemasAreClosedBoundedAndHaveResolvableReferences(t *testing.T) {
	for _, file := range []string{"phase17-device-evidence-v1.schema.json", "phase17-device-verifier-result-v1.schema.json"} {
		schema := loadQualificationSchema(t, file)
		raw, err := json.Marshal(schema)
		if err != nil {
			t.Fatal(err)
		}
		var root map[string]any
		if err = json.Unmarshal(raw, &root); err != nil {
			t.Fatal(err)
		}
		var walk func(any)
		walk = func(value any) {
			switch v := value.(type) {
			case map[string]any:
				if pattern, ok := v["pattern"].(string); ok {
					if _, err := regexp.Compile(pattern); err != nil && !strings.Contains(pattern, "(?!") {
						t.Fatalf("bad schema pattern %s: %v", pattern, err)
					}
				}
				if ref, ok := v["$ref"].(string); ok {
					if !strings.HasPrefix(ref, "#/$defs/") {
						t.Fatal("external/unbounded schema reference")
					}
					if _, exists := schema.Defs[strings.TrimPrefix(ref, "#/$defs/")]; !exists {
						t.Fatalf("missing reference %s", ref)
					}
				}
				if v["type"] == "object" && v["additionalProperties"] != false {
					t.Fatal("open evidence object")
				}
				if v["type"] == "array" {
					if _, ok := v["maxItems"]; !ok {
						t.Fatal("unbounded evidence array")
					}
				}
				for _, child := range v {
					walk(child)
				}
			case []any:
				for _, child := range v {
					walk(child)
				}
			}
		}
		walk(root)
	}
}

func TestDeviceEvidenceSchemaMatchesRequiredGoFields(t *testing.T) {
	schema := loadQualificationSchema(t, "phase17-device-evidence-v1.schema.json")
	assertQualificationSchemaObjectMatches(t, "root", schema, reflect.TypeOf(DeviceEvidence{}))
	for name, kind := range map[string]reflect.Type{
		"subject": reflect.TypeOf(DeviceEvidenceSubject{}), "authorization": reflect.TypeOf(DeviceAuthorization{}),
		"observation": reflect.TypeOf(DeviceObservation{}), "received": reflect.TypeOf(DeviceReceived{}),
		"terminal": reflect.TypeOf(DeviceTerminal{}), "process": reflect.TypeOf(DeviceProcess{}),
		"service": reflect.TypeOf(DeviceServiceFact{}), "command": reflect.TypeOf(DeviceCommandFact{}), "runtime": reflect.TypeOf(DeviceRuntimeFact{}), "tun": reflect.TypeOf(DeviceTunFact{}),
		"route": reflect.TypeOf(DeviceRouteFact{}), "capture": reflect.TypeOf(DeviceCaptureFact{}),
		"packet": reflect.TypeOf(DevicePacketFact{}), "probe": reflect.TypeOf(DeviceProbeFact{}),
		"dns": reflect.TypeOf(DeviceDNSFact{}), "lifecycle": reflect.TypeOf(DeviceLifecycleFact{}),
		"interface": reflect.TypeOf(DeviceInterfaceFact{}), "case": reflect.TypeOf(DeviceCaseFact{}), "flow": reflect.TypeOf(DeviceFlowFact{}),
		"trace": reflect.TypeOf(DeviceTraceFact{}), "boundary": reflect.TypeOf(DeviceBoundaryFact{}),
		"resource": reflect.TypeOf(DeviceResourceFact{}), "status": reflect.TypeOf(DeviceStatusFact{}),
		"clock":       reflect.TypeOf(DeviceClockReceipt{}),
		"calibration": reflect.TypeOf(DeviceCalibration{}), "egress": reflect.TypeOf(DeviceEgress{}),
		"inventory": reflect.TypeOf(DeviceEgressInventory{}),
		"install":   reflect.TypeOf(DeviceInstallFact{}),
	} {
		assertQualificationSchemaObjectMatches(t, name, schema.Defs[name], kind)
	}
	result := loadQualificationSchema(t, "phase17-device-verifier-result-v1.schema.json")
	assertQualificationSchemaObjectMatches(t, "result", result, reflect.TypeOf(DeviceVerifierResult{}))
	assertQualificationSchemaObjectMatches(t, "tier", result.Defs["tier"], reflect.TypeOf(DeviceTierResult{}))
}

func TestDeviceObservationCannotCarryAppAuthoredConclusions(t *testing.T) {
	fixture := newDeviceFixture(t)
	event := DeviceObservation{Schema: DeviceObservationSchema, ContextSHA256: fixture.authorizationDigest,
		ObserverSequence: 1, ObserverBootID: deviceID(10), ObservedMonoMS: 101, EventType: "PROCESS", Data: json.RawMessage(`{"processDeathProved":true}`)}
	if _, err := SignDeviceObservation(fixture.keys["HOST"], event); err == nil {
		t.Fatal("app conclusion accepted as raw process observation")
	}
}

func TestDeviceRawFlowRequiresDirectionAndCoherentEffectivePolicy(t *testing.T) {
	flow := DeviceFlowFact{
		FlowID: deviceID(1), RequestID: deviceID(2), NativeSessionID: deviceID(3),
		CaptureID: deviceID(4), EgressID: deviceID(5), InterfaceID: deviceID(6),
		Direction: "OUTBOUND", Protocol: "UDP", DestinationRole: "CONTROLLED_PROBE", CorrelationID: deviceID(7),
		RouteRule: "APP_UID_TUN", RouteAction: "LOOKUP_TUN", UID: 1000, Family: 4,
	}
	if _, err := decodeDeviceFact("FLOW", deviceBytes(t, flow)); err != nil {
		t.Fatalf("raw flow rejected: %v", err)
	}
	flow.Direction = "TUNNELLED"
	if _, err := decodeDeviceFact("FLOW", deviceBytes(t, flow)); err == nil {
		t.Fatal("conclusion-shaped flow direction accepted")
	}
	flow.Direction = "OUTBOUND"
	flow.RouteAction = "LOOKUP_DENY"
	if _, err := decodeDeviceFact("FLOW", deviceBytes(t, flow)); err == nil {
		t.Fatal("contradictory route rule/action accepted")
	}
}

func TestDeviceRawOutcomeRejectsVerdictShapedAndUnboundRecords(t *testing.T) {
	type rejectedOutcomeFact struct {
		CaseID       string `json:"caseId"`
		RequestID    string `json:"requestId"`
		ActionSHA256 string `json:"actionSha256"`
		OutcomeCode  string `json:"outcomeCode"`
		Stage        string `json:"stage"`
	}
	outcome := rejectedOutcomeFact{CaseID: "D04_MISSING", RequestID: deviceID(2), ActionSHA256: strings.Repeat("a", 64), OutcomeCode: "REJECTED", Stage: "AUTHORITY_ADMISSION"}
	if _, err := decodeDeviceFact("OUTCOME", deviceBytes(t, outcome)); err == nil {
		t.Fatal("observer-authored action outcome accepted as raw evidence")
	}
	outcome.OutcomeCode = "CLEANED"
	if _, err := decodeDeviceFact("OUTCOME", deviceBytes(t, outcome)); err == nil {
		t.Fatal("cleanup conclusion accepted as raw evidence")
	}
}

func TestD04AndD08CaseRegistriesCoverEveryApprovedNegativeAndFailureBoundary(t *testing.T) {
	wantD04 := []string{
		"D04_NULL_INTENT", "D04_UNKNOWN_ACTION", "D04_UNAUTHORIZED_MARKER", "D04_MISSING_AUTHORITY",
		"D04_MALFORMED_FRAME", "D04_SHORT_FRAME", "D04_TRAILING_FRAME", "D04_OVERSIZE_FRAME",
		"D04_TAMPERED_FRAME", "D04_REPLAYED_FRAME", "D04_WRONG_REQUEST", "D04_WRONG_PURPOSE",
		"D04_WRONG_EPOCH", "D04_WRONG_GENERATION", "D04_WRONG_REVISION", "D04_EXPIRED_DEADLINE",
		"D04_WRONG_CAPABILITY_CHANNEL", "D04_WRONG_FRAME_CHANNEL", "D04_EXPIRED_AUTHORITY",
		"D04_REVOKED_AUTHORITY", "D04_WRONG_RECIPIENT", "D04_WRONG_IDENTITY",
		"D04_KEY_INVALID_AUTHORITY", "D04_CONSENT_UNAVAILABLE", "D04_PREPARED_UNAVAILABLE",
	}
	wantD08 := []string{
		"D08_PARSING_THROW", "D08_AUTHORITY_OPEN_THROW", "D08_SOCKET_CREATE_THROW",
		"D08_SOCKET_PROTECT_FALSE", "D08_NETWORK_BIND_THROW", "D08_CONNECT_THROW",
		"D08_AUTHENTICATE_THROW", "D08_TUN_BUILD_THROW", "D08_TUN_ESTABLISH_NULL",
		"D08_TUN_ESTABLISH_THROW", "D08_TUN_DETACH_THROW", "D08_TUN_ATTACH_THROW",
		"D08_CALLBACK_REGISTER_THROW", "D08_NOTIFICATION_PREPARE_THROW",
		"D08_HEALTH_MONITOR_INSTALL_THROW", "D08_REVISION_VALIDATE_STALE",
		"D08_ACTIVE_COMMIT_THROW", "D08_STOP", "D08_REVOKE", "D08_BINDER_DEATH",
		"D08_PROVIDER_DEATH", "D08_TIMEOUT", "D08_CLEANUP_RETRYABLE", "D08_CLEANUP_UNPROVEN",
	}
	if !reflect.DeepEqual(deviceD04Cases, wantD04) {
		t.Fatalf("D04 case registry mismatch:\n got=%v\nwant=%v", deviceD04Cases, wantD04)
	}
	if !reflect.DeepEqual(deviceD08Cases, wantD08) {
		t.Fatalf("D08 case registry mismatch:\n got=%v\nwant=%v", deviceD08Cases, wantD08)
	}
}
