// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package phase17qualification

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

const DeviceVerifierSchema = "kurdistan-phase17-device-verifier-result-v1"
const DeviceVerifierVersion = "phase17-device-core-1"

var deviceTiers = []string{"CONTROLLED_PROBE", "ROUTE_TUN", "DNS_TRANSACTION", "PER_UID", "DEVICE_WIDE"}

type DeviceTierResult struct {
	Tier    string   `json:"tier"`
	Outcome string   `json:"outcome"`
	Missing []string `json:"missing"`
}
type DeviceVerifierResult struct {
	Schema              string                `json:"schema"`
	VerifierVersion     string                `json:"verifierVersion"`
	Subject             DeviceEvidenceSubject `json:"subject"`
	SubjectSHA256       string                `json:"subjectSha256"`
	AuthorizationSHA256 string                `json:"authorizationSha256"`
	InvocationID        string                `json:"invocationId"`
	JourneyID           string                `json:"journeyId"`
	BootID              string                `json:"bootId"`
	SessionID           string                `json:"sessionId"`
	Provenance          string                `json:"provenance"`
	RequiredTiers       []string              `json:"requiredTiers"`
	RawEvidenceSHA256   string                `json:"rawEvidenceSha256"`
	ReceivedHeadSHA256  string                `json:"receivedHeadSha256"`
	FirstReceivedMonoMS uint64                `json:"firstReceivedMonoMs"`
	LastReceivedMonoMS  uint64                `json:"lastReceivedMonoMs"`
	Outcome             string                `json:"outcome"`
	ProcessDeaths       []string              `json:"processDeaths"`
	Failures            []string              `json:"failures"`
	Missing             []string              `json:"missing"`
	Tiers               []DeviceTierResult    `json:"tiers"`
}
type DeviceObserverKey struct {
	Role         string
	PublicKey    []byte
	InvocationID string
}
type DeviceEvidenceTrust struct {
	keys       map[string]DeviceObserverKey
	manifest   CandidateManifest
	provenance string
}

// These constructors accept externally provisioned trust, not proof of observer honesty,
// key custody, physical execution, or installation. Synthetic trust is never gate-capable.
func NewSyntheticDeviceEvidenceTrust(manifestRaw []byte, keys []DeviceObserverKey) (DeviceEvidenceTrust, error) {
	return newDeviceEvidenceTrust(manifestRaw, keys, "SYNTHETIC")
}
func NewAuthorizedDeviceEvidenceTrust(manifestRaw []byte, keys []DeviceObserverKey) (DeviceEvidenceTrust, error) {
	return newDeviceEvidenceTrust(manifestRaw, keys, "AUTHORIZED_DEVICE")
}
func newDeviceEvidenceTrust(manifestRaw []byte, keys []DeviceObserverKey, provenance string) (DeviceEvidenceTrust, error) {
	if len(manifestRaw) == 0 || len(manifestRaw) > MaxDeviceEvidenceBytes {
		return DeviceEvidenceTrust{}, errors.New("device preserved manifest bound rejected")
	}
	copied := append([]byte{}, manifestRaw...)
	manifest, err := DecodeCandidateManifest(bytes.NewReader(copied))
	if err != nil {
		return DeviceEvidenceTrust{}, err
	}
	if len(keys) < 3 || len(keys) > 16 {
		return DeviceEvidenceTrust{}, errors.New("device observer roster size rejected")
	}
	result := DeviceEvidenceTrust{map[string]DeviceObserverKey{}, manifest, provenance}
	roles := map[string]bool{}
	for _, source := range keys {
		key := DeviceObserverKey{source.Role, append([]byte{}, source.PublicKey...), source.InvocationID}
		id, err := KeyID(key.PublicKey)
		if err != nil || !containsExact([]string{"CONTROLLER", "CUSTODY", "LEDGER", "HOST", "OS", "DEFAULT", "VPN", "INSTRUMENTATION", "GATEWAY", "REMOTE", "DNS"}, key.Role) || !hex32Pattern.MatchString(key.InvocationID) || roles[key.Role] {
			return DeviceEvidenceTrust{}, errors.New("device role/key scope rejected")
		}
		if _, exists := result.keys[id]; exists {
			return DeviceEvidenceTrust{}, errors.New("device roles share a signing key")
		}
		result.keys[id] = key
		roles[key.Role] = true
	}
	for _, role := range []string{"CONTROLLER", "CUSTODY", "LEDGER"} {
		if !roles[role] {
			return DeviceEvidenceTrust{}, errors.New("device custody trust missing")
		}
	}
	return result, nil
}

// An exported JSON result is not a credential. Only this opaque reverified value can
// answer a gate question; zero values and computations without a terminal cannot pass.
type DeviceVerification struct {
	result           DeviceVerifierResult
	digest           string
	terminalVerified bool
	authorized       bool
}

func (v DeviceVerification) Result() DeviceVerifierResult {
	raw, err := MarshalCanonical(v.result)
	if err != nil {
		return DeviceVerifierResult{Outcome: "INCOMPLETE"}
	}
	var copied DeviceVerifierResult
	_ = json.Unmarshal(raw, &copied)
	return copied
}
func (v DeviceVerification) ResultSHA256() string { return v.digest }
func (v DeviceVerification) AllowsOperationalTier(tier string) bool {
	if !v.terminalVerified || !v.authorized || v.result.Provenance != "AUTHORIZED_DEVICE" || v.result.Outcome != "PASS" || !containsExact(v.result.RequiredTiers, tier) {
		return false
	}
	for _, result := range v.result.Tiers {
		if result.Tier == tier {
			return result.Outcome == "PASS"
		}
	}
	return false
}

type DeviceComputation struct {
	verification  DeviceVerification
	authorization DeviceAuthorization
}

func (c DeviceComputation) Result() DeviceVerifierResult { return c.verification.Result() }
func (c DeviceComputation) ResultSHA256() string         { return c.verification.digest }
func SignDeviceTerminal(private []byte, c DeviceComputation, terminalMonoMS uint64) ([]byte, error) {
	r := c.verification.result
	if c.verification.digest == "" || terminalMonoMS < r.LastReceivedMonoMS || terminalMonoMS > c.authorization.EndMonoMS {
		return nil, errors.New("device terminal computation missing or out of window")
	}
	return deviceSign(private, "DEVICE_TERMINAL", DeviceTerminal{DeviceTerminalSchema, r.SubjectSHA256, r.AuthorizationSHA256,
		r.InvocationID, r.JourneyID, r.BootID, r.SessionID, r.RawEvidenceSHA256, r.ReceivedHeadSHA256,
		DeviceVerifierVersion, c.verification.digest, r.Outcome, terminalMonoMS})
}

type deviceInterval struct{ lower, upper uint64 }
type deviceObserved struct {
	kind, role string
	fact       any
	time       deviceInterval
	received   uint64
}
type deviceClock struct {
	local, sent, received, drift uint64
	boot                         string
}

func verifyDeviceEnvelope(raw []byte, kind, role string, trust DeviceEvidenceTrust, target any) (string, error) {
	var envelope Envelope
	if err := deviceCanonicalDecode(raw, &envelope); err != nil {
		return "", err
	}
	key, found := trust.keys[envelope.KeyID]
	if !found || (role != "" && key.Role != role) || envelope.Schema != EnvelopeSchema || envelope.StatementType != kind || !hex128Pattern.MatchString(envelope.Signature) {
		return "", errors.New("device observer role or envelope rejected")
	}
	signature, _ := hex.DecodeString(envelope.Signature)
	if !ed25519.Verify(key.PublicKey, signatureMessage(kind, envelope.Payload), signature) {
		return "", errors.New("device observer signature rejected")
	}
	if err := deviceCanonicalDecode(envelope.Payload, target); err != nil {
		return "", err
	}
	return envelope.KeyID, nil
}
func deviceSubjectAgainstManifest(s DeviceEvidenceSubject, trust DeviceEvidenceTrust) error {
	if err := validateDeviceSubject(s); err != nil {
		return err
	}
	raw, err := MarshalCandidateManifest(trust.manifest)
	if err != nil {
		return err
	}
	identity, err := CandidateIdentityFromManifest(trust.manifest)
	if err != nil || identity != s.Candidate || deviceDigest(raw) != s.ManifestSHA256 {
		return errors.New("device subject does not match preserved manifest")
	}
	for _, wanted := range []ManifestEntry{s.AppAPK, s.TestAPK} {
		found := false
		for _, subject := range trust.manifest.Subjects {
			for _, entry := range subject.Entries {
				if entry == wanted {
					found = true
				}
			}
		}
		if !found {
			return errors.New("device APK missing from preserved manifest")
		}
	}
	return nil
}

// ComputeDeviceEvidence is also the only input to the terminal signing helper.
// It validates exact raw records and computes conclusions; it does not trust Terminal.
func ComputeDeviceEvidence(input DeviceEvidence, expected DeviceEvidenceSubject, trust DeviceEvidenceTrust) (DeviceComputation, error) {
	if len(input.Received) == 0 || len(input.Received) > MaxDeviceEvents || len(input.Authorization) > 128<<10 || len(input.Terminal) > 8<<10 {
		return DeviceComputation{}, errors.New("device aggregate bound rejected")
	}
	if err := validateDeviceSubject(input.Subject); err != nil {
		return DeviceComputation{}, err
	}
	total := len(input.Authorization) + len(input.Terminal)
	for _, record := range input.Received {
		if len(record) == 0 || len(record) > 128<<10 {
			return DeviceComputation{}, errors.New("device record bound rejected")
		}
		total += len(record)
		if total > MaxDeviceEvidenceBytes {
			return DeviceComputation{}, errors.New("device aggregate bound rejected")
		}
	}
	snapshot, err := MarshalCanonical(input)
	if err != nil {
		return DeviceComputation{}, err
	}
	var evidence DeviceEvidence
	if err := deviceCanonicalDecode(snapshot, &evidence); err != nil {
		return DeviceComputation{}, err
	}
	if evidence.Schema != DeviceEvidenceSchema || evidence.Subject != expected || len(evidence.Received) == 0 || len(evidence.Received) > MaxDeviceEvents {
		return DeviceComputation{}, errors.New("device evidence subject or count rejected")
	}
	if err := deviceSubjectAgainstManifest(expected, trust); err != nil {
		return DeviceComputation{}, err
	}
	subjectRaw, _ := MarshalCanonical(expected)
	subjectDigest := deviceDigest(subjectRaw)
	var auth DeviceAuthorization
	authorizationKey, err := verifyDeviceEnvelope(evidence.Authorization, "DEVICE_AUTHORIZATION", "CONTROLLER", trust, &auth)
	if err != nil {
		return DeviceComputation{}, err
	}
	if err := validateDeviceAuthorization(auth); err != nil {
		return DeviceComputation{}, err
	}
	if auth.SubjectSHA256 != subjectDigest || auth.Provenance != trust.provenance || trust.keys[authorizationKey].InvocationID != auth.InvocationID {
		return DeviceComputation{}, errors.New("device authorization binding rejected")
	}
	authorizationDigest := deviceDigest(evidence.Authorization)
	clocks := map[string]deviceClock{}
	clockNonces := map[string]bool{}
	for _, calibration := range auth.Calibrations {
		var receipt DeviceClockReceipt
		key, err := verifyDeviceEnvelope(calibration.Receipt, "DEVICE_CLOCK", "", trust, &receipt)
		if err != nil || key != calibration.KeyID || trust.keys[key].InvocationID != auth.InvocationID ||
			receipt.Schema != DeviceClockSchema || receipt.SubjectSHA256 != subjectDigest || receipt.InvocationID != auth.InvocationID || receipt.SessionID != auth.SessionID ||
			!hex32Pattern.MatchString(receipt.Nonce) || receipt.ObserverBootID != calibration.ObserverBootID || !hex32Pattern.MatchString(receipt.ObserverBootID) || receipt.LocalMonoMS > maxDeviceMono ||
			calibration.ControllerReceiveMonoMS < calibration.ControllerSendMonoMS || calibration.ControllerReceiveMonoMS > auth.StartMonoMS || calibration.DriftPPM > 1000 {
			return DeviceComputation{}, errors.New("device clock calibration rejected")
		}
		if _, duplicate := clocks[key]; duplicate || clockNonces[receipt.Nonce] {
			return DeviceComputation{}, errors.New("duplicate device clock calibration")
		}
		clockNonces[receipt.Nonce] = true
		clocks[key] = deviceClock{receipt.LocalMonoMS, calibration.ControllerSendMonoMS, calibration.ControllerReceiveMonoMS, calibration.DriftPPM, receipt.ObserverBootID}
	}
	events := make([]deviceObserved, 0, len(evidence.Received))
	counts := map[string]int{}
	observerSequence := map[string]uint64{}
	previous, previousTime := "", auth.StartMonoMS
	result := DeviceVerifierResult{Schema: DeviceVerifierSchema, VerifierVersion: DeviceVerifierVersion, Subject: expected,
		SubjectSHA256: subjectDigest, AuthorizationSHA256: authorizationDigest, InvocationID: auth.InvocationID, JourneyID: auth.JourneyID,
		BootID: auth.BootID, SessionID: auth.SessionID, Provenance: auth.Provenance, RequiredTiers: append([]string{}, auth.RequiredTiers...), Outcome: "INCOMPLETE", ProcessDeaths: []string{}, Failures: []string{}, Missing: []string{}, Tiers: []DeviceTierResult{}}
	for index, raw := range evidence.Received {
		var received DeviceReceived
		custody, err := verifyDeviceEnvelope(raw, "DEVICE_RECEIVED", "CUSTODY", trust, &received)
		if err != nil || trust.keys[custody].InvocationID != auth.InvocationID || received.Schema != DeviceReceivedSchema || received.ContextSHA256 != authorizationDigest ||
			received.ReceivedSequence != uint64(index+1) || received.PreviousSHA256 != previous || received.ReceiverBootID != auth.BootID || received.ReceivedMonoMS < previousTime || received.ReceivedMonoMS > auth.EndMonoMS {
			return DeviceComputation{}, errors.New("device received order, custody, or clock rejected")
		}
		var observation DeviceObservation
		observer, err := verifyDeviceEnvelope(received.Observation, "DEVICE_OBSERVATION", "", trust, &observation)
		if err != nil || trust.keys[observer].InvocationID != auth.InvocationID || observation.ContextSHA256 != authorizationDigest {
			return DeviceComputation{}, errors.New("device observation context rejected")
		}
		if err := validateDeviceObservation(observation); err != nil {
			return DeviceComputation{}, err
		}
		if observation.ObserverSequence != observerSequence[observer]+1 {
			return DeviceComputation{}, errors.New("device observer sequence gap or replay")
		}
		observerSequence[observer]++
		clock, found := clocks[observer]
		if !found || observation.ObserverBootID != clock.boot {
			return DeviceComputation{}, errors.New("device observer clock proof missing")
		}
		interval, err := calibratedDeviceTime(observation.ObservedMonoMS, clock)
		if err != nil || interval.lower < auth.StartMonoMS || interval.upper > received.ReceivedMonoMS || interval.upper > auth.EndMonoMS {
			return DeviceComputation{}, errors.New("device event outside authorized calibrated interval")
		}
		fact, err := decodeDeviceFact(observation.EventType, observation.Data)
		if err != nil {
			return DeviceComputation{}, err
		}
		counts[observation.EventType]++
		limit := 128
		switch observation.EventType {
		case "PACKET":
			limit = MaxDeviceEvents
		case "RUNTIME":
			limit = 512
		case "ROUTE", "EGRESS":
			limit = 32
		case "CAPTURE":
			limit = 128
		case "TRACE":
			limit = 128
		case "BOUNDARY", "STATUS":
			limit = 512
		case "RESOURCE":
			limit = 2048
		case "INSTALL":
			limit = 1
		}
		if counts[observation.EventType] > limit {
			return DeviceComputation{}, errors.New("device fact resource bound rejected")
		}
		if runtime, ok := fact.(DeviceRuntimeFact); ok && runtime.Stage == "REQUEST" {
			counts["REQUEST"]++
			if counts["REQUEST"] > 64 {
				return DeviceComputation{}, errors.New("device request resource bound rejected")
			}
		}
		role := trust.keys[observer].Role
		if !deviceRoleAllows(role, observation.EventType, fact) {
			return DeviceComputation{}, errors.New("device observer asserted a forbidden fact type")
		}
		events = append(events, deviceObserved{observation.EventType, role, fact, interval, received.ReceivedMonoMS})
		previous = deviceDigest(raw)
		previousTime = received.ReceivedMonoMS
		if index == 0 {
			result.FirstReceivedMonoMS = previousTime
		}
		result.LastReceivedMonoMS = previousTime
	}
	result.ReceivedHeadSHA256 = previous
	rawInput := struct {
		Schema              string            `json:"schema"`
		SubjectSHA256       string            `json:"subjectSha256"`
		AuthorizationSHA256 string            `json:"authorizationSha256"`
		Received            []json.RawMessage `json:"received"`
	}{"kurdistan-phase17-device-raw-v1", subjectDigest, authorizationDigest, evidence.Received}
	raw, _ := MarshalCanonical(rawInput)
	result.RawEvidenceSHA256 = deviceDigest(raw)
	deriveDeviceFacts(&result, auth, events)
	encoded, err := MarshalCanonical(result)
	if err != nil {
		return DeviceComputation{}, err
	}
	return DeviceComputation{DeviceVerification{result, deviceDigest(encoded), false, auth.Provenance == "AUTHORIZED_DEVICE"}, auth}, nil
}

func VerifyDeviceEvidence(raw []byte, expected DeviceEvidenceSubject, trust DeviceEvidenceTrust) (DeviceVerification, error) {
	incomplete := DeviceVerification{result: DeviceVerifierResult{Outcome: "INCOMPLETE"}}
	if len(raw) > MaxDeviceEvidenceBytes {
		return incomplete, errors.New("device evidence size rejected")
	}
	evidence, err := DecodeDeviceEvidence(bytes.NewReader(append([]byte{}, raw...)))
	if err != nil {
		return incomplete, err
	}
	computed, err := ComputeDeviceEvidence(evidence, expected, trust)
	if err != nil {
		return incomplete, err
	}
	var terminal DeviceTerminal
	key, err := verifyDeviceEnvelope(evidence.Terminal, "DEVICE_TERMINAL", "LEDGER", trust, &terminal)
	r := computed.verification.result
	if err != nil || trust.keys[key].InvocationID != r.InvocationID || terminal.Schema != DeviceTerminalSchema || terminal.SubjectSHA256 != r.SubjectSHA256 ||
		terminal.AuthorizationSHA256 != r.AuthorizationSHA256 || terminal.InvocationID != r.InvocationID || terminal.JourneyID != r.JourneyID || terminal.BootID != r.BootID || terminal.SessionID != r.SessionID ||
		terminal.RawEvidenceSHA256 != r.RawEvidenceSHA256 || terminal.ReceivedHeadSHA256 != r.ReceivedHeadSHA256 || terminal.VerifierVersion != DeviceVerifierVersion || terminal.ResultSHA256 != computed.verification.digest ||
		terminal.Outcome != r.Outcome || terminal.TerminalMonoMS < r.LastReceivedMonoMS || terminal.TerminalMonoMS > computed.authorization.EndMonoMS {
		return incomplete, errors.New("device terminal does not bind recomputed evidence and result")
	}
	verified := computed.verification
	verified.terminalVerified = true
	return verified, nil
}

func calibratedDeviceTime(local uint64, c deviceClock) (deviceInterval, error) {
	if local < c.local || local-c.local > maxDeviceWindowMS {
		return deviceInterval{}, errors.New("device calibration interval rejected")
	}
	delta := local - c.local
	uncertainty := (delta*c.drift + 999999) / 1000000
	if c.sent+delta < uncertainty || c.received+delta+uncertainty > maxDeviceMono {
		return deviceInterval{}, errors.New("device calibrated clock overflow")
	}
	return deviceInterval{c.sent + delta - uncertainty, c.received + delta + uncertainty}, nil
}
func deviceRoleAllows(role, kind string, fact any) bool {
	switch kind {
	case "PROCESS":
		return role == "HOST"
	case "INSTALL", "TUN", "ROUTE", "EGRESS", "SERVICE", "COMMAND", "LIFECYCLE", "INTERFACE", "FLOW", "STATUS":
		return role == "OS"
	case "CASE":
		return role == "CONTROLLER"
	case "TRACE", "BOUNDARY", "RESOURCE":
		return role == "INSTRUMENTATION"
	case "CAPTURE", "PACKET", "DNS":
		return role == "GATEWAY"
	case "PROBE":
		return role == "REMOTE"
	case "DNS_RECEIPT":
		return role == "DNS"
	case "RUNTIME":
		r := fact.(DeviceRuntimeFact)
		if containsExact([]string{"REQUEST", "REVISION_READ", "DESCRIPTOR_WRITE"}, r.Stage) {
			return role == "DEFAULT" && r.Process.Role == "DEFAULT"
		}
		return role == "VPN" && r.Process.Role == "VPN"
	}
	return false
}
func deviceAdd(values *[]string, value string) {
	if !containsExact(*values, value) && len(*values) < 64 {
		*values = append(*values, value)
	}
}
func sameDeviceProcess(a, b DeviceProcess) bool { a.State = ""; b.State = ""; return a == b }
func deviceBefore(a, b deviceObserved) bool     { return a.time.upper <= b.time.lower }

type deviceRuntimeTrace struct {
	fact             DeviceRuntimeFact
	stages           map[string]deviceObserved
	native, vpn, tun string
}
type deviceCaptureTrace struct {
	open    deviceObserved
	close   deviceObserved
	fact    DeviceCaptureFact
	packets []deviceObserved
	closed  bool
}

type deviceBoundaryTrace struct {
	open       deviceObserved
	close      deviceObserved
	fact       DeviceTraceFact
	boundaries []deviceObserved
	resources  []deviceObserved
	closed     bool
}

func deriveDeviceFacts(result *DeviceVerifierResult, auth DeviceAuthorization, events []deviceObserved) {
	missing := func(code string) { deviceAdd(&result.Missing, code) }
	failure := func(code string) { deviceAdd(&result.Failures, code) }
	processes := map[string]DeviceProcess{}
	processObservations := map[string]deviceObserved{}
	absences := map[string]deviceObserved{}
	births := map[string]deviceObserved{}
	runtimes := map[string]*deviceRuntimeTrace{}
	generation := map[string]uint64{}
	identifiers := map[string]bool{}
	captures := map[string]*deviceCaptureTrace{}
	routes := map[uint64][]deviceObserved{}
	tuns := map[string]deviceObserved{}
	probes := []deviceObserved{}
	dns := map[string][]deviceObserved{}
	inventory := map[string]deviceObserved{}
	lifecycles := []deviceObserved{}
	interfaces := []deviceObserved{}
	cases := map[string]DeviceCaseFact{}
	caseRequests := map[string]string{}
	flows := []deviceObserved{}
	services := []deviceObserved{}
	commands := []deviceObserved{}
	boundaryTraces := map[string]*deviceBoundaryTrace{}
	statuses := []deviceObserved{}
	installed := false
	latestRevision := uint64(0)
	serviceDispatches := map[string]bool{}
	serviceStarts := 0
	sessions := map[string]string{}
	for _, event := range events {
		switch fact := event.fact.(type) {
		case DeviceInstallFact:
			s := result.Subject
			expected := DeviceInstallFact{s.InstallID, s.AppPackage, s.TestPackage, s.AppAPK.SHA256, s.TestAPK.SHA256, s.AppCertificateSHA256, s.TestCertificateSHA256, s.AppUID, s.VersionCode}
			if fact != expected {
				failure("INSTALL_IDENTITY_MISMATCH")
			}
			if installed {
				failure("INSTALL_OBSERVATION_REPEATED")
			}
			installed = true
		case DeviceProcess:
			if !installed {
				missing("INSTALL_OBSERVATION_MISSING")
			}
			expectedName := result.Subject.AppPackage
			if fact.Role == "VPN" {
				expectedName += ":vpn"
			}
			if fact.UID != result.Subject.AppUID || fact.Name != expectedName {
				failure("PROCESS_IDENTITY_MISMATCH")
			}
			previous, exists := processes[fact.Role]
			if fact.State == "ABSENT" {
				if !exists || !sameDeviceProcess(previous, fact) || previous.State != "PRESENT" {
					failure("PROCESS_ABSENCE_CONTRADICTION")
				}
				absences[fact.Role] = event
			} else if absent, died := absences[fact.Role]; died && exists && previous.State == "ABSENT" {
				old := absent.fact.(DeviceProcess)
				if fact.PID == old.PID || fact.Epoch == old.Epoch || fact.StartTimeMS <= old.StartTimeMS || !deviceBefore(absent, event) {
					failure("PROCESS_REPLACEMENT_CONTRADICTION")
				} else {
					deviceAdd(&result.ProcessDeaths, fact.Role)
					births[fact.Role] = event
				}
			} else if exists && previous.State == "PRESENT" && !sameDeviceProcess(previous, fact) {
				failure("PROCESS_REPLACED_WITHOUT_EXIT")
			}
			processes[fact.Role] = fact
			processObservations[fact.Role] = event
		case DeviceServiceFact:
			if fact.Component != result.Subject.AppPackage+"/org.kurdistanvpn.runtime.android.KurdVpnService" || fact.Process.UID != result.Subject.AppUID {
				failure("SERVICE_IDENTITY_MISMATCH")
			}
			process, present := processes["VPN"]
			if !present || process.State != "PRESENT" || !sameDeviceProcess(process, fact.Process) || !deviceBefore(processObservations["VPN"], event) {
				failure("SERVICE_PROCESS_NOT_PRESENT")
			}
			if serviceDispatches[fact.DispatchID] {
				failure("SERVICE_DISPATCH_REPLAY")
			}
			serviceDispatches[fact.DispatchID] = true
			if fact.Method == "ON_START_COMMAND" {
				serviceStarts++
			}
			services = append(services, event)
		case DeviceCommandFact:
			if fact.Component != result.Subject.AppPackage+"/org.kurdistanvpn.runtime.android.KurdVpnService" || fact.Process.UID != result.Subject.AppUID {
				failure("COMMAND_IDENTITY_MISMATCH")
			}
			process, present := processes["VPN"]
			if !present || process.State != "PRESENT" || !sameDeviceProcess(process, fact.Process) || !deviceBefore(processObservations["VPN"], event) {
				failure("COMMAND_PROCESS_NOT_PRESENT")
			}
			if serviceDispatches[fact.DispatchID] {
				failure("SERVICE_DISPATCH_REPLAY")
			}
			serviceDispatches[fact.DispatchID] = true
			commands = append(commands, event)
		case DeviceLifecycleFact:
			if fact.CurrentBootID != auth.BootID {
				failure("LIFECYCLE_BOOT_ID_MISMATCH")
			}
			lifecycles = append(lifecycles, event)
		case DeviceInterfaceFact:
			interfaces = append(interfaces, event)
		case DeviceCaseFact:
			if _, duplicate := cases[fact.CaseID]; duplicate {
				failure("CONTROLLER_CASE_REPLAY")
			}
			if owner, duplicate := caseRequests[fact.RequestID]; duplicate && owner != fact.CaseID {
				failure("CONTROLLER_REQUEST_REUSE")
			}
			cases[fact.CaseID] = fact
			caseRequests[fact.RequestID] = fact.CaseID
		case DeviceTraceFact:
			trace := boundaryTraces[fact.TraceID]
			if fact.Stage == "OPEN" {
				if trace != nil {
					failure("BOUNDARY_TRACE_REOPENED")
					continue
				}
				boundaryTraces[fact.TraceID] = &deviceBoundaryTrace{open: event, fact: fact, boundaries: []deviceObserved{}, resources: []deviceObserved{}}
				continue
			}
			if trace == nil || trace.closed {
				failure("BOUNDARY_TRACE_CLOSE_CONTRADICTION")
				continue
			}
			if trace.fact.CaseID != fact.CaseID || trace.fact.RequestID != fact.RequestID || !sameDeviceProcess(trace.fact.Process, fact.Process) {
				failure("BOUNDARY_TRACE_IDENTITY_CHANGED")
			}
			trace.close, trace.closed = event, true
			observed := len(trace.boundaries) + len(trace.resources)
			if fact.EventCount != uint64(observed) || fact.DropCount != 0 || fact.GapCount != 0 {
				missing("BOUNDARY_TRACE_LOSS_OR_GAP")
			}
		case DeviceBoundaryFact:
			trace := boundaryTraces[fact.TraceID]
			if trace == nil || trace.closed || trace.fact.CaseID != fact.CaseID || trace.fact.RequestID != fact.RequestID || !sameDeviceProcess(trace.fact.Process, fact.Process) || !deviceBefore(trace.open, event) {
				failure("BOUNDARY_EVENT_OUTSIDE_TRACE")
				continue
			}
			expected := uint64(len(trace.boundaries) + len(trace.resources) + 1)
			if fact.Ordinal != expected {
				missing("BOUNDARY_TRACE_ORDINAL_GAP")
			}
			trace.boundaries = append(trace.boundaries, event)
		case DeviceResourceFact:
			trace := boundaryTraces[fact.TraceID]
			if trace == nil || trace.closed || trace.fact.CaseID != fact.CaseID || trace.fact.RequestID != fact.RequestID || !sameDeviceProcess(trace.fact.Process, fact.Process) || !deviceBefore(trace.open, event) {
				failure("RESOURCE_EVENT_OUTSIDE_TRACE")
				continue
			}
			expected := uint64(len(trace.boundaries) + len(trace.resources) + 1)
			if fact.Ordinal != expected {
				missing("BOUNDARY_TRACE_ORDINAL_GAP")
			}
			trace.resources = append(trace.resources, event)
		case DeviceStatusFact:
			if fact.Process.UID != result.Subject.AppUID {
				failure("STATUS_OWNER_MISMATCH")
			}
			statuses = append(statuses, event)
		case DeviceFlowFact:
			if fact.UID != result.Subject.AppUID {
				failure("FLOW_UID_MISMATCH")
			}
			flows = append(flows, event)
		case DeviceRuntimeFact:
			host, found := processes[fact.Process.Role]
			if !found || host.State != "PRESENT" || !sameDeviceProcess(host, fact.Process) || !deviceBefore(processObservations[fact.Process.Role], event) {
				failure("RUNTIME_PROCESS_NOT_PRESENT")
			}
			vpn, found := processes["VPN"]
			if !found || vpn.State != "PRESENT" || vpn.Epoch != fact.VPNEpoch || !deviceBefore(processObservations["VPN"], event) {
				failure("RUNTIME_VPN_EPOCH_NOT_PRESENT")
			}
			trace := runtimes[fact.RequestID]
			if fact.Stage == "REQUEST" {
				if len(runtimes) >= 64 {
					missing("RUNTIME_REQUEST_RESOURCE_BOUND")
				}
				if fact.Revision < latestRevision {
					failure("REVISION_ROLLBACK")
				}
				latestRevision = fact.Revision
				if trace != nil || fact.Generation <= generation[fact.VPNEpoch] {
					failure("REQUEST_REPLAY_OR_EPOCH_GENERATION")
				}
				for _, id := range []string{fact.RequestID, fact.CapabilityChannelID, fact.FrameChannelID, fact.DescriptorID} {
					if identifiers[id] {
						failure("AUTHORITY_IDENTITY_REUSE")
					}
					identifiers[id] = true
				}
				generation[fact.VPNEpoch] = fact.Generation
				trace = &deviceRuntimeTrace{fact: fact, stages: map[string]deviceObserved{}}
				runtimes[fact.RequestID] = trace
			}
			if trace == nil {
				failure("RUNTIME_WITHOUT_REQUEST")
				continue
			}
			base := trace.fact
			if fact.VPNEpoch != base.VPNEpoch || fact.Generation != base.Generation || fact.Revision != base.Revision || fact.CapabilityChannelID != base.CapabilityChannelID || fact.FrameChannelID != base.FrameChannelID || fact.DescriptorID != base.DescriptorID {
				failure("AUTHORITY_BINDING_CONTRADICTION")
			}
			stage := fact.Stage + ":" + fact.Purpose
			if _, repeated := trace.stages[stage]; repeated {
				failure("RUNTIME_STAGE_REPLAY")
			}
			trace.stages[stage] = event
			if fact.NativeSessionID != "" {
				if trace.native != "" && trace.native != fact.NativeSessionID {
					failure("NATIVE_SESSION_CHANGED")
				}
				trace.native = fact.NativeSessionID
			}
			if fact.VPNSessionID != "" {
				if trace.vpn != "" && trace.vpn != fact.VPNSessionID {
					failure("VPN_SESSION_CHANGED")
				}
				trace.vpn = fact.VPNSessionID
			}
			if fact.TunID != "" {
				if trace.tun != "" && trace.tun != fact.TunID {
					failure("TUN_SESSION_CHANGED")
				}
				trace.tun = fact.TunID
			}
			if fact.Stage == "NATIVE_AUTHENTICATED" || fact.Stage == "ACTIVE" {
				for _, id := range []string{fact.NativeSessionID, fact.VPNSessionID, fact.TunID} {
					if id == "" {
						missing("RUNTIME_SESSION_IDENTITY_MISSING")
						continue
					}
					if owner, exists := sessions[id]; exists && owner != fact.RequestID {
						failure("SESSION_IDENTITY_REUSE")
					}
					sessions[id] = fact.RequestID
				}
			}
		case DeviceTunFact:
			if fact.Process.UID != result.Subject.AppUID {
				failure("TUN_OWNER_MISMATCH")
			}
			key := fact.TunID + ":" + fact.State
			if _, exists := tuns[key]; exists {
				failure("TUN_STATE_REPEATED")
			}
			tuns[key] = event
		case DeviceRouteFact:
			routes[fact.Family] = append(routes[fact.Family], event)
		case DeviceEgressInventory:
			if _, duplicate := inventory[fact.Stage]; duplicate {
				failure("EGRESS_INVENTORY_DUPLICATE")
			}
			inventory[fact.Stage] = event
		case DeviceCaptureFact:
			scoped := false
			for _, e := range auth.Egress {
				if e.ID == fact.EgressID && e.Family == fact.Family && e.Enabled {
					scoped = true
				}
			}
			if !scoped {
				failure("CAPTURE_OUTSIDE_AUTHORIZATION")
			}
			trace := captures[fact.CaptureID]
			if fact.Stage == "OPEN" {
				if trace != nil {
					failure("CAPTURE_REOPENED")
				}
				captures[fact.CaptureID] = &deviceCaptureTrace{open: event, fact: fact, packets: []deviceObserved{}}
				if fact.PacketCount != 0 {
					missing("CAPTURE_PREFIX_MISSING")
				}
			} else if trace == nil || trace.closed {
				failure("CAPTURE_CLOSE_CONTRADICTION")
			} else {
				trace.close = event
				trace.closed = true
				if fact.EgressID != trace.fact.EgressID || fact.Family != trace.fact.Family || fact.InterfaceRevision != trace.fact.InterfaceRevision {
					missing("CAPTURE_INTERFACE_DISCONTINUITY")
				}
				if fact.PacketCount != uint64(len(trace.packets)) {
					missing("CAPTURE_PACKET_GAP")
				}
			}
			if fact.DropCount != 0 || fact.GapCount != 0 {
				missing("CAPTURE_LOSS_OR_GAP")
			}
		case DevicePacketFact:
			trace := captures[fact.CaptureID]
			if trace == nil || trace.closed || fact.EgressID != trace.fact.EgressID || fact.Family != trace.fact.Family {
				failure("PACKET_OUTSIDE_CAPTURE")
				continue
			}
			if fact.Ordinal != uint64(len(trace.packets)+1) {
				missing("CAPTURE_PACKET_GAP")
			}
			if !deviceBefore(trace.open, event) {
				missing("CAPTURE_CLOCK_OVERLAP")
			}
			trace.packets = append(trace.packets, event)
			if fact.Direction == "OUTBOUND" && fact.DestinationRole != "TUNNEL_GATEWAY" {
				failure("DIRECT_OR_UNEXPECTED_EGRESS")
			}
		case DeviceProbeFact:
			probes = append(probes, event)
		case DeviceDNSFact:
			dns[fact.TransactionID] = append(dns[fact.TransactionID], event)
		}
	}
	if !installed {
		missing("INSTALL_OBSERVATION_MISSING")
	}
	for _, trace := range captures {
		if !trace.closed {
			missing("CAPTURE_NOT_CLOSED")
		}
		if trace.closed {
			for _, packet := range trace.packets {
				if !deviceBefore(packet, trace.close) {
					missing("CAPTURE_CLOCK_OVERLAP")
				}
			}
		}
	}
	for _, trace := range boundaryTraces {
		if !trace.closed {
			missing("BOUNDARY_TRACE_NOT_CLOSED")
			continue
		}
		for _, event := range append(append([]deviceObserved{}, trace.boundaries...), trace.resources...) {
			if !deviceBefore(event, trace.close) {
				missing("BOUNDARY_TRACE_CLOCK_OVERLAP")
			}
		}
	}
	for _, stage := range []string{"BEFORE", "AFTER"} {
		observed, ok := inventory[stage]
		if !ok || !reflect.DeepEqual(observed.fact.(DeviceEgressInventory).Interfaces, auth.Egress) {
			missing("EGRESS_COVERAGE_UNPROVED")
		}
	}
	for _, egress := range auth.Egress {
		if !egress.Enabled {
			missing("DISABLED_INTERFACE_AUTHORIZATION_UNPROVED")
			continue
		}
		found := false
		for _, capture := range captures {
			if capture.closed && capture.fact.EgressID == egress.ID && capture.fact.Family == egress.Family {
				found = true
			}
		}
		if !found {
			missing("EGRESS_CAPTURE_MISSING")
		}
	}
	for _, trace := range runtimes {
		if auth.JourneyID == "D04" || auth.JourneyID == "D08" {
			continue
		}
		for _, stages := range [][2]string{{"REQUEST:FULL_AUTHORITY", "REVISION_READ:PRE_DESCRIPTOR"}, {"REVISION_READ:PRE_DESCRIPTOR", "DESCRIPTOR_WRITE:FULL_AUTHORITY"}, {"DESCRIPTOR_WRITE:FULL_AUTHORITY", "ADMIT:FULL_AUTHORITY"}, {"ADMIT:FULL_AUTHORITY", "NATIVE_AUTHENTICATED:FULL_AUTHORITY"}, {"NATIVE_AUTHENTICATED:FULL_AUTHORITY", "REVISION_READ:PRE_ACTIVE"}, {"REVISION_READ:PRE_ACTIVE", "ACTIVE:FULL_AUTHORITY"}} {
			before, a := trace.stages[stages[0]]
			after, b := trace.stages[stages[1]]
			if !a || !b || !deviceBefore(before, after) {
				missing("FRESH_AUTHORITY_VALIDATION_MISSING")
			}
		}
	}
	if len(runtimes) == 0 && auth.JourneyID != "D04" && auth.JourneyID != "D08" {
		missing("AUTHORITY_CONTEXT_MISSING")
	}
	for role, birth := range births {
		fresh := false
		for _, trace := range runtimes {
			if request, ok := trace.stages["REQUEST:FULL_AUTHORITY"]; ok && deviceBefore(birth, request) {
				if (role == "DEFAULT" && trace.fact.Process.Epoch == birth.fact.(DeviceProcess).Epoch) || (role == "VPN" && trace.fact.VPNEpoch == birth.fact.(DeviceProcess).Epoch) {
					fresh = true
				}
			}
		}
		if !fresh {
			missing("POST_DEATH_AUTHORITY_MISSING")
		}
		traffic := false
		for _, trace := range runtimes {
			request, ok := trace.stages["REQUEST:FULL_AUTHORITY"]
			if !ok || !deviceBefore(birth, request) {
				continue
			}
			for _, probe := range probes {
				p := probe.fact.(DeviceProbeFact)
				if p.Stage == "RESPONDED" && p.NativeSessionID == trace.native && deviceBefore(request, probe) {
					traffic = true
				}
			}
		}
		if !traffic {
			missing("POST_DEATH_TRAFFIC_CORRELATION_MISSING")
		}
		if role == "VPN" {
			oldGone := false
			for _, tun := range tuns {
				fact := tun.fact.(DeviceTunFact)
				if fact.State == "ABSENT" && fact.Process.Epoch == absences[role].fact.(DeviceProcess).Epoch && deviceBefore(tun, birth) {
					oldGone = true
				}
			}
			if !oldGone {
				missing("OLD_TUN_TEARDOWN_MISSING")
			}
			missing("OLD_NATIVE_SESSION_TERMINATION_PROOF_UNAVAILABLE")
		}
	}
	routeOK := len(routes) != 0
	probeOK := len(probes) != 0
	dnsOK := len(dns) != 0
	families := map[uint64]bool{}
	for _, e := range auth.Egress {
		if e.Enabled {
			families[e.Family] = true
		}
	}
	for family := range families {
		before, after := deviceObserved{}, deviceObserved{}
		haveBefore, haveAfter := false, false
		for _, event := range routes[family] {
			fact := event.fact.(DeviceRouteFact)
			if fact.Stage == "BEFORE" {
				before = event
				haveBefore = true
			} else {
				after = event
				haveAfter = true
			}
		}
		validRoute := haveBefore && haveAfter
		if validRoute {
			a, b := before.fact.(DeviceRouteFact), after.fact.(DeviceRouteFact)
			a.Stage = ""
			b.Stage = ""
			tun, found := tuns[a.TunID+":PRESENT"]
			validRoute = reflect.DeepEqual(a, b) && found && sameDeviceProcess(tun.fact.(DeviceTunFact).Process, a.Process) && tun.fact.(DeviceTunFact).InterfaceID == a.InterfaceID &&
				tun.fact.(DeviceTunFact).MTU == a.MTU && deviceBefore(tun, before) && a.Process.UID == result.Subject.AppUID && containsExact(a.PolicyRules, "APP_UID_TUN") && !deviceUIDContains(a.DisallowedUIDs, result.Subject.AppUID) && (len(a.AllowedUIDs) == 0 || deviceUIDContains(a.AllowedUIDs, result.Subject.AppUID)) && deviceBefore(before, after)
		}
		if !validRoute {
			routeOK = false
			probeOK = false
		}
		matched := false
		for _, probe := range probes {
			receipt := probe.fact.(DeviceProbeFact)
			if receipt.Family != family || receipt.Stage != "RESPONDED" {
				continue
			}
			for _, capture := range captures {
				if !capture.closed {
					continue
				}
				for _, packet := range capture.packets {
					p := packet.fact.(DevicePacketFact)
					if p.Family != family || p.Direction != "OUTBOUND" || p.DestinationRole != "TUNNEL_GATEWAY" || p.ProbeID != receipt.ProbeID || p.Nonce != receipt.Nonce || p.TranscriptID != receipt.TranscriptID || p.NativeSessionID != receipt.NativeSessionID || p.Protocol != receipt.Protocol {
						continue
					}
					native := false
					for _, trace := range runtimes {
						if trace.native == p.NativeSessionID && validRoute && trace.tun == before.fact.(DeviceRouteFact).TunID && trace.fact.VPNEpoch == before.fact.(DeviceRouteFact).Process.Epoch {
							if authEvent, ok := trace.stages["NATIVE_AUTHENTICATED:FULL_AUTHORITY"]; ok && deviceBefore(authEvent, packet) {
								native = deviceSessionLiveAt(trace, packet, events)
							}
						}
					}
					arrival := false
					for _, observed := range probes {
						r := observed.fact.(DeviceProbeFact)
						if r.Stage == "RECEIVED" && r.ProbeID == receipt.ProbeID && r.Nonce == receipt.Nonce && r.NativeSessionID == receipt.NativeSessionID && r.TranscriptID == receipt.TranscriptID && r.Family == receipt.Family && r.Protocol == receipt.Protocol && deviceBefore(packet, observed) && deviceBefore(observed, probe) {
							arrival = true
						}
					}
					if native && arrival && validRoute && deviceBefore(before, packet) && deviceBefore(packet, probe) && deviceBefore(probe, after) && deviceBefore(probe, capture.close) {
						matched = true
					}
				}
			}
		}
		if !matched {
			probeOK = false
		}
	}
	// Every enabled capture must cover every controlled observation, not just its
	// own successful packet. A quiet second interface is not evidence of absence
	// outside its actual capture interval.
	var windowFirst, windowLast deviceObserved
	haveWindow := false
	for _, event := range events {
		if !containsExact([]string{"PACKET", "PROBE", "DNS", "DNS_RECEIPT"}, event.kind) {
			continue
		}
		if !haveWindow || event.time.lower < windowFirst.time.lower {
			windowFirst = event
		}
		if !haveWindow || event.time.upper > windowLast.time.upper {
			windowLast = event
		}
		haveWindow = true
	}
	if haveWindow {
		before, b := inventory["BEFORE"]
		after, a := inventory["AFTER"]
		if !b || !a || !deviceBefore(before, windowFirst) || !deviceBefore(windowLast, after) {
			missing("EGRESS_INVENTORY_WINDOW_INCOMPLETE")
		}
		for _, egress := range auth.Egress {
			if !egress.Enabled {
				continue
			}
			covered := false
			for _, capture := range captures {
				if capture.closed && capture.fact.EgressID == egress.ID && capture.fact.Family == egress.Family && deviceBefore(capture.open, windowFirst) && deviceBefore(windowLast, capture.close) {
					covered = true
				}
			}
			if !covered {
				missing("CAPTURE_WINDOW_INCOMPLETE")
			}
		}
	}
	for _, transaction := range dns {
		query, response, receipt := deviceObserved{}, deviceObserved{}, deviceObserved{}
		q, s, r := false, false, false
		for _, event := range transaction {
			fact := event.fact.(DeviceDNSFact)
			if fact.ResolverRole == "DIRECT_RESOLVER" {
				failure("DIRECT_DNS_OBSERVED")
			}
			if event.kind == "DNS_RECEIPT" {
				if r {
					failure("DNS_RECORD_REPEATED")
				}
				receipt = event
				r = true
			} else if fact.Stage == "QUERY" {
				if q {
					failure("DNS_RECORD_REPEATED")
				}
				query = event
				q = true
			} else {
				if s {
					failure("DNS_RECORD_REPEATED")
				}
				response = event
				s = true
			}
		}
		if !q || !s || !r {
			dnsOK = false
			continue
		}
		a, b, c := query.fact.(DeviceDNSFact), response.fact.(DeviceDNSFact), receipt.fact.(DeviceDNSFact)
		capture := captures[a.CaptureID]
		native := false
		for _, trace := range runtimes {
			if trace.native == a.NativeSessionID {
				if authenticated, ok := trace.stages["NATIVE_AUTHENTICATED:FULL_AUTHORITY"]; ok && deviceBefore(authenticated, query) {
					native = deviceSessionLiveAt(trace, response, events)
				}
			}
		}
		queryPacket, responsePacket := false, false
		if capture != nil {
			for _, packet := range capture.packets {
				p := packet.fact.(DevicePacketFact)
				if p.DNSTransactionID != a.TransactionID || p.NativeSessionID != a.NativeSessionID || p.EgressID != a.EgressID || p.Family != a.Family || p.DestinationRole != "TUNNEL_GATEWAY" {
					continue
				}
				if p.Ordinal == a.PacketOrdinal && p.Direction == "OUTBOUND" && deviceBefore(packet, query) {
					queryPacket = true
				}
				if p.Ordinal == b.PacketOrdinal && p.Direction == "INBOUND" && deviceBefore(receipt, packet) && deviceBefore(packet, response) {
					responsePacket = true
				}
			}
		}
		if a.QueryToken != b.QueryToken || a.QueryToken != c.QueryToken || a.Family != b.Family || a.Family != c.Family || a.NativeSessionID != b.NativeSessionID || a.NativeSessionID != c.NativeSessionID ||
			a.Direction != "OUTBOUND" || b.Direction != "INBOUND" || c.Direction != "INBOUND" || a.ResolverRole != "PROTECTED_RESOLVER" || b.ResolverRole != "PROTECTED_RESOLVER" || c.ResolverRole != "PROTECTED_RESOLVER" ||
			a.QueryType != b.QueryType || a.QueryType != c.QueryType || b.ResponseCode != 0 || c.ResponseCode != 0 || b.AnswerFamily != c.AnswerFamily || b.AnswerFamily == 0 ||
			a.ResponseCode != 0 || a.AnswerFamily != 0 || a.Stage != "QUERY" || b.Stage != "RESPONSE" || c.Stage != "RESPONSE" || a.CaptureID != b.CaptureID || a.CaptureID != c.CaptureID || a.EgressID != b.EgressID || a.EgressID != c.EgressID || b.PacketOrdinal != c.PacketOrdinal ||
			a.Truncated || b.Truncated || c.Truncated || a.Fallback != "NONE" || b.Fallback != "NONE" || c.Fallback != "NONE" || a.Transport != b.Transport || b.Transport != c.Transport || !native || !queryPacket || !responsePacket ||
			!((a.QueryType == "A" && b.AnswerFamily == 4) || (a.QueryType == "AAAA" && b.AnswerFamily == 6)) || capture == nil || !capture.closed || !deviceBefore(capture.open, query) || !deviceBefore(query, receipt) || !deviceBefore(receipt, response) || !deviceBefore(response, capture.close) {
			dnsOK = false
		}
	}
	perUIDCoverage := map[string]bool{}
	for _, observed := range flows {
		flow := observed.fact.(DeviceFlowFact)
		trace := runtimes[flow.RequestID]
		capture := captures[flow.CaptureID]
		if capture == nil || !capture.closed || capture.fact.EgressID != flow.EgressID || capture.fact.Family != flow.Family || !deviceBefore(capture.open, observed) || !deviceBefore(observed, capture.close) {
			continue
		}
		if flow.RouteAction == "LOOKUP_TUN" && (trace == nil || trace.native != flow.NativeSessionID) {
			continue
		}
		// LOOKUP_TUN is not self-authenticating. It must agree with both the
		// observed live TUN/session and an effective OS route-policy snapshot.
		effectiveRoute := false
		for _, routeObserved := range routes[flow.Family] {
			route := routeObserved.fact.(DeviceRouteFact)
			if route.InterfaceID != flow.InterfaceID || !deviceBefore(routeObserved, observed) {
				continue
			}
			if flow.RouteAction == "LOOKUP_TUN" && containsExact(route.PolicyRules, "APP_UID_TUN") {
				effectiveRoute = true
			}
			if flow.RouteAction == "LOOKUP_DENY" && deviceUIDContains(route.DisallowedUIDs, flow.UID) {
				effectiveRoute = true
			}
		}
		if !effectiveRoute {
			continue
		}
		if flow.RouteAction == "LOOKUP_TUN" {
			tun, live := tuns[trace.tun]
			if !live || tun.fact.(DeviceTunFact).State != "PRESENT" || tun.fact.(DeviceTunFact).InterfaceID != flow.InterfaceID || !deviceBefore(tun, observed) {
				continue
			}
		}
		// The OS observer must establish that this exact egress/interface/family
		// remained available from capture open through close. A signed empty
		// capture without this coverage cannot prove a blocked UID flow.
		interfacePresent := false
		for _, interfaceObserved := range interfaces {
			iface := interfaceObserved.fact.(DeviceInterfaceFact)
			if iface.InterfaceID != flow.InterfaceID || iface.EgressID != flow.EgressID || iface.Family != flow.Family {
				continue
			}
			if iface.State == "PRESENT" && deviceBefore(interfaceObserved, capture.open) {
				interfacePresent = true
			}
			if iface.State == "ABSENT" && !deviceBefore(capture.close, interfaceObserved) {
				interfacePresent = false
			}
		}
		if !interfacePresent {
			continue
		}
		matched := false
		for _, packet := range capture.packets {
			p := packet.fact.(DevicePacketFact)
			if p.NativeSessionID == flow.NativeSessionID && p.EgressID == flow.EgressID && p.Family == flow.Family && p.Direction == flow.Direction && deviceBefore(observed, packet) {
				matched = true
			}
		}
		if (flow.RouteAction == "LOOKUP_TUN" && matched) || (flow.RouteAction == "LOOKUP_DENY" && !matched && capture.fact.PacketCount == 0 && capture.fact.DropCount == 0 && capture.fact.GapCount == 0) {
			perUIDCoverage[flow.EgressID+":"+strconv.FormatUint(flow.Family, 10)] = true
		}
	}
	perUID := true
	for _, egress := range auth.Egress {
		if egress.Enabled && !perUIDCoverage[egress.ID+":"+strconv.FormatUint(egress.Family, 10)] {
			perUID = false
		}
	}
	outcomes := []bool{probeOK, routeOK, dnsOK, perUID, false}
	for index, tier := range deviceTiers {
		tierResult := DeviceTierResult{tier, "INCOMPLETE", []string{}}
		if outcomes[index] && len(result.Missing) == 0 && len(result.Failures) == 0 {
			tierResult.Outcome = "PASS"
		} else if len(result.Failures) != 0 {
			tierResult.Outcome = "FAIL"
		} else {
			tierResult.Missing = append(tierResult.Missing, "REQUIRED_RAW_OBSERVATIONS_MISSING")
		}
		if index == 4 {
			tierResult.Outcome = "INCOMPLETE"
			tierResult.Missing = []string{"PRIVILEGED_PER_PACKET_ATTRIBUTION_UNAVAILABLE"}
		}
		// FIXTURE_CORE is a literal synthetic compatibility vector. Its fixed
		// unprivileged packet model cannot become evidence for PER_UID merely
		// because later verifier contracts add raw flow records.
		if auth.JourneyID == "FIXTURE_CORE" && index == 3 {
			tierResult.Outcome = "INCOMPLETE"
			tierResult.Missing = []string{"PRIVILEGED_PER_PACKET_ATTRIBUTION_UNAVAILABLE"}
		}
		result.Tiers = append(result.Tiers, tierResult)
	}
	deriveDeviceJourney(result, auth, lifecycles, flows, runtimes, tuns, captures, interfaces, cases, boundaryTraces, statuses, commands, serviceStarts, perUID, probeOK, routeOK)
	for _, required := range auth.RequiredTiers {
		for _, tier := range result.Tiers {
			if required == tier.Tier && tier.Outcome != "PASS" {
				missing("AUTHORIZED_TIER_INCOMPLETE")
			}
		}
	}
	result.Outcome = "PASS"
	if len(result.Missing) != 0 {
		result.Outcome = "INCOMPLETE"
	}
	if len(result.Failures) != 0 {
		result.Outcome = "FAIL"
	}
	// Sorting conclusion codes is canonical; signed received observations above
	// retain their exact original order and are never sorted.
	sort.Strings(result.Missing)
	sort.Strings(result.Failures)
	sort.Strings(result.ProcessDeaths)
}
func deviceUIDContains(values []uint64, value uint64) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// Journey conclusions are derived solely from the signed raw trace.  Missing
// external observations are deliberately incomplete rather than a failure that
// an app-side callback could "repair" by asserting a result.
func deriveDeviceJourney(result *DeviceVerifierResult, auth DeviceAuthorization, lifecycles, flows []deviceObserved,
	runtimes map[string]*deviceRuntimeTrace, tuns map[string]deviceObserved, captures map[string]*deviceCaptureTrace,
	interfaces []deviceObserved, cases map[string]DeviceCaseFact, boundaryTraces map[string]*deviceBoundaryTrace,
	statuses, commands []deviceObserved, serviceStarts int, perUID, probeOK, routeOK bool) {
	missing := func(code string) { deviceAdd(&result.Missing, code) }
	hasAction := func(action string) bool {
		for _, observed := range lifecycles {
			if observed.fact.(DeviceLifecycleFact).Action == action {
				return true
			}
		}
		return false
	}
	hasActionForActiveRequest := func(action string) bool {
		for _, observed := range lifecycles {
			fact := observed.fact.(DeviceLifecycleFact)
			if fact.Action == action {
				if trace := runtimes[fact.RequestID]; trace != nil {
					if _, active := trace.stages["ACTIVE:FULL_AUTHORITY"]; active {
						return true
					}
				}
			}
		}
		return false
	}
	hasService := false
	for _, trace := range runtimes {
		if _, ok := trace.stages["ACTIVE:FULL_AUTHORITY"]; ok && trace.native != "" && trace.tun != "" {
			// The raw service observation is checked below from the retained event set.
			hasService = true
		}
	}
	active := 0
	for _, trace := range runtimes {
		if _, ok := trace.stages["ACTIVE:FULL_AUTHORITY"]; ok && trace.tun != "" {
			active++
		}
	}
	tunPresent, tunAbsent := false, false
	for _, observed := range tuns {
		if observed.fact.(DeviceTunFact).State == "PRESENT" {
			tunPresent = true
		} else {
			tunAbsent = true
		}
	}
	// A cold dispatch is independently established by an OS SERVICE record. The
	// generic verifier has already rejected invalid service/process linkage.
	for _, trace := range runtimes {
		_ = trace
	}
	serviceObserved := serviceStarts == 1 && hasAction("SERVICE_START")
	baseTraffic := hasService && active == 1 && tunPresent && probeOK && routeOK
	switch auth.JourneyID {
	case "FIXTURE_CORE":
		return
	case "D01":
		if !serviceObserved {
			missing("D01_COLD_SERVICE_OBSERVATION_MISSING")
		}
		if !hasActionForActiveRequest("SERVICE_START") || !baseTraffic {
			missing("D01_PROTECTED_TRAFFIC_TRACE_MISSING")
		}
	case "D02":
		if !containsExact(result.ProcessDeaths, "DEFAULT") {
			missing("D02_DEFAULT_DEATH_MISSING")
		}
		if !hasAction("PROCESS_EXIT") || !tunAbsent {
			missing("D02_OS_LIFECYCLE_OR_CLEANUP_MISSING")
		}
	case "D03":
		if !containsExact(result.ProcessDeaths, "VPN") {
			missing("D03_VPN_DEATH_MISSING")
		}
		if !hasActionForActiveRequest("ACTIVITY_ABSENT") || !hasActionForActiveRequest("PROCESS_START") {
			missing("D03_NO_UI_REISSUE_OBSERVATION_MISSING")
		}
		if !baseTraffic {
			missing("D03_FRESH_REISSUE_TRACE_MISSING")
		}
	case "D04":
		deriveDeviceCaseMatrix(result, deviceD04Contracts, cases, lifecycles, flows, tuns, captures, interfaces, boundaryTraces, statuses, commands)
		if tunPresent || !perUID {
			missing("D04_NO_TUN_OR_PER_UID_CAPTURE_MISSING")
		}
	case "D05":
		// An overlap is established from distinct OS-observed service dispatches
		// and the request-to-ADMIT intervals, never from the case name or two
		// arbitrary request records. Both dispatches must land before either
		// request is admitted, so sequential reissues cannot satisfy this branch.
		dispatches := map[string]deviceObserved{}
		for _, observed := range lifecycles {
			fact := observed.fact.(DeviceLifecycleFact)
			if fact.Action == "SERVICE_START" {
				dispatches[fact.RequestID] = observed
			}
		}
		overlapped := false
		for firstID, firstDispatch := range dispatches {
			first := runtimes[firstID]
			if first == nil {
				continue
			}
			firstRequest, firstRequested := first.stages["REQUEST:FULL_AUTHORITY"]
			firstAdmit, firstAdmitted := first.stages["ADMIT:FULL_AUTHORITY"]
			if !firstRequested || !firstAdmitted || !deviceBefore(firstRequest, firstDispatch) {
				continue
			}
			for secondID, secondDispatch := range dispatches {
				if secondID == firstID {
					continue
				}
				second := runtimes[secondID]
				if second == nil {
					continue
				}
				secondRequest, secondRequested := second.stages["REQUEST:FULL_AUTHORITY"]
				secondAdmit, secondAdmitted := second.stages["ADMIT:FULL_AUTHORITY"]
				if secondRequested && secondAdmitted && deviceBefore(secondRequest, secondDispatch) && !deviceBefore(firstAdmit, secondDispatch) && !deviceBefore(secondAdmit, firstDispatch) {
					overlapped = true
				}
			}
		}
		if !overlapped {
			missing("D05_CONCURRENT_DISPATCH_OBSERVATION_MISSING")
		}
		if active != 1 || !tunPresent {
			missing("D05_SINGLE_WINNER_TUN_MISSING")
		}
	case "D06":
		if len(result.ProcessDeaths) == 0 {
			missing("D06_PROCESS_DEATH_EVIDENCE_MISSING")
		}
	case "D07":
		if !hasAction("BOOT") || !hasAction("USER_LOCKED") || !hasAction("USER_UNLOCKED") {
			missing("D07_BOOT_UNLOCK_LIFECYCLE_MISSING")
		}
		if !baseTraffic {
			missing("D07_POST_UNLOCK_TRAFFIC_TRACE_MISSING")
		}
	case "D08":
		deriveDeviceCaseMatrix(result, deviceD08Contracts, cases, lifecycles, flows, tuns, captures, interfaces, boundaryTraces, statuses, commands)
		if !perUID {
			missing("D08_CLEANUP_PER_UID_CAPTURE_MISSING")
		}
	default:
		missing("JOURNEY_CONTRACT_UNAVAILABLE")
	}
}

func deviceCasesBound(required []string, cases map[string]DeviceCaseFact) bool {
	if len(cases) != len(required) {
		return false
	}
	for _, id := range required {
		fact, ok := cases[id]
		if !ok || fact.FixtureSHA256 == fact.ActionSHA256 {
			return false
		}
	}
	return true
}

func deviceCaseRawObserved(required []string, cases map[string]DeviceCaseFact, lifecycles, flows []deviceObserved, action string) bool {
	for _, id := range required {
		caseFact := cases[id]
		actionObserved, denied := false, false
		for _, observed := range lifecycles {
			fact := observed.fact.(DeviceLifecycleFact)
			if fact.RequestID == caseFact.RequestID && fact.Action == action {
				actionObserved = true
			}
		}
		for _, observed := range flows {
			fact := observed.fact.(DeviceFlowFact)
			if fact.RequestID == caseFact.RequestID && fact.RouteRule == "DENY_UID_SET" && fact.RouteAction == "LOOKUP_DENY" {
				denied = true
			}
		}
		if !actionObserved || !denied {
			return false
		}
	}
	return true
}

func deriveDeviceCaseMatrix(result *DeviceVerifierResult, contracts []deviceCaseContract, cases map[string]DeviceCaseFact,
	lifecycles, flows []deviceObserved, tuns map[string]deviceObserved, captures map[string]*deviceCaptureTrace,
	interfaces []deviceObserved, traces map[string]*deviceBoundaryTrace, statuses, commands []deviceObserved) {
	prefix := "D04"
	if len(contracts) != 0 && strings.HasPrefix(contracts[0].ID, "D08_") {
		prefix = "D08"
	}
	missing := func(code string) { deviceAdd(&result.Missing, prefix+"_"+code) }
	failure := func(code string) { deviceAdd(&result.Failures, prefix+"_"+code) }
	required := deviceContractIDs(contracts)
	if !deviceCasesBound(required, cases) {
		missing("CASE_MISSING_BINDING")
		return
	}

	for _, contract := range contracts {
		caseFact := cases[contract.ID]
		serviceCount, lifecycleStart := 0, false
		for _, observed := range commands {
			fact := observed.fact.(DeviceCommandFact)
			if fact.RequestID != caseFact.RequestID {
				continue
			}
			serviceCount++
			if contract.ID == "D04_NULL_INTENT" && (fact.Action != "" || fact.Marker != "ABSENT") {
				failure("NULL_INTENT_SHAPE_CONTRADICTION")
			} else if contract.ID == "D04_UNKNOWN_ACTION" && (fact.Action != "org.kurdistanvpn.action.UNKNOWN" || fact.Marker != "ABSENT") {
				failure("UNKNOWN_ACTION_SHAPE_CONTRADICTION")
			} else if contract.ID == "D04_UNAUTHORIZED_MARKER" && (fact.Action != "android.net.VpnService" || fact.Marker != "MALFORMED") {
				failure("UNAUTHORIZED_MARKER_SHAPE_CONTRADICTION")
			} else if !strings.HasPrefix(contract.ID, "D04_NULL_") && contract.ID != "D04_UNKNOWN_ACTION" && contract.ID != "D04_UNAUTHORIZED_MARKER" && fact.Action != "android.net.VpnService" {
				failure("SYSTEM_ACTION_SHAPE_CONTRADICTION")
			}
		}
		for _, observed := range lifecycles {
			fact := observed.fact.(DeviceLifecycleFact)
			if fact.RequestID == caseFact.RequestID && fact.Action == "SERVICE_START" {
				lifecycleStart = true
			}
		}
		if serviceCount != 1 || !lifecycleStart {
			missing("SERVICE_LIFECYCLE_OBSERVATION_MISSING")
		}

		matchingTraces := []*deviceBoundaryTrace{}
		for _, trace := range traces {
			if trace.fact.CaseID == contract.ID && trace.fact.RequestID == caseFact.RequestID {
				matchingTraces = append(matchingTraces, trace)
			}
		}
		if len(matchingTraces) != 1 || !matchingTraces[0].closed {
			missing("BOUNDARY_TRACE_MISSING")
			continue
		}
		trace := matchingTraces[0]
		if trace.fact.Process.Role != "VPN" || len(trace.boundaries) != 2 {
			failure("BOUNDARY_TRACE_SHAPE_CONTRADICTION")
		} else {
			entry := trace.boundaries[0]
			terminal := trace.boundaries[1]
			a := entry.fact.(DeviceBoundaryFact)
			b := terminal.fact.(DeviceBoundaryFact)
			if a.Stage != contract.Stage || a.Event != "ENTER" || a.Code != "NONE" || b.Stage != contract.Stage || b.Event != contract.TerminalEvent || b.Code != contract.TerminalCode || !deviceBefore(entry, terminal) {
				failure("BOUNDARY_RESULT_CONTRADICTION")
			}
		}

		resourceMissing, resourceContradiction, live := deviceCaseResourceState(contract, trace.resources)
		if resourceMissing {
			missing("RESOURCE_OBSERVATION_MISSING")
		}
		if resourceContradiction {
			failure("RESOURCE_OWNERSHIP_CONTRADICTION")
		}
		if contract.AllowsUnproven {
			if !live {
				missing("CLEANUP_UNPROVEN_RESOURCE_MISSING")
			}
		} else if live {
			failure("RESOURCE_REMAINED_LIVE")
		}

		publicationStatus, registrationAbsent, connecting := "", false, false
		for _, observed := range statuses {
			fact := observed.fact.(DeviceStatusFact)
			if fact.CaseID != contract.ID || fact.RequestID != caseFact.RequestID {
				continue
			}
			if fact.Surface == "RUNTIME_PUBLICATION" && fact.State == "ACTIVE" {
				failure("ACTIVE_PUBLISHED_FOR_FAILED_CASE")
			}
			if fact.Surface == "RUNTIME_PUBLICATION" {
				publicationStatus = fact.State
			}
			if fact.Surface == "VPN_REGISTRATION" && fact.State == "ABSENT" {
				registrationAbsent = true
			}
			if fact.Surface == "FOREGROUND_NOTIFICATION" && fact.State == "CONNECTING" {
				connecting = true
			}
		}
		wantStatus := "ABSENT"
		if prefix == "D08" {
			wantStatus = "FAILED"
		}
		if contract.AllowsUnproven {
			wantStatus = "CLEANUP_UNPROVEN"
		}
		if publicationStatus != wantStatus || !registrationAbsent || (prefix == "D08" && !connecting) {
			missing("TRUTHFUL_TERMINAL_STATUS_MISSING")
		}

		present, absent, removed := deviceCaseTunState(contract, caseFact.RequestID, tuns, lifecycles, statuses)
		if contract.RequiresTunRemoval {
			if !present || !absent || !removed {
				missing("TUN_REMOVAL_OBSERVATION_MISSING")
			}
		} else if present {
			failure("UNEXPECTED_TUN_REGISTRATION")
		}

		traffic, dns, coverage := deviceCaseDenyCoverage(contract.ID, caseFact.RequestID, flows, captures, interfaces)
		if !traffic || !dns || !coverage {
			missing("TRAFFIC_DNS_OR_NO_DIRECT_FALLBACK_MISSING")
		}
	}
}

func deviceCaseResourceState(contract deviceCaseContract, observed []deviceObserved) (missing, contradiction, live bool) {
	type resourceState struct {
		kind     string
		acquired bool
		terminal bool
	}
	resources := map[string]resourceState{}
	kinds := map[string]bool{}
	for _, event := range observed {
		fact := event.fact.(DeviceResourceFact)
		state := resources[fact.ResourceID]
		if state.kind != "" && state.kind != fact.ResourceKind {
			contradiction = true
		}
		state.kind = fact.ResourceKind
		if state.terminal {
			contradiction = true
		}
		switch fact.Operation {
		case "ACQUIRE", "REGISTER":
			if state.acquired {
				contradiction = true
			}
			state.acquired = true
			kinds[fact.ResourceKind] = true
		case "TRANSFER":
			if !state.acquired {
				contradiction = true
			}
		case "CLOSE", "WIPE", "REMOVE":
			want := "CLOSE"
			if fact.ResourceKind == "SENSITIVE_BUFFER" {
				want = "WIPE"
			} else if containsExact([]string{"CALLBACK", "NOTIFICATION", "HEALTH_MONITOR"}, fact.ResourceKind) {
				want = "REMOVE"
			}
			if !state.acquired || fact.Operation != want {
				contradiction = true
			}
			state.terminal = true
		}
		resources[fact.ResourceID] = state
	}
	for _, kind := range contract.Resources {
		if !kinds[kind] {
			missing = true
		}
	}
	for _, state := range resources {
		if state.acquired && !state.terminal {
			live = true
		}
	}
	return
}

func deviceCaseTunState(contract deviceCaseContract, requestID string, tuns map[string]deviceObserved, lifecycles, statuses []deviceObserved) (present, absent, removed bool) {
	var presentEvent deviceObserved
	for _, observed := range statuses {
		status := observed.fact.(DeviceStatusFact)
		if status.CaseID != contract.ID || status.RequestID != requestID || status.Surface != "VPN_REGISTRATION" {
			continue
		}
		if status.State == "ACTIVE" {
			if tun, ok := tuns[status.Identity+":PRESENT"]; ok && deviceBefore(tun, observed) {
				present, presentEvent = true, tun
			}
		} else if status.State == "ABSENT" {
			if !present {
				absent = true
			} else if tun, ok := tuns[status.Identity+":ABSENT"]; ok && deviceBefore(presentEvent, tun) && deviceBefore(tun, observed) {
				absent = true
			}
		}
	}
	for _, observed := range lifecycles {
		fact := observed.fact.(DeviceLifecycleFact)
		if fact.RequestID == requestID && fact.Action == "TUN_REMOVED" && (!present || deviceBefore(presentEvent, observed)) {
			removed = true
		}
	}
	return
}

func deviceCaseDenyCoverage(caseID, requestID string, flows []deviceObserved, captures map[string]*deviceCaptureTrace, interfaces []deviceObserved) (traffic, dns, coverage bool) {
	correlations := map[string]bool{}
	for _, observed := range flows {
		flow := observed.fact.(DeviceFlowFact)
		if flow.RequestID != requestID || flow.RouteRule != "DENY_UID_SET" || flow.RouteAction != "LOOKUP_DENY" || flow.Direction != "OUTBOUND" {
			continue
		}
		capture := captures[flow.CaptureID]
		if capture == nil || !capture.closed || capture.fact.PacketCount != 0 || capture.fact.DropCount != 0 || capture.fact.GapCount != 0 || !deviceBefore(capture.open, observed) || !deviceBefore(observed, capture.close) {
			continue
		}
		interfacePresent := false
		for _, item := range interfaces {
			iface := item.fact.(DeviceInterfaceFact)
			if iface.InterfaceID == flow.InterfaceID && iface.EgressID == flow.EgressID && iface.Family == flow.Family && iface.State == "PRESENT" && deviceBefore(item, observed) {
				interfacePresent = true
			}
		}
		if !interfacePresent || correlations[flow.CorrelationID] {
			continue
		}
		correlations[flow.CorrelationID] = true
		coverage = true
		if flow.Protocol == "DNS" && flow.DestinationRole == "DIRECT_RESOLVER" {
			dns = true
		}
		if containsExact([]string{"TCP", "UDP"}, flow.Protocol) && flow.DestinationRole == "CONTROLLED_PROBE" {
			traffic = true
		}
	}
	return
}
func deviceSessionLiveAt(trace *deviceRuntimeTrace, at deviceObserved, events []deviceObserved) bool {
	authenticated, ok := trace.stages["NATIVE_AUTHENTICATED:FULL_AUTHORITY"]
	if !ok {
		return false
	}
	if terminal, ok := trace.stages["TERMINAL:FULL_AUTHORITY"]; ok && !deviceBefore(at, terminal) {
		return false
	}
	for _, event := range events {
		switch fact := event.fact.(type) {
		case DeviceProcess:
			if fact.Role == "VPN" && fact.Epoch == trace.fact.VPNEpoch && fact.State == "ABSENT" && deviceBefore(authenticated, event) && !deviceBefore(at, event) {
				return false
			}
		case DeviceTunFact:
			if fact.TunID == trace.tun && fact.State == "ABSENT" && !deviceBefore(at, event) {
				return false
			}
		}
	}
	return true
}

func (r DeviceVerifierResult) String() string {
	return fmt.Sprintf("device verifier %s (%s)", r.Outcome, r.Provenance)
}
