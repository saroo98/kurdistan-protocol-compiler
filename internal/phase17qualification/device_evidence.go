// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package phase17qualification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"

	"kurdistan/internal/assurance"
)

const (
	DeviceEvidenceSchema      = "kurdistan-phase17-device-evidence-v1"
	DeviceAuthorizationSchema = "kurdistan-phase17-device-authorization-v1"
	DeviceObservationSchema   = "kurdistan-phase17-device-observation-v1"
	DeviceReceivedSchema      = "kurdistan-phase17-device-received-v1"
	DeviceTerminalSchema      = "kurdistan-phase17-device-terminal-v1"
	DeviceClockSchema         = "kurdistan-phase17-device-clock-v1"
	MaxDeviceEvidenceBytes    = 4 << 20
	MaxDeviceEvents           = 4096
	maxDeviceMono             = uint64(9007199254740991)
	maxDeviceWindowMS         = uint64(86_400_000)
)

var devicePackagePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,15}$`)

type DeviceEvidenceSubject struct {
	Candidate             CandidateIdentity `json:"candidate"`
	ManifestSHA256        string            `json:"manifestSha256"`
	AppPackage            string            `json:"appPackage"`
	TestPackage           string            `json:"testPackage"`
	AppAPK                ManifestEntry     `json:"appApk"`
	TestAPK               ManifestEntry     `json:"testApk"`
	AppCertificateSHA256  string            `json:"appCertificateSha256"`
	TestCertificateSHA256 string            `json:"testCertificateSha256"`
	InstallID             string            `json:"installId"`
	AppUID                uint64            `json:"appUid"`
	VersionCode           uint64            `json:"versionCode"`
}
type DeviceEvidence struct {
	Schema        string                `json:"schema"`
	Subject       DeviceEvidenceSubject `json:"subject"`
	Authorization json.RawMessage       `json:"authorization"`
	Received      []json.RawMessage     `json:"received"`
	Terminal      json.RawMessage       `json:"terminal"`
}
type DeviceEgress struct {
	ID      string `json:"id"`
	Family  uint64 `json:"family"`
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
}
type DeviceCalibration struct {
	KeyID                   string          `json:"keyId"`
	ObserverBootID          string          `json:"observerBootId"`
	ControllerSendMonoMS    uint64          `json:"controllerSendMonoMs"`
	ControllerReceiveMonoMS uint64          `json:"controllerReceiveMonoMs"`
	DriftPPM                uint64          `json:"driftPpm"`
	Receipt                 json.RawMessage `json:"receipt"`
}
type DeviceClockReceipt struct {
	Schema         string `json:"schema"`
	SubjectSHA256  string `json:"subjectSha256"`
	InvocationID   string `json:"invocationId"`
	SessionID      string `json:"sessionId"`
	ObserverBootID string `json:"observerBootId"`
	Nonce          string `json:"nonce"`
	LocalMonoMS    uint64 `json:"localMonoMs"`
}
type DeviceAuthorization struct {
	Schema             string              `json:"schema"`
	SubjectSHA256      string              `json:"subjectSha256"`
	InvocationID       string              `json:"invocationId"`
	JourneyID          string              `json:"journeyId"`
	BootID             string              `json:"bootId"`
	SessionID          string              `json:"sessionId"`
	IssuedAt           string              `json:"issuedAt"`
	IssuedMonoMS       uint64              `json:"issuedMonoMs"`
	ControllerSequence uint64              `json:"controllerSequence"`
	StartMonoMS        uint64              `json:"startMonoMs"`
	EndMonoMS          uint64              `json:"endMonoMs"`
	Provenance         string              `json:"provenance"`
	Egress             []DeviceEgress      `json:"egress"`
	RequiredTiers      []string            `json:"requiredTiers"`
	Calibrations       []DeviceCalibration `json:"calibrations"`
}
type DeviceObservation struct {
	Schema           string          `json:"schema"`
	ContextSHA256    string          `json:"contextSha256"`
	ObserverSequence uint64          `json:"observerSequence"`
	ObserverBootID   string          `json:"observerBootId"`
	ObservedMonoMS   uint64          `json:"observedMonoMs"`
	EventType        string          `json:"eventType"`
	Data             json.RawMessage `json:"data"`
}
type DeviceReceived struct {
	Schema           string          `json:"schema"`
	ContextSHA256    string          `json:"contextSha256"`
	ReceivedSequence uint64          `json:"receivedSequence"`
	PreviousSHA256   string          `json:"previousSha256"`
	ReceiverBootID   string          `json:"receiverBootId"`
	ReceivedMonoMS   uint64          `json:"receivedMonoMs"`
	Observation      json.RawMessage `json:"observation"`
}
type DeviceTerminal struct {
	Schema              string `json:"schema"`
	SubjectSHA256       string `json:"subjectSha256"`
	AuthorizationSHA256 string `json:"authorizationSha256"`
	InvocationID        string `json:"invocationId"`
	JourneyID           string `json:"journeyId"`
	BootID              string `json:"bootId"`
	SessionID           string `json:"sessionId"`
	RawEvidenceSHA256   string `json:"rawEvidenceSha256"`
	ReceivedHeadSHA256  string `json:"receivedHeadSha256"`
	VerifierVersion     string `json:"verifierVersion"`
	ResultSHA256        string `json:"resultSha256"`
	Outcome             string `json:"outcome"`
	TerminalMonoMS      uint64 `json:"terminalMonoMs"`
}

type DeviceProcess struct {
	Role        string `json:"role"`
	Name        string `json:"name"`
	UID         uint64 `json:"uid"`
	PID         uint64 `json:"pid"`
	StartTimeMS uint64 `json:"startTimeMs"`
	Epoch       string `json:"epoch"`
	State       string `json:"state"`
}

// OS installation observations are separate from the controller's expected subject.
type DeviceInstallFact struct {
	InstallID             string `json:"installId"`
	AppPackage            string `json:"appPackage"`
	TestPackage           string `json:"testPackage"`
	AppAPKSHA256          string `json:"appApkSha256"`
	TestAPKSHA256         string `json:"testApkSha256"`
	AppCertificateSHA256  string `json:"appCertificateSha256"`
	TestCertificateSHA256 string `json:"testCertificateSha256"`
	AppUID                uint64 `json:"appUid"`
	VersionCode           uint64 `json:"versionCode"`
}
type DeviceRuntimeFact struct {
	Process             DeviceProcess `json:"process"`
	VPNEpoch            string        `json:"vpnEpoch"`
	Stage               string        `json:"stage"`
	RequestID           string        `json:"requestId"`
	Generation          uint64        `json:"generation"`
	Revision            uint64        `json:"revision"`
	Purpose             string        `json:"purpose"`
	CapabilityChannelID string        `json:"capabilityChannelId"`
	FrameChannelID      string        `json:"frameChannelId"`
	DescriptorID        string        `json:"descriptorId"`
	NativeSessionID     string        `json:"nativeSessionId"`
	VPNSessionID        string        `json:"vpnSessionId"`
	TunID               string        `json:"tunId"`
}

// Service delivery is an OS-observed input, never an application conclusion that
// restoration ran. Marker records only the admitted command envelope shape; it
// carries no authority or Intent extras. Signatures authenticate the observer,
// not the truth/completeness of its instrumentation.
type DeviceServiceFact struct {
	Process    DeviceProcess `json:"process"`
	Component  string        `json:"component"`
	Method     string        `json:"method"`
	Action     string        `json:"action"`
	StartID    uint64        `json:"startId"`
	CallerUID  uint64        `json:"callerUid"`
	Flags      uint64        `json:"flags"`
	DispatchID string        `json:"dispatchId"`
	Marker     string        `json:"marker"`
}
type DeviceCommandFact struct {
	CaseID     string        `json:"caseId"`
	RequestID  string        `json:"requestId"`
	Process    DeviceProcess `json:"process"`
	Component  string        `json:"component"`
	Method     string        `json:"method"`
	Action     string        `json:"action"`
	StartID    uint64        `json:"startId"`
	CallerUID  uint64        `json:"callerUid"`
	Flags      uint64        `json:"flags"`
	DispatchID string        `json:"dispatchId"`
	Marker     string        `json:"marker"`
}
type DeviceTunFact struct {
	Process     DeviceProcess `json:"process"`
	TunID       string        `json:"tunId"`
	InterfaceID string        `json:"interfaceId"`
	MTU         uint64        `json:"mtu"`
	State       string        `json:"state"`
}
type DeviceRouteFact struct {
	Process           DeviceProcess `json:"process"`
	TunID             string        `json:"tunId"`
	InterfaceID       string        `json:"interfaceId"`
	Family            uint64        `json:"family"`
	Stage             string        `json:"stage"`
	DestinationPrefix string        `json:"destinationPrefix"`
	MTU               uint64        `json:"mtu"`
	AddressPrefixes   []string      `json:"addressPrefixes"`
	PolicyRules       []string      `json:"policyRules"`
	AllowedUIDs       []uint64      `json:"allowedUids"`
	DisallowedUIDs    []uint64      `json:"disallowedUids"`
}
type DeviceEgressInventory struct {
	Stage      string         `json:"stage"`
	Interfaces []DeviceEgress `json:"interfaces"`
}
type DeviceCaptureFact struct {
	CaptureID         string `json:"captureId"`
	EgressID          string `json:"egressId"`
	Family            uint64 `json:"family"`
	Stage             string `json:"stage"`
	PacketCount       uint64 `json:"packetCount"`
	DropCount         uint64 `json:"dropCount"`
	GapCount          uint64 `json:"gapCount"`
	InterfaceRevision uint64 `json:"interfaceRevision"`
}
type DevicePacketFact struct {
	CaptureID        string `json:"captureId"`
	EgressID         string `json:"egressId"`
	Family           uint64 `json:"family"`
	Ordinal          uint64 `json:"ordinal"`
	Direction        string `json:"direction"`
	Protocol         string `json:"protocol"`
	DestinationRole  string `json:"destinationRole"`
	Length           uint64 `json:"length"`
	ProbeID          string `json:"probeId"`
	Nonce            string `json:"nonce"`
	NativeSessionID  string `json:"nativeSessionId"`
	TranscriptID     string `json:"transcriptId"`
	DNSTransactionID string `json:"dnsTransactionId"`
}
type DeviceProbeFact struct {
	ProbeID         string `json:"probeId"`
	Nonce           string `json:"nonce"`
	NativeSessionID string `json:"nativeSessionId"`
	TranscriptID    string `json:"transcriptId"`
	Family          uint64 `json:"family"`
	Protocol        string `json:"protocol"`
	Stage           string `json:"stage"`
	Bytes           uint64 `json:"bytes"`
}
type DeviceDNSFact struct {
	TransactionID   string `json:"transactionId"`
	QueryToken      string `json:"queryToken"`
	Family          uint64 `json:"family"`
	Direction       string `json:"direction"`
	ResolverRole    string `json:"resolverRole"`
	Transport       string `json:"transport"`
	QueryType       string `json:"queryType"`
	ResponseCode    uint64 `json:"responseCode"`
	AnswerFamily    uint64 `json:"answerFamily"`
	Truncated       bool   `json:"truncated"`
	Fallback        string `json:"fallback"`
	NativeSessionID string `json:"nativeSessionId"`
	CaptureID       string `json:"captureId"`
	EgressID        string `json:"egressId"`
	PacketOrdinal   uint64 `json:"packetOrdinal"`
	Stage           string `json:"stage"`
}

// Lifecycle and flow records are signed observations made by the OS observer.
// Their values describe low-level system actions and route lookups, never a
// test-case result, a "no UI" conclusion, or a tunnelling verdict.
type DeviceLifecycleFact struct {
	Action         string        `json:"action"`
	RequestID      string        `json:"requestId"`
	Process        DeviceProcess `json:"process"`
	PreviousBootID string        `json:"previousBootId"`
	CurrentBootID  string        `json:"currentBootId"`
}

// DeviceInterfaceFact is an OS observation of the interface that was usable
// during a flow window.  It is separate from a route decision: a route rule
// alone cannot establish that the selected interface was actually available.
type DeviceInterfaceFact struct {
	InterfaceID string `json:"interfaceId"`
	EgressID    string `json:"egressId"`
	Family      uint64 `json:"family"`
	State       string `json:"state"`
}

type deviceCaseContract struct {
	ID                 string
	Stage              string
	Fault              string
	TerminalEvent      string
	TerminalCode       string
	Resources          []string
	RequiresTunRemoval bool
	AllowsUnproven     bool
}

var deviceD04Contracts = []deviceCaseContract{
	{"D04_NULL_INTENT", "COMMAND_ADMISSION", "NULL_INPUT", "RETURN", "REJECTED", nil, false, false},
	{"D04_UNKNOWN_ACTION", "COMMAND_ADMISSION", "UNKNOWN_ACTION", "RETURN", "REJECTED", nil, false, false},
	{"D04_UNAUTHORIZED_MARKER", "COMMAND_ADMISSION", "UNAUTHORIZED_MARKER", "RETURN", "REJECTED", nil, false, false},
	{"D04_MISSING_AUTHORITY", "AUTHORITY_FRAME", "OMITTED", "RETURN", "REJECTED", nil, false, false},
	{"D04_MALFORMED_FRAME", "AUTHORITY_FRAME", "MALFORMED", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_SHORT_FRAME", "AUTHORITY_FRAME", "SHORT_READ", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_TRAILING_FRAME", "AUTHORITY_FRAME", "TRAILING_BYTES", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_OVERSIZE_FRAME", "AUTHORITY_FRAME", "OVERSIZE", "RETURN", "REJECTED", nil, false, false},
	{"D04_TAMPERED_FRAME", "AUTHORITY_FRAME", "TAG_MISMATCH", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_REPLAYED_FRAME", "AUTHORITY_CONTEXT", "REPLAY", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_WRONG_REQUEST", "AUTHORITY_CONTEXT", "REQUEST_MISMATCH", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_WRONG_PURPOSE", "AUTHORITY_CONTEXT", "PURPOSE_MISMATCH", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_WRONG_EPOCH", "AUTHORITY_CONTEXT", "EPOCH_MISMATCH", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_WRONG_GENERATION", "AUTHORITY_CONTEXT", "GENERATION_MISMATCH", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_WRONG_REVISION", "AUTHORITY_CONTEXT", "REVISION_MISMATCH", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_EXPIRED_DEADLINE", "AUTHORITY_CONTEXT", "DEADLINE_EXPIRED", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_WRONG_CAPABILITY_CHANNEL", "AUTHORITY_CONTEXT", "CAPABILITY_CHANNEL_MISMATCH", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_WRONG_FRAME_CHANNEL", "AUTHORITY_CONTEXT", "FRAME_CHANNEL_MISMATCH", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_EXPIRED_AUTHORITY", "AUTHORITY_VALIDATION", "EXPIRED", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_REVOKED_AUTHORITY", "AUTHORITY_VALIDATION", "REVOKED", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_WRONG_RECIPIENT", "AUTHORITY_VALIDATION", "RECIPIENT_MISMATCH", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_WRONG_IDENTITY", "AUTHORITY_VALIDATION", "IDENTITY_MISMATCH", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_KEY_INVALID_AUTHORITY", "AUTHORITY_VALIDATION", "KEY_INVALID", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_CONSENT_UNAVAILABLE", "CONSENT_CHECK", "CONSENT_UNAVAILABLE", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D04_PREPARED_UNAVAILABLE", "CONSENT_CHECK", "PREPARED_UNAVAILABLE", "RETURN", "REJECTED", []string{"SENSITIVE_BUFFER"}, false, false},
}

var deviceD08Contracts = []deviceCaseContract{
	{"D08_PARSING_THROW", "PARSING", "THROW", "THROW", "INJECTED_EXCEPTION", []string{"SENSITIVE_BUFFER"}, false, false},
	{"D08_AUTHORITY_OPEN_THROW", "AUTHORITY_OPEN", "THROW_PARTIAL", "THROW", "INJECTED_EXCEPTION", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR"}, false, false},
	{"D08_SOCKET_CREATE_THROW", "SOCKET_CREATION", "THROW_PARTIAL", "THROW", "INJECTED_EXCEPTION", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR", "SOCKET"}, false, false},
	{"D08_SOCKET_PROTECT_FALSE", "SOCKET_PROTECTION", "RETURN_FALSE", "RETURN", "FALSE", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR", "SOCKET"}, false, false},
	{"D08_NETWORK_BIND_THROW", "NETWORK_BINDING", "THROW", "THROW", "INJECTED_EXCEPTION", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR", "SOCKET"}, false, false},
	{"D08_CONNECT_THROW", "CONNECTION", "THROW", "THROW", "INJECTED_EXCEPTION", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR", "SOCKET"}, false, false},
	{"D08_AUTHENTICATE_THROW", "AUTHENTICATION", "THROW_PARTIAL", "THROW", "INJECTED_EXCEPTION", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR", "SOCKET", "NATIVE_SESSION"}, false, false},
	{"D08_TUN_BUILD_THROW", "TUN_CONSTRUCTION", "THROW", "THROW", "INJECTED_EXCEPTION", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR", "SOCKET", "NATIVE_SESSION"}, false, false},
	{"D08_TUN_ESTABLISH_NULL", "TUN_ESTABLISHMENT", "RETURN_NULL", "RETURN", "NULL", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR", "SOCKET", "NATIVE_SESSION"}, false, false},
	{"D08_TUN_ESTABLISH_THROW", "TUN_ESTABLISHMENT", "THROW", "THROW", "INJECTED_EXCEPTION", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR", "SOCKET", "NATIVE_SESSION"}, false, false},
	{"D08_TUN_DETACH_THROW", "TUN_DETACH", "THROW_PARTIAL", "THROW", "INJECTED_EXCEPTION", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR", "SOCKET", "NATIVE_SESSION", "TUN_DESCRIPTOR"}, true, false},
	{"D08_TUN_ATTACH_THROW", "TUN_ATTACHMENT", "THROW", "THROW", "INJECTED_EXCEPTION", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR", "SOCKET", "NATIVE_SESSION", "TUN_DESCRIPTOR"}, true, false},
	{"D08_CALLBACK_REGISTER_THROW", "CALLBACK_REGISTRATION", "THROW_PARTIAL", "THROW", "INJECTED_EXCEPTION", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR", "SOCKET", "NATIVE_SESSION", "TUN_DESCRIPTOR", "CALLBACK"}, true, false},
	{"D08_NOTIFICATION_PREPARE_THROW", "NOTIFICATION_PREPARATION", "THROW_PARTIAL", "THROW", "INJECTED_EXCEPTION", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR", "SOCKET", "NATIVE_SESSION", "TUN_DESCRIPTOR", "CALLBACK", "NOTIFICATION"}, true, false},
	{"D08_HEALTH_MONITOR_INSTALL_THROW", "HEALTH_MONITOR_INSTALLATION", "THROW_PARTIAL", "THROW", "INJECTED_EXCEPTION", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR", "SOCKET", "NATIVE_SESSION", "TUN_DESCRIPTOR", "CALLBACK", "NOTIFICATION", "HEALTH_MONITOR"}, true, false},
	{"D08_REVISION_VALIDATE_STALE", "REVISION_VALIDATION", "STALE", "RETURN", "STALE", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR", "SOCKET", "NATIVE_SESSION", "TUN_DESCRIPTOR", "CALLBACK", "NOTIFICATION", "HEALTH_MONITOR", "REVISION_LEASE"}, true, false},
	{"D08_ACTIVE_COMMIT_THROW", "ACTIVE_COMMIT", "THROW", "THROW", "INJECTED_EXCEPTION", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR", "SOCKET", "NATIVE_SESSION", "TUN_DESCRIPTOR", "CALLBACK", "NOTIFICATION", "HEALTH_MONITOR", "REVISION_LEASE"}, true, false},
	{"D08_STOP", "COORDINATOR", "STOP", "CANCEL", "STOPPED", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR"}, false, false},
	{"D08_REVOKE", "COORDINATOR", "REVOKE", "CANCEL", "REVOKED", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR"}, false, false},
	{"D08_BINDER_DEATH", "AUTHORITY_PROVIDER", "BINDER_DEATH", "CANCEL", "BINDER_DEAD", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR"}, false, false},
	{"D08_PROVIDER_DEATH", "AUTHORITY_PROVIDER", "PROCESS_DEATH", "CANCEL", "PROVIDER_DEAD", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR"}, false, false},
	{"D08_TIMEOUT", "COORDINATOR", "TIMEOUT", "TIMEOUT", "TIMEOUT", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR"}, false, false},
	{"D08_CLEANUP_RETRYABLE", "CLEANUP", "RETRYABLE", "RETURN", "CLEANUP_RETRYABLE", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR"}, false, false},
	{"D08_CLEANUP_UNPROVEN", "CLEANUP", "UNPROVEN", "RETURN", "CLEANUP_UNPROVEN", []string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR"}, false, true},
}

func deviceContractIDs(contracts []deviceCaseContract) []string {
	result := make([]string, 0, len(contracts))
	for _, contract := range contracts {
		result = append(result, contract.ID)
	}
	return result
}

var deviceD04Cases = deviceContractIDs(deviceD04Contracts)
var deviceD08Cases = deviceContractIDs(deviceD08Contracts)

func deviceCaseContractFor(id string) (deviceCaseContract, bool) {
	for _, contract := range append(append([]deviceCaseContract{}, deviceD04Contracts...), deviceD08Contracts...) {
		if contract.ID == id {
			return contract, true
		}
	}
	return deviceCaseContract{}, false
}

func deviceCaseMatches(caseID, requestID string) bool {
	_, ok := deviceCaseContractFor(caseID)
	return ok && hex32Pattern.MatchString(requestID)
}

func optionalDeviceCaseBinding(caseID, requestID string) bool {
	if caseID == "" {
		return requestID == "" || hex32Pattern.MatchString(requestID)
	}
	return deviceCaseMatches(caseID, requestID)
}

// DeviceCaseFact binds a verifier-owned required subcase to immutable controller
// fixture/action digests. It is not a verdict and cannot carry caller checks.
type DeviceCaseFact struct {
	CaseID        string `json:"caseId"`
	RequestID     string `json:"requestId"`
	FaultStage    string `json:"faultStage"`
	FaultMode     string `json:"faultMode"`
	FixtureSHA256 string `json:"fixtureSha256"`
	ActionSHA256  string `json:"actionSha256"`
}

// Trace, boundary, resource, and status facts are bounded raw observations.
// None can carry PASS/FAIL; the offline verifier derives the terminal outcome.
type DeviceTraceFact struct {
	CaseID     string        `json:"caseId"`
	RequestID  string        `json:"requestId"`
	TraceID    string        `json:"traceId"`
	Process    DeviceProcess `json:"process"`
	Stage      string        `json:"stage"`
	EventCount uint64        `json:"eventCount"`
	DropCount  uint64        `json:"dropCount"`
	GapCount   uint64        `json:"gapCount"`
}

type DeviceBoundaryFact struct {
	CaseID    string        `json:"caseId"`
	RequestID string        `json:"requestId"`
	TraceID   string        `json:"traceId"`
	Process   DeviceProcess `json:"process"`
	Ordinal   uint64        `json:"ordinal"`
	Stage     string        `json:"stage"`
	Event     string        `json:"event"`
	Code      string        `json:"code"`
}

type DeviceResourceFact struct {
	CaseID       string        `json:"caseId"`
	RequestID    string        `json:"requestId"`
	TraceID      string        `json:"traceId"`
	Process      DeviceProcess `json:"process"`
	Ordinal      uint64        `json:"ordinal"`
	ResourceKind string        `json:"resourceKind"`
	ResourceID   string        `json:"resourceId"`
	Operation    string        `json:"operation"`
}

type DeviceStatusFact struct {
	CaseID    string        `json:"caseId"`
	RequestID string        `json:"requestId"`
	Process   DeviceProcess `json:"process"`
	Surface   string        `json:"surface"`
	State     string        `json:"state"`
	Identity  string        `json:"identity"`
}

type DeviceFlowFact struct {
	FlowID          string `json:"flowId"`
	RequestID       string `json:"requestId"`
	NativeSessionID string `json:"nativeSessionId"`
	CaptureID       string `json:"captureId"`
	EgressID        string `json:"egressId"`
	InterfaceID     string `json:"interfaceId"`
	Direction       string `json:"direction"`
	Protocol        string `json:"protocol"`
	DestinationRole string `json:"destinationRole"`
	CorrelationID   string `json:"correlationId"`
	RouteRule       string `json:"routeRule"`
	RouteAction     string `json:"routeAction"`
	UID             uint64 `json:"uid"`
	Family          uint64 `json:"family"`
}

func deviceDigest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func deviceCanonicalDecode(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > MaxDeviceEvidenceBytes {
		return errors.New("device evidence size rejected")
	}
	if err := assurance.DecodeStrict(bytes.NewReader(raw), target); err != nil {
		return err
	}
	value := reflectDeviceValue(target)
	canonical, err := MarshalCanonical(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.New("device evidence is not canonical")
	}
	return nil
}
func reflectDeviceValue(target any) any {
	switch p := target.(type) {
	case *DeviceEvidence:
		return *p
	case *Envelope:
		return *p
	case *DeviceAuthorization:
		return *p
	case *DeviceClockReceipt:
		return *p
	case *DeviceObservation:
		return *p
	case *DeviceReceived:
		return *p
	case *DeviceTerminal:
		return *p
	case *DeviceProcess:
		return *p
	case *DeviceInstallFact:
		return *p
	case *DeviceRuntimeFact:
		return *p
	case *DeviceServiceFact:
		return *p
	case *DeviceCommandFact:
		return *p
	case *DeviceTunFact:
		return *p
	case *DeviceRouteFact:
		return *p
	case *DeviceEgressInventory:
		return *p
	case *DeviceCaptureFact:
		return *p
	case *DevicePacketFact:
		return *p
	case *DeviceProbeFact:
		return *p
	case *DeviceDNSFact:
		return *p
	case *DeviceLifecycleFact:
		return *p
	case *DeviceInterfaceFact:
		return *p
	case *DeviceCaseFact:
		return *p
	case *DeviceTraceFact:
		return *p
	case *DeviceBoundaryFact:
		return *p
	case *DeviceResourceFact:
		return *p
	case *DeviceStatusFact:
		return *p
	case *DeviceFlowFact:
		return *p
	default:
		panic("unsupported device evidence type")
	}
}
func DecodeDeviceEvidence(reader io.Reader) (DeviceEvidence, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, MaxDeviceEvidenceBytes+1))
	if err != nil {
		return DeviceEvidence{}, err
	}
	var value DeviceEvidence
	if err := deviceCanonicalDecode(raw, &value); err != nil {
		return DeviceEvidence{}, err
	}
	if value.Schema != DeviceEvidenceSchema || len(value.Received) == 0 || len(value.Received) > MaxDeviceEvents ||
		bytes.Equal(value.Authorization, []byte("null")) || bytes.Equal(value.Terminal, []byte("null")) {
		return DeviceEvidence{}, errors.New("device evidence structure rejected")
	}
	if err := validateDeviceSubject(value.Subject); err != nil {
		return DeviceEvidence{}, err
	}
	return value, nil
}
func validateDeviceSubject(s DeviceEvidenceSubject) error {
	if err := validateCandidateIdentity(s.Candidate); err != nil {
		return err
	}
	if !hex64Pattern.MatchString(s.ManifestSHA256) || !devicePackagePattern.MatchString(s.AppPackage) || len(s.AppPackage) > 128 ||
		!devicePackagePattern.MatchString(s.TestPackage) || len(s.TestPackage) > 128 || s.AppPackage == s.TestPackage ||
		!hex64Pattern.MatchString(s.AppCertificateSHA256) || !hex64Pattern.MatchString(s.TestCertificateSHA256) ||
		!hex32Pattern.MatchString(s.InstallID) || s.AppUID >= 0xffffffff || s.VersionCode == 0 || s.VersionCode > maxDeviceMono {
		return errors.New("device subject rejected")
	}
	for _, entry := range []ManifestEntry{s.AppAPK, s.TestAPK} {
		if !safeSourcePath(entry.Path) || !strings.HasSuffix(entry.Path, ".apk") || entry.Size == 0 || entry.Size > 1<<30 || !hex64Pattern.MatchString(entry.SHA256) {
			return errors.New("device artifact rejected")
		}
	}
	if s.AppAPK.Path == s.TestAPK.Path {
		return errors.New("device artifact alias rejected")
	}
	return nil
}

func deviceSign(private []byte, kind string, payload any) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("device signing key rejected")
	}
	raw, err := MarshalCanonical(payload)
	if err != nil {
		return nil, err
	}
	key, _ := KeyID(ed25519.PrivateKey(private).Public().(ed25519.PublicKey))
	signature := ed25519.Sign(private, signatureMessage(kind, raw))
	return MarshalCanonical(Envelope{EnvelopeSchema, kind, key, json.RawMessage(raw), hex.EncodeToString(signature)})
}
func SignDeviceAuthorization(private []byte, value DeviceAuthorization) ([]byte, error) {
	if err := validateDeviceAuthorization(value); err != nil {
		return nil, err
	}
	return deviceSign(private, "DEVICE_AUTHORIZATION", value)
}
func SignDeviceClock(private []byte, value DeviceClockReceipt) ([]byte, error) {
	if value.Schema != DeviceClockSchema || !hex64Pattern.MatchString(value.SubjectSHA256) || !hex32Pattern.MatchString(value.InvocationID) ||
		!hex32Pattern.MatchString(value.SessionID) || !hex32Pattern.MatchString(value.ObserverBootID) || !hex32Pattern.MatchString(value.Nonce) || value.LocalMonoMS > maxDeviceMono {
		return nil, errors.New("device clock receipt rejected")
	}
	return deviceSign(private, "DEVICE_CLOCK", value)
}
func SignDeviceObservation(private []byte, value DeviceObservation) ([]byte, error) {
	if err := validateDeviceObservation(value); err != nil {
		return nil, err
	}
	return deviceSign(private, "DEVICE_OBSERVATION", value)
}
func SignDeviceReceived(private []byte, value DeviceReceived) ([]byte, error) {
	if value.Schema != DeviceReceivedSchema || !hex64Pattern.MatchString(value.ContextSHA256) || value.ReceivedSequence == 0 ||
		value.ReceivedSequence > MaxDeviceEvents || !validPrevious(value.ReceivedSequence, value.PreviousSHA256) || !hex32Pattern.MatchString(value.ReceiverBootID) ||
		value.ReceivedMonoMS > maxDeviceMono || len(value.Observation) == 0 || len(value.Observation) > 64<<10 {
		return nil, errors.New("device received record rejected")
	}
	return deviceSign(private, "DEVICE_RECEIVED", value)
}
func validateDeviceAuthorization(v DeviceAuthorization) error {
	if v.Schema != DeviceAuthorizationSchema || !hex64Pattern.MatchString(v.SubjectSHA256) || !hex32Pattern.MatchString(v.InvocationID) ||
		!(regexp.MustCompile(`^D0[1-8]$`).MatchString(v.JourneyID) || v.JourneyID == "FIXTURE_CORE") || !hex32Pattern.MatchString(v.BootID) ||
		!hex32Pattern.MatchString(v.SessionID) || !validTimestamp(v.IssuedAt) || v.ControllerSequence == 0 || v.ControllerSequence > maxDeviceMono ||
		v.IssuedMonoMS > v.StartMonoMS || v.EndMonoMS <= v.StartMonoMS || v.EndMonoMS > maxDeviceMono || v.EndMonoMS-v.StartMonoMS > maxDeviceWindowMS ||
		!containsExact([]string{"SYNTHETIC", "AUTHORIZED_DEVICE"}, v.Provenance) || (v.JourneyID == "FIXTURE_CORE" && v.Provenance != "SYNTHETIC") ||
		len(v.Egress) == 0 || len(v.Egress) > 16 || len(v.Calibrations) == 0 || len(v.Calibrations) > 16 || len(v.RequiredTiers) == 0 || len(v.RequiredTiers) > 5 {
		return errors.New("device authorization rejected")
	}
	seen := map[string]bool{}
	for _, tier := range v.RequiredTiers {
		if !containsExact(deviceTiers, tier) || seen[tier] {
			return errors.New("device tier scope rejected")
		}
		seen[tier] = true
	}
	egressSeen := map[string]bool{}
	for _, e := range v.Egress {
		key := fmt.Sprintf("%s:%d", e.ID, e.Family)
		if !validDeviceEgress(e) || egressSeen[key] {
			return errors.New("device egress rejected")
		}
		egressSeen[key] = true
	}
	return nil
}
func validDeviceEgress(e DeviceEgress) bool {
	return hex32Pattern.MatchString(e.ID) && deviceFamily(e.Family) && containsExact([]string{"WIFI", "CELLULAR", "OTHER"}, e.Kind)
}
func deviceFamily(f uint64) bool { return f == 4 || f == 6 }
func validDeviceProcess(p DeviceProcess) bool {
	return containsExact([]string{"DEFAULT", "VPN"}, p.Role) && len(p.Name) > 0 && len(p.Name) <= 160 &&
		regexp.MustCompile(`^[a-zA-Z0-9_.:]+$`).MatchString(p.Name) && p.UID < 0xffffffff && p.PID > 0 && p.PID <= 0x7fffffff &&
		p.StartTimeMS > 0 && p.StartTimeMS <= maxDeviceMono && hex32Pattern.MatchString(p.Epoch) && containsExact([]string{"PRESENT", "ABSENT"}, p.State)
}
func validateDeviceObservation(v DeviceObservation) error {
	if v.Schema != DeviceObservationSchema || !hex64Pattern.MatchString(v.ContextSHA256) || !hex32Pattern.MatchString(v.ObserverBootID) || v.ObserverSequence == 0 || v.ObserverSequence > MaxDeviceEvents || v.ObservedMonoMS > maxDeviceMono || len(v.Data) > 32<<10 {
		return errors.New("device observation rejected")
	}
	_, err := decodeDeviceFact(v.EventType, v.Data)
	return err
}
func decodeDeviceFact(kind string, raw []byte) (any, error) {
	invalid := errors.New("device raw fact rejected")
	switch kind {
	case "INSTALL":
		var p DeviceInstallFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !hex32Pattern.MatchString(p.InstallID) || !devicePackagePattern.MatchString(p.AppPackage) || len(p.AppPackage) > 128 || !devicePackagePattern.MatchString(p.TestPackage) || len(p.TestPackage) > 128 || p.AppPackage == p.TestPackage || !hex64Pattern.MatchString(p.AppAPKSHA256) || !hex64Pattern.MatchString(p.TestAPKSHA256) || !hex64Pattern.MatchString(p.AppCertificateSHA256) || !hex64Pattern.MatchString(p.TestCertificateSHA256) || p.AppUID >= 0xffffffff || p.VersionCode == 0 || p.VersionCode > maxDeviceMono {
			return nil, invalid
		}
		return p, nil
	case "PROCESS":
		var p DeviceProcess
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !validDeviceProcess(p) {
			return nil, invalid
		}
		return p, nil
	case "RUNTIME":
		var p DeviceRuntimeFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !validDeviceProcess(p.Process) || !hex32Pattern.MatchString(p.VPNEpoch) || !hex32Pattern.MatchString(p.RequestID) || p.Generation == 0 || p.Generation > 0x7fffffffffffffff || p.Revision == 0 || p.Revision > 0x7fffffffffffffff || p.Revision%2 != 0 ||
			!containsExact([]string{"REQUEST", "REVISION_READ", "DESCRIPTOR_WRITE", "ADMIT", "NATIVE_AUTHENTICATED", "ACTIVE", "TERMINAL"}, p.Stage) ||
			!containsExact([]string{"FULL_AUTHORITY", "PRE_DESCRIPTOR", "PRE_ACTIVE"}, p.Purpose) || !hex32Pattern.MatchString(p.CapabilityChannelID) || !hex32Pattern.MatchString(p.FrameChannelID) || p.CapabilityChannelID == p.FrameChannelID || !hex32Pattern.MatchString(p.DescriptorID) {
			return nil, invalid
		}
		for _, id := range []string{p.NativeSessionID, p.VPNSessionID, p.TunID} {
			if id != "" && !hex32Pattern.MatchString(id) {
				return nil, invalid
			}
		}
		return p, nil
	case "SERVICE":
		var p DeviceServiceFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !validDeviceProcess(p.Process) || p.Process.Role != "VPN" || p.Process.State != "PRESENT" ||
			len(p.Component) == 0 || len(p.Component) > 256 || !regexp.MustCompile(`^[a-zA-Z0-9_./]+$`).MatchString(p.Component) ||
			!containsExact([]string{"ON_START_COMMAND", "ON_REVOKE"}, p.Method) ||
			len(p.Action) > 160 || (p.Action != "" && !regexp.MustCompile(`^[a-zA-Z0-9_.]+$`).MatchString(p.Action)) ||
			p.StartID > 0x7fffffff || p.CallerUID >= 0xffffffff || p.Flags > 0xffffffff || !hex32Pattern.MatchString(p.DispatchID) ||
			!containsExact([]string{"ABSENT", "PRIVATE_V2", "MALFORMED"}, p.Marker) ||
			(p.Method == "ON_START_COMMAND" && p.StartID == 0) ||
			(p.Method == "ON_REVOKE" && (p.Action != "" || p.StartID != 0 || p.Marker != "ABSENT")) {
			return nil, invalid
		}
		return p, nil
	case "COMMAND":
		var p DeviceCommandFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !deviceCaseMatches(p.CaseID, p.RequestID) || !validDeviceProcess(p.Process) || p.Process.Role != "VPN" || p.Process.State != "PRESENT" ||
			len(p.Component) == 0 || len(p.Component) > 256 || !regexp.MustCompile(`^[a-zA-Z0-9_./]+$`).MatchString(p.Component) || p.Method != "ON_START_COMMAND" ||
			len(p.Action) > 160 || (p.Action != "" && !regexp.MustCompile(`^[a-zA-Z0-9_.]+$`).MatchString(p.Action)) || p.StartID == 0 || p.StartID > 0x7fffffff ||
			p.CallerUID >= 0xffffffff || p.Flags > 0xffffffff || !hex32Pattern.MatchString(p.DispatchID) || !containsExact([]string{"ABSENT", "PRIVATE_V2", "MALFORMED"}, p.Marker) {
			return nil, invalid
		}
		return p, nil
	case "TUN":
		var p DeviceTunFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !validDeviceProcess(p.Process) || p.Process.Role != "VPN" || !hex32Pattern.MatchString(p.TunID) || !hex32Pattern.MatchString(p.InterfaceID) || p.MTU < 1280 || p.MTU > 1500 || !containsExact([]string{"PRESENT", "ABSENT"}, p.State) {
			return nil, invalid
		}
		return p, nil
	case "ROUTE":
		var p DeviceRouteFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !validDeviceProcess(p.Process) || p.Process.Role != "VPN" || !hex32Pattern.MatchString(p.TunID) || !hex32Pattern.MatchString(p.InterfaceID) || !deviceFamily(p.Family) || !containsExact([]string{"BEFORE", "AFTER"}, p.Stage) ||
			!((p.Family == 4 && p.DestinationPrefix == "0.0.0.0/0") || (p.Family == 6 && p.DestinationPrefix == "::/0")) || p.MTU < 1280 || p.MTU > 1500 || len(p.AddressPrefixes) == 0 || len(p.AddressPrefixes) > 2 || len(p.PolicyRules) == 0 || len(p.PolicyRules) > 16 || len(p.AllowedUIDs) > 256 || len(p.DisallowedUIDs) > 256 {
			return nil, invalid
		}
		for _, address := range p.AddressPrefixes {
			prefix, err := netip.ParsePrefix(address)
			if err != nil || !prefix.Addr().IsPrivate() || prefix.String() != address {
				return nil, invalid
			}
		}
		for _, rule := range p.PolicyRules {
			if !containsExact([]string{"APP_UID_TUN", "ALLOW_UID_SET", "DENY_UID_SET"}, rule) {
				return nil, invalid
			}
		}
		for _, uid := range append(append([]uint64{}, p.AllowedUIDs...), p.DisallowedUIDs...) {
			if uid >= 0xffffffff {
				return nil, invalid
			}
		}
		return p, nil
	case "EGRESS":
		var p DeviceEgressInventory
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !containsExact([]string{"BEFORE", "AFTER"}, p.Stage) || len(p.Interfaces) == 0 || len(p.Interfaces) > 16 {
			return nil, invalid
		}
		for _, e := range p.Interfaces {
			if !validDeviceEgress(e) {
				return nil, invalid
			}
		}
		return p, nil
	case "CAPTURE":
		var p DeviceCaptureFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !hex32Pattern.MatchString(p.CaptureID) || !hex32Pattern.MatchString(p.EgressID) || !deviceFamily(p.Family) || !containsExact([]string{"OPEN", "CLOSE"}, p.Stage) || p.PacketCount > MaxDeviceEvents || p.DropCount > maxDeviceMono || p.GapCount > maxDeviceMono || p.InterfaceRevision == 0 || p.InterfaceRevision > maxDeviceMono {
			return nil, invalid
		}
		return p, nil
	case "PACKET":
		var p DevicePacketFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !hex32Pattern.MatchString(p.CaptureID) || !hex32Pattern.MatchString(p.EgressID) || !deviceFamily(p.Family) || p.Ordinal == 0 || p.Ordinal > MaxDeviceEvents || !containsExact([]string{"OUTBOUND", "INBOUND"}, p.Direction) || !containsExact([]string{"TCP", "UDP"}, p.Protocol) || !containsExact([]string{"TUNNEL_GATEWAY", "CONTROLLED_PROBE", "PROTECTED_RESOLVER", "DIRECT_RESOLVER", "OTHER"}, p.DestinationRole) || p.Length == 0 || p.Length > 65535 {
			return nil, invalid
		}
		for _, id := range []string{p.ProbeID, p.Nonce, p.NativeSessionID, p.TranscriptID, p.DNSTransactionID} {
			if id != "" && !hex32Pattern.MatchString(id) {
				return nil, invalid
			}
		}
		return p, nil
	case "PROBE":
		var p DeviceProbeFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !hex32Pattern.MatchString(p.ProbeID) || !hex32Pattern.MatchString(p.Nonce) || !hex32Pattern.MatchString(p.NativeSessionID) || !hex32Pattern.MatchString(p.TranscriptID) || !deviceFamily(p.Family) || !containsExact([]string{"TCP", "UDP"}, p.Protocol) || !containsExact([]string{"RECEIVED", "RESPONDED"}, p.Stage) || p.Bytes == 0 || p.Bytes > 65535 {
			return nil, invalid
		}
		return p, nil
	case "DNS", "DNS_RECEIPT":
		var p DeviceDNSFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !hex32Pattern.MatchString(p.TransactionID) || !hex32Pattern.MatchString(p.QueryToken) || !deviceFamily(p.Family) || !containsExact([]string{"OUTBOUND", "INBOUND"}, p.Direction) || !containsExact([]string{"PROTECTED_RESOLVER", "DIRECT_RESOLVER"}, p.ResolverRole) || !containsExact([]string{"UDP", "TCP"}, p.Transport) || !containsExact([]string{"A", "AAAA"}, p.QueryType) || p.ResponseCode > 15 || !(p.AnswerFamily == 0 || deviceFamily(p.AnswerFamily)) || !containsExact([]string{"NONE", "TCP_COMPLETED"}, p.Fallback) || !hex32Pattern.MatchString(p.NativeSessionID) || !hex32Pattern.MatchString(p.CaptureID) || !hex32Pattern.MatchString(p.EgressID) || p.PacketOrdinal == 0 || p.PacketOrdinal > MaxDeviceEvents || !containsExact([]string{"QUERY", "RESPONSE"}, p.Stage) {
			return nil, invalid
		}
		return p, nil
	case "LIFECYCLE":
		var p DeviceLifecycleFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !containsExact([]string{"BOOT", "USER_LOCKED", "USER_UNLOCKED", "SERVICE_START", "PROCESS_EXIT", "PROCESS_START", "ACTIVITY_ABSENT", "TUN_REMOVED"}, p.Action) ||
			!hex32Pattern.MatchString(p.CurrentBootID) || (p.PreviousBootID != "" && !hex32Pattern.MatchString(p.PreviousBootID)) ||
			(p.RequestID != "" && !hex32Pattern.MatchString(p.RequestID)) {
			return nil, invalid
		}
		if containsExact([]string{"SERVICE_START", "PROCESS_EXIT", "PROCESS_START", "TUN_REMOVED"}, p.Action) && (!validDeviceProcess(p.Process) || p.RequestID == "") {
			return nil, invalid
		}
		if p.Action == "ACTIVITY_ABSENT" && p.RequestID == "" {
			return nil, invalid
		}
		if p.Action == "BOOT" && (p.PreviousBootID == "" || p.PreviousBootID == p.CurrentBootID) {
			return nil, invalid
		}
		return p, nil
	case "INTERFACE":
		var p DeviceInterfaceFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !hex32Pattern.MatchString(p.InterfaceID) || !hex32Pattern.MatchString(p.EgressID) || !deviceFamily(p.Family) || !containsExact([]string{"PRESENT", "ABSENT"}, p.State) {
			return nil, invalid
		}
		return p, nil
	case "CASE":
		var p DeviceCaseFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		contract, ok := deviceCaseContractFor(p.CaseID)
		if !ok || p.FaultStage != contract.Stage || p.FaultMode != contract.Fault || !hex32Pattern.MatchString(p.RequestID) || !hex64Pattern.MatchString(p.FixtureSHA256) || !hex64Pattern.MatchString(p.ActionSHA256) {
			return nil, invalid
		}
		return p, nil
	case "TRACE":
		var p DeviceTraceFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !deviceCaseMatches(p.CaseID, p.RequestID) || !hex32Pattern.MatchString(p.TraceID) || !validDeviceProcess(p.Process) ||
			!containsExact([]string{"OPEN", "CLOSE"}, p.Stage) || p.EventCount > MaxDeviceEvents || p.DropCount > maxDeviceMono || p.GapCount > maxDeviceMono ||
			(p.Stage == "OPEN" && p.EventCount != 0) {
			return nil, invalid
		}
		return p, nil
	case "BOUNDARY":
		var p DeviceBoundaryFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		contract, ok := deviceCaseContractFor(p.CaseID)
		if !ok || !deviceCaseMatches(p.CaseID, p.RequestID) || !hex32Pattern.MatchString(p.TraceID) || !validDeviceProcess(p.Process) ||
			p.Ordinal == 0 || p.Ordinal > MaxDeviceEvents || p.Stage != contract.Stage || !containsExact([]string{"ENTER", "RETURN", "THROW", "CANCEL", "TIMEOUT"}, p.Event) ||
			!containsExact([]string{"NONE", "REJECTED", "FALSE", "NULL", "INJECTED_EXCEPTION", "STALE", "STOPPED", "REVOKED", "BINDER_DEAD", "PROVIDER_DEAD", "TIMEOUT", "CLEANUP_RETRYABLE", "CLEANUP_UNPROVEN"}, p.Code) ||
			(p.Event == "ENTER" && p.Code != "NONE") || (p.Event != "ENTER" && p.Code == "NONE") {
			return nil, invalid
		}
		return p, nil
	case "RESOURCE":
		var p DeviceResourceFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !deviceCaseMatches(p.CaseID, p.RequestID) || !hex32Pattern.MatchString(p.TraceID) || !validDeviceProcess(p.Process) || p.Ordinal == 0 || p.Ordinal > MaxDeviceEvents ||
			!containsExact([]string{"SENSITIVE_BUFFER", "AUTHORITY_DESCRIPTOR", "SOCKET", "NATIVE_SESSION", "TUN_DESCRIPTOR", "CALLBACK", "NOTIFICATION", "HEALTH_MONITOR", "REVISION_LEASE"}, p.ResourceKind) ||
			!hex32Pattern.MatchString(p.ResourceID) || !containsExact([]string{"ACQUIRE", "TRANSFER", "CLOSE", "WIPE", "REGISTER", "REMOVE"}, p.Operation) {
			return nil, invalid
		}
		return p, nil
	case "STATUS":
		var p DeviceStatusFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !deviceCaseMatches(p.CaseID, p.RequestID) || !validDeviceProcess(p.Process) ||
			!containsExact([]string{"FOREGROUND_NOTIFICATION", "VPN_REGISTRATION", "RUNTIME_PUBLICATION"}, p.Surface) ||
			!containsExact([]string{"ABSENT", "CONNECTING", "FAILED", "ACTIVE", "CLEANUP_UNPROVEN"}, p.State) || !hex32Pattern.MatchString(p.Identity) {
			return nil, invalid
		}
		return p, nil
	case "FLOW":
		var p DeviceFlowFact
		if err := deviceCanonicalDecode(raw, &p); err != nil {
			return nil, err
		}
		if !hex32Pattern.MatchString(p.FlowID) || !hex32Pattern.MatchString(p.RequestID) || (p.NativeSessionID != "" && !hex32Pattern.MatchString(p.NativeSessionID)) || !hex32Pattern.MatchString(p.CaptureID) || !hex32Pattern.MatchString(p.EgressID) || !hex32Pattern.MatchString(p.InterfaceID) || !containsExact([]string{"OUTBOUND", "INBOUND"}, p.Direction) || !containsExact([]string{"TCP", "UDP", "DNS"}, p.Protocol) || !containsExact([]string{"CONTROLLED_PROBE", "PROTECTED_RESOLVER", "DIRECT_RESOLVER"}, p.DestinationRole) || !hex32Pattern.MatchString(p.CorrelationID) || p.UID >= 0xffffffff || !deviceFamily(p.Family) || !containsExact([]string{"APP_UID_TUN", "DENY_UID_SET"}, p.RouteRule) || !containsExact([]string{"LOOKUP_TUN", "LOOKUP_DENY"}, p.RouteAction) || (p.RouteRule == "APP_UID_TUN" && p.RouteAction != "LOOKUP_TUN") || (p.RouteRule == "DENY_UID_SET" && p.RouteAction != "LOOKUP_DENY") || (p.RouteAction == "LOOKUP_TUN" && p.NativeSessionID == "") {
			return nil, invalid
		}
		return p, nil
	default:
		return nil, errors.New("device event type rejected")
	}
}
