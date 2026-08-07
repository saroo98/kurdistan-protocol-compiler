// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase17verify checks the public, machine-readable live data-plane
// contract without accepting a wider transport or deployment authority.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const contractPath = "config/runtime/live-data-plane-v1.json"

type contract struct {
	Schema        string                 `json:"schema"`
	RuntimePolicy runtimePolicyAuthority `json:"runtimePolicy"`
	Wire          wireAuthority          `json:"wire"`
	Android       androidAuthority       `json:"android"`
	Relay         relayAuthority         `json:"relay"`
	Limits        limitsAuthority        `json:"limits"`
	Network       networkAuthority       `json:"network"`
	Privacy       privacyAuthority       `json:"privacy"`
}

type runtimePolicyAuthority struct {
	Schema                              string   `json:"schema"`
	WireProtocol                        string   `json:"wireProtocol"`
	CarrierFamily                       string   `json:"carrierFamily"`
	CBORFields                          []string `json:"cborFields"`
	LiveProgramMinBytes                 int      `json:"liveProgramMinBytes"`
	LiveProgramMaxBytes                 int      `json:"liveProgramMaxBytes"`
	LiveProgramDigest                   string   `json:"liveProgramDigest"`
	LiveProgramForbiddenInputs          []string `json:"liveProgramForbiddenInputs"`
	LiveProgramCanonicalReencoding      bool     `json:"liveProgramCanonicalReencoding"`
	LiveProgramIndependentValidation    []string `json:"liveProgramIndependentValidation"`
	LiveProgramCannotWidenOuterPolicy   bool     `json:"liveProgramCannotWidenOuterPolicy"`
	ClientKeyIDBytes                    int      `json:"clientKeyIDBytes"`
	KeyIDFormat                         string   `json:"keyIDFormat"`
	KeyIDDerivation                     string   `json:"keyIDDerivation"`
	ClientPublicKeyBytes                int      `json:"clientPublicKeyBytes"`
	RelayKeyID                          string   `json:"relayKeyID"`
	RelayPublicKeyBytes                 int      `json:"relayPublicKeyBytes"`
	TLSServerNameMaxBytes               int      `json:"tlsServerNameMaxBytes"`
	TLSServerNameKinds                  []string `json:"tlsServerNameKinds"`
	TLSLeafMinBytes                     int      `json:"tlsLeafMinBytes"`
	TLSLeafMaxBytes                     int      `json:"tlsLeafMaxBytes"`
	TLSDigest                           string   `json:"tlsDigest"`
	TLSCertificateRequirements          []string `json:"tlsCertificateRequirements"`
	EndpointMinimum                     int      `json:"endpointMinimum"`
	EndpointMaximum                     int      `json:"endpointMaximum"`
	EndpointIPLiteralsOnly              bool     `json:"endpointIPLiteralsOnly"`
	EndpointFields                      []string `json:"endpointFields"`
	IPv4Bytes                           int      `json:"ipv4Bytes"`
	IPv6Bytes                           int      `json:"ipv6Bytes"`
	AddressAbsentWhenUnauthorized       bool     `json:"addressAbsentWhenUnauthorized"`
	RoutesCanonical                     bool     `json:"routesCanonical"`
	DNSRestrictedToTUN                  bool     `json:"dnsRestrictedToTun"`
	IssuedMTU                           int      `json:"issuedMtu"`
	MinimumMTU                          int      `json:"minimumMtu"`
	MaximumMTU                          int      `json:"maximumMtu"`
	AllowedIPModes                      []string `json:"allowedIPModes"`
	AllowedIPModesSortedUnique          bool     `json:"allowedIPModesSortedUnique"`
	PayloadProtocols                    []string `json:"payloadProtocols"`
	FallbackOrdered                     bool     `json:"fallbackOrdered"`
	FallbackReferencesExistingEndpoints bool     `json:"fallbackReferencesExistingEndpoints"`
	AdmissionDigest                     string   `json:"admissionDigest"`
	DecoderRejects                      []string `json:"decoderRejects"`
	UserMayOnlyNarrow                   bool     `json:"userMayOnlyNarrow"`
}

type wireAuthority struct {
	HeaderMagic                        string   `json:"headerMagic"`
	HeaderBytes                        int      `json:"headerBytes"`
	MajorVersion                       int      `json:"majorVersion"`
	MinorVersion                       int      `json:"minorVersion"`
	CarrierTLSVersion                  string   `json:"carrierTLSVersion"`
	ALPN                               string   `json:"alpn"`
	ExporterLabel                      string   `json:"exporterLabel"`
	ReliableDataRecordType             int      `json:"reliableDataRecordType"`
	ProfileBindRecordType              int      `json:"profileBindRecordType"`
	EngineReadyRecordType              int      `json:"engineReadyRecordType"`
	CloseRecordType                    int      `json:"closeRecordType"`
	ApplicationSlotMinimum             int      `json:"applicationSlotMinimum"`
	ApplicationSlotMaximum             int      `json:"applicationSlotMaximum"`
	PaddingKeepaliveSlot               int      `json:"paddingKeepaliveSlot"`
	ControlSlot                        int      `json:"controlSlot"`
	PacketSemantic                     string   `json:"packetSemantic"`
	PacketPerOperation                 bool     `json:"packetPerOperation"`
	SlotSelection                      string   `json:"slotSelection"`
	SlotHMAC                           string   `json:"slotHmac"`
	InnerFraming                       string   `json:"innerFraming"`
	OuterAuthentication                string   `json:"outerAuthentication"`
	PaddingKeepaliveSeconds            int      `json:"paddingKeepaliveSeconds"`
	UnauthenticatedPeerIdleSeconds     int      `json:"unauthenticatedPeerIdleSeconds"`
	ReplayCommit                       string   `json:"replayCommit"`
	ReplayFailure                      string   `json:"replayFailure"`
	TCPKeepaliveRole                   string   `json:"tcpKeepaliveRole"`
	PacketAcknowledgements             bool     `json:"packetAcknowledgements"`
	LegacyAdapters                     []string `json:"legacyAdapters"`
	LiveFramingNoProfileReconstruction bool     `json:"liveFramingNoProfileReconstruction"`
}

type androidAuthority struct {
	NativeOnly         bool     `json:"nativeOnly"`
	ProtectMustSucceed bool     `json:"protectMustSucceed"`
	Lifecycle          []string `json:"lifecycle"`
}

type relayAuthority struct {
	ListenerFileDescriptor     int      `json:"listenerFileDescriptor"`
	ServiceUser                string   `json:"serviceUser"`
	ServiceGroup               string   `json:"serviceGroup"`
	TUNName                    string   `json:"tunName"`
	TUNPacketInfo              bool     `json:"tunPacketInfo"`
	TUNKeepCarrier             bool     `json:"tunKeepCarrier"`
	PrivateDevices             bool     `json:"privateDevices"`
	DevicePolicy               string   `json:"devicePolicy"`
	TUNDeviceAccess            string   `json:"tunDeviceAccess"`
	NoAmbientCapabilities      bool     `json:"noAmbientCapabilities"`
	EmptyCapabilityBoundingSet bool     `json:"emptyCapabilityBoundingSet"`
	AddressFamilies            []string `json:"addressFamilies"`
	FirewallOwner              string   `json:"firewallOwner"`
	SysctlOwner                string   `json:"sysctlOwner"`
	DNSService                 string   `json:"dnsService"`
	DNSSEC                     bool     `json:"dnssec"`
	DNSQueryLogging            bool     `json:"dnsQueryLogging"`
	DNSBind                    string   `json:"dnsBind"`
	DNSClients                 string   `json:"dnsClients"`
	DNSMinimiseQueryNames      bool     `json:"dnsMinimiseQueryNames"`
	DNSHideIdentityVersion     bool     `json:"dnsHideIdentityVersion"`
	ControlSocketDirectory     string   `json:"controlSocketDirectory"`
	ControlOperations          []string `json:"controlOperations"`
	ControlSocketAccess        string   `json:"controlSocketAccess"`
	PublicListener             string   `json:"publicListener"`
}

type limitsAuthority struct {
	ReferenceVCPU                              int    `json:"referenceVcpu"`
	ReferenceMemoryMiB                         int    `json:"referenceMemoryMiB"`
	PreAuthenticationConnections               int    `json:"preAuthenticationConnections"`
	SimultaneousHandshakes                     int    `json:"simultaneousHandshakes"`
	AuthenticatedSessions                      int    `json:"authenticatedSessions"`
	HandshakeDeadlineSeconds                   int    `json:"handshakeDeadlineSeconds"`
	DirectionalSessionQueuePackets             int    `json:"directionalSessionQueuePackets"`
	IncompleteOperationsPerSession             int    `json:"incompleteOperationsPerSession"`
	ReconstructionDeadlineSeconds              int    `json:"reconstructionDeadlineSeconds"`
	IssuedMTU                                  int    `json:"issuedMtu"`
	InnerFragmentsPerOperation                 int    `json:"innerFragmentsPerOperation"`
	ProcessPacketBufferMiB                     int    `json:"processPacketBufferMiB"`
	SystemdMemoryMaxMiB                        int    `json:"systemdMemoryMaxMiB"`
	SystemdTasksMax                            int    `json:"systemdTasksMax"`
	SystemdLimitNOFILE                         int    `json:"systemdLimitNofile"`
	ReconnectAttempts                          int    `json:"reconnectAttempts"`
	ReconnectDelaysSeconds                     []int  `json:"reconnectDelaysSeconds"`
	ReconnectDelayCapSeconds                   int    `json:"reconnectDelayCapSeconds"`
	AuthenticatedIdleSeconds                   int    `json:"authenticatedIdleSeconds"`
	PreAuthenticationRateLimit                 string `json:"preAuthenticationRateLimit"`
	RateLimitExpirySeconds                     int    `json:"rateLimitExpirySeconds"`
	CeilingUseMustRemainMateriallyBelowMaximum bool   `json:"ceilingUseMustRemainMateriallyBelowMaximum"`
	SignedProgramMayNarrowFragmentLimit        bool   `json:"signedProgramMayNarrowFragmentLimit"`
}

type networkAuthority struct {
	IPv4Pool                      string   `json:"ipv4Pool"`
	IPv4ServerDNS                 string   `json:"ipv4ServerDns"`
	IPv4ClientPrefix              int      `json:"ipv4ClientPrefix"`
	IPv6Pool                      string   `json:"ipv6Pool"`
	IPv6ServerDNS                 string   `json:"ipv6ServerDns"`
	IPv6ClientPrefix              int      `json:"ipv6ClientPrefix"`
	AddressReuse                  string   `json:"addressReuse"`
	RevocationQuarantine          string   `json:"revocationQuarantine"`
	FullTunnelRoutes              []string `json:"fullTunnelRoutes"`
	PrivateNetworkAccess          string   `json:"privateNetworkAccess"`
	BlockedDestinationClasses     []string `json:"blockedDestinationClasses"`
	BlockedDestinationExceptions  []string `json:"blockedDestinationExceptions"`
	IPv6IssuanceRequirements      []string `json:"ipv6IssuanceRequirements"`
	SpoofedSourceAddressesBlocked bool     `json:"spoofedSourceAddressesBlocked"`
	IPv6WithoutEvidence           string   `json:"ipv6WithoutEvidence"`
}

type privacyAuthority struct {
	LogPayloadContents         bool     `json:"logPayloadContents"`
	PersistFiveTuple           bool     `json:"persistFiveTuple"`
	LogFiveTuple               bool     `json:"logFiveTuple"`
	TelemetryDefault           string   `json:"telemetryDefault"`
	PublicResolversAllowed     bool     `json:"publicResolversAllowed"`
	LiveProgramForbiddenInputs []string `json:"liveProgramForbiddenInputs"`
}

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	if err := verify(*root); err != nil {
		fmt.Fprintf(os.Stderr, "PHASE 17 LIVE DATA-PLANE VERIFICATION FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PHASE 17 LIVE DATA-PLANE VERIFICATION PASSED")
}

func verify(root string) error {
	value, err := loadContract(root)
	if err != nil {
		return err
	}
	if err := validateContract(value); err != nil {
		return err
	}
	if err := verifyGoCopies(root, value); err != nil {
		return err
	}
	if err := verifyDeploymentCopies(root, value); err != nil {
		return err
	}
	if err := verifyPublicDocumentation(root, value); err != nil {
		return err
	}
	return nil
}

func loadContract(root string) (contract, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(contractPath)))
	if err != nil {
		return contract{}, fmt.Errorf("read live data-plane authority: %w", err)
	}
	return decodeContract(raw)
}

func decodeContract(raw []byte) (contract, error) {
	if err := rejectDuplicateKeys(raw); err != nil {
		return contract{}, fmt.Errorf("decode live data-plane authority: %w", err)
	}
	if err := requireJSONFields(raw, reflect.TypeFor[contract]()); err != nil {
		return contract{}, fmt.Errorf("decode live data-plane authority: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value contract
	if err := decoder.Decode(&value); err != nil {
		return contract{}, fmt.Errorf("decode live data-plane authority: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return contract{}, errors.New("decode live data-plane authority: trailing JSON value")
		}
		return contract{}, fmt.Errorf("decode live data-plane authority trailing JSON: %w", err)
	}
	return value, nil
}

func requireJSONFields(raw []byte, typ reflect.Type) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		encoded, present := fields[name]
		if !present {
			return fmt.Errorf("missing required field %q", name)
		}
		fieldType := field.Type
		for fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}
		if fieldType.Kind() == reflect.Struct {
			if err := requireJSONFields(encoded, fieldType); err != nil {
				return fmt.Errorf("field %q: %w", name, err)
			}
		}
	}
	return nil
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON token")
		}
		return fmt.Errorf("trailing JSON token: %w", err)
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not text")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func validateContract(value contract) error {
	if value.Schema != "kurd-live-data-plane-v1" || value.RuntimePolicy.Schema != "kurd-runtime-policy-v2" {
		return errors.New("unexpected live data-plane authority schema")
	}
	if value.RuntimePolicy.WireProtocol == "" || value.RuntimePolicy.CarrierFamily == "" ||
		value.Wire.HeaderMagic == "" || value.Wire.ALPN == "" || value.Wire.ExporterLabel == "" {
		return errors.New("protocol authority is incomplete")
	}
	if value.RuntimePolicy.LiveProgramMinBytes < 1 || value.RuntimePolicy.LiveProgramMinBytes > value.RuntimePolicy.LiveProgramMaxBytes ||
		value.RuntimePolicy.ClientKeyIDBytes < 1 || value.RuntimePolicy.ClientPublicKeyBytes < 1 || value.RuntimePolicy.RelayPublicKeyBytes < 1 ||
		value.RuntimePolicy.KeyIDDerivation == "" || value.RuntimePolicy.RelayKeyID == "" ||
		value.RuntimePolicy.TLSLeafMinBytes < 1 || value.RuntimePolicy.TLSLeafMinBytes > value.RuntimePolicy.TLSLeafMaxBytes ||
		value.RuntimePolicy.EndpointMinimum < 1 || value.RuntimePolicy.EndpointMinimum > value.RuntimePolicy.EndpointMaximum ||
		value.RuntimePolicy.MinimumMTU > value.RuntimePolicy.IssuedMTU || value.RuntimePolicy.IssuedMTU > value.RuntimePolicy.MaximumMTU ||
		!value.RuntimePolicy.EndpointIPLiteralsOnly || !value.RuntimePolicy.RoutesCanonical || !value.RuntimePolicy.DNSRestrictedToTUN ||
		!value.RuntimePolicy.AddressAbsentWhenUnauthorized || !value.RuntimePolicy.AllowedIPModesSortedUnique ||
		!value.RuntimePolicy.FallbackOrdered || !value.RuntimePolicy.FallbackReferencesExistingEndpoints || !value.RuntimePolicy.UserMayOnlyNarrow ||
		!value.RuntimePolicy.LiveProgramCanonicalReencoding || !value.RuntimePolicy.LiveProgramCannotWidenOuterPolicy {
		return errors.New("runtime policy limits are unsafe or incomplete")
	}
	if len(value.RuntimePolicy.CBORFields) != 25 || !uniqueNonEmpty(value.RuntimePolicy.CBORFields) ||
		!uniqueNonEmpty(value.RuntimePolicy.LiveProgramForbiddenInputs) || !uniqueNonEmpty(value.RuntimePolicy.LiveProgramIndependentValidation) ||
		!uniqueNonEmpty(value.RuntimePolicy.TLSServerNameKinds) || !uniqueNonEmpty(value.RuntimePolicy.TLSCertificateRequirements) ||
		!uniqueNonEmpty(value.RuntimePolicy.EndpointFields) || !uniqueNonEmpty(value.RuntimePolicy.AllowedIPModes) ||
		!uniqueNonEmpty(value.RuntimePolicy.PayloadProtocols) || !uniqueNonEmpty(value.RuntimePolicy.DecoderRejects) {
		return errors.New("runtime policy fields are incomplete")
	}
	if value.Wire.HeaderBytes < 1 || value.Wire.MajorVersion < 1 || value.Wire.MinorVersion < 0 ||
		value.Wire.ReliableDataRecordType < 1 || value.Wire.ProfileBindRecordType < 1 || value.Wire.EngineReadyRecordType < 1 || value.Wire.CloseRecordType < 1 ||
		value.Wire.ApplicationSlotMinimum < 1 || value.Wire.ApplicationSlotMinimum > value.Wire.ApplicationSlotMaximum ||
		value.Wire.ApplicationSlotMaximum >= value.Wire.PaddingKeepaliveSlot || value.Wire.PaddingKeepaliveSlot >= value.Wire.ControlSlot ||
		!value.Wire.PacketPerOperation || value.Wire.PacketAcknowledgements || value.Wire.PaddingKeepaliveSeconds < 1 ||
		value.Wire.UnauthenticatedPeerIdleSeconds < value.Wire.PaddingKeepaliveSeconds || !value.Wire.LiveFramingNoProfileReconstruction ||
		!uniqueNonEmpty(value.Wire.LegacyAdapters) {
		return errors.New("wire authority is unsafe or incomplete")
	}
	if !value.Android.NativeOnly || !value.Android.ProtectMustSucceed || len(value.Android.Lifecycle) != 8 || !uniqueNonEmpty(value.Android.Lifecycle) {
		return errors.New("android ownership authority is incomplete")
	}
	if value.Relay.ListenerFileDescriptor < 3 || value.Relay.ServiceUser == "" || value.Relay.ServiceGroup == "" || value.Relay.TUNName == "" ||
		value.Relay.TUNPacketInfo || !value.Relay.TUNKeepCarrier || value.Relay.PrivateDevices || value.Relay.DevicePolicy == "" ||
		value.Relay.TUNDeviceAccess != "rw" || !value.Relay.NoAmbientCapabilities || !value.Relay.EmptyCapabilityBoundingSet ||
		value.Relay.FirewallOwner != "root" || value.Relay.SysctlOwner != "root" || value.Relay.DNSService == "" || !value.Relay.DNSSEC ||
		value.Relay.DNSQueryLogging || !value.Relay.DNSMinimiseQueryNames || !value.Relay.DNSHideIdentityVersion || value.Relay.ControlSocketDirectory == "" ||
		value.Relay.ControlSocketAccess == "" || !uniqueNonEmpty(value.Relay.AddressFamilies) || !uniqueNonEmpty(value.Relay.ControlOperations) {
		return errors.New("relay privilege authority is unsafe or incomplete")
	}
	if value.Limits.ReferenceVCPU < 1 || value.Limits.ReferenceMemoryMiB < 1 || value.Limits.PreAuthenticationConnections < value.Limits.AuthenticatedSessions ||
		value.Limits.SimultaneousHandshakes > value.Limits.PreAuthenticationConnections || value.Limits.AuthenticatedSessions < 1 ||
		value.Limits.HandshakeDeadlineSeconds < 1 || value.Limits.DirectionalSessionQueuePackets < 1 || value.Limits.IncompleteOperationsPerSession < 1 ||
		value.Limits.ReconstructionDeadlineSeconds < 1 || value.Limits.IssuedMTU != value.RuntimePolicy.IssuedMTU || value.Limits.InnerFragmentsPerOperation < 1 ||
		value.Limits.ProcessPacketBufferMiB < 1 || value.Limits.SystemdMemoryMaxMiB < value.Limits.ProcessPacketBufferMiB || value.Limits.SystemdTasksMax < 1 ||
		value.Limits.SystemdLimitNOFILE < 1 || value.Limits.ReconnectAttempts < 1 || len(value.Limits.ReconnectDelaysSeconds) != value.Limits.ReconnectAttempts ||
		!strictlyIncreasing(value.Limits.ReconnectDelaysSeconds) || value.Limits.ReconnectDelayCapSeconds < value.Limits.ReconnectDelaysSeconds[len(value.Limits.ReconnectDelaysSeconds)-1] ||
		value.Limits.AuthenticatedIdleSeconds < 1 || value.Limits.RateLimitExpirySeconds < 1 || !value.Limits.CeilingUseMustRemainMateriallyBelowMaximum ||
		!value.Limits.SignedProgramMayNarrowFragmentLimit {
		return errors.New("runtime limit authority is unsafe or incomplete")
	}
	if err := validateNetwork(value.Network); err != nil {
		return err
	}
	if value.Privacy.LogPayloadContents || value.Privacy.PersistFiveTuple || value.Privacy.LogFiveTuple || value.Privacy.TelemetryDefault != "off" ||
		value.Privacy.PublicResolversAllowed || !uniqueNonEmpty(value.Privacy.LiveProgramForbiddenInputs) {
		return errors.New("privacy authority is unsafe or incomplete")
	}
	return nil
}

func validateNetwork(value networkAuthority) error {
	ipv4Pool, err := netip.ParsePrefix(value.IPv4Pool)
	if err != nil || !ipv4Pool.Addr().Is4() || value.IPv4ClientPrefix != 32 {
		return errors.New("invalid IPv4 pool authority")
	}
	ipv4DNS, err := netip.ParseAddr(value.IPv4ServerDNS)
	if err != nil || !ipv4Pool.Contains(ipv4DNS) {
		return errors.New("invalid IPv4 DNS authority")
	}
	ipv6Pool, err := netip.ParsePrefix(value.IPv6Pool)
	if err != nil || !ipv6Pool.Addr().Is6() || value.IPv6ClientPrefix != 128 {
		return errors.New("invalid IPv6 pool authority")
	}
	ipv6DNS, err := netip.ParseAddr(value.IPv6ServerDNS)
	if err != nil || !ipv6Pool.Contains(ipv6DNS) {
		return errors.New("invalid IPv6 DNS authority")
	}
	if value.AddressReuse == "" || value.RevocationQuarantine == "" || value.PrivateNetworkAccess == "" || value.IPv6WithoutEvidence == "" || !value.SpoofedSourceAddressesBlocked ||
		!uniqueNonEmpty(value.FullTunnelRoutes) || !uniqueNonEmpty(value.BlockedDestinationClasses) || !uniqueNonEmpty(value.BlockedDestinationExceptions) ||
		!uniqueNonEmpty(value.IPv6IssuanceRequirements) {
		return errors.New("network authority is incomplete")
	}
	return nil
}

func verifyGoCopies(root string, value contract) error {
	carrier, err := readRequired(root, "internal/transport/tlstcp/carrier.go")
	if err != nil {
		return err
	}
	for _, required := range []string{fmt.Sprintf("ALPN          = %q", value.Wire.ALPN), fmt.Sprintf("exporterLabel = %q", value.Wire.ExporterLabel), "tls.VersionTLS13"} {
		if !strings.Contains(carrier, required) {
			return fmt.Errorf("carrier implementation disagrees with authority: missing %q", required)
		}
	}
	wire, err := readRequired(root, "internal/protocol/wirev1/codec.go")
	if err != nil {
		return err
	}
	for _, required := range []string{
		fmt.Sprintf("HeaderBytes           = %d", value.Wire.HeaderBytes),
		fmt.Sprintf("MajorVersion    uint8 = %d", value.Wire.MajorVersion),
		fmt.Sprintf("MinorVersion    uint8 = %d", value.Wire.MinorVersion),
		"var magic = [4]byte{'K', 'U', 'R', 'D'}",
		fmt.Sprintf("TypeReliableData uint8 = %d", value.Wire.ReliableDataRecordType),
	} {
		if !strings.Contains(wire, required) {
			return fmt.Errorf("wire implementation disagrees with authority: missing %q", required)
		}
	}
	return nil
}

func verifyDeploymentCopies(root string, value contract) error {
	service, err := readRequired(root, "deploy/selfhost/native/kurd-node.service")
	if err != nil {
		return err
	}
	for _, required := range []string{
		fmt.Sprintf("LimitNOFILE=%d", value.Limits.SystemdLimitNOFILE),
		fmt.Sprintf("TasksMax=%d", value.Limits.SystemdTasksMax),
		fmt.Sprintf("MemoryMax=%dM", value.Limits.SystemdMemoryMaxMiB),
	} {
		if !strings.Contains(service, required) {
			return fmt.Errorf("native deployment copy disagrees with authority: missing %q", required)
		}
	}
	return nil
}

func verifyPublicDocumentation(root string, value contract) error {
	protocol, err := readRequired(root, "docs/protocol/KURD-WIRE-V1-LIVE.md")
	if err != nil {
		return err
	}
	selfHosting, err := readRequired(root, "docs/self-hosting/LIVE-DATA-PLANE.md")
	if err != nil {
		return err
	}
	protocol = normalizeWhitespace(protocol)
	selfHosting = normalizeWhitespace(selfHosting)
	for _, required := range []string{
		fmt.Sprintf("ALPN `%s`", value.Wire.ALPN), fmt.Sprintf("`%s`", value.Wire.HeaderMagic),
		fmt.Sprintf("%d-byte", value.Wire.HeaderBytes), fmt.Sprintf("type %d", value.Wire.ReliableDataRecordType),
		fmt.Sprintf("`%d..%d`", value.Wire.ApplicationSlotMinimum, value.Wire.ApplicationSlotMaximum),
		fmt.Sprintf("`%d`", value.Wire.PaddingKeepaliveSlot), fmt.Sprintf("`%d`", value.Wire.ControlSlot),
		fmt.Sprintf("%d seconds", value.Wire.PaddingKeepaliveSeconds), fmt.Sprintf("%d seconds", value.Wire.UnauthenticatedPeerIdleSeconds),
		"profile bind", "TLS exporter", "no per-packet acknowledgements",
	} {
		if !strings.Contains(protocol, required) {
			return fmt.Errorf("protocol documentation disagrees with authority: missing %q", required)
		}
	}
	for _, required := range []string{
		"Native Linux deployment only", "systemd", "systemd-networkd", "nftables", "unbound",
		fmt.Sprintf("file descriptor %d", value.Relay.ListenerFileDescriptor), value.Relay.ServiceUser, value.Relay.TUNName,
		"PrivateDevices=no", fmt.Sprintf("DevicePolicy=%s", value.Relay.DevicePolicy), "/dev/net/tun rw",
		strings.Join(value.Relay.AddressFamilies, " "), "Root owns nftables and sysctl", "DNSSEC", "query logging disabled",
		value.Network.IPv4Pool, value.Network.IPv4ServerDNS, value.Network.IPv6Pool, value.Network.IPv6ServerDNS,
		strings.Join(value.Network.FullTunnelRoutes, " and "),
		fmt.Sprintf("%d accepted TCP connections", value.Limits.PreAuthenticationConnections),
		fmt.Sprintf("%d simultaneous handshakes", value.Limits.SimultaneousHandshakes),
		fmt.Sprintf("%d authenticated sessions", value.Limits.AuthenticatedSessions),
		fmt.Sprintf("%d-second TCP/TLS/Kurd handshake deadline", value.Limits.HandshakeDeadlineSeconds),
		fmt.Sprintf("%d packets per directional session queue", value.Limits.DirectionalSessionQueuePackets),
		fmt.Sprintf("%d incomplete inner operations", value.Limits.IncompleteOperationsPerSession),
		fmt.Sprintf("%d-second reconstruction deadline", value.Limits.ReconstructionDeadlineSeconds),
		fmt.Sprintf("%d inner fragments", value.Limits.InnerFragmentsPerOperation),
		fmt.Sprintf("%d MiB total live packet-buffer budget", value.Limits.ProcessPacketBufferMiB),
		fmt.Sprintf("MemoryMax=%dM", value.Limits.SystemdMemoryMaxMiB), fmt.Sprintf("TasksMax=%d", value.Limits.SystemdTasksMax),
		fmt.Sprintf("LimitNOFILE=%d", value.Limits.SystemdLimitNOFILE), fmt.Sprintf("%d reconnect attempts", value.Limits.ReconnectAttempts),
		fmt.Sprintf("%d-second authenticated idle-session maximum", value.Limits.AuthenticatedIdleSeconds),
		"payload contents", "5-tuple", "telemetry is off by default", "public resolvers are not permitted",
	} {
		if !strings.Contains(selfHosting, required) {
			return fmt.Errorf("self-hosting documentation disagrees with authority: missing %q", required)
		}
	}
	for _, document := range []string{protocol, selfHosting} {
		if err := rejectPrivateOrReadinessClaims(document); err != nil {
			return err
		}
	}
	return nil
}

func rejectPrivateOrReadinessClaims(document string) error {
	lower := strings.ToLower(document)
	for _, forbidden := range []string{
		"roadmap", "private plan", "future phase", "phase 18", "phase 19", "phase 20", "phase 21",
		"pull request", "current pr", "production-ready", "ready for production", "deployed", "deployment status",
		"owner host", "owner vps", "host identifier",
	} {
		if strings.Contains(lower, forbidden) {
			return fmt.Errorf("public documentation contains forbidden content %q", forbidden)
		}
	}
	return nil
}

func readRequired(root, relative string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return "", fmt.Errorf("read required %s: %w", relative, err)
	}
	if len(raw) == 0 {
		return "", fmt.Errorf("required %s is empty", relative)
	}
	return string(raw), nil
}

func normalizeWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func uniqueNonEmpty(values []string) bool {
	if len(values) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func strictlyIncreasing(values []int) bool {
	if len(values) == 0 {
		return false
	}
	for index, value := range values {
		if value < 1 || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}
