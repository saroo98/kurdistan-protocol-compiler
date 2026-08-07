// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestVerifyRepositoryLiveDataPlaneAuthority(t *testing.T) {
	if err := verify(repositoryRoot(t)); err != nil {
		t.Fatal(err)
	}
}

func TestLiveDataPlaneAuthorityFreezesAllBoundValues(t *testing.T) {
	value, err := loadContract(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}

	if value.Schema != "kurd-live-data-plane-v1" {
		t.Fatalf("schema = %q", value.Schema)
	}
	if got, want := value.RuntimePolicy, (runtimePolicyAuthority{
		Schema:        "kurd-runtime-policy-v2",
		WireProtocol:  "kurd-wire-v1",
		CarrierFamily: "tls13-tcp",
		CBORFields: []string{
			"schema-version", "wire-protocol", "carrier-family", "canonical-live-program", "live-program-sha256",
			"client-authentication-key-id", "client-ed25519-public-key", "relay-authentication-key-id", "relay-ed25519-public-key",
			"tls-server-name", "tls-self-signed-leaf-der", "tls-leaf-sha256", "ordered-endpoints", "client-ipv4",
			"server-tun-dns-ipv4", "client-ipv6", "server-tun-dns-ipv6", "routes", "dns-servers", "mtu",
			"allowed-ip-modes", "allowed-payload-protocols", "resource-limits", "fallback-policy", "relay-admission-digest",
		},
		LiveProgramMinBytes:                 1024,
		LiveProgramMaxBytes:                 48 << 10,
		LiveProgramDigest:                   "sha256",
		LiveProgramForbiddenInputs:          []string{"model-only-authentication-key", "lab-carrier-label", "compiler-seed", "operator-only-metadata"},
		LiveProgramCanonicalReencoding:      true,
		LiveProgramIndependentValidation:    []string{"client", "relay"},
		LiveProgramCannotWidenOuterPolicy:   true,
		ClientKeyIDBytes:                    16,
		KeyIDFormat:                         "lowercase-32-hex",
		KeyIDDerivation:                     "sha256-public-key-first-16-bytes",
		ClientPublicKeyBytes:                32,
		RelayKeyID:                          "existing-bounded-relay-key-id",
		RelayPublicKeyBytes:                 32,
		TLSServerNameMaxBytes:               253,
		TLSServerNameKinds:                  []string{"dns-name", "canonical-ip-literal"},
		TLSLeafMinBytes:                     1,
		TLSLeafMaxBytes:                     4096,
		TLSDigest:                           "sha256",
		TLSCertificateRequirements:          []string{"parseable", "currently-valid", "server-auth-usage", "server-name-san"},
		EndpointMinimum:                     1,
		EndpointMaximum:                     4,
		EndpointIPLiteralsOnly:              true,
		EndpointFields:                      []string{"priority", "canonical-ip-bytes", "address-family", "port"},
		IPv4Bytes:                           4,
		IPv6Bytes:                           16,
		AddressAbsentWhenUnauthorized:       true,
		RoutesCanonical:                     true,
		DNSRestrictedToTUN:                  true,
		IssuedMTU:                           1280,
		MinimumMTU:                          1280,
		MaximumMTU:                          1500,
		AllowedIPModes:                      []string{"ipv4-only", "ipv6-only", "dual-stack"},
		AllowedIPModesSortedUnique:          true,
		PayloadProtocols:                    []string{"tcp", "udp", "icmp-pmtu-and-probe-only", "icmpv6-pmtu-and-probe-only"},
		FallbackOrdered:                     true,
		FallbackReferencesExistingEndpoints: true,
		AdmissionDigest:                     "sha256",
		DecoderRejects:                      []string{"duplicate-map-keys", "tags", "indefinite-length-values", "unknown-labels", "missing-labels", "noncanonical-cbor", "invalid-utf8", "oversized-nesting", "unsorted-lists", "duplicate-values", "reencoding-mismatch"},
		UserMayOnlyNarrow:                   true,
	}); !reflect.DeepEqual(got, want) {
		t.Fatalf("runtime policy = %#v, want %#v", got, want)
	}
	if got, want := value.Wire, (wireAuthority{
		HeaderMagic: "KURD", HeaderBytes: 48, MajorVersion: 1, MinorVersion: 0,
		CarrierTLSVersion: "1.3", ALPN: "kurd/1", ExporterLabel: "EXPORTER-Kurdistan-VPN-wire-v1",
		ReliableDataRecordType: 5, ProfileBindRecordType: 3, EngineReadyRecordType: 4, CloseRecordType: 7,
		ApplicationSlotMinimum: 1, ApplicationSlotMaximum: 64, PaddingKeepaliveSlot: 65534, ControlSlot: 65535,
		PacketSemantic: "data", PacketPerOperation: true, SlotSelection: "session-keyed-hmac-sha256-5-tuple",
		SlotHMAC: "hmac-sha256", InnerFraming: "signed-profile-shaped", OuterAuthentication: "authenticated-kurd-envelope",
		PaddingKeepaliveSeconds: 30, UnauthenticatedPeerIdleSeconds: 90,
		ReplayCommit: "after-raw-ip-write", ReplayFailure: "discard-pending-replay-and-close",
		TCPKeepaliveRole: "secondary-transport-liveness", PacketAcknowledgements: false, LegacyAdapters: []string{"encode-operation", "decode-frames", "one-shot-v1-record-api"},
		LiveFramingNoProfileReconstruction: true,
	}); !reflect.DeepEqual(got, want) {
		t.Fatalf("wire authority = %#v, want %#v", got, want)
	}
	if got, want := value.Android, (androidAuthority{
		NativeOnly:         true,
		ProtectMustSucceed: true,
		Lifecycle: []string{
			"vpn-consent", "open-unconnected-tcp-socket", "protect-before-connect", "strict-tls13-and-kurd-handshake",
			"bind-profile-digest-and-tls-exporter", "establish-tun-from-verified-snapshot", "transfer-tun-to-go-pump",
			"bounded-close-on-revoke-network-change-profile-revocation-process-death-or-stop",
		},
	}); !reflect.DeepEqual(got, want) {
		t.Fatalf("android authority = %#v, want %#v", got, want)
	}
	if got, want := value.Relay, (relayAuthority{
		ListenerFileDescriptor: 3, ServiceUser: "kurd-node", ServiceGroup: "kurd-node", TUNName: "kurd0",
		TUNPacketInfo: false, TUNKeepCarrier: true, PrivateDevices: false, DevicePolicy: "closed", TUNDeviceAccess: "rw",
		NoAmbientCapabilities: true, EmptyCapabilityBoundingSet: true, AddressFamilies: []string{"AF_UNIX", "AF_INET", "AF_INET6"},
		FirewallOwner: "root", SysctlOwner: "root", DNSService: "unbound", DNSSEC: true, DNSQueryLogging: false,
		DNSBind: "tun-server-addresses-only", DNSClients: "tun-client-prefixes-only", DNSMinimiseQueryNames: true, DNSHideIdentityVersion: true,
		ControlSocketDirectory: "/run/kurd-node/", ControlOperations: []string{"health", "drain", "resume", "reload"}, PublicListener: "authenticated-kurd-tls-only",
		ControlSocketAccess: "root-local-owner-unix",
	}); !reflect.DeepEqual(got, want) {
		t.Fatalf("relay authority = %#v, want %#v", got, want)
	}
	if got, want := value.Limits, (limitsAuthority{
		ReferenceVCPU: 1, ReferenceMemoryMiB: 2048, PreAuthenticationConnections: 128, SimultaneousHandshakes: 32,
		AuthenticatedSessions: 64, HandshakeDeadlineSeconds: 10, DirectionalSessionQueuePackets: 256,
		IncompleteOperationsPerSession: 64, ReconstructionDeadlineSeconds: 5, IssuedMTU: 1280, InnerFragmentsPerOperation: 16,
		ProcessPacketBufferMiB: 64, SystemdMemoryMaxMiB: 512, SystemdTasksMax: 128, SystemdLimitNOFILE: 4096,
		ReconnectAttempts: 5, ReconnectDelaysSeconds: []int{1, 2, 4, 8, 16}, ReconnectDelayCapSeconds: 30,
		AuthenticatedIdleSeconds: 300, PreAuthenticationRateLimit: "memory-only-per-process-secret-hash", RateLimitExpirySeconds: 600, CeilingUseMustRemainMateriallyBelowMaximum: true,
		SignedProgramMayNarrowFragmentLimit: true,
	}); !reflect.DeepEqual(got, want) {
		t.Fatalf("limits authority = %#v, want %#v", got, want)
	}
	if got, want := value.Network, (networkAuthority{
		IPv4Pool: "10.77.0.0/24", IPv4ServerDNS: "10.77.0.1", IPv4ClientPrefix: 32,
		IPv6Pool: "fd4b:7572:6400::/64", IPv6ServerDNS: "fd4b:7572:6400::1", IPv6ClientPrefix: 128,
		AddressReuse: "never-while-active", RevocationQuarantine: "maximum-profile-validity-plus-24-hours",
		FullTunnelRoutes: []string{"0.0.0.0/0", "::/0"}, PrivateNetworkAccess: "deny-except-tun-dns",
		BlockedDestinationClasses:     []string{"loopback", "link-local", "rfc1918", "cgnat", "ula", "multicast", "documentation", "benchmark", "provider-metadata"},
		BlockedDestinationExceptions:  []string{"tun-dns-ipv4", "tun-dns-ipv6"},
		IPv6IssuanceRequirements:      []string{"global-ipv6-address", "default-route", "forwarding", "nftables-ipv6-nat-or-routed-prefix", "successful-external-ipv6-test"},
		SpoofedSourceAddressesBlocked: true,
		IPv6WithoutEvidence:           "ipv4-only-and-explicit-missing-evidence",
	}); !reflect.DeepEqual(got, want) {
		t.Fatalf("network authority = %#v, want %#v", got, want)
	}
	if got, want := value.Privacy, (privacyAuthority{
		LogPayloadContents: false, PersistFiveTuple: false, LogFiveTuple: false,
		TelemetryDefault: "off", PublicResolversAllowed: false, LiveProgramForbiddenInputs: []string{"model-only-authentication-key", "lab-carrier-label", "compiler-seed", "operator-only-metadata"},
	}); !reflect.DeepEqual(got, want) {
		t.Fatalf("privacy authority = %#v, want %#v", got, want)
	}
}

func TestLiveDataPlaneAuthorityRejectsDuplicateAndUnknownFields(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), filepath.FromSlash(contractPath)))
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(raw, []byte(`"schema": "kurd-live-data-plane-v1"`), []byte(`"schema": "kurd-live-data-plane-v1", "schema": "wrong"`), 1)
	if _, err := decodeContract(duplicate); err == nil {
		t.Fatal("duplicate root key accepted")
	}
	unknown := bytes.Replace(raw, []byte(`"runtimePolicy": {`), []byte(`"runtimePolicy": {"unknown": true,`), 1)
	if _, err := decodeContract(unknown); err == nil {
		t.Fatal("unknown nested field accepted")
	}
	missing := bytes.Replace(raw, []byte("    \"privateDevices\": false,\n"), nil, 1)
	if _, err := decodeContract(missing); err == nil {
		t.Fatal("missing false-valued field accepted")
	}
}

func TestLiveDataPlaneVerifierRejectsAuthorityAndDocumentationDrift(t *testing.T) {
	root := copyAuthority(t)
	if err := replaceFile(root, "internal/transport/tlstcp/carrier.go", `ALPN          = "kurd/1"`, `ALPN          = "other/1"`); err != nil {
		t.Fatal(err)
	}
	if err := verify(root); err == nil {
		t.Fatal("Go carrier authority drift accepted")
	}

	root = copyAuthority(t)
	if err := replaceFile(root, "deploy/selfhost/native/kurd-node.service", "MemoryMax=512M", "MemoryMax=513M"); err != nil {
		t.Fatal(err)
	}
	if err := verify(root); err == nil {
		t.Fatal("deployment authority drift accepted")
	}

	root = copyAuthority(t)
	if err := replaceFile(root, "docs/protocol/KURD-WIRE-V1-LIVE.md", "ALPN `kurd/1`", "ALPN `other/1`"); err != nil {
		t.Fatal(err)
	}
	if err := verify(root); err == nil {
		t.Fatal("public protocol documentation drift accepted")
	}

	root = copyAuthority(t)
	path := filepath.Join(root, filepath.FromSlash("docs/self-hosting/LIVE-DATA-PLANE.md"))
	if err := os.WriteFile(path, append(mustReadFile(t, path), []byte("\nPhase 18 will make this production-ready.\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verify(root); err == nil {
		t.Fatal("private sequencing or unsupported readiness claim accepted")
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
}

func copyAuthority(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, relative := range []string{
		contractPath,
		"docs/protocol/KURD-WIRE-V1-LIVE.md",
		"docs/self-hosting/LIVE-DATA-PLANE.md",
		"internal/transport/tlstcp/carrier.go",
		"internal/protocol/wirev1/codec.go",
		"deploy/selfhost/native/kurd-node.service",
	} {
		destination := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, mustReadFile(t, filepath.Join(repositoryRoot(t), filepath.FromSlash(relative))), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func replaceFile(root, relative, old, new string) error {
	path := filepath.Join(root, filepath.FromSlash(relative))
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !strings.Contains(string(raw), old) {
		return os.ErrNotExist
	}
	return os.WriteFile(path, []byte(strings.Replace(string(raw), old, new, 1)), 0o644)
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
