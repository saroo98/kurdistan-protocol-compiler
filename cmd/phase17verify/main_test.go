// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"encoding/json"
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

func TestPhase17GateDoesNotApplyHistoricalPhase9ArtifactEvidenceToCurrentAPK(t *testing.T) {
	build, err := os.ReadFile(filepath.Join(repositoryRoot(t), "android", "build.gradle.kts"))
	if err != nil {
		t.Fatal(err)
	}
	phase17 := taskBody(t, string(build), "val phase17Gate = tasks.register(\"phase17Gate\")")
	if strings.Contains(phase17, "verifyPhase9Evidence") {
		t.Fatal("phase17Gate applies frozen Phase 9 artifact evidence to the current Phase 17 APK")
	}
}

func TestHistoricalAndroidGatesDoNotBuildOrInspectCurrentAPK(t *testing.T) {
	build, err := os.ReadFile(filepath.Join(repositoryRoot(t), "android", "build.gradle.kts"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(build)
	for _, name := range []string{"phase9Gate", "phase10Gate", "phase11Gate", "phase13Gate", "phase14Gate"} {
		body := taskBody(t, source, "tasks.register(\""+name+"\")")
		for _, forbidden := range []string{"assembleRelease", "assembleInternal", "verifyPhase9Evidence"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s applies current-artifact operation %q", name, forbidden)
			}
		}
	}
}

func taskBody(t *testing.T, source, declaration string) string {
	t.Helper()
	start := strings.Index(source, declaration)
	if start < 0 {
		t.Fatalf("missing Gradle task declaration %q", declaration)
	}
	rest := source[start:]
	end := strings.Index(rest, "\n}")
	if end < 0 {
		t.Fatalf("unterminated Gradle task declaration %q", declaration)
	}
	return rest[:end+2]
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
		LiveProgramMinBytes:                 1,
		LiveProgramMaxBytes:                 48 << 10,
		LiveProgramDigest:                   "sha256",
		LiveProgramForbiddenInputs:          []string{"model-only-authentication-key", "lab-carrier-label", "compiler-seed", "owner-only-metadata"},
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
		SessionBinding: "session-plan-digest-plus-tls-exporter", ExporterContext: "session-plan-digest", TLSMinimumVersion: "1.3", TLSMaximumVersion: "1.3", TLSSessionResumption: "disabled",
		ProfileBind:              profileBindAuthority{Magic: "KRDBND01", BodyBytes: 72, TLSExporterOffset: 8, SessionPlanDigestOffset: 40, ComponentBytes: 32},
		CarrierLengthPrefixBytes: 4, KnownOuterFlags: []string{"critical"}, MaxControlBytes: 64 << 10, MaxPayloadBytes: 1 << 20,
		ReliableDataRecordType: 5, ProfileBindRecordType: 3, EngineReadyRecordType: 4, CloseRecordType: 7,
		ApplicationSlotMinimum: 1, ApplicationSlotMaximum: 64, PaddingKeepaliveSlot: 65534, ControlSlot: 65535,
		PacketSemantic: "data", PacketPerOperation: true, SlotSelection: "session-keyed-hmac-sha256-5-tuple",
		SlotHMAC: "hmac-sha256", InnerFraming: "signed-profile-shaped", OuterAuthentication: "authenticated-kurd-envelope",
		PaddingKeepaliveSeconds: 30, NoAuthenticatedPeerActivityTimeoutSeconds: 90,
		ReplayCommit: "after-raw-ip-write", ReplayFailure: "discard-pending-replay-and-close",
		TCPKeepaliveRole: "secondary-transport-liveness", PacketAcknowledgements: false, LegacyAdapters: []string{"encode-operation", "decode-frames", "one-shot-v1-record-api"},
		LiveFramingNoProfileReconstruction: true,
	}); !reflect.DeepEqual(got, want) {
		t.Fatalf("wire authority = %#v, want %#v", got, want)
	}
	if got, want := value.Android, (androidAuthority{
		NativeOnly:                         true,
		ProtectMustSucceed:                 true,
		RuntimeStatusScope:                 "loopback-only-predecessor",
		RuntimeStatusPlanDigestField:       "planDigest",
		RuntimeStatusMTUMin:                1280,
		RuntimeStatusMTUMax:                1500,
		NativeBridgeSessionPlanDigestBytes: 32,
		NativeBridgeMTUMin:                 1280,
		NativeBridgeMTUMax:                 1500,
		Lifecycle: []string{
			"vpn-consent", "open-unconnected-tcp-socket", "protect-before-connect", "strict-tls13-and-kurd-handshake",
			"bind-session-plan-digest-and-tls-exporter", "establish-tun-from-verified-snapshot", "transfer-tun-to-go-pump",
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
		ControlSocketAccess: "root-local-owner-unix", RequiredLiveUnitState: "not-applied",
		CurrentPredecessorUnit: predecessorUnitAuthority{ServicePath: "deploy/selfhost/native/kurd-node.service", LiveDataPlaneAuthorized: false, PrivateDevices: true, AddressFamilies: []string{"AF_UNIX"}},
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
		SignedProgramMayNarrowFragmentLimit: true, LegacyProtectedRecordIncompleteOperations: 8, LiveIncompleteInnerOperationsAreSeparate: true,
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
		TelemetryDefault: "off", PublicResolversAllowed: false, LiveProgramForbiddenInputs: []string{"model-only-authentication-key", "lab-carrier-label", "compiler-seed", "owner-only-metadata"},
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

func TestLiveDataPlaneContractBindsSessionPlanAndExactSourceValues(t *testing.T) {
	value := rawAuthority(t)
	for name, want := range map[string]any{
		"runtimePolicy.liveProgramMinBytes":                    float64(1),
		"wire.sessionBinding":                                  "session-plan-digest-plus-tls-exporter",
		"wire.exporterContext":                                 "session-plan-digest",
		"wire.tlsSessionResumption":                            "disabled",
		"wire.profileBind.magic":                               "KRDBND01",
		"wire.profileBind.bodyBytes":                           float64(72),
		"wire.profileBind.tlsExporterOffset":                   float64(8),
		"wire.profileBind.sessionPlanDigestOffset":             float64(40),
		"wire.carrierLengthPrefixBytes":                        float64(4),
		"wire.knownOuterFlags":                                 []any{"critical"},
		"wire.maxControlBytes":                                 float64(64 << 10),
		"wire.maxPayloadBytes":                                 float64(1 << 20),
		"wire.noAuthenticatedPeerActivityTimeoutSeconds":       float64(90),
		"android.runtimeStatusScope":                           "loopback-only-predecessor",
		"android.nativeBridgeSessionPlanDigestBytes":           float64(32),
		"relay.requiredLiveUnitState":                          "not-applied",
		"relay.currentPredecessorUnit.liveDataPlaneAuthorized": false,
		"relay.currentPredecessorUnit.privateDevices":          true,
		"relay.currentPredecessorUnit.addressFamilies":         []any{"AF_UNIX"},
		"limits.legacyProtectedRecordIncompleteOperations":     float64(8),
		"limits.liveIncompleteInnerOperationsAreSeparate":      true,
	} {
		if got := rawAuthorityPath(t, value, name); !reflect.DeepEqual(got, want) {
			t.Fatalf("authority %s = %#v, want %#v", name, got, want)
		}
	}
	forbidden := rawAuthorityPath(t, value, "runtimePolicy.liveProgramForbiddenInputs").([]any)
	if !containsValue(forbidden, "owner-only-metadata") || containsValue(forbidden, "operator-only-metadata") {
		t.Fatalf("live-program metadata boundary = %#v", forbidden)
	}
}

func TestLiveDataPlaneAuthorityRejectsNullAtEveryJSONTypeBoundary(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), filepath.FromSlash(contractPath)))
	if err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"string":  "schema",
		"number":  "wire.headerBytes",
		"boolean": "wire.packetPerOperation",
		"list":    "wire.legacyAdapters",
		"object":  "runtimePolicy",
	} {
		t.Run(name, func(t *testing.T) {
			candidate := withJSONNull(t, raw, path)
			if _, err := decodeContract(candidate); err == nil {
				t.Fatal("null accepted")
			}
		})
	}
}

func TestLiveDataPlaneVerifierRejectsCarrierWireRuntimeAndKotlinDrift(t *testing.T) {
	mutations := []struct {
		name, path, old, new string
	}{
		{"TLS minimum", "internal/transport/tlstcp/carrier.go", "cfg.MinVersion = tls.VersionTLS13", "cfg.MinVersion = tls.VersionTLS12"},
		{"TLS resumption", "internal/transport/tlstcp/carrier.go", "cfg.SessionTicketsDisabled = true", "cfg.SessionTicketsDisabled = false"},
		{"exporter context", "internal/transport/tlstcp/carrier.go", "state.ExportKeyingMaterial(exporterLabel, planDigest[:], 32)", "state.ExportKeyingMaterial(exporterLabel, nil, 32)"},
		{"profile-bind type", "internal/protocol/wirev1/codec.go", "TypeProfileBind  uint8 = 3", "TypeProfileBind  uint8 = 9"},
		{"outer flags", "internal/protocol/wirev1/codec.go", "knownFlags         = FlagCritical", "knownFlags         = 0"},
		{"control ceiling", "internal/protocol/wirev1/codec.go", "MaxControlBytes       = 64 << 10", "MaxControlBytes       = 65 << 10"},
		{"profile-bind body", "internal/runtime/process_record_v1.go", "body := make([]byte, 72)", "body := make([]byte, 71)"},
		{"legacy protected-record cap", "internal/runtime/protected_channel.go", "strictFragmentMaxOperationsV1 = 8", "strictFragmentMaxOperationsV1 = 9"},
		{"Kotlin runtime MTU", "android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/RuntimeStatus.kt", "mtu in 1280..1500", "mtu in 1279..1500"},
		{"Kotlin native plan digest", "android/core/native-jni/src/main/kotlin/org/kurdistanvpn/core/nativejni/NativeBridge.kt", "reader.fixedBytes(32)", "reader.fixedBytes(31)"},
		{"live unit device boundary", "deploy/selfhost/native/kurd-node.service", "PrivateDevices=no", "PrivateDevices=yes"},
		{"live unit authenticated reload", "deploy/selfhost/native/kurd-node.service", "ExecReload=/usr/local/bin/kurdctl node reload", "ExecReload=/bin/true"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			root := copyAuthority(t)
			if err := replaceFile(root, mutation.path, mutation.old, mutation.new); err != nil {
				t.Fatal(err)
			}
			if err := verify(root); err == nil {
				t.Fatalf("accepted %s drift", mutation.name)
			}
		})
	}
}

func TestLiveUnitSupportsAuthenticatedOwnerLocalReload(t *testing.T) {
	service := string(mustReadFile(t, filepath.Join(repositoryRoot(t), filepath.FromSlash("deploy/selfhost/native/kurd-node.service"))))
	if !strings.Contains(service, "ExecReload=/usr/local/bin/kurdctl node reload --data-dir /var/lib/kurd-node --control-socket /run/kurd-node/control.sock") {
		t.Fatal("live unit lacks the bounded owner-local reload operation")
	}
}

func TestLiveDataPlaneVerifierRequiresNormativePrivacyAndNonReadinessMarkers(t *testing.T) {
	root := copyAuthority(t)
	if err := replaceFile(root, "docs/self-hosting/LIVE-DATA-PLANE.md", "KURD-LIVE-CONTRACT: READINESS=NOT_CLAIMED", "KURD-LIVE-CONTRACT: READINESS=CLAIMED"); err != nil {
		t.Fatal(err)
	}
	if err := verify(root); err == nil {
		t.Fatal("documentation without the non-readiness marker accepted")
	}
}

func TestLiveDataPlaneVerifierRejectsAffirmativeLoggingReadinessAndHostClaims(t *testing.T) {
	mutations := []string{
		"\nPayload logging is enabled.\n",
		"\n5-tuple logging is allowed.\n",
		"\nThe live service is ready for production.\n",
		"\nhttps://node.example.invalid/\n",
		"\nnode.example.invalid\n",
	}
	for _, mutation := range mutations {
		t.Run(strings.TrimSpace(mutation), func(t *testing.T) {
			root := copyAuthority(t)
			path := filepath.Join(root, filepath.FromSlash("docs/self-hosting/LIVE-DATA-PLANE.md"))
			if err := os.WriteFile(path, append(mustReadFile(t, path), []byte(mutation)...), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := verify(root); err == nil {
				t.Fatal("affirmative claim accepted")
			}
		})
	}
}

func TestLiveDataPlaneVerifierRejectsContradictoryPublicProse(t *testing.T) {
	mutations := []string{
		"\nThe service logs payload contents and retains packet 5-tuples.\n",
		"\nThe live service is available for operation.\n",
		"\nThe owner endpoint is maintained separately.\n",
	}
	for _, mutation := range mutations {
		t.Run(strings.TrimSpace(mutation), func(t *testing.T) {
			root := copyAuthority(t)
			path := filepath.Join(root, filepath.FromSlash("docs/self-hosting/LIVE-DATA-PLANE.md"))
			if err := os.WriteFile(path, append(mustReadFile(t, path), []byte(mutation)...), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := verify(root); err == nil {
				t.Fatal("contradictory public documentation accepted despite the required negative markers")
			}
		})
	}
}

func TestLiveDataPlaneVerifierRequiresExactNormalizedPrivacyStatement(t *testing.T) {
	root := copyAuthority(t)
	if err := replaceFile(
		root,
		"docs/self-hosting/LIVE-DATA-PLANE.md",
		"The service does not log payload contents or a packet 5-tuple, and it does not\npersist either; telemetry is off by default, and public resolvers are not\npermitted.",
		"The service does not log payload contents or persist a packet 5-tuple; telemetry is off by default, and public resolvers are not permitted.",
	); err != nil {
		t.Fatal(err)
	}
	if err := verify(root); err == nil {
		t.Fatal("documentation accepted a non-approved privacy paraphrase")
	}
}

func TestLiveDataPlaneVerifierRejectsPublicIPLiteralOutsideAuthority(t *testing.T) {
	for _, literal := range []string{"198.51.100.7", "198.51.100.7:443", "2001:db8::7"} {
		t.Run(literal, func(t *testing.T) {
			root := copyAuthority(t)
			path := filepath.Join(root, filepath.FromSlash("docs/self-hosting/LIVE-DATA-PLANE.md"))
			mutation := "\n`" + literal + "`\n"
			if err := os.WriteFile(path, append(mustReadFile(t, path), []byte(mutation)...), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := verify(root); err == nil {
				t.Fatal("public IP literal outside machine authority accepted")
			}
		})
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
		"internal/runtime/process_record_v1.go",
		"internal/runtime/protected_channel.go",
		"android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/RuntimeStatus.kt",
		"android/core/native-jni/src/main/kotlin/org/kurdistanvpn/core/nativejni/NativeBridge.kt",
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

func rawAuthority(t *testing.T) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(mustReadFile(t, filepath.Join(repositoryRoot(t), filepath.FromSlash(contractPath))), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func rawAuthorityPath(t *testing.T, value map[string]any, path string) any {
	t.Helper()
	var current any = value
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("authority %s is not an object before %q", path, part)
		}
		var present bool
		current, present = object[part]
		if !present {
			t.Fatalf("authority %s is missing", path)
		}
	}
	return current
}

func containsValue(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func withJSONNull(t *testing.T, raw []byte, path string) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(path, ".")
	current := value
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]any)
		if !ok {
			t.Fatalf("null path %q has non-object parent %q", path, part)
		}
		current = next
	}
	current[parts[len(parts)-1]] = nil
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
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
