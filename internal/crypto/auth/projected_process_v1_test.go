// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package auth

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
)

func TestNewProjectedProcessHandshakeConfigV1CompletesAuthenticatedHandshake(t *testing.T) {
	t.Setenv("GODEBUG", "cryptocustomrand=1")
	fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
	program := projectedProcessProgramV1(fixture.input.SelectedPolicy)

	config, err := NewProjectedProcessHandshakeConfigV1(
		fixture.input.Client.IdentityID,
		fixture.input.Server.IdentityID,
		program,
		"tls13-tcp",
	)
	if err != nil {
		t.Fatal(err)
	}
	if config.input.Client.ProfileHash != program.SourceGenerationHash ||
		config.input.Server.ProfileHash != program.SourceGenerationHash ||
		config.input.SelectedPolicy.ProfileID == fixture.profile.ID ||
		config.input.Client.modeBinding.CarrierFamily != "tls13-tcp" ||
		config.input.Client.modeBinding.ConfigSourceBlock.ProfileHash != program.SourceGenerationHash {
		t.Fatal("projected handshake authority was not bound to the live program")
	}

	client, err := newClientProcessHandshakeV1(config, fixture.input.ClientDependencies, bytes.NewReader(bytes.Repeat([]byte{0x31}, 1024)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	replay, err := NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := newRelayProcessHandshakeV1(config, fixture.input.ServerDependencies, replay, bytes.NewReader(bytes.Repeat([]byte{0x92}, 1024)))
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()

	clientHello, err := client.Start()
	if err != nil {
		t.Fatal(err)
	}
	serverHello, err := relay.AcceptClientHello(clientHello)
	if err != nil {
		t.Fatal(err)
	}
	clientFinish, err := client.AcceptServerHello(serverHello)
	if err != nil {
		t.Fatal(err)
	}
	serverFinish, relayResult, err := relay.AcceptClientFinish(clientFinish)
	if err != nil {
		t.Fatal(err)
	}
	defer relayResult.Close()
	clientResult, err := client.AcceptServerFinish(serverFinish)
	if err != nil {
		t.Fatal(err)
	}
	defer clientResult.Close()
	clientEvidence, clientOK := clientResult.EvidenceV1()
	relayEvidence, relayOK := relayResult.EvidenceV1()
	if !clientOK || !relayOK || clientEvidence.TranscriptHash != relayEvidence.TranscriptHash {
		t.Fatal("projected process handshake did not establish matching authority")
	}
}

func TestNewProjectedProcessHandshakeConfigV1RejectsUnboundProjection(t *testing.T) {
	fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
	valid := projectedProcessProgramV1(fixture.input.SelectedPolicy)

	for name, mutate := range map[string]func(*liveprogram.ProgramV1, *string){
		"invalid program": func(program *liveprogram.ProgramV1, _ *string) {
			program.ProgramID[0] ^= 1
		},
		"unsupported carrier": func(_ *liveprogram.ProgramV1, carrier *string) {
			*carrier = "stream_carrier"
		},
		"empty client identity": func(_ *liveprogram.ProgramV1, carrier *string) {
			*carrier = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			program := valid.Clone()
			carrier := "tls13-tcp"
			clientID := fixture.input.Client.IdentityID
			mutate(&program, &carrier)
			if name == "empty client identity" {
				clientID = ""
				carrier = "tls13-tcp"
			}
			if _, err := NewProjectedProcessHandshakeConfigV1(clientID, fixture.input.Server.IdentityID, program, carrier); err == nil {
				t.Fatal("unbound projected authority accepted")
			}
		})
	}
}

func projectedProcessProgramV1(policy ir.EffectiveSecurityPolicy) liveprogram.ProgramV1 {
	source := sha256.Sum256([]byte("phase17-projected-process-handshake"))
	return liveprogram.ProgramV1{
		Schema:               liveprogram.SchemaV1,
		ProgramID:            liveprogram.DeriveProgramIDV1(source),
		SourceSchemaVersion:  ir.SupportedVersion,
		SourceGenerationHash: source,
		Messages: []liveprogram.MessageV1{
			{Semantic: "data", WireSymbol: "data", Direction: "bidirectional", MaxPayloadBytes: 4096},
			{Semantic: "padding", WireSymbol: "padding", Direction: "bidirectional", MaxPayloadBytes: 4096},
		},
		Frame: liveprogram.FrameV1{
			LengthMode: "varint_prefix", TypeMode: "explicit_generated_tag",
			HeaderOrder: []string{"length", "type", "stream", "flags"}, FragmentationMode: "bounded_variable_chunks",
			ChecksumMode: "crc32", PaddingPlacement: "suffix",
			Compiled: liveprogram.CompiledFramingV1{DataTypeTag: []byte{1}, PaddingTypeTag: []byte{2}, ProfileXORStreamMask: 3, TableStreamMask: 4, CRC32PrefixState: 5},
		},
		Scheduler: liveprogram.SchedulerV1{Mode: "balanced", MaxBatchBytes: 4096, FlushIntervalMs: 10, MaxInFlightFrames: 4, PriorityMode: "fifo"},
		Stream:    liveprogram.StreamV1{IDEncodingMode: "fixed32_be", MaxConcurrentStreams: 4},
		Padding:   liveprogram.PaddingV1{Mode: "none"},
		Security: liveprogram.SecurityV1{
			CompilerSecurityVersion: policy.CompilerSecurityVersion,
			MinimumRuntimeVersion:   policy.MinimumRuntimeVersion,
			Policy: liveprogram.SecurityPolicyV1{
				SecurityVersion: policy.SecurityVersion, TranscriptMode: policy.TranscriptMode,
				KDFSuite: policy.KDFSuite, AEADSuite: policy.AEADSuite, MACSuite: policy.MACSuite,
				NonceMode: policy.NonceMode, ReplayPolicy: policy.ReplayPolicy, ReplayWindowSize: policy.ReplayWindowSize,
				DowngradePolicy: policy.DowngradePolicy, CapabilityNegotiationPolicy: policy.CapabilityNegotiationPolicy,
				ProfileCompatibilityPolicy: policy.ProfileCompatibilityPolicy, KeyRotationPolicy: policy.KeyRotationPolicy,
				ConfigValidationPolicy: policy.ConfigValidationPolicy, SecureEnvelopeMode: policy.SecureEnvelopeMode,
				MaxSessionMessages: policy.MaxSessionMessages, MaxKeyLifetimeMessages: policy.MaxKeyLifetimeMessages,
			},
			ClientMandatoryCapabilities: append([]string(nil), policy.ClientMandatoryCapabilities...),
			RelayMandatoryCapabilities:  append([]string(nil), policy.ServerMandatoryCapabilities...),
			SelectedCapabilities:        append([]string(nil), policy.SelectedCapabilities...),
		},
		Limits: liveprogram.LimitsV1{
			MaxFrameBytes: 8192, MaxPayloadBytes: 4096, MaxSessionMillis: 30000,
			MaxSessionMessages: policy.MaxSessionMessages, MaxKeyLifetimeMessages: policy.MaxKeyLifetimeMessages,
		},
	}
}
