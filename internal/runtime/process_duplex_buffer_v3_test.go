// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/framing"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/wirev1"
	goruntime "runtime"
	"strings"
	"sync"
	"testing"
	"unsafe"
)

func TestSizeDuplexV3MatchesAuthenticatedConstruction(t *testing.T) {
	p := testDuplexProgramV1()
	cr, _, digest := duplexResultsV3(t, p)
	resources, err := auth.ProjectProcessResourcesV3(p, "tls13-tcp", auth.ProjectedContextValidationBytesV3)
	if err != nil {
		t.Fatal(err)
	}
	config, err := strictConfigFromSourcesV1(resources.Policy, resources.ConfigSource, resources.Limits)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := cr.ProjectedContextSnapshotV3(p, "tls13-tcp", auth.ProjectedContextValidationBytesV3)
	if err != nil {
		t.Fatal(err)
	}
	_, actualConfig, err := prepareProcessRecordContextV1(snapshot, true)
	if err != nil || config != actualConfig {
		t.Fatal("strict config parity", err)
	}
	cryptoBytes, err := security.EnvelopeStorageOwnedBytesV3(resources.Policy)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := framing.NewLiveDataCodecV3(p)
	if err != nil {
		t.Fatal(err)
	}
	sized, err := sizeDuplexV3(p, codec, config.MaxEnvelopeBytes, cryptoBytes, 1<<20, 272, 128<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sizeDuplexV3(p, codec, config.MaxEnvelopeBytes, cryptoBytes, 1<<20, 272, sized.bounds.OwnedBytes-1); !errors.Is(err, ServiceResourceLimitV1) {
		t.Fatal("short exact budget", err)
	}
	if _, err = sizeDuplexV3(p, codec, config.MaxEnvelopeBytes, cryptoBytes, 1<<20, sized.bounds.MaxPayloadBytes+1, 128<<20); !errors.Is(err, ServiceResourceLimitV1) {
		t.Fatal("impossible MTU", err)
	}
	endpoint, err := NewProcessClientDuplexEndpointV3(cr, digest, p, 1<<20, sized.bounds.OwnedBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.Abort)
	if endpoint.BoundsV3() != sized.bounds {
		t.Fatal("sizing parity", endpoint.BoundsV3(), sized.bounds)
	}
	w := endpoint.state.bounded
	if uint32(cap(w.txBody)) != sized.dataCap || uint32(cap(w.txFrames)) != sized.frameBytes || uint32(cap(w.padding)) != sized.paddingBytes {
		t.Fatal("arena dimensions")
	}
}

func duplexResultsV3(t testing.TB, p liveprogram.ProgramV1) (*auth.ProcessHandshakeResultV1, *auth.ProcessHandshakeResultV1, [32]byte) {
	t.Helper()
	cp, ck, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rp, rk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(ck); clear(rk) })
	cd := auth.Dependencies{Identity: handshakeIdentity{"runtime-client", ck}, Trust: handshakeTrust{"runtime-server", rp}}
	rd := auth.Dependencies{Identity: handshakeIdentity{"runtime-server", rk}, Trust: handshakeTrust{"runtime-client", cp}}
	cfg, err := auth.NewProjectedProcessHandshakeConfigV1("runtime-client", "runtime-server", p, "tls13-tcp")
	if err != nil {
		t.Fatal(err)
	}
	digest := [32]byte{9}
	cache, _ := auth.NewHandshakeReplayCache(64)
	c, err := NewProcessWireClientHandshakeV1(cfg, cd, digest)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewProcessWireRelayHandshakeV1(cfg, rd, cache, digest)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := c.Start()
	if err != nil {
		t.Fatal(err)
	}
	sh, err := r.AcceptClientHello(ch)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := c.AcceptServerHello(sh)
	if err != nil {
		t.Fatal(err)
	}
	sf, rr, err := r.AcceptClientFinish(cf)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := c.AcceptServerFinish(sf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cr.Close)
	t.Cleanup(rr.Close)
	return cr, rr, digest
}

func boundedDuplexPairV3(t *testing.T) (*ProcessClientDuplexEndpointV3, *ProcessRelayDuplexEndpointV3) {
	t.Helper()
	p := testDuplexProgramV1()
	cr, rr, d := duplexResultsV3(t, p)
	c, e := NewProcessClientDuplexEndpointV3(cr, d, p, 1<<20, 16<<20)
	if e != nil {
		t.Fatal(e)
	}
	r, e := NewProcessRelayDuplexEndpointV3(rr, d, p, 1<<20, 16<<20)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Abort)
	t.Cleanup(r.Abort)
	b, e := c.ProfileBind([32]byte{3})
	if e != nil {
		t.Fatal(e)
	}
	ready, e := r.AcceptProfileBind(b, [32]byte{3})
	if e != nil {
		t.Fatal(e)
	}
	if e = c.AcceptEngineReady(ready); e != nil {
		t.Fatal(e)
	}
	return c, r
}

func TestDuplexBufferV3PendingCopyAndTerminalOutput(t *testing.T) {
	c, r := boundedDuplexPairV3(t)
	payload := bytes.Repeat([]byte{42}, 1536)
	record, err := c.SealDataV3(payload, 7, 19)
	if err != nil {
		t.Fatal(err)
	}
	if len(record) > int(c.BoundsV3().MaxRecordBytes) {
		t.Fatal("record cap")
	}
	pending, err := r.OpenFrameV3(record)
	if err != nil {
		t.Fatal(err)
	}
	info, err := pending.DataInfoV3()
	if err != nil || info != (framing.LiveDataInfoV3{StreamID: 7, PayloadBytes: 1536}) {
		t.Fatal("info", err)
	}
	before := r.state.recvCount
	short := bytes.Repeat([]byte{9}, 1535)
	if _, err = pending.CopyPayloadIntoV3(short); !errors.Is(err, ServiceResourceLimitV1) || !bytes.Equal(short, bytes.Repeat([]byte{9}, 1535)) {
		t.Fatal("short", err)
	}
	out := make([]byte, 1536)
	if n, e := pending.CopyPayloadIntoV3(out); n != 1536 || e != nil || !bytes.Equal(out, payload) || r.state.recvCount != before {
		t.Fatal("copy consumed", e)
	}
	copied := *pending
	if copied.Commit() == nil {
		t.Fatal("copied token")
	}
	if err = pending.Commit(); err != nil || r.state.recvCount != before+1 {
		t.Fatal("commit", err)
	}
	if _, err = pending.DataInfoV3(); !errors.Is(err, ErrAuthenticatedFrameState) {
		t.Fatal("stale info")
	}
	closeRecord, err := c.SealCloseV3(CloseCodeTerminalV1)
	if err != nil {
		t.Fatal(err)
	}
	retained := bytes.Clone(closeRecord)
	if _, err = r.OpenFrameV3(closeRecord); !errors.Is(err, ErrLinkClosed) {
		t.Fatal("close", err)
	}
	if !bytes.Equal(closeRecord, retained) {
		t.Fatal("close erased before write")
	}
	c.Abort()
	c.Abort()
	if !bytes.Equal(closeRecord, make([]byte, len(closeRecord))) || c.ReceiveBufferV3() != nil {
		t.Fatal("abort did not clear/release")
	}
}

func TestDuplexBufferV3BudgetBeforeSecret(t *testing.T) {
	p := testDuplexProgramV1()
	cr, rr, d := duplexResultsV3(t, p)
	defer rr.Close()
	if _, err := NewProcessClientDuplexEndpointV3(cr, d, p, 1<<20, 1); !errors.Is(err, ServiceResourceLimitV1) {
		t.Fatal(err)
	}
	if _, ok := cr.ContextSnapshotV1(); !ok {
		t.Fatal("budget consumed secret")
	}
	other := p.Clone()
	other.Padding.MaxPaddingBytes++
	if _, err := NewProcessClientDuplexEndpointV3(cr, d, other, 1<<20, 16<<20); err == nil {
		t.Fatal("different program")
	}
	if _, ok := cr.ContextSnapshotV1(); !ok {
		t.Fatal("mismatch consumed secret")
	}
	c, err := NewProcessClientDuplexEndpointV3(cr, d, p, 1<<20, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Abort()
	if c.BoundsV3().OwnedBytes > 16<<20 || c.BoundsV3().MaxPayloadBytes < 272 {
		t.Fatal("bounds")
	}
}

func TestRawPacketV2EndpointLegacyCiphertextAndWrap(t *testing.T) {
	for _, nonce := range []string{"counter_xor_base", "counter_append_base", "directional_counter", "stream_partitioned_counter"} {
		t.Run(nonce, func(t *testing.T) {
			program := testDuplexProgramV1()
			program.Security.Policy.NonceMode = nonce
			program.Scheduler.MaxBatchBytes = 512
			program.Padding.Mode = "fixed"
			program.Padding.MinPaddingBytes = 127
			program.Padding.MaxPaddingBytes = 127
			cr, rr, digest := duplexResultsV3(t, program)
			mirror, relay := duplexLegacyMirrorsV3(t, rr, digest, program)
			state, e := newDuplexStateV3(cr, digest, program, 1<<20, 32<<20, true)
			if e != nil {
				t.Fatal(e)
			}
			defer state.abortV1()
			raw := &processClientRawEndpointV2{ProcessClientDuplexEndpointV3{state: state}}
			exporter := [32]byte{3}
			bind, e := raw.ProfileBind(exporter)
			if e != nil {
				t.Fatal(e)
			}
			other, e := mirror.profileBindV1(exporter)
			if e != nil || !bytes.Equal(bind, other) {
				t.Fatal("bind parity", e)
			}
			ready, e := relay.acceptProfileBindV1(bind, exporter)
			if e != nil {
				t.Fatal(e)
			}
			if raw.AcceptEngineReady(ready) != nil || mirror.acceptEngineReadyV1(ready) != nil {
				t.Fatal("ready")
			}
			for _, stream := range []uint32{2, 65534, 2} {
				payload := bytes.Repeat([]byte{42}, 1537)
				got, e := raw.SealDataV3(payload, stream, int64(stream))
				if e != nil {
					t.Fatal(e)
				}
				want, e := mirror.sealOperationV1(framing.Operation{Semantic: "data", StreamID: stream, Sequence: uint64(stream), Payload: payload}, int64(stream))
				if e != nil || len(want) != 1 || !bytes.Equal(got, want[0]) {
					t.Fatal("legacy ciphertext parity", e)
				}
				frame, e := relay.openFrameV1(got)
				if e != nil {
					t.Fatal(e)
				}
				if op := frame.Operation(); op.Sequence != uint64(stream) || !bytes.Equal(op.Payload, payload) {
					t.Fatal("legacy decoded metadata")
				}
				if e = frame.Commit(); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}

func TestDuplexBufferV3ExactBudgetBoundary(t *testing.T) {
	p := testDuplexProgramV1()
	cr, rr, d := duplexResultsV3(t, p)
	c, e := NewProcessClientDuplexEndpointV3(cr, d, p, 1024, 16<<20)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Abort()
	want := c.BoundsV3().OwnedBytes
	if _, e = NewProcessRelayDuplexEndpointV3(rr, d, p, 1024, want-1); !errors.Is(e, ServiceResourceLimitV1) {
		t.Fatal("one-byte-short budget", e)
	}
	if _, ok := rr.ContextSnapshotV1(); !ok {
		t.Fatal("budget consumed result")
	}
	r, e := NewProcessRelayDuplexEndpointV3(rr, d, p, 1024, want)
	if e != nil {
		t.Fatal("exact budget", e)
	}
	defer r.Abort()
	if r.BoundsV3() != c.BoundsV3() {
		t.Fatal("role-dependent accounting")
	}
	b, err := c.state.bounded.framing.Bounds(int(c.BoundsV3().MaxPayloadBytes) + 1)
	if err == nil && 16+4*uint64(b.FrameCount)+uint64(b.FrameBytes) <= uint64(len(c.state.bounded.txBody)) {
		t.Fatal("L was not maximal")
	}
}

// Legacy mirrors are fresh owners derived from the opposite real handshake
// result's equal channel secret, not reset owners or synthetic success flags.
func duplexLegacyMirrorsV3(t *testing.T, result *auth.ProcessHandshakeResultV1, d [32]byte, p liveprogram.ProgramV1) (*processDuplexStateV1, *processDuplexStateV1) {
	t.Helper()
	snapshot, ok := result.ContextSnapshotV1()
	if !ok {
		t.Fatal("snapshot")
	}
	context, config, e := prepareProcessRecordContextV1(snapshot, true)
	if e != nil {
		t.Fatal(e)
	}
	suite, e := strictTrafficSuiteV1(snapshot.SelectedSuite)
	if e != nil {
		t.Fatal(e)
	}
	secret, e := result.TakeChannelSecretV1()
	if e != nil {
		t.Fatal(e)
	}
	schedule, e := security.DeriveKeyScheduleV1(security.KeyScheduleInput{ApplicationSecret: secret, TranscriptHash: snapshot.TranscriptHash[:], Suite: suite})
	if e != nil {
		t.Fatal(e)
	}
	defer schedule.Destroy()
	c, e := security.NewClientEnvelopeV1(schedule, context)
	if e != nil {
		t.Fatal(e)
	}
	r, e := security.NewRelayEnvelopeV1(schedule, context)
	if e != nil {
		t.Fatal(e)
	}
	cs := &processDuplexStateV1{client: true, digest: d, context: context, codec: c, program: p.Clone(), maxMessages: config.MaxSessionMessages}
	cs.self = cs
	rs := &processDuplexStateV1{digest: d, context: context, codec: r, program: p.Clone(), maxMessages: config.MaxSessionMessages}
	rs.self = rs
	t.Cleanup(cs.abortV1)
	t.Cleanup(rs.abortV1)
	return cs, rs
}

func TestDuplexBufferV3LegacyByteParityBothRoles(t *testing.T) {
	for _, client := range []bool{true, false} {
		for _, nonce := range []string{"counter_xor_base", "counter_append_base", "directional_counter", "stream_partitioned_counter"} {
			t.Run(fmt.Sprintf("client=%t/%s", client, nonce), func(t *testing.T) {
				p := testDuplexProgramV1()
				p.Security.Policy.NonceMode = nonce
				p.Scheduler.MaxBatchBytes = 512
				p.Padding.MaxPaddingBytes = 127
				p.Padding.MinPaddingBytes = 127
				p.Padding.Mode = "fixed"
				p.Security.Policy.TranscriptMode = security.TranscriptFullBindingV1
				p.Security.Policy.SecureEnvelopeMode = "full_context_bound_envelope"
				cr, rr, d := duplexResultsV3(t, p)
				source, local := rr, cr
				if !client {
					source, local = cr, rr
				}
				lc, lr := duplexLegacyMirrorsV3(t, source, d, p)
				bounded, e := newDuplexStateV3(local, d, p, 1<<20, 32<<20, client)
				if e != nil {
					t.Fatal(e)
				}
				defer bounded.abortV1()
				mirror, peer := lc, lr
				if !client {
					mirror, peer = lr, lc
				}
				exporter := [32]byte{3}
				if client {
					a, e := bounded.profileBindV1(exporter)
					if e != nil {
						t.Fatal(e)
					}
					b, e := lc.profileBindV1(exporter)
					if e != nil || !bytes.Equal(a, b) {
						t.Fatal("bind parity", e)
					}
					ready, e := lr.acceptProfileBindV1(a, exporter)
					if e != nil {
						t.Fatal(e)
					}
					if bounded.acceptEngineReadyV1(ready) != nil || lc.acceptEngineReadyV1(ready) != nil {
						t.Fatal("ready")
					}
				} else {
					bind, e := lc.profileBindV1(exporter)
					if e != nil {
						t.Fatal(e)
					}
					a, e := bounded.acceptProfileBindV1(bind, exporter)
					if e != nil {
						t.Fatal(e)
					}
					b, e := lr.acceptProfileBindV1(bind, exporter)
					if e != nil || !bytes.Equal(a, b) {
						t.Fatal("ready parity", e)
					}
					if lc.acceptEngineReadyV1(a) != nil {
						t.Fatal("ready accept")
					}
				}
				for _, size := range []int{1, 272, 1536, 4096} {
					payload := bytes.Repeat([]byte{42}, size)
					a, e := bounded.sealDataV3(payload, 65534, 19)
					if e != nil {
						t.Fatal(e)
					}
					b, e := mirror.sealOperationV1(framing.Operation{Semantic: "data", StreamID: 65534, Payload: payload}, 19)
					if e != nil || len(b) != 1 || !bytes.Equal(a, b[0]) {
						t.Fatal("data parity", size, e)
					}
					pending, e := peer.openFrameV1(a)
					if e != nil || pending.Commit() != nil {
						t.Fatal("legacy receives", e)
					}
					reverse, e := peer.sealOperationV1(framing.Operation{Semantic: "data", StreamID: 2, Payload: payload}, 23)
					if e != nil {
						t.Fatal(e)
					}
					pending, e = bounded.openFrameV3(reverse[0])
					if e != nil {
						t.Fatal(e)
					}
					copyOut := make([]byte, size)
					if _, e = pending.CopyPayloadIntoV3(copyOut); e != nil || !bytes.Equal(copyOut, payload) || pending.Commit() != nil {
						t.Fatal("bounded receives", e)
					}
					old, e := mirror.openFrameV1(reverse[0])
					if e != nil || old.Commit() != nil {
						t.Fatal("mirror receives", e)
					}
				}
				a, e := bounded.sealKeepaliveV1(0)
				if e != nil {
					t.Fatal(e)
				}
				b, e := mirror.sealKeepaliveV1(0)
				if e != nil || !bytes.Equal(a, b) {
					t.Fatal("keepalive parity", e)
				}
				if f, e := peer.openFrameV1(a); f != nil || e != nil {
					t.Fatal("keepalive", e)
				}
				a, e = bounded.sealCloseV1(CloseCodeTerminalV1)
				if e != nil {
					t.Fatal(e)
				}
				b, e = mirror.sealCloseV1(CloseCodeTerminalV1)
				if e != nil || !bytes.Equal(a, b) {
					t.Fatal("close parity", e)
				}
				if _, e = peer.openFrameV1(a); !errors.Is(e, ErrLinkClosed) {
					t.Fatal("close", e)
				}
			})
		}
	}
}

func TestDuplexBufferV3RejectMalformedAndSinglePending(t *testing.T) {
	for name, mutate := range map[string]func([]byte) []byte{
		"short": func(b []byte) []byte { return b[:47] }, "digest": func(b []byte) []byte { b[16] ^= 1; return b }, "type": func(b []byte) []byte { b[5] = wirev1.TypeClose; return b }, "outer slot": func(b []byte) []byte { binary.BigEndian.PutUint32(b[8:12], 8); return b }, "inner slot": func(b []byte) []byte { b[63] ^= 1; return b }, "tag": func(b []byte) []byte { b[len(b)-1] ^= 1; return b },
	} {
		t.Run(name, func(t *testing.T) {
			c, r := boundedDuplexPairV3(t)
			b, e := c.SealDataV3([]byte{1}, 7, 1)
			if e != nil {
				t.Fatal(e)
			}
			before := r.state.recvCount
			if f, e := r.OpenFrameV3(mutate(b)); e == nil || f != nil || !r.state.closed || r.state.recvCount != before {
				t.Fatal("malformed accepted", e)
			}
		})
	}
	for name, change := range map[string]func([]byte){"count": func(b []byte) { binary.BigEndian.PutUint16(b[10:12], 257) }, "length": func(b []byte) { binary.BigEndian.PutUint32(b[16:20], ^uint32(0)) }, "trailing": func(b []byte) { binary.BigEndian.PutUint32(b[12:16], 0) }, "reserved": func(b []byte) { b[9] = 1 }, "frame": func(b []byte) { b[len(b)-1] ^= 1 }} {
		t.Run(name, func(t *testing.T) {
			c, r := boundedDuplexPairV3(t)
			frames, e := framing.EncodeLiveOperation(testDuplexProgramV1(), framing.Operation{Semantic: "data", StreamID: 7, Payload: []byte{1}}, 1)
			if e != nil {
				t.Fatal(e)
			}
			body, e := encodeDuplexOperationBodyV1(frames)
			if e != nil {
				t.Fatal(e)
			}
			change(body)
			b, e := c.state.sealBodyLockedV1(wirev1.TypeReliableData, 7, 7, body)
			if e != nil {
				t.Fatal(e)
			}
			before := r.state.recvCount
			if f, e := r.OpenFrameV3(b); f != nil || e == nil || !r.state.closed || r.state.recvCount != before {
				t.Fatal("bad authenticated grammar", e)
			}
		})
	}
	c, r := boundedDuplexPairV3(t)
	b, e := c.SealDataV3([]byte{1}, 7, 1)
	if e != nil {
		t.Fatal(e)
	}
	pending, e := r.OpenFrameV3(b)
	if e != nil {
		t.Fatal(e)
	}
	retained := pending.operation.Payload
	if _, e = r.OpenFrameV3(b); e == nil {
		t.Fatal("second pending")
	}
	if pending.Commit() == nil || !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("pending not invalidated")
	}
}

func TestDuplexBufferV3ResourceBoundaries(t *testing.T) {
	for _, window := range []int{64, 4096} {
		t.Run(fmt.Sprint(window), func(t *testing.T) {
			p := testDuplexProgramV1()
			p.Security.Policy.NonceMode = "stream_partitioned_counter"
			p.Security.Policy.ReplayWindowSize = window
			cr, _, d := duplexResultsV3(t, p)
			for _, recordCap := range []uint32{0, 91, 100, 1<<20 + 1} {
				if _, e := NewProcessClientDuplexEndpointV3(cr, d, p, recordCap, 128<<20); !errors.Is(e, ServiceResourceLimitV1) {
					t.Fatal("record rejection", e)
				}
			}
			if _, e := NewProcessClientDuplexEndpointV3(cr, d, p, 1<<20, 128<<20+1); !errors.Is(e, ServiceResourceLimitV1) {
				t.Fatal("budget max", e)
			}
			if window == 4096 {
				for _, budget := range []uint64{16 << 20, 32 << 20} {
					if _, e := NewProcessClientDuplexEndpointV3(cr, d, p, 1<<20, budget); !errors.Is(e, ServiceResourceLimitV1) {
						t.Fatal("full bitmap admitted small budget", e)
					}
				}
			}
			budget := uint64(16 << 20)
			if window == 4096 {
				budget = 128 << 20
			}
			c, e := NewProcessClientDuplexEndpointV3(cr, d, p, 1<<20, budget)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Abort()
			w := c.state.bounded
			crypto, e := security.EnvelopeOwnedBytesV3(c.state.context)
			if e != nil {
				t.Fatal(e)
			}
			want := auth.ProjectedContextValidationBytesV3 + duplexFramingAllowanceV3 + duplexSetupAllowanceV3 + crypto + uint64(unsafe.Sizeof(*c.state)) + uint64(unsafe.Sizeof(*w)) + uint64(unsafe.Sizeof(AuthenticatedInnerFrameV1{})) + uint64(unsafe.Sizeof(*c))
			for _, v := range [][]byte{w.txFrames, w.txBody, w.rxBody, w.txRecord, w.rxRecord, w.rxPayload, w.padding} {
				if len(v) != cap(v) {
					t.Fatal("excess capacity")
				}
				want += uint64(cap(v))
			}
			if c.BoundsV3().OwnedBytes != want || want > budget || c.state.program.Schema != "" {
				t.Fatal("accounting/program retained")
			}
			t.Logf("window=%d owned=%d L=%d Rcap=%d", window, want, w.bounds.MaxPayloadBytes, w.bounds.MaxRecordBytes)
		})
	}
	p := testDuplexProgramV1()
	p.Messages[0].MaxPayloadBytes = 271
	cr, _, d := duplexResultsV3(t, p)
	if _, e := NewProcessClientDuplexEndpointV3(cr, d, p, 1<<20, 16<<20); e == nil {
		t.Fatal("signed data limit")
	}
	if _, ok := cr.ContextSnapshotV1(); !ok {
		t.Fatal("limit consumed")
	}
	c, r := boundedDuplexPairV3(t)
	before := c.state.sendCount
	tx := bytes.Clone(c.state.bounded.txRecord)
	if _, e := c.SealDataV3(make([]byte, c.BoundsV3().MaxPayloadBytes+1), 7, 1); !errors.Is(e, ServiceResourceLimitV1) || c.state.sendCount != before || !bytes.Equal(tx, c.state.bounded.txRecord) {
		t.Fatal("size changed output/nonce", e)
	}
	if _, e := r.OpenFrameV3(make([]byte, r.BoundsV3().MaxRecordBytes+1)); !errors.Is(e, ServiceResourceLimitV1) {
		t.Fatal("receive limit", e)
	}
}

func TestDuplexBufferV3AuthenticatedMessageLimit(t *testing.T) {
	for _, kind := range []string{"data", "keepalive", "close"} {
		t.Run(kind, func(t *testing.T) {
			p := testDuplexProgramV1()
			p.Limits.MaxSessionMessages = 3
			p.Limits.MaxKeyLifetimeMessages = 3
			p.Security.Policy.MaxSessionMessages = 3
			p.Security.Policy.MaxKeyLifetimeMessages = 3
			cr, rr, d := duplexResultsV3(t, p)
			c, e := NewProcessClientDuplexEndpointV3(cr, d, p, 1<<20, 16<<20)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Abort()
			r, e := NewProcessRelayDuplexEndpointV3(rr, d, p, 1<<20, 16<<20)
			if e != nil {
				t.Fatal(e)
			}
			defer r.Abort()
			bind, e := c.ProfileBind([32]byte{1})
			if e != nil {
				t.Fatal(e)
			}
			ready, e := r.AcceptProfileBind(bind, [32]byte{1})
			if e != nil {
				t.Fatal(e)
			}
			if c.AcceptEngineReady(ready) != nil {
				t.Fatal("ready")
			}
			for i := 0; i < 2; i++ {
				b, e := c.SealKeepaliveV3()
				if e != nil {
					t.Fatal(e)
				}
				if _, e = r.OpenFrameV3(b); e != nil {
					t.Fatal(e)
				}
			}
			if r.state.recvCount != 3 || r.state.maxMessages != 3 {
				t.Fatal("not authenticated limit")
			}
			// Adversarial producer can emit a valid-tag next record below the public
			// send-count guard. Receiver must refuse it before authentication/dispatch.
			body := encodeDuplexControlBodyV1(duplexKindKeepaliveV1, 0)
			typ := uint8(wirev1.TypeReliableData)
			stream := uint32(65535)
			slot := uint16(65535)
			if kind == "data" {
				frames, e := framing.EncodeLiveOperation(p, framing.Operation{Semantic: "data", StreamID: 7, Payload: []byte{1}}, 1)
				if e != nil {
					t.Fatal(e)
				}
				body, e = encodeDuplexOperationBodyV1(frames)
				if e != nil {
					t.Fatal(e)
				}
				stream = 7
				slot = 7
			}
			if kind == "close" {
				body = encodeDuplexControlBodyV1(duplexKindCloseV1, CloseCodeTerminalV1)
				typ = wirev1.TypeClose
				stream = 0
			}
			b, e := c.state.sealBodyIntoV3Locked(typ, stream, slot, body)
			if e != nil {
				t.Fatal(e)
			}
			if f, e := r.OpenFrameV3(b); f != nil || !errors.Is(e, ErrSessionMessageLimit) || r.state.recvCount != 3 {
				t.Fatal("receive count guard", e)
			}
		})
	}
}

func TestDuplexBufferV3JoinedAbortClearsBorrowedBacking(t *testing.T) {
	c, r := boundedDuplexPairV3(t)
	b, e := c.SealDataV3(bytes.Repeat([]byte{7}, 272), 7, 1)
	if e != nil {
		t.Fatal(e)
	}
	pending, e := r.OpenFrameV3(b)
	if e != nil {
		t.Fatal(e)
	}
	payloadView := pending.operation.Payload
	txView := b
	rxView := r.ReceiveBufferV3()
	copy(rxView, b)
	var joined sync.WaitGroup
	joined.Add(1)
	go func() {
		defer joined.Done()
		dst := make([]byte, 272)
		if _, e := pending.CopyPayloadIntoV3(dst); e != nil {
			t.Error(e)
		}
		if e := pending.Commit(); e != nil {
			t.Error(e)
		}
	}()
	joined.Wait()
	c.Abort()
	r.Abort()
	r.Abort()
	for _, v := range [][]byte{payloadView, txView, rxView} {
		if !bytes.Equal(v, make([]byte, len(v))) {
			t.Fatal("joined backing not cleared")
		}
	}
	if pending.Commit() == nil {
		t.Fatal("stale pending")
	}
}

func TestDuplexBufferV3SetupAllowance(t *testing.T) {
	p := testDuplexProgramV1()
	cr, rr, d := duplexResultsV3(t, p)
	snapshot, ok := cr.ContextSnapshotV1()
	if !ok {
		t.Fatal("snapshot")
	}
	context, _, e := prepareProcessRecordContextV1(snapshot, true)
	if e != nil {
		t.Fatal(e)
	}
	_ = d
	// Measure both strict-config projections and complete fixed KDF separately
	// from AEAD/arena allocation, which the envelope estimator already owns.
	suite, e := strictTrafficSuiteV1(snapshot.SelectedSuite)
	if e != nil {
		t.Fatal(e)
	}
	secret, e := rr.TakeChannelSecretV1()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(secret)
	goruntime.GC()
	var before, after goruntime.MemStats
	goruntime.ReadMemStats(&before)
	for i := 0; i < 50; i++ {
		if _, _, e := prepareProcessRecordContextV1(snapshot, true); e != nil {
			t.Fatal(e)
		}
		s, e := security.DeriveKeyScheduleV1(security.KeyScheduleInput{ApplicationSecret: bytes.Clone(secret), TranscriptHash: snapshot.TranscriptHash[:], Suite: suite})
		if e != nil {
			t.Fatal(e)
		}
		s.Destroy()
	}
	goruntime.ReadMemStats(&after)
	_ = context
	per := (after.TotalAlloc - before.TotalAlloc) / 50
	t.Logf("config+KDF=%d bytes/call", per)
	if per > duplexSetupAllowanceV3 {
		t.Fatal("setup allowance")
	}
}

func TestDuplexBufferV3FramingConstructionAllowance(t *testing.T) {
	ordinary := testDuplexProgramV1()
	worst := ordinary.Clone()
	worst.SourceSchemaVersion = strings.Repeat("s", 256)
	worst.Security.CompilerSecurityVersion = strings.Repeat("c", 256)
	worst.Security.MinimumRuntimeVersion = strings.Repeat("r", 256)
	worst.Security.Policy.SecurityVersion = strings.Repeat("v", 256)
	worst.Scheduler.PriorityMode = strings.Repeat("<", 256)
	worst.Messages[0].WireSymbol = strings.Repeat("a", 96)
	worst.Messages[1].WireSymbol = strings.Repeat("b", 96)
	worst.Frame.Compiled.DataTypeTag = bytes.Repeat([]byte{1}, 255)
	worst.Frame.Compiled.PaddingTypeTag = bytes.Repeat([]byte{2}, 255)
	worst.Security.SelectedCapabilities = []string{"adapter_interface", "carrier_abstraction", "carrier_backpressure", "carrier_loss_recovery", "generated_backend", "multi_stream", "nonce_schedule", "proxy_semantics", "replay_window", "transcript_binding"}
	worst.Security.ClientMandatoryCapabilities = worst.Security.SelectedCapabilities
	worst.Security.RelayMandatoryCapabilities = worst.Security.SelectedCapabilities
	for name, p := range map[string]liveprogram.ProgramV1{"ordinary": ordinary, "max_fields": worst} {
		t.Run(name, func(t *testing.T) {
			goruntime.GC()
			var before, after goruntime.MemStats
			goruntime.ReadMemStats(&before)
			var retained *framing.LiveDataCodecV3
			for i := 0; i < 50; i++ {
				var e error
				retained, e = framing.NewLiveDataCodecV3(p)
				if e != nil {
					t.Fatal(e)
				}
			}
			goruntime.ReadMemStats(&after)
			goruntime.KeepAlive(retained)
			per := (after.TotalAlloc - before.TotalAlloc) / 50
			t.Logf("framing construction=%d bytes/call", per)
			if per > duplexFramingAllowanceV3 {
				t.Fatal("framing allowance")
			}
		})
	}
}

func BenchmarkDuplexBufferV3RoundTrip(b *testing.B) {
	// Authentication fixture setup is outside the measurement. Keep real fresh
	// identities per record; no pooling and no network/device dependencies.
	p := testDuplexProgramV1()
	p.Limits.MaxSessionMessages = 1 << 24
	p.Limits.MaxKeyLifetimeMessages = 1 << 24
	p.Security.Policy.MaxSessionMessages = 1 << 24
	p.Security.Policy.MaxKeyLifetimeMessages = 1 << 24
	cr, rr, d := duplexResultsV3(b, p)
	c, e := NewProcessClientDuplexEndpointV3(cr, d, p, 1<<20, 16<<20)
	if e != nil {
		b.Fatal(e)
	}
	defer c.Abort()
	r, e := NewProcessRelayDuplexEndpointV3(rr, d, p, 1<<20, 16<<20)
	if e != nil {
		b.Fatal(e)
	}
	defer r.Abort()
	bind, e := c.ProfileBind([32]byte{1})
	if e != nil {
		b.Fatal(e)
	}
	ready, e := r.AcceptProfileBind(bind, [32]byte{1})
	if e != nil {
		b.Fatal(e)
	}
	if c.AcceptEngineReady(ready) != nil {
		b.Fatal("ready")
	}
	payload := make([]byte, 1536)
	out := make([]byte, 1536)
	b.SetBytes(1536)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		record, e := c.SealDataV3(payload, 7, 1)
		if e != nil {
			b.Fatal(e)
		}
		pending, e := r.OpenFrameV3(record)
		if e != nil {
			b.Fatal(e)
		}
		if _, e = pending.CopyPayloadIntoV3(out); e != nil {
			b.Fatal(e)
		}
		if e = pending.Commit(); e != nil {
			b.Fatal(e)
		}
	}
}
