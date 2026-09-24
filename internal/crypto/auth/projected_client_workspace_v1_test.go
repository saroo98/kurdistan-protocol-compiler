// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/ir"
	"math"
	"reflect"
	"testing"
	"unsafe"
)

// These literal requirements independently exercise the pinned local capacity
// recurrences. Overflow must refuse, never turn a large requirement into zero.
func TestProjectedClientWorkspaceV1CheckedCapacity(t *testing.T) {
	for _, tc := range []struct {
		n, clone, retained, growth, json uint64
	}{
		{0, 0, 72, 72, 216},
		{1, 10, 76, 79, 228},
		{32, 72, 200, 296, 600},
		{65536, 131080, 262216, 458824, 786648},
	} {
		c := projectedWorkspaceArithmeticV1{}
		if got := c.clone(tc.n); got != tc.clone {
			t.Fatalf("clone(%d)=%d want %d", tc.n, got, tc.clone)
		}
		if got := c.retained(tc.n); got != tc.retained {
			t.Fatalf("retained(%d)=%d want %d", tc.n, got, tc.retained)
		}
		if got := c.growth(tc.n); got != tc.growth {
			t.Fatalf("growth(%d)=%d want %d", tc.n, got, tc.growth)
		}
		if got := c.json(tc.n); got != tc.json {
			t.Fatalf("json(%d)=%d want %d", tc.n, got, tc.json)
		}
		if c.overflow {
			t.Fatal("valid requirement overflowed")
		}
	}
	for _, operation := range []func(*projectedWorkspaceArithmeticV1){
		func(c *projectedWorkspaceArithmeticV1) { c.add(math.MaxUint64, 1) },
		func(c *projectedWorkspaceArithmeticV1) { c.mul(math.MaxUint64, 2) },
		func(c *projectedWorkspaceArithmeticV1) { c.clone(math.MaxUint64 / 2) },
		func(c *projectedWorkspaceArithmeticV1) { c.retained(math.MaxUint64 / 4) },
		func(c *projectedWorkspaceArithmeticV1) { c.growth(math.MaxUint64 / 7) },
		func(c *projectedWorkspaceArithmeticV1) { c.json(math.MaxUint64 / 12) },
	} {
		c := projectedWorkspaceArithmeticV1{}
		operation(&c)
		if !c.overflow {
			t.Fatal("overflow accepted")
		}
	}
}

func TestProjectedClientWorkspaceV1StageCoverageIsSubset(t *testing.T) {
	c := projectedWorkspaceArithmeticV1{}
	// Two different live stages, not max(total) minus max(coverage): stage one
	// has 100 bytes with 90 already charged; stage two has 80 with 20 charged.
	if got := c.additional([2]uint64{100, 90}, [2]uint64{80, 20}); got != 60 || c.overflow {
		t.Fatalf("additional=%d overflow=%v", got, c.overflow)
	}
	c = projectedWorkspaceArithmeticV1{}
	_ = c.additional([2]uint64{100, 101})
	if !c.overflow {
		t.Fatal("non-subset coverage silently clamped")
	}
}

func TestProjectedClientWorkspaceV1CanonicalLengths(t *testing.T) {
	f := newFirstContactFixture(t, security.TranscriptFullBindingV1)
	p := projectedProcessProgramV1(f.input.SelectedPolicy)
	q, err := NewProjectedProcessHandshakeConfigV1(f.input.Client.IdentityID, f.input.Server.IdentityID, p, "tls13-tcp")
	if err != nil {
		t.Fatal(err)
	}
	l, err := projectedWorkspaceLengthsForV1(p, f.input.Client.IdentityID, f.input.Server.IdentityID)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := security.EncodePolicyV1(q.input.SelectedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	client, server, err := projectedModeBindings(q.input)
	if err != nil {
		t.Fatal(err)
	}
	k, err := security.CanonicalCompatibilityBlockV1(client.CompatibilityBlock)
	if err != nil {
		t.Fatal(err)
	}
	g, err := security.CanonicalConfigSourceBlockV1(client.ConfigSourceBlock)
	if err != nil {
		t.Fatal(err)
	}
	m, err := security.CanonicalAuthenticatedModeBindingV1(p.Security.Policy.TranscriptMode, client)
	if err != nil {
		t.Fatal(err)
	}
	b, err := security.CanonicalHandshakeModeBinding(p.Security.Policy.TranscriptMode, server)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		name     string
		got      uint64
		actual   int
		capacity int
	}{
		{"policy", l.policy, len(policy), cap(policy)}, {"compatibility", l.compatibility, len(k), cap(k)},
		{"config", l.config, len(g), cap(g)}, {"mode", l.mode, len(m), cap(m)}, {"old-mode", l.oldMode, len(b), cap(b)},
	} {
		if v.got != uint64(v.actual) {
			t.Fatalf("%s length %d actual %d", v.name, v.got, v.actual)
		}
		c := projectedWorkspaceArithmeticV1{}
		if uint64(v.capacity) > c.retained(v.got) {
			t.Fatalf("%s returned capacity %d exceeds source envelope", v.name, v.capacity)
		}
	}
	clientHandshake, err := NewClientProcessHandshakeV1(q, f.input.ClientDependencies)
	if err != nil {
		t.Fatal(err)
	}
	defer clientHandshake.Close()
	hello, err := clientHandshake.Start()
	if err != nil {
		t.Fatal(err)
	}
	if l.hello != uint64(len(hello)) {
		t.Fatalf("hello %d actual %d", l.hello, len(hello))
	}
	c := projectedWorkspaceArithmeticV1{}
	if uint64(cap(hello)) > c.clone(l.hello) {
		t.Fatal("returned Hello capacity exceeds clone envelope")
	}
	if n := testing.AllocsPerRun(10, func() {
		_, e := projectedWorkspaceLengthsForV1(p, f.input.Client.IdentityID, f.input.Server.IdentityID)
		if e != nil {
			panic(e)
		}
	}); n != 0 {
		t.Fatalf("pure arithmetic allocated: %v", n)
	}
	j, err := projectedWorkspaceJSONForV1(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		value any
		bound uint64
	}{{q.input.SelectedPolicy, j.policy}, {q.input.Client.modeBinding, j.binding}, {p.Frame, j.projection}, {p.Messages, j.projection}, {p.Scheduler, j.projection}, {p.Padding, j.projection}, {p.Stream, j.projection}} {
		raw, e := json.Marshal(v.value)
		if e != nil {
			t.Fatal(e)
		}
		if uint64(len(raw)) > v.bound {
			t.Fatalf("JSON output %d exceeds structural bound %d", len(raw), v.bound)
		}
		if uint64(cap(raw)) > c.clone(v.bound) {
			t.Fatal("returned JSON capacity exceeds source clone envelope")
		}
	}
}

func TestProjectedClientWorkspaceV1MaximumJSONLeaves(t *testing.T) {
	f := newFirstContactFixture(t, security.TranscriptFullBindingV1)
	p := projectedProcessProgramV1(f.input.SelectedPolicy)
	// Calculation-only maximum-cardinality serializer shape, not an auth or
	// Program admission fixture. Only the actual JSON encoder is observed here.
	p.Frame.Compiled.DataTypeTag = bytes.Repeat([]byte{255}, 255)
	p.Frame.Compiled.PaddingTypeTag = bytes.Repeat([]byte{255}, 255)
	p.Security.SelectedCapabilities = ir.SecurityCapabilities()
	j, err := projectedWorkspaceJSONForV1(p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(p.Frame)
	if err != nil {
		t.Fatal(err)
	}
	c := projectedWorkspaceArithmeticV1{}
	if uint64(len(raw)) > j.projection || uint64(cap(raw)) > c.clone(j.projection) {
		t.Fatal("maximum leaf output/capacity exceeds source bound")
	}
	p.Frame.Compiled.DataTypeTag = append(p.Frame.Compiled.DataTypeTag, 0)
	if _, err := projectedWorkspaceJSONForV1(p); err == nil {
		t.Fatal("over-maximum leaf accepted by sizing")
	}
}

func TestProjectedClientWorkspaceV1CloneGraph(t *testing.T) {
	b, err := projectedWorkspaceClonesForV1(10, 10, 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	if b.policy != 984 || b.compatibility != 552 || b.binding != 1008 || b.clientPeer != 3632 || b.relayPeer != 3632 || b.config != 8576 || b.snapshot != 4104 || b.hashInput != 3000 {
		t.Fatalf("maximum clone graph %#v", b)
	}
	if _, err := projectedWorkspaceClonesForV1(11, 10, 10, 1); err == nil {
		t.Fatal("impossible mandatory subset accepted")
	}
	if _, err := projectedWorkspaceClonesForV1(1, 1, math.MaxUint64, 1); err == nil {
		t.Fatal("unbounded count accepted")
	}
}

func TestProjectedClientWorkspaceV1JSONProbabilityBound(t *testing.T) {
	f := newFirstContactFixture(t, security.TranscriptFullBindingV1)
	p := projectedProcessProgramV1(f.input.SelectedPolicy)
	for _, v := range []float64{0, math.SmallestNonzeroFloat64, math.Nextafter(1e-6, 0), 1e-6, math.Nextafter(1e-6, 1), math.Nextafter(1, 0), 1} {
		p.Padding.Probability = v
		raw, err := json.Marshal(p.Padding)
		if err != nil {
			t.Fatal(err)
		}
		j, err := projectedWorkspaceJSONForV1(p)
		if err != nil || uint64(len(raw)) > j.projection {
			t.Fatalf("probability JSON bytes %d exceed %d: %v", len(raw), j.projection, err)
		}
		value, err := json.Marshal(v)
		if err != nil || len(value) > 24 {
			t.Fatalf("float bytes %d exceed24: %v", len(value), err)
		}
	}
	if n := testing.AllocsPerRun(10, func() {
		_, err := projectedWorkspaceJSONForV1(p)
		if err != nil {
			panic(err)
		}
	}); n != 0 {
		t.Fatalf("JSON calculation allocated: %v", n)
	}
}

func TestProjectedClientWorkspaceV1ConfirmationChildren(t *testing.T) {
	var transcript [32]byte
	key := bytes.Repeat([]byte{7}, 32)
	private := ed25519.NewKeyFromSeed(key)
	defer clear(private)
	for _, label := range []string{"kurdistan/hkdf/v1/client-confirm", "kurdistan/hkdf/v1/server-confirm"} {
		info := keyInfo(label, transcript, 0)
		if len(info) != 76 || cap(info) > 376 {
			t.Fatal("keyInfo length/capacity", len(info), cap(info))
		}
	}
	mac := confirm(key, "kurdistan/handshake/v1/server-key-confirm", transcript)
	defer clear(mac)
	if len(mac) != 32 || cap(mac) > 72 {
		t.Fatal("confirmation MAC capacity", len(mac), cap(mac))
	}
	client, server, prk, err := confirmationKeys(key, transcript, transcript, transcript, transcript, transcript, transcript)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(client)
	defer clear(server)
	defer clear(prk)
	for _, output := range [][]byte{client, server, prk} {
		if len(output) != 32 || cap(output) > 72 {
			t.Fatal("HKDF output capacity", len(output), cap(output))
		}
	}
	full, body := makeClientFinish(private, client, transcript)
	if len(full) != 136 || cap(full) > 616 || len(body) != 132 || cap(body) > 272 {
		t.Fatal("finish capacity", len(full), cap(full), len(body), cap(body))
	}
	serverFull, _ := makeServerFinish(private, server, transcript)
	validated, err := validateServerFinish(serverFull, private.Public().(ed25519.PublicKey), server, transcript)
	if err != nil || len(validated) != 132 || cap(validated) > 272 {
		t.Fatal("validated finish capacity", err)
	}
	serverFull[len(serverFull)-1] ^= 1
	_, err = validateServerFinish(serverFull, private.Public().(ed25519.PublicKey), server, transcript)
	assertHandshakeCode(t, err, FailureKeyConfirmation)
	// Pinned returned crypto object layouts, not heap-peak measurements.
	if reflect.TypeOf(hmac.New(sha256.New, key)).Elem().Size() != 96 || reflect.TypeOf(sha256.New()).Elem().Size() != 120 {
		t.Fatal("unproven named crypto holder layout")
	}
	c := projectedWorkspaceArithmeticV1{}
	children := c.confirmationChildrenV1()
	// Independent lower bounds: both keyInfo retained buffers (R(76)=376),
	// info string76 and byte conversion76, HKDF return32 and PRK/client72; make's
	// body R(132)=600 plus unsigned A(36)=80 and MAC A(32)=72; validate's
	// decoded A(132)=272 plus MAC72. Named/root holders add beyond these.
	for i, minimum := range []uint64{1080, 752, 344, 72} {
		if children[i] < minimum {
			t.Fatalf("confirmation child %d omitted: %d < %d", i, children[i], minimum)
		}
	}
	if c.overflow {
		t.Fatal("fixed confirmation arithmetic overflow")
	}
	if n := c.confirmationMalformedFinishV1(65536); n < 131072 {
		t.Fatal("missing maximum decoded finish body", n)
	}
}

func TestProjectedClientWorkspaceV1ConfirmationAncestors(t *testing.T) {
	for _, mode := range []string{security.TranscriptCanonicalV1, security.TranscriptCapabilitiesV1, security.TranscriptCarrierBindingV1, security.TranscriptFullBindingV1} {
		f := newFirstContactFixture(t, mode)
		p := projectedProcessProgramV1(f.input.SelectedPolicy)
		for _, frame := range []int{184, 4096, 65584, 1 << 20} {
			p.Limits.MaxFrameBytes = frame
			bounds, err := ProjectedClientWorkspaceV1(p, f.input.Client.IdentityID, f.input.Server.IdentityID)
			if err != nil {
				t.Fatal(err)
			}
			c := projectedWorkspaceArithmeticV1{}
			child := c.confirmationChildrenV1()
			q := uint64(min(65536, frame-48))
			// Independently enumerate the parser's three clones, two q-sized
			// fields and signature while the already-retained client/Hello lives.
			parsed := 2*(q-4) + 8 + 2*q + 64 + 2*(q-68) + 8 + 2*(q-4) + 8 + uint64(unsafe.Sizeof(serverHello{}))
			helloAncestors := bounds.AwaitHelloBytes + parsed + uint64(unsafe.Sizeof(FirstContactInput{})) + uint64(unsafe.Sizeof(projectedCanonicalHoldersV1{})) + uint64(unsafe.Sizeof(projectedAcceptHelloHoldersV1{}))
			for _, extra := range []uint64{32 + child[0], 32 + 32 + 32 + 72 + child[1]} {
				if bounds.Stages[3] < helloAncestors+extra {
					t.Fatal("confirmation lost Hello ancestors", mode, frame)
				}
			}
			// AwaitFinish already includes both retained32-byte keys; caller
			// input136, two decoded/returned A(132)=272, and one further32 stay.
			finishAncestors := bounds.AwaitFinishBytes + 136 + 272 + 272 + 32 + uint64(unsafe.Sizeof(projectedCanonicalHoldersV1{})) + uint64(unsafe.Sizeof(projectedAcceptFinishHoldersV1{}))
			for _, extra := range child[2:] {
				if bounds.Stages[4] < finishAncestors+extra {
					t.Fatal("confirmation lost finish ancestors", mode, frame)
				}
			}
		}
	}
}

func TestProjectedClientWorkspaceV1FiniteStages(t *testing.T) {
	f := newFirstContactFixture(t, security.TranscriptFullBindingV1)
	p := projectedProcessProgramV1(f.input.SelectedPolicy)
	b, err := ProjectedClientWorkspaceV1(p, f.input.Client.IdentityID, f.input.Server.IdentityID)
	if err != nil {
		t.Fatal(err)
	}
	if b.HelloBytes == 0 || b.PeerHelloBytes != uint64(p.Limits.MaxFrameBytes-48) {
		t.Fatal("wrong source-sized peer envelope", b)
	}
	for _, n := range b.Stages {
		if n == 0 {
			t.Fatal("uncounted stage")
		}
	}
	if n := testing.AllocsPerRun(10, func() {
		_, e := ProjectedClientWorkspaceV1(p, f.input.Client.IdentityID, f.input.Server.IdentityID)
		if e != nil {
			panic(e)
		}
	}); n != 0 {
		t.Fatalf("workspace calculation allocated %v", n)
	}
	p.Limits.MaxFrameBytes = 1 << 20
	large, err := ProjectedClientWorkspaceV1(p, f.input.Client.IdentityID, f.input.Server.IdentityID)
	if err != nil || large.PeerHelloBytes != 65536 {
		t.Fatal("peer upper bound incorrectly clipped to current output", err)
	}
	if b.HelloBytes != large.HelloBytes {
		t.Fatal("outgoing length depends on unknown peer")
	}
}
