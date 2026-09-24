// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package auth

import (
	"bytes"
	"crypto/ecdh"
	"hash"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"math"
	"unsafe"
)

// ProjectedClientWorkspaceBoundsV1 is calculation-only. Stages are projection,
// client construction, Hello, ServerHello, final confirmation, returned result.
// Caller/transport/frame ownership is added in the containing packages.
type ProjectedClientWorkspaceBoundsV1 struct {
	Stages                     [6]uint64
	HelloBytes, PeerHelloBytes uint64
	// Retained between serial auth calls, without transient parser/serializer work.
	ClientBytes, AwaitHelloBytes, AwaitFinishBytes uint64
}
type projectedProjectionHoldersV1 struct {
	program       liveprogram.ProgramV1
	policy        ir.EffectiveSecurityPolicy
	binding       security.HandshakeModeBinding
	client, relay PeerParameters
	result        ProcessHandshakeConfigV1
}
type projectedPeerHoldersV1 struct {
	program        liveprogram.ProgramV1
	policy         ir.EffectiveSecurityPolicy
	binding        security.HandshakeModeBinding
	peer           PeerParameters
	offered, floor []string
	identity       string
	err            error
}
type projectedConfigHoldersV1 struct {
	client, relay PeerParameters
	selected      ir.EffectiveSecurityPolicy
	capabilities  []string
	input         FirstContactInput
	result        ProcessHandshakeConfigV1
}
type projectedValidationHoldersV1 struct {
	input         FirstContactInput
	client, relay security.HandshakeModeBinding
	encoded       [10][]byte // two modes, three lists, five policies
	profileHash   [32]byte
	selection     security.BilateralCapabilityInput
}
type projectedSealLoopHoldersV1 struct {
	input FirstContactInput
	peers [2]PeerParameters
	peer  PeerParameters
	seal  [32]byte
	err   error
}
type projectedSealCallHoldersV1 struct {
	peer    PeerParameters
	encoded [5][]byte
	err     error
	parts   [8][]byte
}
type projectedModeBindingItemV1 struct {
	mode            string
	stored, derived security.HandshakeModeBinding
}
type projectedModeBindingsHoldersV1 struct {
	input                          FirstContactInput
	client, server                 security.HandshakeModeBinding
	clientOptional, serverOptional []string
	items                          [2]projectedModeBindingItemV1
	item                           projectedModeBindingItemV1
	derivedRaw, storedRaw          []byte
	err                            error
}
type projectedContextSourcesHoldersV1 struct {
	input                      FirstContactInput
	client, server             security.HandshakeModeBinding
	hashInput                  security.AuthenticatedContextHashInputV1
	policyHash, capabilityHash [32]byte
	err                        error
}
type projectedContextValidHoldersV1 struct {
	context           AuthenticatedContextV1
	snapshot          AuthenticatedContextSnapshotV1
	hashInput         security.AuthenticatedContextHashInputV1
	contextHash, seal [32]byte
	err               error
}
type projectedContextHoldersV1 struct {
	input         FirstContactInput
	client, relay security.HandshakeModeBinding
	hashInput     security.AuthenticatedContextHashInputV1
	snapshot      AuthenticatedContextSnapshotV1
	context       AuthenticatedContextV1
	hashes        [4][32]byte
	suite         security.SelectedSuiteV1
}
type projectedContextHashHoldersV1 struct {
	input                                   security.AuthenticatedContextHashInputV1
	encoded                                 [11][]byte
	profileHash, policyHash, capabilityHash [32]byte
	version                                 [2]byte
	parts                                   [22][]byte
}
type projectedBindingHoldersV1 struct {
	input                                    security.AuthenticatedContextHashInputV1
	validated, binding                       security.HandshakeModeBinding
	config                                   security.ConfigSourceBlockV1
	compatibility                            security.CompatibilityBlockV1
	wantCompatibility, wantLimit, wantConfig [32]byte
	encoded                                  [4][]byte
	out                                      bytes.Buffer
	lists                                    [5][]string
	hashes                                   [11][32]byte
}
type projectedCanonicalHoldersV1 struct {
	configHash, configEncoder, configValidator security.ConfigSourceBlockV1
	policy                                     ir.EffectiveSecurityPolicy
	strings                                    [13]string
	lists                                      [5][]string
	buffer, shaInput                           bytes.Buffer
	parts                                      [8][]byte
	fixed                                      [8]byte
}

func (c *projectedWorkspaceArithmeticV1) hash(label string, parts ...uint64) uint64 {
	n := c.text(label)
	for _, p := range parts {
		n = c.add(n, c.lp(p))
	}
	return c.growth(n)
}

// ProjectedClientWorkspaceV1 evaluates pinned source stage equations before
// identity operations. Inputs must come from the genuine private admitted Plan;
// numeric output confers no provenance. Backend-private standard-crypto
// arithmetic registers/stack scratch are excluded, not native serializers,
// key inputs/results or retained ECDH/auth objects. No RSS/stack ceiling follows.
func ProjectedClientWorkspaceV1(p liveprogram.ProgramV1, clientID, relayID string) (ProjectedClientWorkspaceBoundsV1, error) {
	var result ProjectedClientWorkspaceBoundsV1
	if unsafe.Sizeof(uintptr(0)) != 8 || unsafe.Sizeof("") != 16 || p.Limits.MaxFrameBytes < 48+136 || p.Limits.MaxFrameBytes > 1<<20 {
		return result, fail(FailureInternalLimit)
	}
	l, err := projectedWorkspaceLengthsForV1(p, clientID, relayID)
	if err != nil {
		return result, err
	}
	j, err := projectedWorkspaceJSONForV1(p)
	if err != nil {
		return result, err
	}
	b, err := projectedWorkspaceClonesForV1(l.clientCount, l.relayCount, l.selectedCount, l.proxyCount)
	if err != nil {
		return result, err
	}
	c := projectedWorkspaceArithmeticV1{}
	a, r, w := c.clone, c.retained, c.growth
	q := min(uint64(65536), uint64(p.Limits.MaxFrameBytes-48))
	result.HelloBytes, result.PeerHelloBytes = l.hello, q
	// Ten-entry Swiss map: header48, table32, directory8, two 8-slot
	// string-key groups. Bilateral normalization retains four lists+selected.
	mapTen := uint64(48 + 32 + 8 + 2*(8+8*16))
	listBacking := a(c.mul(16, l.selectedCount))
	normalize := c.add(c.mul(2, mapTen), c.mul(5, listBacking))
	canonicalFixed := uint64(unsafe.Sizeof(projectedCanonicalHoldersV1{}))
	policyWork := max(c.add(normalize, c.json(j.policy)), w(l.policy))
	listMax := max(l.selected, l.clientFloor, l.relayFloor, l.features, l.clientOptional, l.relayOptional)
	compatWork := c.add(w(l.compatibility), r(listMax))
	configWork := c.add(w(l.config), r(l.suite))
	bindingWork := max(compatWork,
		c.add(r(l.compatibility), max(compatWork, c.add(r(l.compatibility), c.hash("kurdistan/context/v1/compatibility-block", l.compatibility)))),
		c.add(r(l.compatibility), w(36)),
		c.add(r(l.compatibility), r(36), max(w(36), c.add(r(36), c.hash("kurdistan/context/v1/limit-block", 36)))),
		c.add(r(l.compatibility), r(36), configWork),
		c.add(r(l.compatibility), r(36), r(l.config), max(configWork, c.add(r(l.config), c.hash("kurdistan/context/v1/config-source-block", l.config)))),
		c.add(r(l.compatibility), r(36), r(l.config), w(l.mode), r(listMax)))
	bindingWork = c.add(bindingWork, uint64(unsafe.Sizeof(projectedBindingHoldersV1{})), canonicalFixed)
	// ContextHash accumulates only returned outputs; child scratch is maxed.
	contextWork := policyWork
	retained := r(l.policy)
	contextWork = max(contextWork, c.add(retained, max(policyWork, c.add(r(l.policy), c.hash("kurdistan/policy/v1/effective", l.policy)))))
	retained = c.add(retained, 32)
	contextWork = max(contextWork, c.add(retained, w(l.suite)))
	retained = c.add(retained, r(l.suite))
	contextWork = max(contextWork, c.add(retained, normalize, c.json(c.jlist(p.Security.SelectedCapabilities))))
	for range 2 {
		contextWork = max(contextWork, c.add(retained, bindingWork))
		retained = c.add(retained, r(l.mode))
	}
	for range 2 {
		contextWork = max(contextWork, c.add(retained, compatWork, canonicalFixed))
		retained = c.add(retained, r(l.compatibility))
	}
	for range 2 {
		contextWork = max(contextWork, c.add(retained, w(36), canonicalFixed))
		retained = c.add(retained, r(36))
	}
	for range 2 {
		contextWork = max(contextWork, c.add(retained, configWork, canonicalFixed))
		retained = c.add(retained, r(l.config))
	}
	contextWork = max(contextWork, c.add(retained, w(l.contextHash)))
	contextWork = c.add(contextWork, uint64(unsafe.Sizeof(projectedContextHashHoldersV1{})))
	sealRaw := c.add(c.mul(2, r(l.policy)), r(l.selected), r(max(l.clientFloor, l.relayFloor)))
	sealHash := c.hash("kurdistan/handshake/v1/peer-parameters", uint64(max(len(clientID), len(relayID))), 32, 32, l.policy, l.policy, l.selected, max(l.clientFloor, l.relayFloor), j.binding)
	sealWork := c.add(sealRaw, max(c.json(j.binding), c.add(a(j.binding), a(uint64(max(len(clientID), len(relayID)))), a(32), sealHash)), canonicalFixed, uint64(unsafe.Sizeof(projectedSealCallHoldersV1{})))
	derived := c.add(c.mul(2, b.binding), c.mul(3, a(c.mul(16, l.selectedCount-l.clientCount))), c.mul(3, a(c.mul(16, l.selectedCount-l.relayCount))))
	// Literal two-peer and four-policy loop value holders are sequential;
	// account the larger active loop, not one backing per iteration.
	validationLoops := max(3*uint64(unsafe.Sizeof(PeerParameters{})), 5*uint64(unsafe.Sizeof(ir.EffectiveSecurityPolicy{})))
	modeBindingFixed := uint64(unsafe.Sizeof(projectedModeBindingsHoldersV1{}))
	validationWork := max(c.add(sealWork, uint64(unsafe.Sizeof(projectedSealLoopHoldersV1{}))), c.add(normalize, policyWork, validationLoops), c.add(derived, bindingWork, modeBindingFixed),
		c.add(derived, c.mul(5, r(l.policy)), c.mul(2, r(l.oldMode)), c.mul(3, r(l.selected)), b.hashInput, contextWork, uint64(unsafe.Sizeof(projectedContextSourcesHoldersV1{}))))
	validationWork = c.add(validationWork, uint64(unsafe.Sizeof(projectedValidationHoldersV1{})))
	// Feature construction grows4->8->16 slots; the old8/new16 overlap is
	// charged at that stage, not mistaken for the nil-append clone recurrence.
	featureCount := 4 + l.selectedCount
	featureBytes := l.features - 4 - 4*featureCount
	generated := c.add(160, featureBytes)
	bindingOriginal := c.add(16*16, 3*16, listBacking, 16, 16*l.proxyCount, 16)
	projectionRoot := uint64(unsafe.Sizeof(projectedProjectionHoldersV1{}))
	// scheduler-policy is the longest domain among the eight sequential projections.
	projectionBuild := c.add(b.policy, bindingOriginal, 8*16+16*16, max(c.json(j.projection), c.add(a(j.projection), c.hash("kurdistan/live-program/v1/scheduler-policy", j.projection))), canonicalFixed)
	projectionPeers := c.add(b.policy, bindingOriginal, b.clientPeer, b.relayPeer, sealWork, uint64(unsafe.Sizeof(projectedPeerHoldersV1{})))
	projectionConfig := c.add(b.policy, bindingOriginal, b.clientPeer, b.relayPeer, b.config, validationWork, uint64(unsafe.Sizeof(projectedConfigHoldersV1{})))
	result.Stages[0] = c.add(projectionRoot, generated, max(projectionBuild, projectionPeers, projectionConfig))
	credentials := c.add(64, 64, 32, a(64), a(32))
	clientFixed := uint64(unsafe.Sizeof(ClientProcessHandshakeV1{}))
	configFixed := uint64(unsafe.Sizeof(ProcessHandshakeConfigV1{}))
	result.Stages[1] = c.add(generated, configFixed, b.config, max(validationWork, c.add(credentials, clientFixed, b.config)))
	clientRetained := c.add(generated, clientFixed, b.config, a(64), a(32))
	ecdhRetained := c.add(uint64(unsafe.Sizeof(ecdh.PrivateKey{})), uint64(unsafe.Sizeof(ecdh.PublicKey{})), a(32), 32)
	start := c.add(a(l.hello), a(l.hello-4))
	offer := c.add(c.lp(l.policy), c.lp(l.selected))
	floor := c.add(c.lp(l.policy), c.lp(l.clientFloor))
	helloUnsigned := l.hello - 68
	helloBuild := c.add(r(offer), r(floor), r(helloUnsigned), 64, max(c.hash("kurdistan/handshake/v1/client-hello-signature", helloUnsigned), c.add(a(helloUnsigned), a(c.add(a(helloUnsigned), 64)), w(l.hello))))
	helloReturn := c.add(r(l.hello), a(l.hello-4), start, a(l.hello))
	result.Stages[2] = c.add(clientRetained, ecdhRetained, uint64(unsafe.Sizeof(PeerParameters{})), canonicalFixed, max(helloBuild, helloReturn, policyWork))
	// LP allocations together fit q; identity string conversion may copy q
	// again on malformed input before legitimate128-byte identity validation.
	parsed := c.add(a(q-4), c.mul(2, q), 64, a(q-68), a(q-4), uint64(unsafe.Sizeof(serverHello{})))
	finish := c.add(start, a(q), a(q-4), a(136), a(132))
	helloValidate := c.add(r(offer), r(floor), r(c.add(c.lp(l.policy), c.lp(l.relayFloor))), r(c.add(offer, 64)), c.hash("kurdistan/handshake/v1/server-hello-signature", l.hello-4, q-68))
	finishBuild := c.add(32, 32, 32, 32, 64, r(132), r(136), a(132), a(136), c.hash("kurdistan/handshake/v1/transcript-hello", l.hello-4, q-4))
	confirmation := c.confirmationChildrenV1()
	// Keep AcceptServerHello ancestors while deriving keys or constructing the
	// finish. dh32, returned client/server keys32 each and extracted PRK A(32)
	// remain distinct from the child serializer/HMAC roots.
	result.Stages[3] = c.add(clientRetained, ecdhRetained, start, parsed, uint64(unsafe.Sizeof(FirstContactInput{})), canonicalFixed,
		uint64(unsafe.Sizeof(projectedAcceptHelloHoldersV1{})),
		max(helloValidate, finishBuild, c.add(32, confirmation[0]), c.add(32, 32, 32, a(32), confirmation[1]), c.add(a(q), a(q-4), a(136), a(132), a(136))))
	contextCreate := c.add(uint64(unsafe.Sizeof(projectedContextHoldersV1{})), max(c.add(derived, bindingWork, modeBindingFixed), c.add(derived, b.hashInput, b.snapshot, b.hashInput, contextWork, uint64(unsafe.Sizeof(projectedContextValidHoldersV1{})))))
	evidence := c.add(a(l.hello), a(q), c.mul(2, a(136)))
	returned := c.add(uint64(unsafe.Sizeof(ProcessHandshakeResultV1{})), b.snapshot, a(32), evidence, generated)
	result.Stages[4] = c.add(clientRetained-a(64), finish, 136, a(132), a(132), 32, 32, 32, canonicalFixed,
		uint64(unsafe.Sizeof(projectedAcceptFinishHoldersV1{})),
		max(c.hash("kurdistan/handshake/v1/transcript-client-finish", l.hello-4, q-4, 132), confirmation[2], c.confirmationMalformedFinishV1(q),
			c.hash("kurdistan/handshake/v1/transcript-final", l.hello-4, q-4, 132, 132),
			c.hash("kurdistan/hkdf/v1/application-salt", 32, 32), confirmation[3],
			contextCreate, c.add(returned, b.snapshot, 2*uint64(unsafe.Sizeof(AuthenticatedContextV1{})), uint64(unsafe.Sizeof(ProcessHandshakeEvidenceV1{})))))
	result.Stages[5] = returned
	result.ClientBytes = clientRetained
	result.AwaitHelloBytes = c.add(clientRetained, ecdhRetained, start)
	result.AwaitFinishBytes = c.add(clientRetained-a(64), finish, 32, 32)
	if c.overflow {
		return ProjectedClientWorkspaceBoundsV1{}, fail(FailureInternalLimit)
	}
	return result, nil
}

// These recurrences apply only to the named Go1.26.6 append-only serializer
// operations. They describe exposed backing, not RSS or allocator history.
type projectedWorkspaceArithmeticV1 struct{ overflow bool }

func (c *projectedWorkspaceArithmeticV1) confirmationMalformedFinishV1(q uint64) uint64 {
	if q < 136 || q > 65536 {
		c.overflow = true
		return 0
	}
	// wirev1 limits this control payload to q before auth. decodeOuter can
	// clone q-4 bytes before validateFinish rejects a body not exactly132.
	return c.add(uint64(unsafe.Sizeof(projectedValidateFinishHoldersV1{})), uint64(unsafe.Sizeof(projectedDecodeOuterHoldersV1{})), c.clone(q-4), uint64(unsafe.Sizeof(HandshakeError{})))
}

type projectedDecodeOuterHoldersV1 struct {
	message, returned []byte
	length            uint32
}

// These are named product/caller holders, not generated scalar/field scratch.
type projectedConfirmationKeysHoldersV1 struct {
	dh                                          []byte
	inputs                                      [6][32]byte
	salt                                        [32]byte
	prk, clientInfo, serverInfo, client, server []byte
	err                                         error
}
type projectedKeyInfoHoldersV1 struct {
	label      string
	transcript [32]byte
	epoch      uint64
	out        bytes.Buffer
}
type projectedConfirmationWriteHoldersV1 struct {
	out, integerOut *bytes.Buffer
	value           []byte
	integer         uint64
	raw             [8]byte
}
type projectedConfirmHoldersV1 struct {
	key        []byte
	domain     string
	transcript [32]byte
	mac        hash.Hash
	message    bytes.Buffer
}
type projectedMakeFinishHoldersV1 struct {
	privateKey, confirmKey []byte
	transcript, sigHash    [32]byte
	body                   bytes.Buffer
	unsigned, full         []byte
}
type projectedValidateFinishHoldersV1 struct {
	message                             []byte
	kind                                uint16
	signatureDomain, confirmationDomain string
	trusted, confirmKey                 []byte
	transcript, sigHash                 [32]byte
	body, unsigned, want                []byte
	err                                 error
}
type projectedHKDFHoldersV1 struct {
	h, fh                 func() hash.Hash
	key, salt             []byte
	info                  string
	keyLen, limit, remain int
	out, buf              []byte
	hmac                  hash.Hash
	counter               [1]byte
	err                   error
}
type projectedAcceptHelloHoldersV1 struct {
	client                                        *ClientProcessHandshakeV1
	message, receivedBody, dh                     []byte
	err                                           error
	th2                                           [32]byte
	clientKey, serverKey, prk, finish, finishBody []byte
	wipeClosure                                   [2]uintptr
	// parsed serverHello is already counted by parsed in the containing stage.
}
type projectedAcceptFinishHoldersV1 struct {
	client                        *ClientProcessHandshakeV1
	message, receivedBody, secret []byte
	err                           error
	th3, th4, applicationSalt     [32]byte
	context                       AuthenticatedContextV1
	result                        *ProcessHandshakeResultV1
}

// Go1.26.6 ordinary64, crypto/internal/fips140/{hmac,sha256}: HMAC96,
// two retained Digest120 objects and two make([]byte,64) pads. The 32-byte
// keys never take the oversized-key branch; one-block Expand never Reset's
// marshaled-pad branch. UnwrapNew's closure is16. Arithmetic backend scratch
// remains excluded, but these retained crypto objects and returned slices do not.
func (c *projectedWorkspaceArithmeticV1) confirmationChildrenV1() [4]uint64 {
	a, r, w := c.clone, c.retained, c.growth
	hmac := uint64(96 + 2*120 + 2*64 + 16)
	hkdfRoot := uint64(unsafe.Sizeof(projectedHKDFHoldersV1{}))
	extract := c.add(hkdfRoot, hmac, a(32))
	writeRoot := uint64(unsafe.Sizeof(projectedConfirmationWriteHoldersV1{}))
	infoRoot := uint64(unsafe.Sizeof(projectedKeyInfoHoldersV1{}))
	// keyInfo: LP(label32), transcript32, epoch8 =76. The string input
	// and HKDF's []byte(info) conversion coexist with both retained info buffers.
	info := c.add(infoRoot, writeRoot, 32, w(76))
	expand := c.add(hkdfRoot, hmac, 76, 76, 32, a(32), 1)
	keys := c.add(uint64(unsafe.Sizeof(projectedConfirmationKeysHoldersV1{})),
		max(c.hash("kurdistan/hkdf/v1/handshake-salt", 32, 32, 32, 32, 32), extract,
			c.add(a(32), r(76), info), c.add(a(32), 32, 2*r(76), expand)))
	// confirm: LP(domain41), transcript32 =77. Hash output is A(32);
	// body growth and MAC return are distinct complete child stages.
	confirm := c.add(uint64(unsafe.Sizeof(projectedConfirmHoldersV1{})), hmac,
		max(c.add(writeRoot, 41, w(77)), c.add(r(77), a(32))))
	makeFinish := c.add(uint64(unsafe.Sizeof(projectedMakeFinishHoldersV1{})), a(36),
		max(c.add(r(36), c.hash("kurdistan/handshake/v1/client-finish-signature", 36)),
			c.add(64, writeRoot, w(100)), c.add(r(100), confirm),
			c.add(a(32), writeRoot, w(132)), c.add(r(132), w(136)),
			c.add(r(132), r(136), a(132))))
	validate := c.add(uint64(unsafe.Sizeof(projectedValidateFinishHoldersV1{})), a(132),
		max(c.hash("kurdistan/handshake/v1/server-finish-signature", 36), confirm, c.add(a(32), a(132), uint64(unsafe.Sizeof(HandshakeError{})))))
	return [4]uint64{keys, makeFinish, validate, extract}
}

func (c *projectedWorkspaceArithmeticV1) add(values ...uint64) uint64 {
	var n uint64
	for _, value := range values {
		if value > math.MaxUint64-n {
			c.overflow = true
			return 0
		}
		n += value
	}
	return n
}
func (c *projectedWorkspaceArithmeticV1) mul(a, b uint64) uint64 {
	if a != 0 && b > math.MaxUint64/a {
		c.overflow = true
		return 0
	}
	return a * b
}
func (c *projectedWorkspaceArithmeticV1) clone(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	return c.add(c.mul(2, n), 8)
}
func (c *projectedWorkspaceArithmeticV1) retained(n uint64) uint64 { return c.add(c.mul(4, n), 72) }
func (c *projectedWorkspaceArithmeticV1) growth(n uint64) uint64   { return c.add(c.mul(7, n), 72) }
func (c *projectedWorkspaceArithmeticV1) json(n uint64) uint64 {
	r := c.retained(n)
	return max(c.mul(3, r), c.add(c.growth(n), r), c.add(r, c.clone(n)))
}

// Each pair is one live stage's complete cost and its identical backing subset
// already charged elsewhere. A non-subset is an accounting error, not zero.
func (c *projectedWorkspaceArithmeticV1) additional(stages ...[2]uint64) uint64 {
	var n uint64
	for _, stage := range stages {
		if stage[1] > stage[0] {
			c.overflow = true
			return 0
		}
		n = max(n, stage[0]-stage[1])
	}
	return n
}

type projectedWorkspaceLengthsV1 struct {
	policy, compatibility, config, mode, oldMode, contextHash uint64
	suite, selected, clientFloor, relayFloor, features        uint64
	clientOptional, relayOptional, hello                      uint64
	clientCount, relayCount, selectedCount, proxyCount        uint64
}

func (c *projectedWorkspaceArithmeticV1) lp(n uint64) uint64   { return c.add(4, n) }
func (c *projectedWorkspaceArithmeticV1) text(s string) uint64 { return c.lp(uint64(len(s))) }
func (c *projectedWorkspaceArithmeticV1) list(values []string) uint64 {
	n := uint64(4)
	for _, v := range values {
		n = c.add(n, c.text(v))
	}
	return n
}

// Calculation-only traversal. The containing attempt supplies a Program from
// its genuine admitted private Plan; this numeric result confers no provenance.
// There is no config construction, canonical encoder, hash, key, or allocation.
func projectedWorkspaceLengthsForV1(p liveprogram.ProgramV1, clientID, relayID string) (projectedWorkspaceLengthsV1, error) {
	l := projectedWorkspaceLengthsV1{}
	if clientID == "" || relayID == "" || clientID == relayID || len(clientID) > 128 || len(relayID) > 128 {
		return l, fail(FailureProfileMismatch)
	}
	client, relay, selected := p.Security.ClientMandatoryCapabilities, p.Security.RelayMandatoryCapabilities, p.Security.SelectedCapabilities
	if len(client) == 0 || len(relay) == 0 || len(selected) == 0 || len(client) > 10 || len(relay) > 10 || len(selected) > 10 {
		return l, fail(FailureInternalLimit)
	}
	c := projectedWorkspaceArithmeticV1{}
	l.clientCount, l.relayCount, l.selectedCount = uint64(len(client)), uint64(len(relay)), uint64(len(selected))
	l.clientFloor, l.relayFloor, l.selected = c.list(client), c.list(relay), c.list(selected)
	l.clientOptional, l.relayOptional = 4, 4
	for _, s := range selected {
		presentClient, presentRelay := false, false
		for _, v := range client {
			presentClient = presentClient || s == v
		}
		for _, v := range relay {
			presentRelay = presentRelay || s == v
		}
		if !presentClient {
			l.clientOptional = c.add(l.clientOptional, c.text(s))
		}
		if !presentRelay {
			l.relayOptional = c.add(l.relayOptional, c.text(s))
		}
		if s == "proxy_semantics" {
			l.proxyCount = 1
		}
	}
	s := p.Security.Policy
	l.policy = 20 // replay-window uint32 and two uint64 message limits
	for _, v := range [...]string{s.SecurityVersion, s.TranscriptMode, s.KDFSuite, s.AEADSuite, s.MACSuite, s.NonceMode, s.ReplayPolicy, s.DowngradePolicy, s.CapabilityNegotiationPolicy, s.ProfileCompatibilityPolicy, s.KeyRotationPolicy, s.ConfigValidationPolicy, s.SecureEnvelopeMode} {
		l.policy = c.add(l.policy, c.text(v))
	}
	l.suite = c.add(c.text(s.KDFSuite), c.text(s.AEADSuite), c.text(s.MACSuite))
	const carrier = "tls13-tcp"
	const adapter = "metadata_bound_stream"
	proxyList := uint64(4)
	if l.proxyCount != 0 {
		proxyList = c.add(proxyList, c.text("proxy_semantics"))
	}
	l.compatibility = c.add(c.text(ir.SupportedVersion), c.text(p.Security.CompilerSecurityVersion), c.text(p.Security.MinimumRuntimeVersion), c.lp(c.add(4, l.suite)), c.lp(l.selected), c.lp(c.add(4, c.text(carrier))), c.lp(proxyList), c.lp(c.add(4, c.text(p.Stream.IDEncodingMode))), 12)
	l.config = c.add(c.lp(32), 160, c.text(s.SecurityVersion), c.lp(l.suite), c.text(adapter))
	l.features = 4
	for _, v := range [...]struct{ prefix, value string }{{"carrier:", carrier}, {"frame:", p.Frame.FragmentationMode}, {"scheduler:", p.Scheduler.Mode}, {"stream:", p.Stream.IDEncodingMode}} {
		l.features = c.add(l.features, c.lp(c.add(uint64(len(v.prefix)), uint64(len(v.value)))))
	}
	for _, v := range selected {
		l.features = c.add(l.features, c.lp(c.add(uint64(len("capability:")), uint64(len(v)))))
	}
	lists := c.add(c.lp(l.clientOptional), c.lp(l.relayOptional), c.lp(l.features))
	l.mode = c.add(c.text(s.TranscriptMode), lists, c.text(carrier), 32, 8, c.text(adapter), 7*32, c.lp(l.compatibility), 32, c.lp(36), 32, c.lp(l.config), 32)
	l.oldMode = c.lp(c.add(uint64(len("kurdistan/transcript/v1/")), uint64(len(s.TranscriptMode))))
	oldCarrier := c.add(c.text(carrier), 32, 4, c.text(adapter))
	switch s.TranscriptMode {
	case security.TranscriptCanonicalV1:
	case security.TranscriptCapabilitiesV1:
		l.oldMode = c.add(l.oldMode, lists)
	case security.TranscriptCarrierBindingV1:
		l.oldMode = c.add(l.oldMode, oldCarrier)
	case security.TranscriptFullBindingV1:
		l.oldMode = c.add(l.oldMode, lists, oldCarrier, 7*32)
	default:
		return projectedWorkspaceLengthsV1{}, fail(FailureProfileMismatch)
	}
	l.contextHash = c.add(c.text("kurdistan/context/v1/authenticated"), 22*4, 2, l.policy, l.suite, 11*32, c.mul(2, l.compatibility), 2*36, c.mul(2, l.config), c.mul(2, l.mode))
	offer := c.add(c.lp(l.policy), c.lp(l.selected))
	floor := c.add(c.lp(l.policy), c.lp(l.clientFloor))
	l.hello = c.add(188, uint64(len(clientID)), 32, uint64(len(s.SecurityVersion)), offer, floor)
	if c.overflow {
		return projectedWorkspaceLengthsV1{}, fail(FailureInternalLimit)
	}
	return l, nil
}

type projectedWorkspaceJSONV1 struct{ policy, binding, projection uint64 }
type projectedWorkspaceClonesV1 struct{ policy, compatibility, binding, clientPeer, relayPeer, config, snapshot, hashInput uint64 }

func projectedWorkspaceClonesForV1(client, relay, selected, proxy uint64) (projectedWorkspaceClonesV1, error) {
	if client == 0 || relay == 0 || selected > 10 || client > selected || relay > selected || proxy > 1 {
		return projectedWorkspaceClonesV1{}, fail(FailureInternalLimit)
	}
	c := projectedWorkspaceArithmeticV1{}
	s := func(n uint64) uint64 { return c.clone(c.mul(16, n)) }
	policy := c.add(s(client), s(relay), s(selected))
	compatibility := c.add(s(3), s(selected), s(1), s(proxy), s(1))
	binding := c.add(s(4+selected), compatibility)
	clientPeer := c.add(c.mul(2, policy), s(selected), s(client), binding)
	relayPeer := c.add(c.mul(2, policy), s(selected), s(relay), binding)
	config := c.add(clientPeer, relayPeer, policy, s(selected))
	derived := c.add(binding, s(selected-client), s(selected-relay))
	hashInput := c.add(policy, c.mul(2, derived))
	snapshot := c.add(hashInput, c.mul(2, compatibility))
	if c.overflow {
		return projectedWorkspaceClonesV1{}, fail(FailureInternalLimit)
	}
	return projectedWorkspaceClonesV1{policy, compatibility, binding, clientPeer, relayPeer, config, snapshot, hashInput}, nil
}
func (c *projectedWorkspaceArithmeticV1) jtext(v string) uint64 {
	return c.add(2, c.mul(6, uint64(len(v))))
}
func (c *projectedWorkspaceArithmeticV1) jarray(v ...uint64) uint64 {
	if len(v) == 0 {
		return 2
	}
	return c.add(1, uint64(len(v)), c.add(v...))
}
func (c *projectedWorkspaceArithmeticV1) jlist(v []string) uint64 {
	if len(v) == 0 {
		return 4
	} // nil is null, larger than empty []
	n := c.add(1, uint64(len(v)))
	for _, s := range v {
		n = c.add(n, c.jtext(s))
	}
	return n
}

// keys concatenates the exact emitted key names (without punctuation). The
// object adds key quotes, colons, commas and braces, independent of key values.
func (c *projectedWorkspaceArithmeticV1) jobject(keys string, v ...uint64) uint64 {
	if len(v) == 0 {
		return 2
	}
	return c.add(uint64(len(keys)), c.mul(4, uint64(len(v))), 1, c.add(v...))
}
func (c *projectedWorkspaceArithmeticV1) jbytes(n int) uint64 {
	return max(uint64(4), c.add(2, c.mul(4, c.add(uint64(n), 2)/3)))
}

// Exact fixed JSON source shapes from projected_process_v1.go, plus policy and
// binding seal JSON. Text uses encoding/json's six-byte escape bound. Byte tags
// use base64, hashes use [32]byte decimal arrays (129), integers use 20. The
// admitted nonnegative finite padding probability uses at most 24 JSON bytes
// under the pinned floatEncoder's f/e formatting thresholds. No encoder runs.
func projectedWorkspaceJSONForV1(p liveprogram.ProgramV1) (projectedWorkspaceJSONV1, error) {
	c := projectedWorkspaceArithmeticV1{}
	s := p.Security.Policy
	client, relay, selected := p.Security.ClientMandatoryCapabilities, p.Security.RelayMandatoryCapabilities, p.Security.SelectedCapabilities
	if len(selected) > 10 || len(p.Messages) > 2 || len(p.Frame.HeaderOrder) > 4 || len(p.Frame.Compiled.DataTypeTag) > 255 || len(p.Frame.Compiled.PaddingTypeTag) > 255 {
		return projectedWorkspaceJSONV1{}, fail(FailureInternalLimit)
	}
	text := c.jtext
	policy := c.jobject("profile_idprofile_hashschema_versioncompiler_security_versionminimum_runtime_versionsecurity_versiontranscript_modekdf_suiteaead_suitemac_suitenonce_modereplay_policyreplay_window_sizedowngrade_policycapability_negotiation_policyprofile_compatibility_policykey_rotation_policyconfig_validation_policysecure_envelope_modemax_session_messagesmax_key_lifetime_messagesclient_mandatory_capabilitiesserver_mandatory_capabilitiesselected_capabilities",
		194, 386, text(ir.SupportedVersion), text(p.Security.CompilerSecurityVersion), text(p.Security.MinimumRuntimeVersion), text(s.SecurityVersion), text(s.TranscriptMode), text(s.KDFSuite), text(s.AEADSuite), text(s.MACSuite), text(s.NonceMode), text(s.ReplayPolicy), 20, text(s.DowngradePolicy), text(s.CapabilityNegotiationPolicy), text(s.ProfileCompatibilityPolicy), text(s.KeyRotationPolicy), text(s.ConfigValidationPolicy), text(s.SecureEnvelopeMode), 20, 20, c.jlist(client), c.jlist(relay), c.jlist(selected))
	suite := c.jobject("KDFSuiteAEADSuiteMACSuite", text(s.KDFSuite), text(s.AEADSuite), text(s.MACSuite))
	proxy := uint64(4)
	for _, v := range selected {
		if v == "proxy_semantics" {
			proxy = c.jarray(text(v))
		}
	}
	compatibility := c.jobject("SchemaVersionCompilerSecurityVersionMinimumRuntimeVersionSupportedSecuritySuitesRequiredCapabilitiesSupportedCarrierFamiliesSupportedProxyFeaturesSupportedStreamFeaturesMaxEnvelopeBytesMaxStreamCountMaxReplayWindow",
		text(ir.SupportedVersion), text(p.Security.CompilerSecurityVersion), text(p.Security.MinimumRuntimeVersion), c.jarray(text(s.KDFSuite), text(s.AEADSuite), text(s.MACSuite)), c.jlist(selected), c.jarray(text("tls13-tcp")), proxy, c.jarray(text(p.Stream.IDEncodingMode)), 20, 20, 20)
	limit := c.jobject("MaxFrameBytesMaxPayloadBytesMaxStatesMaxTransitionsMaxSessionMillisCarrierMaxEnvelopeBytesCarrierMaxQueueDepthSessionMaxConcurrentStreams", 20, 20, 20, 20, 20, 20, 20, 20)
	config := c.jobject("ProfileIDProfileHashSecurityVersionSelectedSuiteEffectivePolicyHashSelectedCapabilityHashAdapterClassCompatibilityBlockHashLimitBlockHash", 194, 129, text(s.SecurityVersion), suite, 129, 129, text("metadata_bound_stream"), 129, 129)
	featureStrings := uint64(0)
	for _, v := range [...]struct{ prefix, value string }{{"carrier:", "tls13-tcp"}, {"frame:", p.Frame.FragmentationMode}, {"scheduler:", p.Scheduler.Mode}, {"stream:", p.Stream.IDEncodingMode}} {
		featureStrings = c.add(featureStrings, 2, c.mul(6, c.add(uint64(len(v.prefix)), uint64(len(v.value)))))
	}
	for _, v := range selected {
		featureStrings = c.add(featureStrings, 2, c.mul(6, c.add(uint64(len("capability:")), uint64(len(v)))))
	}
	features := c.add(1, 4, uint64(len(selected)), featureStrings)
	// Stored projected bindings have nil optional lists. Derived validation
	// bindings can contain subsets of selected: whole selected is the safe
	// source-bound envelope for either subset, not a new copied string owner.
	binding := c.jobject("ClientOptionalServerOptionalFeatureVectorsCarrierFamilyCarrierPolicyHashEnvelopeLimitMaxFrameBytesLocalAdapterClassFramingPolicyHashStateMachinePolicyHashSchedulerPolicyHashPaddingPolicyHashStreamPolicyHashProxyPolicyHashCarrierContextHashCompatibilityBlockCompatibilityBlockHashLimitBlockLimitBlockHashConfigSourceBlockConfigSourceBlockHash",
		c.jlist(selected), c.jlist(selected), features, text("tls13-tcp"), 129, 20, 20, text("metadata_bound_stream"), 129, 129, 129, 129, 129, 129, 129, compatibility, 129, limit, 129, config, 129)
	compiled := c.jobject("DataTypeTagPaddingTypeTagProfileXORStreamMaskTableStreamMaskCRC32PrefixState", c.jbytes(len(p.Frame.Compiled.DataTypeTag)), c.jbytes(len(p.Frame.Compiled.PaddingTypeTag)), 20, 20, 20)
	frame := c.jobject("LengthModeTypeModeHeaderOrderFragmentationModeChecksumModePaddingPlacementCompiled", text(p.Frame.LengthMode), text(p.Frame.TypeMode), c.jlist(p.Frame.HeaderOrder), text(p.Frame.FragmentationMode), text(p.Frame.ChecksumMode), text(p.Frame.PaddingPlacement), compiled)
	var messages [2]uint64
	for i, v := range p.Messages {
		messages[i] = c.jobject("SemanticWireSymbolDirectionMinPayloadBytesMaxPayloadBytes", text(v.Semantic), text(v.WireSymbol), text(v.Direction), 20, 20)
	}
	message := c.jarray(messages[:len(p.Messages)]...)
	scheduler := c.jobject("ModePriorityModeMaxBatchBytesFlushIntervalMsMaxInFlightFrames", text(p.Scheduler.Mode), text(p.Scheduler.PriorityMode), 20, 20, 20)
	padding := c.jobject("ModeMinPaddingBytesMaxPaddingBytesProbability", text(p.Padding.Mode), 20, 20, 24)
	stream := c.jobject("IDEncodingModeMaxConcurrentStreams", text(p.Stream.IDEncodingMode), 20)
	carrier := c.jobject("FamilyMaxFrameBytesMaxPayloadBytes", text("tls13-tcp"), 20, 20)
	carrierContext := c.jobject("FamilyProgramIDSource", text("tls13-tcp"), 65, 129)
	if c.overflow {
		return projectedWorkspaceJSONV1{}, fail(FailureInternalLimit)
	}
	return projectedWorkspaceJSONV1{policy, binding, max(frame, message, scheduler, padding, stream, carrier, carrierContext, c.jlist(selected))}, nil
}
