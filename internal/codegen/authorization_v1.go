package codegen

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"sort"

	"kurdistan/internal/protocol/ir"
)

const (
	AuthorizationCatalogVersionV1           = "profile-authorization-catalog-v1"
	AuthorizationCatalogScopeDefaultAuditV1 = "default_audit_v1"
	AuthorizationCatalogScopeExplicitV1     = "explicit_v1"
)

var (
	ErrAuthorizationCatalogInvalid = errors.New("codegen authorization catalog invalid")
	ErrAuthorizationMismatch       = errors.New("codegen authorization mismatch")
	ErrStrictModulePath            = errors.New("strict codegen module path rejected")
	ErrStrictSeedRange             = errors.New("strict codegen seed out of range")
)

type AuthorizationPinV1 struct {
	ProfileHash                   [32]byte
	EffectivePolicyHash           [32]byte
	FramingHash                   [32]byte
	StateMachineHash              [32]byte
	SchedulerHash                 [32]byte
	PaddingHash                   [32]byte
	StreamHash                    [32]byte
	ProxyHash                     [32]byte
	CarrierContextHash            [32]byte
	EffectiveReplayWindow         uint32
	EffectiveMaxConcurrentStreams uint32
	EffectiveMaxFrameBytes        uint32
	EffectiveMaxEnvelopeBytes     uint32
}
type ClientAuthorizationCatalogV1 struct{ entries []authorizationEntryV1 }
type RelayAuthorizationCatalogV1 struct{ entries []authorizationEntryV1 }
type AuthorizationCatalogV1 struct {
	version, scope string
	client         ClientAuthorizationCatalogV1
	relay          RelayAuthorizationCatalogV1
	digest         [32]byte
}
type authorizationEntryV1 struct {
	seed int64
	pin  AuthorizationPinV1
}

type catalogWireV1 struct {
	Version string        `json:"version"`
	Scope   string        `json:"scope"`
	Entries []entryWireV1 `json:"entries"`
}
type entryWireV1 struct {
	Seed   int64     `json:"seed"`
	Client pinWireV1 `json:"client"`
	Relay  pinWireV1 `json:"relay"`
}
type pinWireV1 struct {
	ProfileHash                   string `json:"profile_hash"`
	EffectivePolicyHash           string `json:"effective_policy_hash"`
	FramingHash                   string `json:"framing_hash"`
	StateMachineHash              string `json:"state_machine_hash"`
	SchedulerHash                 string `json:"scheduler_hash"`
	PaddingHash                   string `json:"padding_hash"`
	StreamHash                    string `json:"stream_hash"`
	ProxyHash                     string `json:"proxy_hash"`
	CarrierContextHash            string `json:"carrier_context_hash"`
	EffectiveReplayWindow         uint32 `json:"effective_replay_window"`
	EffectiveMaxConcurrentStreams uint32 `json:"effective_max_concurrent_streams"`
	EffectiveMaxFrameBytes        uint32 `json:"effective_max_frame_bytes"`
	EffectiveMaxEnvelopeBytes     uint32 `json:"effective_max_envelope_bytes"`
}

func ParseAuthorizationCatalogV1(raw []byte) (AuthorizationCatalogV1, error) {
	var zero AuthorizationCatalogV1
	if len(raw) == 0 || len(raw) > 1<<20 {
		return zero, ErrAuthorizationCatalogInvalid
	}
	if strictCatalogJSONV1(raw) != nil {
		return zero, ErrAuthorizationCatalogInvalid
	}
	if validateCatalogKeySetsV1(raw) != nil {
		return zero, ErrAuthorizationCatalogInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var wire catalogWireV1
	if dec.Decode(&wire) != nil || wire.Version != AuthorizationCatalogVersionV1 || (wire.Scope != AuthorizationCatalogScopeDefaultAuditV1 && wire.Scope != AuthorizationCatalogScopeExplicitV1) || len(wire.Entries) == 0 || len(wire.Entries) > 512 {
		return zero, ErrAuthorizationCatalogInvalid
	}
	c := AuthorizationCatalogV1{version: wire.Version, scope: wire.Scope}
	seenSeed := map[int64]bool{}
	seenProfile := map[[32]byte]bool{}
	var last int64
	for i, e := range wire.Entries {
		if seenSeed[e.Seed] || (i > 0 && e.Seed <= last) {
			return zero, ErrAuthorizationCatalogInvalid
		}
		last = e.Seed
		seenSeed[e.Seed] = true
		cp, err := parsePinV1(e.Client)
		if err != nil {
			return zero, ErrAuthorizationCatalogInvalid
		}
		rp, err := parsePinV1(e.Relay)
		if err != nil {
			return zero, ErrAuthorizationCatalogInvalid
		}
		// Equal client/relay values within one entry are valid for M0, but a
		// profile hash cannot be reused by any later entry in either role.
		if seenProfile[cp.ProfileHash] || seenProfile[rp.ProfileHash] {
			return zero, ErrAuthorizationCatalogInvalid
		}
		seenProfile[cp.ProfileHash] = true
		seenProfile[rp.ProfileHash] = true
		c.client.entries = append(c.client.entries, authorizationEntryV1{e.Seed, cp})
		c.relay.entries = append(c.relay.entries, authorizationEntryV1{e.Seed, rp})
	}
	canonical, err := c.canonical()
	if err != nil {
		return zero, ErrAuthorizationCatalogInvalid
	}
	c.digest = sha256.Sum256(canonical)
	return c, nil
}
func parsePinV1(w pinWireV1) (AuthorizationPinV1, error) {
	var p AuthorizationPinV1
	values := []struct {
		s string
		d *[32]byte
	}{{w.ProfileHash, &p.ProfileHash}, {w.EffectivePolicyHash, &p.EffectivePolicyHash}, {w.FramingHash, &p.FramingHash}, {w.StateMachineHash, &p.StateMachineHash}, {w.SchedulerHash, &p.SchedulerHash}, {w.PaddingHash, &p.PaddingHash}, {w.StreamHash, &p.StreamHash}, {w.ProxyHash, &p.ProxyHash}, {w.CarrierContextHash, &p.CarrierContextHash}}
	seen := map[[32]byte]bool{}
	for _, v := range values {
		if len(v.s) != 64 || v.s != string(bytes.ToLower([]byte(v.s))) {
			return p, ErrAuthorizationCatalogInvalid
		}
		b, e := hex.DecodeString(v.s)
		if e != nil || len(b) != 32 {
			return p, ErrAuthorizationCatalogInvalid
		}
		copy(v.d[:], b)
		if *v.d == ([32]byte{}) {
			return p, ErrAuthorizationCatalogInvalid
		}
		if seen[*v.d] {
			return p, ErrAuthorizationCatalogInvalid
		}
		seen[*v.d] = true
	}
	p.EffectiveReplayWindow = w.EffectiveReplayWindow
	p.EffectiveMaxConcurrentStreams = w.EffectiveMaxConcurrentStreams
	p.EffectiveMaxFrameBytes = w.EffectiveMaxFrameBytes
	p.EffectiveMaxEnvelopeBytes = w.EffectiveMaxEnvelopeBytes
	if p.EffectiveReplayWindow == 0 || p.EffectiveMaxConcurrentStreams == 0 || p.EffectiveMaxFrameBytes == 0 || p.EffectiveMaxEnvelopeBytes == 0 {
		return p, ErrAuthorizationCatalogInvalid
	}
	return p, nil
}

func validateCatalogKeySetsV1(raw []byte) error {
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || !exactKeysV1(top, []string{"version", "scope", "entries"}) {
		return ErrAuthorizationCatalogInvalid
	}
	var entries []json.RawMessage
	if json.Unmarshal(top["entries"], &entries) != nil {
		return ErrAuthorizationCatalogInvalid
	}
	for _, entryRaw := range entries {
		var entry map[string]json.RawMessage
		if json.Unmarshal(entryRaw, &entry) != nil || !exactKeysV1(entry, []string{"seed", "client", "relay"}) {
			return ErrAuthorizationCatalogInvalid
		}
		for _, role := range []string{"client", "relay"} {
			var pin map[string]json.RawMessage
			if json.Unmarshal(entry[role], &pin) != nil || !exactKeysV1(pin, []string{"profile_hash", "effective_policy_hash", "framing_hash", "state_machine_hash", "scheduler_hash", "padding_hash", "stream_hash", "proxy_hash", "carrier_context_hash", "effective_replay_window", "effective_max_concurrent_streams", "effective_max_frame_bytes", "effective_max_envelope_bytes"}) {
				return ErrAuthorizationCatalogInvalid
			}
		}
	}
	return nil
}
func exactKeysV1(values map[string]json.RawMessage, want []string) bool {
	if len(values) != len(want) {
		return false
	}
	for _, key := range want {
		if _, ok := values[key]; !ok {
			return false
		}
	}
	return true
}
func strictCatalogJSONV1(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if scanCatalogValueV1(d) != nil {
		return ErrAuthorizationCatalogInvalid
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrAuthorizationCatalogInvalid
	}
	return nil
}
func scanCatalogValueV1(d *json.Decoder) error {
	t, e := d.Token()
	if e != nil {
		return e
	}
	x, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if x == '{' {
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := k.(string)
			if !ok || seen[s] {
				return ErrAuthorizationCatalogInvalid
			}
			seen[s] = true
			if e = scanCatalogValueV1(d); e != nil {
				return e
			}
		}
	} else if x == '[' {
		for d.More() {
			if e := scanCatalogValueV1(d); e != nil {
				return e
			}
		}
	}
	_, e = d.Token()
	return e
}

func (c AuthorizationCatalogV1) ValidateExactSeedRangeV1(scope string, start int64, count int) error {
	if c.validate() != nil || scope != AuthorizationCatalogScopeDefaultAuditV1 && scope != AuthorizationCatalogScopeExplicitV1 || scope != c.scope || count <= 0 || count > 512 || start > math.MaxInt64-int64(count-1) || len(c.client.entries) != count || len(c.relay.entries) != count {
		return ErrAuthorizationCatalogInvalid
	}
	for i := 0; i < count; i++ {
		if c.client.entries[i].seed != start+int64(i) || c.relay.entries[i].seed != start+int64(i) {
			return ErrAuthorizationCatalogInvalid
		}
	}
	return nil
}

func (c AuthorizationCatalogV1) validate() error {
	raw, err := c.canonical()
	if err != nil {
		return ErrAuthorizationCatalogInvalid
	}
	sum := sha256.Sum256(raw)
	if c.digest == ([32]byte{}) || sum != c.digest {
		return ErrAuthorizationCatalogInvalid
	}
	return nil
}
func (c AuthorizationCatalogV1) canonical() ([]byte, error) {
	if len(c.client.entries) != len(c.relay.entries) || len(c.client.entries) == 0 {
		return nil, ErrAuthorizationCatalogInvalid
	}
	var out bytes.Buffer
	lpV1(&out, []byte("kurdistan/codegen/authorization-catalog/v1"))
	lpV1(&out, []byte(c.version))
	lpV1(&out, []byte(c.scope))
	u32V1(&out, uint32(len(c.client.entries)))
	for i, ce := range c.client.entries {
		re := c.relay.entries[i]
		if ce.seed != re.seed {
			return nil, ErrAuthorizationCatalogInvalid
		}
		var seed [8]byte
		binary.BigEndian.PutUint64(seed[:], uint64(ce.seed))
		out.Write(seed[:])
		lpV1(&out, []byte("client"))
		lpV1(&out, pinBytesV1(ce.pin))
		lpV1(&out, []byte("relay"))
		lpV1(&out, pinBytesV1(re.pin))
	}
	return out.Bytes(), nil
}
func pinBytesV1(p AuthorizationPinV1) []byte {
	var out bytes.Buffer
	for _, h := range [][32]byte{p.ProfileHash, p.EffectivePolicyHash, p.FramingHash, p.StateMachineHash, p.SchedulerHash, p.PaddingHash, p.StreamHash, p.ProxyHash, p.CarrierContextHash} {
		out.Write(h[:])
	}
	for _, v := range []uint32{p.EffectiveReplayWindow, p.EffectiveMaxConcurrentStreams, p.EffectiveMaxFrameBytes, p.EffectiveMaxEnvelopeBytes} {
		u32V1(&out, v)
	}
	return out.Bytes()
}
func lpV1(out *bytes.Buffer, b []byte) { u32V1(out, uint32(len(b))); out.Write(b) }
func u32V1(out *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	out.Write(b[:])
}

func expectedPinV1(p *ir.Profile) (AuthorizationPinV1, error) {
	var out AuthorizationPinV1
	hash, err := ir.CanonicalHash(p)
	if err != nil {
		return out, err
	}
	b, _ := hex.DecodeString(hash)
	copy(out.ProfileHash[:], b)
	out.EffectivePolicyHash = policyHashV1(p)
	component := func(domain string, v any) [32]byte { raw, _ := json.Marshal(v); return domainHashV1(domain, raw) }
	out.FramingHash = component("kurdistan/profile/v1/framing-policy", p.FrameGrammar)
	out.StateMachineHash = component("kurdistan/profile/v1/state-machine-policy", struct {
		FirstContact ir.FirstContactSpec
		States       []ir.State
		Transitions  []ir.Transition
	}{p.FirstContact, p.States, p.Transitions})
	out.SchedulerHash = component("kurdistan/profile/v1/scheduler-policy", p.Scheduler)
	out.PaddingHash = component("kurdistan/profile/v1/padding-policy", p.Padding)
	out.StreamHash = component("kurdistan/profile/v1/stream-policy", p.Stream)
	out.ProxyHash = component("kurdistan/profile/v1/proxy-policy", p.ProxySemantics)
	out.CarrierContextHash = component("kurdistan/profile/v1/carrier-context", struct {
		Policy  ir.CarrierPolicy
		Adapter ir.AdapterPolicy
	}{p.CarrierPolicy, p.AdapterPolicy})
	out.EffectiveReplayWindow = uint32(p.Security.ReplayWindowSize)
	out.EffectiveMaxConcurrentStreams = uint32(p.Stream.MaxConcurrentStreams)
	out.EffectiveMaxFrameBytes = uint32(p.Limits.MaxFrameBytes)
	out.EffectiveMaxEnvelopeBytes = uint32(p.CarrierPolicy.MaxEnvelopeBytes)
	return out, nil
}
func domainHashV1(label string, parts ...[]byte) [32]byte {
	var b bytes.Buffer
	lpV1(&b, []byte(label))
	for _, p := range parts {
		lpV1(&b, p)
	}
	return sha256.Sum256(b.Bytes())
}
func policyHashV1(p *ir.Profile) [32]byte {
	var b bytes.Buffer
	for _, s := range []string{p.Security.SecurityVersion, p.Security.TranscriptMode, p.Security.KDFSuite, p.Security.AEADSuite, p.Security.MACSuite, p.Security.NonceMode, p.Security.ReplayPolicy} {
		lpV1(&b, []byte(s))
	}
	u32V1(&b, uint32(p.Security.ReplayWindowSize))
	for _, s := range []string{p.Security.DowngradePolicy, p.Security.CapabilityNegotiationPolicy, p.Security.ProfileCompatibilityPolicy, p.Security.KeyRotationPolicy, p.Security.ConfigValidationPolicy, p.Security.SecureEnvelopeMode} {
		lpV1(&b, []byte(s))
	}
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], uint64(p.Security.MaxSessionMessages))
	b.Write(x[:])
	binary.BigEndian.PutUint64(x[:], uint64(p.Security.MaxKeyLifetimeMessages))
	b.Write(x[:])
	return domainHashV1("kurdistan/policy/v1/effective", b.Bytes())
}

func findCatalogPinV1(c AuthorizationCatalogV1, seed int64) (AuthorizationPinV1, AuthorizationPinV1, bool) {
	i := sort.Search(len(c.client.entries), func(i int) bool { return c.client.entries[i].seed >= seed })
	if i >= len(c.client.entries) || c.client.entries[i].seed != seed {
		return AuthorizationPinV1{}, AuthorizationPinV1{}, false
	}
	return c.client.entries[i].pin, c.relay.entries[i].pin, true
}
