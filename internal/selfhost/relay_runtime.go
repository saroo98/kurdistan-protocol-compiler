// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"

	"kurdistan/internal/product/runtimepolicy"
)

// RelayRuntimeStatusV1 is a nonsecret summary of one immutable relay snapshot.
type RelayRuntimeStatusV1 struct {
	Revision, Generation, RelayEpoch, TLSEpoch uint64
	RelayKeyID, TLSKeyID                       string
	RelayPublic                                [32]byte
	AdmissionCount                             int
	Drained                                    bool
}

// RelayAdmissionV1 is the exact current relay-side authority for one client
// identity. It intentionally contains no profile artifact or recipient key.
type RelayAdmissionV1 struct {
	ProfileID, ContentID  string
	Generation            uint64
	ValidFrom, ValidUntil int64
	ClientAuthKeyID       string
	ClientAuthPublic      [32]byte
	AssignedIPv4          []byte
	AssignedIPv6          []byte
	RuntimePolicy         runtimepolicy.PolicyV2
	StrategyIDs           []string
	RelayIDs              []string
}

func (a RelayAdmissionV1) clone() RelayAdmissionV1 {
	a.AssignedIPv4 = bytes.Clone(a.AssignedIPv4)
	a.AssignedIPv6 = bytes.Clone(a.AssignedIPv6)
	a.RuntimePolicy = a.RuntimePolicy.Clone()
	a.StrategyIDs = append([]string(nil), a.StrategyIDs...)
	a.RelayIDs = append([]string(nil), a.RelayIDs...)
	return a
}

type relayProfileKeyV1 struct {
	ContentID  string
	Generation uint64
}

// RelayRuntimeSnapshotV1 owns the only in-process copies of the current relay
// and TLS private identities. Reload constructs a replacement snapshot; Close
// destroys this snapshot before it can be reused.
type RelayRuntimeSnapshotV1 struct {
	mu sync.RWMutex

	status         RelayRuntimeStatusV1
	relayPrivate   ed25519.PrivateKey
	tlsPrivate     ed25519.PrivateKey
	tlsCertificate []byte
	admissions     map[string]RelayAdmissionV1
	profiles       map[relayProfileKeyV1]string
	closed         bool
}

// OpenRelayRuntimeSnapshotV1 opens a validated state-v2 relay view at the
// caller's trusted time. It never returns raw persisted state or sealed data.
func OpenRelayRuntimeSnapshotV1(dataDir string, now time.Time) (*RelayRuntimeSnapshotV1, error) {
	now = now.UTC()
	if dataDir == "" || now.IsZero() {
		return nil, ErrInvalidInput
	}
	state, master, err := loadState(dataDir)
	if err != nil {
		return nil, err
	}
	defer zero(master)
	if state.Drained {
		return nil, ErrDrained
	}
	if err := validateTLSReady(state.TLS, now); err != nil {
		return nil, err
	}

	relayPrivate, err := openWithKey(master, state.RelaySecret, []byte(state.DeploymentID+"|"+state.RelayKeyID))
	if err != nil || len(relayPrivate) != ed25519.PrivateKeySize || len(state.RelayPublic) != ed25519.PublicKeySize {
		zero(relayPrivate)
		return nil, ErrStateCorrupt
	}
	if !bytes.Equal(ed25519.PrivateKey(relayPrivate).Public().(ed25519.PublicKey), state.RelayPublic) {
		zero(relayPrivate)
		return nil, ErrStateCorrupt
	}
	tlsSeed, err := openTLSSeed(master, state.DeploymentID, state.TLS)
	if err != nil {
		zero(relayPrivate)
		return nil, err
	}
	seed := tlsSeed.Bytes()
	tlsSeed.Close()
	if len(seed) != ed25519.SeedSize {
		zero(relayPrivate)
		zero(seed)
		return nil, ErrStateCorrupt
	}
	tlsPrivate := ed25519.NewKeyFromSeed(seed)
	zero(seed)
	leaf, err := x509.ParseCertificate(state.TLS.LeafDER)
	leafPublic, publicOK := leafPublicKey(leaf)
	if err != nil || !publicOK || !bytes.Equal(tlsPrivate.Public().(ed25519.PublicKey), leafPublic) {
		zero(relayPrivate)
		zero(tlsPrivate)
		return nil, ErrStateCorrupt
	}

	snapshot := &RelayRuntimeSnapshotV1{
		status: RelayRuntimeStatusV1{
			Revision: state.Revision, Generation: state.Generation, RelayEpoch: state.RelayEpoch, TLSEpoch: state.TLS.Epoch,
			RelayKeyID: state.RelayKeyID, TLSKeyID: state.TLS.KeyID, AdmissionCount: 0, Drained: state.Drained,
		},
		relayPrivate:   ed25519.PrivateKey(bytes.Clone(relayPrivate)),
		tlsPrivate:     ed25519.PrivateKey(bytes.Clone(tlsPrivate)),
		tlsCertificate: bytes.Clone(state.TLS.LeafDER),
		admissions:     make(map[string]RelayAdmissionV1),
		profiles:       make(map[relayProfileKeyV1]string),
	}
	zero(relayPrivate)
	zero(tlsPrivate)
	copy(snapshot.status.RelayPublic[:], state.RelayPublic)

	for _, record := range state.Profiles {
		if record.Mode != profileModeLive || record.Revoked || now.Unix() < record.CreatedAt || now.Unix() >= record.ValidUntil {
			continue
		}
		policy, decodeErr := runtimepolicy.DecodeV2At(record.RuntimePolicy, now)
		if decodeErr != nil || policy.RelayAuthKeyID != state.RelayKeyID ||
			!bytes.Equal(policy.RelayAuthPublic[:], state.RelayPublic) || policy.ClientAuthKeyID != record.ClientAuthKeyID ||
			!bytes.Equal(policy.ClientAuthPublic[:], record.ClientAuthPublic) || !bytes.Equal(policy.ClientIPv4, record.AssignedIPv4) ||
			!bytes.Equal(policy.ClientIPv6, record.AssignedIPv6) {
			snapshot.Close()
			return nil, ErrStateCorrupt
		}
		if _, duplicate := snapshot.admissions[record.ClientAuthKeyID]; duplicate {
			snapshot.Close()
			return nil, ErrStateCorrupt
		}
		profileKey := relayProfileKeyV1{ContentID: record.ContentID, Generation: record.Generation}
		if _, duplicate := snapshot.profiles[profileKey]; duplicate {
			snapshot.Close()
			return nil, ErrStateCorrupt
		}
		var clientPublic [32]byte
		copy(clientPublic[:], record.ClientAuthPublic)
		snapshot.admissions[record.ClientAuthKeyID] = RelayAdmissionV1{
			ProfileID: record.ProfileID, ContentID: record.ContentID, Generation: record.Generation,
			ValidFrom: record.CreatedAt, ValidUntil: record.ValidUntil,
			ClientAuthKeyID: record.ClientAuthKeyID, ClientAuthPublic: clientPublic,
			AssignedIPv4: bytes.Clone(record.AssignedIPv4), AssignedIPv6: bytes.Clone(record.AssignedIPv6), RuntimePolicy: policy.Clone(),
			StrategyIDs: []string{"strategy.kurd-tls13-tcp"}, RelayIDs: []string{state.RelayKeyID},
		}
		snapshot.profiles[profileKey] = record.ClientAuthKeyID
	}
	snapshot.status.AdmissionCount = len(snapshot.admissions)
	return snapshot, nil
}

func leafPublicKey(certificate *x509.Certificate) (ed25519.PublicKey, bool) {
	if certificate == nil {
		return nil, false
	}
	public, ok := certificate.PublicKey.(ed25519.PublicKey)
	return public, ok
}

// StatusV1 returns a nonsecret immutable status projection.
func (snapshot *RelayRuntimeSnapshotV1) StatusV1() (RelayRuntimeStatusV1, bool) {
	if snapshot == nil {
		return RelayRuntimeStatusV1{}, false
	}
	snapshot.mu.RLock()
	defer snapshot.mu.RUnlock()
	if snapshot.closed {
		return RelayRuntimeStatusV1{}, false
	}
	return snapshot.status, true
}

// AdmissionByClientKeyIDV1 returns a defensive copy of an exact active
// admission. Unknown and closed snapshots are indistinguishable.
func (snapshot *RelayRuntimeSnapshotV1) AdmissionByClientKeyIDV1(keyID string) (RelayAdmissionV1, bool) {
	if snapshot == nil {
		return RelayAdmissionV1{}, false
	}
	snapshot.mu.RLock()
	defer snapshot.mu.RUnlock()
	if snapshot.closed {
		return RelayAdmissionV1{}, false
	}
	admission, ok := snapshot.admissions[keyID]
	if !ok {
		return RelayAdmissionV1{}, false
	}
	return admission.clone(), true
}

// AdmissionByProfileV1 returns the one exact active profile generation. It is
// used only to select relay-owned authority before TLS and Kurd authentication.
func (snapshot *RelayRuntimeSnapshotV1) AdmissionByProfileV1(contentID string, generation uint64) (RelayAdmissionV1, bool) {
	if snapshot == nil || contentID == "" || generation == 0 {
		return RelayAdmissionV1{}, false
	}
	snapshot.mu.RLock()
	defer snapshot.mu.RUnlock()
	if snapshot.closed {
		return RelayAdmissionV1{}, false
	}
	keyID, ok := snapshot.profiles[relayProfileKeyV1{ContentID: contentID, Generation: generation}]
	if !ok {
		return RelayAdmissionV1{}, false
	}
	admission, ok := snapshot.admissions[keyID]
	if !ok {
		return RelayAdmissionV1{}, false
	}
	return admission.clone(), true
}

// Local implements auth.IdentityProvider without exposing persisted state.
func (snapshot *RelayRuntimeSnapshotV1) Local(identityID string) (ed25519.PrivateKey, error) {
	if snapshot == nil {
		return nil, ErrRelayRuntimeUnavailable
	}
	snapshot.mu.RLock()
	defer snapshot.mu.RUnlock()
	if snapshot.closed || identityID != snapshot.status.RelayKeyID || len(snapshot.relayPrivate) != ed25519.PrivateKeySize {
		return nil, ErrRelayRuntimeUnavailable
	}
	return ed25519.PrivateKey(bytes.Clone(snapshot.relayPrivate)), nil
}

// Peer implements auth.TrustProvider for only currently admitted clients.
func (snapshot *RelayRuntimeSnapshotV1) Peer(identityID string) (ed25519.PublicKey, error) {
	admission, ok := snapshot.AdmissionByClientKeyIDV1(identityID)
	if !ok {
		return nil, ErrRelayRuntimeUnavailable
	}
	return ed25519.PublicKey(bytes.Clone(admission.ClientAuthPublic[:])), nil
}

// ServerTLSConfigV1 returns a strict TLS 1.3 server configuration with a
// defensive private-key copy. The caller owns the returned configuration.
func (snapshot *RelayRuntimeSnapshotV1) ServerTLSConfigV1() (*tls.Config, error) {
	if snapshot == nil {
		return nil, ErrRelayRuntimeUnavailable
	}
	snapshot.mu.RLock()
	defer snapshot.mu.RUnlock()
	if snapshot.closed || len(snapshot.tlsPrivate) != ed25519.PrivateKeySize || len(snapshot.tlsCertificate) == 0 {
		return nil, ErrRelayRuntimeUnavailable
	}
	certificate := tls.Certificate{
		Certificate: [][]byte{bytes.Clone(snapshot.tlsCertificate)},
		PrivateKey:  ed25519.PrivateKey(bytes.Clone(snapshot.tlsPrivate)),
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"kurd/1"}, Certificates: []tls.Certificate{certificate},
		SessionTicketsDisabled: true,
	}, nil
}

// Close destroys runtime private identities and admissions. It is idempotent.
func (snapshot *RelayRuntimeSnapshotV1) Close() {
	if snapshot == nil {
		return
	}
	snapshot.mu.Lock()
	defer snapshot.mu.Unlock()
	if snapshot.closed {
		return
	}
	zero(snapshot.relayPrivate)
	zero(snapshot.tlsPrivate)
	zero(snapshot.tlsCertificate)
	for key, admission := range snapshot.admissions {
		zero(admission.AssignedIPv4)
		zero(admission.AssignedIPv6)
		zero(admission.RuntimePolicy.LiveProgram)
		zero(admission.RuntimePolicy.TLSLeafDER)
		delete(snapshot.admissions, key)
	}
	clear(snapshot.profiles)
	snapshot.relayPrivate = nil
	snapshot.tlsPrivate = nil
	snapshot.tlsCertificate = nil
	snapshot.profiles = nil
	snapshot.status = RelayRuntimeStatusV1{}
	snapshot.closed = true
}
