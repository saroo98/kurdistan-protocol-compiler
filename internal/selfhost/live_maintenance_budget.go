// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"math"
	"unsafe"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
)

type LiveMaintenanceLimits struct {
	OwnedBudgetBytes    uint64
	MaxArtifactBytes    uint32
	MaxPublicationBytes uint32
}

// RetainedBytes includes CandidateBytes. Opaque admission storage uses the
// conservative source clone envelope; directly owned backing uses capacity.
// Reservations describe named native backing, not allocator/GC/process RSS.
type LiveMaintenanceBounds struct {
	BudgetBytes, RetainedBytes, CandidateBytes uint64
	OperationReservedBytes, PeakReservedBytes  uint64
}

func maintenanceFailure(reason LiveMaintenanceFailureV1) error {
	return &LiveMaintenanceVerificationError{reason: reason}
}

func maintenanceAdd(values ...uint64) (uint64, bool) {
	var n uint64
	for _, v := range values {
		if v > math.MaxUint64-n {
			return 0, false
		}
		n += v
	}
	return n, true
}

// The accepted pinned append-clone envelope, applied per owned leaf.
func maintenanceClone(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	return 2*n + 8
}

func validMaintenanceLimits(l LiveMaintenanceLimits) bool {
	return l.OwnedBudgetBytes > 0 && l.OwnedBudgetBytes <= 128<<20 && l.MaxArtifactBytes > 0 && l.MaxArtifactBytes <= envelope.MaxTotalInputBytes && l.MaxPublicationBytes > 0 && l.MaxPublicationBytes <= maxStateBytes && unsafe.Sizeof(uintptr(0)) == 8
}

// The enclosing caps are checked before this source-bounded calculation.
// Each term names simultaneously chargeable representations, not a universal
// input multiplier. Shared CBOR/crypto caches and encoding pools are global.
func maintenanceVerificationWorkspace(l LiveMaintenanceLimits) uint64 {
	n := uint64(l.MaxArtifactBytes)
	s := min(n, uint64(envelope.MaxSignedObjectBytes))
	p := min(s, uint64(envelope.MaxPayloadBytes))
	r := uint64(65536)
	// Provider, verification, request capture and unwrap typed bundle views.
	bundles := 4 * (2*n + 8*1024 + uint64(unsafe.Sizeof(liveProfileBundleV2{})) + 3*256*24)
	// Native artifact and unwrap argument copies, then the four sealed-parser
	// representations: raw fields, decoded fields, exact frame, component clones.
	sealed := 6 * maintenanceClone(n)
	// Plaintext plus RawTag, raw array, decoded fields, exact signed object and
	// component clones. The extracted payload and policy coexist in preflight.
	signed := 6*maintenanceClone(s) + maintenanceClone(p) + maintenanceClone(r)
	// Shared named typed/maps/arrays/policy-program canonical/crypto subset.
	codec, ok := runtimepolicy.AdmittedCodecWorkspaceV1(uint32(p))
	if !ok {
		return math.MaxUint64
	}
	// Opaque return overlaps: two activation records and the offline result.
	records := 3 * (maintenanceClone(n) + maintenanceClone(s) + maintenanceProfileMaximum())
	// Current/P3 revocation results, canonical payloads and accessor/list copies.
	revocations := uint64(4 * (2*(512*128) + 2*512*16 + 1024))
	// Generic leaves/canonical outputs and one active dynamic decoder error.
	canonical := 4 * maintenanceClone(n)
	// Shared current continuation's actual fixed temporary and synchronous
	// function slot. Its bundle/result backing already uses the named stages
	// above; the separately retained production root is reserved by its entry.
	fixed := uint64(unsafe.Sizeof(liveCurrentVerificationV1{})) + uint64(unsafe.Sizeof(liveCurrentCoreVerifierV1(nil)))
	return bundles + sealed + signed + codec + records + revocations + canonical + fixed
}

func maintenanceProfileMaximum() uint64 {
	return uint64(unsafe.Sizeof(envelope.CanonicalProfileV1{})) + maintenanceClone(65536) + 2*maintenanceClone(256*16) + (10+512)*128
}

func maintenanceProfileCharge(p envelope.CanonicalProfileV1) uint64 {
	n := uint64(cap(p.Policy)+16*(cap(p.RelayIDs)+cap(p.StrategyIDs))) + uint64(unsafe.Sizeof(p))
	for _, s := range []string{p.ContentID, p.ProfileID, p.LineageID, p.ProviderID, p.ContractVersion, p.RevocationScope, p.SnapshotMode, p.UpdateKind, p.PreviousContentID, p.PreviousProviderID} {
		n += uint64(len(s))
	}
	for _, s := range p.RelayIDs {
		n += uint64(len(s))
	}
	for _, s := range p.StrategyIDs {
		n += uint64(len(s))
	}
	return n
}

func maintenanceOpaqueCharge(n, signed int, p envelope.CanonicalProfileV1) uint64 {
	// State/receipt/inspection strings are separately retained even where the
	// implementation shares their backing with the canonical profile.
	return uint64(unsafe.Sizeof(profile.VerifiedActivationAdmission{})) + maintenanceClone(uint64(n)) + maintenanceClone(uint64(signed)) + maintenanceProfileCharge(p) + maintenanceClone(uint64(len(p.Policy))) + maintenanceClone(uint64(16*len(p.RelayIDs))) + maintenanceClone(uint64(16*len(p.StrategyIDs))) + 12*128
}

func (o *LiveMaintenanceAdmission) retainedCharge(signed int) uint64 {
	n := uint64(unsafe.Sizeof(*o)) + uint64(cap(o.artifact)) + maintenanceProfileCharge(o.value) + maintenanceOpaqueCharge(len(o.artifact), signed, o.value)
	b := o.bundle
	for _, v := range [][]byte{b.RootPublicDER, b.IssuerPublicDER, b.DelegationPayload, b.DelegationSignature, b.RevocationPayload, b.RevocationSignature, b.SealedProfile, o.request.RecipientPublic, o.request.ClientAuthPublic, o.request.Nonce, o.request.Signature, o.private.RecipientPrivate, o.private.ClientAuthSeed} {
		n += uint64(cap(v))
	}
	n += uint64(cap(b.Root.Keys)) * uint64(unsafe.Sizeof(profile.KeyReference{}))
	for _, s := range []string{b.DeploymentID, b.RootFingerprint, b.Root.ViewID, b.IssuerKey.KeyID, b.Delegation.RootKeyID, b.Delegation.IssuerKey.KeyID, b.Delegation.Scope.ProviderID, b.Delegation.Scope.LineageID, b.Delegation.Scope.ProfileNamespace, b.Revocations.Scope, o.request.RequestID, o.request.RecipientKeyID, o.request.ClientAuthKeyID, o.binding.ProviderID, o.binding.LineageID, o.binding.ProfileNamespace, o.binding.Hint, o.binding.KeyID} {
		n += uint64(len(s))
	}
	for _, k := range b.Root.Keys {
		n += uint64(len(k.KeyID))
	}
	for _, list := range [][]string{b.Revocations.RevokedIssuerKeyIDs, b.Revocations.RevokedContentIDs} {
		n += uint64(cap(list)) * 16
		for _, s := range list {
			n += uint64(len(s))
		}
	}
	return n + maintenanceServicesCharge(o.services)
}

func maintenanceServicesCharge(s *runtimepolicy.ServicesV1) uint64 {
	if s == nil {
		return 0
	}
	n := uint64(unsafe.Sizeof(*s))
	if p := s.Proxy; p != nil {
		n += uint64(unsafe.Sizeof(*p)) + uint64(cap(p.AddressKinds)) + uint64(cap(p.DestinationCIDRs))*uint64(unsafe.Sizeof(runtimepolicy.PrefixV2{})) + uint64(cap(p.DestinationPorts))*uint64(unsafe.Sizeof(runtimepolicy.PortRangeV1{}))
		for _, v := range p.DestinationCIDRs {
			n += uint64(cap(v.Address))
		}
	}
	if p := s.Probes; p != nil {
		n += uint64(unsafe.Sizeof(*p)) + uint64(cap(p.Targets))*uint64(unsafe.Sizeof(runtimepolicy.ProbeTargetV1{}))
		for _, v := range p.Targets {
			n += uint64(cap(v.Address) + cap(v.Methods) + cap(v.Modes))
		}
	}
	if u := s.Update; u != nil {
		n += uint64(unsafe.Sizeof(*u)) + uint64(len(u.URL)+len(u.ProfileID))
	}
	return n
}
