// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import "kurdistan/internal/product/envelope"

// LocallyWrappedActivationRequest opens an artifact using an opaque local key
// handle before entering the verified activation transaction. A local unwrap
// failure is terminal for this attempt and occurs before activation storage is
// observed or mutated.
type LocallyWrappedActivationRequest struct {
	Activation      ActivationRequest
	Wrapper         LocalWrapper
	Key             KeyReference
	WrappedArtifact []byte
}

// ActivateLocallyWrappedProfile is the production recovery boundary for a
// locally protected profile artifact. It fails closed when the device key is
// unavailable and never falls back to unwrapped or stale profile bytes.
func ActivateLocallyWrappedProfile(request LocallyWrappedActivationRequest) (ActivationRecord, error) {
	if request.Wrapper == nil || request.Key.validate() != nil || len(request.WrappedArtifact) == 0 || len(request.WrappedArtifact) > envelope.MaxTotalInputBytes {
		return ActivationRecord{}, activationFailure(ActivationStorageFailure)
	}
	artifact, err := request.Wrapper.Unwrap(request.Key, request.WrappedArtifact)
	if err != nil || len(artifact) == 0 || len(artifact) > envelope.MaxTotalInputBytes {
		return ActivationRecord{}, activationFailure(ActivationStorageFailure)
	}
	request.Activation.Artifact = artifact
	return ActivateVerifiedProfile(request.Activation)
}
