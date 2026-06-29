// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"fmt"

	"kurdistan/internal/ir"
)

type RuntimeCompatibility struct {
	SchemaVersion            string
	CompilerSecurityVersion  string
	SupportedSecuritySuites  []string
	RequiredCapabilities     []string
	SupportedCarrierFamilies []string
	SupportedProxyFeatures   []string
	SupportedStreamFeatures  []string
	MaxEnvelopeBytes         int
	MaxStreamCount           int
	MaxReplayWindow          int
}

func DefaultRuntimeCompatibility() RuntimeCompatibility {
	return RuntimeCompatibility{
		SchemaVersion:            ir.SupportedVersion,
		CompilerSecurityVersion:  Version,
		SupportedSecuritySuites:  []string{SuiteKDFHKDFSHA256 + "/" + SuiteAEADAES256GCM + "/" + SuiteMACHMACSHA256 + "/" + SuiteTranscriptSHA256V1},
		RequiredCapabilities:     DefaultCapabilities().Features,
		SupportedCarrierFamilies: ir.CarrierFamilies(),
		SupportedProxyFeatures:   ir.ProxySemantics(),
		SupportedStreamFeatures:  []string{"open_stream", "data", "close_stream", "reset_stream", "window_update", "session_close"},
		MaxEnvelopeBytes:         64 * 1024,
		MaxStreamCount:           16,
		MaxReplayWindow:          4096,
	}
}

func CheckProfileCompatibility(p *ir.Profile, runtime RuntimeCompatibility) error {
	if p == nil {
		return fmt.Errorf("%w: nil profile", ErrCompatibility)
	}
	c := p.Compatibility
	if c.SchemaVersion != runtime.SchemaVersion {
		return fmt.Errorf("%w: schema version", ErrCompatibility)
	}
	if c.CompilerSecurityVersion == "" || c.MinimumRuntimeVersion == "" {
		return fmt.Errorf("%w: missing version metadata", ErrCompatibility)
	}
	if !contains(c.SupportedSecuritySuites, suiteString(DefaultSuite())) {
		return fmt.Errorf("%w: security suite unsupported by profile", ErrCompatibility)
	}
	if !contains(runtime.SupportedSecuritySuites, suiteString(DefaultSuite())) {
		return fmt.Errorf("%w: security suite unsupported by runtime", ErrCompatibility)
	}
	if err := RequireCapabilities(CapabilitySet{Features: c.RequiredCapabilities}, CapabilitySet{Features: runtime.RequiredCapabilities}); err != nil {
		return err
	}
	if !contains(runtime.SupportedCarrierFamilies, p.CarrierPolicy.CarrierFamily) {
		return fmt.Errorf("%w: carrier family", ErrCompatibility)
	}
	if c.MaxEnvelopeBytes <= 0 || c.MaxEnvelopeBytes > runtime.MaxEnvelopeBytes {
		return fmt.Errorf("%w: envelope size", ErrCompatibility)
	}
	if c.MaxStreamCount <= 0 || c.MaxStreamCount > runtime.MaxStreamCount {
		return fmt.Errorf("%w: stream count", ErrCompatibility)
	}
	if c.MaxReplayWindow <= 0 || c.MaxReplayWindow > runtime.MaxReplayWindow {
		return fmt.Errorf("%w: replay window", ErrCompatibility)
	}
	return nil
}

func suiteString(s Suite) string {
	return s.KDF + "/" + s.AEAD + "/" + s.MAC + "/" + s.Transcript
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
