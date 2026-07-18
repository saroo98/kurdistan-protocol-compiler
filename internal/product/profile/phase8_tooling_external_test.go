package profile_test

import (
	"bytes"
	"encoding/json"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/testkit/phase8issuance"
	"os"
	"path/filepath"
	"testing"
)

type scopeSubstitutingResolver struct {
	next   profile.RecipientResolver
	mutate func(*profile.RecipientBinding)
}

func (r scopeSubstitutingResolver) ResolveRecipient(class envelope.ArtifactClass, hint string) (profile.RecipientBinding, error) {
	binding, err := r.next.ResolveRecipient(class, hint)
	if err != nil {
		return profile.RecipientBinding{}, err
	}
	r.mutate(&binding)
	return binding, nil
}

func TestOfflineIssuanceRoundTripsAllArtifactClasses(t *testing.T) {
	for _, class := range []envelope.ArtifactClass{envelope.ArtifactSignedPublic, envelope.ArtifactProviderGroup, envelope.ArtifactDeviceRecipient, envelope.ArtifactEncryptedBackup} {
		t.Run(string(class), func(t *testing.T) {
			issuer, verifier := phase8issuance.NewIssuer(), phase8issuance.NewIndependentVerifier()
			sealer, opener, resolver := phase8issuance.NewRecipientSealer(), phase8issuance.NewIndependentRecipientOpener(), phase8issuance.NewResolver(class)
			spec := phase8issuance.ValidSpec(class)
			artifact, err := profile.IssueOffline(spec, issuer, sealer)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := profile.VerifyOffline(boundVerifyRequest(spec, artifact), verifier, resolver, opener)
			if err != nil {
				t.Fatal(err)
			}
			if verified.Profile.ContentID != spec.Profile.ContentID || !bytes.Equal(verified.ExactArtifact, artifact) {
				t.Fatal("round trip mismatch")
			}
			if class != envelope.ArtifactSignedPublic && (sealer.Phase8BindingsUsed() != 1 || opener.Phase8BindingsUsed() != 1) {
				t.Fatal("Phase8 info/AAD not independently used")
			}
			inspection := profile.InspectRedacted(verified)
			if inspection.ContentSHA256 == "" || inspection.Generation != spec.Profile.Generation || inspection.ValidUntil != spec.Profile.ValidUntil {
				t.Fatal("redacted inspect")
			}
		})
	}
}

func TestOfflineIssuanceRejectsUnsafeInputsBeforeProviderUse(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*profile.OfflineIssuanceSpec)
	}{{"wrong-role", func(s *profile.OfflineIssuanceSpec) { s.IssuerRole = profile.RoleProvider }}, {"unsupported-suite", func(s *profile.OfflineIssuanceSpec) { s.Suite = envelope.SuiteReservedPQV1 }}, {"missing-audience", func(s *profile.OfflineIssuanceSpec) { s.Audience = "" }}, {"stale-generation", func(s *profile.OfflineIssuanceSpec) { s.MinimumGeneration = s.Profile.Generation + 1 }}, {"expired", func(s *profile.OfflineIssuanceSpec) { s.Now = s.Profile.ValidUntil }}, {"scope", func(s *profile.OfflineIssuanceSpec) { s.IssuerScope.ProviderID = "other" }}, {"recipient", func(s *profile.OfflineIssuanceSpec) {
		s.Recipient = nil
		s.Class = envelope.ArtifactDeviceRecipient
		s.Audience = envelope.AudienceProvisionedDevice
	}}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issuer := phase8issuance.NewIssuer()
			spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
			tc.mutate(&spec)
			artifact, err := profile.IssueOffline(spec, issuer, phase8issuance.NewRecipientSealer())
			if err == nil || len(artifact) != 0 {
				t.Fatal("accepted")
			}
			if issuer.Operations() != 0 {
				t.Fatal("provider used before validation")
			}
		})
	}
}

func TestOfflineVerifierRejectsTamperHeadersRecipientsAndTruncation(t *testing.T) {
	issuer, verifier := phase8issuance.NewIssuer(), phase8issuance.NewIndependentVerifier()
	sealer, opener, resolver := phase8issuance.NewRecipientSealer(), phase8issuance.NewIndependentRecipientOpener(), phase8issuance.NewResolver(envelope.ArtifactDeviceRecipient)
	spec := phase8issuance.ValidSpec(envelope.ArtifactDeviceRecipient)
	artifact, err := profile.IssueOffline(spec, issuer, sealer)
	if err != nil {
		t.Fatal(err)
	}
	request := boundVerifyRequest(spec, artifact)
	cases := []struct {
		name   string
		mutate func(*profile.OfflineVerifyRequest)
	}{{"truncation", func(r *profile.OfflineVerifyRequest) { r.Artifact = r.Artifact[:len(r.Artifact)-1] }}, {"ciphertext-tamper", func(r *profile.OfflineVerifyRequest) {
		r.Artifact = append([]byte(nil), r.Artifact...)
		r.Artifact[len(r.Artifact)-1] ^= 1
	}}, {"wrong-header-class", func(r *profile.OfflineVerifyRequest) {
		r.Class = envelope.ArtifactProviderGroup
		r.Audience = envelope.AudienceProvisionedGroup
	}}, {"wrong-recipient", func(r *profile.OfflineVerifyRequest) { resolver.UseWrongRecipient(true) }}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := request
			tc.mutate(&r)
			if _, err := profile.VerifyOffline(r, verifier, resolver, opener); err == nil {
				t.Fatal("accepted")
			}
			resolver.UseWrongRecipient(false)
		})
	}
}

func TestPhase8OfflineVerifierRejectsRecipientScopeSubstitution(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*profile.RecipientBinding)
	}{
		{"provider", func(binding *profile.RecipientBinding) { binding.ProviderID = "provider.other" }},
		{"lineage", func(binding *profile.RecipientBinding) { binding.LineageID = "lineage.other" }},
		{"namespace", func(binding *profile.RecipientBinding) { binding.ProfileNamespace = "other." }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := phase8issuance.ValidSpec(envelope.ArtifactDeviceRecipient)
			artifact, err := profile.IssueOffline(spec, phase8issuance.NewIssuer(), phase8issuance.NewRecipientSealer())
			if err != nil {
				t.Fatal(err)
			}
			resolver := scopeSubstitutingResolver{next: phase8issuance.NewResolver(spec.Class), mutate: tc.mutate}
			if _, err := profile.VerifyOffline(boundVerifyRequest(spec, artifact), phase8issuance.NewIndependentVerifier(), resolver, phase8issuance.NewIndependentRecipientOpener()); err == nil {
				t.Fatal("recipient scope substitution was accepted")
			}
		})
	}
}

func TestOfflineVerifierRejectsPolicyBindingNegatives(t *testing.T) {
	spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	artifact, err := profile.IssueOffline(spec, phase8issuance.NewIssuer(), phase8issuance.NewRecipientSealer())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*profile.OfflineVerifyRequest)
	}{{"issuer-suite", func(r *profile.OfflineVerifyRequest) { r.IssuerKey.SuiteID = 99 }}, {"issuer-role", func(r *profile.OfflineVerifyRequest) { r.IssuerRole = profile.RoleProvider }}, {"issuer-scope", func(r *profile.OfflineVerifyRequest) { r.IssuerScope.ProviderID = "other" }}, {"time", func(r *profile.OfflineVerifyRequest) { r.Now = spec.Profile.ValidUntil }}, {"generation-floor", func(r *profile.OfflineVerifyRequest) { r.MinimumGeneration++ }}, {"safety-floor", func(r *profile.OfflineVerifyRequest) { r.MinimumSafetyFloor++ }}, {"root-floor", func(r *profile.OfflineVerifyRequest) { r.MinimumRootEpoch++ }}, {"revocation-floor", func(r *profile.OfflineVerifyRequest) { r.MinimumRevocationEpoch++ }}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := boundVerifyRequest(spec, artifact)
			tc.mutate(&r)
			if _, err := profile.VerifyOffline(r, phase8issuance.NewIndependentVerifier(), nil, nil); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestWO806InvalidFixturesAreRejectedByIndependentConsumers(t *testing.T) {
	dir := filepath.Join("testdata", "phase8-issuance")
	spec := phase8issuance.ValidSpec(envelope.ArtifactDeviceRecipient)
	for _, name := range []string{"invalid-tamper.bin", "invalid-truncation.bin"} {
		artifact, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := profile.VerifyOffline(boundVerifyRequest(spec, artifact), phase8issuance.NewIndependentVerifier(), phase8issuance.NewResolver(spec.Class), phase8issuance.NewIndependentRecipientOpener()); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
	for _, name := range []string{"invalid-wrong-role.json", "invalid-generation.json"} {
		var invalid profile.OfflineIssuanceSpec
		readFixtureJSON(t, filepath.Join(dir, name), &invalid)
		if artifact, err := profile.IssueOffline(invalid, phase8issuance.NewIssuer(), phase8issuance.NewRecipientSealer()); err == nil || len(artifact) != 0 {
			t.Fatalf("accepted %s", name)
		}
	}
	var wrongHeader profile.OfflineVerifyRequest
	readFixtureJSON(t, filepath.Join(dir, "invalid-wrong-header.json"), &wrongHeader)
	if _, err := profile.VerifyOffline(wrongHeader, phase8issuance.NewIndependentVerifier(), phase8issuance.NewResolver(spec.Class), phase8issuance.NewIndependentRecipientOpener()); err == nil {
		t.Fatal("accepted invalid-wrong-header.json")
	}
	var wrongRecipient struct {
		Request profile.OfflineVerifyRequest `json:"request"`
	}
	readFixtureJSON(t, filepath.Join(dir, "invalid-wrong-recipient.json"), &wrongRecipient)
	resolver := phase8issuance.NewResolver(spec.Class)
	resolver.UseWrongRecipient(true)
	if _, err := profile.VerifyOffline(wrongRecipient.Request, phase8issuance.NewIndependentVerifier(), resolver, phase8issuance.NewIndependentRecipientOpener()); err == nil {
		t.Fatal("accepted invalid-wrong-recipient.json")
	}
}

func readFixtureJSON(t *testing.T, path string, target any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatal(err)
	}
}

func boundVerifyRequest(spec profile.OfflineIssuanceSpec, artifact []byte) profile.OfflineVerifyRequest {
	return profile.OfflineVerifyRequest{Artifact: artifact, Class: spec.Class, Audience: spec.Audience, Suite: spec.Suite, IssuerRole: profile.RoleIssuer, IssuerScope: spec.IssuerScope, IssuerKey: spec.IssuerKey, Now: spec.Now, MinimumGeneration: spec.MinimumGeneration, MinimumSafetyFloor: spec.Profile.RequiredSafetyFloor, MinimumRootEpoch: spec.Profile.RootEpoch, MinimumRevocationEpoch: spec.Profile.RevocationEpoch}
}
