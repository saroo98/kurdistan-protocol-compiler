package compiler

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/ir"
)

func TestVersionAuthorityV1(t *testing.T) {
	if ir.LegacySchemaVersionV1 != "0.1.0-lab" || ir.NextSchemaVersionV1 != "0.2.0-lab" ||
		ir.LegacySecurityVersionV1 != "0.12.0-lab" || ir.NextSecurityVersionV1 != "0.13.0-lab" {
		t.Fatal("frozen legacy/next version authority drifted")
	}
	if ir.SupportedVersion != ir.NextSchemaVersionV1 || ir.SupportedSecurityVersion != ir.NextSecurityVersionV1 {
		t.Fatal("active aliases did not move to reviewed next versions")
	}
	if security.Version != ir.SupportedSecurityVersion || security.HandshakeVersionV1 != "kurdistan-handshake-v1" ||
		security.PolicyEncodingVersionV1 != "policy-v1" || security.RecordVersionV1 != "record-v1" {
		t.Fatal("security component identifiers or active alias drifted")
	}
	profile, err := Generate(13035)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Version != ir.NextSchemaVersionV1 ||
		profile.Security.SecurityVersion != ir.NextSecurityVersionV1 ||
		profile.Compatibility.SchemaVersion != ir.NextSchemaVersionV1 ||
		profile.Compatibility.CompilerSecurityVersion != ir.NextSecurityVersionV1 ||
		profile.Compatibility.MinimumRuntimeVersion != ir.SupportedSecurityVersion {
		t.Fatalf("generated serialized version tuple drifted: profile=%q security=%q compatibility=%+v", profile.Version, profile.Security.SecurityVersion, profile.Compatibility)
	}
	for _, path := range []string{"../ir/profile.go", "../../crypto/security/context.go"} {
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, invented := range []string{"SerializedSchemaVersion", "SerializedSecurityVersion", "SerializedMinimumRuntimeVersion", "LegacyMinimumRuntimeVersionV1", "SchemaVersion         = ir.", "MinimumRuntimeVersion = ir."} {
			if strings.Contains(string(raw), invented) {
				t.Fatalf("invented version alias %q remains in %s", invented, path)
			}
		}
	}
}

func TestModelOnlyAuthMaterialInventoryV1(t *testing.T) {
	profile, err := Generate(13013)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Auth.TestKeyHex == "" || !strings.Contains(profile.Auth.Mode, "test-only") {
		t.Fatalf("generated auth material is not explicitly model-only: %+v", profile.Auth)
	}
	if strings.Contains(strings.ToLower(profile.Auth.Mode), "production") {
		t.Fatal("model profile claimed production authentication")
	}
}

func validCandidateRequestV1() CandidateRequestV1 {
	return CandidateRequestV1{Seed: 13013, Route: "strict_candidate", NonceSource: "authenticated_entropy", SecretSource: "caller_secret", IdentitySource: "authenticated_owner", TrustSource: "owner_registry"}
}

func TestGeneratedStrictBoundaryCandidateRequestV1(t *testing.T) {
	request := validCandidateRequestV1()
	if err := ValidateCandidateRequestV1(request); err != nil {
		t.Fatalf("strict candidate request shape rejected: %v", err)
	}
	profile, err := GenerateCandidateV1(request)
	if err != errCandidateMigrationPendingV1 || profile != nil {
		t.Fatalf("strict candidate did not fail closed: profile=%v err=%v", profile, err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*CandidateRequestV1)
	}{
		{"lab selector", func(v *CandidateRequestV1) { v.Route = "lab_fault" }},
		{"legacy model route", func(v *CandidateRequestV1) { v.Route = "legacy_model" }},
		{"deterministic nonce", func(v *CandidateRequestV1) { v.NonceSource = "deterministic" }},
		{"default secret", func(v *CandidateRequestV1) { v.SecretSource = "default" }},
		{"default identity", func(v *CandidateRequestV1) { v.IdentitySource = "default" }},
		{"default trust", func(v *CandidateRequestV1) { v.TrustSource = "default" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := request
			test.mutate(&invalid)
			if profile, err := GenerateCandidateV1(invalid); err == nil || profile != nil {
				t.Fatalf("unsafe candidate accepted: %+v", invalid)
			}
		})
	}
}

func TestNoDefaultSecretIdentityOrTrustV1(t *testing.T) {
	request := validCandidateRequestV1()
	for _, mutate := range []func(*CandidateRequestV1){
		func(v *CandidateRequestV1) { v.SecretSource = "" },
		func(v *CandidateRequestV1) { v.IdentitySource = "" },
		func(v *CandidateRequestV1) { v.TrustSource = "" },
	} {
		invalid := request
		mutate(&invalid)
		if err := ValidateCandidateRequestV1(invalid); err == nil {
			t.Fatalf("missing candidate authority accepted: %+v", invalid)
		}
	}
}

func TestSameSeedProducesSameProfile(t *testing.T) {
	a, err := Generate(99)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(99)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("same seed produced different profiles")
	}
}

func TestDifferentSeedsProduceDifferentProfiles(t *testing.T) {
	a, _ := Generate(1)
	b, _ := Generate(2)
	if a.GenerationHash == b.GenerationHash {
		t.Fatal("different seeds produced same profile hash")
	}
}

func TestGeneratedTenProfilesValidate(t *testing.T) {
	for seed := int64(1); seed <= 10; seed++ {
		p, err := Generate(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if err := ir.Validate(p); err != nil {
			t.Fatalf("seed %d failed validation: %v", seed, err)
		}
		if err := ValidateDeterministic(p); err != nil {
			t.Fatalf("seed %d failed deterministic validation: %v", seed, err)
		}
	}
}

func TestGeneratedProfilesVaryPatternsAndFrameGrammars(t *testing.T) {
	patterns := map[string]bool{}
	grammars := map[string]bool{}
	for seed := int64(1); seed <= 20; seed++ {
		p, err := Generate(seed)
		if err != nil {
			t.Fatal(err)
		}
		patterns[p.FirstContact.PatternID] = true
		grammars[p.FrameGrammar.LengthMode+"|"+p.FrameGrammar.TypeMode+"|"+p.FrameGrammar.PaddingPlacement] = true
	}
	if len(patterns) < 3 {
		t.Fatalf("expected at least 3 first-contact patterns, got %d", len(patterns))
	}
	if len(grammars) < 3 {
		t.Fatalf("expected at least 3 frame grammar combinations, got %d", len(grammars))
	}
}
