package diversity

import (
	"strings"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/framing"
	"kurdistan/internal/ir"
)

func TestGeneratedProfilesAvoidFixedSignatureBehavior(t *testing.T) {
	const count = 80
	firstWireSymbols := map[string]bool{}
	firstContactShapes := map[string]bool{}
	firstFrameLengths := map[int]bool{}
	failedAuthPolicies := map[string]bool{}
	malformedFramePolicies := map[string]bool{}

	for seed := int64(1); seed <= count; seed++ {
		p, err := compiler.Generate(seed)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.FirstContact.Steps) == 0 {
			t.Fatal("profile has no first-contact steps")
		}
		first := p.FirstContact.Steps[0]
		if containsForbiddenConstant(first.WireSymbol) {
			t.Fatalf("first wire symbol contains forbidden constant: %q", first.WireSymbol)
		}
		firstWireSymbols[first.WireSymbol] = true
		firstContactShapes[firstContactShape(p)] = true
		failedAuthPolicies[p.InvalidInput.FailedAuth] = true
		malformedFramePolicies[p.InvalidInput.MalformedFrame] = true
		frames, err := framing.EncodeOperation(p, framing.Operation{Semantic: ir.SemanticData, StreamID: 1, Payload: []byte("hello")}, seed)
		if err != nil {
			t.Fatal(err)
		}
		firstFrameLengths[len(frames[0])] = true
	}

	if len(firstWireSymbols) <= 1 {
		t.Fatal("universal first wire symbol detected")
	}
	if len(firstContactShapes) <= 1 {
		t.Fatal("universal first-contact state path shape detected")
	}
	if len(firstFrameLengths) <= 1 {
		t.Fatal("universal first frame length detected")
	}
	if len(failedAuthPolicies) <= 1 {
		t.Fatal("universal invalid-auth response policy detected")
	}
	if len(malformedFramePolicies) <= 1 {
		t.Fatal("universal malformed-frame response policy detected")
	}
}

func containsForbiddenConstant(value string) bool {
	upper := strings.ToUpper(value)
	for _, forbidden := range []string{"HELLO", "AUTH", "OPEN", "KURD", "VPN", "PROXY", "CONNECT"} {
		if strings.Contains(upper, forbidden) {
			return true
		}
	}
	return false
}
