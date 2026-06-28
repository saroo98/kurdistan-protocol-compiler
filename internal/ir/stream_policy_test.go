package ir_test

import (
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func TestGeneratedProfilesIncludeValidStreamPolicies(t *testing.T) {
	seenEncodings := map[string]bool{}
	seenPriorities := map[string]bool{}
	seenWindowPolicies := map[string]bool{}
	for seed := int64(1); seed <= 32; seed++ {
		p, err := compiler.Generate(seed)
		if err != nil {
			t.Fatal(err)
		}
		if err := ir.Validate(p); err != nil {
			t.Fatalf("seed %d failed validation: %v", seed, err)
		}
		if p.Stream.MaxConcurrentStreams < 2 {
			t.Fatalf("seed %d max concurrent streams = %d", seed, p.Stream.MaxConcurrentStreams)
		}
		if p.Stream.InitialStreamWindowBytes <= 0 || p.Stream.InitialSessionWindowBytes < p.Stream.InitialStreamWindowBytes {
			t.Fatalf("seed %d invalid windows: %+v", seed, p.Stream)
		}
		for _, semantic := range []string{
			ir.SemanticOpenStream,
			ir.SemanticData,
			ir.SemanticClose,
			ir.SemanticResetStream,
			ir.SemanticWindowUpdate,
			ir.SemanticSessionClose,
		} {
			if _, ok := ir.MessageBySemantic(p, semantic); !ok {
				t.Fatalf("seed %d missing semantic %q", seed, semantic)
			}
		}
		seenEncodings[p.Stream.IDEncodingMode] = true
		seenPriorities[p.Stream.PriorityPolicy] = true
		seenWindowPolicies[p.Stream.WindowUpdatePolicy] = true
	}
	if len(seenEncodings) < 3 {
		t.Fatalf("stream ID encodings did not vary enough: %v", seenEncodings)
	}
	if len(seenPriorities) < 3 {
		t.Fatalf("priority policies did not vary enough: %v", seenPriorities)
	}
	if len(seenWindowPolicies) < 3 {
		t.Fatalf("window update policies did not vary enough: %v", seenWindowPolicies)
	}
}

func TestValidateRejectsInvalidStreamPolicies(t *testing.T) {
	base, err := compiler.Generate(99)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*ir.Profile){
		"zero max streams": func(p *ir.Profile) {
			p.Stream.MaxConcurrentStreams = 0
		},
		"zero stream window": func(p *ir.Profile) {
			p.Stream.InitialStreamWindowBytes = 0
		},
		"session smaller than stream": func(p *ir.Profile) {
			p.Stream.InitialSessionWindowBytes = p.Stream.InitialStreamWindowBytes - 1
		},
		"unsupported stream id encoding": func(p *ir.Profile) {
			p.Stream.IDEncodingMode = "fixed_external_tag"
		},
		"duplicate stream semantic wire symbol": func(p *ir.Profile) {
			for i := range p.Messages {
				if p.Messages[i].Semantic == ir.SemanticWindowUpdate {
					p.Messages[i].WireSymbol = p.Messages[0].WireSymbol
				}
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cp := *base
			cp.Messages = append([]ir.MessageSymbol(nil), base.Messages...)
			cp.GenerationHash = ""
			mutate(&cp)
			if err := ir.Validate(&cp); err == nil {
				t.Fatalf("Validate accepted invalid stream policy: %+v", cp.Stream)
			}
		})
	}
}
