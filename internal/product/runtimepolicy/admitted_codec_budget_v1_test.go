package runtimepolicy

import (
	"kurdistan/internal/product/envelope"
	"testing"
)

func TestAdmittedCodecWorkspaceV1SourceTermsAndCaps(t *testing.T) {
	maximum, ok := AdmittedCodecWorkspaceV1(envelope.MaxPayloadBytes)
	if !ok || maximum != 24215673 {
		t.Fatalf("source decoder terms=%d valid=%v", maximum, ok)
	}
	for _, size := range []uint32{0, envelope.MaxPayloadBytes + 1, ^uint32(0)} {
		if _, ok := AdmittedCodecWorkspaceV1(size); ok {
			t.Fatal("invalid cap", size)
		}
	}
	small, ok := AdmittedCodecWorkspaceV1(1)
	if !ok || maximum-small != 6*(envelope.MaxPayloadBytes-1) {
		t.Fatal("profile term drift")
	}
}
