// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package envelope

import (
	"bytes"
	"testing"
)

func FuzzPhase8ProfileCodec(f *testing.F) {
	seed, err := EncodeCanonicalProfileV1(canonicalFixtureProfile())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{0xbf, 0x01, 0x01, 0xff})
	f.Fuzz(func(t *testing.T, input []byte) {
		profile, err := DecodeCanonicalProfileV1(input)
		if err != nil {
			return
		}
		reencoded, err := EncodeCanonicalProfileV1(profile)
		if err != nil {
			t.Fatalf("accepted profile failed encode: %v", err)
		}
		if !bytes.Equal(input, reencoded) {
			t.Fatal("accepted profile was not byte-canonical")
		}
	})
}

func FuzzPhase8SignedParser(f *testing.F) {
	payload, err := EncodeCanonicalProfileV1(canonicalFixtureProfile())
	if err != nil {
		f.Fatal(err)
	}
	protected, err := BuildSignedProtectedHeaders([]byte("phase8-key-id"), fixturePublicMetadata())
	if err != nil {
		f.Fatal(err)
	}
	signature, err := EncodeRawES256Signature(bigOne(), bigOne())
	if err != nil {
		f.Fatal(err)
	}
	signed, err := BuildTaggedCOSESign1(protected, payload, signature)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(signed)
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, input []byte) {
		parsed, err := ParseSignedProfileOpaque(input)
		if err != nil {
			return
		}
		if !bytes.Equal(parsed.ExactObject, input) || len(parsed.Payload) == 0 {
			t.Fatal("accepted signed object lost exact bytes")
		}
	})
}

func FuzzPhase8SealedParser(f *testing.F) {
	outer, err := BuildSealProtected(fixtureDeviceMetadata())
	if err != nil {
		f.Fatal(err)
	}
	sealed, err := BuildSealedFrame(outer, make([]byte, HPKEP256EncSize), make([]byte, HPKEAEADTagSize+1))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sealed)
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, input []byte) {
		parsed, err := ParseSealedProfileOpaque(input)
		if err != nil {
			return
		}
		if !bytes.Equal(parsed.ExactFrame, input) || len(parsed.Ciphertext) <= HPKEAEADTagSize {
			t.Fatal("accepted sealed frame lost exact bytes")
		}
	})
}

func FuzzPhase8URIIngress(f *testing.F) {
	seed, err := EncodeCanonicalProfileV1(canonicalFixtureProfile())
	if err != nil {
		f.Fatal(err)
	}
	uri, err := EncodeArtifactURI(seed)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uri)
	f.Add("kurd://legacy?exp=1")
	f.Fuzz(func(t *testing.T, text string) {
		normalized, err := NormalizeProfileIngress(ProfileIngress{Kind: IngressURI, Text: text})
		if err != nil {
			return
		}
		canonical, err := EncodeArtifactURI(normalized)
		if err != nil {
			t.Fatalf("accepted ingress failed canonical encoding: %v", err)
		}
		if canonical != text {
			t.Fatal("accepted URI was not canonical")
		}
	})
}

func FuzzPhase8QRIngress(f *testing.F) {
	seed, err := EncodeCanonicalProfileV1(canonicalFixtureProfile())
	if err != nil {
		f.Fatal(err)
	}
	chunks, err := EncodeQRChunks(seed, len(seed))
	if err != nil || len(chunks) != 1 {
		f.Fatalf("seed chunks=%d err=%v", len(chunks), err)
	}
	f.Add(chunks[0])
	f.Add("KURD1/01/1/AQ")
	f.Fuzz(func(t *testing.T, chunk string) {
		normalized, err := NormalizeProfileIngress(ProfileIngress{Kind: IngressQRChunks, Chunks: []string{chunk}})
		if err != nil {
			return
		}
		canonical, err := EncodeQRChunks(normalized, len(normalized))
		if err != nil || len(canonical) != 1 || canonical[0] != chunk {
			t.Fatal("accepted QR chunk was not canonical")
		}
	})
}
