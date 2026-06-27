package auth

import (
	"bytes"
	"testing"

	"kurdistan/internal/compiler"
)

func TestValidProofAccepted(t *testing.T) {
	p, _ := compiler.Generate(1)
	transcript := [][]byte{[]byte("a"), []byte("b")}
	nonce := []byte("1234567890123456")
	proof, err := Proof(p, transcript, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(p, transcript, nonce, proof) {
		t.Fatal("valid proof rejected")
	}
}

func TestWrongProofRejected(t *testing.T) {
	p, _ := compiler.Generate(1)
	transcript := [][]byte{[]byte("a")}
	nonce := []byte("1234567890123456")
	proof := bytes.Repeat([]byte{1}, 32)
	if Verify(p, transcript, nonce, proof) {
		t.Fatal("wrong proof accepted")
	}
}

func TestTamperedTranscriptRejected(t *testing.T) {
	p, _ := compiler.Generate(1)
	nonce := []byte("1234567890123456")
	proof, _ := Proof(p, [][]byte{[]byte("a")}, nonce)
	if Verify(p, [][]byte{[]byte("b")}, nonce, proof) {
		t.Fatal("tampered transcript accepted")
	}
}

func TestReplayNonceCheckRepresented(t *testing.T) {
	cache := NewReplayCache()
	nonce := []byte("1234567890123456")
	if !cache.Accept(nonce) {
		t.Fatal("first nonce rejected")
	}
	if cache.Accept(nonce) {
		t.Fatal("replayed nonce accepted")
	}
}
