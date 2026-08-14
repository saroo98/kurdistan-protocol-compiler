// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignedReceiptRequiresExactDomainCanonicalPayloadAndTrustedKey(t *testing.T) {
	privateKey, publicKey := receiptKeyPair(1)
	payload := validRCLockedPayload(t)
	raw, err := SignStatement(privateKey, StatementRCLocked, payload)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyStatement(raw, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if verified.StatementType != StatementRCLocked || verified.DigestSHA256 == "" {
		t.Fatalf("verified statement=%+v", verified)
	}
	decoded, ok := verified.Payload.(RCLockedPayload)
	if !ok || decoded != payload {
		t.Fatalf("payload=%#v", verified.Payload)
	}

	_, wrongPublic := receiptKeyPair(2)
	if _, err := VerifyStatement(raw, wrongPublic); err == nil {
		t.Fatal("receipt verified under an untrusted key")
	}

	var envelope Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.StatementType = StatementSoakReady
	mutated, err := MarshalCanonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyStatement(mutated, publicKey); err == nil {
		t.Fatal("receipt verified under a substituted statement domain")
	}
}

func TestReceiptRejectsNonCanonicalDuplicateUnknownAndTrailingJSON(t *testing.T) {
	privateKey, publicKey := receiptKeyPair(3)
	raw, err := SignStatement(privateKey, StatementRCLocked, validRCLockedPayload(t))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"leading whitespace": append([]byte(" "), raw...),
		"trailing newline":   append(append([]byte(nil), raw...), '\n'),
		"duplicate":          bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1),
		"unknown":            bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":true,"schema":`), 1),
		"trailing value":     append(append([]byte(nil), raw...), []byte(`{}`)...),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyStatement(candidate, publicKey); err == nil {
				t.Fatal("noncanonical or non-strict receipt accepted")
			}
		})
	}
}

func TestReceiptRejectsInvalidPrivateAndPublicKeySizes(t *testing.T) {
	if _, err := SignStatement(make([]byte, ed25519.PrivateKeySize-1), StatementRCLocked, validRCLockedPayload(t)); err == nil {
		t.Fatal("short private key accepted")
	}
	privateKey, _ := receiptKeyPair(4)
	raw, err := SignStatement(privateKey, StatementRCLocked, validRCLockedPayload(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyStatement(raw, make([]byte, ed25519.PublicKeySize-1)); err == nil {
		t.Fatal("short public key accepted")
	}
}

func TestAttemptPayloadRejectsMissingTerminalEvidenceAndUnknownOutcomes(t *testing.T) {
	value := validAttemptPayload(1, "")
	value.State = AttemptTerminal
	value.Outcome = "PASS"
	if err := ValidateAttemptPayload(value); err == nil {
		t.Fatal("terminal attempt without result digest accepted")
	}
	value.ResultSHA256 = strings.Repeat("a", 64)
	value.Outcome = "UNKNOWN"
	if err := ValidateAttemptPayload(value); err == nil {
		t.Fatal("unknown attempt outcome accepted")
	}
}

func TestAttemptPayloadRequiresRCLockAndDirectBindingOutsideFinalSoak(t *testing.T) {
	value := validAttemptPayload(1, "")
	value.Mode = "Stress"
	value.AuthorizationSHA256 = value.RCLockedSHA256
	if err := ValidateAttemptPayload(value); err != nil {
		t.Fatal(err)
	}
	value.AuthorizationSHA256 = strings.Repeat("0", 64)
	if err := ValidateAttemptPayload(value); err == nil {
		t.Fatal("non-final attempt accepted an authorization other than its RC lock")
	}
}

func validRCLockedPayload(t *testing.T) RCLockedPayload {
	t.Helper()
	roots, err := NewSubjectRoots(
		strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64),
		strings.Repeat("4", 64), strings.Repeat("5", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	return RCLockedPayload{
		Schema: RCLockedSchema,
		Candidate: CandidateIdentity{
			Repository: "saroo98/kurdistan-protocol-compiler",
			CommitSHA:  strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40),
			Roots: roots, ComparisonSHA256: strings.Repeat("c", 64),
		},
		AuthorizationID: strings.Repeat("d", 32),
		IssuedAt:        "2026-08-14T12:00:00Z",
	}
}

func receiptKeyPair(seedByte byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize))
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	return privateKey, publicKey
}
