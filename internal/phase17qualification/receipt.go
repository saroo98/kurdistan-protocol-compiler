// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"kurdistan/internal/assurance"
)

const (
	EnvelopeSchema      = "kurdistan-phase17-qualification-envelope-v1"
	RCLockedSchema      = "kurdistan-phase17-rc-locked-v1"
	AttemptSchema       = "kurdistan-phase17-attempt-v1"
	SoakReadySchema     = "kurdistan-phase17-soak-ready-v1"
	SoakConsumedSchema  = "kurdistan-phase17-soak-consumed-v1"
	SupersedeSchema     = "kurdistan-phase17-supersede-v1"
	EvidenceFinalSchema = "kurdistan-phase17-evidence-final-v1"

	StatementRCLocked      = "RC_LOCKED"
	StatementAttempt       = "ATTEMPT"
	StatementSoakReady     = "SOAK_READY"
	StatementSoakConsumed  = "SOAK_CONSUMED"
	StatementSupersede     = "SUPERSEDE"
	StatementEvidenceFinal = "EVIDENCE_FINAL"

	AttemptBegin    = "BEGIN"
	AttemptTerminal = "TERMINAL"
)

const signatureDomain = "KURDISTAN-PHASE17-QUALIFICATION-V1\x00"

var (
	hex32Pattern        = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex40Pattern        = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64Pattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex128Pattern       = regexp.MustCompile(`^[0-9a-f]{128}$`)
	repositoryPatternV1 = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
)

type Envelope struct {
	Schema        string          `json:"schema"`
	StatementType string          `json:"statementType"`
	KeyID         string          `json:"keyId"`
	Payload       json.RawMessage `json:"payload"`
	Signature     string          `json:"signature"`
}

type SubjectRoots struct {
	SourceSHA256   string `json:"sourceSha256"`
	ProductSHA256  string `json:"productSha256"`
	HarnessSHA256  string `json:"harnessSha256"`
	WorkloadSHA256 string `json:"workloadSha256"`
	VerifierSHA256 string `json:"verifierSha256"`
	CandidateID    string `json:"candidateId"`
}

type CandidateIdentity struct {
	Repository       string       `json:"repository"`
	CommitSHA        string       `json:"commitSha"`
	TreeSHA          string       `json:"treeSha"`
	Roots            SubjectRoots `json:"roots"`
	ComparisonSHA256 string       `json:"comparisonSha256"`
}

type RCLockedPayload struct {
	Schema          string            `json:"schema"`
	Candidate       CandidateIdentity `json:"candidate"`
	AuthorizationID string            `json:"authorizationId"`
	IssuedAt        string            `json:"issuedAt"`
}

type AttemptPayload struct {
	Schema              string `json:"schema"`
	CandidateID         string `json:"candidateId"`
	Sequence            uint64 `json:"sequence"`
	PreviousEntrySHA256 string `json:"previousEntrySha256"`
	State               string `json:"state"`
	AttemptID           string `json:"attemptId"`
	Mode                string `json:"mode"`
	RCLockedSHA256      string `json:"rcLockedSha256"`
	AuthorizationSHA256 string `json:"authorizationSha256"`
	EnvironmentSHA256   string `json:"environmentSha256"`
	PreflightSHA256     string `json:"preflightSha256"`
	Outcome             string `json:"outcome"`
	ResultSHA256        string `json:"resultSha256"`
	RecordedAt          string `json:"recordedAt"`
}

type SoakReadyPayload struct {
	Schema                  string `json:"schema"`
	CandidateID             string `json:"candidateId"`
	RCLockedSHA256          string `json:"rcLockedSha256"`
	EvidenceIndexSHA256     string `json:"evidenceIndexSha256"`
	PriorStressResultSHA256 string `json:"priorStressResultSha256"`
	LedgerHeadSHA256        string `json:"ledgerHeadSha256"`
	AuthorizationID         string `json:"authorizationId"`
	IssuedAt                string `json:"issuedAt"`
}

type SoakConsumedPayload struct {
	Schema              string `json:"schema"`
	CandidateID         string `json:"candidateId"`
	Sequence            uint64 `json:"sequence"`
	PreviousEntrySHA256 string `json:"previousEntrySha256"`
	SoakReadySHA256     string `json:"soakReadySha256"`
	RCLockedSHA256      string `json:"rcLockedSha256"`
	AttemptID           string `json:"attemptId"`
	EnvironmentSHA256   string `json:"environmentSha256"`
	PreflightSHA256     string `json:"preflightSha256"`
	ConsumedAt          string `json:"consumedAt"`
}

type SupersedePayload struct {
	Schema           string   `json:"schema"`
	CandidateID      string   `json:"candidateId"`
	NewCandidateID   string   `json:"newCandidateId"`
	ReasonCode       string   `json:"reasonCode"`
	AffectedRoots    []string `json:"affectedRoots"`
	RequiredReruns   []string `json:"requiredReruns"`
	LedgerHeadSHA256 string   `json:"ledgerHeadSha256"`
	IssuedAt         string   `json:"issuedAt"`
}

type EvidenceFinalPayload struct {
	Schema                  string `json:"schema"`
	CandidateID             string `json:"candidateId"`
	SoakResultSHA256        string `json:"soakResultSha256"`
	SanitizedEvidenceSHA256 string `json:"sanitizedEvidenceSha256"`
	LedgerHeadSHA256        string `json:"ledgerHeadSha256"`
	IssuedAt                string `json:"issuedAt"`
}

type VerifiedStatement struct {
	StatementType string
	KeyID         string
	DigestSHA256  string
	Payload       any
}

type rootsWithoutID struct {
	SourceSHA256   string `json:"sourceSha256"`
	ProductSHA256  string `json:"productSha256"`
	HarnessSHA256  string `json:"harnessSha256"`
	WorkloadSHA256 string `json:"workloadSha256"`
	VerifierSHA256 string `json:"verifierSha256"`
}

func NewSubjectRoots(source, product, harness, workload, verifier string) (SubjectRoots, error) {
	base := rootsWithoutID{source, product, harness, workload, verifier}
	for _, value := range []string{source, product, harness, workload, verifier} {
		if !hex64Pattern.MatchString(value) {
			return SubjectRoots{}, errors.New("qualification subject root rejected")
		}
	}
	raw, err := MarshalCanonical(base)
	if err != nil {
		return SubjectRoots{}, err
	}
	digest := sha256.Sum256(raw)
	return SubjectRoots{
		SourceSHA256: source, ProductSHA256: product, HarnessSHA256: harness,
		WorkloadSHA256: workload, VerifierSHA256: verifier,
		CandidateID: hex.EncodeToString(digest[:]),
	}, nil
}

func KeyID(publicKey []byte) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", errors.New("qualification public key size rejected")
	}
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:]), nil
}

func SignStatement(privateKey []byte, statementType string, payload any) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("qualification private key size rejected")
	}
	if err := validateStatementPayload(statementType, payload); err != nil {
		return nil, err
	}
	payloadRaw, err := MarshalCanonical(payload)
	if err != nil {
		return nil, err
	}
	publicKey := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	keyID, err := KeyID(publicKey)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(ed25519.PrivateKey(privateKey), signatureMessage(statementType, payloadRaw))
	envelope := Envelope{
		Schema: EnvelopeSchema, StatementType: statementType, KeyID: keyID,
		Payload:   json.RawMessage(append([]byte(nil), payloadRaw...)),
		Signature: hex.EncodeToString(signature),
	}
	return MarshalCanonical(envelope)
}

func VerifyStatement(raw, trustedPublicKey []byte) (VerifiedStatement, error) {
	if len(trustedPublicKey) != ed25519.PublicKeySize {
		return VerifiedStatement{}, errors.New("qualification trusted public key size rejected")
	}
	var envelope Envelope
	if err := assurance.DecodeStrict(bytes.NewReader(raw), &envelope); err != nil {
		return VerifiedStatement{}, err
	}
	canonicalEnvelope, err := MarshalCanonical(envelope)
	if err != nil {
		return VerifiedStatement{}, err
	}
	if !bytes.Equal(raw, canonicalEnvelope) {
		return VerifiedStatement{}, errors.New("qualification envelope is not canonical")
	}
	if envelope.Schema != EnvelopeSchema || !validStatementType(envelope.StatementType) || !hex128Pattern.MatchString(envelope.Signature) {
		return VerifiedStatement{}, errors.New("qualification envelope identity rejected")
	}
	wantKeyID, err := KeyID(trustedPublicKey)
	if err != nil {
		return VerifiedStatement{}, err
	}
	if envelope.KeyID != wantKeyID {
		return VerifiedStatement{}, errors.New("qualification envelope is not signed by the trusted key")
	}
	signature, err := hex.DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(trustedPublicKey), signatureMessage(envelope.StatementType, envelope.Payload), signature) {
		return VerifiedStatement{}, errors.New("qualification signature rejected")
	}
	payload, err := decodeStatementPayload(envelope.StatementType, envelope.Payload)
	if err != nil {
		return VerifiedStatement{}, err
	}
	digest := sha256.Sum256(raw)
	return VerifiedStatement{
		StatementType: envelope.StatementType, KeyID: envelope.KeyID,
		DigestSHA256: hex.EncodeToString(digest[:]), Payload: payload,
	}, nil
}

func signatureMessage(statementType string, payload []byte) []byte {
	message := make([]byte, 0, len(signatureDomain)+len(statementType)+1+len(payload))
	message = append(message, signatureDomain...)
	message = append(message, statementType...)
	message = append(message, 0)
	message = append(message, payload...)
	return message
}

func validStatementType(value string) bool {
	switch value {
	case StatementRCLocked, StatementAttempt, StatementSoakReady, StatementSoakConsumed, StatementSupersede, StatementEvidenceFinal:
		return true
	default:
		return false
	}
}

func decodeStatementPayload(statementType string, raw []byte) (any, error) {
	var target any
	switch statementType {
	case StatementRCLocked:
		target = &RCLockedPayload{}
	case StatementAttempt:
		target = &AttemptPayload{}
	case StatementSoakReady:
		target = &SoakReadyPayload{}
	case StatementSoakConsumed:
		target = &SoakConsumedPayload{}
	case StatementSupersede:
		target = &SupersedePayload{}
	case StatementEvidenceFinal:
		target = &EvidenceFinalPayload{}
	default:
		return nil, errors.New("qualification statement type rejected")
	}
	if err := assurance.DecodeStrict(bytes.NewReader(raw), target); err != nil {
		return nil, err
	}
	value := reflectPayload(target)
	canonical, err := MarshalCanonical(value)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(raw, canonical) {
		return nil, errors.New("qualification payload is not canonical")
	}
	if err := validateStatementPayload(statementType, value); err != nil {
		return nil, err
	}
	return value, nil
}

func reflectPayload(pointer any) any {
	switch value := pointer.(type) {
	case *RCLockedPayload:
		return *value
	case *AttemptPayload:
		return *value
	case *SoakReadyPayload:
		return *value
	case *SoakConsumedPayload:
		return *value
	case *SupersedePayload:
		return *value
	case *EvidenceFinalPayload:
		return *value
	default:
		panic("unsupported qualification payload")
	}
}

func validateStatementPayload(statementType string, payload any) error {
	switch value := payload.(type) {
	case RCLockedPayload:
		if statementType != StatementRCLocked {
			return errors.New("qualification payload type/domain mismatch")
		}
		return ValidateRCLockedPayload(value)
	case AttemptPayload:
		if statementType != StatementAttempt {
			return errors.New("qualification payload type/domain mismatch")
		}
		return ValidateAttemptPayload(value)
	case SoakReadyPayload:
		if statementType != StatementSoakReady {
			return errors.New("qualification payload type/domain mismatch")
		}
		return ValidateSoakReadyPayload(value)
	case SoakConsumedPayload:
		if statementType != StatementSoakConsumed {
			return errors.New("qualification payload type/domain mismatch")
		}
		return ValidateSoakConsumedPayload(value)
	case SupersedePayload:
		if statementType != StatementSupersede {
			return errors.New("qualification payload type/domain mismatch")
		}
		return validateSupersedePayload(value)
	case EvidenceFinalPayload:
		if statementType != StatementEvidenceFinal {
			return errors.New("qualification payload type/domain mismatch")
		}
		return validateEvidenceFinalPayload(value)
	default:
		return errors.New("qualification payload concrete type rejected")
	}
}

func ValidateRCLockedPayload(value RCLockedPayload) error {
	if value.Schema != RCLockedSchema || !hex32Pattern.MatchString(value.AuthorizationID) || !validTimestamp(value.IssuedAt) {
		return errors.New("RC lock identity rejected")
	}
	return validateCandidateIdentity(value.Candidate)
}

func ValidateAttemptPayload(value AttemptPayload) error {
	if value.Schema != AttemptSchema || !hex64Pattern.MatchString(value.CandidateID) || value.Sequence == 0 ||
		!validPrevious(value.Sequence, value.PreviousEntrySHA256) || !hex32Pattern.MatchString(value.AttemptID) ||
		!validCampaignMode(value.Mode) || !hex64Pattern.MatchString(value.RCLockedSHA256) || !hex64Pattern.MatchString(value.AuthorizationSHA256) ||
		!hex64Pattern.MatchString(value.EnvironmentSHA256) || !hex64Pattern.MatchString(value.PreflightSHA256) || !validTimestamp(value.RecordedAt) {
		return errors.New("attempt identity rejected")
	}
	switch value.State {
	case AttemptBegin:
		if value.Outcome != "" || value.ResultSHA256 != "" {
			return errors.New("begin attempt overstated terminal evidence")
		}
	case AttemptTerminal:
		if !containsExact(exactOutcomes, value.Outcome) || !hex64Pattern.MatchString(value.ResultSHA256) {
			return errors.New("terminal attempt evidence rejected")
		}
	default:
		return errors.New("attempt state rejected")
	}
	if value.Mode != "Soak12h" && value.AuthorizationSHA256 != value.RCLockedSHA256 {
		return errors.New("non-final attempt authorization differs from RC lock")
	}
	return nil
}

func ValidateSoakReadyPayload(value SoakReadyPayload) error {
	if value.Schema != SoakReadySchema || !hex64Pattern.MatchString(value.CandidateID) ||
		!hex64Pattern.MatchString(value.RCLockedSHA256) || !hex64Pattern.MatchString(value.EvidenceIndexSHA256) ||
		!hex64Pattern.MatchString(value.PriorStressResultSHA256) ||
		!hex64Pattern.MatchString(value.LedgerHeadSHA256) || !hex32Pattern.MatchString(value.AuthorizationID) ||
		!validTimestamp(value.IssuedAt) {
		return errors.New("soak readiness payload rejected")
	}
	return nil
}

func ValidateSoakConsumedPayload(value SoakConsumedPayload) error {
	if value.Schema != SoakConsumedSchema || !hex64Pattern.MatchString(value.CandidateID) || value.Sequence == 0 ||
		!validPrevious(value.Sequence, value.PreviousEntrySHA256) || !hex64Pattern.MatchString(value.SoakReadySHA256) ||
		!hex64Pattern.MatchString(value.RCLockedSHA256) || !hex32Pattern.MatchString(value.AttemptID) || !hex64Pattern.MatchString(value.EnvironmentSHA256) ||
		!hex64Pattern.MatchString(value.PreflightSHA256) ||
		!validTimestamp(value.ConsumedAt) {
		return errors.New("soak consumption payload rejected")
	}
	return nil
}

func validateSupersedePayload(value SupersedePayload) error {
	if value.Schema != SupersedeSchema || !hex64Pattern.MatchString(value.CandidateID) || !hex64Pattern.MatchString(value.NewCandidateID) ||
		value.CandidateID == value.NewCandidateID || !safeCode(value.ReasonCode) || !hex64Pattern.MatchString(value.LedgerHeadSHA256) ||
		!validTimestamp(value.IssuedAt) || !orderedUniqueCodes(value.AffectedRoots) || !orderedUniqueCodes(value.RequiredReruns) {
		return errors.New("supersede payload rejected")
	}
	return nil
}

func validateEvidenceFinalPayload(value EvidenceFinalPayload) error {
	if value.Schema != EvidenceFinalSchema || !hex64Pattern.MatchString(value.CandidateID) ||
		!hex64Pattern.MatchString(value.SoakResultSHA256) || !hex64Pattern.MatchString(value.SanitizedEvidenceSHA256) ||
		!hex64Pattern.MatchString(value.LedgerHeadSHA256) || !validTimestamp(value.IssuedAt) {
		return errors.New("final evidence payload rejected")
	}
	return nil
}

func validateCandidateIdentity(value CandidateIdentity) error {
	if !repositoryPatternV1.MatchString(value.Repository) || !hex40Pattern.MatchString(value.CommitSHA) ||
		!hex40Pattern.MatchString(value.TreeSHA) || !hex64Pattern.MatchString(value.ComparisonSHA256) {
		return errors.New("candidate source identity rejected")
	}
	want, err := NewSubjectRoots(value.Roots.SourceSHA256, value.Roots.ProductSHA256, value.Roots.HarnessSHA256, value.Roots.WorkloadSHA256, value.Roots.VerifierSHA256)
	if err != nil || value.Roots != want {
		return errors.New("candidate subject roots rejected")
	}
	return nil
}

func validPrevious(sequence uint64, previous string) bool {
	if sequence == 1 {
		return previous == ""
	}
	return hex64Pattern.MatchString(previous)
}

func validTimestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.Location() == time.UTC && parsed.Format(time.RFC3339) == value
}

func validCampaignMode(value string) bool {
	for _, campaign := range exactCampaigns {
		if campaign.Mode == value {
			return true
		}
	}
	return false
}

func containsExact(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func safeCode(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if char != '_' && char != '-' && (char < 'A' || char > 'Z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func orderedUniqueCodes(values []string) bool {
	if len(values) == 0 || len(values) > 16 {
		return false
	}
	last := ""
	for _, value := range values {
		if !safeCode(value) || strings.Compare(value, last) <= 0 {
			return false
		}
		last = value
	}
	return true
}
