// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"kurdistan/internal/assurance"
)

const (
	ReadinessEvidenceIndexSchema = "kurdistan-phase17-readiness-evidence-index-v1"
	ReadinessProofSchema         = "kurdistan-phase17-readiness-proof-v1"
)

var exactReadinessEvidenceKinds = []string{
	"SOURCE_GATES",
	"REPRODUCIBILITY",
	"FUNCTIONAL",
	"DETERMINISTIC_GAUNTLET",
	"STRESS",
	"SOAK_60M",
	"SOAK_90M",
	"SOAK_120M",
	"PHYSICAL_API26",
	"PHYSICAL_CURRENT",
	"SECOND_PROVIDER",
	"PRIVACY_SCANNERS",
	"BOUNDARY_MONITOR",
}

type ReadinessEvidenceEntry struct {
	Kind           string `json:"kind"`
	Path           string `json:"path"`
	Size           uint64 `json:"size"`
	EvidenceSHA256 string `json:"evidenceSha256"`
	Result         string `json:"result"`
	RawLogRetained bool   `json:"rawLogRetained"`
}

type ReadinessEvidenceIndex struct {
	Schema           string                   `json:"schema"`
	CandidateID      string                   `json:"candidateId"`
	Roots            SubjectRoots             `json:"roots"`
	RCLockedSHA256   string                   `json:"rcLockedSha256"`
	LedgerHeadSHA256 string                   `json:"ledgerHeadSha256"`
	Entries          []ReadinessEvidenceEntry `json:"entries"`
}

type ReadinessProof struct {
	Schema         string       `json:"schema"`
	Kind           string       `json:"kind"`
	CandidateID    string       `json:"candidateId"`
	Roots          SubjectRoots `json:"roots"`
	Result         string       `json:"result"`
	RawLogRetained bool         `json:"rawLogRetained"`
}

type ReadinessEvidenceVerifier func(kind string, raw []byte, candidate CandidateIdentity) error

func ReadinessEvidenceKinds() []string {
	return append([]string(nil), exactReadinessEvidenceKinds...)
}

func MarshalReadinessProof(value ReadinessProof) ([]byte, error) {
	if err := ValidateReadinessProof(value); err != nil {
		return nil, err
	}
	return MarshalCanonical(value)
}

func DecodeReadinessProof(reader io.Reader) (ReadinessProof, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, (64<<10)+1))
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
		return ReadinessProof{}, errors.New("qualification readiness proof input rejected")
	}
	var value ReadinessProof
	if err := assurance.DecodeStrict(bytes.NewReader(raw), &value); err != nil {
		return ReadinessProof{}, err
	}
	if err := ValidateReadinessProof(value); err != nil {
		return ReadinessProof{}, err
	}
	canonical, err := MarshalCanonical(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ReadinessProof{}, errors.New("qualification readiness proof is not canonical")
	}
	return value, nil
}

func ValidateReadinessProof(value ReadinessProof) error {
	if value.Schema != ReadinessProofSchema || !containsExact(exactReadinessEvidenceKinds, value.Kind) ||
		!hex64Pattern.MatchString(value.CandidateID) || value.Result != "PASS" || value.RawLogRetained {
		return errors.New("qualification readiness proof rejected")
	}
	want, err := NewSubjectRoots(
		value.Roots.SourceSHA256, value.Roots.ProductSHA256, value.Roots.HarnessSHA256,
		value.Roots.WorkloadSHA256, value.Roots.VerifierSHA256,
	)
	if err != nil || value.Roots != want || value.CandidateID != value.Roots.CandidateID {
		return errors.New("qualification readiness proof roots rejected")
	}
	return nil
}

func MarshalReadinessEvidenceIndex(value ReadinessEvidenceIndex) ([]byte, error) {
	if err := ValidateReadinessEvidenceIndex(value); err != nil {
		return nil, err
	}
	return MarshalCanonical(value)
}

func DecodeReadinessEvidenceIndex(reader io.Reader) (ReadinessEvidenceIndex, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, 1<<20+1))
	if err != nil {
		return ReadinessEvidenceIndex{}, err
	}
	if len(raw) > 1<<20 {
		return ReadinessEvidenceIndex{}, errors.New("qualification readiness index exceeds limit")
	}
	var value ReadinessEvidenceIndex
	if err := assurance.DecodeStrict(bytes.NewReader(raw), &value); err != nil {
		return ReadinessEvidenceIndex{}, err
	}
	if err := ValidateReadinessEvidenceIndex(value); err != nil {
		return ReadinessEvidenceIndex{}, err
	}
	canonical, err := MarshalCanonical(value)
	if err != nil {
		return ReadinessEvidenceIndex{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return ReadinessEvidenceIndex{}, errors.New("qualification readiness index is not canonical")
	}
	return value, nil
}

func ValidateReadinessEvidenceIndex(value ReadinessEvidenceIndex) error {
	if value.Schema != ReadinessEvidenceIndexSchema || !hex64Pattern.MatchString(value.CandidateID) ||
		!hex64Pattern.MatchString(value.RCLockedSHA256) || !hex64Pattern.MatchString(value.LedgerHeadSHA256) ||
		len(value.Entries) != len(exactReadinessEvidenceKinds) {
		return errors.New("qualification readiness index identity rejected")
	}
	wantRoots, err := NewSubjectRoots(
		value.Roots.SourceSHA256, value.Roots.ProductSHA256, value.Roots.HarnessSHA256,
		value.Roots.WorkloadSHA256, value.Roots.VerifierSHA256,
	)
	if err != nil || value.Roots != wantRoots || value.CandidateID != value.Roots.CandidateID {
		return errors.New("qualification readiness subject roots rejected")
	}
	seenDigests := make(map[string]struct{}, len(value.Entries))
	seenPaths := make(map[string]struct{}, len(value.Entries))
	for index, entry := range value.Entries {
		if entry.Kind != exactReadinessEvidenceKinds[index] || !hex64Pattern.MatchString(entry.EvidenceSHA256) ||
			!safeReadinessPath(entry.Path) || entry.Size == 0 || entry.Size > 64<<20 || entry.Result != "PASS" || entry.RawLogRetained {
			return errors.New("qualification readiness evidence entry rejected")
		}
		if _, duplicate := seenDigests[entry.EvidenceSHA256]; duplicate {
			return errors.New("qualification readiness evidence digest repeated")
		}
		seenDigests[entry.EvidenceSHA256] = struct{}{}
		foldedPath := strings.ToLower(entry.Path)
		if _, duplicate := seenPaths[foldedPath]; duplicate {
			return errors.New("qualification readiness evidence path repeated")
		}
		seenPaths[foldedPath] = struct{}{}
	}
	return nil
}

func BuildSoakReadyPayload(
	candidate CandidateIdentity, rcLockedRaw, evidenceIndexRaw []byte,
	evidenceRoot string, ledger LedgerState, trustedPublicKey []byte, verifier ReadinessEvidenceVerifier,
	authorizationID, issuedAt string,
) (SoakReadyPayload, error) {
	if err := validateCandidateIdentity(candidate); err != nil {
		return SoakReadyPayload{}, err
	}
	rcLocked, err := VerifyStatement(rcLockedRaw, trustedPublicKey)
	if err != nil {
		return SoakReadyPayload{}, err
	}
	if rcLocked.StatementType != StatementRCLocked {
		return SoakReadyPayload{}, errors.New("qualification readiness RC lock type rejected")
	}
	rcPayload := rcLocked.Payload.(RCLockedPayload)
	if rcPayload.Candidate != candidate {
		return SoakReadyPayload{}, errors.New("qualification readiness candidate differs from RC lock")
	}
	index, err := DecodeReadinessEvidenceIndex(bytes.NewReader(evidenceIndexRaw))
	if err != nil {
		return SoakReadyPayload{}, err
	}
	if index.CandidateID != candidate.Roots.CandidateID || index.Roots != candidate.Roots || index.RCLockedSHA256 != rcLocked.DigestSHA256 {
		return SoakReadyPayload{}, errors.New("qualification readiness evidence does not bind the RC candidate")
	}
	if ledger.CandidateID != candidate.Roots.CandidateID || ledger.Entries == 0 || ledger.HeadSHA256 != index.LedgerHeadSHA256 {
		return SoakReadyPayload{}, errors.New("qualification readiness ledger state is stale")
	}
	if err := VerifyReadinessEvidenceFiles(evidenceRoot, index, candidate, verifier); err != nil {
		return SoakReadyPayload{}, err
	}
	priorStressDigest := ""
	for _, entry := range index.Entries {
		if entry.Kind == "STRESS" {
			priorStressDigest = entry.EvidenceSHA256
			break
		}
	}
	if !hex64Pattern.MatchString(priorStressDigest) {
		return SoakReadyPayload{}, errors.New("qualification readiness prior Stress evidence unavailable")
	}
	indexDigest := sha256.Sum256(evidenceIndexRaw)
	result := SoakReadyPayload{
		Schema: SoakReadySchema, CandidateID: candidate.Roots.CandidateID,
		RCLockedSHA256: rcLocked.DigestSHA256, EvidenceIndexSHA256: hex.EncodeToString(indexDigest[:]),
		PriorStressResultSHA256: priorStressDigest, LedgerHeadSHA256: index.LedgerHeadSHA256,
		AuthorizationID: authorizationID, IssuedAt: issuedAt,
	}
	if err := ValidateSoakReadyPayload(result); err != nil {
		return SoakReadyPayload{}, err
	}
	return result, nil
}

func VerifyReadinessEvidenceFiles(root string, index ReadinessEvidenceIndex, candidate CandidateIdentity, verifier ReadinessEvidenceVerifier) error {
	if verifier == nil {
		return errors.New("qualification readiness evidence verifier required")
	}
	if err := ValidateReadinessEvidenceIndex(index); err != nil {
		return err
	}
	if err := validateCandidateIdentity(candidate); err != nil || index.CandidateID != candidate.Roots.CandidateID || index.Roots != candidate.Roots {
		return errors.New("qualification readiness evidence candidate rejected")
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	resolvedRoot, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return err
	}
	if !samePath(rootAbs, resolvedRoot) {
		return errors.New("qualification readiness evidence root contains a symbolic link")
	}
	for _, entry := range index.Entries {
		path := filepath.Join(rootAbs, filepath.FromSlash(entry.Path))
		pathAbs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(rootAbs, pathAbs)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("qualification readiness evidence path escapes root")
		}
		before, err := os.Lstat(pathAbs)
		if err != nil {
			return err
		}
		if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || uint64(before.Size()) != entry.Size {
			return errors.New("qualification readiness evidence file rejected")
		}
		file, err := os.Open(pathAbs)
		if err != nil {
			return err
		}
		opened, err := file.Stat()
		if err != nil || !os.SameFile(before, opened) {
			_ = file.Close()
			return errors.New("qualification readiness evidence changed while opening")
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, int64(entry.Size)+1))
		after, statErr := file.Stat()
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if statErr != nil {
			return statErr
		}
		if closeErr != nil {
			return closeErr
		}
		if uint64(len(raw)) != entry.Size || !os.SameFile(opened, after) || opened.Size() != after.Size() || opened.ModTime() != after.ModTime() {
			return errors.New("qualification readiness evidence changed while hashing")
		}
		digest := sha256.Sum256(raw)
		if hex.EncodeToString(digest[:]) != entry.EvidenceSHA256 {
			return errors.New("qualification readiness evidence digest rejected")
		}
		if err := verifier(entry.Kind, raw, candidate); err != nil {
			return errors.New("qualification readiness evidence content rejected")
		}
	}
	return nil
}

func safeReadinessPath(value string) bool {
	if value == "" || len(value) > 512 || filepath.IsAbs(value) || strings.Contains(value, "\\") ||
		filepath.ToSlash(filepath.Clean(filepath.FromSlash(value))) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return false
	}
	return true
}
