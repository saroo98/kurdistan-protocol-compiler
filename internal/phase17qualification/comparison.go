// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"errors"
	"io"

	"kurdistan/internal/assurance"
)

const CandidateComparisonSchema = "kurdistan-phase17-candidate-comparison-v1"

type CandidateComparison struct {
	Schema    string          `json:"schema"`
	CommitSHA string          `json:"commitSha"`
	TreeSHA   string          `json:"treeSha"`
	Result    string          `json:"result"`
	Entries   []ManifestEntry `json:"entries"`
}

func BuildCandidateComparison(commitSHA, treeSHA, leftRoot, rightRoot string) (CandidateComparison, error) {
	if !hex40Pattern.MatchString(commitSHA) || !hex40Pattern.MatchString(treeSHA) {
		return CandidateComparison{}, errors.New("qualification comparison source identity rejected")
	}
	left, err := BuildSubjectManifestTree("PQS", leftRoot)
	if err != nil {
		return CandidateComparison{}, err
	}
	right, err := BuildSubjectManifestTree("PQS", rightRoot)
	if err != nil {
		return CandidateComparison{}, err
	}
	if !equalComparisonEntries(left.Entries, right.Entries) {
		return CandidateComparison{}, errors.New("qualification candidate roots are not byte-identical")
	}
	return CandidateComparison{
		Schema: CandidateComparisonSchema, CommitSHA: commitSHA, TreeSHA: treeSHA,
		Result: "PASS", Entries: append([]ManifestEntry(nil), left.Entries...),
	}, nil
}

func MarshalCandidateComparison(value CandidateComparison) ([]byte, error) {
	if err := validateCandidateComparison(value); err != nil {
		return nil, err
	}
	return MarshalCanonical(value)
}

func DecodeCandidateComparison(reader io.Reader) (CandidateComparison, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, (4<<20)+1))
	if err != nil || len(raw) == 0 || len(raw) > 4<<20 {
		return CandidateComparison{}, errors.New("qualification candidate comparison input rejected")
	}
	var value CandidateComparison
	if err := assurance.DecodeStrict(bytes.NewReader(raw), &value); err != nil {
		return CandidateComparison{}, err
	}
	if err := validateCandidateComparison(value); err != nil {
		return CandidateComparison{}, err
	}
	canonical, err := MarshalCandidateComparison(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return CandidateComparison{}, errors.New("qualification candidate comparison is not canonical")
	}
	return value, nil
}

func validateCandidateComparison(value CandidateComparison) error {
	if value.Schema != CandidateComparisonSchema || !hex40Pattern.MatchString(value.CommitSHA) ||
		!hex40Pattern.MatchString(value.TreeSHA) || value.Result != "PASS" {
		return errors.New("qualification candidate comparison rejected")
	}
	return validateSourceInventoryEntries(value.Entries)
}

func equalComparisonEntries(left, right []ManifestEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
