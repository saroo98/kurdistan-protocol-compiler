// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command releasepolicy evaluates an exact, offline release evidence set. It
// has no credentials, network client, signing authority, or publication path.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const maxReleasePolicyBytes = 4 << 20

var (
	sha256Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	gitPattern        = regexp.MustCompile(`^[0-9a-f]{40}$`)
	idPattern         = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
	errNoGo           = errors.New("release decision is NO_GO")
)

type releasePolicy struct {
	Schema           string                `json:"schema"`
	PolicyID         string                `json:"policyId"`
	Subject          releaseSubject        `json:"subject"`
	RequiredEvidence []evidenceRequirement `json:"requiredEvidence"`
}

type releaseSubject struct {
	Repository     string `json:"repository"`
	Commit         string `json:"commit"`
	Tree           string `json:"tree"`
	Ref            string `json:"ref"`
	ArtifactSHA256 string `json:"artifactSha256"`
	MetadataSHA256 string `json:"metadataSha256"`
	RollbackSHA256 string `json:"rollbackSha256"`
}

type evidenceRequirement struct {
	ID            string `json:"id"`
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	MaxAgeSeconds int64  `json:"maxAgeSeconds"`
}

type evidenceRecord struct {
	Schema      string         `json:"schema"`
	EvidenceID  string         `json:"evidenceId"`
	Subject     releaseSubject `json:"subject"`
	ObservedAt  string         `json:"observedAt"`
	ExpiresAt   string         `json:"expiresAt,omitempty"`
	Status      string         `json:"status"`
	Terminal    bool           `json:"terminal"`
	Limitations []string       `json:"limitations"`
}

type evaluation struct {
	Schema       string              `json:"schema"`
	PolicyID     string              `json:"policyId"`
	PolicySHA256 string              `json:"policySha256"`
	Subject      releaseSubject      `json:"subject"`
	Decision     string              `json:"decision"`
	EvaluatedAt  string              `json:"evaluatedAt"`
	Evidence     []evaluatedEvidence `json:"evidence"`
	Reasons      []string            `json:"reasons"`
}

type evaluatedEvidence struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
	Status string `json:"status"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "releasepolicy:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("releasepolicy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "offline evidence root")
	policyPath := flags.String("policy", "", "release policy path under root")
	expectedPolicyDigest := flags.String("policy-sha256", "", "expected exact policy SHA-256")
	nowText := flags.String("now", "", "evaluation time in canonical UTC RFC3339")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *policyPath == "" || !sha256Pattern.MatchString(*expectedPolicyDigest) || *nowText == "" {
		return errors.New("-policy, -policy-sha256, and -now are required")
	}
	now, err := parseCanonicalTime(*nowText)
	if err != nil {
		return fmt.Errorf("invalid -now: %w", err)
	}
	policyRaw, err := readBoundedRootFile(*root, *policyPath)
	if err != nil {
		return fmt.Errorf("read release policy: %w", err)
	}
	var policy releasePolicy
	if err := decodeStrictDocument(policyRaw, &policy); err != nil {
		return fmt.Errorf("decode release policy: %w", err)
	}
	if err := policy.validate(); err != nil {
		return fmt.Errorf("invalid release policy: %w", err)
	}
	actualPolicyDigest := fmt.Sprintf("%x", sha256.Sum256(policyRaw))
	result := evaluation{
		Schema: "kurdistan-release-evaluation-v1", PolicyID: policy.PolicyID,
		PolicySHA256: actualPolicyDigest, Subject: policy.Subject,
		Decision: "GO", EvaluatedAt: now.Format(time.RFC3339Nano),
		Evidence: []evaluatedEvidence{}, Reasons: []string{},
	}
	if actualPolicyDigest != *expectedPolicyDigest {
		result.Reasons = append(result.Reasons, "release policy digest mismatch")
	}
	for _, requirement := range policy.RequiredEvidence {
		evaluated, reason := evaluateEvidence(*root, policy.Subject, requirement, now)
		result.Evidence = append(result.Evidence, evaluated)
		if reason != "" {
			result.Reasons = append(result.Reasons, reason)
		}
	}
	if len(result.Reasons) != 0 {
		result.Decision = "NO_GO"
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return err
	}
	if result.Decision != "GO" {
		return errNoGo
	}
	return nil
}

func (policy releasePolicy) validate() error {
	if policy.Schema != "kurdistan-release-policy-v1" || !idPattern.MatchString(policy.PolicyID) || !policy.Subject.valid() || len(policy.RequiredEvidence) == 0 || len(policy.RequiredEvidence) > 128 {
		return errors.New("invalid policy identity, subject, or evidence cardinality")
	}
	lastID := ""
	paths := map[string]bool{}
	digests := map[string]bool{}
	for _, requirement := range policy.RequiredEvidence {
		if !idPattern.MatchString(requirement.ID) || requirement.ID <= lastID || !safeRelativePath(requirement.Path) || !sha256Pattern.MatchString(requirement.SHA256) || requirement.MaxAgeSeconds < 0 || requirement.MaxAgeSeconds > 31*24*60*60 || paths[requirement.Path] || digests[requirement.SHA256] {
			return fmt.Errorf("invalid, duplicate, or unordered evidence requirement %q", requirement.ID)
		}
		lastID = requirement.ID
		paths[requirement.Path] = true
		digests[requirement.SHA256] = true
	}
	return nil
}

func (subject releaseSubject) valid() bool {
	return repositoryPattern.MatchString(subject.Repository) && gitPattern.MatchString(subject.Commit) && gitPattern.MatchString(subject.Tree) && strings.HasPrefix(subject.Ref, "refs/") && len(subject.Ref) <= 256 && !strings.ContainsAny(subject.Ref, "\\\x00 \t\r\n") && !strings.Contains(subject.Ref, "..") && sha256Pattern.MatchString(subject.ArtifactSHA256) && sha256Pattern.MatchString(subject.MetadataSHA256) && sha256Pattern.MatchString(subject.RollbackSHA256)
}

func evaluateEvidence(root string, subject releaseSubject, requirement evidenceRequirement, now time.Time) (evaluatedEvidence, string) {
	result := evaluatedEvidence{ID: requirement.ID, SHA256: requirement.SHA256, Status: "FAIL"}
	raw, err := readBoundedRootFile(root, requirement.Path)
	if err != nil {
		return result, fmt.Sprintf("required evidence %s is unavailable", requirement.ID)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	result.SHA256 = digest
	if digest != requirement.SHA256 {
		return result, fmt.Sprintf("required evidence %s digest mismatch", requirement.ID)
	}
	var record evidenceRecord
	if err := decodeStrictDocument(raw, &record); err != nil {
		return result, fmt.Sprintf("required evidence %s is malformed", requirement.ID)
	}
	if record.Schema != "kurdistan-release-evidence-v1" || record.EvidenceID != requirement.ID || !record.Subject.valid() || record.Subject != subject || record.Status != "PASS" || !record.Terminal || record.Limitations == nil || len(record.Limitations) != 0 {
		return result, fmt.Sprintf("required evidence %s identity, subject, or terminal status mismatch", requirement.ID)
	}
	observed, err := parseCanonicalTime(record.ObservedAt)
	if err != nil || observed.After(now) {
		return result, fmt.Sprintf("required evidence %s has invalid observation time", requirement.ID)
	}
	if requirement.MaxAgeSeconds == 0 {
		if record.ExpiresAt != "" {
			return result, fmt.Sprintf("deterministic evidence %s must not expire by wall clock", requirement.ID)
		}
	} else {
		expires, err := parseCanonicalTime(record.ExpiresAt)
		if err != nil || !expires.Equal(observed.Add(time.Duration(requirement.MaxAgeSeconds)*time.Second)) || !now.Before(expires) {
			return result, fmt.Sprintf("required evidence %s is stale or has invalid expiry", requirement.ID)
		}
	}
	result.Status = "PASS"
	return result, ""
}

func decodeStrictDocument(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > maxReleasePolicyBytes {
		return errors.New("JSON document has invalid size")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if seen[key] {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = true
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object terminator")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array terminator")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func readBoundedRootFile(root, relative string) ([]byte, error) {
	if !safeRelativePath(relative) {
		return nil, fmt.Errorf("unsafe path %q", relative)
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	resolvedRoot, err := filepath.EvalSymlinks(absoluteRoot)
	if err != nil {
		return nil, err
	}
	candidate := filepath.Join(resolvedRoot, filepath.FromSlash(relative))
	info, err := os.Lstat(candidate)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("path is not a regular non-symlink file")
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(resolvedRoot, resolvedCandidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, errors.New("path escapes root")
	}
	file, err := os.Open(resolvedCandidate)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxReleasePolicyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxReleasePolicyBytes {
		return nil, errors.New("file exceeds size bound")
	}
	return raw, nil
}

func safeRelativePath(value string) bool {
	if value == "" || len(value) > 512 || strings.Contains(value, "\\") || strings.ContainsRune(value, '\x00') || filepath.IsAbs(value) || filepath.VolumeName(value) != "" {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(value)))
	return clean == value && clean != "." && !strings.HasPrefix(clean, "../")
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || !strings.HasSuffix(value, "Z") || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("timestamp is not canonical UTC RFC3339")
	}
	return parsed, nil
}
