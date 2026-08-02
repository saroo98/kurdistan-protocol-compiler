// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package assurance

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const ReceiptSchema = "kurdistan-assurance-receipt-v1"

var (
	gitObjectPattern  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	receiptIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	jobIDPattern      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,99}$`)
	repositoryPattern = regexp.MustCompile(
		`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`,
	)
	decimalIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
)

type Receipt struct {
	Schema      string            `json:"schema"`
	ReceiptID   string            `json:"receiptId"`
	Subject     Subject           `json:"subject"`
	Workflow    WorkflowIdentity  `json:"workflow"`
	Execution   ExecutionIdentity `json:"execution"`
	Proof       ProofIdentity     `json:"proof"`
	Inventories []NamedDigest     `json:"inventories"`
	Toolchain   []ToolIdentity    `json:"toolchain"`
	Runner      RunnerIdentity    `json:"runner"`
	Commands    [][]string        `json:"commands"`
	Timing      Timing            `json:"timing"`
	CachePolicy string            `json:"cachePolicy"`
	Result      string            `json:"result"`
	Terminal    bool              `json:"terminal"`
	Artifacts   []Artifact        `json:"artifacts"`
	Limitations []string          `json:"limitations"`
	ExpiresAt   string            `json:"expiresAt,omitempty"`
}

type Subject struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Tree       string `json:"tree"`
	Ref        string `json:"ref"`
}

type WorkflowIdentity struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type ExecutionIdentity struct {
	RunID   string `json:"runId"`
	JobID   string `json:"jobId"`
	Attempt int    `json:"attempt"`
	Trigger string `json:"trigger"`
}

type ProofIdentity struct {
	ID           string `json:"id"`
	PolicySHA256 string `json:"policySha256"`
}

type NamedDigest struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type ToolIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type RunnerIdentity struct {
	OperatingSystem string `json:"operatingSystem"`
	Architecture    string `json:"architecture"`
	RequestedLabel  string `json:"requestedLabel"`
	Image           string `json:"image"`
	ImageVersion    string `json:"imageVersion"`
}

type Timing struct {
	StartedAt      string `json:"startedAt"`
	CompletedAt    string `json:"completedAt"`
	DurationMillis int64  `json:"durationMillis"`
}

type Artifact struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func DecodeReceipt(reader io.Reader) (Receipt, error) {
	var value Receipt
	if err := decodeStrict(reader, &value); err != nil {
		return Receipt{}, fmt.Errorf("decode assurance receipt: %w", err)
	}
	if err := value.Validate(); err != nil {
		return Receipt{}, err
	}
	return value, nil
}

func (value Receipt) Validate() error {
	if value.Schema != ReceiptSchema || !receiptIDPattern.MatchString(value.ReceiptID) || !identifierPattern.MatchString(value.Proof.ID) {
		return errors.New("invalid assurance receipt identity")
	}
	if !repositoryPattern.MatchString(value.Subject.Repository) || !gitObjectPattern.MatchString(value.Subject.Commit) || !gitObjectPattern.MatchString(value.Subject.Tree) || !validRef(value.Subject.Ref) {
		return errors.New("invalid assurance receipt subject")
	}
	if !validWorkflowPath(value.Workflow.Path) || !sha256Pattern.MatchString(value.Workflow.SHA256) {
		return errors.New("invalid assurance receipt workflow identity")
	}
	if !decimalIDPattern.MatchString(value.Execution.RunID) || !jobIDPattern.MatchString(value.Execution.JobID) || value.Execution.Attempt < 1 || value.Execution.Attempt > 100 || !allowedTrigger(value.Execution.Trigger) {
		return errors.New("invalid assurance receipt execution identity")
	}
	if !sha256Pattern.MatchString(value.Proof.PolicySHA256) {
		return errors.New("invalid assurance receipt proof policy digest")
	}
	if err := validateNamedDigests("inventory", value.Inventories, 256); err != nil {
		return err
	}
	if err := validateToolchain(value.Toolchain); err != nil {
		return err
	}
	if err := validateRunner(value.Runner); err != nil {
		return err
	}
	if err := validateCommands(value.Commands); err != nil {
		return err
	}
	started, err := parseCanonicalUTC("startedAt", value.Timing.StartedAt)
	if err != nil {
		return err
	}
	completed, err := parseCanonicalUTC("completedAt", value.Timing.CompletedAt)
	if err != nil {
		return err
	}
	if completed.Before(started) || value.Timing.DurationMillis < 0 || completed.Sub(started).Milliseconds() != value.Timing.DurationMillis {
		return errors.New("assurance receipt timing is inconsistent")
	}
	if value.CachePolicy != CacheIndependent && value.CachePolicy != CacheAllowed {
		return errors.New("invalid assurance receipt cache policy")
	}
	if value.Result != "PASS" && value.Result != "FAIL" {
		return errors.New("invalid assurance receipt result")
	}
	if !value.Terminal {
		return errors.New("assurance receipt must be explicitly terminal")
	}
	if err := validateArtifacts(value.Artifacts); err != nil {
		return err
	}
	if err := validateBoundedStrings("limitation", value.Limitations, 32, 512); err != nil {
		return err
	}
	if value.ExpiresAt != "" {
		expires, err := parseCanonicalUTC("expiresAt", value.ExpiresAt)
		if err != nil {
			return err
		}
		if !expires.After(completed) {
			return errors.New("assurance receipt expiry must follow completion")
		}
	}
	return nil
}

func ValidateReceipt(value Receipt, policy ProofPolicy, policySHA256 string, now time.Time) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("invalid proof policy: %w", err)
	}
	if !sha256Pattern.MatchString(policySHA256) || value.Proof.PolicySHA256 != policySHA256 {
		return errors.New("assurance receipt proof policy digest mismatch")
	}
	var selected *Proof
	for index := range policy.Proofs {
		if policy.Proofs[index].ID == value.Proof.ID {
			selected = &policy.Proofs[index]
			break
		}
	}
	if selected == nil {
		return fmt.Errorf("assurance receipt proof %q is not authorized by policy", value.Proof.ID)
	}
	commands, err := selected.CommandsForOperatingSystem(value.Runner.OperatingSystem)
	if err != nil {
		return err
	}
	if !commandsEqual(value.Commands, commands) {
		return errors.New("assurance receipt command inventory mismatch")
	}
	if value.CachePolicy != selected.CachePolicy || !containsString(selected.OperatingSystems, value.Runner.OperatingSystem) {
		return errors.New("assurance receipt execution policy mismatch")
	}
	completed, _ := parseCanonicalUTC("completedAt", value.Timing.CompletedAt)
	if now.IsZero() || completed.After(now) {
		return errors.New("assurance receipt completion is in the future")
	}
	if selected.Deterministic {
		if value.ExpiresAt != "" {
			return errors.New("deterministic assurance receipt must not have a wall-clock expiry")
		}
		return nil
	}
	if value.ExpiresAt == "" {
		return errors.New("freshness-limited assurance receipt is missing expiry")
	}
	expires, _ := parseCanonicalUTC("expiresAt", value.ExpiresAt)
	wantExpiry := completed.Add(time.Duration(selected.FreshnessSeconds) * time.Second)
	if !expires.Equal(wantExpiry) {
		return errors.New("assurance receipt expiry does not match proof policy")
	}
	if !now.Before(expires) {
		return errors.New("assurance receipt has expired")
	}
	return nil
}

func commandsEqual(left, right [][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if len(left[index]) != len(right[index]) {
			return false
		}
		for argument := range left[index] {
			if left[index][argument] != right[index][argument] {
				return false
			}
		}
	}
	return true
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func validRef(value string) bool {
	return strings.HasPrefix(value, "refs/") && len(value) <= 256 && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\\\x00 \t\r\n") && !strings.Contains(value, "..")
}

func validWorkflowPath(value string) bool {
	if !validRelativePath(value) || !strings.HasPrefix(value, ".github/workflows/") {
		return false
	}
	return strings.HasSuffix(value, ".yml") || strings.HasSuffix(value, ".yaml")
}

func allowedTrigger(value string) bool {
	switch value {
	case "push", "pull_request", "workflow_dispatch", "schedule", "workflow_call":
		return true
	default:
		return false
	}
}

func validateNamedDigests(name string, values []NamedDigest, maximum int) error {
	if len(values) == 0 || len(values) > maximum {
		return fmt.Errorf("%s set has invalid cardinality", name)
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !identifierPattern.MatchString(value.Name) || !sha256Pattern.MatchString(value.SHA256) || seen[value.Name] {
			return fmt.Errorf("%s set contains invalid or duplicate identity %q", name, value.Name)
		}
		seen[value.Name] = true
	}
	return nil
}

func validateToolchain(values []ToolIdentity) error {
	if len(values) == 0 || len(values) > 64 {
		return errors.New("toolchain set has invalid cardinality")
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !identifierPattern.MatchString(value.Name) || seen[value.Name] || value.Version == "" || value.Version != strings.TrimSpace(value.Version) || len(value.Version) > 128 || !sha256Pattern.MatchString(value.SHA256) {
			return fmt.Errorf("toolchain contains invalid or duplicate identity %q", value.Name)
		}
		seen[value.Name] = true
	}
	return nil
}

func validateRunner(value RunnerIdentity) error {
	for name, field := range map[string]string{
		"operating system": value.OperatingSystem,
		"architecture":     value.Architecture,
		"requested label":  value.RequestedLabel,
		"image":            value.Image,
		"image version":    value.ImageVersion,
	} {
		if field == "" || field != strings.TrimSpace(field) || len(field) > 128 || strings.ContainsRune(field, '\x00') {
			return fmt.Errorf("runner %s is invalid", name)
		}
	}
	return nil
}

func validateCommands(commands [][]string) error {
	if len(commands) == 0 || len(commands) > 16 {
		return errors.New("command set has invalid cardinality")
	}
	for _, command := range commands {
		if len(command) == 0 || len(command) > 32 {
			return errors.New("command has invalid argument count")
		}
		for _, argument := range command {
			if argument == "" || len(argument) > 2048 || strings.ContainsRune(argument, '\x00') {
				return errors.New("command contains an invalid argument")
			}
		}
	}
	return nil
}

func validateArtifacts(values []Artifact) error {
	if len(values) > 256 {
		return errors.New("artifact set has invalid cardinality")
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !validRelativePath(value.Path) || seen[value.Path] || value.Size < 0 || value.Size > 1<<50 || !sha256Pattern.MatchString(value.SHA256) {
			return fmt.Errorf("artifact contains invalid or duplicate path %q", value.Path)
		}
		seen[value.Path] = true
	}
	return nil
}

func validRelativePath(value string) bool {
	if value == "" || len(value) > 512 || strings.Contains(value, "\\") || strings.ContainsRune(value, '\x00') || filepath.IsAbs(value) || filepath.VolumeName(value) != "" {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(value)))
	return clean == value && clean != "." && !strings.HasPrefix(clean, "../")
}

func parseCanonicalUTC(name, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || !strings.HasSuffix(value, "Z") || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, fmt.Errorf("%s is not canonical UTC RFC3339", name)
	}
	return parsed, nil
}

func validateBoundedStrings(name string, values []string, maximum, maxLength int) error {
	if len(values) > maximum {
		return fmt.Errorf("%s set has invalid cardinality", name)
	}
	seen := map[string]bool{}
	for _, value := range values {
		if value == "" || value != strings.TrimSpace(value) || len(value) > maxLength || strings.ContainsRune(value, '\x00') || seen[value] {
			return fmt.Errorf("%s set contains invalid or duplicate value", name)
		}
		seen[value] = true
	}
	return nil
}
