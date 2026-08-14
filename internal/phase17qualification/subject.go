// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"kurdistan/internal/assurance"
)

const (
	SubjectManifestSchema     = "kurdistan-phase17-subject-manifest-v1"
	CandidateManifestSchema   = "kurdistan-phase17-candidate-manifest-v1"
	EnvironmentSchema         = "kurdistan-phase17-environment-context-v1"
	sourceChangedPathsSchema  = "kurdistan-phase17-source-changed-paths-v1"
	sourceFileInventorySchema = "kurdistan-phase17-source-file-inventory-v1"
)

var exactArtifactSubjectOrder = []string{"PQS", "QHS", "QWS", "OVS"}

type ManifestEntry struct {
	Path   string `json:"path"`
	Size   uint64 `json:"size"`
	SHA256 string `json:"sha256"`
}

type SubjectManifest struct {
	Schema     string          `json:"schema"`
	Name       string          `json:"name"`
	RootSHA256 string          `json:"rootSha256"`
	Entries    []ManifestEntry `json:"entries"`
}

type subjectRootInput struct {
	Schema  string          `json:"schema"`
	Name    string          `json:"name"`
	Entries []ManifestEntry `json:"entries"`
}

type SourceProvenance struct {
	Repository                  string `json:"repository"`
	BaselineCommitSHA           string `json:"baselineCommitSha"`
	CommitSHA                   string `json:"commitSha"`
	TreeSHA                     string `json:"treeSha"`
	ChangedPathsSHA256          string `json:"changedPathsSha256"`
	ToolchainDeclarationsSHA256 string `json:"toolchainDeclarationsSha256"`
	DependencyLocksSHA256       string `json:"dependencyLocksSha256"`
}

type sourceChangedPathsInput struct {
	Schema string   `json:"schema"`
	Paths  []string `json:"paths"`
}

type sourceFileInventoryInput struct {
	Schema  string          `json:"schema"`
	Kind    string          `json:"kind"`
	Entries []ManifestEntry `json:"entries"`
}

type CandidateManifest struct {
	Schema           string            `json:"schema"`
	Source           SourceProvenance  `json:"source"`
	ComparisonSHA256 string            `json:"comparisonSha256"`
	Roots            SubjectRoots      `json:"roots"`
	Subjects         []SubjectManifest `json:"subjects"`
}

type EnvironmentContext struct {
	Schema            string `json:"schema"`
	HostOS            string `json:"hostOs"`
	HostArch          string `json:"hostArch"`
	HostBootClass     string `json:"hostBootClass"`
	AndroidClass      string `json:"androidClass"`
	AndroidAPI        int    `json:"androidApi"`
	AndroidABI        string `json:"androidAbi"`
	VPSOS             string `json:"vpsOs"`
	VPSArch           string `json:"vpsArch"`
	ProviderClass     string `json:"providerClass"`
	TimeSource        string `json:"timeSource"`
	PowerPolicy       string `json:"powerPolicy"`
	PythonSHA256      string `json:"pythonSha256"`
	ADBSHA256         string `json:"adbSha256"`
	SSHSHA256         string `json:"sshSha256"`
	SCPSHA256         string `json:"scpSha256"`
	PowerShellSHA256  string `json:"powershellSha256"`
	PrivateCommitment string `json:"privateCommitment"`
}

func BuildSubjectManifest(name, root string, paths []string) (SubjectManifest, error) {
	if !containsExact(exactArtifactSubjectOrder, name) || len(paths) == 0 || len(paths) > 4096 {
		return SubjectManifest{}, errors.New("qualification subject identity rejected")
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return SubjectManifest{}, err
	}
	resolvedRoot, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return SubjectManifest{}, err
	}
	if !samePath(rootAbs, resolvedRoot) {
		return SubjectManifest{}, errors.New("qualification subject root contains a symbolic link")
	}
	normalized := make([]string, 0, len(paths))
	casePaths := make(map[string]string, len(paths))
	for _, path := range paths {
		path = filepath.ToSlash(path)
		if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") || filepath.ToSlash(filepath.Clean(filepath.FromSlash(path))) != path ||
			path == "." || path == ".." || strings.HasPrefix(path, "../") || len(path) > 512 {
			return SubjectManifest{}, errors.New("qualification subject path rejected")
		}
		folded := strings.ToLower(path)
		if prior, duplicate := casePaths[folded]; duplicate {
			return SubjectManifest{}, fmt.Errorf("qualification subject path collision %q and %q", prior, path)
		}
		casePaths[folded] = path
		normalized = append(normalized, path)
	}
	sort.Strings(normalized)
	entries := make([]ManifestEntry, 0, len(normalized))
	infos := make([]os.FileInfo, 0, len(normalized))
	for _, relative := range normalized {
		path := filepath.Join(rootAbs, filepath.FromSlash(relative))
		candidateAbs, err := filepath.Abs(path)
		if err != nil {
			return SubjectManifest{}, err
		}
		rel, err := filepath.Rel(rootAbs, candidateAbs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return SubjectManifest{}, errors.New("qualification subject path escapes root")
		}
		lstat, err := os.Lstat(candidateAbs)
		if err != nil {
			return SubjectManifest{}, err
		}
		if lstat.Mode()&os.ModeSymlink != 0 || !lstat.Mode().IsRegular() {
			return SubjectManifest{}, errors.New("qualification subject entry is not a regular file")
		}
		for _, prior := range infos {
			if os.SameFile(prior, lstat) {
				return SubjectManifest{}, errors.New("qualification subject contains a hardlink alias")
			}
		}
		file, err := os.Open(candidateAbs)
		if err != nil {
			return SubjectManifest{}, err
		}
		opened, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return SubjectManifest{}, err
		}
		if !os.SameFile(lstat, opened) {
			_ = file.Close()
			return SubjectManifest{}, errors.New("qualification subject changed while opening")
		}
		digest := sha256.New()
		if _, err := io.Copy(digest, file); err != nil {
			_ = file.Close()
			return SubjectManifest{}, err
		}
		closedInfo, err := file.Stat()
		closeErr := file.Close()
		if err != nil {
			return SubjectManifest{}, err
		}
		if closeErr != nil {
			return SubjectManifest{}, closeErr
		}
		if !os.SameFile(opened, closedInfo) || opened.Size() != closedInfo.Size() || opened.ModTime() != closedInfo.ModTime() || opened.Size() < 0 {
			return SubjectManifest{}, errors.New("qualification subject changed while hashing")
		}
		entries = append(entries, ManifestEntry{Path: relative, Size: uint64(opened.Size()), SHA256: hex.EncodeToString(digest.Sum(nil))})
		infos = append(infos, lstat)
	}
	input := subjectRootInput{Schema: SubjectManifestSchema, Name: name, Entries: entries}
	raw, err := MarshalCanonical(input)
	if err != nil {
		return SubjectManifest{}, err
	}
	digest := sha256.Sum256(raw)
	return SubjectManifest{
		Schema: SubjectManifestSchema, Name: name,
		RootSHA256: hex.EncodeToString(digest[:]), Entries: entries,
	}, nil
}

func BuildSubjectManifestTree(name, root string) (SubjectManifest, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return SubjectManifest{}, err
	}
	resolvedRoot, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return SubjectManifest{}, err
	}
	if !samePath(rootAbs, resolvedRoot) {
		return SubjectManifest{}, errors.New("qualification subject root contains a symbolic link")
	}
	paths := make([]string, 0, 64)
	err = filepath.WalkDir(rootAbs, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == rootAbs {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("qualification subject tree contains a symbolic link")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("qualification subject tree contains a non-regular entry")
		}
		relative, err := filepath.Rel(rootAbs, path)
		if err != nil {
			return err
		}
		paths = append(paths, filepath.ToSlash(relative))
		if len(paths) > 4096 {
			return errors.New("qualification subject tree exceeds entry limit")
		}
		return nil
	})
	if err != nil {
		return SubjectManifest{}, err
	}
	return BuildSubjectManifest(name, rootAbs, paths)
}

func MarshalSourceProvenance(value SourceProvenance) ([]byte, error) {
	if err := validateSourceProvenance(value); err != nil {
		return nil, err
	}
	return MarshalCanonical(value)
}

func NewSourceProvenance(repository, baselineCommitSHA, commitSHA, treeSHA string, changedPaths []string, toolchainDeclarations, dependencyLocks []ManifestEntry) (SourceProvenance, error) {
	if !repositoryPatternV1.MatchString(repository) || !hex40Pattern.MatchString(baselineCommitSHA) ||
		!hex40Pattern.MatchString(commitSHA) || baselineCommitSHA == commitSHA || !hex40Pattern.MatchString(treeSHA) {
		return SourceProvenance{}, errors.New("qualification source identity rejected")
	}
	if err := validateSourceChangedPaths(changedPaths); err != nil {
		return SourceProvenance{}, err
	}
	if err := validateSourceInventoryEntries(toolchainDeclarations); err != nil {
		return SourceProvenance{}, err
	}
	if err := validateSourceInventoryEntries(dependencyLocks); err != nil {
		return SourceProvenance{}, err
	}
	toolchainPaths := make(map[string]struct{}, len(toolchainDeclarations))
	for _, entry := range toolchainDeclarations {
		toolchainPaths[entry.Path] = struct{}{}
	}
	for _, entry := range dependencyLocks {
		if _, overlaps := toolchainPaths[entry.Path]; overlaps {
			return SourceProvenance{}, errors.New("qualification source inventories overlap")
		}
	}
	changedRaw, err := MarshalCanonical(sourceChangedPathsInput{
		Schema: sourceChangedPathsSchema,
		Paths:  append([]string(nil), changedPaths...),
	})
	if err != nil {
		return SourceProvenance{}, err
	}
	toolchainRaw, err := MarshalCanonical(sourceFileInventoryInput{
		Schema:  sourceFileInventorySchema,
		Kind:    "TOOLCHAIN_DECLARATIONS",
		Entries: append([]ManifestEntry(nil), toolchainDeclarations...),
	})
	if err != nil {
		return SourceProvenance{}, err
	}
	locksRaw, err := MarshalCanonical(sourceFileInventoryInput{
		Schema:  sourceFileInventorySchema,
		Kind:    "DEPENDENCY_LOCKS",
		Entries: append([]ManifestEntry(nil), dependencyLocks...),
	})
	if err != nil {
		return SourceProvenance{}, err
	}
	changedDigest := sha256.Sum256(changedRaw)
	toolchainDigest := sha256.Sum256(toolchainRaw)
	locksDigest := sha256.Sum256(locksRaw)
	return SourceProvenance{
		Repository: repository, BaselineCommitSHA: baselineCommitSHA, CommitSHA: commitSHA, TreeSHA: treeSHA,
		ChangedPathsSHA256:          hex.EncodeToString(changedDigest[:]),
		ToolchainDeclarationsSHA256: hex.EncodeToString(toolchainDigest[:]),
		DependencyLocksSHA256:       hex.EncodeToString(locksDigest[:]),
	}, nil
}

func validateSourceChangedPaths(values []string) error {
	if len(values) == 0 || len(values) > 4096 {
		return errors.New("qualification changed-path inventory rejected")
	}
	last := ""
	casePaths := make(map[string]struct{}, len(values))
	for _, path := range values {
		if path <= last || !safeSourcePath(path) {
			return errors.New("qualification changed-path inventory rejected")
		}
		folded := strings.ToLower(path)
		if _, duplicate := casePaths[folded]; duplicate {
			return errors.New("qualification changed-path inventory collision")
		}
		casePaths[folded] = struct{}{}
		last = path
	}
	return nil
}

func validateSourceInventoryEntries(values []ManifestEntry) error {
	if len(values) == 0 || len(values) > 4096 {
		return errors.New("qualification source file inventory rejected")
	}
	last := ""
	casePaths := make(map[string]struct{}, len(values))
	for _, entry := range values {
		if entry.Path <= last || !safeSourcePath(entry.Path) || !hex64Pattern.MatchString(entry.SHA256) {
			return errors.New("qualification source file inventory rejected")
		}
		folded := strings.ToLower(entry.Path)
		if _, duplicate := casePaths[folded]; duplicate {
			return errors.New("qualification source file inventory collision")
		}
		casePaths[folded] = struct{}{}
		last = entry.Path
	}
	return nil
}

func safeSourcePath(path string) bool {
	if path == "" || len(path) > 512 || !utf8.ValidString(path) || filepath.IsAbs(path) || strings.Contains(path, "\\") ||
		strings.ContainsAny(path, "\r\n\x00") || filepath.ToSlash(filepath.Clean(filepath.FromSlash(path))) != path ||
		path == "." || path == ".." || strings.HasPrefix(path, "../") {
		return false
	}
	for _, char := range path {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func DecodeSourceProvenance(reader io.Reader) (SourceProvenance, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, 64<<10+1))
	if err != nil {
		return SourceProvenance{}, err
	}
	if len(raw) > 64<<10 {
		return SourceProvenance{}, errors.New("qualification source provenance exceeds limit")
	}
	var value SourceProvenance
	if err := assurance.DecodeStrict(bytes.NewReader(raw), &value); err != nil {
		return SourceProvenance{}, err
	}
	if err := validateSourceProvenance(value); err != nil {
		return SourceProvenance{}, err
	}
	canonical, err := MarshalSourceProvenance(value)
	if err != nil {
		return SourceProvenance{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return SourceProvenance{}, errors.New("qualification source provenance is not canonical")
	}
	return value, nil
}

func NewCandidateManifest(source SourceProvenance, comparisonSHA256 string, subjects []SubjectManifest) (CandidateManifest, error) {
	if err := validateSourceProvenance(source); err != nil {
		return CandidateManifest{}, err
	}
	if !hex64Pattern.MatchString(comparisonSHA256) {
		return CandidateManifest{}, errors.New("qualification comparison digest rejected")
	}
	ordered, err := orderAndValidateSubjects(subjects)
	if err != nil {
		return CandidateManifest{}, err
	}
	sourceRaw, err := MarshalCanonical(source)
	if err != nil {
		return CandidateManifest{}, err
	}
	sourceDigest := sha256.Sum256(sourceRaw)
	roots, err := NewSubjectRoots(
		hex.EncodeToString(sourceDigest[:]), ordered[0].RootSHA256, ordered[1].RootSHA256,
		ordered[2].RootSHA256, ordered[3].RootSHA256,
	)
	if err != nil {
		return CandidateManifest{}, err
	}
	return CandidateManifest{
		Schema: CandidateManifestSchema, Source: source, ComparisonSHA256: comparisonSHA256,
		Roots: roots, Subjects: ordered,
	}, nil
}

func MarshalCandidateManifest(value CandidateManifest) ([]byte, error) {
	if err := ValidateCandidateManifest(value); err != nil {
		return nil, err
	}
	return MarshalCanonical(value)
}

func DecodeCandidateManifest(reader io.Reader) (CandidateManifest, error) {
	var value CandidateManifest
	var capture bytes.Buffer
	tee := io.TeeReader(io.LimitReader(reader, 4<<20+1), &capture)
	if err := assurance.DecodeStrict(tee, &value); err != nil {
		return CandidateManifest{}, err
	}
	if capture.Len() > 4<<20 {
		return CandidateManifest{}, errors.New("qualification candidate manifest exceeds limit")
	}
	if err := ValidateCandidateManifest(value); err != nil {
		return CandidateManifest{}, err
	}
	canonical, err := MarshalCanonical(value)
	if err != nil {
		return CandidateManifest{}, err
	}
	if !bytes.Equal(capture.Bytes(), canonical) {
		return CandidateManifest{}, errors.New("qualification candidate manifest is not canonical")
	}
	return value, nil
}

func ValidateCandidateManifest(value CandidateManifest) error {
	if value.Schema != CandidateManifestSchema {
		return errors.New("qualification candidate schema rejected")
	}
	want, err := NewCandidateManifest(value.Source, value.ComparisonSHA256, value.Subjects)
	if err != nil {
		return err
	}
	if value.Roots != want.Roots {
		return errors.New("qualification candidate roots rejected")
	}
	return nil
}

func CandidateIdentityFromManifest(value CandidateManifest) (CandidateIdentity, error) {
	if err := ValidateCandidateManifest(value); err != nil {
		return CandidateIdentity{}, err
	}
	result := CandidateIdentity{
		Repository: value.Source.Repository, CommitSHA: value.Source.CommitSHA,
		TreeSHA: value.Source.TreeSHA, Roots: value.Roots, ComparisonSHA256: value.ComparisonSHA256,
	}
	if err := validateCandidateIdentity(result); err != nil {
		return CandidateIdentity{}, err
	}
	return result, nil
}

// VerifyCandidateArtifact proves that path contains the exact bytes declared
// for one entry of a validated candidate subject. The file is opened and
// re-statted through the same handle so a link swap or concurrent rewrite is
// rejected instead of being silently hashed as another artifact.
func VerifyCandidateArtifact(value CandidateManifest, subjectName, entryPath, path string, maximum int64) (string, error) {
	if err := ValidateCandidateManifest(value); err != nil {
		return "", err
	}
	if path == "" || maximum <= 0 {
		return "", errors.New("qualification candidate artifact path rejected")
	}
	var expected *ManifestEntry
	for _, subject := range value.Subjects {
		if subject.Name != subjectName {
			continue
		}
		for index := range subject.Entries {
			if subject.Entries[index].Path == entryPath {
				entry := subject.Entries[index]
				expected = &entry
				break
			}
		}
		break
	}
	if expected == nil || expected.Size > uint64(maximum) {
		return "", errors.New("qualification candidate artifact entry rejected")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 0 || uint64(before.Size()) != expected.Size {
		return "", errors.New("qualification candidate artifact file rejected")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || before.Size() != opened.Size() || before.ModTime() != opened.ModTime() {
		_ = file.Close()
		return "", errors.New("qualification candidate artifact changed while opening")
	}
	digest := sha256.New()
	written, copyErr := io.Copy(digest, io.LimitReader(file, maximum+1))
	after, statErr := file.Stat()
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if statErr != nil {
		return "", statErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if written != opened.Size() || written > maximum || uint64(written) != expected.Size || !os.SameFile(opened, after) ||
		opened.Size() != after.Size() || opened.ModTime() != after.ModTime() {
		return "", errors.New("qualification candidate artifact changed while hashing")
	}
	digestHex := hex.EncodeToString(digest.Sum(nil))
	if digestHex != expected.SHA256 {
		return "", errors.New("qualification candidate artifact digest rejected")
	}
	return digestHex, nil
}

func MarshalEnvironmentContext(value EnvironmentContext) ([]byte, error) {
	if err := validateEnvironment(value); err != nil {
		return nil, err
	}
	return MarshalCanonical(value)
}

func DecodeEnvironmentContext(reader io.Reader) (EnvironmentContext, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, 64<<10+1))
	if err != nil {
		return EnvironmentContext{}, err
	}
	if len(raw) > 64<<10 {
		return EnvironmentContext{}, errors.New("qualification environment context exceeds limit")
	}
	var value EnvironmentContext
	if err := assurance.DecodeStrict(bytes.NewReader(raw), &value); err != nil {
		return EnvironmentContext{}, err
	}
	if err := validateEnvironment(value); err != nil {
		return EnvironmentContext{}, err
	}
	canonical, err := MarshalEnvironmentContext(value)
	if err != nil {
		return EnvironmentContext{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return EnvironmentContext{}, errors.New("qualification environment context is not canonical")
	}
	return value, nil
}

func EnvironmentDigest(value EnvironmentContext) (string, error) {
	if err := validateEnvironment(value); err != nil {
		return "", err
	}
	raw, err := MarshalCanonical(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func validateSourceProvenance(value SourceProvenance) error {
	if !repositoryPatternV1.MatchString(value.Repository) || !hex40Pattern.MatchString(value.BaselineCommitSHA) ||
		!hex40Pattern.MatchString(value.CommitSHA) || value.BaselineCommitSHA == value.CommitSHA ||
		!hex40Pattern.MatchString(value.TreeSHA) || !hex64Pattern.MatchString(value.ChangedPathsSHA256) ||
		!hex64Pattern.MatchString(value.ToolchainDeclarationsSHA256) || !hex64Pattern.MatchString(value.DependencyLocksSHA256) {
		return errors.New("qualification source provenance rejected")
	}
	return nil
}

func orderAndValidateSubjects(values []SubjectManifest) ([]SubjectManifest, error) {
	if len(values) != len(exactArtifactSubjectOrder) {
		return nil, errors.New("qualification subject cardinality rejected")
	}
	byName := make(map[string]SubjectManifest, len(values))
	for _, value := range values {
		if _, duplicate := byName[value.Name]; duplicate {
			return nil, errors.New("qualification subject name repeated")
		}
		if err := validateSubjectManifest(value); err != nil {
			return nil, err
		}
		byName[value.Name] = value
	}
	ordered := make([]SubjectManifest, 0, len(values))
	for _, name := range exactArtifactSubjectOrder {
		value, found := byName[name]
		if !found {
			return nil, errors.New("qualification subject missing")
		}
		ordered = append(ordered, value)
	}
	return ordered, nil
}

func validateSubjectManifest(value SubjectManifest) error {
	if value.Schema != SubjectManifestSchema || !containsExact(exactArtifactSubjectOrder, value.Name) ||
		!hex64Pattern.MatchString(value.RootSHA256) || len(value.Entries) == 0 || len(value.Entries) > 4096 {
		return errors.New("qualification subject manifest rejected")
	}
	last := ""
	casePaths := map[string]struct{}{}
	for _, entry := range value.Entries {
		if entry.Path <= last || filepath.ToSlash(filepath.Clean(filepath.FromSlash(entry.Path))) != entry.Path ||
			entry.Path == "." || entry.Path == ".." || strings.HasPrefix(entry.Path, "../") || filepath.IsAbs(entry.Path) ||
			!hex64Pattern.MatchString(entry.SHA256) {
			return errors.New("qualification subject manifest entry rejected")
		}
		folded := strings.ToLower(entry.Path)
		if _, duplicate := casePaths[folded]; duplicate {
			return errors.New("qualification subject manifest path collision")
		}
		casePaths[folded] = struct{}{}
		last = entry.Path
	}
	input := subjectRootInput{Schema: SubjectManifestSchema, Name: value.Name, Entries: value.Entries}
	raw, err := MarshalCanonical(input)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	if value.RootSHA256 != hex.EncodeToString(digest[:]) {
		return errors.New("qualification subject manifest root rejected")
	}
	return nil
}

func validateEnvironment(value EnvironmentContext) error {
	if value.Schema != EnvironmentSchema || !containsExact([]string{"windows", "linux", "darwin"}, value.HostOS) ||
		!containsExact([]string{"amd64", "arm64"}, value.HostArch) || value.HostBootClass != "BOUND_CURRENT_BOOT" ||
		!containsExact([]string{"EMULATOR", "PHYSICAL"}, value.AndroidClass) ||
		(value.AndroidAPI != 26 && value.AndroidAPI != 34 && value.AndroidAPI != 36) ||
		!containsExact([]string{"x86_64", "arm64-v8a"}, value.AndroidABI) || value.VPSOS != "linux" ||
		value.VPSArch != "amd64" ||
		!containsExact([]string{"PRIMARY", "UNRELATED_SECONDARY"}, value.ProviderClass) ||
		value.TimeSource != "OWNER_VPS_INTERVAL_REQUIRED" || value.PowerPolicy != "RUNNER_SYSTEM_REQUIRED" ||
		!hex64Pattern.MatchString(value.PythonSHA256) || !hex64Pattern.MatchString(value.ADBSHA256) ||
		!hex64Pattern.MatchString(value.SSHSHA256) || !hex64Pattern.MatchString(value.SCPSHA256) ||
		!hex64Pattern.MatchString(value.PowerShellSHA256) ||
		!hex64Pattern.MatchString(value.PrivateCommitment) {
		return errors.New("qualification environment context rejected")
	}
	return nil
}
