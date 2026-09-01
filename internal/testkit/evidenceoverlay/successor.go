// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package evidenceoverlay validates append-only successor evidence without
// rewriting historical evidence manifests.
package evidenceoverlay

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	SuccessorPath                       = "testdata/evidence/phase15/production-contract-overlay.json"
	Phase16SuccessorPath                = "testdata/evidence/phase16/ci-release-acceleration-overlay.json"
	Phase16ProductionTrustSuccessorPath = "testdata/evidence/phase16/production-trust-overlay.json"
	Phase16RuntimeSuccessorPath         = "testdata/evidence/phase16/production-runtime-overlay.json"
	Phase16DecentralizedSuccessorPath   = "testdata/evidence/phase16/decentralized-self-hosted-overlay.json"
	Phase17SuccessorPath                = "testdata/evidence/phase17/live-data-plane-overlay.json"
	Phase17SuccessorEntryLimit          = 512
	PublicDocumentationSuccessorPath    = "testdata/evidence/public-documentation-sanitization-overlay.json"
	// The pre-rewrite baseline remains provenance only. Repository evidence is
	// read from the exact sanitized main subject and never from the live tree.
	LegacyHistoricalCommit = "8ef19dd57520c2930d12e81ed7769a6ec6cf3326"
	LegacyHistoricalTree   = "3a51879991388775abffa9e3df7984d624b63852"
	HistoricalCommit       = "c84473e28249e1d165da23a4bc9be6d4d219784a"
	HistoricalTree         = "b29fac42992b04e072c727b79a33bcd904e5d9aa"
	maximumObjectBytes     = 64 << 20
)

// HistoricalFile binds bytes to one exact Git object and tree entry. Content is
// a defensive copy; it is never a qualification receipt for the working tree.
type HistoricalFile struct {
	Commit, Tree, Path, Mode, Type, ObjectID, SHA256 string
	Length                                           int64
	Content                                          []byte
}

// sanitizedLineageRecord binds the history rewrite without embedding removed
// path names or contents. The manifest digests use ordinal path ordering and:
// domain NUL, u32be record count, then status u8, old/new mode as six ASCII
// bytes, old/new SHA-1 object IDs as 20 raw bytes, u32be UTF-8 path length and
// path bytes. It is provenance metadata, never qualification evidence.
type sanitizedLineageRecord struct {
	Version                string
	LegacyBaselineCommit   string
	LegacyBaselineTree     string
	SanitizedMainCommit    string
	SanitizedMainTree      string
	LegacyFeatureCommit    string
	LegacyFeatureTree      string
	SanitizedFeatureCommit string
	SanitizedFeatureTree   string
	RemovedManifestDomain  string
	RemovedRecordCount     int
	RemovedFrameLength     int
	RemovedManifestSHA256  string
	FeatureManifestDomain  string
	FeatureRecordCount     int
	FeatureFrameLength     int
	FeatureManifestSHA256  string
}

func sanitizedLineageRecordV2() sanitizedLineageRecord {
	return sanitizedLineageRecord{
		Version:                "sanitized-history-lineage-v2",
		LegacyBaselineCommit:   LegacyHistoricalCommit,
		LegacyBaselineTree:     LegacyHistoricalTree,
		SanitizedMainCommit:    HistoricalCommit,
		SanitizedMainTree:      HistoricalTree,
		LegacyFeatureCommit:    "c88113fb7143a677dbb859b82fdf12cd6953f402",
		LegacyFeatureTree:      "1739ccb6150fe6d9ea1403ca7c17174cfd9ef2ba",
		SanitizedFeatureCommit: "046f129ae5076d8f63f2907de5bf9e8af4a26a33",
		SanitizedFeatureTree:   "3c9a2d547f709686cf00f4fd7963c0a202b1466a",
		RemovedManifestDomain:  "KURDISTAN-SANITIZED-LINEAGE-REMOVALS-V2",
		RemovedRecordCount:     121,
		RemovedFrameLength:     12072,
		RemovedManifestSHA256:  "c85925077c12b547b864ba25f19b64e9abd80ad5dc719036b0cb6f8e3ec1b20a",
		FeatureManifestDomain:  "KURDISTAN-SANITIZED-FEATURE-DELTA-V2",
		FeatureRecordCount:     192,
		FeatureFrameLength:     25353,
		FeatureManifestSHA256:  "0c1b8bf49fb77774ae42714af4cbb474ae388ad48df52d09e6835c47ac874d58",
	}
}

func validateSanitizedLineageRecord(record sanitizedLineageRecord) error {
	want := sanitizedLineageRecordV2()
	if record != want || record.Version != "sanitized-history-lineage-v2" ||
		!validObjectID(record.LegacyBaselineCommit) || !validObjectID(record.LegacyBaselineTree) ||
		!validObjectID(record.SanitizedMainCommit) || !validObjectID(record.SanitizedMainTree) ||
		!validObjectID(record.LegacyFeatureCommit) || !validObjectID(record.LegacyFeatureTree) ||
		!validObjectID(record.SanitizedFeatureCommit) || !validObjectID(record.SanitizedFeatureTree) ||
		!validDigest(record.RemovedManifestSHA256) || !validDigest(record.FeatureManifestSHA256) ||
		record.RemovedManifestDomain == record.FeatureManifestDomain ||
		record.RemovedRecordCount <= 0 || record.FeatureRecordCount <= 0 ||
		record.RemovedFrameLength <= 0 || record.FeatureFrameLength <= 0 {
		return errors.New("invalid sanitized history lineage record")
	}
	return nil
}

type historicalSubject struct {
	root, commit, tree string
	entries            map[string]HistoricalFile
	mu                 sync.Mutex
	content            map[string][]byte
	resultMu           sync.Mutex
	results            map[string]map[string]string
}

var historicalSubjects sync.Map

func gitObjectCommand(root string, input []byte, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"--no-replace-objects", "--literal-pathspecs", "-C", root}, args...)...)
	// Object reads must neither fetch a missing promisor object nor use an
	// environment-supplied repository, index, namespace or replacement object.
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if !strings.HasPrefix(strings.ToUpper(key), "GIT_") {
			cmd.Env = append(cmd.Env, item)
		}
	}
	cmd.Env = append(cmd.Env, "GIT_NO_LAZY_FETCH=1", "GIT_NO_REPLACE_OBJECTS=1", "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0")
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("immutable Git object read failed (%s): %w", args[0], err)
	}
	return raw, nil
}

func gitObjectID(kind string, raw []byte) string {
	h := sha1.New() // Git SHA-1 object identity, not a new security digest.
	_, _ = fmt.Fprintf(h, "%s %d\x00", kind, len(raw))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

func validObjectID(value string) bool {
	if len(value) != 40 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validateSubjectPath(path string) error {
	if path == "" || strings.ContainsAny(path, "\\:\x00\r\n\t") || strings.HasPrefix(path, "/") {
		return errors.New("invalid evidence subject path")
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." || strings.EqualFold(part, ".git") ||
			strings.EqualFold(part, ".codex-private") || strings.EqualFold(part, "AGENTS.override.md") {
			return errors.New("invalid or private evidence subject path")
		}
	}
	return nil
}

func openHistoricalSubject(root, commit, tree string) (*historicalSubject, error) {
	if !validObjectID(commit) || !validObjectID(tree) {
		return nil, errors.New("exact immutable commit and tree required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	top, err := gitObjectCommand(abs, nil, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	if filepath.Clean(filepath.FromSlash(strings.TrimSpace(string(top)))) != filepath.Clean(abs) {
		return nil, errors.New("evidence root is not the exact Git worktree root")
	}
	raw, err := gitObjectCommand(abs, nil, "cat-file", "commit", commit)
	if err != nil {
		return nil, err
	}
	first, _, _ := bytes.Cut(raw, []byte{'\n'})
	if gitObjectID("commit", raw) != commit || string(first) != "tree "+tree {
		return nil, errors.New("immutable commit/tree binding mismatch")
	}
	raw, err = gitObjectCommand(abs, nil, "cat-file", "tree", tree)
	if err != nil {
		return nil, err
	}
	if gitObjectID("tree", raw) != tree {
		return nil, errors.New("immutable tree digest mismatch")
	}
	raw, err = gitObjectCommand(abs, nil, "ls-tree", "-r", "-t", "-l", "-z", tree)
	if err != nil {
		return nil, err
	}
	s := &historicalSubject{root: abs, commit: commit, tree: tree, entries: map[string]HistoricalFile{}, content: map[string][]byte{}}
	for _, row := range bytes.Split(raw, []byte{0}) {
		if len(row) == 0 {
			continue
		}
		header, name, ok := bytes.Cut(row, []byte{'\t'})
		fields := strings.Fields(string(header))
		if !ok || len(fields) != 4 || !validObjectID(fields[2]) {
			return nil, errors.New("invalid immutable tree inventory")
		}
		path := string(name)
		if err := validateSubjectPath(path); err != nil {
			return nil, err
		}
		if _, exists := s.entries[path]; exists {
			return nil, errors.New("duplicate immutable tree path")
		}
		length, err := strconv.ParseInt(fields[3], 10, 64)
		if fields[1] == "tree" && fields[3] == "-" {
			length, err = -1, nil
		}
		if err != nil || (length < 0 && fields[1] != "tree") {
			return nil, errors.New("invalid immutable object length")
		}
		s.entries[path] = HistoricalFile{Commit: commit, Tree: tree, Path: path, Mode: fields[0], Type: fields[1], ObjectID: fields[2], Length: length}
	}
	return s, nil
}

func historicalForRoot(root string) (*historicalSubject, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	key := filepath.Clean(abs)
	if cached, ok := historicalSubjects.Load(key); ok {
		return cached.(*historicalSubject), nil
	}
	s, err := openHistoricalSubject(key, HistoricalCommit, HistoricalTree)
	if err != nil {
		return nil, err
	}
	actual, _ := historicalSubjects.LoadOrStore(key, s)
	return actual.(*historicalSubject), nil
}

func (s *historicalSubject) read(path string) (HistoricalFile, error) {
	if err := validateSubjectPath(path); err != nil {
		return HistoricalFile{}, err
	}
	entry, ok := s.entries[path]
	if !ok {
		return HistoricalFile{}, &os.PathError{Op: "immutable tree lookup", Path: path, Err: os.ErrNotExist}
	}
	if entry.Type != "blob" || (entry.Mode != "100644" && entry.Mode != "100755") || entry.Length < 0 || entry.Length > maximumObjectBytes {
		return HistoricalFile{}, errors.New("unsupported immutable object type, mode or length")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, found := s.content[path]
	if !found {
		framed, err := gitObjectCommand(s.root, []byte(entry.ObjectID+"\n"), "cat-file", "--batch")
		if err != nil {
			return HistoricalFile{}, err
		}
		header, body, ok := bytes.Cut(framed, []byte{'\n'})
		if !ok || string(header) != fmt.Sprintf("%s blob %d", entry.ObjectID, entry.Length) ||
			int64(len(body)) != entry.Length+1 || body[len(body)-1] != '\n' {
			return HistoricalFile{}, errors.New("immutable object type/length framing mismatch")
		}
		raw = bytes.Clone(body[:len(body)-1])
		if gitObjectID("blob", raw) != entry.ObjectID {
			return HistoricalFile{}, errors.New("immutable blob digest mismatch")
		}
		s.content[path] = raw
	}
	digest := sha256.Sum256(raw)
	entry.SHA256 = hex.EncodeToString(digest[:])
	entry.Content = bytes.Clone(raw)
	return entry, nil
}

// ReadHistoricalFile has no filesystem, index, HEAD or alternate-subject fallback.
func ReadHistoricalFile(root, path string) (HistoricalFile, error) {
	s, err := historicalForRoot(root)
	if err != nil {
		return HistoricalFile{}, err
	}
	return s.read(path)
}

func isFixtureRoot(root string) (bool, error) {
	// Existing mutation tests use deliberately standalone directories, including
	// copied module files. A Git marker selects immutable mode before any lookup; a failed
	// immutable lookup can never cause a switch to fixture mode.
	for _, marker := range []string{".git"} {
		if _, err := os.Lstat(filepath.Join(root, marker)); err == nil {
			return false, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	// A fixture may live in a test-owned temporary directory beneath a worktree.
	// Do not discover its parent and silently change the explicitly supplied root.
	return true, nil
}

// ReadSubjectFile preserves standalone fixture mutation tests. Repository reads
// always use the pinned historical subject. Fixture verification is not evidence
// for the repository or for any qualification consumer.
func ReadSubjectFile(root, path string) ([]byte, error) {
	if err := validateSubjectPath(path); err != nil {
		return nil, err
	}
	fixture, err := isFixtureRoot(root)
	if err != nil {
		return nil, err
	}
	if !fixture {
		file, err := ReadHistoricalFile(root, path)
		if err != nil {
			return nil, err
		}
		if path == "android/gradlew.bat" {
			// This frozen manifest hashes the CRLF checkout representation. Bind
			// both the literal blob and its immutable eol=crlf declaration before
			// reproducing those bytes in memory. Never consult local attributes,
			// core.autocrlf, the index, or a working-tree copy.
			attributes, err := ReadHistoricalFile(root, ".gitattributes")
			if err != nil {
				return nil, err
			}
			if attributes.ObjectID != "617a8337920f314cd1f2bd013efbcbe6ad148a90" ||
				!bytes.Contains(attributes.Content, []byte("\ngradlew.bat text eol=crlf\n")) ||
				file.Length != 2803 || file.SHA256 != "9ca26d733ada3a45f27b2151288f54e75c9f95b287d1f82ef942ec5cc2d4f006" ||
				bytes.ContainsRune(file.Content, '\r') {
				return nil, errors.New("frozen checkout representation binding mismatch")
			}
			projected := bytes.ReplaceAll(file.Content, []byte{'\n'}, []byte{'\r', '\n'})
			if len(projected) != 2896 || fmt.Sprintf("%x", sha256.Sum256(projected)) != "fedad02c18e266ec094995a5751b7fe1eb6e74f66bf75db64fae2e50eb22c234" {
				return nil, errors.New("frozen checkout representation digest mismatch")
			}
			return projected, nil
		}
		return file.Content, nil
	}
	full := root
	for _, part := range strings.Split(path, "/") {
		full = filepath.Join(full, part)
		info, err := os.Lstat(full)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("fixture symlink rejected")
		}
	}
	info, err := os.Lstat(full)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maximumObjectBytes {
		return nil, errors.New("invalid fixture file type or length")
	}
	return os.ReadFile(full)
}

// SubjectState returns ABSENT only when the chosen subject actually lacks the
// path. Missing Git objects and invalid identities are errors, never ABSENT.
func SubjectState(root, path string) (string, error) {
	raw, err := ReadSubjectFile(root, path)
	if errors.Is(err, os.ErrNotExist) {
		return "ABSENT", nil
	}
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func HistoricalPaths(root string) ([]string, error) {
	s, err := historicalForRoot(root)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(s.entries))
	for path, entry := range s.entries {
		if entry.Type != "tree" {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	return paths, nil
}

// Cache only successfully reconstructed immutable subjects. Callers receive a
// copy; standalone mutation fixtures and caller-supplied post-states are never
// cached. This avoids revalidating the same frozen chain for every file hash.
func immutableResult(root, key string, compute func() (map[string]string, error)) (map[string]string, error) {
	fixture, err := isFixtureRoot(root)
	if err != nil {
		return nil, err
	}
	if fixture {
		return compute()
	}
	s, err := historicalForRoot(root)
	if err != nil {
		return nil, err
	}
	s.resultMu.Lock()
	defer s.resultMu.Unlock()
	value, found := s.results[key]
	if !found {
		value, err = compute()
		if err != nil {
			return nil, err
		}
		if s.results == nil {
			s.results = make(map[string]map[string]string)
		}
		snapshot := make(map[string]string, len(value))
		for path, digest := range value {
			snapshot[path] = digest
		}
		value = snapshot
		s.results[key] = value
	}
	copyValue := make(map[string]string, len(value))
	for path, digest := range value {
		copyValue[path] = digest
	}
	return copyValue, nil
}

type overlay struct {
	Version                  string  `json:"version"`
	SelfPath                 string  `json:"self_path,omitempty"`
	SelfPreEvidence          string  `json:"self_pre_evidence,omitempty"`
	SelfPreSHA256            string  `json:"self_pre_sha256,omitempty"`
	PredecessorBindingSHA256 string  `json:"predecessor_binding_sha256,omitempty"`
	Entries                  []entry `json:"entries"`
	SuccessorEntries         []entry `json:"successor_entries,omitempty"`
	SuccessorEntriesV2       []entry `json:"successor_entries_v2,omitempty"`
}

type entry struct {
	Path         string `json:"path"`
	PreSHA256    string `json:"pre_sha256,omitempty"`
	PreEvidence  string `json:"pre_evidence,omitempty"`
	PostSHA256   string `json:"post_sha256,omitempty"`
	PostEvidence string `json:"post_evidence,omitempty"`
}

// LoadSuccessor verifies the exact historical (or standalone fixture) post-state and returns the
// predecessor state that the historical overlay validators must evaluate.
func LoadSuccessor(root, expectedVersion string) (map[string]string, error) {
	return immutableResult(root, "successor:"+expectedVersion, func() (map[string]string, error) {
		return LoadSuccessorAtPost(root, nil, expectedVersion)
	})
}

// LoadSuccessorAtPost verifies the successor chain using currentAtPost for
// paths advanced by a later in-manifest overlay. This keeps the append-only
// external chain verifiable while the caller reconstructs an earlier phase.
func LoadSuccessorAtPost(root string, currentAtPost map[string]string, expectedVersion string) (map[string]string, error) {
	layers := []struct {
		path     string
		version  string
		optional bool
		entries  func(overlay) []entry
	}{
		{Phase17SuccessorPath, "phase17-live-data-plane-v1", true, func(value overlay) []entry { return value.SuccessorEntriesV2 }},
		{Phase17SuccessorPath, "phase17-live-data-plane-v1", true, func(value overlay) []entry { return value.SuccessorEntries }},
		{Phase17SuccessorPath, "phase17-live-data-plane-v1", true, func(value overlay) []entry { return value.Entries }},
		{Phase16DecentralizedSuccessorPath, "phase16-decentralized-self-hosted-v1", true, func(value overlay) []entry { return value.SuccessorEntries }},
		{PublicDocumentationSuccessorPath, "public-documentation-sanitization-v1", true, func(value overlay) []entry { return value.Entries }},
		{Phase16DecentralizedSuccessorPath, "phase16-decentralized-self-hosted-v1", true, func(value overlay) []entry { return value.Entries }},
		{Phase16RuntimeSuccessorPath, "phase16-production-runtime-v1", true, func(value overlay) []entry { return value.Entries }},
		{Phase16ProductionTrustSuccessorPath, "phase16-production-trust-v1", true, func(value overlay) []entry { return value.Entries }},
		{Phase16SuccessorPath, "phase16-ci-release-acceleration-v1", true, func(value overlay) []entry { return value.Entries }},
		{SuccessorPath, expectedVersion, false, func(value overlay) []entry { return value.Entries }},
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, digest := range currentAtPost {
		pre[path] = digest
	}
	for _, layer := range layers {
		if _, err := ReadSubjectFile(root, layer.path); err != nil {
			if errors.Is(err, os.ErrNotExist) && layer.optional {
				continue
			}
			if errors.Is(err, os.ErrNotExist) && layer.path == SuccessorPath {
				return pre, nil
			}
			return nil, err
		}
		value, err := readOverlay(root, layer.path, layer.version)
		if err != nil {
			return nil, err
		}
		for index, item := range layer.entries(value) {
			observed, ok := pre[item.Path]
			if !ok {
				observed, err = SubjectState(root, item.Path)
				if err != nil {
					return nil, fmt.Errorf("read successor path %s: %w", item.Path, err)
				}
			}
			if observed != postState(item) {
				return nil, fmt.Errorf("successor evidence drift in %s entry %d: %s", layer.path, index, item.Path)
			}
			pre[item.Path] = predecessor(item)
		}
	}
	return pre, nil
}

// ResolveCurrentSHA256 returns the effective current hash for a historical
// evidence validator. A validated successor overlay contributes the exact
// predecessor hash for paths it advances; all other paths are hashed from the
// immutable subject (or explicit standalone fixture). This lets a new append-only overlay advance a path whose most
// recent historical owner is older than the immediately preceding phase.
func ResolveCurrentSHA256(root, path string) (string, error) {
	predecessors, err := LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		return "", err
	}
	if digest, ok := predecessors[path]; ok {
		return digest, nil
	}
	content, err := ReadSubjectFile(root, path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

// ResolvePhase17PredecessorSHA256 returns the hash at the Phase 17 boundary.
// It validates and unwinds only the Phase 17 overlay, leaving the established
// Phase 16 state intact. Historical generators that were already reconciled
// during Phase 16 use this boundary while Phase 17 advances their source files.
func ResolvePhase17PredecessorSHA256(root, path string) (string, error) {
	predecessors, err := loadPhase17Predecessors(root)
	if err != nil {
		return "", err
	}
	if digest, ok := predecessors[path]; ok {
		return digest, nil
	}
	content, err := ReadSubjectFile(root, path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func loadPhase17Predecessors(root string) (map[string]string, error) {
	return immutableResult(root, "phase17-predecessors", func() (map[string]string, error) {
		return readPhase17Predecessors(root)
	})
}

func readPhase17Predecessors(root string) (map[string]string, error) {
	if _, err := ReadSubjectFile(root, Phase17SuccessorPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	value, err := readOverlay(root, Phase17SuccessorPath, "phase17-live-data-plane-v1")
	if err != nil {
		return nil, err
	}
	pre := make(map[string]string, len(value.Entries)+len(value.SuccessorEntries)+len(value.SuccessorEntriesV2))
	for _, entries := range [][]entry{value.SuccessorEntriesV2, value.SuccessorEntries, value.Entries} {
		for index, item := range entries {
			observed, ok := pre[item.Path]
			if !ok {
				observed, err = SubjectState(root, item.Path)
				if err != nil {
					return nil, fmt.Errorf("read successor path %s: %w", item.Path, err)
				}
			}
			if observed != postState(item) {
				return nil, fmt.Errorf("successor evidence drift in %s entry %d: %s", Phase17SuccessorPath, index, item.Path)
			}
			pre[item.Path] = predecessor(item)
		}
	}
	return pre, nil
}

func readOverlay(root, relative, expectedVersion string) (overlay, error) {
	raw, err := ReadSubjectFile(root, relative)
	if err != nil {
		return overlay{}, err
	}
	var value overlay
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return overlay{}, fmt.Errorf("decode successor overlay %s: %w", relative, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return overlay{}, fmt.Errorf("decode successor overlay %s: trailing JSON", relative)
	}
	successorLimit := 128
	if relative == Phase17SuccessorPath {
		successorLimit = Phase17SuccessorEntryLimit
	}
	if value.Version != expectedVersion || len(value.Entries) == 0 || len(value.Entries) > 128 || len(value.SuccessorEntries) > successorLimit || len(value.SuccessorEntriesV2) > successorLimit {
		return overlay{}, fmt.Errorf("invalid successor overlay identity or cardinality: %s", relative)
	}
	if relative != Phase16DecentralizedSuccessorPath && relative != Phase17SuccessorPath && len(value.SuccessorEntries) != 0 {
		return overlay{}, fmt.Errorf("successor entries are only valid in %s", Phase16DecentralizedSuccessorPath)
	}
	if relative != Phase17SuccessorPath && len(value.SuccessorEntriesV2) != 0 {
		return overlay{}, fmt.Errorf("successor v2 entries are only valid in %s", Phase17SuccessorPath)
	}
	if err := validateEntries(value.Entries, relative, "entries"); err != nil {
		return overlay{}, err
	}
	if err := validateEntries(value.SuccessorEntries, relative, "successor_entries"); err != nil {
		return overlay{}, err
	}
	if err := validateEntries(value.SuccessorEntriesV2, relative, "successor_entries_v2"); err != nil {
		return overlay{}, err
	}
	return value, nil
}

func validateEntries(entries []entry, relative, field string) error {
	last := ""
	for index, item := range entries {
		if err := validateSubjectPath(item.Path); err != nil {
			return fmt.Errorf("invalid successor path %d in %s: %w", index, relative, err)
		}
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(item.Path)))
		if clean != item.Path || item.Path <= last || filepath.IsAbs(item.Path) || strings.HasPrefix(item.Path, "../") || strings.HasPrefix(item.Path, ".tools/") || strings.HasPrefix(item.Path, "planning/") {
			return fmt.Errorf("invalid successor overlay %s path %d in %s", field, index, relative)
		}
		if item.PostEvidence == "ABSENT" {
			if item.PostSHA256 != "" {
				return fmt.Errorf("invalid absent successor %d in %s", index, relative)
			}
		} else if item.PostEvidence != "" || !validDigest(item.PostSHA256) {
			return fmt.Errorf("invalid successor post state %d in %s", index, relative)
		}
		if item.PreEvidence == "ABSENT" {
			if item.PreSHA256 != "" {
				return fmt.Errorf("invalid absent predecessor %d in %s", index, relative)
			}
		} else if item.PreEvidence != "" || !validDigest(item.PreSHA256) {
			return fmt.Errorf("invalid existing predecessor %d in %s", index, relative)
		}
		if predecessor(item) == postState(item) {
			return fmt.Errorf("successor entry does not change state %d in %s", index, relative)
		}
		last = item.Path
	}
	return nil
}

func predecessor(item entry) string {
	if item.PreEvidence == "ABSENT" {
		return "ABSENT"
	}
	return item.PreSHA256
}

func postState(item entry) string {
	if item.PostEvidence == "ABSENT" {
		return "ABSENT"
	}
	return item.PostSHA256
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
