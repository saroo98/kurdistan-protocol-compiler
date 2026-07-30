// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase9evidence converts the Android dependency report into stable,
// reviewable Phase 9 evidence. The command deliberately removes generator
// timestamps and serial numbers so a dependency change, rather than wall-clock
// time, is what changes the committed evidence.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	sourceBOMPath        = "android/build/reports/cyclonedx/bom.json"
	evidenceDir          = "testdata/evidence/phase9"
	projectRepository    = "https://github.com/saroo98/kurdistan-protocol-compiler"
	projectRepositoryGit = projectRepository + ".git"
)

type artifact struct {
	path string
	data []byte
}

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	Name             string            `json:"name"`
	SPDXID           string            `json:"SPDXID"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

type toolchainManifest struct {
	Schema            string            `json:"schema"`
	EvidenceVersion   string            `json:"evidence_version"`
	SourceDate        string            `json:"source_date"`
	Android           map[string]string `json:"android"`
	Go                map[string]string `json:"go"`
	GradleWrapper     map[string]string `json:"gradle_wrapper"`
	CIActionPins      map[string]string `json:"ci_action_pins"`
	ReleaseBoundaries []string          `json:"release_boundaries"`
}

type reproducibilityReport struct {
	Schema      string `json:"schema"`
	Artifact    string `json:"artifact"`
	Environment struct {
		OperatingSystem string `json:"operating_system"`
	} `json:"environment"`
	BuildASHA256    string `json:"build_a_sha256"`
	BuildBSHA256    string `json:"build_b_sha256"`
	ArtifactSize    int64  `json:"artifact_size_bytes"`
	ByteIdentical   bool   `json:"byte_identical"`
	CrossHostStatus string `json:"cross_host_windows_linux"`
}

type acceptanceStatus struct {
	Schema          string         `json:"schema"`
	LocalHost       map[string]any `json:"local_host"`
	MergeEligible   bool           `json:"merge_eligible"`
	ProductionReady bool           `json:"production_ready"`
	VPNPresent      bool           `json:"vpn_runtime_present"`
}

func main() {
	write := flag.Bool("write", false, "write canonical evidence instead of checking it")
	apkSummary := flag.String("apk-summary", "", "print a deterministic ZIP-entry fingerprint for an APK and exit")
	flag.Parse()
	root, err := repositoryRoot()
	if err != nil {
		fail(err)
	}
	if *apkSummary != "" {
		path := *apkSummary
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, filepath.FromSlash(path))
		}
		summary, err := apkEntrySummary(path)
		if err != nil {
			fail(err)
		}
		fmt.Print(summary)
		return
	}
	artifacts, err := generate(root)
	if err != nil {
		fail(err)
	}
	for _, item := range artifacts {
		target := filepath.Join(root, item.path)
		if *write {
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				fail(err)
			}
			if err := os.WriteFile(target, item.data, 0o644); err != nil {
				fail(err)
			}
			continue
		}
		existing, err := os.ReadFile(target)
		if err != nil {
			fail(fmt.Errorf("%s: %w; run go run ./cmd/phase9evidence -write", item.path, err))
		}
		if !bytes.Equal(existing, item.data) {
			fail(fmt.Errorf(
				"%s is stale: existing_sha256=%s generated_sha256=%s first_difference=%s; run go run ./cmd/phase9evidence -write and review the diff",
				item.path,
				bytesSHA256(existing),
				bytesSHA256(item.data),
				firstJSONDifference(existing, item.data),
			))
		}
	}
	if *write {
		fmt.Println("PHASE 9 EVIDENCE WRITTEN")
	} else {
		fmt.Println("PHASE 9 EVIDENCE VERIFIED")
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "phase9evidence: %v\n", err)
	os.Exit(1)
}

func repositoryRoot() (string, error) {
	current, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if fileExists(filepath.Join(current, "go.mod")) && fileExists(filepath.Join(current, "android", "settings.gradle.kts")) {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", errors.New("repository root not found")
		}
		current = parent
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func generate(root string) ([]artifact, error) {
	if err := verifyCanonicalAndroidText(root); err != nil {
		return nil, err
	}
	if err := verifyFixedEvidence(root); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(root, sourceBOMPath))
	if err != nil {
		return nil, fmt.Errorf("read generated CycloneDX report: %w", err)
	}
	var bom map[string]any
	if err := json.Unmarshal(raw, &bom); err != nil {
		return nil, fmt.Errorf("decode generated CycloneDX report: %w", err)
	}
	if bom["bomFormat"] != "CycloneDX" || bom["specVersion"] != "1.6" {
		return nil, errors.New("generated report is not CycloneDX 1.6")
	}
	canonicalizeBOM(bom)
	canonical, err := marshalStable(bom)
	if err != nil {
		return nil, err
	}
	spdx, err := buildSPDX(bom)
	if err != nil {
		return nil, err
	}
	spdxBytes, err := marshalStable(spdx)
	if err != nil {
		return nil, err
	}
	toolchain, err := buildToolchainManifest(root)
	if err != nil {
		return nil, err
	}
	toolchainBytes, err := marshalStable(toolchain)
	if err != nil {
		return nil, err
	}
	return []artifact{
		{path: filepath.Join(evidenceDir, "android-sbom.cdx.json"), data: canonical},
		{path: filepath.Join(evidenceDir, "android-licenses.spdx.json"), data: spdxBytes},
		{path: filepath.Join(evidenceDir, "toolchain-manifest.json"), data: toolchainBytes},
	}, nil
}

func verifyCanonicalAndroidText(root string) error {
	androidRoot := filepath.Join(root, "android")
	return filepath.WalkDir(androidRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".cxx", ".gradle", ".idea", "build":
				if path != androidRoot {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !isCanonicalAndroidText(entry.Name()) {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(raw, []byte{'\r'}) {
			relative, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			return fmt.Errorf("%s contains CR bytes; Android source and configuration files must use canonical LF", filepath.ToSlash(relative))
		}
		return nil
	})
}

func isCanonicalAndroidText(name string) bool {
	if name == "gradlew" || strings.HasSuffix(name, ".lockfile") {
		return true
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".c", ".h", ".json", ".kt", ".kts", ".pro", ".properties", ".toml", ".xml":
		return true
	default:
		return false
	}
}

func verifyFixedEvidence(root string) error {
	var reproducibility reproducibilityReport
	if err := readJSON(
		filepath.Join(root, evidenceDir, "reproducibility-report.json"),
		&reproducibility,
	); err != nil {
		return err
	}
	if reproducibility.Schema != "kurdistan.phase9.reproducibility-report.v1" ||
		reproducibility.Environment.OperatingSystem == "" ||
		!reproducibility.ByteIdentical ||
		reproducibility.BuildASHA256 != reproducibility.BuildBSHA256 ||
		reproducibility.CrossHostStatus != "[UNVERIFIED]" {
		return errors.New("reproducibility report has an invalid or overstated result")
	}
	if _, err := verifyReproducibilityArtifact(root, reproducibility); err != nil {
		return err
	}

	var acceptance acceptanceStatus
	if err := readJSON(filepath.Join(root, evidenceDir, "acceptance-status.json"), &acceptance); err != nil {
		return err
	}
	recordedHash, _ := acceptance.LocalHost["release_apk_sha256"].(string)
	if acceptance.Schema != "kurdistan.phase9.acceptance-status.v1" ||
		acceptance.MergeEligible || acceptance.ProductionReady || acceptance.VPNPresent ||
		recordedHash != reproducibility.BuildASHA256 {
		return errors.New("acceptance status is stale or overstates Phase 9")
	}
	var provenance struct {
		Schema string `json:"schema"`
		Assets []struct {
			Path           string `json:"path"`
			ExternalSource bool   `json:"external_source"`
		} `json:"assets"`
		ThirdParty []any `json:"third_party_brand_assets"`
	}
	if err := readJSON(filepath.Join(root, evidenceDir, "asset-provenance.json"), &provenance); err != nil {
		return err
	}
	if provenance.Schema != "kurdistan.phase9.asset-provenance.v1" ||
		len(provenance.Assets) == 0 || len(provenance.ThirdParty) != 0 {
		return errors.New("asset provenance is incomplete")
	}
	for _, asset := range provenance.Assets {
		if asset.ExternalSource || !fileExists(filepath.Join(root, filepath.FromSlash(asset.Path))) {
			return fmt.Errorf("asset provenance is invalid for %q", asset.Path)
		}
	}
	return nil
}

func verifyReproducibilityArtifact(root string, reproducibility reproducibilityReport) (string, error) {
	artifactPath := filepath.Join(root, filepath.FromSlash(reproducibility.Artifact))
	info, err := os.Stat(artifactPath)
	if err != nil {
		return "", fmt.Errorf("reproducibility artifact: %w", err)
	}
	hash, err := fileSHA256(artifactPath)
	if err != nil {
		return "", err
	}
	if strings.EqualFold(reproducibility.Environment.OperatingSystem, runtime.GOOS) &&
		(hash != reproducibility.BuildASHA256 || info.Size() != reproducibility.ArtifactSize) {
		summary, summaryErr := apkEntrySummary(artifactPath)
		if summaryErr != nil {
			summary = "unavailable: " + summaryErr.Error()
		}
		return "", fmt.Errorf(
			"release APK differs from the recorded %s reproducibility result: sha256=%s size=%d want_sha256=%s want_size=%d\napk_entry_summary:\n%s",
			reproducibility.Environment.OperatingSystem,
			hash,
			info.Size(),
			reproducibility.BuildASHA256,
			reproducibility.ArtifactSize,
			summary,
		)
	}
	return hash, nil
}

func apkEntrySummary(path string) (string, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer reader.Close()
	var summary strings.Builder
	for index, entry := range reader.File {
		raw, err := entry.OpenRaw()
		if err != nil {
			return "", fmt.Errorf("open raw APK entry %q: %w", entry.Name, err)
		}
		rawHash, err := readerSHA256(raw)
		if err != nil {
			return "", fmt.Errorf("hash raw APK entry %q: %w", entry.Name, err)
		}
		content, err := entry.Open()
		if err != nil {
			return "", fmt.Errorf("open APK entry %q: %w", entry.Name, err)
		}
		contentHash, hashErr := readerSHA256(content)
		closeErr := content.Close()
		if hashErr != nil {
			return "", fmt.Errorf("hash APK entry %q: %w", entry.Name, hashErr)
		}
		if closeErr != nil {
			return "", fmt.Errorf("close APK entry %q: %w", entry.Name, closeErr)
		}
		fmt.Fprintf(
			&summary,
			"%04d|%s|method=%d|flags=%d|crc32=%08x|compressed=%d|uncompressed=%d|modified=%s|external=%08x|extra=%s|raw=%s|content=%s\n",
			index,
			entry.Name,
			entry.Method,
			entry.Flags,
			entry.CRC32,
			entry.CompressedSize64,
			entry.UncompressedSize64,
			entry.Modified.UTC().Format("2006-01-02T15:04:05Z"),
			entry.ExternalAttrs,
			bytesSHA256(entry.Extra),
			rawHash,
			contentHash,
		)
	}
	return summary.String(), nil
}

func readerSHA256(reader io.Reader) (string, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, reader); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func readJSON(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func canonicalizeBOM(bom map[string]any) {
	delete(bom, "serialNumber")
	if metadata, ok := bom["metadata"].(map[string]any); ok {
		delete(metadata, "timestamp")
	}
	canonicalizeBOMValue(bom)
}

// canonicalizeBOMValue sorts only CycloneDX collections whose ordering carries
// no meaning. Gradle can discover these values in a different order on Windows
// and Linux even when the resolved dependency graph is identical.
func canonicalizeBOMValue(value any) {
	switch current := value.(type) {
	case map[string]any:
		canonicalizeProjectVCSReference(current)
		for key, child := range current {
			canonicalizeBOMValue(child)
			values, ok := child.([]any)
			if !ok || !isUnorderedBOMCollection(key) {
				continue
			}
			sort.SliceStable(values, func(i, j int) bool {
				return bomCollectionSortKey(key, values[i]) < bomCollectionSortKey(key, values[j])
			})
		}
	case []any:
		for _, child := range current {
			canonicalizeBOMValue(child)
		}
	}
}

func canonicalizeProjectVCSReference(value map[string]any) {
	if stringValue(value["type"]) == "vcs" && stringValue(value["url"]) == projectRepositoryGit {
		value["url"] = projectRepository
	}
}

func isUnorderedBOMCollection(key string) bool {
	switch key {
	case "components", "dependencies", "dependsOn", "externalReferences", "hashes", "licenses", "properties":
		return true
	default:
		return false
	}
}

func bomCollectionSortKey(collection string, value any) string {
	object, _ := value.(map[string]any)
	switch collection {
	case "components":
		if ref := stringValue(object["bom-ref"]); ref != "" {
			return ref
		}
	case "dependencies":
		if ref := stringValue(object["ref"]); ref != "" {
			return ref
		}
	case "hashes":
		return stringValue(object["alg"]) + "\x00" + stringValue(object["content"])
	case "externalReferences":
		return stringValue(object["type"]) + "\x00" + stringValue(object["url"])
	case "properties":
		return stringValue(object["name"]) + "\x00" + stringValue(object["value"])
	}
	return canonicalJSONKey(value)
}

func canonicalJSONKey(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(data)
}

func firstJSONDifference(left, right []byte) string {
	var leftValue any
	var rightValue any
	if err := json.Unmarshal(left, &leftValue); err != nil {
		return "existing JSON cannot be decoded: " + err.Error()
	}
	if err := json.Unmarshal(right, &rightValue); err != nil {
		return "generated JSON cannot be decoded: " + err.Error()
	}
	if difference := compareJSON("$", leftValue, rightValue); difference != "" {
		return difference
	}
	return "JSON values are equal but serialized bytes differ"
}

func compareJSON(path string, left, right any) string {
	switch leftValue := left.(type) {
	case map[string]any:
		rightValue, ok := right.(map[string]any)
		if !ok {
			return formatJSONDifference(path, left, right)
		}
		keys := make([]string, 0, len(leftValue)+len(rightValue))
		seen := make(map[string]bool, len(leftValue)+len(rightValue))
		for key := range leftValue {
			keys = append(keys, key)
			seen[key] = true
		}
		for key := range rightValue {
			if !seen[key] {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			leftChild, leftOK := leftValue[key]
			rightChild, rightOK := rightValue[key]
			childPath := path + "." + key
			if !leftOK || !rightOK {
				return fmt.Sprintf("%s presence differs: existing=%t generated=%t", childPath, leftOK, rightOK)
			}
			if difference := compareJSON(childPath, leftChild, rightChild); difference != "" {
				return difference
			}
		}
	case []any:
		rightValue, ok := right.([]any)
		if !ok || len(leftValue) != len(rightValue) {
			return formatJSONDifference(path, left, right)
		}
		for index := range leftValue {
			if difference := compareJSON(fmt.Sprintf("%s[%d]", path, index), leftValue[index], rightValue[index]); difference != "" {
				return difference
			}
		}
	default:
		if canonicalJSONKey(left) != canonicalJSONKey(right) {
			return formatJSONDifference(path, left, right)
		}
	}
	return ""
}

func formatJSONDifference(path string, left, right any) string {
	return fmt.Sprintf(
		"%s existing=%s generated=%s",
		path,
		boundedJSONValue(left),
		boundedJSONValue(right),
	)
}

func boundedJSONValue(value any) string {
	const maximum = 256
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%T", value)
	}
	if len(data) <= maximum {
		return string(data)
	}
	return string(data[:maximum]) + "..."
}

func buildSPDX(bom map[string]any) (spdxDocument, error) {
	document := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "KurdistanVPN-Android-release-dependencies",
		DocumentNamespace: "https://github.com/saroo98/kurdistan-protocol-compiler/spdx/phase9/0.9.0",
		CreationInfo: spdxCreationInfo{
			Created:  "2026-07-28T00:00:00Z",
			Creators: []string{"Tool: phase9evidence-v1"},
		},
	}
	components, ok := bom["components"].([]any)
	if !ok {
		return spdxDocument{}, errors.New("CycloneDX report has no components")
	}
	for _, value := range components {
		component, ok := value.(map[string]any)
		if !ok {
			return spdxDocument{}, errors.New("CycloneDX component is not an object")
		}
		group := stringValue(component["group"])
		if group == "org.kurdistanvpn" {
			continue
		}
		name := stringValue(component["name"])
		version := stringValue(component["version"])
		purl := stringValue(component["purl"])
		if name == "" || purl == "" {
			return spdxDocument{}, fmt.Errorf("external component lacks name or purl: %v", component["bom-ref"])
		}
		license, err := componentLicense(component)
		if err != nil {
			return spdxDocument{}, fmt.Errorf("%s: %w", purl, err)
		}
		id := "SPDXRef-Package-" + shortHash(purl)
		document.Packages = append(document.Packages, spdxPackage{
			Name:             strings.Trim(strings.Join([]string{group, name}, ":"), ":"),
			SPDXID:           id,
			VersionInfo:      version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			LicenseConcluded: "NOASSERTION",
			LicenseDeclared:  license,
			CopyrightText:    "NOASSERTION",
			ExternalRefs: []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  purl,
			}},
		})
		document.Relationships = append(document.Relationships, spdxRelationship{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: id,
		})
	}
	sort.Slice(document.Packages, func(i, j int) bool { return document.Packages[i].SPDXID < document.Packages[j].SPDXID })
	sort.Slice(document.Relationships, func(i, j int) bool {
		return document.Relationships[i].RelatedSPDXElement < document.Relationships[j].RelatedSPDXElement
	})
	if len(document.Packages) == 0 {
		return spdxDocument{}, errors.New("SPDX inventory would be empty")
	}
	return document, nil
}

func componentLicense(component map[string]any) (string, error) {
	values, ok := component["licenses"].([]any)
	if !ok || len(values) == 0 {
		return "", errors.New("declared license is missing")
	}
	var expressions []string
	for _, value := range values {
		entry, ok := value.(map[string]any)
		if !ok {
			continue
		}
		if expression := stringValue(entry["expression"]); expression != "" {
			expressions = append(expressions, expression)
			continue
		}
		license, _ := entry["license"].(map[string]any)
		if id := stringValue(license["id"]); id != "" {
			expressions = append(expressions, id)
			continue
		}
		if name := stringValue(license["name"]); name != "" {
			expressions = append(expressions, "LicenseRef-"+shortHash(name))
		}
	}
	if len(expressions) == 0 {
		return "", errors.New("declared license is unusable")
	}
	sort.Strings(expressions)
	return strings.Join(unique(expressions), " OR "), nil
}

func buildToolchainManifest(root string) (toolchainManifest, error) {
	wrapperHash, err := fileSHA256(filepath.Join(root, "android", "gradle", "wrapper", "gradle-wrapper.jar"))
	if err != nil {
		return toolchainManifest{}, err
	}
	return toolchainManifest{
		Schema:          "kurdistan.phase9.toolchain-manifest.v1",
		EvidenceVersion: "phase9-wo908-v1",
		SourceDate:      "2026-07-28",
		Android: map[string]string{
			"agp":             "9.2.1",
			"build_tools":     "36.0.0",
			"compile_sdk":     "36",
			"jdk":             "17",
			"kotlin":          "2.3.10",
			"min_sdk":         "26",
			"ndk":             "28.2.13676358",
			"target_sdk":      "36",
			"version_catalog": "android/gradle/libs.versions.toml",
		},
		Go: map[string]string{
			"module":  "kurdistan",
			"version": "1.26.5",
		},
		GradleWrapper: map[string]string{
			"distribution_sha256": "2ab2958f2a1e51120c326cad6f385153bb11ee93b3c216c5fccebfdfbb7ec6cb",
			"distribution_url":    "https://services.gradle.org/distributions/gradle-9.4.1-bin.zip",
			"jar_sha256":          wrapperHash,
			"version":             "9.4.1",
		},
		CIActionPins: map[string]string{
			"actions/checkout@v6.0.2":   "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
			"actions/setup-go@v6.4.0":   "4a3601121dd01d1626a1e23e37211e3254c1c06c",
			"actions/setup-java@v5.1.0": "f2beeb24e141e01a676f977032f5a29d81c9e27e",
		},
		ReleaseBoundaries: []string{
			"arm64-v8a only",
			"no INTERNET permission",
			"no VPN service or foreground service",
			"empty production profile-authority trust store",
			"unsigned nonproduction release artifact",
		},
	}, nil
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return bytesSHA256(data), nil
}

func bytesSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func unique(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func marshalStable(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
