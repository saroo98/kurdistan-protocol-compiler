// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command releaseverify validates the checked-in release metadata contract.
// It is intentionally offline and does not authorize signing, publication, or
// any other external release action.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	versionPropertiesPath = "config/release/version.properties"
	productsPath          = "config/release/products.json"
	maxGradleVersionCode  = 2_147_483_647
)

var (
	releaseVersionNamePattern   = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$`)
	androidApplicationIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$`)
)

type versionProperties struct {
	Name string
	Code int
}

type releaseProducts struct {
	Schema  string          `json:"schema"`
	Android androidProduct  `json:"android"`
	Go      publicGoProduct `json:"go"`
}

type androidProduct struct {
	ApplicationID         string     `json:"applicationId"`
	InternalApplicationID string     `json:"internalApplicationId"`
	PublishAAB            *bool      `json:"publishAab"`
	PublishInspectionAPK  *bool      `json:"publishInspectionApk"`
	ReleaseABIs           []string   `json:"releaseAbis"`
	MinSDK                int        `json:"minSdk"`
	TargetSDK             int        `json:"targetSdk"`
	Play                  playTracks `json:"play"`
}

type playTracks struct {
	TestTrack       string `json:"testTrack"`
	ProductionTrack string `json:"productionTrack"`
}

type publicGoProduct struct {
	ApprovedCommands []string          `json:"approvedCommands"`
	Targets          []json.RawMessage `json:"targets"`
}

func main() {
	if err := runCommand(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "RELEASE METADATA VERIFICATION FAILED: %v\n", err)
		os.Exit(1)
	}
}

type artifactSpecList []artifactSpec

func (values *artifactSpecList) String() string {
	parts := make([]string, 0, len(*values))
	for _, value := range *values {
		parts = append(parts, value.Name+"="+value.Pattern)
	}
	return strings.Join(parts, ",")
}

func (values *artifactSpecList) Set(value string) error {
	name, pattern, ok := strings.Cut(value, "=")
	if !ok || name == "" || pattern == "" {
		return errors.New("artifact must use name=repository-relative-path-or-glob")
	}
	*values = append(*values, artifactSpec{Name: name, Pattern: pattern})
	return nil
}

func runCommand(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("releaseverify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	artifactSubject := flags.String("artifact-subject", "", "DEVICE_TEST_SET or UNSIGNED_ENGINEERING_CANDIDATE")
	artifactOutput := flags.String("artifact-metadata", "", "repository-relative artifact metadata output path")
	var artifacts artifactSpecList
	flags.Var(&artifacts, "artifact", "repeatable name=repository-relative-path-or-glob artifact input")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("releaseverify does not accept positional arguments")
	}
	if err := verify(*root); err != nil {
		return err
	}
	metadataRequested := *artifactSubject != "" || *artifactOutput != "" || len(artifacts) != 0
	if metadataRequested {
		if *artifactSubject == "" || *artifactOutput == "" || len(artifacts) == 0 {
			return errors.New("artifact-subject, artifact-metadata, and at least one artifact are required together")
		}
		version, err := loadVersionProperties(filepath.Join(*root, filepath.FromSlash(versionPropertiesPath)))
		if err != nil {
			return err
		}
		if err := writeArtifactMetadata(*root, version, *artifactSubject, artifacts, *artifactOutput); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "ARTIFACT METADATA WRITTEN: %s\n", filepath.ToSlash(*artifactOutput))
	}
	fmt.Fprintln(stdout, "RELEASE METADATA VERIFICATION PASSED (OFFLINE CONFIGURATION ONLY)")
	return nil
}

func verify(root string) error {
	version, err := loadVersionProperties(filepath.Join(root, filepath.FromSlash(versionPropertiesPath)))
	if err != nil {
		return err
	}
	products, err := loadProducts(filepath.Join(root, filepath.FromSlash(productsPath)))
	if err != nil {
		return err
	}
	if strings.TrimSpace(version.Name) == "" || version.Code <= 0 {
		return fmt.Errorf("release version must have a non-empty name and positive code")
	}
	if err := validateProducts(products); err != nil {
		return err
	}
	return verifyGradleWiring(root, version, products)
}

func validateProducts(products releaseProducts) error {
	if products.Schema != "kpc-release-products-v1" {
		return fmt.Errorf("unsupported release products schema %q", products.Schema)
	}
	if products.Android.Play.TestTrack != "<CONFIGURE_AFTER_TRACK_DISCOVERY>" {
		return fmt.Errorf("Play test track must remain unconfigured in the offline release contract")
	}
	if products.Android.Play.ProductionTrack != "production" {
		return fmt.Errorf("Play production track identity must remain canonical and inactive")
	}
	if !androidApplicationIDPattern.MatchString(products.Android.ApplicationID) ||
		products.Android.InternalApplicationID != products.Android.ApplicationID+".internal" {
		return fmt.Errorf("Android application identities are invalid or inconsistent")
	}
	if products.Android.MinSDK <= 0 || products.Android.TargetSDK < products.Android.MinSDK {
		return fmt.Errorf("Android SDK range is invalid")
	}
	if products.Android.PublishAAB == nil || products.Android.PublishInspectionAPK == nil {
		return fmt.Errorf("Android public artifact inventory flags must be explicit")
	}
	if !*products.Android.PublishAAB || *products.Android.PublishInspectionAPK {
		return fmt.Errorf("Android public artifact inventory must contain only the future AAB product")
	}
	if len(products.Android.ReleaseABIs) == 0 {
		return fmt.Errorf("Android release ABI inventory must not be empty")
	}
	allowedABIs := map[string]bool{"arm64-v8a": true, "armeabi-v7a": true, "x86": true, "x86_64": true}
	seenABIs := map[string]bool{}
	for _, abi := range products.Android.ReleaseABIs {
		if !allowedABIs[abi] || seenABIs[abi] {
			return fmt.Errorf("Android release ABI inventory contains invalid or duplicate ABI %q", abi)
		}
		seenABIs[abi] = true
	}
	if products.Go.ApprovedCommands == nil || products.Go.Targets == nil {
		return fmt.Errorf("public Go product inventories must be explicit arrays")
	}
	if len(products.Go.ApprovedCommands) != 0 || len(products.Go.Targets) != 0 {
		return fmt.Errorf("public Go products require separate declaration authority")
	}
	return nil
}

func verifyGradleWiring(root string, version versionProperties, products releaseProducts) error {
	rootPath := filepath.Join(root, "android", "build.gradle.kts")
	rootRaw, err := os.ReadFile(rootPath)
	if err != nil {
		return fmt.Errorf("read android/build.gradle.kts: %w", err)
	}
	appPath := filepath.Join(root, "android", "app", "build.gradle.kts")
	appRaw, err := os.ReadFile(appPath)
	if err != nil {
		return fmt.Errorf("read android/app/build.gradle.kts: %w", err)
	}
	rootBuild := string(rootRaw)
	appBuild := string(appRaw)
	for _, marker := range []string{
		`rootProject.file("../config/release/version.properties")`,
		`extra["releaseVersionName"] = releaseVersionName`,
		`extra["releaseVersionCode"] = releaseVersionCode`,
		`version = releaseVersionName`,
		`componentVersion.set(releaseVersionName)`,
	} {
		if !strings.Contains(rootBuild, marker) {
			return fmt.Errorf("android/build.gradle.kts is missing centralized release marker %q", marker)
		}
	}
	for _, marker := range []string{
		`val releaseVersionName: String by rootProject.extra`,
		`val releaseVersionCode: Int by rootProject.extra`,
		`versionCode = releaseVersionCode`,
		`versionName = releaseVersionName`,
		fmt.Sprintf(`applicationId = %q`, products.Android.ApplicationID),
		`applicationIdSuffix = ".internal"`,
		fmt.Sprintf("minSdk = %d", products.Android.MinSDK),
		fmt.Sprintf("targetSdk = %d", products.Android.TargetSDK),
	} {
		if !strings.Contains(appBuild, marker) {
			return fmt.Errorf("android/app/build.gradle.kts disagrees with release metadata: missing %q", marker)
		}
	}
	for _, abi := range products.Android.ReleaseABIs {
		marker := fmt.Sprintf(`abiFilters += %q`, abi)
		if !strings.Contains(appBuild, marker) {
			return fmt.Errorf("android/app/build.gradle.kts is missing release ABI %q", abi)
		}
	}
	for _, forbidden := range []*regexp.Regexp{
		regexp.MustCompile(`(?m)^\s*version\s*=\s*"` + regexp.QuoteMeta(version.Name) + `"\s*$`),
		regexp.MustCompile(`(?m)^\s*componentVersion\.set\(\s*"` + regexp.QuoteMeta(version.Name) + `"\s*\)\s*$`),
		regexp.MustCompile(`(?m)^\s*versionCode\s*=\s*` + strconv.Itoa(version.Code) + `\s*$`),
		regexp.MustCompile(`(?m)^\s*versionName\s*=\s*"` + regexp.QuoteMeta(version.Name) + `"\s*$`),
	} {
		if forbidden.MatchString(rootBuild) || forbidden.MatchString(appBuild) {
			return fmt.Errorf("Android Gradle retains a hard-coded release version")
		}
	}
	return nil
}

func loadVersionProperties(path string) (versionProperties, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return versionProperties{}, fmt.Errorf("read %s: %w", versionPropertiesPath, err)
	}
	values := map[string]string{}
	for lineNumber, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line != strings.TrimSpace(line) {
			return versionProperties{}, fmt.Errorf("parse %s line %d: surrounding whitespace is not canonical", versionPropertiesPath, lineNumber+1)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return versionProperties{}, fmt.Errorf("parse %s line %d: expected key=value", versionPropertiesPath, lineNumber+1)
		}
		if key == "" || value == "" || key != strings.TrimSpace(key) || value != strings.TrimSpace(value) {
			return versionProperties{}, fmt.Errorf("parse %s line %d: key and value must be non-empty without surrounding whitespace", versionPropertiesPath, lineNumber+1)
		}
		if _, duplicate := values[key]; duplicate {
			return versionProperties{}, fmt.Errorf("parse %s line %d: duplicate key %q", versionPropertiesPath, lineNumber+1, key)
		}
		if key != "versionName" && key != "versionCode" {
			return versionProperties{}, fmt.Errorf("parse %s line %d: unknown key %q", versionPropertiesPath, lineNumber+1, key)
		}
		values[key] = value
	}
	code, err := strconv.Atoi(values["versionCode"])
	if err != nil {
		return versionProperties{}, fmt.Errorf("parse versionCode: %w", err)
	}
	if code <= 0 || code > maxGradleVersionCode {
		return versionProperties{}, fmt.Errorf("versionCode must be a positive Gradle integer")
	}
	name := values["versionName"]
	if !releaseVersionNamePattern.MatchString(name) {
		return versionProperties{}, fmt.Errorf("versionName %q must be a semantic release version", name)
	}
	canonical := fmt.Sprintf("versionName=%s\nversionCode=%d\n", name, code)
	if string(raw) != canonical {
		return versionProperties{}, fmt.Errorf("%s is not in canonical form", versionPropertiesPath)
	}
	return versionProperties{Name: name, Code: code}, nil
}

func loadProducts(path string) (releaseProducts, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return releaseProducts{}, fmt.Errorf("read %s: %w", productsPath, err)
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return releaseProducts{}, fmt.Errorf("decode %s: %w", productsPath, err)
	}
	var products releaseProducts
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&products); err != nil {
		return releaseProducts{}, fmt.Errorf("decode %s: %w", productsPath, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return releaseProducts{}, fmt.Errorf("decode %s: trailing JSON value", productsPath)
		}
		return releaseProducts{}, fmt.Errorf("decode %s trailing JSON: %w", productsPath, err)
	}
	return products, nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanJSONValue(decoder, "$"); err != nil {
		return err
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key at %s is not a string", path)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate object key %q at %s", key, path)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, path+"."+key); err != nil {
				return err
			}
		}
	case '[':
		for index := 0; decoder.More(); index++ {
			if err := scanJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q at %s", delimiter, path)
	}
	end, err := decoder.Token()
	if err != nil {
		return err
	}
	if end != json.Delim(map[json.Delim]rune{'{': '}', '[': ']'}[delimiter]) {
		return fmt.Errorf("mismatched JSON delimiter at %s", path)
	}
	return nil
}
