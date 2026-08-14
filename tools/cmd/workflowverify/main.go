// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command workflowverify validates GitHub workflow structure without granting
// any workflow or release authority.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxWorkflowBytes = 1 << 20

var actionPin = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$`)

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	if err := verifyRoot(*root); err != nil {
		fmt.Fprintln(os.Stderr, "WORKFLOW VERIFICATION FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("WORKFLOW VERIFICATION PASSED")
}

func verifyRoot(root string) error {
	directory := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return errors.New("no workflows found")
	}
	sort.Strings(names)
	for _, name := range names {
		if err := verifyWorkflow(filepath.Join(directory, name), name); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if workflowReferencesEmulatorProof(directory, names) {
		if err := verifyEmulatorProofScript(filepath.Join(root, "tools", "scripts", "run-android-emulator-proof.ps1")); err != nil {
			return err
		}
	}
	actionsRoot := filepath.Join(root, ".github", "actions")
	if err := filepath.WalkDir(actionsRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Name() != "action.yml" && entry.Name() != "action.yaml" {
			return nil
		}
		if err := verifyAction(path); err != nil {
			return fmt.Errorf("%s: %w", filepath.ToSlash(path), err)
		}
		return nil
	}); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func workflowReferencesEmulatorProof(directory string, names []string) bool {
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(directory, name))
		if err == nil && strings.Contains(string(raw), "run-android-emulator-proof.ps1") {
			return true
		}
	}
	return false
}

func verifyEmulatorProofScript(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read Android emulator proof script: %w", err)
	}
	content := string(raw)
	for _, token := range []string{
		"$env:ANDROID_AVD_HOME = $avdHome",
		"$env:RUNNER_TEMP",
		"& $emulator '-list-avds'",
		"$process.HasExited",
		"adb emulator discovery timed out",
		"-not (Test-Path -LiteralPath $GateReceipt)",
		"$emulatorIdentity = \".tools/phase17/emulator-api$Api-identity.json\"",
		"kurdistan-emulator-package-identity-v1",
		"Resolve-SdkPackageMetadata",
		"source.properties",
		"$emulatorPackageRevision = Get-SdkPackageRevision",
		"$emulatorVersionSource = if ($emulatorVersionMatch.Success)",
		"Remove-Item -LiteralPath $rawPostRunLogcat, $rawEmulatorLog, $rawEmulatorError",
	} {
		if !strings.Contains(content, token) {
			return fmt.Errorf("Android emulator proof script is missing fail-closed contract %q", token)
		}
	}
	if strings.Contains(content, "& $adb wait-for-device") {
		return errors.New("Android emulator proof script uses unbounded adb wait-for-device")
	}
	if strings.Contains(content, "Join-Path '.tools/phase16' \"avd-api$Api\"") {
		return errors.New("Android emulator proof script stores disposable AVD state in uploaded evidence")
	}
	for _, prohibited := range []string{".tools/phase17/emulator-api$Api.log", ".tools/phase17/logcat-api$Api.txt"} {
		if strings.Contains(content, prohibited) {
			return errors.New("Android emulator proof script stores raw diagnostic output in uploaded evidence")
		}
	}
	return nil
}

func verifyWorkflow(path, name string) error {
	root, err := decodeYAMLFile(path)
	if err != nil {
		return err
	}
	if mappingValue(root, "on") == nil || mappingValue(root, "permissions") == nil || mappingValue(root, "jobs") == nil {
		return errors.New("workflow requires on, permissions, and jobs")
	}
	allowOIDC := name == "phase16-production-plan.yml" || name == "phase16-production-apply.yml" || name == "phase16-drill.yml"
	if err := validatePermissionNodes(root, allowOIDC); err != nil {
		return err
	}
	if containsScalar(root, "pull_request_target") {
		return errors.New("pull_request_target is prohibited")
	}
	if err := inspectNode(root, strings.Contains(name, "promote") || strings.Contains(name, "sign")); err != nil {
		return err
	}
	if name == "assurance.yml" {
		if err := verifyAssuranceQualificationTopology(root); err != nil {
			return err
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return verifyKnownWorkflowContract(name, string(raw))
}

func verifyAssuranceQualificationTopology(root *yaml.Node) error {
	jobs := mappingValue(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return errors.New("assurance workflow jobs must be a mapping")
	}
	goProof := mappingValue(jobs, "go-proof")
	if goProof == nil || goProof.Kind != yaml.MappingNode {
		return errors.New("assurance workflow is missing the receipt-producing go-proof job")
	}
	strategy := mappingValue(goProof, "strategy")
	matrix := mappingValue(strategy, "matrix")
	include := mappingValue(matrix, "include")
	if include == nil || include.Kind != yaml.SequenceNode {
		return errors.New("assurance go-proof receipt matrix is missing")
	}
	for _, lane := range include.Content {
		if lane.Kind != yaml.MappingNode {
			return errors.New("assurance go-proof receipt lane must be a mapping")
		}
		proof := mappingValue(lane, "proof")
		if proof != nil && proof.Kind == yaml.ScalarNode && proof.Value == "phase17-qualification" {
			return errors.New("Phase 17 qualification must not widen the immutable assurance receipt authority")
		}
	}

	qualification := mappingValue(jobs, "phase17-qualification")
	if qualification == nil || qualification.Kind != yaml.MappingNode {
		return errors.New("assurance workflow is missing the required non-receipt Phase 17 qualification job")
	}
	runsOn := mappingValue(qualification, "runs-on")
	if runsOn == nil || runsOn.Kind != yaml.ScalarNode || runsOn.Value != "${{ matrix.os }}" {
		return errors.New("Phase 17 qualification must run on its exact OS matrix")
	}
	qualificationStrategy := mappingValue(qualification, "strategy")
	qualificationMatrix := mappingValue(qualificationStrategy, "matrix")
	operatingSystems := mappingValue(qualificationMatrix, "os")
	if !exactScalarSet(operatingSystems, []string{"ubuntu-24.04", "windows-2025"}) {
		return errors.New("Phase 17 qualification must run exactly on ubuntu-24.04 and windows-2025")
	}
	if !nodeContainsCommand(qualification, "go run ./cmd/gate -proof phase17-qualification") {
		return errors.New("Phase 17 qualification job is missing its exact gate command")
	}
	if nodeContainsSubstring(qualification, "cmd/assure receipt") || nodeContainsSubstring(qualification, "-receipt") {
		return errors.New("Phase 17 qualification job must not issue or upload assurance receipts")
	}
	if !nodeContainsExactScalar(mappingValue(qualification, "needs"), "policy") {
		return errors.New("Phase 17 qualification must depend on workflow policy verification")
	}

	certificate := mappingValue(jobs, "certificate")
	if certificate == nil || certificate.Kind != yaml.MappingNode || !nodeContainsExactScalar(mappingValue(certificate, "needs"), "phase17-qualification") {
		return errors.New("assurance certificate must fail closed on Phase 17 qualification")
	}
	return nil
}

func exactScalarSet(node *yaml.Node, expected []string) bool {
	if node == nil || node.Kind != yaml.SequenceNode || len(node.Content) != len(expected) {
		return false
	}
	want := make(map[string]bool, len(expected))
	for _, value := range expected {
		want[value] = true
	}
	for _, child := range node.Content {
		if child.Kind != yaml.ScalarNode || !want[child.Value] {
			return false
		}
		delete(want, child.Value)
	}
	return len(want) == 0
}

func nodeContainsExactScalar(node *yaml.Node, wanted string) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.ScalarNode && node.Value == wanted {
		return true
	}
	for _, child := range node.Content {
		if nodeContainsExactScalar(child, wanted) {
			return true
		}
	}
	return false
}

func nodeContainsCommand(node *yaml.Node, wanted string) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.MappingNode {
		for index := 0; index < len(node.Content); index += 2 {
			if node.Content[index].Value == "run" && node.Content[index+1].Kind == yaml.ScalarNode && strings.TrimSpace(node.Content[index+1].Value) == wanted {
				return true
			}
			if nodeContainsCommand(node.Content[index+1], wanted) {
				return true
			}
		}
		return false
	}
	for _, child := range node.Content {
		if nodeContainsCommand(child, wanted) {
			return true
		}
	}
	return false
}

func nodeContainsSubstring(node *yaml.Node, wanted string) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.ScalarNode && strings.Contains(node.Value, wanted) {
		return true
	}
	for _, child := range node.Content {
		if nodeContainsSubstring(child, wanted) {
			return true
		}
	}
	return false
}

func verifyKnownWorkflowContract(name, content string) error {
	required := map[string][]string{
		"assurance.yml": {
			"github.workflow_sha }}^{commit}",
			"-workflow-source-commit ${{ github.workflow_sha }}",
			"pattern: device-artifacts-${{ github.run_id }}-*",
			"path: .tools/device-attempts",
			"Select newest available device artifact attempt",
			"-artifact .tools/device/app-internal.apk",
			"-artifact .tools/device/app-internal-androidTest.apk",
			"-artifact .tools/device/device-artifacts.json",
			"-artifact .tools/phase17/emulator-api${{ matrix.api }}-identity.json",
			"pattern: shadow-*-${{ github.run_id }}-*",
			"path: .tools/collected-attempts",
			"Select newest receipt for each proof identity",
			"$safeName = ($identity -replace '[^A-Za-z0-9._-]', '_') + '-receipt.json'",
			"Get-ChildItem -LiteralPath .tools/collected -Filter '*-receipt.json' -File -Recurse",
			"name: device-log-${{ matrix.proof }}-${{ github.run_id }}-${{ github.run_attempt }}",
			"include-hidden-files: true",
			"-ref refs/subjects/${{ inputs.sha || github.sha }}",
			"expected 16 proof receipts",
			"'-required', 'go-executable-evidence'",
			"'-required', 'linux-netns'",
			"-required', 'dependency-freshness'",
			"-required', 'docs-evidence'",
			"-proof android-host",
		},
		"candidate.yml": {
			"assurance_run_attempt:",
			"if ('${{ github.ref }}' -cne 'refs/heads/main')",
			"refs/heads/main:refs/remotes/origin/main",
			"actions/runs/${{ inputs.assurance_run_id }}/attempts/${{ inputs.assurance_run_attempt }}",
			".github/workflows/assurance.yml",
			"pattern: shadow-*-${{ inputs.assurance_run_id }}-${{ inputs.assurance_run_attempt }}",
			"expected 16 receipts",
			"-required go-executable-evidence",
			"-required linux-netns",
			"expected one API $api emulator identity",
			"expected three emulator identity inventories",
			"Copy-Item -LiteralPath $receipt.FullName -Destination (Join-Path .tools/collected $receipt.Name)",
			"-expected-run-id '${{ inputs.assurance_run_id }}'",
			"-expected-run-attempt '${{ inputs.assurance_run_attempt }}'",
			"-expected-workflow-path .github/workflows/assurance.yml",
			"-required dependency-freshness",
			"-required docs-evidence",
			"Normalize deterministic SBOM and refresh candidate metadata",
			"candidate-provenance.json",
			"candidate validate",
			"verified-assurance/**",
		},
		"pr.yml": {
			"ref: ${{ github.event.pull_request.base.sha }}",
			"Check out protected base enforcement tooling",
			"-workflow-source-commit '${{ github.workflow_sha }}'",
			"-artifact .tools/device/app-internal.apk",
			"-artifact .tools/device/app-internal-androidTest.apk",
			"-artifact .tools/device/device-artifacts.json",
			"-artifact .tools/phase17/emulator-api${{ matrix.api }}-identity.json",
			"ref: ${{ github.event.pull_request.head.sha }}",
			"git diff --name-only --no-renames",
			"include-hidden-files: true",
			"-ref 'refs/subjects/${{ github.event.pull_request.head.sha }}'",
			"'dependency-freshness'",
			"'linux-netns-contract'",
			"-proof android-pr-host",
			"android-pr-host-receipt.json",
		},
		"scheduled.yml": {
			"-proof dependency-freshness",
			"dependency-freshness-receipt.json",
			"-workflow-source-commit '${{ github.workflow_sha }}'",
			"include-hidden-files: true",
		},
	}
	for _, token := range required[name] {
		if !strings.Contains(content, token) {
			return fmt.Errorf("workflow is missing required evidence-preservation contract %q", token)
		}
	}
	return nil
}

func validatePermissionNodes(node *yaml.Node, allowOIDC bool) error {
	if node.Kind == yaml.MappingNode {
		for index := 0; index < len(node.Content); index += 2 {
			key, value := node.Content[index].Value, node.Content[index+1]
			if key == "permissions" {
				if value.Kind != yaml.MappingNode {
					return errors.New("permissions must be an explicit mapping")
				}
				for permission := 0; permission < len(value.Content); permission += 2 {
					level := value.Content[permission+1]
					allowed := level.Value == "read" || level.Value == "none" || (allowOIDC && value.Content[permission].Value == "id-token" && level.Value == "write")
					if level.Kind != yaml.ScalarNode || !allowed {
						return fmt.Errorf("Phase 16 workflow permission %q must be read or none", value.Content[permission].Value)
					}
				}
			}
			if err := validatePermissionNodes(value, allowOIDC); err != nil {
				return err
			}
		}
		return nil
	}
	for _, child := range node.Content {
		if err := validatePermissionNodes(child, allowOIDC); err != nil {
			return err
		}
	}
	return nil
}

func verifyAction(path string) error {
	root, err := decodeYAMLFile(path)
	if err != nil {
		return err
	}
	if mappingValue(root, "name") == nil || mappingValue(root, "description") == nil || mappingValue(root, "runs") == nil {
		return errors.New("composite action requires name, description, and runs")
	}
	return inspectNode(root, false)
}

func decodeYAMLFile(path string) (*yaml.Node, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxWorkflowBytes {
		return nil, errors.New("YAML input is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var document yaml.Node
	decoder := yaml.NewDecoder(io.LimitReader(file, maxWorkflowBytes+1))
	decoder.KnownFields(false)
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("YAML input contains trailing document")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("YAML root must be one mapping")
	}
	root := document.Content[0]
	if err := rejectDuplicateKeys(root); err != nil {
		return nil, err
	}
	return root, nil
}

func rejectDuplicateKeys(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index].Value
			if seen[key] {
				return fmt.Errorf("duplicate YAML key %q", key)
			}
			seen[key] = true
			if err := rejectDuplicateKeys(node.Content[index+1]); err != nil {
				return err
			}
		}
		return nil
	}
	for _, child := range node.Content {
		if err := rejectDuplicateKeys(child); err != nil {
			return err
		}
	}
	return nil
}

func inspectNode(node *yaml.Node, prohibitBuild bool) error {
	if node.Kind == yaml.MappingNode {
		for index := 0; index < len(node.Content); index += 2 {
			key, value := node.Content[index].Value, node.Content[index+1]
			if key == "uses" && value.Kind == yaml.ScalarNode {
				uses := value.Value
				if !strings.HasPrefix(uses, "./") && !actionPin.MatchString(uses) {
					return fmt.Errorf("external action is not pinned to a full commit: %s", uses)
				}
			}
			if prohibitBuild && key == "run" && value.Kind == yaml.ScalarNode && containsBuildCommand(value.Value) {
				return errors.New("signing or promotion workflow contains a build command")
			}
			if err := inspectNode(value, prohibitBuild); err != nil {
				return err
			}
		}
		return nil
	}
	for _, child := range node.Content {
		if err := inspectNode(child, prohibitBuild); err != nil {
			return err
		}
	}
	return nil
}

func mappingValue(mapping *yaml.Node, wanted string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == wanted {
			return mapping.Content[index+1]
		}
	}
	return nil
}

func containsScalar(node *yaml.Node, wanted string) bool {
	if node.Kind == yaml.ScalarNode && node.Value == wanted {
		return true
	}
	for _, child := range node.Content {
		if containsScalar(child, wanted) {
			return true
		}
	}
	return false
}

func containsBuildCommand(command string) bool {
	lower := strings.ToLower(command)
	for _, prohibited := range []string{"gradlew", "gradle ", "go build", "go test", "npm run build", "cargo build"} {
		if strings.Contains(lower, prohibited) {
			return true
		}
	}
	return false
}
