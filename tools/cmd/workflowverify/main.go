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

func verifyWorkflow(path, name string) error {
	root, err := decodeYAMLFile(path)
	if err != nil {
		return err
	}
	if mappingValue(root, "on") == nil || mappingValue(root, "permissions") == nil || mappingValue(root, "jobs") == nil {
		return errors.New("workflow requires on, permissions, and jobs")
	}
	if err := validatePermissionNodes(root); err != nil {
		return err
	}
	if containsScalar(root, "pull_request_target") {
		return errors.New("pull_request_target is prohibited")
	}
	if err := inspectNode(root, strings.Contains(name, "promote") || strings.Contains(name, "sign")); err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return verifyKnownWorkflowContract(name, string(raw))
}

func verifyKnownWorkflowContract(name, content string) error {
	required := map[string][]string{
		"assurance.yml": {
			"github.workflow_sha }}:.github/workflows/assurance.yml",
			"running workflow blob $running differs from exact-subject workflow blob $subject",
			"-artifact .tools/device/app-internal.apk",
			"-artifact .tools/device/app-internal-androidTest.apk",
			"-artifact .tools/device/device-artifacts.json",
			"Get-ChildItem -LiteralPath .tools/collected -Filter '*-receipt.json' -File -Recurse",
			"name: device-log-${{ matrix.proof }}-${{ github.run_id }}-${{ github.run_attempt }}",
			"include-hidden-files: true",
			"-ref refs/subjects/${{ inputs.sha || github.sha }}",
		},
		"candidate.yml": {
			"assurance_run_attempt:",
			"pattern: shadow-*-${{ inputs.assurance_run_id }}-${{ inputs.assurance_run_attempt }}",
			"Copy-Item -LiteralPath $receipt.FullName -Destination (Join-Path .tools/collected $receipt.Name)",
			"Normalize deterministic SBOM and refresh candidate metadata",
		},
		"pr.yml": {
			"-artifact .tools/device/app-internal.apk",
			"-artifact .tools/device/app-internal-androidTest.apk",
			"-artifact .tools/device/device-artifacts.json",
			"ref: ${{ github.event.pull_request.head.sha }}",
			"git diff --name-only --no-renames",
			"include-hidden-files: true",
			"-ref 'refs/subjects/${{ github.event.pull_request.head.sha }}'",
			"'dependency-freshness'",
		},
		"scheduled.yml": {
			"-proof dependency-freshness",
			"dependency-freshness-receipt.json",
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

func validatePermissionNodes(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		for index := 0; index < len(node.Content); index += 2 {
			key, value := node.Content[index].Value, node.Content[index+1]
			if key == "permissions" {
				if value.Kind != yaml.MappingNode {
					return errors.New("permissions must be an explicit mapping")
				}
				for permission := 0; permission < len(value.Content); permission += 2 {
					level := value.Content[permission+1]
					if level.Kind != yaml.ScalarNode || (level.Value != "read" && level.Value != "none") {
						return fmt.Errorf("Phase 16 workflow permission %q must be read or none", value.Content[permission].Value)
					}
				}
			}
			if err := validatePermissionNodes(value); err != nil {
				return err
			}
		}
		return nil
	}
	for _, child := range node.Content {
		if err := validatePermissionNodes(child); err != nil {
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
