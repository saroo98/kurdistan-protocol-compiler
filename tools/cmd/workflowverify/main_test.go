// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyWorkflowAcceptsPinnedLeastPrivilegeWorkflow(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "good.yml", `name: good
on: [workflow_dispatch]
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
`)
	if err := verifyRoot(root); err != nil {
		t.Fatalf("verify valid workflow: %v", err)
	}
}

func TestVerifyWorkflowRejectsDuplicateKeysAndFloatingActions(t *testing.T) {
	tests := map[string]string{
		"duplicate": `name: bad
on: [workflow_dispatch]
permissions: {contents: read}
permissions: {contents: write}
jobs: {}
`,
		"floating": `name: bad
on: [workflow_dispatch]
permissions: {contents: read}
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v6
`,
		"target": `name: bad
on: [pull_request_target]
permissions: {contents: read}
jobs: {}
`,
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeWorkflow(t, root, "bad.yml", content)
			if err := verifyRoot(root); err == nil {
				t.Fatal("expected workflow rejection")
			}
		})
	}
}

func TestVerifyWorkflowRejectsBuildCommandsInPromotionWorkflow(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "promote.yml", `name: promote
on: [workflow_dispatch]
permissions: {contents: read}
jobs:
  promote:
    runs-on: ubuntu-24.04
    steps:
      - run: ./gradlew bundleRelease
`)
	err := verifyRoot(root)
	if err == nil || !strings.Contains(err.Error(), "build command") {
		t.Fatalf("error = %v, want build command rejection", err)
	}
}

func TestVerifyWorkflowAllowsOIDCWriteOnlyForProtectedPhase16Workflows(t *testing.T) {
	for name, wantPass := range map[string]bool{"phase16-production-plan.yml": true, "phase16-production-apply.yml": true, "phase16-drill.yml": true, "ordinary.yml": false} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeWorkflow(t, root, name, `name: oidc
on: [workflow_dispatch]
permissions:
  contents: read
  id-token: write
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
`)
			err := verifyRoot(root)
			if (err == nil) != wantPass {
				t.Fatalf("pass=%v error=%v", wantPass, err)
			}
		})
	}
}

func TestVerifyKnownWorkflowContractRejectsAttemptAmbiguityAndUnboundDeviceBytes(t *testing.T) {
	for name, content := range map[string]string{
		"assurance.yml": "name: incomplete assurance",
		"candidate.yml": "name: incomplete candidate",
		"pr.yml":        "name: incomplete pull request",
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyKnownWorkflowContract(name, content); err == nil {
				t.Fatal("expected incomplete evidence-preservation contract to be rejected")
			}
		})
	}
}

func TestRepositoryAssuranceRequiresPhase17QualificationWithoutWideningReceiptAuthority(t *testing.T) {
	path := filepath.Join("..", "..", "..", ".github", "workflows", "assurance.yml")
	root, err := decodeYAMLFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAssuranceQualificationTopology(root); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryCarriesOnePortableAssuranceBundleIntoCandidateBuild(t *testing.T) {
	assurancePath := filepath.Join("..", "..", "..", ".github", "workflows", "assurance.yml")
	candidatePath := filepath.Join("..", "..", "..", ".github", "workflows", "candidate.yml")
	assuranceRoot, err := decodeYAMLFile(assurancePath)
	if err != nil {
		t.Fatal(err)
	}
	candidateRoot, err := decodeYAMLFile(candidatePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPortableAssuranceBundleHandoff(assuranceRoot, candidateRoot); err != nil {
		t.Fatal(err)
	}
}

func TestPortableAssuranceBundleHandoffRejectsFlattenedCandidateDownload(t *testing.T) {
	assurancePath := filepath.Join("..", "..", "..", ".github", "workflows", "assurance.yml")
	candidatePath := filepath.Join("..", "..", "..", ".github", "workflows", "candidate.yml")
	assuranceRoot, err := decodeYAMLFile(assurancePath)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(candidatePath)
	if err != nil {
		t.Fatal(err)
	}
	old := "          name: shadow-certificate-${{ inputs.assurance_run_id }}-${{ inputs.assurance_run_attempt }}\n"
	new := "          pattern: shadow-*-${{ inputs.assurance_run_id }}-${{ inputs.assurance_run_attempt }}\n          merge-multiple: true\n"
	if !strings.Contains(string(raw), old) {
		t.Fatalf("repository fixture is missing %q", old)
	}
	mutatedPath := filepath.Join(t.TempDir(), "candidate.yml")
	if err := os.WriteFile(mutatedPath, []byte(strings.Replace(string(raw), old, new, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	candidateRoot, err := decodeYAMLFile(mutatedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPortableAssuranceBundleHandoff(assuranceRoot, candidateRoot); err == nil {
		t.Fatal("flattened multi-artifact candidate handoff passed")
	}
}

func TestAssuranceQualificationTopologyRejectsAuthorityWideningAndDetachedGates(t *testing.T) {
	repositoryPath := filepath.Join("..", "..", "..", ".github", "workflows", "assurance.yml")
	raw, err := os.ReadFile(repositoryPath)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		old  string
		new  string
	}{
		{
			name: "receipt authority widened",
			old:  "          - {os: windows-2025, proof: operator}\n",
			new:  "          - {os: windows-2025, proof: operator}\n          - {os: ubuntu-24.04, proof: phase17-qualification}\n",
		},
		{
			name: "certificate detached",
			old:  "needs: [policy, go-proof, phase17-qualification, linux-netns, android-host, android-device]",
			new:  "needs: [policy, go-proof, linux-netns, android-host, android-device]",
		},
		{
			name: "windows qualification removed",
			old:  "os: [ubuntu-24.04, windows-2025]",
			new:  "os: [ubuntu-24.04]",
		},
		{
			name: "qualification issues receipt",
			old:  "run: go run ./cmd/gate -proof phase17-qualification",
			new:  "run: go run ./cmd/gate -proof phase17-qualification -receipt result.json",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !strings.Contains(string(raw), test.old) {
				t.Fatalf("repository fixture is missing %q", test.old)
			}
			path := filepath.Join(t.TempDir(), "assurance.yml")
			mutated := strings.Replace(string(raw), test.old, test.new, 1)
			if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
				t.Fatal(err)
			}
			root, err := decodeYAMLFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyAssuranceQualificationTopology(root); err == nil {
				t.Fatal("invalid assurance qualification topology accepted")
			}
		})
	}
}

func TestVerifyEmulatorProofScriptRequiresSharedAVDHomeAndBoundedDiscovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run-android-emulator-proof.ps1")
	bad := `$env:ANDROID_AVD_HOME = $avdHome
$env:RUNNER_TEMP
& $emulator '-list-avds'
$process.HasExited
& $adb wait-for-device
adb emulator discovery timed out
-not (Test-Path -LiteralPath $GateReceipt)
$emulatorIdentity = ".tools/phase17/emulator-api$Api-identity.json"
kurdistan-emulator-package-identity-v1
Resolve-SdkPackageMetadata
source.properties
$emulatorPackageRevision = Get-SdkPackageRevision
$emulatorVersionSource = if ($emulatorVersionMatch.Success)
function Install-SdkPackageWithBoundedRetry
$maxAttempts = 2
for ($attempt = 1; $attempt -le $maxAttempts; $attempt++)
Remove-Item -LiteralPath $PackageRoot -Recurse -Force
Remove-Item -LiteralPath $sdkTemp -Recurse -Force
Install-SdkPackageWithBoundedRetry -Package 'platform-tools'
Install-SdkPackageWithBoundedRetry -Package 'emulator'
Install-SdkPackageWithBoundedRetry -Package $systemImage
sdkmanager failed for required package after bounded clean retry
Remove-Item -LiteralPath $rawPostRunLogcat, $rawEmulatorLog, $rawEmulatorError
`
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyEmulatorProofScript(path); err == nil || !strings.Contains(err.Error(), "unbounded adb") {
		t.Fatalf("error = %v, want unbounded adb rejection", err)
	}

	good := strings.ReplaceAll(bad, "& $adb wait-for-device\n", "")
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyEmulatorProofScript(path); err != nil {
		t.Fatalf("verify bounded emulator proof script: %v", err)
	}
}

func TestRepositoryEmulatorProofScriptRequiresBoundedCleanSDKRetry(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "run-android-emulator-proof.ps1")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	for _, token := range []string{
		"function Install-SdkPackageWithBoundedRetry",
		"$maxAttempts = 2",
		"for ($attempt = 1; $attempt -le $maxAttempts; $attempt++)",
		"Remove-Item -LiteralPath $PackageRoot -Recurse -Force",
		"Remove-Item -LiteralPath $sdkTemp -Recurse -Force",
		"Install-SdkPackageWithBoundedRetry -Package 'platform-tools'",
		"Install-SdkPackageWithBoundedRetry -Package 'emulator'",
		"Install-SdkPackageWithBoundedRetry -Package $systemImage",
		"sdkmanager failed for required package after bounded clean retry",
	} {
		if !strings.Contains(content, token) {
			t.Fatalf("Android emulator proof script is missing bounded SDK recovery contract %q", token)
		}
	}
	if strings.Contains(content, "Remove-Item -LiteralPath $env:ANDROID_HOME -Recurse") {
		t.Fatal("Android emulator proof script must not delete the complete SDK installation")
	}
}

func writeWorkflow(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, ".github", "workflows", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
