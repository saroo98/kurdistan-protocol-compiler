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

func TestVerifyEmulatorProofScriptRequiresSharedAVDHomeAndBoundedDiscovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run-android-emulator-proof.ps1")
	bad := `$env:ANDROID_AVD_HOME = $avdHome
$env:RUNNER_TEMP
& $emulator '-list-avds'
$process.HasExited
& $adb wait-for-device
adb emulator discovery timed out
-not (Test-Path -LiteralPath $GateReceipt)
$emulatorIdentity = ".tools/phase16/emulator-api$Api-identity.json"
kurdistan-emulator-package-identity-v1
Resolve-SdkPackageMetadata
source.properties
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
