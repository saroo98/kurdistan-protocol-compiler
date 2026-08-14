// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyQualificationInfrastructureAcceptsRepository(t *testing.T) {
	if err := verifyQualificationInfrastructure(repositoryRoot(t)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyQualificationInfrastructureRejectsPolicySchemaAndBoundaryDrift(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		old      string
		new      string
		appendix string
	}{
		{
			name: "policy retry widening", path: "config/phase17/qualification-policy-v1.json",
			old: `"instrumentationLaunchAttempts": 2`, new: `"instrumentationLaunchAttempts": 3`,
		},
		{
			name: "permissive schema", path: "testdata/schemas/phase17-qualification-policy-v1.schema.json",
			old: `"additionalProperties": false`, new: `"additionalProperties": true`,
		},
		{
			name: "coupled independent scanner", path: "scripts/phase17/privacy_scanner_b.py",
			appendix: "\n# forbidden coupling: phase17qualification\n",
		},
		{
			name: "Python qualification writes bytecode", path: "scripts/phase17/privacy_scan_b_test.py",
			old: `sys.dont_write_bytecode = True`, new: `sys.dont_write_bytecode = False`,
		},
		{
			name: "qualified scanner writes bytecode", path: "cmd/phase17field/privacy.go",
			old: `args: []string{"-B", "-I", value.scannerBPath`, new: `args: []string{"-I", value.scannerBPath`,
		},
		{
			name: "newest evidence selection", path: "scripts/phase17/run-qualified-campaign.ps1",
			appendix: "\n# forbidden: Sort-Object LastWriteTimeUtc\n",
		},
		{
			name: "crash surviving runner output", path: "scripts/phase17/run-qualified-campaign.ps1",
			old: `& $runner @runnerArguments 2> $null`, new: `& $runner @runnerArguments 2> runner.stderr.tmp`,
		},
		{
			name: "recursive sanitizer discovery", path: "scripts/phase17/sanitize-field-evidence.ps1",
			appendix: "\n# forbidden: Get-ChildItem -Recurse\n",
		},
		{
			name: "active runner invokes offline converter", path: "cmd/phase17field/main.go",
			appendix: "\nfunc forbiddenOfflineConverterForTest() { _ = exec.Command(\"phase17evidence.exe\") }\n",
		},
		{
			name: "builder uses stale device inventory path", path: "scripts/phase17/build-qualification-candidate.ps1",
			old: `android\config\phase17-required-device-tests.txt`, new: `config\phase17-required-device-tests.txt`,
		},
		{
			name: "builder ignores untracked source", path: "scripts/phase17/build-qualification-candidate.ps1",
			old: `'status', '--porcelain=v1', '--untracked-files=all'`, new: `'status', '--porcelain=v1', '--untracked-files=no'`,
		},
		{
			name: "builder omits historical evidence schema", path: "scripts/phase17/build-qualification-candidate.ps1",
			old: `'phase17-historical-gate-supersession-v1.schema.json'`, new: `'phase17-historical-gate-supersession-removed.schema.json'`,
		},
		{
			name: "wrapper skips private environment verification", path: "scripts/phase17/run-qualified-campaign.ps1",
			old: `'environment', 'verify'`, new: `'environment', 'removed'`,
		},
		{
			name: "wrapper exposes private SSH selector", path: "scripts/phase17/run-qualified-campaign.ps1",
			appendix: "\n# forbidden argument: '-ssh-alias',\n",
		},
		{
			name: "wrapper skips candidate-bound preflight verification", path: "scripts/phase17/run-qualified-campaign.ps1",
			old: `'candidate', 'artifact', 'verify'`, new: `'candidate', 'artifact', 'removed'`,
		},
		{
			name: "wrapper skips active preflight", path: "scripts/phase17/run-qualified-campaign.ps1",
			old: `& $preflight -PrivateEnvironment`, new: `# removed $preflight -PrivateEnvironment`,
		},
		{
			name: "wrapper reuses preflight identity", path: "scripts/phase17/run-qualified-campaign.ps1",
			old: `$preflightId = [Guid]::NewGuid().ToString('N')`, new: `$preflightId = '00000000000000000000000000000000'`,
		},
		{
			name: "wrapper omits one preflight binding", path: "scripts/phase17/run-qualified-campaign.ps1",
			old: `'-preflight-result', $preflightResult,`, new: `'-preflight-removed', $preflightResult,`,
		},
		{
			name: "preflight restores private command-line selector", path: "scripts/phase17/owned-vps-preflight.ps1",
			appendix: "\n# forbidden interface: [string]$SshAlias\n",
		},
		{
			name: "preflight omits launch nonce", path: "scripts/phase17/owned-vps-preflight.ps1",
			old: `[Parameter(Mandatory = $true)][string]$PreflightId`, new: `[string]$RemovedPreflightId`,
		},
		{
			name: "preflight omits environment binding", path: "scripts/phase17/owned-vps-preflight.ps1",
			old: `environmentSha256 = $environmentDigest`, new: `removedEnvironmentSha256 = $environmentDigest`,
		},
		{
			name: "preflight omits clock proof", path: "scripts/phase17/owned-vps-preflight.ps1",
			old: `hostClockToVps = $true`, new: `removedHostClockToVps = $true`,
		},
		{
			name: "vps architecture widened", path: "testdata/schemas/phase17-owned-vps-evidence-v3.schema.json",
			old: `"vpsArch": {"const": "amd64"}`, new: `"vpsArch": {"enum": ["amd64", "arm64"]}`,
		},
		{
			name: "vps architecture widened in verifier", path: "internal/phase17evidence/field_v3.go",
			old: `value.VPSArch != "amd64"`, new: `!containsString([]string{"amd64", "arm64"}, value.VPSArch)`,
		},
		{
			name: "host boot omitted from authority commitment", path: "cmd/phase17qual/main.go",
			old: `probeURL, probeDigest, hostBootIdentity,`, new: `probeURL, probeDigest, nil,`,
		},
		{
			name: "powershell digest omitted from environment", path: "cmd/phase17qual/main.go",
			old: `PowerShellSHA256: toolDigests[4]`, new: `PowerShellSHA256: toolDigests[3]`,
		},
		{
			name: "campaign omits owner vps clock", path: "cmd/phase17field/main.go",
			old: `verifyOwnerVPSClock(parent, runner, value, root, time.Now)`, new: `verifyOwnerVPSClockRemoved(parent, runner, value, root, time.Now)`,
		},
		{
			name: "campaign omits wake inhibitor", path: "cmd/phase17field/main.go",
			old: `runWithHostWakeGuard(acquireHostWakeInhibitor, func() error`, new: `runWithHostWakeGuard(acquireHostWakeInhibitorRemoved, func() error`,
		},
		{
			name: "non windows wake guard fails open", path: "cmd/phase17field/host_awake_other.go",
			old: `return nil, errors.New("host wake inhibition unsupported")`, new: `return func() {}, nil`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := copyQualificationInfrastructure(t)
			path := filepath.Join(root, filepath.FromSlash(test.path))
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if test.old != "" {
				if !strings.Contains(string(raw), test.old) {
					t.Fatalf("fixture missing %q", test.old)
				}
				raw = []byte(strings.Replace(string(raw), test.old, test.new, 1))
			}
			raw = append(raw, test.appendix...)
			if err := os.WriteFile(path, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := verifyQualificationInfrastructure(root); err == nil {
				t.Fatal("qualification drift accepted")
			}
		})
	}
}

func TestVerifyQualificationInfrastructureRejectsMissingAttemptClosure(t *testing.T) {
	root := copyQualificationInfrastructure(t)
	path := filepath.Join(root, filepath.FromSlash("scripts/phase17/run-qualified-campaign.ps1"))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.ReplaceAll(string(raw), "'attempt', 'close'", "'attempt', 'removed'"))
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyQualificationInfrastructure(root); err == nil {
		t.Fatal("campaign wrapper without categorical attempt closure accepted")
	}
}

func TestVerifyQualificationInfrastructureRejectsUnlistedCriticalFiles(t *testing.T) {
	tests := []string{
		"cmd/phase17qual/unlisted.go",
		"android/app/src/androidTest/kotlin/org/kurdistanvpn/app/Phase17UnlistedDeviceTest.kt",
		"testdata/schemas/phase17-unlisted-v1.schema.json",
	}
	for _, relative := range tests {
		t.Run(relative, func(t *testing.T) {
			root := copyQualificationInfrastructure(t)
			path := filepath.Join(root, filepath.FromSlash(relative))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("unlisted qualification input\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := verifyQualificationInfrastructure(root); err == nil {
				t.Fatal("unlisted critical qualification file accepted")
			}
		})
	}
}

func copyQualificationInfrastructure(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, relative := range qualificationRequiredFiles() {
		source := filepath.Join(repositoryRoot(t), filepath.FromSlash(relative))
		destination := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
