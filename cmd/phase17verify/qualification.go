// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"kurdistan/internal/phase17qualification"
)

const qualificationMaximumSourceBytes = 16 << 20

var qualificationOpaqueFiles = map[string]struct{}{
	"android/app/src/main/res/drawable-nodpi/ic_kurdistan_vpn_foreground.png": {},
}

var qualificationSchemaFiles = []string{
	"testdata/schemas/phase17-acceptance-registry-v2.schema.json",
	"testdata/schemas/phase17-candidate-comparison-v1.schema.json",
	"testdata/schemas/phase17-candidate-manifest-v1.schema.json",
	"testdata/schemas/phase17-device-evidence-v1.schema.json",
	"testdata/schemas/phase17-device-verifier-result-v1.schema.json",
	"testdata/schemas/phase17-environment-context-v1.schema.json",
	"testdata/schemas/phase17-historical-gate-supersession-v1.schema.json",
	"testdata/schemas/phase17-owned-vps-evidence-v3.schema.json",
	"testdata/schemas/phase17-owned-vps-preflight-v1.schema.json",
	"testdata/schemas/phase17-qualification-envelope-v1.schema.json",
	"testdata/schemas/phase17-qualification-policy-v1.schema.json",
	"testdata/schemas/phase17-readiness-evidence-index-v1.schema.json",
	"testdata/schemas/phase17-readiness-proof-v1.schema.json",
}

var qualificationFiles = []string{
	"android/app/src/androidTest/kotlin/org/kurdistanvpn/app/Phase17BootQualificationDeviceTest.kt",
	"android/app/src/androidTest/kotlin/org/kurdistanvpn/app/Phase17CanonicalDeviceEvidenceHarness.kt",
	"android/app/src/androidTest/kotlin/org/kurdistanvpn/app/Phase17FieldActionDeviceTest.kt",
	"android/app/src/androidTest/kotlin/org/kurdistanvpn/app/Phase17FieldHarness.kt",
	"android/app/src/androidTest/kotlin/org/kurdistanvpn/app/Phase17LiveDataPlaneDeviceTest.kt",
	"android/app/src/androidTest/kotlin/org/kurdistanvpn/app/Phase17ProtectedStateIntegrityDeviceTest.kt",
	"android/app/src/internal/AndroidManifest.xml",
	"android/app/src/internal/kotlin/org/kurdistanvpn/app/InternalVpnSocketProtectionService.kt",
	"android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/ActiveVpnUnderlyingNetwork.kt",
	"android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/KurdVpnService.kt",
	"android/runtime/android/src/test/kotlin/org/kurdistanvpn/runtime/android/ActiveVpnUnderlyingNetworkTest.kt",
	"android/build.gradle.kts",
	"android/config/phase17-required-device-tests.txt",
	"cmd/phase17boundary/main.go",
	"cmd/phase17boundary/main_test.go",
	"cmd/phase17devicegate/main.go",
	"cmd/phase17devicegate/main_test.go",
	"cmd/phase17evidence/main.go",
	"cmd/phase17evidence/main_test.go",
	"cmd/phase17field/atomic_test.go",
	"cmd/phase17field/boundary.go",
	"cmd/phase17field/boundary_test.go",
	"cmd/phase17field/campaign.go",
	"cmd/phase17field/campaign_test.go",
	"cmd/phase17field/command_test.go",
	"cmd/phase17field/evidence_v3.go",
	"cmd/phase17field/evidence_v3_test.go",
	"cmd/phase17field/host_awake.go",
	"cmd/phase17field/host_awake_other.go",
	"cmd/phase17field/host_awake_windows.go",
	"cmd/phase17field/host_awake_windows_test.go",
	"cmd/phase17field/host_environment.go",
	"cmd/phase17field/main.go",
	"cmd/phase17field/main_test.go",
	"cmd/phase17field/privacy.go",
	"cmd/phase17field/privacy_test.go",
	"cmd/phase17field/qualification.go",
	"cmd/phase17field/qualification_test.go",
	"cmd/phase17qual/main.go",
	"cmd/phase17qual/main_test.go",
	"cmd/phase17scan/main.go",
	"cmd/phase17scan/main_test.go",
	"cmd/phase17verify/artifact.go",
	"cmd/phase17verify/artifact_test.go",
	"cmd/phase17verify/inventory.go",
	"cmd/phase17verify/inventory_test.go",
	"cmd/phase17verify/main.go",
	"cmd/phase17verify/main_test.go",
	"cmd/phase17verify/native_durable_fs_linux_test.go",
	"cmd/phase17verify/qualification.go",
	"cmd/phase17verify/qualification_test.go",
	"config/phase17-acceptance-registry-v2.json",
	"config/phase17/qualification-policy-v1.json",
	"internal/phase17boundary/monitor.go",
	"internal/phase17boundary/monitor_test.go",
	"internal/phase17evidence/evidence.go",
	"internal/phase17evidence/field.go",
	"internal/phase17evidence/field_test.go",
	"internal/phase17evidence/field_v3.go",
	"internal/phase17evidence/field_v3_schema_test.go",
	"internal/phase17evidence/field_v3_test.go",
	"internal/phase17evidence/fuzz_test.go",
	"internal/phase17privacy/scannera/corpus_test.go",
	"internal/phase17privacy/scannera/fuzz_test.go",
	"internal/phase17privacy/scannera/scanner.go",
	"internal/phase17privacy/scannera/scanner_b_test.go",
	"internal/phase17privacy/scannera/scanner_test.go",
	"internal/phase17qualification/acceptance_registry.go",
	"internal/phase17qualification/acceptance_registry_test.go",
	"internal/phase17qualification/atomic.go",
	"internal/phase17qualification/atomic_test.go",
	"internal/phase17qualification/canonical.go",
	"internal/phase17qualification/canonical_test.go",
	"internal/phase17qualification/comparison.go",
	"internal/phase17qualification/comparison_test.go",
	"internal/phase17qualification/device_evidence.go",
	"internal/phase17qualification/device_evidence_test.go",
	"internal/phase17qualification/device_verifier.go",
	"internal/phase17qualification/device_verifier_test.go",
	"internal/phase17qualification/environment_private.go",
	"internal/phase17qualification/environment_private_test.go",
	"internal/phase17qualification/fuzz_test.go",
	"internal/phase17qualification/host_boot.go",
	"internal/phase17qualification/host_boot_test.go",
	"internal/phase17qualification/key.go",
	"internal/phase17qualification/key_test.go",
	"internal/phase17qualification/ledger.go",
	"internal/phase17qualification/ledger_lock.go",
	"internal/phase17qualification/ledger_lock_unix.go",
	"internal/phase17qualification/ledger_lock_windows.go",
	"internal/phase17qualification/ledger_test.go",
	"internal/phase17qualification/path.go",
	"internal/phase17qualification/path_nonwindows.go",
	"internal/phase17qualification/path_windows.go",
	"internal/phase17qualification/path_windows_test.go",
	"internal/phase17qualification/policy.go",
	"internal/phase17qualification/policy_test.go",
	"internal/phase17qualification/preflight.go",
	"internal/phase17qualification/preflight_test.go",
	"internal/phase17qualification/readiness.go",
	"internal/phase17qualification/readiness_test.go",
	"internal/phase17qualification/receipt.go",
	"internal/phase17qualification/receipt_test.go",
	"internal/phase17qualification/schema_test.go",
	"internal/phase17qualification/subject.go",
	"internal/phase17qualification/subject_test.go",
	"internal/testkit/importrules/importrules_test.go",
	"scripts/phase17/build-qualification-candidate.ps1",
	"scripts/phase17/local-correction-checks.Tests.ps1",
	"scripts/phase17/netns-e2e.sh",
	"scripts/phase17/netns_probe.py",
	"scripts/phase17/netns_witness.py",
	"scripts/phase17/owned-vps-e2e.ps1",
	"scripts/phase17/owned-vps-preflight.ps1",
	"scripts/phase17/owned-vps-scripts.Tests.ps1",
	"scripts/phase17/privacy_scan_b_test.py",
	"scripts/phase17/privacy_scanner_b.py",
	"scripts/phase17/run-local-correction-checks.ps1",
	"scripts/phase17/run-qualified-campaign.ps1",
	"scripts/phase17/sanitize-field-evidence.ps1",
	"testdata/fixtures/phase17/privacy-scanner/corpus-v1.json",
}

var qualificationInventoryDirectories = []string{
	"cmd/phase17boundary",
	"cmd/phase17devicegate",
	"cmd/phase17evidence",
	"cmd/phase17field",
	"cmd/phase17qual",
	"cmd/phase17scan",
	"cmd/phase17verify",
	"config/phase17",
	"internal/phase17boundary",
	"internal/phase17evidence",
	"internal/phase17privacy",
	"internal/phase17qualification",
	"scripts/phase17",
}

type qualificationPatternScope struct {
	directory string
	prefix    string
	suffix    string
}

var qualificationPatternScopes = []qualificationPatternScope{
	{
		directory: "android/app/src/androidTest/kotlin/org/kurdistanvpn/app",
		prefix:    "Phase17",
		suffix:    ".kt",
	},
	{
		directory: "testdata/schemas",
		prefix:    "phase17-",
		suffix:    ".schema.json",
	},
}

// Explicit product inputs for G02. They remain ordinary source inputs, not
// execution evidence or permission to construct a qualification candidate.
var correctionQualificationFiles = []string{
	"android/app/build.gradle.kts",
	"android/app/gradle.lockfile",
	"android/app/src/main/AndroidManifest.xml",
	"android/app/src/main/res/drawable-nodpi/ic_kurdistan_vpn_foreground.png",
	"android/app/src/main/res/mipmap-anydpi-v26/ic_kurdistan_vpn.xml",
	"android/app/src/main/res/mipmap-anydpi-v26/ic_kurdistan_vpn_round.xml",
	"android/app/src/main/res/mipmap-anydpi-v33/ic_kurdistan_vpn.xml",
	"android/app/src/main/res/mipmap-anydpi-v33/ic_kurdistan_vpn_round.xml",
	"android/app/src/main/res/values/launcher_icon_colors.xml",
	"android/app/src/main/kotlin/org/kurdistanvpn/app/KurdistanApplication.kt",
	"android/app/src/main/kotlin/org/kurdistanvpn/app/MainActivity.kt",
	"android/app/src/main/kotlin/org/kurdistanvpn/app/Phase13Coordinators.kt",
	"android/app/src/main/kotlin/org/kurdistanvpn/app/Phase9CompositionRoot.kt",
	"android/app/src/main/kotlin/org/kurdistanvpn/app/Phase9ExportWire.kt",
	"android/app/src/main/kotlin/org/kurdistanvpn/app/Phase9ViewModel.kt",
	"android/app/src/main/kotlin/org/kurdistanvpn/app/RuntimeAuthorityReissueAdmission.kt",
	"android/app/src/main/kotlin/org/kurdistanvpn/app/RuntimeAuthorityReissueIpcAdapter.kt",
	"android/app/src/main/kotlin/org/kurdistanvpn/app/RuntimeAuthorityReissueService.kt",
	"android/app/src/main/kotlin/org/kurdistanvpn/app/SensitiveActionAuthorizer.kt",
	"android/app/src/main/kotlin/org/kurdistanvpn/app/VpnNetworkTeardownBarrier.kt",
	"android/app/src/main/kotlin/org/kurdistanvpn/app/VpnRuntimeController.kt",
	"android/app/src/main/res/values/strings.xml",
	"android/core/model/src/main/kotlin/org/kurdistanvpn/core/model/AppState.kt",
	"android/core/model/src/main/kotlin/org/kurdistanvpn/core/model/ProductSettings.kt",
	"android/core/native-api/build.gradle.kts",
	"android/core/native-api/gradle.lockfile",
	"android/core/native-api/src/main/kotlin/org/kurdistanvpn/core/nativeapi/DurableFilePrimitives.kt",
	"android/core/native-jni/build.gradle.kts",
	"android/core/native-jni/src/main/cpp/CMakeLists.txt",
	"android/core/native-jni/src/main/cpp/kvpn_durable_fs.c",
	"android/core/native-jni/src/main/cpp/kvpn_durable_fs.h",
	"android/core/native-jni/src/main/cpp/kvpn_durable_fs_jni.c",
	"android/core/native-jni/src/main/kotlin/org/kurdistanvpn/core/nativejni/NativeBridge.kt",
	"android/data/metadata/schemas/org.kurdistanvpn.data.metadata.KurdistanMetadataDatabase/2.json",
	"android/data/metadata/src/main/kotlin/org/kurdistanvpn/data/metadata/ProfileCatalog.kt",
	"android/data/protected-state/build.gradle.kts",
	"android/data/protected-state/gradle.lockfile",
	"android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ActiveSessionMutationPolicy.kt",
	"android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateAuthorityFactory.kt",
	"android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateCompositionRoot.kt",
	"android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateContracts.kt",
	"android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateJournalLifecycle.kt",
	"android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateMigrationCoordinator.kt",
	"android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateMutationBroker.kt",
	"android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateOperationJournal.kt",
	"android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStatePreviewBackupPolicy.kt",
	"android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateProjectionWitness.kt",
	"android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateResetRecoveryCoordinator.kt",
	"android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateSnapshotReader.kt",
	"android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/AndroidKeystoreKek.kt",
	"android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/BackupPayloadCodec.kt",
	"android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/ClientKeyBundleStore.kt",
	"android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/EncryptedDiagnosticEventStore.kt",
	"android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/ProfileAdmissionJournal.kt",
	"android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/SecureBlobStore.kt",
	"android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/SecureEnvelope.kt",
	"android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/SecureRoutingPolicyStore.kt",
	"android/data/settings/src/main/kotlin/org/kurdistanvpn/data/settings/Phase9SettingsStore.kt",
	"android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/ProductSettingsScreens.kt",
	"android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/SettingsRecoveryScreen.kt",
	"android/runtime/android/src/main/AndroidManifest.xml",
	"android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/NativeTunnelController.kt",
	"android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/PendingRuntimeTermination.kt",
	"android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeActivationGuard.kt",
	"android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeAuthorityFrameCodec.kt",
	"android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeAuthorityReissueClient.kt",
	"android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeAuthorityTimeoutPolicy.kt",
	"android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeRevisionLeaseClient.kt",
	"android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeServiceCommand.kt",
	"android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeStartCoordinator.kt",
	"android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/UnderlyingNetworkMonitor.kt",
	"android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/LiveRuntimeModels.kt",
	"android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/RuntimeAuthorityPurpose.kt",
	"android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/RuntimeAuthorityReissueContract.kt",
	"android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/RuntimeStartWire.kt",
	"android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/RuntimeStatus.kt",
	"android/settings-gradle.lockfile",
	"android/settings.gradle.kts",
}

func qualificationRequiredFiles() []string {
	result := make([]string, 0, len(qualificationFiles)+len(qualificationSchemaFiles))
	result = append(result, qualificationFiles...)
	result = append(result, qualificationSchemaFiles...)
	result = append(result, correctionQualificationFiles...)
	return result
}

func verifyQualificationInfrastructure(root string) error {
	files, err := loadQualificationFiles(root)
	if err != nil {
		return err
	}
	policyPath := filepath.Join(root, filepath.FromSlash("config/phase17/qualification-policy-v1.json"))
	if _, err := phase17qualification.LoadPolicy(policyPath); err != nil {
		return fmt.Errorf("Phase 17 qualification policy: %w", err)
	}
	for _, relative := range qualificationSchemaFiles {
		if err := verifyQualificationSchema(relative, files[relative]); err != nil {
			return err
		}
	}
	if err := verifyQualificationSemanticContracts(files); err != nil {
		return err
	}
	if err := verifyQualificationPrivacyCorpus(files["testdata/fixtures/phase17/privacy-scanner/corpus-v1.json"]); err != nil {
		return err
	}
	if err := verifyQualificationGoBoundaries(root); err != nil {
		return err
	}
	if err := verifyQualificationScripts(files); err != nil {
		return err
	}
	if err := verifyQualificationSourcePrivacy(files); err != nil {
		return err
	}
	return nil
}

func verifyQualificationSemanticContracts(files map[string][]byte) error {
	// Definitions are an immutable source contract, not test results. This decoder
	// deliberately refuses PASS/executed claims and cannot open an operational gate.
	if _, err := phase17qualification.DecodeAcceptanceRegistry(bytes.NewReader(
		files["config/phase17-acceptance-registry-v2.json"],
	)); err != nil {
		return errors.New("qualification acceptance definitions or source-only accounting rejected")
	}
	if value, err := qualificationSchemaStringConst(
		files["testdata/schemas/phase17-owned-vps-evidence-v3.schema.json"], "environment", "vpsArch",
	); err != nil || value != "amd64" {
		return errors.New("qualification evidence schema VPS architecture is not frozen to amd64")
	}
	if value, err := qualificationSchemaStringConst(
		files["testdata/schemas/phase17-owned-vps-preflight-v1.schema.json"], "arch",
	); err != nil || value != "amd64" {
		return errors.New("qualification preflight schema VPS architecture is not frozen to amd64")
	}
	requiredMarkers := map[string][]string{
		"cmd/phase17qual/main.go": {
			"readCurrentHostBootIdentity(context.Background(), privateEnvironment.PowerShellExecutable)",
			"probeURL, probeDigest, hostBootIdentity,",
			"PowerShellSHA256: toolDigests[4]",
			"loadPreflightDigest(*preflightResultPath, environmentSHA256)",
			"PreflightSHA256: preflightSHA256",
		},
		"cmd/phase17field/main.go": {
			"runWithHostWakeGuard(acquireHostWakeInhibitor, func() error",
			"verifyPrivateEnvironmentCommitment(parent, qualified, value, environmentSalt, probeURL, probeDigest)",
			"verifyOwnerVPSClock(parent, runner, value, root, time.Now)",
		},
		"cmd/phase17field/qualification.go": {
			"readCurrentHostBootIdentity(ctx, value.powershellPath)",
			"salt, privateEnvironment, probeURL, probeDigest, hostBootIdentity,",
			"artifacts.powershellPath: environment.PowerShellSHA256",
			"attempt.PreflightSHA256 != preflightResultDigest",
		},
		"cmd/phase17field/privacy.go": {
			`args: []string{"-B", "-I", value.scannerBPath`,
		},
		"cmd/phase17field/host_awake_windows.go": {
			"runtime.LockOSThread()",
			"SetThreadExecutionState",
			"setThreadExecutionState(esContinuous|esSystemRequired)",
			"runtime.UnlockOSThread()",
		},
		"cmd/phase17field/host_awake_other.go": {
			"return nil, errors.New(\"host wake inhibition unsupported\")",
		},
		"cmd/phase17field/host_environment.go": {
			"verifyOwnerVPSClock(",
			"StrictHostKeyChecking=yes",
			"date -u +%s",
			"ownerVPSClockTolerance",
		},
		"internal/phase17evidence/field_v3.go": {
			`value.VPSArch != "amd64"`,
		},
		"internal/phase17privacy/scannera/corpus_test.go": {
			`exec.Command(python, "-B", "-I", script`,
		},
		"internal/phase17privacy/scannera/scanner_b_test.go": {
			`exec.Command(python, "-B", "-I", script`,
			"TestPythonScannerQualificationLeavesSourceTreeBytecodeFree",
		},
		"scripts/phase17/privacy_scan_b_test.py": {
			"sys.dont_write_bytecode = True",
			"sys.executable,\n            \"-B\",\n            \"-I\",",
		},
	}
	for relative, markers := range requiredMarkers {
		source := string(files[relative])
		for _, marker := range markers {
			if !strings.Contains(source, marker) {
				return fmt.Errorf("qualification source %s is missing frozen contract %q", relative, marker)
			}
		}
	}
	return nil
}

func qualificationSchemaStringConst(raw []byte, path ...string) (string, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return "", err
	}
	node := root
	for _, field := range path {
		var properties map[string]json.RawMessage
		if err := json.Unmarshal(node["properties"], &properties); err != nil {
			return "", err
		}
		rawChild, found := properties[field]
		if !found {
			return "", fmt.Errorf("schema property %s unavailable", field)
		}
		if err := json.Unmarshal(rawChild, &node); err != nil {
			return "", err
		}
		resolved, err := resolveLocalQualificationSchemaNode(root, node)
		if err != nil {
			return "", err
		}
		node = resolved
	}
	var value string
	if err := json.Unmarshal(node["const"], &value); err != nil {
		return "", err
	}
	return value, nil
}

func resolveLocalQualificationSchemaNode(root, node map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	rawReference, found := node["$ref"]
	if !found {
		return node, nil
	}
	var reference string
	if err := json.Unmarshal(rawReference, &reference); err != nil || !strings.HasPrefix(reference, "#/$defs/") {
		return nil, errors.New("qualification schema reference rejected")
	}
	name := strings.TrimPrefix(reference, "#/$defs/")
	if name == "" || strings.Contains(name, "/") {
		return nil, errors.New("qualification schema reference rejected")
	}
	var definitions map[string]json.RawMessage
	if err := json.Unmarshal(root["$defs"], &definitions); err != nil {
		return nil, err
	}
	rawDefinition, found := definitions[name]
	if !found {
		return nil, errors.New("qualification schema reference unavailable")
	}
	var resolved map[string]json.RawMessage
	if err := json.Unmarshal(rawDefinition, &resolved); err != nil {
		return nil, err
	}
	return resolved, nil
}

func loadQualificationFiles(root string) (map[string][]byte, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("qualification root: %w", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return nil, fmt.Errorf("qualification root: %w", err)
	}
	if !sameFilesystemPath(rootAbs, resolvedRoot) {
		return nil, errors.New("qualification root contains a symbolic link")
	}
	if err := verifyQualificationInventoryCompleteness(rootAbs); err != nil {
		return nil, err
	}
	result := make(map[string][]byte, len(qualificationFiles)+len(qualificationSchemaFiles))
	infos := make([]os.FileInfo, 0, len(qualificationFiles)+len(qualificationSchemaFiles))
	for _, relative := range qualificationRequiredFiles() {
		if relative == "" || filepath.IsAbs(relative) || strings.Contains(relative, "\\") ||
			filepath.ToSlash(filepath.Clean(filepath.FromSlash(relative))) != relative || strings.HasPrefix(relative, "../") {
			return nil, fmt.Errorf("qualification inventory path %q rejected", relative)
		}
		path := filepath.Join(rootAbs, filepath.FromSlash(relative))
		pathAbs, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("qualification inventory %s: %w", relative, err)
		}
		inside, err := filepath.Rel(rootAbs, pathAbs)
		if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("qualification inventory %s escapes root", relative)
		}
		lstat, err := os.Lstat(pathAbs)
		if err != nil {
			return nil, fmt.Errorf("qualification inventory %s: %w", relative, err)
		}
		if lstat.Mode()&os.ModeSymlink != 0 || !lstat.Mode().IsRegular() || lstat.Size() < 1 || lstat.Size() > qualificationMaximumSourceBytes {
			return nil, fmt.Errorf("qualification inventory %s is not a bounded regular file", relative)
		}
		for index, prior := range infos {
			if os.SameFile(prior, lstat) {
				return nil, fmt.Errorf("qualification inventory %s aliases %s", relative, qualificationRequiredFiles()[index])
			}
		}
		file, err := os.Open(pathAbs)
		if err != nil {
			return nil, fmt.Errorf("qualification inventory %s: %w", relative, err)
		}
		opened, err := file.Stat()
		if err != nil || !os.SameFile(lstat, opened) {
			_ = file.Close()
			return nil, fmt.Errorf("qualification inventory %s changed while opening", relative)
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, qualificationMaximumSourceBytes+1))
		closed, statErr := file.Stat()
		closeErr := file.Close()
		if readErr != nil || statErr != nil || closeErr != nil || len(raw) != int(opened.Size()) ||
			!os.SameFile(opened, closed) || opened.Size() != closed.Size() || opened.ModTime() != closed.ModTime() {
			return nil, fmt.Errorf("qualification inventory %s changed while reading", relative)
		}
		if _, opaque := qualificationOpaqueFiles[relative]; !utf8.Valid(raw) && !opaque {
			return nil, fmt.Errorf("qualification inventory %s is not UTF-8", relative)
		}
		result[relative] = raw
		infos = append(infos, lstat)
	}
	return result, nil
}

func verifyQualificationInventoryCompleteness(root string) error {
	expected := make(map[string]struct{}, len(qualificationFiles)+len(qualificationSchemaFiles))
	for _, relative := range qualificationRequiredFiles() {
		if _, duplicate := expected[relative]; duplicate {
			return fmt.Errorf("qualification inventory duplicates %s", relative)
		}
		expected[relative] = struct{}{}
	}
	for _, relativeDirectory := range qualificationInventoryDirectories {
		directory := filepath.Join(root, filepath.FromSlash(relativeDirectory))
		err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			if relative == relativeDirectory {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("qualification inventory scope contains symbolic link %s", relative)
			}
			if entry.IsDir() {
				prefix := relative + "/"
				for candidate := range expected {
					if strings.HasPrefix(candidate, prefix) {
						return nil
					}
				}
				return fmt.Errorf("qualification inventory scope contains unexpected directory %s", relative)
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("qualification inventory scope contains non-regular file %s", relative)
			}
			if _, found := expected[relative]; !found {
				return fmt.Errorf("qualification inventory scope contains unlisted file %s", relative)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	for _, scope := range qualificationPatternScopes {
		directory := filepath.Join(root, filepath.FromSlash(scope.directory))
		entries, err := os.ReadDir(directory)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), scope.prefix) || !strings.HasSuffix(entry.Name(), scope.suffix) {
				continue
			}
			relative := scope.directory + "/" + entry.Name()
			if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
				return fmt.Errorf("qualification patterned scope contains invalid file %s", relative)
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("qualification patterned scope contains non-regular file %s", relative)
			}
			if _, found := expected[relative]; !found {
				return fmt.Errorf("qualification patterned scope contains unlisted file %s", relative)
			}
		}
	}
	return nil
}

func sameFilesystemPath(left, right string) bool {
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}

func verifyQualificationSchema(relative string, raw []byte) error {
	if err := rejectDuplicateKeys(raw); err != nil {
		return fmt.Errorf("qualification schema %s: %w", relative, err)
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("qualification schema %s: %w", relative, err)
	}
	for _, key := range []string{"$schema", "$id", "title", "type", "additionalProperties", "required", "properties"} {
		if _, found := value[key]; !found {
			return fmt.Errorf("qualification schema %s is missing %q", relative, key)
		}
	}
	var draft, id, kind string
	var additional bool
	var required []string
	var properties map[string]json.RawMessage
	if json.Unmarshal(value["$schema"], &draft) != nil || draft != "https://json-schema.org/draft/2020-12/schema" ||
		json.Unmarshal(value["$id"], &id) != nil || !strings.HasSuffix(id, "/"+filepath.Base(relative)) ||
		json.Unmarshal(value["type"], &kind) != nil || kind != "object" ||
		json.Unmarshal(value["additionalProperties"], &additional) != nil || additional ||
		json.Unmarshal(value["required"], &required) != nil || len(required) == 0 ||
		json.Unmarshal(value["properties"], &properties) != nil || len(properties) == 0 {
		return fmt.Errorf("qualification schema %s has a permissive or invalid root", relative)
	}
	seen := make(map[string]struct{}, len(required))
	for _, field := range required {
		if field == "" {
			return fmt.Errorf("qualification schema %s has an empty required field", relative)
		}
		if _, duplicate := seen[field]; duplicate {
			return fmt.Errorf("qualification schema %s has duplicate required field %q", relative, field)
		}
		if _, found := properties[field]; !found {
			return fmt.Errorf("qualification schema %s requires undeclared field %q", relative, field)
		}
		seen[field] = struct{}{}
	}
	return nil
}

type qualificationPrivacyCorpus struct {
	Schema string                           `json:"schema"`
	Cases  []qualificationPrivacyCorpusCase `json:"cases"`
}

type qualificationPrivacyCorpusCase struct {
	Name        string          `json:"name"`
	Source      string          `json:"source"`
	PayloadUTF8 string          `json:"payloadUtf8"`
	PayloadHex  string          `json:"payloadHex"`
	WantPass    bool            `json:"wantPass"`
	WantPrivacy map[string]bool `json:"wantPrivacy"`
}

func verifyQualificationPrivacyCorpus(raw []byte) error {
	if err := rejectDuplicateKeys(raw); err != nil {
		return fmt.Errorf("qualification privacy corpus: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value qualificationPrivacyCorpus
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("qualification privacy corpus: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("qualification privacy corpus has trailing JSON")
	}
	if value.Schema != "kurdistan-phase17-privacy-corpus-v1" || len(value.Cases) < 20 || len(value.Cases) > 256 {
		return errors.New("qualification privacy corpus inventory rejected")
	}
	predicates := make(map[string]struct{}, len(phase17qualification.PrivacyPredicates()))
	for _, name := range phase17qualification.PrivacyPredicates() {
		predicates[name] = struct{}{}
	}
	names := make(map[string]struct{}, len(value.Cases))
	positive := 0
	negative := 0
	for _, test := range value.Cases {
		if test.Name == "" || len(test.Name) > 80 || (test.Source != "ANDROID_LOGCAT" && test.Source != "REMOTE_JOURNAL") ||
			(test.PayloadUTF8 == "") == (test.PayloadHex == "") {
			return errors.New("qualification privacy corpus case rejected")
		}
		if _, duplicate := names[test.Name]; duplicate {
			return errors.New("qualification privacy corpus contains a duplicate case")
		}
		names[test.Name] = struct{}{}
		if test.WantPass {
			positive++
			if len(test.WantPrivacy) != 0 {
				return errors.New("qualification privacy PASS case sets a privacy predicate")
			}
		} else {
			negative++
			if len(test.WantPrivacy) == 0 {
				return errors.New("qualification privacy negative case lacks a predicate")
			}
		}
		for name, set := range test.WantPrivacy {
			if _, found := predicates[name]; !found || !set {
				return errors.New("qualification privacy corpus predicate rejected")
			}
		}
	}
	if positive < 3 || negative < 15 {
		return errors.New("qualification privacy corpus coverage is insufficient")
	}
	return nil
}

func verifyQualificationGoBoundaries(root string) error {
	for _, relative := range []string{"cmd/phase17scan", "internal/phase17privacy/scannera"} {
		directory := filepath.Join(root, filepath.FromSlash(relative))
		err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || filepath.Ext(path) != ".go" {
				return nil
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, spec := range parsed.Imports {
				name, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					return err
				}
				if name == "kurdistan/internal/phase17evidence" || name == "kurdistan/internal/phase17qualification" ||
					strings.HasPrefix(name, "kurdistan/cmd/phase17") {
					return fmt.Errorf("qualification scanner %s imports verdict authority %s", relative, name)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	fieldDirectory := filepath.Join(root, filepath.FromSlash("cmd/phase17field"))
	err := filepath.WalkDir(fieldDirectory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		var boundaryErr error
		ast.Inspect(parsed, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				boundaryErr = err
				return false
			}
			folded := strings.ToLower(filepath.ToSlash(value))
			for _, forbidden := range []string{"kurdistan/cmd/phase17evidence", "./cmd/phase17evidence", "phase17evidence.exe", "bin/phase17evidence", "sanitize-v3-input", "sanitize-v3-output"} {
				if strings.Contains(folded, forbidden) {
					boundaryErr = errors.New("active Phase 17 runner invokes the offline evidence converter")
					return false
				}
			}
			return true
		})
		return boundaryErr
	})
	return err
}

func verifyQualificationScripts(files map[string][]byte) error {
	builder := string(files["scripts/phase17/build-qualification-candidate.ps1"])
	// G03 is a pre-construction source gate. Runtime evidence is independently
	// recomputed by verify-canonical; this check prevents deleting or weakening
	// the exact invocation while retaining unrelated historical builder tokens.
	gateStart := strings.Index(builder, "$priorProxy = $env:GOPROXY")
	gateEnd := strings.Index(builder, "$worktreeAAdded = $false")
	creation := "New-Item -ItemType Directory -Path $temporaryRoot, $candidateA, $candidateB"
	if gateStart < 0 || gateEnd <= gateStart || strings.Count(builder, creation) != 1 ||
		strings.Index(builder, creation) <= gateEnd {
		return errors.New("canonical engineering admission must precede candidate mutation")
	}
	gate := strings.Join(strings.Fields(builder[gateStart:gateEnd]), " ")
	for _, required := range []string{
		"$env:GOPROXY = 'off'; $env:GOSUMDB = 'off'; $env:GOTOOLCHAIN = 'local'",
		"Invoke-Checked -FilePath 'go' -Arguments @('run', '-mod=readonly', './cmd/phase17devicegate', 'verify-canonical',",
		"'-purpose', 'ENGINEERING_REHEARSAL', '-manifest', $EngineeringManifest,",
		"'-roster', $EngineeringDeviceRoster, '-trusted-public-key', $TrustedObserverPublicKey,",
		"'-expected-commit', $Commit, '-expected-tree', $tree",
		") -Failure 'PHASE17_BUILD_CANONICAL_ENGINEERING_REHEARSAL_REQUIRED'",
	} {
		if strings.Count(gate, required) != 1 {
			return errors.New("canonical engineering admission identity or verifier changed")
		}
	}
	for _, required := range []string{
		"candidate-A", "candidate-B", "candidate-manifest.json", "candidate-comparison.json", "Build-CandidateRoot",
		"'-trimpath'", "'candidate', 'create'", "android\\config\\phase17-required-device-tests.txt",
		"phase17-historical-gate-supersession-v1.schema.json", "phase17-owned-vps-preflight-v1.schema.json",
		"'status', '--porcelain=v1', '--untracked-files=all'", "('p17q-' +", "Remove-QualificationWorktree",
		"'-c', 'core.longpaths=true'", "'--no-daemon'", "'-Pkotlin.compiler.execution.strategy=in-process'",
		"throw $primaryFailure", "PHASE17_BUILD_CLEANUP_FAILED",
	} {
		if !strings.Contains(builder, required) {
			return fmt.Errorf("qualification candidate builder is missing %q", required)
		}
	}
	foldedBuilder := strings.ToLower(builder)
	if strings.Contains(foldedBuilder, "go run") {
		return errors.New("qualification candidate builder uses go run")
	}
	if strings.Contains(foldedBuilder, "--untracked-files=no") {
		return errors.New("qualification candidate builder ignores untracked source inputs")
	}
	runner := string(files["scripts/phase17/run-qualified-campaign.ps1"])
	for _, required := range []string{
		"candidate-A", "candidate-B", "'attempt', 'begin'", "'attempt', 'close'", "'attempt', 'finish'", "'soak', 'consume'",
		"'environment', 'verify'", "RUNNER_RESULT_AMBIGUOUS", "& $runner @runnerArguments 2> $null",
		"'-wrapper', $PSCommandPath", "'-wrapper-entry', 'scripts/run-qualified-campaign.ps1'",
		"'-private-environment', $PrivateEnvironment", "'-environment-salt', $EnvironmentSalt",
		"'candidate', 'artifact', 'verify'", "'scripts/owned-vps-preflight.ps1'",
		"& $preflight -PrivateEnvironment", "'-preflight', $preflight", "'-preflight-entry', 'scripts/owned-vps-preflight.ps1'",
		"$preflightId = [Guid]::NewGuid().ToString('N')", "'-preflight-result', $preflightResult,",
	} {
		if !strings.Contains(runner, required) {
			return fmt.Errorf("qualification campaign wrapper is missing %q", required)
		}
	}
	if strings.Count(runner, "'environment', 'verify'") != 2 {
		return errors.New("qualification campaign wrapper must verify the private environment before and after preflight")
	}
	if strings.Count(runner, "'-preflight-result', $preflightResult,") != 3 {
		return errors.New("qualification campaign wrapper must bind preflight evidence to consumption, attempt, and runner")
	}
	preflightVerifyIndex := strings.Index(runner, "'candidate', 'artifact', 'verify'")
	preflightRunIndex := strings.Index(runner, "& $preflight -PrivateEnvironment")
	postPreflightEnvironmentIndex := strings.LastIndex(runner, "'environment', 'verify'")
	soakConsumeIndex := strings.Index(runner, "'soak', 'consume'")
	attemptBeginIndex := strings.Index(runner, "'attempt', 'begin'")
	if preflightVerifyIndex < 0 || preflightRunIndex < 0 || soakConsumeIndex < 0 || attemptBeginIndex < 0 ||
		postPreflightEnvironmentIndex < 0 || preflightVerifyIndex >= preflightRunIndex ||
		preflightRunIndex >= postPreflightEnvironmentIndex || postPreflightEnvironmentIndex >= soakConsumeIndex ||
		postPreflightEnvironmentIndex >= attemptBeginIndex {
		return errors.New("qualification campaign preflight order rejected")
	}
	foldedRunner := strings.ToLower(runner)
	for _, forbidden := range []string{
		"sort-object lastwritetimeutc", "go run ./cmd/phase17field", "start-process", "runner.stdout.tmp", "runner.stderr.tmp",
		"'-ssh-alias',", "'-avd-name',", "'-device-serial',", "'-probe-url-file',", "'-probe-digest-file',",
		"'-python',", "'-adb',", "'-ssh',", "'-scp',", "'-relay-port',",
	} {
		if strings.Contains(foldedRunner, forbidden) {
			return fmt.Errorf("qualification campaign wrapper contains forbidden operation %q", forbidden)
		}
	}
	preflight := string(files["scripts/phase17/owned-vps-preflight.ps1"])
	for _, required := range []string{
		"[string]$PrivateEnvironment", "[string]$Environment", "[string]$PreflightId", "[string]$Output",
		"BatchMode=yes", "StrictHostKeyChecking=yes", "environmentSha256 = $environmentDigest",
		"hostClockToVps = $true", "remoteEpoch", "$hostClockBefore - 5", "$hostClockAfter + 5",
		"OWNER_CONTROLLED_VPS", "rawLogRetained", "Write-ExclusiveUtf8Json", "[IO.FileMode]::CreateNew", "Move-Item",
	} {
		if !strings.Contains(preflight, required) {
			return fmt.Errorf("qualification preflight is missing %q", required)
		}
	}
	for _, forbidden := range []string{"[string]$SshAlias", "[string]$EvidenceRoot", "[string]$SshExecutable", "Set-Content"} {
		if strings.Contains(preflight, forbidden) {
			return fmt.Errorf("qualification preflight contains forbidden interface %q", forbidden)
		}
	}
	sanitizer := string(files["scripts/phase17/sanitize-field-evidence.ps1"])
	for _, required := range []string{
		"-sanitize-v3-input", "-sanitize-v3-output", "PHASE17_SANITIZER_OUTPUT_EXISTS",
		"[Alias('Input')][string]$RawEvidence", "[Alias('Output')][string]$SanitizedEvidence",
	} {
		if !strings.Contains(sanitizer, required) {
			return fmt.Errorf("qualification sanitizer is missing %q", required)
		}
	}
	for _, forbidden := range []string{"[string]$Input", "[string]$Output"} {
		if strings.Contains(sanitizer, forbidden) {
			return fmt.Errorf("qualification sanitizer uses reserved automatic-variable parameter %q", forbidden)
		}
	}
	foldedSanitizer := strings.ToLower(sanitizer)
	for _, forbidden := range []string{"get-childitem", "sort-object", "lastwritetime", "go run"} {
		if strings.Contains(foldedSanitizer, forbidden) {
			return fmt.Errorf("qualification sanitizer contains forbidden discovery %q", forbidden)
		}
	}
	pythonScanner := strings.ToLower(string(files["scripts/phase17/privacy_scanner_b.py"]))
	for _, forbidden := range []string{"phase17evidence", "phase17qualification", "phase17scan", "kurdistan/internal"} {
		if strings.Contains(pythonScanner, forbidden) {
			return fmt.Errorf("independent Python scanner is coupled to %q", forbidden)
		}
	}
	return nil
}

func verifyQualificationSourcePrivacy(files map[string][]byte) error {
	forbiddenMaterial := []string{
		strings.Join([]string{"c:", "users", ""}, "\\"),
		strings.Join([]string{"c:", "users", ""}, "/"),
		strings.Join([]string{"-----begin", "openssh", "private", "key-----"}, " "),
		"ssh-" + "ed25519 ",
	}
	for relative, raw := range files {
		if strings.Contains(relative, "/testdata/") || strings.HasPrefix(relative, "testdata/") ||
			strings.HasSuffix(relative, "_test.go") || strings.HasSuffix(relative, "Tests.ps1") || strings.HasSuffix(relative, "_test.py") {
			continue
		}
		folded := strings.ToLower(string(raw))
		for _, forbidden := range forbiddenMaterial {
			if strings.Contains(folded, forbidden) {
				return fmt.Errorf("qualification source %s contains owner-private material", relative)
			}
		}
	}
	return nil
}
