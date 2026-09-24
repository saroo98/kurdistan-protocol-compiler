// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase16verify validates the local Phase 16 evidence boundary and the
// current decentralized self-hosting authority. It explicitly rejects the
// superseded external mode; exercised legacy cloud contracts are test-only. It
// never calls a cloud API and never treats local evidence as production evidence.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	statusPath                  = "testdata/evidence/phase16/production-trust-status.json"
	selfHostedQualificationPath = "testdata/evidence/phase16/self-hosted-vps-qualification.json"
	ownerInputDefault           = ".tools/phase16/private/owner-inputs.json"
)

var errHistoricalEvidenceNotAvailable = errors.New("historical evidence not available")

var requiredFiles = []string{
	"README.md",
	"docs/self-hosting/INSTALL.md",
	"docs/self-hosting/LIVE-DATA-PLANE.md",
	"docs/self-hosting/QUICKSTART.md",
	"docs/self-hosting/SECURITY.md",
	"testdata/schemas/phase16-production-trust-status-v1.schema.json",
	"testdata/schemas/phase16-self-hosted-vps-qualification-v1.schema.json",
	statusPath,
	selfHostedQualificationPath,
	"cmd/kurd-node/main.go",
	"cmd/kurdctl/main.go",
	"cmd/kurdpackage/main.go",
	"cmd/kandroidbridge/environment_selfhost.go",
	"cmd/phase16androidverify/main.go",
	"internal/selfhost/model.go",
	"deploy/selfhost/native/kurd-node.service",
	"deploy/selfhost/container/compose.yml",
}

var decentralizedAuthorityFiles = []string{
	"README.md",
	"docs/self-hosting/INSTALL.md",
	"docs/self-hosting/SECURITY.md",
}

var excludedPublicationFiles = []string{
	"RZ-evidence-ref-069",
	"SZ-evidence-ref-070",
	"docs/PZ-evidence-ref-060",
	"docs/PZ-evidence-ref-062",
	"docs/PZ-evidence-ref-063",
}

type status struct {
	Schema         string `json:"schema"`
	Phase          int    `json:"phase"`
	BaselineCommit string `json:"baselineCommit"`
	State          string `json:"state"`
	PolicyDigests  struct {
		Actions   string `json:"actions"`
		KeyPolicy string `json:"keyPolicy"`
		Regions   string `json:"regions"`
		Retention string `json:"retention"`
		Roles     string `json:"roles"`
		Services  string `json:"services"`
		Tools     string `json:"tools"`
	} `json:"policyDigests"`
	LocalAuthority   []string           `json:"localAuthority"`
	ExternalEvidence []externalEvidence `json:"externalEvidence"`
	ReleaseDecision  string             `json:"releaseDecision"`
	Limitations      []string           `json:"limitations"`
	Findings         struct {
		Critical int `json:"critical"`
		High     int `json:"high"`
	} `json:"findings"`
}

type externalEvidence struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	EvidenceDigest string `json:"evidenceDigest"`
}

type selfHostedQualification struct {
	Schema     string `json:"schema"`
	Phase      int    `json:"phase"`
	Authority  string `json:"authority"`
	RecordedAt string `json:"recordedAt"`
	Source     struct {
		Branch                    string `json:"branch"`
		BaselineCommit            string `json:"baselineCommit"`
		PackageSourceCommit       string `json:"packageSourceCommit"`
		PackageBuiltFromDirtyTree bool   `json:"packageBuiltFromDirtyTree"`
	} `json:"source"`
	Packages struct {
		Version                  string `json:"version"`
		AMD64SHA256              string `json:"amd64Sha256"`
		ARM64SHA256              string `json:"arm64Sha256"`
		IndependentBuildsMatched bool   `json:"independentBuildsMatched"`
		Signed                   bool   `json:"signed"`
		RelayDataPlane           bool   `json:"relayDataPlane"`
	} `json:"packages"`
	VPS struct {
		ProviderClass   string `json:"providerClass"`
		RegionClass     string `json:"regionClass"`
		OperatingSystem string `json:"operatingSystem"`
		Architecture    string `json:"architecture"`
		CPUCores        int    `json:"cpuCores"`
		MemoryMiB       int    `json:"memoryMiB"`
		StorageGiB      int    `json:"storageGiB"`
		EndpointSHA256  string `json:"endpointSha256"`
	} `json:"vps"`
	Deployment struct {
		RootFingerprint     string `json:"rootFingerprint"`
		Revision            uint64 `json:"revision"`
		Generation          uint64 `json:"generation"`
		RootEpoch           uint64 `json:"rootEpoch"`
		RevocationEpoch     uint64 `json:"revocationEpoch"`
		ProfileCount        int    `json:"profileCount"`
		RevokedProfileCount int    `json:"revokedProfileCount"`
		RecoveryConfirmed   bool   `json:"recoveryConfirmed"`
		Drained             bool   `json:"drained"`
		Disabled            bool   `json:"disabled"`
	} `json:"deployment"`
	Artifacts struct {
		RecoverySHA256          string `json:"recoverySha256"`
		BackupSHA256            string `json:"backupSha256"`
		PostUpgradeBackupSHA256 string `json:"postUpgradeBackupSha256"`
		ProfileSHA256           string `json:"profileSha256"`
		BackupAuditHead         string `json:"backupAuditHead"`
	} `json:"artifacts"`
	Checks struct {
		FreshNativeInstall             bool `json:"freshNativeInstall"`
		UpgradeRollbackReupgrade       bool `json:"upgradeRollbackReupgrade"`
		TotalHostLossRestore           bool `json:"totalHostLossRestore"`
		OldBackupRejected              bool `json:"oldBackupRejected"`
		WrongPassphraseRejected        bool `json:"wrongPassphraseRejected"`
		CorruptBackupRejected          bool `json:"corruptBackupRejected"`
		DoctorPassed                   bool `json:"doctorPassed"`
		PublicationCursorAuthenticated bool `json:"publicationCursorAuthenticated"`
		SystemdSandboxed               bool `json:"systemdSandboxed"`
		OnlySSHPublicListener          bool `json:"onlySshPublicListener"`
		DefaultDenyFirewall            bool `json:"defaultDenyFirewall"`
		ContainerConformance           bool `json:"containerConformance"`
		AndroidKVP2ExactActivation     bool `json:"androidKvp2ExactActivation"`
		HundredCycleSoak               bool `json:"hundredCycleSoak"`
		DeterministicPackages          bool `json:"deterministicPackages"`
		TemporaryArtifactsRemoved      bool `json:"temporaryArtifactsRemoved"`
	} `json:"checks"`
	Limitations []string `json:"limitations"`
	Findings    struct {
		Critical int `json:"critical"`
		High     int `json:"high"`
	} `json:"findings"`
	ReleaseDecision string `json:"releaseDecision"`
}

func main() {
	os.Exit(runWithVerifier(os.Args[1:], os.Stdout, os.Stderr, verify))
}

func runWithVerifier(args []string, stdout, stderr io.Writer, verifier func(string, string, string) error) int {
	flags := flag.NewFlagSet("phase16verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	mode := flags.String("mode", "offline", "offline or external")
	ownerPath := flags.String("owner-inputs", ownerInputDefault, "private owner input file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "PHASE 16 VERIFICATION FAILED: unexpected arguments: %v\n", flags.Args())
		return 2
	}
	if err := verifier(*root, *mode, *ownerPath); err != nil {
		if errors.Is(err, errHistoricalEvidenceNotAvailable) {
			fmt.Fprintf(stdout, "PHASE 16 %s VERIFICATION NOT_AVAILABLE; CURRENT QUALIFICATION REMAINS BLOCKED\n", strings.ToUpper(*mode))
			return 0
		}
		fmt.Fprintln(stderr, "PHASE 16 VERIFICATION FAILED:", err)
		return 1
	}
	fmt.Fprintf(stdout, "PHASE 16 %s VERIFICATION PASSED\n", strings.ToUpper(*mode))
	return 0
}

func verify(root, mode, ownerPath string) error {
	if mode != "offline" && mode != "external" {
		return fmt.Errorf("unsupported mode %q", mode)
	}
	for _, rel := range requiredFiles {
		if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil || info.IsDir() {
			return fmt.Errorf("required file unavailable: %s", rel)
		}
	}
	if err := verifyPublicationBoundary(root); err != nil {
		return err
	}
	var value status
	if err := decodeFile(root, statusPath, &value); err != nil {
		return err
	}
	unavailable := make([]string, 0, 2)
	if err := validateStatus(root, value, mode); err != nil {
		if !errors.Is(err, errHistoricalEvidenceNotAvailable) {
			return err
		}
		unavailable = append(unavailable, err.Error())
	}
	if err := verifySelfHostedQualification(root); err != nil {
		if !errors.Is(err, errHistoricalEvidenceNotAvailable) {
			return err
		}
		unavailable = append(unavailable, err.Error())
	}
	if err := verifyDocuments(root); err != nil {
		return err
	}
	if err := verifyDecentralizedAuthority(root); err != nil {
		return err
	}
	if err := verifyNoMandatoryCloudWorkflows(root); err != nil {
		return err
	}
	if err := verifySchemas(root); err != nil {
		return err
	}
	if err := verifyPortableImplementation(root); err != nil {
		return err
	}
	if mode == "external" {
		return errors.New("legacy centralized external mode is superseded; use the self-hosted VPS acceptance verifier")
	}
	if len(unavailable) != 0 {
		return fmt.Errorf("%w: %s", errHistoricalEvidenceNotAvailable, strings.Join(unavailable, "; "))
	}
	return nil
}

func gitValue(root string, args ...string) (string, error) {
	command := exec.Command("git", args...)
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func validateStatus(root string, value status, mode string) error {
	if value.Schema != "phase16-production-trust-status-v1" || value.Phase != 16 {
		return errors.New("invalid status identity")
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(value.BaselineCommit) {
		return errors.New("invalid baseline commit")
	}
	baselineAvailability := historicalCommitAvailability(root, value.BaselineCommit, "phase16 production-trust baseline")
	if value.ReleaseDecision != "NO_GO" {
		return errors.New("Phase 16 cannot widen the full VPN release decision")
	}
	if value.State == "COMPLETE" && mode != "external" {
		return errors.New("offline verification cannot establish Phase 16 completion")
	}
	if value.Findings.Critical < 0 || value.Findings.High < 0 || len(value.Limitations) < 1 {
		return errors.New("invalid findings or limitations")
	}
	want := map[string]string{
		"config/production/actions.json":    value.PolicyDigests.Actions,
		"config/production/key-policy.json": value.PolicyDigests.KeyPolicy,
		"config/production/regions.json":    value.PolicyDigests.Regions,
		"config/production/retention.json":  value.PolicyDigests.Retention,
		"config/production/roles.json":      value.PolicyDigests.Roles,
		"config/production/services.json":   value.PolicyDigests.Services,
		"config/production/tools.json":      value.PolicyDigests.Tools,
	}
	for path, digest := range want {
		observed, err := fileDigest(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		if observed != digest {
			return fmt.Errorf("policy digest drift: %s", path)
		}
	}
	seen := map[string]bool{}
	for _, item := range value.ExternalEvidence {
		if item.ID == "" || seen[item.ID] {
			return errors.New("invalid or duplicate external evidence id")
		}
		seen[item.ID] = true
		if item.Status == "UNVERIFIED" {
			if item.EvidenceDigest != "UNVERIFIED" {
				return fmt.Errorf("unverified evidence has digest: %s", item.ID)
			}
		} else if item.Status != "PASS" && item.Status != "FAIL" {
			return fmt.Errorf("invalid external evidence state: %s", item.ID)
		} else if !validDigest(item.EvidenceDigest) {
			return fmt.Errorf("invalid evidence digest: %s", item.ID)
		}
	}
	if value.State == "COMPLETE" {
		if value.Findings.Critical != 0 || value.Findings.High != 0 {
			return errors.New("complete status retains blocking findings")
		}
		for _, item := range value.ExternalEvidence {
			if item.Status != "PASS" {
				return fmt.Errorf("complete status lacks external evidence: %s", item.ID)
			}
		}
	}
	return baselineAvailability
}

func historicalCommitAvailability(root, commit, label string) error {
	if _, err := gitValue(root, "rev-parse", "--git-dir"); err != nil {
		return fmt.Errorf("historical repository boundary: %w", err)
	}
	if _, err := gitValue(root, "cat-file", "-e", "HEAD^{commit}"); err != nil {
		return fmt.Errorf("current repository subject: %w", err)
	}
	command := exec.Command("git", "cat-file", "-e", commit+"^{commit}")
	command.Dir = root
	if err := command.Run(); err != nil {
		return fmt.Errorf("%w: %s %s", errHistoricalEvidenceNotAvailable, label, commit)
	}
	return nil
}

func verifyDocuments(root string) error {
	required := map[string][]string{
		"README.md":                            {"profile-driven, self-hosted relay transport system", "Each operator controls", "no telemetry", "pre-release software"},
		"docs/self-hosting/INSTALL.md":         {"The installer verifies the manifest and every checksum", "The relay process runs as `kurd-node`", "contacts an update service"},
		"docs/self-hosting/LIVE-DATA-PLANE.md": {"PRIVACY_PAYLOAD_LOGGING=PROHIBITED", "`kurd-node` runs unprivileged", "query logging disabled"},
		"docs/self-hosting/SECURITY.md":        {"There is no Kurdistan account", "global root", "It cannot control another deployment"},
	}
	for path, needles := range required {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		text := string(raw)
		for _, needle := range needles {
			if !strings.Contains(text, needle) {
				return fmt.Errorf("%s missing authority text %q", path, needle)
			}
		}
	}
	return nil
}

func verifyDecentralizedAuthority(root string) error {
	required := map[string][]string{
		"README.md": {
			"profile-driven, self-hosted relay transport system",
			"Each operator controls",
			"does not require a Kurdistan account",
			"one deployment cannot revoke or disable another independent deployment",
		},
		"docs/self-hosting/INSTALL.md": {
			"owner-controlled qualification host",
			"The relay process runs as `kurd-node`",
			"owns no capability",
		},
		"docs/self-hosting/SECURITY.md": {
			"There is no Kurdistan account",
			"global root",
			"It cannot control another deployment",
		},
	}
	for path, needles := range required {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		text := string(raw)
		for _, needle := range needles {
			if !strings.Contains(text, needle) {
				return fmt.Errorf("%s missing decentralized authority text %q", path, needle)
			}
		}
	}

	for _, path := range []string{
		"README.md",
		"docs/self-hosting/SECURITY.md",
	} {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		text := strings.ToLower(string(raw))
		for _, forbidden := range []string{
			"google cloud is mandatory",
			"google cloud account is required",
			"requires a google cloud account",
			"must use google cloud",
			"spanner is mandatory",
			"cloud kms is mandatory",
			"requires a global kurdistan root",
			"kurdistan-operated global shutdown switch",
		} {
			if strings.Contains(text, forbidden) {
				return fmt.Errorf("%s reintroduces prohibited centralized authority %q", path, forbidden)
			}
		}
	}
	return nil
}

func verifyPublicationBoundary(root string) error {
	for _, path := range excludedPublicationFiles {
		_, err := os.Lstat(filepath.Join(root, filepath.FromSlash(path)))
		if err == nil {
			return fmt.Errorf("excluded file is present in the public repository tree: %s", path)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect excluded publication path %s: %w", path, err)
		}
	}
	return nil
}

func verifyNoMandatoryCloudWorkflows(root string) error {
	paths := []string{
		".github/workflows/phase16-qualification.yml",
		".github/workflows/phase16-drill.yml",
		".github/workflows/phase16-production-plan.yml",
		".github/workflows/phase16-production-apply.yml",
	}
	for _, path := range paths {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		text := strings.ToLower(string(raw))
		if strings.Contains(text, "phase16-cloud-experiment-disabled") {
			continue
		}
		for _, forbidden := range []string{
			"id-token: write",
			"google-github-actions/",
			"gcloud ",
			"terraform",
			"spanner",
			"cloud kms",
		} {
			if strings.Contains(text, forbidden) {
				return fmt.Errorf("%s retains mandatory cloud workflow authority %q", path, forbidden)
			}
		}
	}
	return verifyPortableDrillWorkflow(root)
}

func verifyPortableDrillWorkflow(root string) error {
	path := filepath.Join(root, filepath.FromSlash(".github/workflows/phase16-drill.yml"))
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	requiredTests := []string{
		"TestEncryptedBackupRestoreAndRollbackProtection",
		"TestInterruptedStateWriteResidueCannotReplaceCommittedState",
		"TestClockRollbackAndLargeForwardJumpFailClosed",
		"TestIssuerAndRelayRotationRevokePriorProfiles",
		"TestBackupRejectsWrongPassphraseTamperAndUnsafePaths",
	}
	text := string(raw)
	for _, required := range append([]string{
		"case \"$DRILL\" in",
		"LISTED=$(go test ./internal/selfhost -list",
		"expected drill test is absent",
	}, requiredTests...) {
		if !strings.Contains(text, required) {
			return fmt.Errorf("phase16 drill workflow missing zero-test guard %q", required)
		}
	}
	pattern := "^(" + strings.Join(requiredTests, "|") + ")$"
	command := exec.Command("go", "test", "./internal/selfhost", "-list", pattern)
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("phase16 drill test inventory: %w: %s", err, strings.TrimSpace(string(output)))
	}
	found := map[string]bool{}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		for _, expected := range requiredTests {
			if line == expected {
				found[expected] = true
			}
		}
	}
	for _, expected := range requiredTests {
		if !found[expected] {
			return fmt.Errorf("phase16 drill test inventory omits %s", expected)
		}
	}
	return nil
}

func verifyPortableImplementation(root string) error {
	required := map[string][]string{
		"cmd/kurd-node/main.go":                      {"selfhost.PublishSnapshot", "READY_AUTHORITY_ONLY", "UNAVAILABLE_PHASE_16"},
		"cmd/kurdctl/main.go":                        {"profile", "backup", "restore", "upgrade", "rollback"},
		"cmd/kurdpackage/main.go":                    {"kurd-node-native-package-v1", "Signed", "RelayDataPlane"},
		"cmd/kandroidbridge/environment_selfhost.go": {"selfhost.VerifyBundle", "deployment-local", "OwnerControlled"},
		"cmd/phase16androidverify/main.go":           {"phase16-android-exact-profile-verification-v1", "selfhost.VerifyBundle"},
		"internal/selfhost/model.go":                 {"kurd-selfhost-state-v1", "maxProfiles", "maxStateBytes"},
		"android/core/native-jni/src/main/kotlin/org/kurdistanvpn/core/nativejni/NativeBridge.kt": {"KVP2", "deploymentFingerprint", "ownerControlled"},
	}
	for path, needles := range required {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		for _, needle := range needles {
			if !strings.Contains(string(raw), needle) {
				return fmt.Errorf("%s missing authority marker %q", path, needle)
			}
		}
	}
	if err := verifyServiceUnit(root); err != nil {
		return err
	}
	if err := verifyContainerDefinition(root); err != nil {
		return err
	}
	command := exec.Command("go", "list", "-buildvcs=false", "-deps", "./cmd/kurd-node", "./cmd/kurdctl", "./internal/selfhost")
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("portable dependency inventory: %s", strings.TrimSpace(string(output)))
	}
	dependencies := "\n" + strings.ToLower(string(output)) + "\n"
	for _, forbidden := range []string{"\nnet/http\n", "\nnet/rpc\n", "\ncloud.google.com/", "\ngoogle.golang.org/", "\ngo.opentelemetry.io/", "\nkurdistan/production/"} {
		if strings.Contains(dependencies, forbidden) {
			return fmt.Errorf("portable self-hosting runtime imports prohibited dependency %q", strings.TrimSpace(forbidden))
		}
	}
	return nil
}

func verifySelfHostedQualification(root string) error {
	var value selfHostedQualification
	if err := decodeFile(root, selfHostedQualificationPath, &value); err != nil {
		return err
	}
	if value.Schema != "phase16-self-hosted-vps-qualification-v1" || value.Phase != 16 || value.Authority != "KIP-0093" || value.ReleaseDecision != "NO_GO" {
		return errors.New("invalid self-hosted qualification identity or release boundary")
	}
	recorded, err := time.Parse(time.RFC3339, value.RecordedAt)
	if err != nil || recorded.Before(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) || recorded.After(time.Now().UTC().Add(5*time.Minute)) {
		return errors.New("invalid self-hosted qualification time")
	}
	if value.Source.Branch != "product/phase16-production-trust" || !value.Source.PackageBuiltFromDirtyTree ||
		value.Source.BaselineCommit != value.Source.PackageSourceCommit || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(value.Source.BaselineCommit) {
		return errors.New("self-hosted qualification source identity mismatch")
	}
	baselineAvailability := historicalCommitAvailability(root, value.Source.BaselineCommit, "phase16 self-hosted qualification baseline")
	if value.Packages.Version != "0.16.3-phase16" || !validDigest(value.Packages.AMD64SHA256) || !validDigest(value.Packages.ARM64SHA256) ||
		value.Packages.AMD64SHA256 == value.Packages.ARM64SHA256 || !value.Packages.IndependentBuildsMatched || value.Packages.Signed || value.Packages.RelayDataPlane {
		return errors.New("self-hosted package qualification is incomplete or widens Phase 16 authority")
	}
	if value.VPS.ProviderClass != "owner-controlled-vps" || value.VPS.RegionClass != "external-european" ||
		value.VPS.OperatingSystem != "Ubuntu Server 26.04 LTS" || value.VPS.Architecture != "amd64" ||
		value.VPS.CPUCores < 1 || value.VPS.MemoryMiB < 1024 || value.VPS.StorageGiB < 10 || !validDigest(value.VPS.EndpointSHA256) {
		return errors.New("self-hosted VPS qualification is invalid")
	}
	deployment := value.Deployment
	if !validDigest(deployment.RootFingerprint) || deployment.Revision == 0 || deployment.Generation == 0 || deployment.RootEpoch == 0 || deployment.RevocationEpoch == 0 ||
		deployment.ProfileCount < 1 || deployment.RevokedProfileCount < 1 || deployment.RevokedProfileCount >= deployment.ProfileCount ||
		!deployment.RecoveryConfirmed || deployment.Drained || deployment.Disabled {
		return errors.New("self-hosted deployment qualification is incomplete")
	}
	for name, digest := range map[string]string{
		"recovery":            value.Artifacts.RecoverySHA256,
		"backup":              value.Artifacts.BackupSHA256,
		"post-upgrade backup": value.Artifacts.PostUpgradeBackupSHA256,
		"profile":             value.Artifacts.ProfileSHA256,
		"backup audit head":   value.Artifacts.BackupAuditHead,
	} {
		if !validDigest(digest) {
			return fmt.Errorf("invalid %s digest in self-hosted qualification", name)
		}
	}
	checks := value.Checks
	if !checks.FreshNativeInstall || !checks.UpgradeRollbackReupgrade || !checks.TotalHostLossRestore || !checks.OldBackupRejected ||
		!checks.WrongPassphraseRejected || !checks.CorruptBackupRejected || !checks.DoctorPassed || !checks.PublicationCursorAuthenticated ||
		!checks.SystemdSandboxed || !checks.OnlySSHPublicListener || !checks.DefaultDenyFirewall || !checks.ContainerConformance ||
		!checks.AndroidKVP2ExactActivation || !checks.HundredCycleSoak || !checks.DeterministicPackages || !checks.TemporaryArtifactsRemoved {
		return errors.New("self-hosted qualification has an incomplete acceptance check")
	}
	if value.Findings.Critical != 0 || value.Findings.High != 0 || len(value.Limitations) < 3 || len(value.Limitations) > 8 {
		return errors.New("self-hosted qualification findings or limitations are invalid")
	}
	limitations := strings.ToLower(strings.Join(value.Limitations, "\n"))
	for _, required := range []string{"unsigned", "phase 19", "relay data plane", "phase 17", "physical android"} {
		if !strings.Contains(limitations, required) {
			return fmt.Errorf("self-hosted qualification omits limitation %q", required)
		}
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(selfHostedQualificationPath)))
	if err != nil {
		return err
	}
	if regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`).Match(raw) {
		return errors.New("self-hosted qualification exposes a raw IPv4 endpoint")
	}
	return baselineAvailability
}

func verifyServiceUnit(root string) error {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash("deploy/selfhost/native/kurd-node.service")))
	if err != nil {
		return err
	}
	text := string(raw)
	for _, required := range []string{"User=kurd-node", "Group=kurd-node", "NoNewPrivileges=yes", "CapabilityBoundingSet=", "ProtectSystem=strict", "PrivateTmp=yes"} {
		if !strings.Contains(text, required) {
			return fmt.Errorf("native service missing hardening marker %q", required)
		}
	}
	for _, forbidden := range []string{"CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "AmbientCapabilities=CAP"} {
		if strings.Contains(text, forbidden) {
			return fmt.Errorf("native service widens process authority %q", forbidden)
		}
	}
	authorityOnly := strings.Contains(text, "PrivateDevices=yes") && strings.Contains(text, "RestrictAddressFamilies=AF_UNIX")
	liveUnprivileged := strings.Contains(text, "PrivateDevices=no") && strings.Contains(text, "DevicePolicy=closed") &&
		strings.Contains(text, "DeviceAllow=/dev/net/tun rw") && strings.Contains(text, "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6") &&
		strings.Contains(text, "Requires=kurd-node.socket")
	if !authorityOnly && !liveUnprivileged {
		return errors.New("native service is neither authority-only nor the bounded unprivileged live successor")
	}
	return nil
}

func verifyContainerDefinition(root string) error {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash("deploy/selfhost/container/compose.yml")))
	if err != nil {
		return err
	}
	text := strings.ToLower(string(raw))
	for _, required := range []string{"network_mode: none", "read_only: true", "cap_drop:", "- all", "no-new-privileges:true", "65532:65532"} {
		if !strings.Contains(text, required) {
			return fmt.Errorf("container definition missing hardening marker %q", required)
		}
	}
	for _, forbidden := range []string{"privileged: true", "network_mode: host", "/var/run/docker.sock"} {
		if strings.Contains(text, forbidden) {
			return fmt.Errorf("container definition enables prohibited authority %q", forbidden)
		}
	}
	return nil
}

func verifySchemas(root string) error {
	for _, path := range requiredFiles {
		if !strings.Contains(path, "testdata/schemas/phase16-") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		if err := rejectDuplicateKeys(raw); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		if value["$schema"] != "https://json-schema.org/draft/2020-12/schema" || value["additionalProperties"] != false {
			return fmt.Errorf("schema is not strict: %s", path)
		}
	}
	return nil
}

func decodeFile(root, path string, target any) error {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return err
	}
	if err := rejectSecretMaterial(raw); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode %s: trailing JSON", path)
	}
	return nil
}

func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return fmt.Errorf("duplicate or invalid object key %q", key)
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		default:
			return fmt.Errorf("unexpected delimiter %q", delim)
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func rejectSecretMaterial(raw []byte) error {
	lower := strings.ToLower(string(raw))
	for _, marker := range []string{"-----begin private key", "-----begin encrypted private key", "service_account", "private_key_id", "\"password\"", "\"access_token\"", "\"refresh_token\"", "ghp_", "github_pat_", "aiza"} {
		if strings.Contains(lower, marker) {
			return errors.New("secret-like material is forbidden")
		}
	}
	return nil
}
func fileDigest(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func validDigest(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}
