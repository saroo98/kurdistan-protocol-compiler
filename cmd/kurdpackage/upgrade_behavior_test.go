// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

type upgradeFixtureOptions struct {
	stateVersion             int
	mutateAfterCheck         bool
	mutateAfterBridgeUse     bool
	failCleanupOnce          bool
	failBackupVerify         bool
	signalDuringDrain        bool
	signalAfterSuccessfulCmd string
}

type upgradeFixtureResult struct {
	exitCode        int
	output          string
	operations      []string
	bridgeRemaining bool
}

func TestUpgradeStateV2UsesCandidateBridgeWhenPredecessorCannotDecodeState(t *testing.T) {
	result := runUpgradeFixture(t, upgradeFixtureOptions{stateVersion: 2})
	if result.exitCode != 0 {
		t.Fatalf("state-v2 bridge upgrade failed: exit=%d output=%s", result.exitCode, result.output)
	}
	assertOperationOrder(t, result.operations,
		"candidate:node:drain",
		"candidate:backup:create",
		"candidate:backup:verify",
		"install",
		"candidate:migration:apply",
		"candidate:doctor:--data-dir",
		"candidate:node:resume",
	)
	if containsOperation(result.operations, "predecessor:node:drain") {
		t.Fatal("state-v2 upgrade used the predecessor decoder before installation")
	}
	if result.bridgeRemaining {
		t.Fatal("successful upgrade left the candidate bridge behind")
	}
}

func TestUpgradeStateV1RetainsPredecessorMigrationPath(t *testing.T) {
	result := runUpgradeFixture(t, upgradeFixtureOptions{stateVersion: 1})
	if result.exitCode != 0 {
		t.Fatalf("state-v1 upgrade failed: exit=%d output=%s", result.exitCode, result.output)
	}
	assertOperationOrder(t, result.operations,
		"predecessor:node:drain",
		"predecessor:backup:create",
		"predecessor:backup:verify",
		"install",
		"candidate:migration:apply",
	)
	if containsOperation(result.operations, "candidate:node:drain") {
		t.Fatal("state-v1 upgrade bypassed the authenticated predecessor migration path")
	}
}

func TestUpgradeRejectsCandidateMutationAfterChecksumVerification(t *testing.T) {
	result := runUpgradeFixture(t, upgradeFixtureOptions{stateVersion: 2, mutateAfterCheck: true})
	if result.exitCode == 0 {
		t.Fatalf("mutated candidate was accepted; operations=%v", result.operations)
	}
	if containsOperation(result.operations, "install") {
		t.Fatal("mutated candidate reached host installation")
	}
	if !strings.Contains(result.output, "CANDIDATE_PACKAGE_FAILED") && !strings.Contains(result.output, "CANDIDATE_BRIDGE_FAILED") && !strings.Contains(result.output, "CANDIDATE_BRIDGE_INVALID") {
		t.Fatalf("mutation was not rejected categorically: %s", result.output)
	}
	if result.bridgeRemaining {
		t.Fatal("mutation rejection left the candidate bridge behind")
	}
}

func TestUpgradeInstallsFromAuthenticatedSnapshotAfterBridgeUse(t *testing.T) {
	result := runUpgradeFixture(t, upgradeFixtureOptions{stateVersion: 2, mutateAfterBridgeUse: true})
	if result.exitCode != 0 {
		t.Fatalf("authenticated snapshot upgrade failed: exit=%d output=%s", result.exitCode, result.output)
	}
	if containsOperation(result.operations, "malicious-install") || containsOperation(result.operations, "malicious:migration:apply") {
		t.Fatalf("post-staging package mutation reached installation: operations=%v", result.operations)
	}
	assertOperationOrder(t, result.operations,
		"candidate:backup:verify",
		"install",
		"candidate:migration:apply",
	)
}

func TestUpgradeRetriesBridgeCleanupWithoutLosingFailedPaths(t *testing.T) {
	result := runUpgradeFixture(t, upgradeFixtureOptions{stateVersion: 2, failCleanupOnce: true})
	if result.exitCode == 0 || !strings.Contains(result.output, "CANDIDATE_BRIDGE_CLEANUP_FAILED") {
		t.Fatalf("cleanup failure was not reported categorically: exit=%d output=%s", result.exitCode, result.output)
	}
	if countOperation(result.operations, "bridge-rm") < 2 {
		t.Fatalf("cleanup did not retry the retained bridge path: operations=%v", result.operations)
	}
	if result.bridgeRemaining {
		t.Fatal("cleanup retry left the candidate bridge behind")
	}
}

func TestUpgradeExitHandlerRetriesTransientCleanupFailure(t *testing.T) {
	result := runUpgradeFixture(t, upgradeFixtureOptions{stateVersion: 2, failCleanupOnce: true, failBackupVerify: true})
	if result.exitCode == 0 || !strings.Contains(result.output, "BACKUP_VERIFY_FAILED") {
		t.Fatalf("backup failure was not preserved through cleanup retry: exit=%d output=%s", result.exitCode, result.output)
	}
	if countOperation(result.operations, "bridge-rm") < 2 {
		t.Fatalf("exit handler did not retry transient cleanup: operations=%v", result.operations)
	}
	if result.bridgeRemaining {
		t.Fatal("exit handler cleanup retry left staging material behind")
	}
}

func TestUpgradeNeverInstallsBeforeBackupVerification(t *testing.T) {
	result := runUpgradeFixture(t, upgradeFixtureOptions{stateVersion: 2, failBackupVerify: true})
	if result.exitCode == 0 || !strings.Contains(result.output, "BACKUP_VERIFY_FAILED") {
		t.Fatalf("backup verification failure was not categorical: exit=%d output=%s", result.exitCode, result.output)
	}
	if containsOperation(result.operations, "install") {
		t.Fatal("upgrade installed the candidate before backup verification completed")
	}
	if result.bridgeRemaining {
		t.Fatal("backup verification failure left the candidate bridge behind")
	}
}

func TestUpgradeSignalPathRemovesCandidateBridge(t *testing.T) {
	result := runUpgradeFixture(t, upgradeFixtureOptions{stateVersion: 2, signalDuringDrain: true})
	if result.exitCode == 0 {
		t.Fatal("signalled upgrade unexpectedly succeeded")
	}
	if containsOperation(result.operations, "install") {
		t.Fatal("signalled upgrade reached installation")
	}
	if result.bridgeRemaining {
		t.Fatal("signalled upgrade left the candidate bridge behind")
	}
}

func TestUpgradeSignalHandlerRetriesTransientCleanupFailure(t *testing.T) {
	result := runUpgradeFixture(t, upgradeFixtureOptions{stateVersion: 2, failCleanupOnce: true, signalDuringDrain: true})
	if result.exitCode == 0 {
		t.Fatal("signalled upgrade with transient cleanup failure unexpectedly succeeded")
	}
	if countOperation(result.operations, "bridge-rm") < 2 {
		t.Fatalf("signal handler did not retry transient cleanup: operations=%v", result.operations)
	}
	if result.bridgeRemaining {
		t.Fatal("signal handler cleanup retry left staging material behind")
	}
}

func TestUpgradeSignalAfterSuccessfulCommandFailsClosed(t *testing.T) {
	result := runUpgradeFixture(t, upgradeFixtureOptions{stateVersion: 2, signalAfterSuccessfulCmd: "cleanup"})
	if result.exitCode == 0 {
		t.Fatalf("signal after a successful command reported success: operations=%v output=%s", result.operations, result.output)
	}
	if containsOperation(result.operations, "install") {
		t.Fatal("signal after a successful command reached installation")
	}
	if result.bridgeRemaining {
		t.Fatal("signal after a successful command left staging material behind")
	}
}

func TestUpgradeRollbackSignalAfterSuccessfulCommandFailsClosed(t *testing.T) {
	result := runUpgradeFixture(t, upgradeFixtureOptions{stateVersion: 2, signalAfterSuccessfulCmd: "rollback"})
	if result.exitCode == 0 {
		t.Fatalf("rollback-phase signal after a successful command reported success: operations=%v output=%s", result.operations, result.output)
	}
	if containsOperation(result.operations, "install") {
		t.Fatal("rollback-phase controlled signal reached installation")
	}
	if result.bridgeRemaining {
		t.Fatal("rollback-phase controlled signal left staging material behind")
	}
}

func runUpgradeFixture(t *testing.T, options upgradeFixtureOptions) upgradeFixtureResult {
	t.Helper()
	if options.stateVersion != 1 && options.stateVersion != 2 {
		t.Fatalf("invalid fixture state version %d", options.stateVersion)
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is required for native upgrade behavior tests")
	}

	root := t.TempDir()
	posixRoot := toPOSIXPath(t, bash, root)
	packageDir := filepath.Join(root, "package")
	mockBin := filepath.Join(root, "mock-bin")
	hostDir := filepath.Join(root, "host")
	dataDir := filepath.Join(hostDir, "data")
	runtimeDir := filepath.Join(root, "runtime")
	for _, dir := range []string{packageDir, filepath.Join(packageDir, "bin"), mockBin, dataDir, filepath.Join(dataDir, "recipient-registry"), filepath.Join(hostDir, "backups"), runtimeDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	paths := map[string]string{
		"root":               posixRoot,
		"package":            posixRoot + "/package",
		"mockBin":            posixRoot + "/mock-bin",
		"host":               posixRoot + "/host",
		"data":               posixRoot + "/host/data",
		"backups":            posixRoot + "/host/backups",
		"runtime":            posixRoot + "/runtime",
		"installed":          posixRoot + "/host/installed-kurdctl",
		"currentManifest":    posixRoot + "/host/current-manifest.json",
		"rollback":           posixRoot + "/host/rollback.sh",
		"socketUnit":         posixRoot + "/host/kurd-node.socket",
		"tunFlag":            posixRoot + "/host/tun-flags",
		"passphrase":         posixRoot + "/host/backup-passphrase",
		"operations":         posixRoot + "/operations.log",
		"cleanupCount":       posixRoot + "/cleanup-count",
		"maliciousCandidate": posixRoot + "/malicious-kurdctl",
		"maliciousInstall":   posixRoot + "/malicious-install.sh",
	}

	writeFixtureFile(t, filepath.Join(dataDir, "state.kurd-state"), "valid-state-v2-beyond-predecessor-decoder-limit\n")
	writeFixtureFile(t, filepath.Join(hostDir, "backup-passphrase"), "fixture-passphrase\n")
	writeFixtureFile(t, filepath.Join(hostDir, "current-manifest.json"), fmt.Sprintf("{\"version\":\"predecessor\",\"stateVersion\":%d}\n", options.stateVersion))
	writeFixtureFile(t, filepath.Join(packageDir, "manifest.json"), "{\"version\":\"candidate\",\"arch\":\"amd64\",\"stateVersion\":2}\n")
	writeFixtureExecutable(t, bash, filepath.Join(packageDir, "preflight.sh"), "#!/bin/sh\nexit 0\n")
	writeFixtureExecutable(t, bash, filepath.Join(packageDir, "install.sh"), fmt.Sprintf("#!/bin/sh\nprintf 'install\\n' >> %s\ncp bin/kurdctl %s\nchmod 0750 %s\n", shellQuote(paths["operations"]), shellQuote(paths["installed"]), shellQuote(paths["installed"])))
	writeFixtureExecutable(t, bash, filepath.Join(packageDir, "bin", "kurdctl"), fixtureKurdctl("candidate"))
	writeFixtureExecutable(t, bash, filepath.Join(hostDir, "installed-kurdctl"), fixtureKurdctl("predecessor"))
	writeFixtureExecutable(t, bash, filepath.Join(root, "malicious-kurdctl"), fixtureKurdctl("malicious"))
	writeFixtureExecutable(t, bash, filepath.Join(root, "malicious-install.sh"), fmt.Sprintf("#!/bin/sh\nprintf 'malicious-install\\n' >> %s\ncp %s %s\nchmod 0750 %s\n", shellQuote(paths["operations"]), shellQuote(paths["maliciousCandidate"]), shellQuote(paths["installed"]), shellQuote(paths["installed"])))

	upgradeBytes, err := os.ReadFile(filepath.Join(repositoryRootV1(t), "deploy", "selfhost", "native", "upgrade.sh"))
	if err != nil {
		t.Fatal(err)
	}
	upgrade := string(upgradeBytes)
	replacements := map[string]string{
		"/usr/local/share/doc/kurd-node/manifest.json": paths["currentManifest"],
		"/usr/local/bin/kurdctl":                       paths["installed"],
		"/usr/local/lib/kurd-node/rollback.sh":         paths["rollback"],
		"/var/lib/kurd-node":                           paths["data"],
		"/var/backups/kurd-node":                       paths["backups"],
		"/etc/systemd/system/kurd-node.socket":         paths["socketUnit"],
		"/sys/class/net/kurd0/tun_flags":               paths["tunFlag"],
		"/run/kurd-node-upgrade.XXXXXX":                paths["runtime"] + "/kurd-node-upgrade.XXXXXX",
	}
	for from, to := range replacements {
		if !strings.Contains(upgrade, from) {
			t.Fatalf("upgrade fixture root marker disappeared: %s", from)
		}
		upgrade = strings.ReplaceAll(upgrade, from, to)
	}
	if options.signalAfterSuccessfulCmd != "" {
		marker := ""
		switch options.signalAfterSuccessfulCmd {
		case "cleanup":
			for _, candidate := range []string{"trap cleanup_only EXIT HUP INT TERM", "trap 'cleanup_and_exit 143' TERM"} {
				if strings.Contains(upgrade, candidate) {
					marker = candidate
					break
				}
			}
		case "rollback":
			for _, candidate := range []string{"trap 'rollback_and_exit 143' TERM", "trap 'rollback_and_exit 0' TERM", "trap rollback_on_exit EXIT HUP INT TERM"} {
				if strings.Contains(upgrade, candidate) {
					marker = candidate
					break
				}
			}
		default:
			t.Fatalf("unknown controlled signal phase %q", options.signalAfterSuccessfulCmd)
		}
		if marker == "" || !strings.Contains(upgrade, marker) {
			t.Fatalf("upgrade fixture could not arm the %s controlled signal", options.signalAfterSuccessfulCmd)
		}
		upgrade = strings.Replace(upgrade, marker, marker+"\ntrue\nkill -TERM \"$$\"", 1)
	}
	upgradePath := filepath.Join(packageDir, "upgrade.sh")
	writeFixtureExecutable(t, bash, upgradePath, upgrade)

	writeMockCommands(t, bash, mockBin, paths)
	digest := sha256.Sum256(mustReadFile(t, filepath.Join(packageDir, "bin", "kurdctl")))
	writeFixtureFile(t, filepath.Join(packageDir, "SHA256SUMS"), hex.EncodeToString(digest[:])+"  bin/kurdctl\n")

	fixtureEnv := map[string]string{
		"PATH":                        paths["mockBin"] + ":/usr/bin:/bin:/usr/sbin:/sbin",
		"KURD_BACKUP_PASSPHRASE_FILE": paths["passphrase"],
		"FIXTURE_OPERATIONS":          paths["operations"],
		"FIXTURE_STATE_VERSION":       fmt.Sprintf("%d", options.stateVersion),
		"FIXTURE_TUN_FLAG":            paths["tunFlag"],
		"FIXTURE_CLEANUP_COUNT":       paths["cleanupCount"],
		"FIXTURE_MALICIOUS_CANDIDATE": paths["maliciousCandidate"],
		"FIXTURE_MALICIOUS_INSTALL":   paths["maliciousInstall"],
		"FIXTURE_PACKAGE":             paths["package"],
	}
	if options.mutateAfterCheck {
		fixtureEnv["FIXTURE_MUTATE_AFTER_CHECK"] = "1"
	}
	if options.mutateAfterBridgeUse {
		fixtureEnv["FIXTURE_MUTATE_AFTER_BRIDGE_USE"] = "1"
	}
	if options.failCleanupOnce {
		fixtureEnv["FIXTURE_FAIL_CLEANUP_ONCE"] = "1"
	}
	if options.failBackupVerify {
		fixtureEnv["FIXTURE_FAIL_BACKUP_VERIFY"] = "1"
	}
	if options.signalDuringDrain {
		fixtureEnv["FIXTURE_SIGNAL_DURING_DRAIN"] = "1"
	}

	assignments := make([]string, 0, len(fixtureEnv))
	for name, value := range fixtureEnv {
		assignments = append(assignments, name+"="+shellQuote(value))
	}
	sort.Strings(assignments)
	commandLine := "env " + strings.Join(assignments, " ") + " " + shellQuote(toPOSIXPath(t, bash, upgradePath)) + " --apply --port 443"
	command := exec.Command(bash, "-lc", commandLine)
	output, runErr := command.CombinedOutput()
	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("execute upgrade fixture: %v", runErr)
		}
	}
	operations := readOperationLog(t, filepath.Join(root, "operations.log"))
	entries, err := os.ReadDir(runtimeDir)
	if err != nil {
		t.Fatal(err)
	}
	bridgeRemaining := false
	for _, entry := range entries {
		if entry.IsDir() || strings.Contains(entry.Name(), "kurdctl") || strings.Contains(entry.Name(), "upgrade") {
			bridgeRemaining = true
		}
	}
	return upgradeFixtureResult{exitCode: exitCode, output: string(output), operations: operations, bridgeRemaining: bridgeRemaining}
}

func fixtureKurdctl(identity string) string {
	return fmt.Sprintf(`#!/bin/sh
set -eu
command_name=${1:-}
subcommand=${2:-}
printf '%%s:%%s:%%s\n' %s "$command_name" "$subcommand" >> "$FIXTURE_OPERATIONS"
if [ %s = predecessor ] && [ "$FIXTURE_STATE_VERSION" = 2 ] && [ "$command_name" = node ] && [ "$subcommand" = drain ]; then
  exit 42
fi
if [ "${FIXTURE_SIGNAL_DURING_DRAIN:-}" = 1 ] && [ %s = candidate ] && [ "$command_name" = node ] && [ "$subcommand" = drain ]; then
  kill -TERM "$PPID"
  sleep 1
  exit 42
fi
if [ "$command_name" = backup ] && [ "$subcommand" = create ]; then
  backup_file=
  shift 2
  while [ "$#" -gt 0 ]; do
    if [ "$1" = --file ]; then backup_file=$2; shift 2; else shift; fi
  done
  [ -n "$backup_file" ] || exit 43
  printf 'verified fixture backup\n' > "$backup_file"
fi
if [ "$command_name" = backup ] && [ "$subcommand" = verify ] && [ "${FIXTURE_FAIL_BACKUP_VERIFY:-}" = 1 ]; then
  exit 44
fi
if [ %s = candidate ] && [ "$command_name" = backup ] && [ "$subcommand" = verify ] && [ "${FIXTURE_MUTATE_AFTER_BRIDGE_USE:-}" = 1 ]; then
  cp "$FIXTURE_MALICIOUS_CANDIDATE" "$FIXTURE_PACKAGE/bin/kurdctl"
  cp "$FIXTURE_MALICIOUS_INSTALL" "$FIXTURE_PACKAGE/install.sh"
  chmod 0750 "$FIXTURE_PACKAGE/bin/kurdctl" "$FIXTURE_PACKAGE/install.sh"
  digest=$(sha256sum "$FIXTURE_PACKAGE/bin/kurdctl" | cut -d' ' -f1)
  printf '%%s  bin/kurdctl\n' "$digest" > "$FIXTURE_PACKAGE/SHA256SUMS"
fi
exit 0
`, shellQuote(identity), shellQuote(identity), shellQuote(identity), shellQuote(identity))
}

func writeMockCommands(t *testing.T, bash, mockBin string, paths map[string]string) {
	t.Helper()
	commands := map[string]string{
		"id": `#!/bin/sh
if [ "${1:-}" = -u ]; then printf '0\n'; exit 0; fi
if [ "${1:-}" = -g ]; then printf '123\n'; exit 0; fi
exec /usr/bin/id "$@"
`,
		"stat": `#!/bin/sh
format=${2:-}
path=${3:-}
case "$format" in
  %u) printf '0\n' ;;
  %g) case "$path" in */runtime/*/package) printf '0\n' ;; *) printf '123\n' ;; esac ;;
  %a) case "$path" in *backup-passphrase) printf '600\n' ;; */runtime/*/package) printf '700\n' ;; *) printf '750\n' ;; esac ;;
  *) exec /usr/bin/stat "$@" ;;
esac
`,
		"find": "#!/bin/sh\nexit 0\n",
		"install": `#!/bin/sh
if [ "${1:-}" = -d ]; then
  for arg in "$@"; do target=$arg; done
  mkdir -p "$target"
  exit 0
fi
previous=
for arg in "$@"; do source=$previous; destination=$arg; previous=$arg; done
cp "$source" "$destination"
/usr/bin/chmod 0750 "$destination"
`,
		"mktemp": `#!/bin/sh
template=$2
target=${template%XXXXXX}fixture
mkdir "$target"
printf '%s\n' "$target"
`,
		"chown": "#!/bin/sh\nexit 0\n",
		"chmod": "#!/bin/sh\nexit 0\n",
		"runuser": `#!/bin/sh
while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
[ "${1:-}" = -- ] || exit 45
shift
exec "$@"
`,
		"systemctl": `#!/bin/sh
printf 'systemctl:%s\n' "$*" >> "$FIXTURE_OPERATIONS"
case "$*" in
  "is-active --quiet kurd-node.service"|"is-enabled --quiet kurd-node.socket") exit 1 ;;
  *) exit 0 ;;
esac
`,
		"networkctl": `#!/bin/sh
printf 'networkctl:%s\n' "$*" >> "$FIXTURE_OPERATIONS"
if [ "${1:-}" = reload ]; then mkdir -p "$(dirname "$FIXTURE_TUN_FLAG")"; : > "$FIXTURE_TUN_FLAG"; fi
exit 0
`,
		"sha256sum": `#!/bin/sh
if [ "${1:-}" = -c ]; then
  /usr/bin/sha256sum "$@"
  status=$?
  if [ "$status" -eq 0 ] && [ "${FIXTURE_MUTATE_AFTER_CHECK:-}" = 1 ]; then
    cp "$FIXTURE_MALICIOUS_CANDIDATE" bin/kurdctl
    /usr/bin/chmod 0750 bin/kurdctl
    digest=$(/usr/bin/sha256sum bin/kurdctl | /usr/bin/cut -d' ' -f1)
    printf '%s  bin/kurdctl\n' "$digest" > SHA256SUMS
  fi
  exit "$status"
fi
exec /usr/bin/sha256sum "$@"
`,
		"rm": `#!/bin/sh
printf 'bridge-rm\n' >> "$FIXTURE_OPERATIONS"
if [ "${FIXTURE_FAIL_CLEANUP_ONCE:-}" = 1 ]; then
  count=0
  [ ! -f "$FIXTURE_CLEANUP_COUNT" ] || count=$(cat "$FIXTURE_CLEANUP_COUNT")
  count=$((count + 1))
  printf '%s\n' "$count" > "$FIXTURE_CLEANUP_COUNT"
  [ "$count" -gt 1 ] || exit 46
fi
exec /usr/bin/rm "$@"
`,
		"rmdir": `#!/bin/sh
printf 'bridge-rmdir\n' >> "$FIXTURE_OPERATIONS"
exec /usr/bin/rmdir "$@"
`,
	}
	for name, body := range commands {
		writeFixtureExecutable(t, bash, filepath.Join(mockBin, name), body)
	}
	_ = paths
}

func writeFixtureFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeFixtureExecutable(t *testing.T, bash, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(contents, "\r\n", "\n")), 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(bash, "-lc", "chmod 0755 "+shellQuote(toPOSIXPath(t, bash, path)))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("chmod fixture %s: %v: %s", filepath.Base(path), err, output)
	}
}

func toPOSIXPath(t *testing.T, bash, path string) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return filepath.ToSlash(path)
	}
	command := exec.Command(bash, "-lc", `
if command -v cygpath >/dev/null 2>&1; then
  printf 'git-bash\n'
elif command -v wslpath >/dev/null 2>&1; then
  printf 'wsl\n'
else
  exit 64
fi
`)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("detect bash path namespace: %v: %s", err, output)
	}
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' {
		t.Fatalf("unsupported Windows fixture path %q", path)
	}
	remainder := filepath.ToSlash(strings.TrimPrefix(path, volume))
	namespace := ""
	for _, field := range strings.Fields(strings.ReplaceAll(string(output), "\x00", "")) {
		if field == "wsl" || field == "git-bash" {
			namespace = field
		}
	}
	switch namespace {
	case "wsl":
		return "/mnt/" + strings.ToLower(volume[:1]) + remainder
	case "git-bash":
		return "/" + strings.ToLower(volume[:1]) + remainder
	default:
		t.Fatalf("bash returned an unknown path namespace %q", namespace)
	}
	return ""
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func readOperationLog(t *testing.T, path string) []string {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimSpace(string(encoded))
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func assertOperationOrder(t *testing.T, operations []string, expected ...string) {
	t.Helper()
	position := -1
	for _, want := range expected {
		found := -1
		for index := position + 1; index < len(operations); index++ {
			if operations[index] == want {
				found = index
				break
			}
		}
		if found < 0 {
			t.Fatalf("operation %q missing after position %d: %v", want, position, operations)
		}
		position = found
	}
}

func containsOperation(operations []string, expected string) bool {
	return countOperation(operations, expected) > 0
}

func countOperation(operations []string, expected string) int {
	count := 0
	for _, operation := range operations {
		if operation == expected {
			count++
		}
	}
	return count
}
