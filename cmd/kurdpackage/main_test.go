// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestArchiveIsDeterministicAndStrictlyVerified(t *testing.T) {
	files := fixturePackageFiles(t, false)
	one := filepath.Join(t.TempDir(), "one.tar.gz")
	two := filepath.Join(t.TempDir(), "two.tar.gz")
	if err := writeArchive(one, "kurd-node-test-linux-amd64", files); err != nil {
		t.Fatal(err)
	}
	if err := writeArchive(two, "kurd-node-test-linux-amd64", files); err != nil {
		t.Fatal(err)
	}
	oneBytes, _ := os.ReadFile(one)
	twoBytes, _ := os.ReadFile(two)
	if !bytes.Equal(oneBytes, twoBytes) {
		t.Fatal("same package inputs produced different archive bytes")
	}
	manifest, err := verifyArchive(one)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Arch != "amd64" || manifest.Signed || !manifest.RelayDataPlane {
		t.Fatalf("manifest authority mismatch: %+v", manifest)
	}

	invalid := filepath.Join(t.TempDir(), "invalid.tar.gz")
	if err := writeArchive(invalid, "kurd-node-test-linux-amd64", fixturePackageFiles(t, true)); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyArchive(invalid); err == nil {
		t.Fatal("package with forged checksum inventory was accepted")
	}

	extra := filepath.Join(t.TempDir(), "extra.tar.gz")
	extraFiles := fixturePackageFiles(t, false)
	extraFiles = append(extraFiles, packageFile{Path: "unexpected.bin", Mode: 0o644, Data: []byte("not in the authenticated inventories")})
	sort.Slice(extraFiles, func(left, right int) bool { return extraFiles[left].Path < extraFiles[right].Path })
	if err := writeArchive(extra, "kurd-node-test-linux-amd64", extraFiles); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyArchive(extra); err == nil {
		t.Fatal("package with an unmanifested extra file was accepted")
	}
}

func TestNativePackageRequiresExactLiveDataPlaneAssets(t *testing.T) {
	root := repositoryRootV1(t)
	for path, mode := range requiredNativeFilesV1 {
		source := nativeSourceForPackagePathV1(path)
		if source == "" {
			t.Fatalf("required package path has no source mapping: %s", path)
		}
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(source)))
		if err != nil || info.IsDir() {
			t.Fatalf("required native asset %s: %v", source, err)
		}
		if strings.HasSuffix(source, ".sh") != (mode == 0o755) {
			t.Fatalf("mode policy mismatch for %s: %o", path, mode)
		}
	}

	compose, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "container", "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(compose)
	if !strings.Contains(text, `org.kurdistan.relay-data-plane: "false"`) || !strings.Contains(text, "network_mode: none") {
		t.Fatal("container deployment did not remain explicitly authority-only")
	}
}

func TestNativeShellAssetsRemainFailClosedAndSecretSafe(t *testing.T) {
	root := repositoryRootV1(t)
	native := filepath.Join(root, "deploy", "selfhost", "native")
	entries, err := filepath.Glob(filepath.Join(native, "*.sh"))
	if err != nil || len(entries) != 6 {
		t.Fatalf("native shell inventory=%d err=%v", len(entries), err)
	}
	for _, path := range entries {
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(encoded)
		if !strings.HasPrefix(text, "#!/bin/sh\nset -eu\n") {
			t.Fatalf("%s lacks strict POSIX shell preamble", filepath.Base(path))
		}
		for _, forbidden := range []string{"eval ", "curl |", "wget |", "--private-key", "--password", "--token", "flush ruleset"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains forbidden shell pattern %q", filepath.Base(path), forbidden)
			}
		}
		for _, forbidden := range []string{"rm -rf $", "cp -p $", "mv $", "install $"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains an unquoted high-risk path expansion %q", filepath.Base(path), forbidden)
			}
		}
		if strings.Contains(text, "nft -f") && (!strings.Contains(text, "nft -c -f") || strings.Index(text, "nft -c -f") > strings.Index(text, "nft -f")) {
			t.Fatalf("%s applies nftables without an earlier atomic syntax check", filepath.Base(path))
		}
	}
	rollback, err := os.ReadFile(filepath.Join(native, "rollback.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rollback), "preflight.sh --runtime") || !strings.Contains(string(rollback), "state-v2") {
		t.Fatal("rollback does not preflight or enforce the state-v2 compatibility boundary")
	}
	rollbackText := string(rollback)
	validationAt := strings.Index(rollbackText, "PREVIOUS_NFT_INVALID")
	previousDoctorAt := strings.Index(rollbackText, `"$previous_doctor" doctor`)
	stopAt := strings.Index(rollbackText, "systemctl stop kurd-node.socket")
	migrationAt := strings.Index(rollbackText, "kurdctl migration rollback")
	if validationAt < 0 || previousDoctorAt < 0 || stopAt < 0 || migrationAt < 0 || !(validationAt < previousDoctorAt && previousDoctorAt < stopAt && stopAt < migrationAt) {
		t.Fatal("rollback must validate the previous package, stop live writers, then mutate state")
	}
	for _, required := range []string{
		`install -o root -g kurd-node -m 0750 "$previous/bin/kurdctl" "$previous_doctor"`,
		`runuser -u kurd-node -- "$previous_doctor" doctor --data-dir /var/lib/kurd-node`,
	} {
		if !strings.Contains(rollbackText, required) {
			t.Fatalf("rollback previous-state preflight missing %q", required)
		}
	}
	if strings.Contains(rollbackText, `runuser -u kurd-node -- "$previous/bin/kurdctl"`) {
		t.Fatal("rollback cannot execute the previous binary through the root-only snapshot path")
	}
	installScript, err := os.ReadFile(filepath.Join(native, "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	installText := string(installScript)
	if !strings.Contains(installText, "systemd_root=") || !strings.Contains(installText, `systemd-analyze --root="$systemd_root" verify`) {
		t.Fatal("install must verify the candidate units and executables in an isolated root before host mutation")
	}
	upgradeScript, err := os.ReadFile(filepath.Join(native, "upgrade.sh"))
	if err != nil {
		t.Fatal(err)
	}
	upgradeText := string(upgradeScript)
	migrateAt := strings.Index(upgradeText, "kurdctl migration apply")
	mutationAt := strings.Index(upgradeText, "v2_mutated=true")
	doctorAt := strings.Index(upgradeText, "kurdctl doctor")
	if migrateAt < 0 || mutationAt < 0 || doctorAt < 0 || !(migrateAt < mutationAt && mutationAt < doctorAt) {
		t.Fatal("upgrade must close automatic v1 rollback immediately after the first successful v2 mutation")
	}
}

func TestPreflightFailureFixtureInventory(t *testing.T) {
	root := repositoryRootV1(t)
	encoded, err := os.ReadFile(filepath.Join(root, "cmd", "kurdpackage", "testdata", "preflight-failures.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Schema string `json:"schema"`
		Cases  []struct {
			Name string `json:"name"`
			Code string `json:"code"`
		} `json:"cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil || fixture.Schema != "kurd-node-preflight-failure-fixtures-v1" {
		t.Fatalf("fixture decode: %v", err)
	}
	want := []string{"NO_TUN", "TIME_NOT_SYNCED", "NO_IPV4_ROUTE", "MULTIPLE_EGRESS", "PORT_CONFLICT", "NFT_MISSING", "UNBOUND_MISSING", "NETWORKD_MISSING", "KERNEL_UNSUPPORTED", "LOW_DISK", "LOW_MEMORY"}
	if len(fixture.Cases) != len(want) {
		t.Fatalf("fixture cases=%d want=%d", len(fixture.Cases), len(want))
	}
	preflight, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "preflight.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for index, code := range want {
		if fixture.Cases[index].Code != code || fixture.Cases[index].Name == "" || !strings.Contains(string(preflight), code) {
			t.Fatalf("fixture %d=%+v code=%s", index, fixture.Cases[index], code)
		}
	}
}

func TestNativeDeploymentSupportsDistinctIPv4AndIPv6EgressInterfaces(t *testing.T) {
	root := repositoryRootV1(t)
	preflight, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "preflight.sh"))
	if err != nil {
		t.Fatal(err)
	}
	preflightText := string(preflight)
	for _, marker := range []string{`"egressInterfaceV4"`, `"egressInterfaceV6"`} {
		if !strings.Contains(preflightText, marker) {
			t.Fatalf("preflight is missing separate egress field %s", marker)
		}
	}
	if strings.Contains(preflightText, `[ "$ipv6_interfaces" = "$egress_interface" ]`) {
		t.Fatal("preflight still requires IPv4 and IPv6 to share one interface")
	}

	nft, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "kurd-node.nft"))
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"KURD_EGRESS_INTERFACE_V4", "KURD_EGRESS_INTERFACE_V6"} {
		if !strings.Contains(string(nft), marker) {
			t.Fatalf("nft policy is missing %s", marker)
		}
	}

	install, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"egress_interface_v4", "egress_interface_v6", "KURD_EGRESS_INTERFACE_V4", "KURD_EGRESS_INTERFACE_V6"} {
		if !strings.Contains(string(install), marker) {
			t.Fatalf("installer is missing %s", marker)
		}
	}
}

func TestNativeDeploymentReconcilesUFWWithoutTakingFirewallOwnership(t *testing.T) {
	root := repositoryRootV1(t)
	helperPath := filepath.Join(root, "deploy", "selfhost", "native", "firewall-compat.sh")
	helper, err := os.ReadFile(helperPath)
	if err != nil {
		t.Fatal(err)
	}
	helperText := string(helper)
	for _, required := range []string{
		"kurd-node-managed-v1",
		"ufw show added",
		"ufw allow in on kurd0 to 10.77.0.1 port 53 proto udp",
		"ufw allow in on kurd0 to 10.77.0.1 port 53 proto tcp",
		"ufw route allow in on kurd0 out on",
		"ufw allow in on",
		`port "$ingress_port" proto tcp`,
		"--check",
		"--apply",
		"--remove",
	} {
		if !strings.Contains(helperText, required) {
			t.Fatalf("UFW compatibility helper is missing %q", required)
		}
	}
	for _, forbidden := range []string{"ufw enable", "ufw disable", "ufw reset", "DEFAULT_FORWARD_POLICY", "flush ruleset", "eval "} {
		if strings.Contains(helperText, forbidden) {
			t.Fatalf("UFW compatibility helper takes ownership of host firewall state through %q", forbidden)
		}
	}

	install, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	installText := string(install)
	checkAt := strings.Index(installText, `./firewall-compat.sh --check "$listen_port" "$egress_interface_v4" "$egress_interface_v6"`)
	mutationAt := strings.Index(installText, "install_atomic bin/kurd-node")
	applyAt := strings.Index(installText, `/usr/local/lib/kurd-node/firewall-compat.sh --apply "$listen_port" "$egress_interface_v4" "$egress_interface_v6"`)
	if checkAt < 0 || mutationAt < 0 || applyAt < 0 || !(checkAt < mutationAt && mutationAt < applyAt) {
		t.Fatal("installer must validate UFW compatibility before mutation and apply it after installing the owned helper")
	}

	rollback, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "rollback.sh"))
	if err != nil {
		t.Fatal(err)
	}
	rollbackText := string(rollback)
	if !strings.Contains(rollbackText, "firewall-compat.sh --remove") ||
		!strings.Contains(rollbackText, "for helper in firewall-compat") ||
		!strings.Contains(rollbackText, `"$previous/lib/$helper.sh"`) {
		t.Fatal("rollback must remove current managed UFW rules and restore the previous helper authority")
	}
	uninstall, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "uninstall.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(uninstall), "firewall-compat.sh --remove") {
		t.Fatal("uninstall must remove only Kurd-managed UFW compatibility rules")
	}

	if got := nativeSourceMappingsV1["deploy/selfhost/native/firewall-compat.sh"]; got != "firewall-compat.sh" {
		t.Fatalf("package mapping=%q", got)
	}
}

func TestNativeInstallerStagesEveryServiceExecutableForIsolatedVerification(t *testing.T) {
	root := repositoryRootV1(t)
	install, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	installText := string(install)
	for _, marker := range []string{
		"stage_systemd_executable bin/kurd-node /usr/local/bin/kurd-node",
		"stage_systemd_executable bin/kurdctl /usr/local/bin/kurdctl",
	} {
		if !strings.Contains(installText, marker) {
			t.Fatalf("isolated systemd verification is missing %q", marker)
		}
	}
}

func TestNativeFirewallSelectsAddressFamilyWithNFProto(t *testing.T) {
	root := repositoryRootV1(t)
	nft, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "kurd-node.nft"))
	if err != nil {
		t.Fatal(err)
	}
	nftText := string(nft)
	for _, invalid := range []string{`iifname "kurd0" ip oifname`, `iifname "kurd0" ip6 oifname`} {
		if strings.Contains(nftText, invalid) {
			t.Fatalf("nft policy contains invalid standalone family selector %q", invalid)
		}
	}
	for _, required := range []string{
		`iifname "kurd0" meta nfproto ipv4 oifname $egress_if_v4 accept`,
		`iifname "kurd0" meta nfproto ipv6 oifname $egress_if_v6 accept`,
	} {
		if !strings.Contains(nftText, required) {
			t.Fatalf("nft policy is missing address-family selector %q", required)
		}
	}
}

func TestRelayServiceAllowsItsPreflightToReadMemoryCapacity(t *testing.T) {
	root := repositoryRootV1(t)
	unit, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "kurd-node.service"))
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "preflight.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(preflight), "/proc/meminfo") {
		t.Fatal("test precondition failed: runtime preflight no longer reads /proc/meminfo")
	}
	if strings.Contains(string(unit), "ProcSubset=pid") {
		t.Fatal("relay service hides /proc/meminfo from its own ExecStartPre capacity check")
	}
}

func TestRelayServiceAllowsItsPreflightToInspectRoutes(t *testing.T) {
	root := repositoryRootV1(t)
	unit, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "kurd-node.service"))
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "preflight.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(preflight), "ip -o -4 route") {
		t.Fatal("test precondition failed: runtime preflight no longer inspects routes through iproute2")
	}
	if !strings.Contains(string(unit), "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK") {
		t.Fatal("relay service blocks the AF_NETLINK socket required by its own route preflight")
	}
}

func TestNetworkPolicySurvivesBoundedDnsOutage(t *testing.T) {
	root := repositoryRootV1(t)
	unit, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "kurd-node-network.service"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(unit)
	if strings.Contains(text, "Requires=systemd-networkd.service unbound.service") {
		t.Fatal("stopping the DNS resolver also tears down the relay nftables policy")
	}
	if !strings.Contains(text, "Requires=systemd-networkd.service") ||
		!strings.Contains(text, "Wants=unbound.service") ||
		!strings.Contains(text, "After=network-online.target systemd-networkd.service unbound.service") {
		t.Fatal("network policy must require networkd while ordering after and softly requesting DNS")
	}
}

func TestRelaySocketListensOnBothPublicAddressFamilies(t *testing.T) {
	root := repositoryRootV1(t)
	unit, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "kurd-node.socket"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(unit)
	if !strings.Contains(text, "\nListenStream=[::]:KURD_LISTEN_PORT\n") {
		t.Fatal("relay socket is missing its single inherited dual-stack listener")
	}
	if !strings.Contains(text, "\nBindIPv6Only=both\n") {
		t.Fatal("relay socket must explicitly accept both IPv4-mapped and IPv6 clients")
	}
	if !strings.Contains(text, "\nFileDescriptorName=kurd\n") {
		t.Fatal("relay socket must use the descriptor name enforced by the runtime")
	}
	if strings.Count(text, "\nListenStream=") != 1 || strings.Contains(text, "\nListenStream=0.0.0.0:KURD_LISTEN_PORT\n") {
		t.Fatal("relay service accepts exactly one systemd listener descriptor")
	}
}

func TestNativeDeploymentUsesOneValidatedConfigurableSignedPort(t *testing.T) {
	root := repositoryRootV1(t)
	read := func(relative string) string {
		t.Helper()
		encoded, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}

	service := read("deploy/selfhost/native/kurd-node.service")
	socket := read("deploy/selfhost/native/kurd-node.socket")
	install := read("deploy/selfhost/native/install.sh")
	upgrade := read("deploy/selfhost/native/upgrade.sh")
	rollback := read("deploy/selfhost/native/rollback.sh")
	firewall := read("deploy/selfhost/native/firewall-compat.sh")

	for name, text := range map[string]string{"service": service, "socket": socket} {
		if !strings.Contains(text, "KURD_LISTEN_PORT") {
			t.Fatalf("%s unit does not use the validated installer port placeholder", name)
		}
		if strings.Contains(text, ":443") || strings.Contains(text, "--port 443") {
			t.Fatalf("%s unit still hardcodes port 443", name)
		}
	}
	for name, text := range map[string]string{"install": install, "upgrade": upgrade, "rollback": rollback} {
		if !strings.Contains(text, "listen_port") || !strings.Contains(text, "--port") {
			t.Fatalf("%s does not preserve the configured listener port", name)
		}
	}
	for _, marker := range []string{"ingress_port", "ingressPort=", `port "$ingress_port" proto tcp`} {
		if !strings.Contains(firewall, marker) {
			t.Fatalf("firewall compatibility helper is missing %q", marker)
		}
	}
	if strings.Contains(firewall, "port 443 proto tcp") {
		t.Fatal("firewall compatibility helper still hardcodes port 443")
	}
}

func TestRelayServiceKeepsOutputPrivateAndCategoricalFailuresObservable(t *testing.T) {
	root := repositoryRootV1(t)
	unit, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "kurd-node.service"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(unit)
	if !strings.Contains(text, "\nStandardOutput=null\n") || !strings.Contains(text, "\nStandardError=journal\n") {
		t.Fatal("relay service output policy must suppress stdout and retain bounded categorical failures")
	}
}

func TestRelayTUNAllowsTheUnprivilegedProcessToAttachItsOwnQueue(t *testing.T) {
	root := repositoryRootV1(t)
	netdev, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "80-kurd0.netdev"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(netdev)
	if strings.Count(text, "\nMultiQueue=") != 1 || !strings.Contains(text, "\nMultiQueue=yes\n") {
		t.Fatal("owner-created relay TUN must permit the relay process to attach a queue")
	}
}

func TestUpgradeAndRollbackRecreateTheOwnedTUNFromTheActiveVersion(t *testing.T) {
	root := repositoryRootV1(t)
	for _, name := range []string{"upgrade.sh", "rollback.sh"} {
		script, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(script)
		if !strings.Contains(text, "recreate_owned_tun()") || !strings.Contains(text, "networkctl delete kurd0") || !strings.Contains(text, "networkctl reload") || !strings.Contains(text, "[ -e /sys/class/net/kurd0/tun_flags ]") {
			t.Fatalf("%s must recreate and await the owned TUN before restarting the relay", name)
		}
	}
}

func TestUpgradeAcceptsOnlyCommittedRuntimeNotificationPendingForOfflineStateTransitions(t *testing.T) {
	root := repositoryRootV1(t)
	script, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "upgrade.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for _, required := range []string{
		"node_state_transition()",
		`[ "$status" -eq 0 ] || [ "$status" -eq 7 ]`,
		"node_state_transition drain || fail DRAIN_FAILED",
		"node_state_transition resume || fail RESUME_FAILED",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("upgrade must accept only the committed-runtime-pending exit after an offline state transition: missing %q", required)
		}
	}
	if strings.Contains(text, `node "$action" --data-dir "$data_dir" >/dev/null || true`) {
		t.Fatal("upgrade must not hide arbitrary node state-transition failures")
	}
}

func TestRollbackRestoresTheOwnedTUNConfigurationWithNetworkdAccess(t *testing.T) {
	root := repositoryRootV1(t)
	script, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "rollback.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for _, required := range []string{
		"getent group systemd-network",
		"network_group=systemd-network",
		`restore_or_remove "$previous/networkd/80-kurd0.netdev" /etc/systemd/network/80-kurd0.netdev 0640 "$network_group"`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("rollback must preserve systemd-network access to the restored TUN configuration: missing %q", required)
		}
	}
}

func TestInstallUpgradeAndRollbackRebindOwnedDNSAfterTUNCreation(t *testing.T) {
	root := repositoryRootV1(t)
	for _, name := range []string{"install.sh", "upgrade.sh", "rollback.sh"} {
		script, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(script)
		if !strings.Contains(text, "rebind_owned_dns()") ||
			!strings.Contains(text, "systemctl restart unbound.service") ||
			!strings.Contains(text, "systemctl is-active --quiet unbound.service") {
			t.Fatalf("%s must rebind and verify owned DNS after the active TUN exists", name)
		}
	}
}

func repositoryRootV1(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func fixturePackageFiles(t *testing.T, forge bool) []packageFile {
	t.Helper()
	files := []packageFile{
		{Path: "bin/kurd-node", Mode: 0o755, Data: []byte("node")},
		{Path: "bin/kurdctl", Mode: 0o755, Data: []byte("ctl")},
		{Path: "firewall-compat.sh", Mode: 0o755, Data: []byte("firewall")},
		{Path: "install.sh", Mode: 0o755, Data: []byte("install")},
		{Path: "preflight.sh", Mode: 0o755, Data: []byte("preflight")},
		{Path: "rollback.sh", Mode: 0o755, Data: []byte("rollback")},
		{Path: "uninstall.sh", Mode: 0o755, Data: []byte("uninstall")},
		{Path: "upgrade.sh", Mode: 0o755, Data: []byte("upgrade")},
		{Path: "systemd/kurd-node.service", Mode: 0o644, Data: []byte("service")},
		{Path: "systemd/kurd-node.socket", Mode: 0o644, Data: []byte("socket")},
		{Path: "systemd/kurd-node-network.service", Mode: 0o644, Data: []byte("network-service")},
		{Path: "systemd/kurd-node.sysusers.conf", Mode: 0o644, Data: []byte("sysusers")},
		{Path: "systemd/kurd-node.tmpfiles.conf", Mode: 0o644, Data: []byte("tmpfiles")},
		{Path: "networkd/80-kurd0.netdev", Mode: 0o640, Data: []byte("netdev")},
		{Path: "networkd/80-kurd0.network", Mode: 0o644, Data: []byte("network")},
		{Path: "sysctl/90-kurd-node.conf", Mode: 0o644, Data: []byte("sysctl")},
		{Path: "nftables/kurd-node.nft", Mode: 0o600, Data: []byte("nft")},
		{Path: "unbound/kurd-node-unbound.conf", Mode: 0o644, Data: []byte("unbound")},
		{Path: "THIRD_PARTY_MODULES.json", Mode: 0o644, Data: []byte("{}")},
		{Path: "docs/INSTALL.md", Mode: 0o644, Data: []byte("install")},
		{Path: "docs/CONTAINER.md", Mode: 0o644, Data: []byte("container")},
		{Path: "docs/LIVE-DATA-PLANE.md", Mode: 0o644, Data: []byte("live data plane")},
	}
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	manifest := packageManifest{Schema: "kurd-node-native-package-v1", Version: "test", OS: "linux", Arch: "amd64", GoVersion: "go version go1.26.5 test", SourceCommit: strings.Repeat("a", 40), RelayDataPlane: true, StateVersion: 2, Files: []fileDigest{}}
	for _, file := range files {
		manifest.Files = append(manifest.Files, digestFile(file))
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, packageFile{Path: "manifest.json", Mode: 0o644, Data: encoded})
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	var sums strings.Builder
	for _, file := range files {
		digest := digestFile(file).SHA256
		if forge && file.Path == "bin/kurd-node" {
			raw, _ := hex.DecodeString(digest)
			raw[0] ^= 1
			digest = hex.EncodeToString(raw)
		}
		sums.WriteString(digest + "  " + file.Path + "\n")
	}
	files = append(files, packageFile{Path: "SHA256SUMS", Mode: 0o644, Data: []byte(sums.String())})
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	return files
}
