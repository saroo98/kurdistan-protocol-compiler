// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAssertRemoteHealthRestartsFailSafeStoppedNodeBeforeChecking(t *testing.T) {
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
		if name != "ssh" || len(arguments) == 0 {
			return nil, errors.New("unexpected command")
		}
		command := arguments[len(arguments)-1]
		for _, required := range []string{
			"sudo -n systemctl start kurd-node-network.service kurd-node.socket",
			"sudo -n systemctl start kurd-node.service",
			"NETWORK_START_FAILED",
			"TUN_UNAVAILABLE",
			"DOCTOR_FAILED",
			"SERVICE_HEALTH_PASS",
		} {
			if !strings.Contains(command, required) {
				return nil, errors.New("retry recovery missing")
			}
		}
		return []byte("SERVICE_HEALTH_PASS\n"), nil
	}}
	value := config{sshAlias: "kurd-node", sshPath: "ssh", relayPort: 8443}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := assertRemoteHealth(ctx, runner, value, "."); err != nil {
		t.Fatal(err)
	}
	if remoteHealthAttempts < 10 {
		t.Fatalf("remote health convergence attempts=%d, want at least 10", remoteHealthAttempts)
	}
}

func TestRetryRemoteHealthAcceptsOnlyAConfirmedBoundedRecovery(t *testing.T) {
	attempts := 0
	err := retryRemoteHealth(context.Background(), 4, 0, func() error {
		attempts++
		if attempts < 3 {
			return errors.New("not ready")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("attempts=%d, want 3", attempts)
	}
}

func TestRetryRemoteHealthFailsClosedAfterBoundedAttempts(t *testing.T) {
	attempts := 0
	err := retryRemoteHealth(context.Background(), 3, 0, func() error {
		attempts++
		return errors.New("not ready")
	})
	if err == nil {
		t.Fatal("persistent remote health failure accepted")
	}
	if attempts != 3 {
		t.Fatalf("attempts=%d, want 3", attempts)
	}
}

func TestPrepareIPv6CapabilityRestoresNetworkPolicyBeforeAuthorization(t *testing.T) {
	step := 0
	runner := commandRunner{runFunc: func(_ context.Context, stdin []byte, _ string, name string, arguments ...string) ([]byte, error) {
		if name != "ssh" || len(arguments) == 0 {
			return nil, errors.New("unexpected command")
		}
		step++
		command := arguments[len(arguments)-1]
		switch step {
		case 1:
			if !strings.Contains(command, "systemctl start kurd-node-network.service") {
				return nil, errors.New("network policy was not restored first")
			}
			return []byte("SERVICE_HEALTH_PASS\n"), nil
		case 2:
			if command != "sudo -n sh -s" {
				return nil, errors.New("IPv6 authorization must use a bounded stdin script")
			}
			if !strings.Contains(string(stdin), "IPV6_AUTHORIZED") || strings.Contains(command, "IPV6_AUTHORIZED") {
				return nil, errors.New("IPv6 authorization script was not isolated from argv")
			}
			return []byte("IPV6_AUTHORIZED\n"), nil
		case 3:
			if !strings.Contains(command, "systemctl start kurd-node.service") {
				return nil, errors.New("runtime health was not restored after authority reload")
			}
			return []byte("SERVICE_HEALTH_PASS\n"), nil
		default:
			return nil, errors.New("unexpected extra command")
		}
	}}
	value := config{sshAlias: "kurd-node", sshPath: "ssh", relayPort: 8443, ipv6ProbeAddress: "2001:db8::1"}
	authorized, err := prepareIPv6Capability(context.Background(), runner, value, ".")
	if err != nil {
		t.Fatal(err)
	}
	if !authorized || step != 3 {
		t.Fatalf("authorized=%v steps=%d", authorized, step)
	}
}

func TestPrepareRemoteCampaignAuthorityRotatesBeforeFieldTraffic(t *testing.T) {
	step := 0
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
		if name != "ssh" || len(arguments) == 0 {
			return nil, errors.New("unexpected command")
		}
		step++
		command := arguments[len(arguments)-1]
		switch step {
		case 1:
			if !strings.Contains(command, "keys rotate issuer") || !strings.Contains(command, "ISSUER_ROLLOVER_PASS") {
				return nil, errors.New("campaign issuer rollover missing")
			}
			return []byte("ISSUER_ROLLOVER_PASS\n"), nil
		case 2:
			if !strings.Contains(command, "systemctl start kurd-node.service") {
				return nil, errors.New("post-rollover health validation missing")
			}
			return []byte("SERVICE_HEALTH_PASS\n"), nil
		default:
			return nil, errors.New("unexpected extra command")
		}
	}}
	value := config{sshAlias: "kurd-node", sshPath: "ssh", relayPort: 8443}
	if err := prepareRemoteCampaignAuthority(context.Background(), runner, value, "."); err != nil {
		t.Fatal(err)
	}
	if step != 2 {
		t.Fatalf("steps=%d, want 2", step)
	}
}

func TestRemoteDnsDegradedCheckRequiresOnlyResolverToBeUnavailable(t *testing.T) {
	script := remoteDNSDegradedScript(8443)
	for _, required := range []string{
		"systemctl is-active --quiet kurd-node.service",
		"systemctl is-active --quiet kurd-node.socket",
		"systemctl is-active --quiet kurd-node-network.service",
		"! systemctl is-active --quiet unbound.service",
		"ss -H -ltn 'sport = :8443'",
		"printf DNS_DEGRADED_PASS",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("DNS degraded check missing %q", required)
		}
	}
}

func TestRemoteRollbackRestoreStopsRestoredListenersBeforeReinstall(t *testing.T) {
	script := remoteRollbackRestoreScript("/var/tmp/phase17-package", 8443)
	if !strings.Contains(script, "sudo -n test -x /var/lib/kurd-node/install/previous/bin/kurd-node") {
		t.Fatal("rollback snapshot precheck must cross the root-only install directory with explicit privilege")
	}
	rollbackAt := strings.Index(script, "rollback.sh --apply --confirm rollback")
	stopAt := strings.Index(script, "systemctl stop kurd-node.socket kurd-node.service kurd-node-network.service")
	installAt := strings.Index(script, `./install.sh --upgrade --port "$2"`)
	if rollbackAt < 0 || stopAt < 0 || installAt < 0 || !(rollbackAt < stopAt && stopAt < installAt) {
		t.Fatal("rollback recovery must stop the restored listeners before reinstall preflight")
	}
	for _, category := range []string{
		"ROLLBACK_APPLY_FAILED",
		"RESTORED_LISTENER_STOP_FAILED",
		"PACKAGE_REINSTALL_FAILED",
		"ROLLBACK_RESTORE_PASS",
	} {
		if !strings.Contains(script, category) {
			t.Fatalf("rollback recovery is missing safe category %q", category)
		}
	}
	if !strings.Contains(script, `sudo -n sh -c 'cd "$1" && ./install.sh --upgrade --port "$2"'`) {
		t.Fatal("reinstall must enter the root-only staged package inside the privileged shell")
	}
	if strings.Contains(script, "\ncd /var/tmp/phase17-package") {
		t.Fatal("reinstall must not traverse the root-only staged package as the SSH account")
	}
}

func TestAssertAndroidPrivacyUsesStablePackageUIDAfterInstrumentationExit(t *testing.T) {
	step := 0
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
		if name != "adb" {
			return nil, errors.New("unexpected command")
		}
		step++
		switch step {
		case 1:
			joined := strings.Join(arguments, " ")
			if !strings.Contains(joined, "shell cmd package list packages -U "+appPackage) || strings.Contains(joined, "pidof") {
				return nil, errors.New("package UID lookup missing")
			}
			return []byte("package:" + appPackage + " uid:10288\n"), nil
		case 2:
			joined := strings.Join(arguments, " ")
			if !strings.Contains(joined, "logcat -d -v brief --uid=10288") || strings.Contains(joined, "--pid") {
				return nil, errors.New("UID-scoped log scan missing")
			}
			return []byte("I/KurdistanVPN: categorical-state\n"), nil
		default:
			return nil, errors.New("unexpected extra command")
		}
	}}
	value := config{adbPath: "adb"}
	if err := assertAndroidPrivacy(context.Background(), runner, value, ".", "emulator-5554", []byte("https://probe.invalid/check")); err != nil {
		t.Fatal(err)
	}
	if step != 2 {
		t.Fatalf("steps=%d, want 2", step)
	}
}

func TestAssertAndroidPrivacyRejectsPrivateProbeEndpointInLogcat(t *testing.T) {
	for _, leaked := range []string{
		"I/KurdistanVPN: https://private-probe.invalid/check\n",
		"I/KurdistanVPN: private-probe.invalid\n",
		"I/KurdistanVPN: 2001:db8::7\n",
	} {
		t.Run(leaked, func(t *testing.T) {
			step := 0
			runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
				if name != "adb" {
					return nil, errors.New("unexpected command")
				}
				step++
				if step == 1 {
					return []byte("package:" + appPackage + " uid:10288\n"), nil
				}
				return []byte(leaked), nil
			}}
			value := config{adbPath: "adb", ipv6ProbeAddress: "2001:db8::7"}
			if err := assertAndroidPrivacy(context.Background(), runner, value, ".", "emulator-5554", []byte("https://private-probe.invalid/check")); err == nil {
				t.Fatal("private probe endpoint was accepted in Android logs")
			}
		})
	}
}

func TestAssertAndroidPrivacyScansCompleteBufferBeyondGenericCommandLimit(t *testing.T) {
	benign := bytes.Repeat([]byte{'x'}, maxOutputBytes+1024)
	if len(benign) <= maxOutputBytes {
		t.Fatalf("fixture bytes=%d, want more than generic command bound %d", len(benign), maxOutputBytes)
	}
	if len(benign) >= maxAndroidPrivacyLogBytes {
		t.Fatalf("fixture bytes=%d, want less than privacy bound %d", len(benign), maxAndroidPrivacyLogBytes)
	}
	step := 0
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, _ ...string) ([]byte, error) {
		if name != "adb" {
			return nil, errors.New("unexpected command")
		}
		step++
		if step == 1 {
			return []byte("package:" + appPackage + " uid:10288\n"), nil
		}
		return benign, nil
	}}
	value := config{adbPath: "adb"}
	if err := assertAndroidPrivacy(context.Background(), runner, value, ".", "emulator-5554", []byte("https://probe.invalid/check")); err != nil {
		t.Fatal(err)
	}
}

func TestAssertAndroidPrivacyRejectsBufferBeyondDedicatedBound(t *testing.T) {
	step := 0
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, _ ...string) ([]byte, error) {
		if name != "adb" {
			return nil, errors.New("unexpected command")
		}
		step++
		if step == 1 {
			return []byte("package:" + appPackage + " uid:10288\n"), nil
		}
		return bytes.Repeat([]byte{'x'}, maxAndroidPrivacyLogBytes+1), nil
	}}
	value := config{adbPath: "adb"}
	err := assertAndroidPrivacy(context.Background(), runner, value, ".", "emulator-5554", []byte("https://probe.invalid/check"))
	if err == nil || err.Error() != "Android privacy log scan unavailable" {
		t.Fatalf("error=%v, want bounded privacy scan failure", err)
	}
}

func TestRunBytesWithLimitEnforcesBoundForInjectedRunner(t *testing.T) {
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, _ string, _ ...string) ([]byte, error) {
		return []byte("123456789"), nil
	}}
	if _, err := runBytesWithLimit(context.Background(), runner, nil, ".", time.Second, 8, "fixture"); err == nil {
		t.Fatal("injected runner output beyond the requested bound was accepted")
	}
}

func TestParsePackageUIDRejectsAmbiguousOrMalformedIdentity(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
	}{
		{name: "empty", raw: ""},
		{name: "wrong package", raw: "package:example.invalid uid:10288"},
		{name: "multiple lines", raw: "package:" + appPackage + " uid:10288\npackage:" + appPackage + " uid:10289"},
		{name: "zero", raw: "package:" + appPackage + " uid:0"},
		{name: "negative", raw: "package:" + appPackage + " uid:-1"},
		{name: "suffix", raw: "package:" + appPackage + " uid:10288 extra"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parsePackageUID(test.raw, appPackage); err == nil {
				t.Fatal("malformed package identity accepted")
			}
		})
	}
}

func TestParsePackageUIDSelectsExactPackageFromPrefixMatches(t *testing.T) {
	raw := "package:" + appPackage + " uid:10288\npackage:" + appPackage + ".test uid:10289\n"
	uid, err := parsePackageUID(raw, appPackage)
	if err != nil {
		t.Fatal(err)
	}
	if uid != "10288" {
		t.Fatalf("uid=%q, want 10288", uid)
	}
}

func TestRemoteMetricsCommandUsesReadOnlyPrivilegeForProtectedProcState(t *testing.T) {
	command := remoteMetricsCommand()
	if !strings.HasPrefix(command, "sudo -n sh -c ") {
		t.Fatal("resource measurement must enter the protected process namespace explicitly")
	}
	for _, required := range []string{"/proc/$pid/status", "/proc/$pid/fd", "ip -o -6 route show default"} {
		if !strings.Contains(command, required) {
			t.Fatalf("resource measurement missing %q", required)
		}
	}
	for _, forbidden := range []string{"kill ", "systemctl stop", "systemctl restart", "rm -"} {
		if strings.Contains(command, forbidden) {
			t.Fatalf("resource measurement must remain read-only: found %q", forbidden)
		}
	}
}

func TestFieldRuntimeMetricsStayInsideLiveProfileWindow(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	runFieldStart := bytes.Index(source, []byte("func runField("))
	runFunctionalStart := bytes.Index(source, []byte("func runFunctional("))
	if runFieldStart < 0 || runFunctionalStart < 0 {
		t.Fatal("field orchestration boundary unavailable")
	}
	issueStart := bytes.Index(source[runFunctionalStart:], []byte("issueAndActivateProfile("))
	verifyStart := bytes.Index(source[runFunctionalStart:], []byte("verifyFieldTraffic("))
	revokeStart := bytes.Index(source[runFunctionalStart:], []byte("revokeRemoteProfile("))
	functionalEnd := bytes.Index(source[runFunctionalStart:], []byte("\n}\n\nfunc issueAndActivateProfile("))
	if issueStart < 0 || verifyStart < 0 || revokeStart < 0 || functionalEnd < 0 {
		t.Fatal("field orchestration boundary unavailable")
	}
	runFieldBody := source[runFieldStart:runFunctionalStart]
	if bytes.Contains(runFieldBody, []byte("observeRemoteMetrics(")) {
		t.Fatal("runtime metrics sampled before a live profile exists")
	}
	functionalBody := source[runFunctionalStart : runFunctionalStart+functionalEnd]
	firstSample := bytes.Index(functionalBody, []byte("observeRemoteMetrics("))
	lastSample := bytes.LastIndex(functionalBody, []byte("observeRemoteMetrics("))
	if !(issueStart < verifyStart && verifyStart < firstSample && firstSample < lastSample && lastSample < revokeStart) {
		t.Fatalf("runtime metrics are outside the active profile window: issue=%d verify=%d first=%d last=%d revoke=%d", issueStart, verifyStart, firstSample, lastSample, revokeStart)
	}
}

func TestPrepareAndroidPackagesCompilesExactInstalledArtifactsBeforeFieldActions(t *testing.T) {
	var commands []string
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
		commands = append(commands, name+" "+strings.Join(arguments, " "))
		if len(arguments) >= 7 && arguments[2] == "shell" && arguments[3] == "cmd" && arguments[4] == "package" && arguments[5] == "compile" {
			return []byte("Success\n"), nil
		}
		return []byte("Success\n"), nil
	}}
	value := config{adbPath: "adb", appAPK: "app.apk", testAPK: "test.apk"}
	if err := prepareAndroidPackages(context.Background(), runner, value, ".", "emulator-5554"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"adb -s emulator-5554 install -r -t app.apk",
		"adb -s emulator-5554 install -r -t test.apk",
		"adb -s emulator-5554 shell cmd package compile -m speed -f org.kurdistanvpn.app.internal",
		"adb -s emulator-5554 shell cmd package compile -m speed -f org.kurdistanvpn.app.internal.test",
		"adb -s emulator-5554 shell appops set org.kurdistanvpn.app.internal ACTIVATE_VPN allow",
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands=%q, want %q", commands, want)
	}
}

func TestVerifyFieldTrafficProvesTunnelDNSAndHostnameDataPlaneInOneVpnSession(t *testing.T) {
	for _, test := range []struct {
		name           string
		ipv6Authorized bool
		wantIPv6       string
	}{
		{name: "IPv4 only", wantIPv6: "false"},
		{name: "dual stack", ipv6Authorized: true, wantIPv6: "true"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var actions []string
			var activeAction string
			var instrumentationArguments []string
			runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
				if name != "adb" {
					return nil, fmt.Errorf("unexpected command %q", name)
				}
				for index, argument := range arguments {
					if argument == "phase17FieldAction" && index+1 < len(arguments) {
						activeAction = arguments[index+1]
						actions = append(actions, activeAction)
						instrumentationArguments = append([]string(nil), arguments...)
						return []byte("OK (1 test)\n"), nil
					}
				}
				if len(arguments) >= 6 && arguments[2] == "shell" && arguments[3] == "run-as" && arguments[5] == "cat" {
					if activeAction == "traffic" {
						return []byte("TRAFFIC_VERIFIED\n"), nil
					}
					return nil, errors.New("field action unavailable")
				}
				return []byte(""), nil
			}}
			value := config{adbPath: "adb"}
			if err := verifyFieldTraffic(
				context.Background(), runner, value, "", "emulator-5554",
				[]byte("https://probe.example/"), []byte(strings.Repeat("0", 64)), test.ipv6Authorized,
			); err != nil {
				t.Fatal(err)
			}
			if want := []string{"traffic"}; !reflect.DeepEqual(actions, want) {
				t.Fatalf("actions=%v, want %v", actions, want)
			}
			for key, want := range map[string]string{
				"phase17ProbeUrl":               "https://probe.example/",
				"phase17ExpectedResponseSha256": strings.Repeat("0", 64),
				"phase17VerifyIPv6":             test.wantIPv6,
			} {
				if !instrumentationExtraEquals(instrumentationArguments, key, want) {
					t.Fatalf("instrumentation extra %s=%q missing from %q", key, want, instrumentationArguments)
				}
			}
		})
	}
}

func instrumentationExtraEquals(arguments []string, key, want string) bool {
	for index := 0; index+2 < len(arguments); index++ {
		if arguments[index] == "-e" && arguments[index+1] == key && arguments[index+2] == want {
			return true
		}
	}
	return false
}

func TestFieldHarnessBindsDNSAndHostnameTrafficToTheSameVerifiedVpnNetwork(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(
		"..", "..", "android", "app", "src", "androidTest", "kotlin",
		"org", "kurdistanvpn", "app", "Phase17FieldHarness.kt",
	))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte(`"traffic" ->`),
		[]byte(`"TRAFFIC_VERIFIED\n"`),
		[]byte("vpnNetwork.bindSocket(socket)"),
		[]byte("vpnNetwork.openConnection(uri.toURL())"),
	} {
		if !bytes.Contains(source, required) {
			t.Fatalf("field harness missing same-session VPN binding %q", required)
		}
	}
	if bytes.Contains(source, []byte("uri.toURL().openConnection()")) {
		t.Fatal("hostname probe still relies on asynchronous process-default network selection")
	}
	for _, required := range [][]byte{
		[]byte("awaitVpnNetworkTeardown(application)"),
		[]byte("connectivity.activeNetwork"),
		[]byte("NetworkCapabilities.TRANSPORT_VPN"),
		[]byte("VPN_NETWORK_TEARDOWN_TIMEOUT"),
	} {
		if !bytes.Contains(source, required) {
			t.Fatalf("field harness missing teardown synchronization %q", required)
		}
	}
}

func TestInstrumentationFailureCategoryRejectsAndroidProcessCrash(t *testing.T) {
	got := instrumentationFailureCategory([]byte("INSTRUMENTATION_RESULT: shortMsg=Process crashed.\nINSTRUMENTATION_CODE: 0\n"))
	if got != "INSTRUMENTATION_PROCESS_CRASH" {
		t.Fatalf("category=%q, want INSTRUMENTATION_PROCESS_CRASH", got)
	}
}

func TestInstrumentationFailureCategoryClassifiesSafeDataPlaneBoundary(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "dns resolution",
			raw:  "java.net.UnknownHostException: private.example.invalid\nFAILURES!!!\n",
			want: "DATA_PLANE_DNS_RESOLUTION_FAILED",
		},
		{
			name: "connect timeout",
			raw:  "java.net.SocketTimeoutException: connect timed out\nFAILURES!!!\n",
			want: "DATA_PLANE_CONNECT_TIMEOUT",
		},
		{
			name: "read timeout",
			raw:  "java.net.SocketTimeoutException: Read timed out\nFAILURES!!!\n",
			want: "DATA_PLANE_READ_TIMEOUT",
		},
		{
			name: "tls handshake",
			raw:  "javax.net.ssl.SSLHandshakeException: private certificate detail\nFAILURES!!!\n",
			want: "DATA_PLANE_TLS_HANDSHAKE_FAILED",
		},
		{
			name: "connect failure",
			raw:  "java.net.ConnectException: private endpoint detail\nFAILURES!!!\n",
			want: "DATA_PLANE_CONNECT_FAILED",
		},
		{
			name: "rapid reconnect fallback",
			raw:  "LIVE_CONNECT_FAILED:LIVE_FALLBACK_EXHAUSTED:LIVE_STAGE_SOCKET_PROTECTED\nFAILURES!!!\n",
			want: "LIVE_CONNECT_FAILED:LIVE_FALLBACK_EXHAUSTED:LIVE_STAGE_SOCKET_PROTECTED",
		},
		{
			name: "teardown readiness timeout",
			raw:  "VPN_NETWORK_TEARDOWN_TIMEOUT\nFAILURES!!!\n",
			want: "VPN_NETWORK_TEARDOWN_TIMEOUT",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := instrumentationFailureCategory([]byte(test.raw))
			if got != test.want {
				t.Fatalf("category=%q, want %q", got, test.want)
			}
			if strings.Contains(got, "private") || strings.Contains(got, "example") {
				t.Fatalf("category exposed private instrumentation output: %q", got)
			}
		})
	}
}

func TestFieldActionsUseDedicatedNonComposeInstrumentationEntryPoint(t *testing.T) {
	want := "org.kurdistanvpn.app.Phase17FieldActionDeviceTest#runRequestedFieldAction"
	if fieldTest != want {
		t.Fatalf("fieldTest=%q, want %q", fieldTest, want)
	}
	source, err := os.ReadFile(filepath.Join("..", "..", "android", "app", "src", "androidTest", "kotlin", "org", "kurdistanvpn", "app", "Phase17FieldActionDeviceTest.kt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range [][]byte{
		[]byte("createAndroidComposeRule"),
		[]byte("ActivityScenario"),
		[]byte("MainActivity"),
	} {
		if bytes.Contains(source, prohibited) {
			t.Fatalf("field action entry point contains UI lifecycle dependency %q", prohibited)
		}
	}
}

type countingConnectionGate struct{ calls int }

func (gate *countingConnectionGate) wait(context.Context) error {
	gate.calls++
	return nil
}

func TestCommandRunnerPacesOnlyConfiguredRemoteConnections(t *testing.T) {
	gate := &countingConnectionGate{}
	runner := commandRunner{
		remoteGate:     gate,
		remoteCommands: map[string]struct{}{"ssh": {}, "scp": {}},
		runFunc: func(_ context.Context, _ []byte, _ string, _ string, _ ...string) ([]byte, error) {
			return nil, nil
		},
	}
	for _, command := range []string{"ssh", "scp", "adb"} {
		if _, err := runner.run(context.Background(), nil, ".", command); err != nil {
			t.Fatal(err)
		}
	}
	if gate.calls != 2 {
		t.Fatalf("remote gate calls = %d, want 2", gate.calls)
	}
}

func TestIssueProfileLeavesExclusiveOutputCreationToKurdctl(t *testing.T) {
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
		switch name {
		case "ssh":
			command := arguments[len(arguments)-1]
			if strings.Contains(command, "profile create") {
				if strings.Contains(command, "install -d -o kurd-node -g kurd-node -m 0700 \"$out\"") {
					return []byte("kurdctl: output exists\n"), errors.New("command failed")
				}
				return []byte("PHASE17_ISSUE_READY\n"), nil
			}
			if strings.Contains(command, ".response") {
				return []byte("{\"schema\":\"kurdctl-profile-create-v2\",\"profileId\":\"profile.test\"}\n"), nil
			}
			return nil, nil
		case "scp":
			destination := arguments[len(arguments)-1]
			if strings.Contains(destination, ":/tmp/phase17-recipient-") {
				return nil, nil
			}
			return nil, os.WriteFile(destination, []byte("sealed-profile"), 0o600)
		default:
			return nil, errors.New("unexpected command")
		}
	}}
	value := config{sshAlias: "kurd-node", sshPath: "ssh", scpPath: "scp"}
	profileID, artifact, err := issueProfile(context.Background(), runner, value, t.TempDir(), []byte("recipient-request"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(artifact)
	if profileID != "profile.test" || string(artifact) != "sealed-profile" {
		t.Fatalf("profile=%q artifact=%q", profileID, artifact)
	}
}

func TestIssueProfileUsesOwnerPrivateRemoteOutputDirectory(t *testing.T) {
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
		switch name {
		case "ssh":
			command := arguments[len(arguments)-1]
			switch {
			case strings.Contains(command, "profile create"):
				if strings.Contains(command, `out="/var/tmp/`) || !strings.Contains(command, `out="/var/lib/kurd-node/.phase17-profile-`) ||
					!strings.Contains(command, `sudo -n test -s "$out/profile.kurd-profile"`) {
					return []byte("kurdctl: unsupported filesystem\n"), errors.New("command failed")
				}
				return []byte("PHASE17_ISSUE_READY\n"), nil
			case strings.Contains(command, ".response"):
				return []byte("{\"schema\":\"kurdctl-profile-create-v2\",\"profileId\":\"profile.private-output\"}\n"), nil
			default:
				return nil, nil
			}
		case "scp":
			destination := arguments[len(arguments)-1]
			if strings.Contains(destination, ":/tmp/phase17-recipient-") {
				return nil, nil
			}
			return nil, os.WriteFile(destination, []byte("sealed-profile"), 0o600)
		default:
			return nil, errors.New("unexpected command")
		}
	}}
	value := config{sshAlias: "kurd-node", sshPath: "ssh", scpPath: "scp"}
	profileID, artifact, err := issueProfile(context.Background(), runner, value, t.TempDir(), []byte("recipient-request"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(artifact)
	if profileID != "profile.private-output" || string(artifact) != "sealed-profile" {
		t.Fatalf("profile=%q artifact=%q", profileID, artifact)
	}
}

func TestIssueProfileRecoversCompletedIssuanceAfterSSHTransportLossWithoutReissuing(t *testing.T) {
	createCalls := 0
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
		switch name {
		case "ssh":
			command := arguments[len(arguments)-1]
			switch {
			case strings.Contains(command, "profile create"):
				createCalls++
				return []byte("connection reset\n"), errors.New("command failed")
			case strings.Contains(command, "PHASE17_ISSUE_READY"):
				return []byte("PHASE17_ISSUE_READY\n"), nil
			case strings.Contains(command, ".response"):
				return []byte("{\"schema\":\"kurdctl-profile-create-v2\",\"profileId\":\"profile.recovered\"}\n"), nil
			default:
				return nil, nil
			}
		case "scp":
			destination := arguments[len(arguments)-1]
			if strings.Contains(destination, ":/tmp/phase17-recipient-") {
				return nil, nil
			}
			return nil, os.WriteFile(destination, []byte("sealed-profile"), 0o600)
		default:
			return nil, errors.New("unexpected command")
		}
	}}
	value := config{sshAlias: "kurd-node", sshPath: "ssh", scpPath: "scp"}
	profileID, artifact, err := issueProfile(context.Background(), runner, value, t.TempDir(), []byte("recipient-request"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(artifact)
	if createCalls != 1 {
		t.Fatalf("profile creation attempts = %d, want exactly one", createCalls)
	}
	if profileID != "profile.recovered" || string(artifact) != "sealed-profile" {
		t.Fatalf("profile=%q artifact=%q", profileID, artifact)
	}
}

func TestIssueProfileRecoversCommittedOutputWhenRuntimeReloadWasPending(t *testing.T) {
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
		switch name {
		case "ssh":
			command := arguments[len(arguments)-1]
			switch {
			case strings.Contains(command, "profile create"):
				for _, required := range []string{
					`status=0`,
					`[ -s "$response" ] && sudo -n test -s "$out/profile.kurd-profile"`,
					`[ "$status" -eq 7 ]`,
					`kurdctl node reload`,
				} {
					if !strings.Contains(command, required) {
						return []byte("kurdctl: state committed; runtime notification pending\n"), errors.New("command failed")
					}
				}
				return []byte("PHASE17_ISSUE_READY\n"), nil
			case strings.Contains(command, ".response"):
				return []byte("{\"schema\":\"kurdctl-profile-create-v2\",\"profileId\":\"profile.pending\"}\n"), nil
			default:
				return nil, nil
			}
		case "scp":
			destination := arguments[len(arguments)-1]
			if strings.Contains(destination, ":/tmp/phase17-recipient-") {
				return nil, nil
			}
			return nil, os.WriteFile(destination, []byte("sealed-profile"), 0o600)
		default:
			return nil, errors.New("unexpected command")
		}
	}}
	value := config{sshAlias: "kurd-node", sshPath: "ssh", scpPath: "scp"}
	profileID, artifact, err := issueProfile(context.Background(), runner, value, t.TempDir(), []byte("recipient-request"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(artifact)
	if profileID != "profile.pending" || string(artifact) != "sealed-profile" {
		t.Fatalf("profile=%q artifact=%q", profileID, artifact)
	}
}

func TestCategorizeProfileIssuanceFailureReturnsOnlySafeKnownCategories(t *testing.T) {
	for name, test := range map[string]struct {
		raw  string
		want string
	}{
		"registry":   {raw: "kurdctl: recipient registry rejected\n", want: "profile issuance rejected: recipient registry unavailable"},
		"replay":     {raw: "kurdctl: request rejected\n", want: "profile issuance rejected: recipient request unavailable"},
		"authority":  {raw: "kurdctl: recipient authority rejected\n", want: "profile issuance rejected: recipient authority unavailable"},
		"capacity":   {raw: "kurdctl: capacity exhausted\n", want: "profile issuance rejected: node capacity unavailable"},
		"tls":        {raw: "kurdctl: tls validity rejected\n", want: "profile issuance rejected: relay TLS unavailable"},
		"filesystem": {raw: "kurdctl: unsupported filesystem\n", want: "profile issuance rejected: private output filesystem unavailable"},
		"reload":     {raw: "PROFILE_RUNTIME_RELOAD_FAILED\n", want: "profile issuance committed: relay runtime reload failed"},
		"response":   {raw: "PROFILE_COMMITTED_RESPONSE_MISSING\n", want: "profile issuance committed: response evidence unavailable"},
		"artifact":   {raw: "PROFILE_COMMITTED_ARTIFACT_MISSING\n", want: "profile issuance committed: artifact evidence unavailable"},
		"owner":      {raw: "PROFILE_REQUEST_OWNER_FAILED\n", want: "profile issuance rejected: request ownership unavailable"},
		"mode":       {raw: "PROFILE_REQUEST_MODE_FAILED\n", want: "profile issuance rejected: request protection unavailable"},
		"stage":      {raw: "PROFILE_ARTIFACT_STAGE_FAILED\n", want: "profile issuance committed: artifact staging unavailable"},
		"command":    {raw: "PROFILE_COMMAND_FAILED_1\n", want: "profile issuance failed: command produced no category"},
	} {
		t.Run(name, func(t *testing.T) {
			err := categorizeProfileIssuanceFailure([]byte(test.raw))
			if err == nil || err.Error() != test.want {
				t.Fatalf("category error = %v, want %q", err, test.want)
			}
			if !safeCategory([]byte(err.Error())) {
				t.Fatalf("category is not privacy-safe: %v", err)
			}
		})
	}
}

func TestCategorizeProfileIssuanceFailureDoesNotEchoUnknownOutput(t *testing.T) {
	raw := []byte("kurdctl: unexpected failure endpoint 198.51.100.7 password=secret\n")
	err := categorizeProfileIssuanceFailure(raw)
	if err == nil || err.Error() != "profile issuance failed" {
		t.Fatalf("unknown failure category = %v", err)
	}
	if strings.Contains(err.Error(), "198.51.100.7") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unknown failure leaked command output: %v", err)
	}
}

func TestRemoteRecoveryScriptUsesCurrentTransactionalBackupRestoreAndRegistry(t *testing.T) {
	script := remoteRecoveryScript()
	for _, required := range []string{
		"pass=/root/.kurd-node-field/current-passphrase",
		"recovery=/root/.kurd-node-field/current.kurd-recovery",
		"chown kurd-node:kurd-node \"$tmp\"",
		"backup create --data-dir /var/lib/kurd-node --recipient-registry-dir /var/lib/kurd-node/recipient-registry",
		"restore preview --file \"$backup\" --data-dir \"$restored\"",
		"restore apply --file \"$backup\" --data-dir \"$restored\" --recipient-registry-dir \"$restored/recipient-registry\" --expected-digest \"$digest\"",
		"recovery confirm --data-dir \"$restored\" --recovery-file \"$work/recovery\"",
		"cleanup()",
		"RECOVERY_BACKUP_PASS",
		"[ ! -e \"$restored\" ]",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("recovery script missing %q", required)
		}
	}
	confirm := strings.Index(script, "recovery confirm --data-dir \"$restored\"")
	doctor := strings.Index(script, "doctor --data-dir \"$restored\"")
	if confirm < 0 || doctor < 0 || confirm > doctor {
		t.Fatal("restored state was examined before its offline recovery was explicitly reconfirmed")
	}
	for _, rejected := range []string{
		"find /root /var/lib /var/backups",
		"kurdctl restore --file",
		"install -d -o kurd-node -g kurd-node -m 0700 \"$restored\"",
		"sha256sum \"$backup\"",
		"deployment disable",
		"deployment enable",
	} {
		if strings.Contains(script, rejected) {
			t.Fatalf("recovery script retains unsafe legacy flow %q", rejected)
		}
	}
}

func TestRemoteRevocationScriptGrantsKurdNodeAccessToPrivateWorkspace(t *testing.T) {
	script := remoteRevocationScript("profiles.test")
	for _, required := range []string{
		"chown kurd-node:kurd-node \"$tmp\"",
		"install -o kurd-node -g kurd-node -m 0600 \"$recovery\" \"$tmp/recovery\"",
		"profile_id='profiles.test'",
		"--profile-id \"$profile_id\"",
		"--confirm-profile \"$profile_id\"",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("revocation script missing %q", required)
		}
	}
}

func TestRemoveRemoteProfileRevokesIssuedFieldAuthority(t *testing.T) {
	calls := 0
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
		if name != "ssh" || len(arguments) == 0 || !strings.Contains(arguments[len(arguments)-1], "profile revoke") {
			return nil, errors.New("unexpected cleanup command")
		}
		calls++
		return []byte("REVOKE_PASS"), nil
	}}
	value := config{sshPath: "ssh", sshAlias: "kurd-node"}
	if err := removeRemoteProfile(context.Background(), runner, value, "", "profiles.field"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("cleanup revocation calls=%d", calls)
	}
}

func TestRevokeRemoteProfileReconcilesCommittedRuntimeNotification(t *testing.T) {
	calls := 0
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
		if name != "ssh" || len(arguments) == 0 {
			return nil, errors.New("unexpected executable")
		}
		calls++
		command := arguments[len(arguments)-1]
		switch calls {
		case 1:
			if !strings.Contains(command, "profile revoke") {
				return nil, errors.New("initial revocation missing")
			}
			return []byte("REVOKE_COMMITTED_PENDING"), errors.New("command failed")
		case 2:
			for _, required := range []string{"profile show", "\"revoked\":true", "node reload", "systemctl restart kurd-node.socket kurd-node.service"} {
				if !strings.Contains(command, required) {
					return nil, fmt.Errorf("reconciliation missing %q", required)
				}
			}
			return []byte("REVOKE_PASS"), nil
		default:
			return nil, errors.New("unexpected extra command")
		}
	}}
	value := config{sshPath: "ssh", sshAlias: "kurd-node"}
	if err := revokeRemoteProfile(context.Background(), runner, value, "", "profiles.field"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("revocation calls=%d, want 2", calls)
	}
}

func TestSetRemoteDeploymentReconcilesCommittedRuntimeNotification(t *testing.T) {
	calls := 0
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
		if name != "ssh" || len(arguments) == 0 {
			return nil, errors.New("unexpected executable")
		}
		calls++
		command := arguments[len(arguments)-1]
		switch calls {
		case 1:
			if !strings.Contains(command, "deployment disable") {
				return nil, errors.New("initial deployment disable missing")
			}
			return []byte("DEPLOYMENT_COMMITTED_PENDING"), errors.New("command failed")
		case 2:
			for _, required := range []string{"deployment status", "node reload", "systemctl restart kurd-node.socket kurd-node.service"} {
				if !strings.Contains(command, required) {
					return nil, fmt.Errorf("reconciliation missing %q", required)
				}
			}
			return []byte("DEPLOYMENT_RECONCILE_PASS"), nil
		case 3:
			if !strings.Contains(command, "deployment status") {
				return nil, errors.New("deployment state verification missing")
			}
			return []byte("DEPLOYMENT_DISABLED"), nil
		default:
			return nil, errors.New("unexpected extra command")
		}
	}}
	value := config{sshPath: "ssh", sshAlias: "kurd-node"}
	if err := setRemoteDeployment(context.Background(), runner, value, "", true); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("deployment calls=%d, want 3", calls)
	}
}

func TestWithRemoteDeploymentDisabledReenablesAfterFailure(t *testing.T) {
	calls := 0
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
		if name != "ssh" || len(arguments) == 0 {
			return nil, errors.New("unexpected executable")
		}
		calls++
		command := arguments[len(arguments)-1]
		switch calls {
		case 1:
			if !strings.Contains(command, "deployment disable") {
				return nil, errors.New("disable mutation missing")
			}
			return []byte("DEPLOYMENT_MUTATION_PASS"), nil
		case 2, 3:
			if !strings.Contains(command, "deployment status") {
				return nil, errors.New("disabled state verification missing")
			}
			return []byte("DEPLOYMENT_DISABLED"), nil
		case 4:
			if !strings.Contains(command, "deployment enable") {
				return nil, errors.New("fail-safe enable mutation missing")
			}
			return []byte("DEPLOYMENT_MUTATION_PASS"), nil
		case 5:
			if !strings.Contains(command, "deployment status") {
				return nil, errors.New("enabled state verification missing")
			}
			return []byte("DEPLOYMENT_ENABLED"), nil
		default:
			return nil, errors.New("unexpected extra command")
		}
	}}
	value := config{sshPath: "ssh", sshAlias: "kurd-node"}
	injected := errors.New("injected disabled-state check failure")
	err := withRemoteDeploymentDisabled(context.Background(), runner, value, "", func() error { return injected })
	if !errors.Is(err, injected) {
		t.Fatalf("recovery error=%v, want injected failure", err)
	}
	if calls != 5 {
		t.Fatalf("deployment calls=%d, want 5", calls)
	}
}

func TestRunFieldActionDeletesStaleEvidenceBeforeInstrumentation(t *testing.T) {
	step := 0
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
		if name != "adb" {
			return nil, errors.New("unexpected executable")
		}
		step++
		switch step {
		case 1:
			joined := strings.Join(arguments, " ")
			if !strings.Contains(joined, "run-as "+appPackage+" rm -f "+fieldResultFile) {
				return nil, errors.New("stale evidence was not cleared first")
			}
			return nil, nil
		case 2:
			if !strings.Contains(strings.Join(arguments, " "), "am instrument") {
				return nil, errors.New("instrumentation was not second")
			}
			return []byte("OK"), nil
		case 3:
			if !strings.Contains(strings.Join(arguments, " "), "run-as "+appPackage+" cat "+fieldResultFile) {
				return nil, errors.New("evidence read was not last")
			}
			return []byte("CONNECTED"), nil
		default:
			return nil, errors.New("unexpected extra command")
		}
	}}
	value := config{adbPath: "adb"}
	if err := runFieldAction(context.Background(), runner, value, "", "emulator-5554", "connect", nil, "CONNECTED"); err != nil {
		t.Fatal(err)
	}
}

func TestRunFieldActionReportsCategoricalInstrumentationFailureWithoutReadingMissingEvidence(t *testing.T) {
	step := 0
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
		if name != "adb" {
			return nil, errors.New("unexpected executable")
		}
		step++
		switch step {
		case 1:
			return nil, nil
		case 2:
			return []byte("INSTRUMENTATION_STATUS: stack=java.lang.IllegalStateException: LIVE_CONNECT_FAILED:LIVE_TLS_REJECTED:LIVE_STAGE_SOCKET_PROTECTED\nFAILURES!!!\n"), nil
		default:
			return nil, errors.New("missing evidence must not be read after a reported instrumentation failure")
		}
	}}
	value := config{adbPath: "adb"}
	err := runFieldAction(context.Background(), runner, value, "", "emulator-5554", "dns-probe", nil, "DNS_IPV4_VERIFIED")
	if err == nil || err.Error() != "Android field action dns-probe failed: LIVE_CONNECT_FAILED:LIVE_TLS_REJECTED:LIVE_STAGE_SOCKET_PROTECTED" {
		t.Fatalf("unexpected categorical failure: %v", err)
	}
	if step != 2 {
		t.Fatalf("steps=%d, want 2", step)
	}
}

func TestInstrumentationFailureCategoryNeverSurfacesSurroundingPrivateOutput(t *testing.T) {
	raw := []byte("private endpoint https://private.invalid/check\njava.lang.IllegalStateException: LIVE_CONNECT_FAILED:LIVE_TLS_REJECTED:LIVE_STAGE_SOCKET_PROTECTED\n")
	category := instrumentationFailureCategory(raw)
	if category != "LIVE_CONNECT_FAILED:LIVE_TLS_REJECTED:LIVE_STAGE_SOCKET_PROTECTED" {
		t.Fatalf("category=%q", category)
	}
	if strings.Contains(category, "private") || strings.Contains(category, "https") {
		t.Fatal("categorical failure exposed surrounding private instrumentation output")
	}
}

func TestInstrumentationFailureCategoryFailsClosedForUnknownInstrumentationFailure(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte("FAILURES!!!\nunknown stack trace\n"),
		[]byte("INSTRUMENTATION_FAILED: process crashed\n"),
	} {
		if category := instrumentationFailureCategory(raw); category != "INSTRUMENTATION_FAILED" {
			t.Fatalf("category=%q, want INSTRUMENTATION_FAILED", category)
		}
	}
}

func TestValidateConfigAcceptsBoundedFunctionalRun(t *testing.T) {
	value := config{
		sshAlias: "kurd-node", avdName: "Pixel_10_Pro", evidenceRoot: ".tools/phase17/field",
		mode: "Functional", relayPort: 8443, packagePath: "node.tar.gz", appAPK: "app.apk",
		testAPK: "test.apk", adbPath: "adb", sshPath: "ssh", scpPath: "scp",
		ipv6ProbeAddress: "2001:db8::53",
	}
	if err := validateConfig(value); err != nil {
		t.Fatal(err)
	}
}

func TestValidateConfigAcceptsStressAndSoakModes(t *testing.T) {
	base := config{
		sshAlias: "kurd-node", avdName: "Pixel_10_Pro", evidenceRoot: ".tools/phase17/field",
		relayPort: 8443, packagePath: "node.tar.gz", appAPK: "app.apk",
		testAPK: "test.apk", adbPath: "adb", sshPath: "ssh", scpPath: "scp",
		ipv6ProbeAddress: "2001:db8::53",
	}
	for _, mode := range []string{"Stress", "Soak12h"} {
		value := base
		value.mode = mode
		if err := validateConfig(value); err != nil {
			t.Fatalf("mode %q rejected: %v", mode, err)
		}
	}
}

func TestExecuteStressCampaignRunsExactFrozenInventory(t *testing.T) {
	restarts := 0
	rotations := 0
	impairments := make([]string, 0, len(frozenImpairmentMatrix))
	samples := 0
	progress := make([]string, 0, frozenRestartCycles+frozenProfileRotationCycles+len(frozenImpairmentMatrix))
	actions := stressActions{
		restartReconnect: func(context.Context, int) error { restarts++; return nil },
		rotateReissue:    func(context.Context, int) error { rotations++; return nil },
		impair: func(_ context.Context, name string) error {
			impairments = append(impairments, name)
			return nil
		},
		sample: func(context.Context) error { samples++; return nil },
		progress: func(category string, completed, total int) {
			progress = append(progress, fmt.Sprintf("%s:%d/%d", category, completed, total))
		},
	}
	if err := executeStressCampaign(context.Background(), actions); err != nil {
		t.Fatal(err)
	}
	if restarts != frozenRestartCycles {
		t.Fatalf("restart cycles=%d, want %d", restarts, frozenRestartCycles)
	}
	if rotations != frozenProfileRotationCycles {
		t.Fatalf("profile rotation cycles=%d, want %d", rotations, frozenProfileRotationCycles)
	}
	if !reflect.DeepEqual(impairments, []string{"bandwidth", "latency", "loss", "combined", "carrier-reset"}) {
		t.Fatalf("impairment matrix=%v", impairments)
	}
	wantSamples := frozenRestartCycles + frozenProfileRotationCycles + len(frozenImpairmentMatrix)
	if samples != wantSamples {
		t.Fatalf("resource samples=%d, want %d", samples, wantSamples)
	}
	if len(progress) != wantSamples || progress[0] != "restart-reconnect:1/100" || progress[frozenRestartCycles] != "profile-rotation:1/100" || progress[len(progress)-1] != "impairment:5/5" {
		t.Fatalf("progress inventory=%v", progress)
	}
}

func TestReadCleanSourceIdentityRequiresAnExactCommittedTree(t *testing.T) {
	const commit = "1111111111111111111111111111111111111111"
	const tree = "2222222222222222222222222222222222222222"
	for name, status := range map[string]string{
		"tracked":   " M internal/runtime/ip_tunnel_v1.go\n",
		"untracked": "?? cmd/phase17field/new.go\n",
	} {
		t.Run(name, func(t *testing.T) {
			runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, command string, arguments ...string) ([]byte, error) {
				if command == "git" && reflect.DeepEqual(arguments, []string{"status", "--porcelain=v1", "--untracked-files=all"}) {
					return []byte(status), nil
				}
				return nil, errors.New("unexpected command")
			}}
			if _, _, err := readCleanSourceIdentity(context.Background(), runner, t.TempDir()); err == nil || err.Error() != "source state is not clean" {
				t.Fatalf("dirty source error=%v", err)
			}
		})
	}

	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, command string, arguments ...string) ([]byte, error) {
		if command != "git" {
			return nil, errors.New("unexpected command")
		}
		switch strings.Join(arguments, " ") {
		case "status --porcelain=v1 --untracked-files=all":
			return nil, nil
		case "rev-parse HEAD":
			return []byte(commit + "\n"), nil
		case "rev-parse HEAD^{tree}":
			return []byte(tree + "\n"), nil
		default:
			return nil, errors.New("unexpected git command")
		}
	}}
	gotCommit, gotTree, err := readCleanSourceIdentity(context.Background(), runner, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if gotCommit != commit || gotTree != tree {
		t.Fatalf("identity=(%q,%q)", gotCommit, gotTree)
	}
}

func TestExecuteStressCampaignStopsAtFirstFailure(t *testing.T) {
	restarts := 0
	actions := stressActions{
		restartReconnect: func(_ context.Context, cycle int) error {
			restarts++
			if cycle == 7 {
				return errors.New("synthetic restart failure")
			}
			return nil
		},
		rotateReissue: func(context.Context, int) error { return nil },
		impair:        func(context.Context, string) error { return nil },
		sample:        func(context.Context) error { return nil },
	}
	err := executeStressCampaign(context.Background(), actions)
	if err == nil || !strings.Contains(err.Error(), "restart/reconnect cycle 7") {
		t.Fatalf("unexpected failure: %v", err)
	}
	if restarts != 8 {
		t.Fatalf("restart calls=%d, want 8", restarts)
	}
}

func TestRemoteImpairmentScriptsAreBoundedToKurdTun(t *testing.T) {
	for _, scenario := range frozenImpairmentMatrix {
		t.Run(scenario.name, func(t *testing.T) {
			if scenario.carrierReset {
				return
			}
			apply := remoteImpairmentApplyScript(scenario)
			cleanup := remoteImpairmentCleanupScript()
			if !strings.Contains(apply, "tc qdisc replace dev kurd0 root netem") {
				t.Fatalf("impairment not bound to kurd0: %q", apply)
			}
			if !strings.Contains(cleanup, "tc qdisc del dev kurd0 root") {
				t.Fatalf("cleanup not bound to kurd0: %q", cleanup)
			}
			for _, forbidden := range []string{"eth0", "ens", "default", "ip link set", "systemctl stop ssh"} {
				if strings.Contains(apply, forbidden) || strings.Contains(cleanup, forbidden) {
					t.Fatalf("unsafe impairment command contains %q", forbidden)
				}
			}
		})
	}
}

func TestResourceTrackerRejectsPersistentMonotonicGrowthAndOOM(t *testing.T) {
	tracker := resourceTracker{}
	for index := 0; index < 12; index++ {
		err := tracker.observe(resourceSample{
			rss: uint64(32+index*4) << 20,
			fds: uint64(20 + index*4),
		})
		if index < 7 && err != nil {
			t.Fatalf("premature growth rejection at sample %d: %v", index, err)
		}
		if index >= 7 && err != nil {
			return
		}
	}
	t.Fatal("persistent resource growth was accepted")
}

func TestResourceTrackerAcceptsBoundedNoiseAndTracksPeaks(t *testing.T) {
	tracker := resourceTracker{}
	for _, sample := range []resourceSample{
		{rss: 32 << 20, fds: 20},
		{rss: 40 << 20, fds: 24},
		{rss: 36 << 20, fds: 22},
		{rss: 48 << 20, fds: 28},
	} {
		if err := tracker.observe(sample); err != nil {
			t.Fatal(err)
		}
	}
	if tracker.peakRSS != 48<<20 || tracker.peakFDs != 28 {
		t.Fatalf("peaks rss=%d fds=%d", tracker.peakRSS, tracker.peakFDs)
	}
	if err := tracker.observe(resourceSample{rss: 48 << 20, fds: 28, oomKills: 1}); err == nil {
		t.Fatal("OOM evidence was accepted")
	}
}

func TestValidateConfigRejectsUnsafeSelectors(t *testing.T) {
	base := config{
		sshAlias: "kurd-node", avdName: "Pixel_10_Pro", evidenceRoot: ".tools/phase17/field",
		mode: "Functional", relayPort: 8443, packagePath: "node.tar.gz", appAPK: "app.apk",
		testAPK: "test.apk", adbPath: "adb", sshPath: "ssh", scpPath: "scp",
		ipv6ProbeAddress: "2001:db8::53",
	}
	for name, mutate := range map[string]func(*config){
		"ssh shell input": func(value *config) { value.sshAlias = "node;id" },
		"empty avd":       func(value *config) { value.avdName = "" },
		"unknown mode":    func(value *config) { value.mode = "Quick" },
		"invalid port":    func(value *config) { value.relayPort = 0 },
		"IPv4 probe":      func(value *config) { value.ipv6ProbeAddress = "192.0.2.53" },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if err := validateConfig(value); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestDNSProbeFamiliesFollowAuthorizedProfileFamilies(t *testing.T) {
	if got := dnsProbeFamilies(false); !reflect.DeepEqual(got, []string{"4"}) {
		t.Fatalf("IPv4-only DNS families=%v", got)
	}
	if got := dnsProbeFamilies(true); !reflect.DeepEqual(got, []string{"4", "6"}) {
		t.Fatalf("dual-stack DNS families=%v", got)
	}
}

func TestRemoteIPv6CapabilityScriptRequiresEveryPlanCapability(t *testing.T) {
	script := remoteIPv6CapabilityScript("2001:db8::53")
	for _, required := range []string{
		"ip -o -6 addr show scope global", "ip -o -6 route show default",
		"net.ipv6.conf.all.forwarding", "nft list table inet kurd_node",
		"ip6 saddr fd4b:7572:6400::/64", "ping -6 -n -c 1",
		"kurdctl network ipv6 enable", "--confirm enable-ipv6",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("IPv6 capability script missing %q", required)
		}
	}
	if strings.Contains(script, "2001:db8::53") {
		t.Fatal("IPv6 witness address was embedded without shell-safe encoding")
	}
}

func TestSafeCategoryRejectsEndpointsAndSecrets(t *testing.T) {
	for _, value := range []string{
		"endpoint 198.51.100.7", "endpoint 192.0.2.10:443", "probe https://198.51.100.20/check",
		"endpoint [2001:db8::10]:443", "interface fe80::1%eth0",
		"password=secret", "BEGIN OPENSSH PRIVATE KEY", "C:\\Users\\owner\\key",
	} {
		if safeCategory([]byte(value)) {
			t.Fatalf("sensitive output accepted: %q", value)
		}
	}
	if !safeCategory([]byte("SERVICE_HEALTH_PASS")) {
		t.Fatal("categorical output rejected")
	}
}

func TestPassingEvidenceContainsEveryRequiredCheck(t *testing.T) {
	value := passingEvidence(fieldIdentity{
		commitSHA: strings.Repeat("a", 40), treeSHA: strings.Repeat("b", 40),
		packageSHA: strings.Repeat("c", 64), appSHA: strings.Repeat("d", 64),
		testSHA: strings.Repeat("e", 64), api: 36, abi: "x86_64", ipv6: true,
	}, 1200, 1024, 12, 4)
	for _, name := range requiredChecks {
		if value.Checks[name] != "PASS" {
			t.Fatalf("check %q not passing", name)
		}
	}
	if value.Result != "PASS" || value.Schema != rawSchema || len(value.Limitations) == 0 {
		t.Fatalf("invalid passing evidence: %+v", value)
	}
	encoded, err := marshalEvidence(value)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("PENDING")) || bytes.Contains(encoded, []byte("IN_PROGRESS")) {
		t.Fatalf("passing evidence contains placeholder state: %s", encoded)
	}
}

func TestPackageManifestDigestBindsExactInstalledDocument(t *testing.T) {
	manifest := []byte("{\"schema\":\"kurd-node-native-package-v1\"}\n")
	path := filepath.Join(t.TempDir(), "package.tar.gz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zipper := gzip.NewWriter(file)
	writer := tar.NewWriter(zipper)
	if err := writer.WriteHeader(&tar.Header{Name: "kurd-node/manifest.json", Mode: 0o644, Size: int64(len(manifest))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zipper.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	digest, err := packageManifestDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(manifest)
	if digest != hex.EncodeToString(expected[:]) {
		t.Fatalf("digest=%s expected=%x", digest, expected)
	}
}
