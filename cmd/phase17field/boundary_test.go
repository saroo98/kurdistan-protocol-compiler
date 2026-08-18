// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"kurdistan/internal/phase17boundary"
)

func TestRunBoundaryMonitorAccountsForItsOutOfProcessSSHConnection(t *testing.T) {
	root := t.TempDir()
	interval := 100 * time.Millisecond
	gate := &pacedConnectionGate{interval: interval}
	var boundaryStarted time.Time
	runner := commandRunner{
		remoteGate:     gate,
		remoteCommands: map[string]struct{}{"ssh": {}},
		runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
			if name == "ssh" {
				return nil, nil
			}
			boundaryStarted = time.Now()
			request := decodeBoundaryRequestForTest(t, arguments)
			time.Sleep(10 * time.Millisecond)
			return json.Marshal(passingBoundaryReceipt(request))
		},
	}
	if _, err := runner.run(context.Background(), nil, root, "ssh", "true"); err != nil {
		t.Fatal(err)
	}
	reservedAt := time.Now()
	if _, err := runBoundaryMonitor(
		context.Background(), runner,
		config{evidenceRoot: root, mode: "Functional", boundaryPath: "boundary-monitor", adbPath: "adb", sshPath: "ssh", sshAlias: "owner", relayPort: 8443},
		qualifiedRun{boundaryDigest: strings.Repeat("4", 64)}, root, "emulator-5554",
		[]byte("https://probe.invalid/check"), true,
	); err != nil {
		t.Fatal(err)
	}
	if elapsed := boundaryStarted.Sub(reservedAt); elapsed < 70*time.Millisecond {
		t.Fatalf("boundary SSH budget was not reserved: elapsed=%v", elapsed)
	}
	nextStarted := time.Now()
	if _, err := runner.run(context.Background(), nil, root, "ssh", "true"); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(nextStarted); elapsed < 70*time.Millisecond {
		t.Fatalf("boundary SSH activity was not recorded: elapsed=%v", elapsed)
	}
}

func TestRunBoundaryMonitorBindsExactLockedActiveObserverAndDeletesRequest(t *testing.T) {
	root := t.TempDir()
	value := config{
		evidenceRoot: root, mode: "Functional", boundaryPath: "boundary-monitor",
		adbPath: "adb-private", sshPath: "ssh-private", sshAlias: "owner-private", relayPort: 8443,
	}
	qualified := qualifiedRun{boundaryDigest: strings.Repeat("4", 64)}
	probeURL := []byte("https://probe.invalid/check")
	commands := []string{}
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
		commands = append(commands, name)
		if len(arguments) != 2 || arguments[0] != "-request" {
			t.Fatalf("arguments=%v", arguments)
		}
		file, err := os.Open(arguments[1])
		if err != nil {
			t.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		request, err := phase17boundary.DecodeRequest(file, info.Size())
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		if request.ADBPath != value.adbPath || request.SSHPath != value.sshPath ||
			request.SSHAlias != value.sshAlias || request.DeviceSerial != "emulator-private" ||
			request.ProbeURL != string(probeURL) || !request.VerifyIPv6 ||
			request.RelayPort != uint16(value.relayPort) {
			t.Fatalf("request=%+v", request)
		}
		return json.Marshal(passingBoundaryReceipt(request))
	}}
	receipt, err := runBoundaryMonitor(
		context.Background(), runner, value, qualified, root, "emulator-private", probeURL, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(commands, []string{"boundary-monitor"}) || receipt.Result != "PASS" || receipt.MonitorSHA256 != qualified.boundaryDigest {
		t.Fatalf("commands=%v receipt=%+v", commands, receipt)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("boundary request retained: %v", entries)
	}
}

func TestRunBoundaryMonitorFailsClosedOnLeakChildFailureAndReceiptMismatch(t *testing.T) {
	for name, run := range map[string]func(context.Context, []byte, string, string, ...string) ([]byte, error){
		"leak": func(_ context.Context, _ []byte, _ string, _ string, arguments ...string) ([]byte, error) {
			request := decodeBoundaryRequestForTest(t, arguments)
			receipt := passingBoundaryReceipt(request)
			receipt.Result = "FAIL"
			receipt.RouteLeak = true
			return json.Marshal(receipt)
		},
		"child failure": func(context.Context, []byte, string, string, ...string) ([]byte, error) {
			return nil, errors.New("synthetic monitor failure")
		},
		"receipt mismatch": func(_ context.Context, _ []byte, _ string, _ string, arguments ...string) ([]byte, error) {
			request := decodeBoundaryRequestForTest(t, arguments)
			receipt := passingBoundaryReceipt(request)
			receipt.AttemptID = strings.Repeat("b", 32)
			return json.Marshal(receipt)
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			_, err := runBoundaryMonitor(
				context.Background(), commandRunner{runFunc: run},
				config{evidenceRoot: root, mode: "Functional", boundaryPath: "boundary-monitor", adbPath: "adb", sshPath: "ssh", sshAlias: "owner", relayPort: 8443},
				qualifiedRun{boundaryDigest: strings.Repeat("4", 64)}, root, "emulator-5554",
				[]byte("https://probe.invalid/check"), true,
			)
			if err == nil {
				t.Fatal("boundary failure accepted")
			}
			entries, readErr := os.ReadDir(root)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("retained=%v readErr=%v", entries, readErr)
			}
		})
	}
}

func passingBoundaryReceipt(request phase17boundary.Request) phase17boundary.Receipt {
	return phase17boundary.Receipt{
		Schema: phase17boundary.ReceiptSchema, Name: phase17boundary.MonitorName,
		AttemptID: request.AttemptID, Result: "PASS", AndroidVPNActive: true,
		AndroidIPv4Default: true, AndroidIPv6Default: true, AndroidDNSPinned: true,
		AndroidBypassBlocked: true, VPSRoutePolicy: true, VPSDNSPinned: true,
		VPSRelayBound: true, VPSSourceGuard: true, VPSIPv6Policy: true,
		IPv6Required: request.VerifyIPv6,
	}
}

func decodeBoundaryRequestForTest(t *testing.T, arguments []string) phase17boundary.Request {
	t.Helper()
	if len(arguments) != 2 || arguments[0] != "-request" {
		t.Fatalf("arguments=%v", arguments)
	}
	file, err := os.Open(arguments[1])
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	request, err := phase17boundary.DecodeRequest(file, info.Size())
	if err != nil {
		t.Fatal(err)
	}
	return request
}
