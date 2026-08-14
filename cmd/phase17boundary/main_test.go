// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/phase17boundary"
)

func TestRunActivelyObservesAndroidAndVPSAndEmitsOnlyCategoricalReceipt(t *testing.T) {
	request := boundaryRequestForTest()
	path := writeBoundaryRequest(t, request)
	android, _ := json.Marshal(validAndroidObservation(request.AttemptID))
	vps, _ := json.Marshal(validVPSObservation(request.AttemptID))
	commands := []string{}
	runner := observerRunnerFunc(func(_ context.Context, stdin []byte, name string, arguments ...string) ([]byte, error) {
		commands = append(commands, name+" "+strings.Join(arguments, " "))
		if name == request.SSHPath {
			if !bytes.Contains(stdin, []byte("kurd_node")) || !bytes.Contains(stdin, []byte("unbound.service")) {
				t.Fatal("fixed VPS boundary script was not supplied")
			}
			return vps, nil
		}
		joined := strings.Join(arguments, " ")
		switch {
		case strings.Contains(joined, " rm -f "):
			return nil, nil
		case strings.Contains(joined, " sh -c "):
			if string(stdin) != "PENDING:"+request.AttemptID+"\n" {
				t.Fatalf("pending marker=%q", stdin)
			}
			return nil, nil
		case strings.Contains(joined, " am instrument "):
			if !strings.Contains(joined, "phase17FieldAction boundary") ||
				!strings.Contains(joined, "phase17AttemptId "+request.AttemptID) {
				t.Fatalf("instrumentation arguments=%q", joined)
			}
			return []byte("OK"), nil
		case strings.HasSuffix(joined, "attempt.txt"):
			return []byte(base64.StdEncoding.EncodeToString([]byte("STARTED:" + request.AttemptID + "\n"))), nil
		case strings.HasSuffix(joined, "result.txt"):
			return []byte(base64.StdEncoding.EncodeToString(android)), nil
		default:
			return nil, errors.New("unexpected command")
		}
	})
	var stdout, stderr bytes.Buffer
	if code := runWithObserver([]string{"-request", path}, &stdout, &stderr, runner); code != 0 {
		t.Fatalf("code=%d stderr=%q commands=%v", code, stderr.String(), commands)
	}
	var receipt phase17boundary.Receipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Result != "PASS" || receipt.Name != phase17boundary.MonitorName ||
		receipt.AttemptID != request.AttemptID || stderr.Len() != 0 {
		t.Fatalf("receipt=%+v stderr=%q", receipt, stderr.String())
	}
	if bytes.Contains(stdout.Bytes(), []byte(request.SSHAlias)) || bytes.Contains(stdout.Bytes(), []byte(request.DeviceSerial)) {
		t.Fatal("private selector retained in receipt")
	}
}

func TestRunEmitsCategoricalFailureInsteadOfHidingObservedLeak(t *testing.T) {
	request := boundaryRequestForTest()
	path := writeBoundaryRequest(t, request)
	androidValue := validAndroidObservation(request.AttemptID)
	androidValue.BypassBlocked = false
	android, _ := json.Marshal(androidValue)
	vps, _ := json.Marshal(validVPSObservation(request.AttemptID))
	runner := successfulObserverRunner(request, android, vps)
	var stdout, stderr bytes.Buffer
	if code := runWithObserver([]string{"-request", path}, &stdout, &stderr, runner); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var receipt phase17boundary.Receipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Result != "FAIL" || !receipt.RouteLeak || receipt.DNSLeak {
		t.Fatalf("receipt=%+v", receipt)
	}
}

func TestRunRejectsSymlinkChildCrashAndDoesNotEchoPrivateInput(t *testing.T) {
	request := boundaryRequestForTest()
	target := writeBoundaryRequest(t, request)
	link := filepath.Join(filepath.Dir(target), "link.json")
	if err := os.Symlink(target, link); err == nil {
		var stdout, stderr bytes.Buffer
		if code := runWithObserver([]string{"-request", link}, &stdout, &stderr, observerRunnerFunc(nil)); code == 0 {
			t.Fatal("symlink request accepted")
		}
	}
	runner := observerRunnerFunc(func(context.Context, []byte, string, ...string) ([]byte, error) {
		return []byte("owner-private-endpoint.invalid"), errors.New("synthetic child crash")
	})
	var stdout, stderr bytes.Buffer
	if code := runWithObserver([]string{"-request", target}, &stdout, &stderr, runner); code == 0 {
		t.Fatal("child crash accepted")
	}
	for _, secret := range []string{request.SSHAlias, request.DeviceSerial, "owner-private-endpoint.invalid"} {
		if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
			t.Fatalf("private input echoed: %q", secret)
		}
	}
}

func successfulObserverRunner(request phase17boundary.Request, android, vps []byte) observerRunnerFunc {
	return func(_ context.Context, _ []byte, name string, arguments ...string) ([]byte, error) {
		if name == request.SSHPath {
			return vps, nil
		}
		joined := strings.Join(arguments, " ")
		switch {
		case strings.Contains(joined, " rm -f "), strings.Contains(joined, " sh -c "):
			return nil, nil
		case strings.Contains(joined, " am instrument "):
			return []byte("OK"), nil
		case strings.HasSuffix(joined, "attempt.txt"):
			return []byte(base64.StdEncoding.EncodeToString([]byte("STARTED:" + request.AttemptID + "\n"))), nil
		case strings.HasSuffix(joined, "result.txt"):
			return []byte(base64.StdEncoding.EncodeToString(android)), nil
		default:
			return nil, errors.New("unexpected command")
		}
	}
}

func boundaryRequestForTest() phase17boundary.Request {
	return phase17boundary.Request{
		Schema: phase17boundary.RequestSchema, CampaignMode: "Functional", AttemptID: strings.Repeat("a", 32),
		ADBPath: "adb-private", DeviceSerial: "emulator-private", SSHPath: "ssh-private",
		SSHAlias: "owner-private", RelayPort: 8443, VerifyIPv6: true,
	}
}

func validAndroidObservation(attemptID string) phase17boundary.AndroidObservation {
	return phase17boundary.AndroidObservation{
		Schema: phase17boundary.AndroidSchema, AttemptID: attemptID, VPNActive: true,
		IPv4Default: true, IPv6Default: true, DNSPinned: true, BypassBlocked: true,
	}
}

func validVPSObservation(attemptID string) phase17boundary.VPSObservation {
	return phase17boundary.VPSObservation{
		Schema: phase17boundary.VPSSchema, AttemptID: attemptID, RoutePolicy: true,
		DNSPinned: true, RelayBound: true, SourceGuard: true, IPv6Policy: true,
	}
}

func writeBoundaryRequest(t *testing.T, request phase17boundary.Request) string {
	t.Helper()
	raw, err := phase17boundary.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
