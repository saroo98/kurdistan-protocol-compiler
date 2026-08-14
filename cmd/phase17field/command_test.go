// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"errors"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestPrepareProductionCommandRunnerUsesLoadedPrivateRemoteExecutables(t *testing.T) {
	prepared := prepareProductionCommandRunner(commandRunner{}, config{sshPath: "qualified-ssh", scpPath: "qualified-scp"})
	if prepared.remoteGate == nil || len(prepared.remoteCommands) != 2 {
		t.Fatalf("prepared=%+v", prepared)
	}
	if _, found := prepared.remoteCommands["qualified-ssh"]; !found {
		t.Fatal("loaded SSH executable was not paced")
	}
	if _, found := prepared.remoteCommands["qualified-scp"]; !found {
		t.Fatal("loaded SCP executable was not paced")
	}
	if _, found := prepared.remoteCommands[""]; found {
		t.Fatal("empty pre-load executable was registered")
	}
	injected := commandRunner{runFunc: func(context.Context, []byte, string, string, ...string) ([]byte, error) { return nil, nil }}
	if got := prepareProductionCommandRunner(injected, config{sshPath: "ssh", scpPath: "scp"}); got.remoteGate != nil || got.remoteCommands != nil {
		t.Fatal("test command runner was modified")
	}
}

func TestVerifyOwnerVPSClockRequiresRemoteTimeInsideMeasuredHostInterval(t *testing.T) {
	before := time.Unix(1_000_000, 0).UTC()
	after := before.Add(2 * time.Second)
	times := []time.Time{before, after}
	now := func() time.Time {
		value := times[0]
		times = times[1:]
		return value
	}
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, arguments ...string) ([]byte, error) {
		if name != "ssh" || arguments[len(arguments)-1] != "date -u +%s" {
			t.Fatalf("command=%q %#v", name, arguments)
		}
		return []byte("1000001\n"), nil
	}}
	if err := verifyOwnerVPSClock(context.Background(), runner, config{sshPath: "ssh", sshAlias: "owner-node"}, ".", now); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyOwnerVPSClockRejectsSkewMalformedOutputAndSlowProbe(t *testing.T) {
	tests := map[string]struct {
		raw    string
		before time.Time
		after  time.Time
	}{
		"future skew": {raw: "1000100\n", before: time.Unix(1_000_000, 0), after: time.Unix(1_000_001, 0)},
		"past skew":   {raw: "999900\n", before: time.Unix(1_000_000, 0), after: time.Unix(1_000_001, 0)},
		"malformed":   {raw: "not-time\n", before: time.Unix(1_000_000, 0), after: time.Unix(1_000_001, 0)},
		"slow probe":  {raw: "1000010\n", before: time.Unix(1_000_000, 0), after: time.Unix(1_000_031, 0)},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			times := []time.Time{testCase.before, testCase.after}
			runner := commandRunner{runFunc: func(context.Context, []byte, string, string, ...string) ([]byte, error) {
				return []byte(testCase.raw), nil
			}}
			err := verifyOwnerVPSClock(
				context.Background(), runner, config{sshPath: "ssh", sshAlias: "owner-node"}, ".",
				func() time.Time { value := times[0]; times = times[1:]; return value },
			)
			if !errors.Is(err, errVPSEnvironmentUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestSSHClassifiesOnlyTransportExitAsEnvironmentLoss(t *testing.T) {
	value := config{sshPath: "ssh", sshAlias: "qualified-node"}
	operations := map[string]func(commandRunner) error{
		"command": func(runner commandRunner) error {
			_, err := ssh(context.Background(), runner, value, ".", time.Second, "true")
			return err
		},
		"script": func(runner commandRunner) error {
			_, err := sshScript(context.Background(), runner, value, ".", time.Second, "true")
			return err
		},
	}
	for operationName, operation := range operations {
		for caseName, test := range map[string]struct {
			exitCode        int
			wantEnvironment bool
		}{
			"transport exit":         {exitCode: 255, wantEnvironment: true},
			"remote command failure": {exitCode: 1, wantEnvironment: false},
		} {
			t.Run(operationName+"/"+caseName, func(t *testing.T) {
				runner := commandRunner{runFunc: func(context.Context, []byte, string, string, ...string) ([]byte, error) {
					return nil, &commandExitFailure{code: test.exitCode}
				}}
				err := operation(runner)
				if err == nil || errors.Is(err, errVPSEnvironmentUnavailable) != test.wantEnvironment {
					t.Fatalf("error=%v environment=%t", err, errors.Is(err, errVPSEnvironmentUnavailable))
				}
			})
		}
	}
}

func TestCommandRunnerPreservesRealChildExitCodeForTransportClassification(t *testing.T) {
	for _, exitCode := range []int{1, 255} {
		t.Run(strconv.Itoa(exitCode), func(t *testing.T) {
			name, arguments := exitCommand(exitCode)
			raw, err := runBytes(context.Background(), commandRunner{}, nil, t.TempDir(), 30*time.Second, name, arguments...)
			clear(raw)
			var exitFailure *commandExitFailure
			if !errors.As(err, &exitFailure) || exitFailure.code != exitCode {
				t.Fatalf("error=%v exit=%+v", err, exitFailure)
			}
			_, classified := classifySSHFailure(nil, err)
			if errors.Is(classified, errVPSEnvironmentUnavailable) != (exitCode == 255) {
				t.Fatalf("exit=%d classified=%v", exitCode, classified)
			}
		})
	}
}

func exitCommand(code int) (string, []string) {
	if runtime.GOOS == "windows" {
		return "powershell.exe", []string{"-NoProfile", "-NonInteractive", "-Command", "exit " + strconv.Itoa(code)}
	}
	return "sh", []string{"-c", "exit " + strconv.Itoa(code)}
}
