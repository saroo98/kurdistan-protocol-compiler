// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/relay/node"
	"kurdistan/internal/selfhost"
)

func TestCLIEndToEndUsesStdinPassphrasesAndExclusiveOutputs(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	passphrase := "correct horse battery staple\n"
	call := func(args []string, input string) (int, bytes.Buffer, bytes.Buffer) {
		var stdout, stderr bytes.Buffer
		code := run(args, bytes.NewBufferString(input), &stdout, &stderr)
		return code, stdout, stderr
	}
	if code, _, stderr := call([]string{"init", "--data-dir", dataDir, "--name", "owner-node", "--endpoint", "203.0.113.7:443", "--recovery-file", recovery}, passphrase); code != 0 {
		t.Fatalf("init code=%d stderr=%s", code, stderr.String())
	}
	if code, _, stderr := call([]string{"recovery", "confirm", "--data-dir", dataDir, "--recovery-file", recovery}, passphrase); code != 0 {
		t.Fatalf("confirm code=%d stderr=%s", code, stderr.String())
	}
	outputDir := filepath.Join(base, "profile-one")
	code, stdout, stderr := call([]string{"profile", "create", "--data-dir", dataDir, "--name", "phone", "--valid-for", "24h", "--output-dir", outputDir, "--authority-only"}, "")
	if code != 0 {
		t.Fatalf("create code=%d stderr=%s", code, stderr.String())
	}
	var created struct {
		ProfileID string `json:"profileId"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &created); err != nil || created.ProfileID == "" {
		t.Fatalf("create output=%s err=%v", stdout.String(), err)
	}
	for _, name := range []string{"profile.kurd-profile", "profile.kurd-uri.txt", "profile-qr-1.png", "profile-qr-1.svg"} {
		if info, err := os.Stat(filepath.Join(outputDir, name)); err != nil || info.Size() == 0 {
			t.Fatalf("missing output %s: %v", name, err)
		}
	}
	if code, stdout, stderr := call([]string{"profile", "verify", "--file", filepath.Join(outputDir, "profile.kurd-profile")}, ""); code != 0 || !bytes.Contains(stdout.Bytes(), []byte(created.ProfileID)) {
		t.Fatalf("verify code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	} else {
		var verified map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &verified); err != nil {
			t.Fatalf("decode verify output: %v", err)
		}
		for _, forbidden := range []string{"deploymentId", "rootFingerprint", "issuerFingerprint", "relayKeyId", "endpoint"} {
			if _, exists := verified[forbidden]; exists {
				t.Fatalf("verify output exposed %q: %s", forbidden, stdout.String())
			}
		}
	}
	if code, _, _ := call([]string{"profile", "create", "--data-dir", dataDir, "--name", "duplicate-output", "--output-dir", outputDir, "--authority-only"}, ""); code == 0 {
		t.Fatal("existing output directory was overwritten")
	}
	if code, stdout, stderr := call([]string{"profile", "show", "--data-dir", dataDir, "--id", created.ProfileID, "--reveal", "terminal"}, ""); code != 0 || !bytes.Contains(stdout.Bytes(), []byte("Chunk 1/")) {
		t.Fatalf("show code=%d stdout=%d stderr=%s", code, stdout.Len(), stderr.String())
	}
	if code, stdout, stderr := call([]string{"profile", "show", "--data-dir", dataDir, "--id", created.ProfileID, "--qr"}, ""); code != 0 || !bytes.Contains(stdout.Bytes(), []byte("Chunk 1/")) {
		t.Fatalf("show --qr code=%d stdout=%d stderr=%s", code, stdout.Len(), stderr.String())
	}
	backup := filepath.Join(base, "offline", "node.kurd-backup")
	if code, _, stderr := call([]string{"backup", "create", "--data-dir", dataDir, "--file", backup}, passphrase); code != 0 {
		t.Fatalf("backup code=%d stderr=%s", code, stderr.String())
	}
	if code, _, _ := call([]string{"profile", "revoke", "--data-dir", dataDir, "--id", created.ProfileID, "--recovery-file", recovery, "--confirm", "wrong"}, passphrase); code != 2 {
		t.Fatalf("revoke without exact confirmation code=%d", code)
	}
	if code, _, stderr := call([]string{"profile", "revoke", "--data-dir", dataDir, "--profile-id", created.ProfileID, "--recovery-file", recovery, "--confirm-profile", created.ProfileID}, passphrase); code != 0 {
		t.Fatalf("canonical revoke code=%d stderr=%s", code, stderr.String())
	}
	if code, stdout, stderr := call([]string{"profile", "show", "--data-dir", dataDir, "--profile-id", created.ProfileID, "--redacted"}, ""); code != 0 {
		t.Fatalf("show revoked code=%d stderr=%s", code, stderr.String())
	} else {
		var shown struct {
			Revoked     bool `json:"revoked"`
			Connectable bool `json:"connectable"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &shown); err != nil || !shown.Revoked || shown.Connectable {
			t.Fatalf("revoked show=%s err=%v", stdout.String(), err)
		}
	}
}

func TestCLINetworkIPv6RequiresExactConfirmationAndRecoveryAuthorization(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	passphrase := "correct horse battery staple\n"
	call := func(args []string, input string) (int, bytes.Buffer, bytes.Buffer) {
		var stdout, stderr bytes.Buffer
		code := run(args, bytes.NewBufferString(input), &stdout, &stderr)
		return code, stdout, stderr
	}
	if code, _, stderr := call([]string{"init", "--data-dir", dataDir, "--name", "owner-node", "--endpoint", "203.0.113.7:443", "--recovery-file", recovery}, passphrase); code != 0 {
		t.Fatalf("init code=%d stderr=%s", code, stderr.String())
	}
	if code, _, _ := call([]string{"network", "ipv6", "enable", "--data-dir", dataDir, "--recovery-file", recovery, "--confirm", "wrong"}, passphrase); code != 2 {
		t.Fatalf("IPv6 enable without exact confirmation code=%d", code)
	}
	code, stdout, stderr := call([]string{"network", "ipv6", "enable", "--data-dir", dataDir, "--recovery-file", recovery, "--confirm", "enable-ipv6"}, passphrase)
	if code != 0 {
		t.Fatalf("IPv6 enable code=%d stderr=%s", code, stderr.String())
	}
	var result struct {
		Schema  string `json:"schema"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Schema != "kurdctl-network-ipv6-v1" || !result.Enabled {
		t.Fatalf("IPv6 enable output=%s err=%v", stdout.String(), err)
	}
}

func TestCommittedOperationsNotifyRunningRelayImmediately(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "recovery")
	passphrase := "correct horse battery staple\n"
	call := func(args []string, input string) (int, bytes.Buffer, bytes.Buffer) {
		var stdout, stderr bytes.Buffer
		code := run(args, bytes.NewBufferString(input), &stdout, &stderr)
		return code, stdout, stderr
	}
	if code, _, stderr := call([]string{"init", "--data-dir", dataDir, "--name", "owner-node", "--endpoint", "203.0.113.7:443", "--recovery-file", recovery}, passphrase); code != 0 {
		t.Fatalf("init code=%d stderr=%s", code, stderr.String())
	}
	if code, _, stderr := call([]string{"recovery", "confirm", "--data-dir", dataDir, "--recovery-file", recovery}, passphrase); code != 0 {
		t.Fatalf("confirm code=%d stderr=%s", code, stderr.String())
	}
	outputDir := filepath.Join(base, "profile")
	code, stdout, stderr := call([]string{"profile", "create", "--data-dir", dataDir, "--name", "phone", "--valid-for", "24h", "--output-dir", outputDir, "--authority-only"}, "")
	if code != 0 {
		t.Fatalf("create code=%d stderr=%s", code, stderr.String())
	}
	var created struct {
		ProfileID string `json:"profileId"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &created); err != nil || created.ProfileID == "" {
		t.Fatalf("create output=%s err=%v", stdout.String(), err)
	}

	previousNotify := notifyRelayRuntime
	defer func() { notifyRelayRuntime = previousNotify }()
	var commands []node.ControlCommandV1
	notifyRelayRuntime = func(path string, request node.ControlRequestV1, required bool) error {
		if path != filepath.Join(base, "run", "control.sock") || required {
			t.Fatalf("notification path=%q required=%v", path, required)
		}
		commands = append(commands, request.Command)
		return nil
	}
	control := filepath.Join(base, "run", "control.sock")
	operations := []struct {
		args  []string
		input string
	}{
		{args: []string{"profile", "revoke", "--data-dir", dataDir, "--profile-id", created.ProfileID, "--recovery-file", recovery, "--confirm-profile", created.ProfileID, "--control-socket", control}, input: passphrase},
		{args: []string{"keys", "rotate", "relay", "--data-dir", dataDir, "--recovery-file", recovery, "--confirm", "relay", "--control-socket", control}, input: passphrase},
		{args: []string{"node", "drain", "--data-dir", dataDir, "--control-socket", control}},
		{args: []string{"node", "resume", "--data-dir", dataDir, "--control-socket", control}},
		{args: []string{"deployment", "disable", "--data-dir", dataDir, "--recovery-file", recovery, "--confirm", "disable", "--control-socket", control}, input: passphrase},
		{args: []string{"deployment", "enable", "--data-dir", dataDir, "--recovery-file", recovery, "--confirm", "enable", "--control-socket", control}, input: passphrase},
	}
	for _, operation := range operations {
		if code, _, stderr := call(operation.args, operation.input); code != 0 {
			t.Fatalf("operation=%v code=%d stderr=%s", operation.args[:2], code, stderr.String())
		}
	}
	want := []node.ControlCommandV1{
		node.ControlReloadV1, node.ControlReloadV1, node.ControlDrainV1,
		node.ControlResumeV1, node.ControlReloadV1, node.ControlReloadV1,
	}
	if len(commands) != len(want) {
		t.Fatalf("commands=%v want=%v", commands, want)
	}
	for index := range want {
		if commands[index] != want[index] {
			t.Fatalf("commands[%d]=%d want=%d", index, commands[index], want[index])
		}
	}
}

func TestCommittedOperationReportsNotificationFailureWithoutRepeatingMutation(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "recovery")
	passphrase := "correct horse battery staple\n"
	call := func(args []string, input string) (int, bytes.Buffer, bytes.Buffer) {
		var stdout, stderr bytes.Buffer
		code := run(args, bytes.NewBufferString(input), &stdout, &stderr)
		return code, stdout, stderr
	}
	if code, _, stderr := call([]string{"init", "--data-dir", dataDir, "--name", "owner-node", "--endpoint", "203.0.113.7:443", "--recovery-file", recovery}, passphrase); code != 0 {
		t.Fatalf("init code=%d stderr=%s", code, stderr.String())
	}

	previousNotify := notifyRelayRuntime
	defer func() { notifyRelayRuntime = previousNotify }()
	notifyRelayRuntime = func(string, node.ControlRequestV1, bool) error {
		return node.ErrControlConfig
	}
	control := filepath.Join(base, "run", "control.sock")
	code, _, stderr := call([]string{"node", "drain", "--data-dir", dataDir, "--control-socket", control}, "")
	if code != 7 || stderr.String() != "kurdctl: state committed; runtime notification pending; run kurdctl node reload\n" {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	status, err := selfhost.LoadStatus(dataDir)
	if err != nil || !status.Drained {
		t.Fatalf("committed drain status=%+v err=%v", status, err)
	}
}

func TestWriteIssuedRendersBeforeCreatingOutputRoot(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "profile-output")
	_, err := writeIssued(outputDir, selfhost.IssuedProfile{
		Artifact: []byte("artifact"),
		URI:      "kurd://artifact/example",
		QRChunks: []string{""},
	})
	if err == nil {
		t.Fatal("invalid QR chunk was accepted")
	}
	if _, statErr := os.Lstat(outputDir); !os.IsNotExist(statErr) {
		t.Fatalf("output root was created before rendering completed: %v", statErr)
	}
}

func TestWriteIssuedReportsEveryPartialFileFailureWithoutOverwriting(t *testing.T) {
	issued := selfhost.IssuedProfile{
		Artifact: []byte("artifact"),
		URI:      "kurd://artifact/YXJ0aWZhY3Q",
		QRChunks: []string{"KURD1/1/1/AAAA"},
	}
	for failedAt := 0; failedAt < 4; failedAt++ {
		t.Run(string(rune('a'+failedAt)), func(t *testing.T) {
			outputDir := filepath.Join(t.TempDir(), "profile-output")
			calls := 0
			injected := errors.New("injected output failure")
			_, err := writeIssuedWithWriter(outputDir, issued, func(root *privateOutputRoot, name string, value []byte) error {
				if calls == failedAt {
					calls++
					return injected
				}
				calls++
				return writePrivateFile(root, name, value)
			})
			if !errors.Is(err, injected) || calls != failedAt+1 {
				t.Fatalf("failedAt=%d calls=%d err=%v", failedAt, calls, err)
			}
			if _, statErr := os.Lstat(outputDir); statErr != nil {
				t.Fatalf("committed partial output directory missing: %v", statErr)
			}
			if _, createErr := writeIssued(outputDir, issued); !errors.Is(createErr, errOutputExists) {
				t.Fatalf("partial directory was overwritten: %v", createErr)
			}
		})
	}
}

func TestCLIRejectsAmbiguousSensitiveFlagsAndAliases(t *testing.T) {
	tests := [][]string{
		{"profile", "create", "--data-dir", "one", "--data-dir=two", "--name", "phone", "--authority-only", "--output-dir", "out"},
		{"profile", "show", "--data-dir", "node", "--id", "profiles.one", "--profile-id", "profiles.two"},
		{"profile", "show", "--data-dir", "node", "--profile-id", "profiles.one", "--redacted", "--reveal", "uri"},
		{"profile", "show", "--data-dir", "node", "--profile-id", "profiles.one", "--"},
		{"profile", "revoke", "--data-dir", "node", "--profile-id", "profiles.one", "--recovery-file", "recovery", "--confirm", "profiles.one", "--confirm-profile", "profiles.one"},
		{"keys", "rotate", "tls", "--data-dir", "node", "--recovery-file", "recovery", "--confirm", "relay"},
	}
	for _, args := range tests {
		var stdout, stderr bytes.Buffer
		if code := run(args, bytes.NewBufferString("not-read\n"), &stdout, &stderr); code != 2 {
			t.Fatalf("args=%v code=%d stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
		}
		if stdout.Len() != 0 || stderr.String() != "kurdctl: invalid input\n" {
			t.Fatalf("args=%v stdout=%q stderr=%q", args, stdout.String(), stderr.String())
		}
	}
}

func TestDefaultRecipientRegistryUsesSharedUserConfiguration(t *testing.T) {
	directory, err := defaultRecipientRegistryDir()
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(config, "kurdistan-vpn", "recipient-use-v1")
	if directory != want {
		t.Fatalf("default recipient registry=%q want=%q", directory, want)
	}
}

func TestRequestReaderRejectsFinalSymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "request")
	if err := os.WriteFile(target, []byte("request"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "request-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if value, err := readBoundedRequest(link, 512); !errors.Is(err, errRequestRejected) {
		clear(value)
		t.Fatalf("final symlink accepted: %v", err)
	}
}

func TestCommittedProfileOutputCanBeRecoveredExactly(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	passphrase := "correct horse battery staple\n"
	call := func(args []string, input string) (int, bytes.Buffer, bytes.Buffer) {
		var stdout, stderr bytes.Buffer
		code := run(args, bytes.NewBufferString(input), &stdout, &stderr)
		return code, stdout, stderr
	}
	if code, _, stderr := call([]string{"init", "--data-dir", dataDir, "--name", "owner-node", "--endpoint", "203.0.113.7:443", "--recovery-file", recovery}, passphrase); code != 0 {
		t.Fatalf("init code=%d stderr=%s", code, stderr.String())
	}
	if code, _, stderr := call([]string{"recovery", "confirm", "--data-dir", dataDir, "--recovery-file", recovery}, passphrase); code != 0 {
		t.Fatalf("confirm code=%d stderr=%s", code, stderr.String())
	}
	failedOutput := filepath.Join(base, "already-exists")
	if err := os.Mkdir(failedOutput, 0o700); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := call([]string{"profile", "create", "--data-dir", dataDir, "--name", "phone", "--authority-only", "--output-dir", failedOutput}, "")
	if code != 6 || stdout.Len() != 0 || !bytes.Contains(stderr.Bytes(), []byte("output exists profile_id=")) || bytes.Contains(stderr.Bytes(), []byte("203.0.113.7")) {
		t.Fatalf("create code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	profiles, err := selfhost.ListProfiles(dataDir)
	if err != nil || len(profiles) != 1 {
		t.Fatalf("profiles=%+v err=%v", profiles, err)
	}
	stored, err := selfhost.LoadProfile(dataDir, profiles[0].ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	recovered := filepath.Join(base, "recovered")
	if code, _, stderr := call([]string{"profile", "show", "--data-dir", dataDir, "--profile-id", profiles[0].ProfileID, "--output-dir", recovered}, ""); code != 0 {
		t.Fatalf("recover code=%d stderr=%s", code, stderr.String())
	}
	exported, err := os.ReadFile(filepath.Join(recovered, "profile.kurd-profile"))
	if err != nil || !bytes.Equal(exported, stored.Artifact) {
		t.Fatalf("recovered artifact mismatch err=%v", err)
	}
}

func TestTLSRotationOutputDoesNotExposeKeyIdentifiers(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	passphrase := "correct horse battery staple\n"
	call := func(args []string, input string) (int, bytes.Buffer, bytes.Buffer) {
		var stdout, stderr bytes.Buffer
		code := run(args, bytes.NewBufferString(input), &stdout, &stderr)
		return code, stdout, stderr
	}
	if code, _, stderr := call([]string{"init", "--data-dir", dataDir, "--name", "owner-node", "--endpoint", "203.0.113.7:443", "--recovery-file", recovery}, passphrase); code != 0 {
		t.Fatalf("init code=%d stderr=%s", code, stderr.String())
	}
	if code, _, stderr := call([]string{"recovery", "confirm", "--data-dir", dataDir, "--recovery-file", recovery}, passphrase); code != 0 {
		t.Fatalf("confirm code=%d stderr=%s", code, stderr.String())
	}
	code, stdout, stderr := call([]string{"keys", "rotate", "tls", "--data-dir", dataDir, "--recovery-file", recovery, "--confirm", "tls"}, passphrase)
	if code != 0 {
		t.Fatalf("rotate code=%d stderr=%s", code, stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["kind"] != "tls" || result["tlsEpoch"] == nil {
		t.Fatalf("unexpected result: %s", stdout.String())
	}
	for _, forbidden := range []string{"previousKeyId", "currentKeyId", "rootFingerprint", "endpoint"} {
		if _, exists := result[forbidden]; exists {
			t.Fatalf("rotation output exposed %q: %s", forbidden, stdout.String())
		}
	}
}

func TestCLICreatesDeviceBoundLiveProfileAndRejectsRecipientReplay(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	registry := filepath.Join(base, "recipient-registry")
	passphrase := "correct horse battery staple\n"
	call := func(args []string, input string) (int, bytes.Buffer, bytes.Buffer) {
		var stdout, stderr bytes.Buffer
		code := run(args, bytes.NewBufferString(input), &stdout, &stderr)
		return code, stdout, stderr
	}
	if code, _, stderr := call([]string{"init", "--data-dir", dataDir, "--name", "owner-node", "--endpoint", "203.0.113.7:443", "--recovery-file", recovery}, passphrase); code != 0 {
		t.Fatalf("init code=%d stderr=%s", code, stderr.String())
	}
	if code, _, stderr := call([]string{"recovery", "confirm", "--data-dir", dataDir, "--recovery-file", recovery}, passphrase); code != 0 {
		t.Fatalf("confirm code=%d stderr=%s", code, stderr.String())
	}
	request, private, err := enrollment.Generate(time.Now().UTC(), time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivate(private)
	requestBytes, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(base, "device.kurd-enrollment")
	if err := os.WriteFile(requestPath, requestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	previousNotify := notifyRelayRuntime
	defer func() { notifyRelayRuntime = previousNotify }()
	control := filepath.Join(base, "run", "control.sock")
	var reloads int
	notifyRelayRuntime = func(path string, request node.ControlRequestV1, required bool) error {
		if path != control || required || request.Command != node.ControlReloadV1 {
			t.Fatalf("notification path=%q command=%d required=%v", path, request.Command, required)
		}
		reloads++
		return nil
	}
	if code, _, _ := call([]string{"profile", "create", "--data-dir", dataDir, "--name", "missing-request", "--output-dir", filepath.Join(base, "missing")}, ""); code != 2 {
		t.Fatalf("live create without recipient request code=%d", code)
	}
	outputDir := filepath.Join(base, "live-profile")
	code, stdout, stderr := call([]string{
		"profile", "create", "--data-dir", dataDir, "--name", "phone", "--valid-for", "24h",
		"--recipient-request", requestPath, "--recipient-registry-dir", registry, "--output-dir", outputDir,
		"--control-socket", control,
	}, "")
	if code != 0 {
		t.Fatalf("live create code=%d stderr=%s", code, stderr.String())
	}
	var created struct {
		ProfileID   string `json:"profileId"`
		Mode        string `json:"mode"`
		Sealed      bool   `json:"sealed"`
		Connectable bool   `json:"connectable"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &created); err != nil || created.ProfileID == "" || created.Mode != "live" || !created.Sealed || !created.Connectable {
		t.Fatalf("live create output=%s err=%v", stdout.String(), err)
	}
	for _, forbidden := range [][]byte{
		[]byte("203.0.113.7"), []byte(request.RequestID), []byte(request.RecipientKeyID), []byte(request.ClientAuthKeyID),
		request.RecipientPublic, request.ClientAuthPublic,
	} {
		if len(forbidden) != 0 && (bytes.Contains(stdout.Bytes(), forbidden) || bytes.Contains(stderr.Bytes(), forbidden)) {
			t.Fatalf("live create output exposed protected value %x", forbidden)
		}
	}
	issued, err := selfhost.LoadProfile(dataDir, created.ProfileID)
	if err != nil || issued.Mode != "live" || !issued.Sealed || !issued.Connectable {
		t.Fatalf("loaded live profile=%+v err=%v", issued, err)
	}
	if code, _, _ := call([]string{
		"profile", "create", "--data-dir", dataDir, "--name", "replayed", "--recipient-request", requestPath,
		"--recipient-registry-dir", registry, "--output-dir", filepath.Join(base, "replayed"),
	}, ""); code == 0 {
		t.Fatal("recipient request replay was accepted")
	}
	rotatedRequest, rotatedPrivate, err := enrollment.Generate(time.Now().UTC(), time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivate(rotatedPrivate)
	rotatedRequestBytes, err := enrollment.EncodeRequestV1(rotatedRequest)
	if err != nil {
		t.Fatal(err)
	}
	rotatedRequestPath := filepath.Join(base, "rotated-device.kurd-enrollment")
	if err := os.WriteFile(rotatedRequestPath, rotatedRequestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := call([]string{
		"profile", "rotate", "--data-dir", dataDir, "--profile-id", created.ProfileID,
		"--recovery-file", recovery, "--valid-for", "24h", "--recipient-request", rotatedRequestPath,
		"--recipient-registry-dir", registry, "--output-dir", filepath.Join(base, "rotated-profile"),
		"--control-socket", control,
	}, passphrase); code != 0 {
		t.Fatalf("live rotate code=%d stderr=%s", code, stderr.String())
	}
	if reloads != 2 {
		t.Fatalf("runtime reloads=%d want=2", reloads)
	}
}

func TestCLIReportsCommittedLiveProfileBeforeRuntimeNotificationFailure(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	registry := filepath.Join(base, "recipient-registry")
	passphrase := "correct horse battery staple\n"
	call := func(args []string, input string) (int, bytes.Buffer, bytes.Buffer) {
		var stdout, stderr bytes.Buffer
		code := run(args, bytes.NewBufferString(input), &stdout, &stderr)
		return code, stdout, stderr
	}
	if code, _, stderr := call([]string{"init", "--data-dir", dataDir, "--name", "owner-node", "--endpoint", "203.0.113.7:443", "--recovery-file", recovery}, passphrase); code != 0 {
		t.Fatalf("init code=%d stderr=%s", code, stderr.String())
	}
	if code, _, stderr := call([]string{"recovery", "confirm", "--data-dir", dataDir, "--recovery-file", recovery}, passphrase); code != 0 {
		t.Fatalf("confirm code=%d stderr=%s", code, stderr.String())
	}
	request, private, err := enrollment.Generate(time.Now().UTC(), time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivate(private)
	requestBytes, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(base, "device.kurd-enrollment")
	if err := os.WriteFile(requestPath, requestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	previousNotify := notifyRelayRuntime
	defer func() { notifyRelayRuntime = previousNotify }()
	notifyRelayRuntime = func(string, node.ControlRequestV1, bool) error { return node.ErrControlConfig }
	outputDir := filepath.Join(base, "live-profile")
	code, stdout, stderr := call([]string{
		"profile", "create", "--data-dir", dataDir, "--name", "phone", "--valid-for", "24h",
		"--recipient-request", requestPath, "--recipient-registry-dir", registry, "--output-dir", outputDir,
		"--control-socket", filepath.Join(base, "run", "control.sock"),
	}, "")
	if code != 7 || stderr.String() != "kurdctl: state committed; runtime notification pending; run kurdctl node reload\n" {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var created struct {
		ProfileID   string `json:"profileId"`
		Connectable bool   `json:"connectable"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &created); err != nil || created.ProfileID == "" || !created.Connectable {
		t.Fatalf("committed response=%q err=%v", stdout.String(), err)
	}
	if info, err := os.Stat(filepath.Join(outputDir, "profile.kurd-profile")); err != nil || info.Size() == 0 {
		t.Fatalf("committed artifact missing: %v", err)
	}
	if issued, err := selfhost.LoadProfile(dataDir, created.ProfileID); err != nil || !issued.Connectable {
		t.Fatalf("committed profile unavailable: %+v err=%v", issued, err)
	}
}

func TestRecipientAuthorityFailureHasStableRedactedCategory(t *testing.T) {
	message, code := categorizeCLIError(selfhost.ErrRecipientAuthority)
	if code != 4 || message != "recipient authority rejected" {
		t.Fatalf("unexpected category message=%q code=%d", message, code)
	}
}

func clearEnrollmentPrivate(bundle enrollment.PrivateBundleV1) {
	for index := range bundle.RecipientPrivate {
		bundle.RecipientPrivate[index] = 0
	}
	for index := range bundle.ClientAuthSeed {
		bundle.ClientAuthSeed[index] = 0
	}
}

func TestCLINeverAcceptsPassphraseArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"init", "--passphrase", "secret"}, bytes.NewBufferString("correct horse battery staple\n"), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("secret-bearing argument code=%d stderr=%s", code, stderr.String())
	}
}

func TestPrivateOutputProtectionIsEnforced(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := protectPrivatePath(directory, true); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "artifact")
	if err := os.WriteFile(file, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := protectPrivatePath(file, false); err != nil {
		t.Fatal(err)
	}
}

func TestCLIHelpListsStableAdministrationInterface(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--help"}, bytes.NewReader(nil), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("help code=%d stderr=%s", code, stderr.String())
	}
	for _, command := range []string{
		"profile create",
		"profile revoke",
		"backup create",
		"restore apply",
		"migration apply",
		"migration rollback",
		"upgrade apply",
		"logs export-redacted",
	} {
		if !bytes.Contains(stdout.Bytes(), []byte(command)) {
			t.Fatalf("help output missing %q:\n%s", command, stdout.String())
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("help wrote stderr: %s", stderr.String())
	}
}

func TestMigrationCommandsRequireExplicitBoundaryAndDelegate(t *testing.T) {
	originalMigrate, originalRollback := migrateStateToV2, rollbackStateV2
	defer func() {
		migrateStateToV2, rollbackStateV2 = originalMigrate, originalRollback
	}()
	var migrated, rolledBack string
	migrateStateToV2 = func(dataDir string, now time.Time) error {
		if now.IsZero() {
			t.Fatal("migration did not receive trusted current time")
		}
		migrated = dataDir
		return nil
	}
	rollbackStateV2 = func(dataDir string) error {
		rolledBack = dataDir
		return nil
	}
	var output bytes.Buffer
	if err := runMigration([]string{"apply", "--data-dir", "state"}, &output); err != nil || migrated != "state" || !strings.Contains(output.String(), `"stateVersion":2`) {
		t.Fatalf("apply output=%q migrated=%q err=%v", output.String(), migrated, err)
	}
	output.Reset()
	if err := runMigration([]string{"rollback", "--data-dir", "state", "--confirm", "state-v2"}, &output); err != nil || rolledBack != "state" || !strings.Contains(output.String(), `"stateVersion":1`) {
		t.Fatalf("rollback output=%q rolledBack=%q err=%v", output.String(), rolledBack, err)
	}
	if err := runMigration([]string{"rollback", "--data-dir", "state"}, &output); !errors.Is(err, selfhost.ErrInvalidInput) {
		t.Fatalf("rollback without confirmation err=%v", err)
	}
}
