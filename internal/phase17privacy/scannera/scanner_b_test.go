// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package scannera

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIndependentPythonScannerAgreesOnParityAndPrivacyCorpus(t *testing.T) {
	python := findPythonForTest(t)
	repositoryRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(repositoryRoot, "scripts", "phase17", "privacy_scanner_b.py")
	cases := []struct {
		name     string
		payload  []byte
		wantPass bool
	}{
		{name: "safe", payload: []byte("categorical lifecycle status"), wantPass: true},
		{name: "framework noise", payload: []byte("W/FrameTracker(23097): Missed SF frame:JANK_COMPOSER, CUJ=J<IME_INSETS_SHOW_ANIMATION::0@1@org.kurdistanvpn.app.internal>"), wantPass: true},
		{name: "instrumentation package replacement noise", payload: []byte("D/ActivityThread(23097): Package [org.kurdistanvpn.app.internal.test] reported as REPLACED, but missing application info. Assuming REMOVED."), wantPass: true},
		{name: "instrumentation ABI noise", payload: []byte("W/ActivityThread(23097): Package uses different ABI(s) than its instrumentation: package[org.kurdistanvpn.app.internal]: x86_64, null instrumentation[org.kurdistanvpn.app.internal.test]: null, null"), wantPass: true},
		{name: "instrumentation loader noise", payload: []byte("D/nativeloader(23097): Configuring clns-9 for other apk /data/app/random/org.kurdistanvpn.app.internal.test-random/base.apk"), wantPass: true},
		{name: "instrumentation DNS use", payload: []byte("application resolved DNS name org.kurdistanvpn.app.internal.test"), wantPass: false},
		{name: "destination", payload: []byte("https://198.51.100.7/check"), wantPass: false},
		{name: "mapped IPv6", payload: []byte("::ffff:192.0.2.7"), wantPass: false},
		{name: "zoned IPv6", payload: []byte("fe80::1%wlan0"), wantPass: false},
		{name: "credential", payload: []byte("password=private"), wantPass: false},
		{name: "ANSI credential", payload: []byte("pass\x1b[31mword=private"), wantPass: false},
		{name: "invalid credential", payload: []byte{'p', 'a', 's', 's', 0xff, 'w', 'o', 'r', 'd', '=', 'x'}, wantPass: false},
		{name: "percent credential", payload: []byte("%70%61%73%73%77%6f%72%64%3d%73%65%63%72%65%74"), wantPass: false},
		{name: "base64 credential", payload: []byte("cGFzc3dvcmQ9c2VjcmV0"), wantPass: false},
		{name: "Windows owner path", payload: []byte(`C:\Users\Owner\private`), wantPass: false},
		{name: "Unix owner path", payload: []byte(`/home/owner/private`), wantPass: false},
		{name: "profile", payload: []byte("kurd://private"), wantPass: false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			raw := scannerByteStream([2]any{"ANDROID_LOGCAT", test.payload}, [2]any{"REMOTE_JOURNAL", []byte("safe")})
			input := filepath.Join(t.TempDir(), "stream.jsonl")
			if err := os.WriteFile(input, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			goReceipt := Scan(bytes.NewReader(raw), int64(len(raw)))
			output, err := exec.Command(python, "-B", "-I", script, "--input", input).CombinedOutput()
			if err != nil {
				t.Fatalf("python scanner: %v: %s", err, output)
			}
			var pythonReceipt Receipt
			if err := json.Unmarshal(output, &pythonReceipt); err != nil {
				t.Fatal(err)
			}
			if pythonReceipt.Name != "PYTHON_B" || pythonReceipt.InputSHA256 != goReceipt.InputSHA256 ||
				pythonReceipt.BytesConsumed != goReceipt.BytesConsumed || pythonReceipt.RecordsConsumed != goReceipt.RecordsConsumed ||
				(pythonReceipt.Result == "PASS") != test.wantPass || (goReceipt.Result == "PASS") != test.wantPass {
				t.Fatalf("go=%+v python=%+v", goReceipt, pythonReceipt)
			}
		})
	}
}

func TestPythonScannerQualificationLeavesSourceTreeBytecodeFree(t *testing.T) {
	python := findPythonForTest(t)
	repositoryRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	temporaryRoot := t.TempDir()
	for _, relative := range []string{
		filepath.Join("scripts", "phase17", "privacy_scan_b_test.py"),
		filepath.Join("scripts", "phase17", "privacy_scanner_b.py"),
		filepath.Join("testdata", "fixtures", "phase17", "privacy-scanner", "corpus-v1.json"),
	} {
		source := filepath.Join(repositoryRoot, relative)
		destination := filepath.Join(temporaryRoot, relative)
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	testScript := filepath.Join(temporaryRoot, "scripts", "phase17", "privacy_scan_b_test.py")
	if output, err := exec.Command(python, testScript).CombinedOutput(); err != nil {
		t.Fatalf("Python scanner qualification failed: %v: %s", err, output)
	}
	if err := filepath.WalkDir(temporaryRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Name() == "__pycache__" || filepath.Ext(entry.Name()) == ".pyc" {
			t.Fatalf("Python qualification mutated frozen source tree: %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func findPythonForTest(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"python", "python3"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	t.Fatal("supported Python runtime unavailable")
	return ""
}
