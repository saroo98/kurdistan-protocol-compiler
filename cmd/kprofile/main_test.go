package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/testkit/phase8issuance"
)

type failingLocalOutput struct {
	file        *os.File
	short       bool
	writeErr    error
	closeErr    error
	beforeWrite func()
}

func (f *failingLocalOutput) Write(content []byte) (int, error) {
	if f.beforeWrite != nil {
		beforeWrite := f.beforeWrite
		f.beforeWrite = nil
		beforeWrite()
	}
	if f.writeErr == nil {
		if f.short && len(content) > 0 {
			if _, err := f.file.Write(content[:1]); err != nil {
				return 0, err
			}
			return 1, nil
		}
		return f.file.Write(content)
	}
	if len(content) == 0 {
		return 0, f.writeErr
	}
	if _, err := f.file.Write(content[:1]); err != nil {
		return 0, err
	}
	return 1, f.writeErr
}

func (f *failingLocalOutput) Close() error {
	if err := f.file.Close(); err != nil {
		return err
	}
	return f.closeErr
}

func TestWriteNewLocalFileFailsClosedWithoutPathCleanup(t *testing.T) {
	for _, tc := range []struct {
		name     string
		short    bool
		writeErr error
		closeErr error
	}{
		{name: "write", writeErr: errors.New("write failed")},
		{name: "short write", short: true},
		{name: "close", closeErr: errors.New("close failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "profile.cbor")
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			err = writeNewLocalFile([]byte("profile"), &failingLocalOutput{file: file, short: tc.short, writeErr: tc.writeErr, closeErr: tc.closeErr})
			if err == nil {
				t.Fatal("write unexpectedly succeeded")
			}
			if got, statErr := os.ReadFile(path); statErr != nil || len(got) == 0 {
				t.Fatalf("failed write did not remain contained at its original handle: data=%q err=%v", got, statErr)
			}
		})
	}
}

func TestWriteFailureDoesNotDeleteReplacementPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.cbor")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	output := &failingLocalOutput{
		file:     file,
		writeErr: errors.New("write failed"),
		beforeWrite: func() {
			if err := os.Remove(path); err != nil {
				t.Skipf("filesystem does not permit replacing an open file: %v", err)
			}
			if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	if err := writeNewLocalFile([]byte("profile"), output); err == nil {
		t.Fatal("write unexpectedly succeeded")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "replacement" {
		t.Fatalf("path cleanup touched replacement: data=%q err=%v", got, err)
	}
}

func TestRootedLocalPathOperationsStayBoundToOpenedParent(t *testing.T) {
	t.Run("input", func(t *testing.T) {
		base := t.TempDir()
		parent := filepath.Join(base, "trusted")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(parent, "input")
		if err := os.WriteFile(path, []byte("trusted"), 0o600); err != nil {
			t.Fatal(err)
		}
		retained := parent + "-retained"
		got, err := readBoundedLocalWithHook(path, func() {
			if err := os.Rename(parent, retained); err != nil {
				t.Fatalf("replace parent: %v", err)
			}
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
				t.Fatal(err)
			}
		})
		if err != nil || string(got) != "trusted" {
			t.Fatalf("input redirected after parent replacement: data=%q err=%v", got, err)
		}
	})

	t.Run("output", func(t *testing.T) {
		base := t.TempDir()
		parent := filepath.Join(base, "trusted")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(parent, "output")
		retained := parent + "-retained"
		err := writeNewLocalWithHook(path, []byte("trusted"), func() {
			if err := os.Rename(parent, retained); err != nil {
				t.Fatalf("replace parent: %v", err)
			}
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		if got, err := os.ReadFile(filepath.Join(retained, "output")); err != nil || string(got) != "trusted" {
			t.Fatalf("output was not created in opened parent: data=%q err=%v", got, err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("output redirected to replacement parent: %v", err)
		}
	})
}

func TestRootedLocalPathOperationsRejectFinalSymlinkSwap(t *testing.T) {
	t.Run("input", func(t *testing.T) {
		base := t.TempDir()
		path := filepath.Join(base, "input")
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(path, []byte("trusted"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := readBoundedLocalWithHook(path, func() {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, path); err != nil {
				t.Skipf("symlink creation unavailable: %v", err)
			}
		})
		if err == nil {
			t.Fatal("accepted final symlink replacement")
		}
	})

	t.Run("output", func(t *testing.T) {
		base := t.TempDir()
		path := filepath.Join(base, "output")
		outside := filepath.Join(t.TempDir(), "outside")
		err := writeNewLocalWithHook(path, []byte("trusted"), func() {
			if err := os.Symlink(outside, path); err != nil {
				t.Skipf("symlink creation unavailable: %v", err)
			}
		})
		if err == nil {
			t.Fatal("accepted final symlink output replacement")
		}
		if _, err := os.Lstat(outside); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("output followed final symlink: %v", err)
		}
	})
}

func TestCompileInspectAreSecretSafeAndNeverOverwrite(t *testing.T) {
	dir := t.TempDir()
	specPath, outPath := filepath.Join(dir, "spec.json"), filepath.Join(dir, "profile.cbor")
	spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	raw, _ := json.Marshal(spec)
	if err := os.WriteFile(specPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	commandStdout, commandStderr = &stdout, &stderr
	t.Cleanup(func() { commandStdout, commandStderr = os.Stdout, os.Stderr })
	if code := run([]string{"compile", "--spec", specPath, "--out", outPath}); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	output := stdout.String()
	if strings.Contains(output, spec.Profile.ContentID) || strings.Contains(output, spec.IssuerKey.KeyID) || strings.Contains(output, specPath) {
		t.Fatalf("secret-bearing output: %q", output)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"compile", "--spec", specPath, "--out", outPath}); code == 0 || stderr.String() != "output rejected\n" {
		t.Fatalf("overwrite code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"inspect", "--in", outPath}); code != 0 {
		t.Fatalf("inspect=%d %q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), spec.Profile.ContentID) || strings.Contains(stdout.String(), "relay.0001") || strings.Contains(stdout.String(), "strategy.0001") {
		t.Fatalf("inspect leaked: %q", stdout.String())
	}
}

func TestHelpHasNoDeterministicOrKeySelection(t *testing.T) {
	var stdout, stderr bytes.Buffer
	commandStdout, commandStderr = &stdout, &stderr
	t.Cleanup(func() { commandStdout, commandStderr = os.Stdout, os.Stderr })
	_ = run([]string{"compile", "-h"})
	help := strings.ToLower(stderr.String())
	for _, forbidden := range []string{"deterministic", "private-key", "seed", "environment"} {
		if strings.Contains(help, forbidden) {
			t.Fatalf("help exposes %q: %s", forbidden, help)
		}
	}
}

func TestCLIRejectsNetworkDeviceSymlinkAndNonCanonicalInputs(t *testing.T) {
	for _, path := range []string{`\\server\share\spec.json`, `\\?\C:\spec.json`, `\\.\PhysicalDrive0`} {
		if _, err := readBoundedLocal(path); err == nil {
			t.Fatalf("accepted network/device path %q", path)
		}
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err == nil {
		if _, err := readBoundedLocal(link); err == nil {
			t.Fatal("accepted symlink input")
		}
	}
	oversized := filepath.Join(dir, "oversized")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte{'x'}, envelope.MaxTotalInputBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedLocal(oversized); err == nil {
		t.Fatal("accepted max+1 input")
	}
	spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	canonical, _ := json.Marshal(spec)
	for _, raw := range [][]byte{append(append([]byte{}, canonical...), []byte("{}")...), append([]byte(" "), canonical...)} {
		path := filepath.Join(dir, fmt.Sprintf("bad-%d.json", len(raw)))
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		commandStdout, commandStderr = &stdout, &stderr
		if code := run([]string{"compile", "--spec", path, "--out", filepath.Join(dir, fmt.Sprintf("out-%d", len(raw)))}); code == 0 {
			t.Fatal("accepted noncanonical/multiple JSON")
		}
	}
}
