// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateEnvironmentCommitmentMatchesIndependentVector(t *testing.T) {
	root := t.TempDir()
	value := validPrivateEnvironmentForTest(root)
	want := "f51522a571bdc737b2daf76e945a6eeb22c6610e1709083af0100abdc37a331b"
	got, err := ComputePrivateEnvironmentCommitment(
		strings.Repeat("11", 32),
		"EMULATOR",
		byteRange(32),
		value,
		[]byte("https://probe.invalid/check"),
		[]byte(strings.Repeat("22", 32)),
		[]byte("2026-08-14T05:06:07.1234567Z"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("commitment=%q, want independent vector %q", got, want)
	}
}

func TestPrivateEnvironmentCommitmentBindsCandidateEverySelectorAndHostBoot(t *testing.T) {
	root := t.TempDir()
	baseline := validPrivateEnvironmentForTest(root)
	salt := bytes.Repeat([]byte{0x5a}, PrivateEnvironmentSaltSize)
	probeURL := []byte("https://probe.invalid/check")
	probeDigest := []byte(strings.Repeat("33", 32))
	bootIdentity := []byte("2026-08-14T05:06:07.1234567Z")
	base, err := ComputePrivateEnvironmentCommitment(
		strings.Repeat("44", 32), "EMULATOR", salt, baseline, probeURL, probeDigest, bootIdentity,
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func() (string, string, []byte, PrivateEnvironment, []byte, []byte, []byte){
		"candidate": func() (string, string, []byte, PrivateEnvironment, []byte, []byte, []byte) {
			return strings.Repeat("45", 32), "EMULATOR", salt, baseline, probeURL, probeDigest, bootIdentity
		},
		"salt": func() (string, string, []byte, PrivateEnvironment, []byte, []byte, []byte) {
			return strings.Repeat("44", 32), "EMULATOR", bytes.Repeat([]byte{0x5b}, PrivateEnvironmentSaltSize), baseline, probeURL, probeDigest, bootIdentity
		},
		"ssh alias": func() (string, string, []byte, PrivateEnvironment, []byte, []byte, []byte) {
			changed := baseline
			changed.SSHAlias = "other-node"
			return strings.Repeat("44", 32), "EMULATOR", salt, changed, probeURL, probeDigest, bootIdentity
		},
		"android selector": func() (string, string, []byte, PrivateEnvironment, []byte, []byte, []byte) {
			changed := baseline
			changed.AVDName = "api36-other"
			return strings.Repeat("44", 32), "EMULATOR", salt, changed, probeURL, probeDigest, bootIdentity
		},
		"android class": func() (string, string, []byte, PrivateEnvironment, []byte, []byte, []byte) {
			changed := baseline
			changed.AVDName = ""
			changed.DeviceSerial = "physical-one"
			return strings.Repeat("44", 32), "PHYSICAL", salt, changed, probeURL, probeDigest, bootIdentity
		},
		"probe URL": func() (string, string, []byte, PrivateEnvironment, []byte, []byte, []byte) {
			return strings.Repeat("44", 32), "EMULATOR", salt, baseline, []byte("https://probe.invalid/other"), probeDigest, bootIdentity
		},
		"probe digest": func() (string, string, []byte, PrivateEnvironment, []byte, []byte, []byte) {
			return strings.Repeat("44", 32), "EMULATOR", salt, baseline, probeURL, []byte(strings.Repeat("34", 32)), bootIdentity
		},
		"IPv6 selector": func() (string, string, []byte, PrivateEnvironment, []byte, []byte, []byte) {
			changed := baseline
			changed.IPv6ProbeAddress = "2001:db8::2"
			return strings.Repeat("44", 32), "EMULATOR", salt, changed, probeURL, probeDigest, bootIdentity
		},
		"relay port": func() (string, string, []byte, PrivateEnvironment, []byte, []byte, []byte) {
			changed := baseline
			changed.RelayPort = 9443
			return strings.Repeat("44", 32), "EMULATOR", salt, changed, probeURL, probeDigest, bootIdentity
		},
		"host boot": func() (string, string, []byte, PrivateEnvironment, []byte, []byte, []byte) {
			return strings.Repeat("44", 32), "EMULATOR", salt, baseline, probeURL, probeDigest, []byte("2026-08-14T06:07:08.2345678Z")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate, class, changedSalt, changed, changedURL, changedDigest, changedBoot := mutate()
			got, err := ComputePrivateEnvironmentCommitment(candidate, class, changedSalt, changed, changedURL, changedDigest, changedBoot)
			if err != nil {
				t.Fatal(err)
			}
			if got == base {
				t.Fatal("private selector or host boot mutation preserved commitment")
			}
		})
	}
}

func TestDecodePrivateEnvironmentRejectsAmbiguousOrUnsafeConfiguration(t *testing.T) {
	root := filepath.ToSlash(t.TempDir())
	valid := fmt.Sprintf(`{"schema":"kurdistan-phase17-private-environment-v1","sshAlias":"owner-node","avdName":"api36-field","deviceSerial":"","probeUrlFile":%q,"probeDigestFile":%q,"ipv6ProbeAddress":"2001:db8::1","relayPort":8443,"pythonExecutable":%q,"adbExecutable":%q,"sshExecutable":%q,"scpExecutable":%q,"powershellExecutable":%q}`,
		root+"/probe-url.txt", root+"/probe-digest.txt", root+"/python", root+"/adb", root+"/ssh", root+"/scp", root+"/powershell")
	decoded, err := DecodePrivateEnvironment(bytes.NewBufferString(valid))
	if err != nil || decoded.SSHAlias != "owner-node" || decoded.AVDName != "api36-field" {
		t.Fatalf("valid private environment rejected: value=%+v err=%v", decoded, err)
	}

	invalid := map[string]string{
		"unknown field":  strings.Replace(valid, `"sshAlias":"owner-node"`, `"unknown":true,"sshAlias":"owner-node"`, 1),
		"both selectors": strings.Replace(valid, `"deviceSerial":""`, `"deviceSerial":"physical-one"`, 1),
		"no selector":    strings.Replace(valid, `"avdName":"api36-field"`, `"avdName":""`, 1),
		"unsafe alias":   strings.Replace(valid, `"sshAlias":"owner-node"`, `"sshAlias":"owner node"`, 1),
		"relative path":  strings.Replace(valid, fmt.Sprintf(`"probeUrlFile":%q`, root+"/probe-url.txt"), `"probeUrlFile":"probe-url.txt"`, 1),
		"IPv4 selector":  strings.Replace(valid, `"ipv6ProbeAddress":"2001:db8::1"`, `"ipv6ProbeAddress":"192.0.2.1"`, 1),
		"zero port":      strings.Replace(valid, `"relayPort":8443`, `"relayPort":0`, 1),
		"trailing data":  valid + ` {}`,
	}
	for name, raw := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePrivateEnvironment(bytes.NewBufferString(raw)); err == nil {
				t.Fatal("unsafe private environment accepted")
			}
		})
	}
}

func TestPrivateEnvironmentCommitmentRejectsWrongSaltLengthOrClass(t *testing.T) {
	value := validPrivateEnvironmentForTest(t.TempDir())
	for name, testCase := range map[string]struct {
		class string
		salt  []byte
	}{
		"short salt":  {class: "EMULATOR", salt: bytes.Repeat([]byte{1}, PrivateEnvironmentSaltSize-1)},
		"wrong class": {class: "PHYSICAL", salt: bytes.Repeat([]byte{1}, PrivateEnvironmentSaltSize)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ComputePrivateEnvironmentCommitment(
				strings.Repeat("55", 32), testCase.class, testCase.salt, value,
				[]byte("https://probe.invalid/check"), []byte(strings.Repeat("66", 32)),
				[]byte("2026-08-14T05:06:07.1234567Z"),
			); err == nil {
				t.Fatal("invalid private environment commitment input accepted")
			}
		})
	}
}

func validPrivateEnvironmentForTest(root string) PrivateEnvironment {
	return PrivateEnvironment{
		Schema:   PrivateEnvironmentSchema,
		SSHAlias: "owner-node", AVDName: "api36-field", DeviceSerial: "",
		ProbeURLFile: filepath.Join(root, "probe-url.txt"), ProbeDigestFile: filepath.Join(root, "probe-digest.txt"),
		IPv6ProbeAddress: "2001:db8::1", RelayPort: 8443,
		PythonExecutable: filepath.Join(root, "python"), ADBExecutable: filepath.Join(root, "adb"),
		SSHExecutable: filepath.Join(root, "ssh"), SCPExecutable: filepath.Join(root, "scp"),
		PowerShellExecutable: filepath.Join(root, "powershell"),
	}
}

func byteRange(size int) []byte {
	result := make([]byte, size)
	for index := range result {
		result[index] = byte(index)
	}
	return result
}
