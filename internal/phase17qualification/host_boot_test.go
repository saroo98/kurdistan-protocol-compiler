// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestReadCurrentHostBootIdentityCanonicalizesDocumentedWMIValue(t *testing.T) {
	var gotExecutable string
	var gotArguments []string
	identity, err := readCurrentHostBootIdentity(
		context.Background(), `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		func(_ context.Context, executable string, arguments ...string) ([]byte, error) {
			gotExecutable = executable
			gotArguments = append([]string(nil), arguments...)
			return []byte("2026-08-14T05:06:07.1234567Z\r\n"), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(identity) != "2026-08-14T05:06:07.1234567Z" {
		t.Fatalf("identity=%q", identity)
	}
	if gotExecutable == "" || !reflect.DeepEqual(gotArguments[:5], []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"}) {
		t.Fatalf("command=%q %#v", gotExecutable, gotArguments)
	}
}

func TestReadCurrentHostBootIdentityFailsClosed(t *testing.T) {
	tests := map[string]struct {
		raw []byte
		err error
	}{
		"command failure": {err: errors.New("failed")},
		"empty":           {raw: []byte("\r\n")},
		"offset":          {raw: []byte("2026-08-14T06:06:07.1234567+01:00")},
		"multiple lines":  {raw: []byte("2026-08-14T05:06:07Z\nsecond")},
		"oversized":       {raw: []byte(strings.Repeat("1", 257))},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			if identity, err := readCurrentHostBootIdentity(
				context.Background(), `C:\Windows\powershell.exe`,
				func(context.Context, string, ...string) ([]byte, error) { return testCase.raw, testCase.err },
			); err == nil || identity != nil {
				t.Fatalf("identity=%q err=%v", identity, err)
			}
		})
	}
}
