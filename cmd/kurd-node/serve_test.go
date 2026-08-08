// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"kurdistan/internal/relay/node"
)

func TestSessionRejectReporterIsCategoricalAndBounded(t *testing.T) {
	var output bytes.Buffer
	report := newSessionRejectReporterV1(&output, 2)
	report(node.SessionRejectAdmissionV1)
	report(node.SessionRejectTLSV1)
	report(node.SessionRejectStateV1)

	if got := output.String(); got != "kurd-node serve: session-rejected:admission\nkurd-node serve: session-rejected:tls\n" {
		t.Fatalf("unexpected categorical report %q", got)
	}
	for _, prohibited := range []string{"profile", "endpoint", "address", "key", "credential"} {
		if strings.Contains(output.String(), prohibited) {
			t.Fatalf("session rejection report exposed %q", prohibited)
		}
	}
}

func TestServerStopCategoryIsBounded(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{err: node.ErrServerRegistry, want: "registry"},
		{err: node.ErrServerListener, want: "listener"},
		{err: node.ErrServerControl, want: "control"},
		{err: node.ErrServerReload, want: "reload"},
		{err: errors.New("private detail"), want: "unknown"},
	}
	for _, test := range tests {
		if got := serverStopCategoryV1(test.err); got != test.want {
			t.Fatalf("category=%q want=%q", got, test.want)
		}
	}
}
