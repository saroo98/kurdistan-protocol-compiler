// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"testing"

	"kurdistan/internal/audit"
)

func TestAuditExecutorOptions(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		workers int
		want    audit.ExecutorOptions
		wantErr bool
	}{
		{name: "serial default", mode: "serial", workers: 1, want: audit.ExecutorOptions{Mode: audit.ExecutorSerial, Workers: 1}},
		{name: "bounded parallel shadow", mode: "parallel", workers: 3, want: audit.ExecutorOptions{Mode: audit.ExecutorParallel, Workers: 3}},
		{name: "unknown executor", mode: "distributed", workers: 3, wantErr: true},
		{name: "zero workers", mode: "parallel", workers: 0, wantErr: true},
		{name: "negative workers", mode: "parallel", workers: -1, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := auditExecutorOptions(test.mode, test.workers)
			if test.wantErr {
				if err == nil {
					t.Fatalf("auditExecutorOptions(%q, %d) unexpectedly succeeded", test.mode, test.workers)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("options = %+v, want %+v", got, test.want)
			}
		})
	}
}
