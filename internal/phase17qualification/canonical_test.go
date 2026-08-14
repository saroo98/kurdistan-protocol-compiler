// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"testing"
)

func TestMarshalCanonicalUsesFixedStructOrderWithoutHTMLEscapingOrNewline(t *testing.T) {
	type fixture struct {
		First  string `json:"first"`
		Second uint64 `json:"second"`
	}
	raw, err := MarshalCanonical(fixture{First: "<safe>", Second: 2})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(raw), `{"first":"<safe>","second":2}`; got != want {
		t.Fatalf("canonical JSON=%q want %q", got, want)
	}
	if bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatal("canonical JSON contains a trailing newline")
	}
}

func TestMarshalCanonicalRejectsMapsInterfacesFloatsAndPointers(t *testing.T) {
	for name, value := range map[string]any{
		"map": map[string]string{"a": "b"},
		"interface": struct {
			Value any `json:"value"`
		}{Value: "x"},
		"float": struct {
			Value float64 `json:"value"`
		}{Value: 1},
		"pointer": &struct {
			Value string `json:"value"`
		}{Value: "x"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := MarshalCanonical(value); err == nil {
				t.Fatal("non-fixed canonical payload accepted")
			}
		})
	}
}
