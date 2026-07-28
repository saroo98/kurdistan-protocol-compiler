// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"testing"

	"kurdistan/internal/product/diagnosticexport"
)

func TestDiagnosticBridgeRequiresExactPreviewConfirmation(t *testing.T) {
	request, err := EncodeDiagnosticRequest(diagnosticexport.Request{
		Version:       diagnosticexport.Version,
		Revision:      9,
		UserInitiated: true,
		Entries: []diagnosticexport.Entry{{
			Category: diagnosticexport.CategoryContractVersions,
			Value:    diagnosticexport.ValueSupported,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var registry HandleRegistry
	handle, code := DiagnosticPrepare(&registry, request)
	if code != CodeOK {
		t.Fatalf("prepare code=%v", code)
	}
	preview, code := DiagnosticPreview(&registry, handle)
	if code != CodeOK {
		t.Fatalf("preview code=%v", code)
	}
	mutated := append([]byte(nil), preview...)
	mutated[len(mutated)-1] ^= 1
	if code := DiagnosticConfirm(&registry, handle, true, mutated); code == CodeOK {
		t.Fatal("mutated preview accepted")
	}
	if code := DiagnosticConfirm(&registry, handle, true, preview); code != CodeOK {
		t.Fatalf("confirm code=%v", code)
	}
	bundle, code := DiagnosticBuild(&registry, handle)
	if code != CodeOK || !bytes.Contains(bundle, []byte(diagnosticexport.PrivacyStatement)) {
		t.Fatalf("bundle code=%v bytes=%q", code, bundle)
	}
}
