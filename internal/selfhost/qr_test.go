// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"image/png"
	"strings"
	"testing"
)

func TestQRRenderersAreDeterministicAndBounded(t *testing.T) {
	text := "KURD1/1/1/0123456789abcdef"
	terminal, err := RenderTerminalQR(text)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(terminal, "█") || len(terminal) > maxRenderedQRBytes {
		t.Fatalf("terminal QR is missing or unbounded: bytes=%d", len(terminal))
	}

	pngOne, err := RenderPNGQR(text, 6)
	if err != nil {
		t.Fatal(err)
	}
	pngTwo, err := RenderPNGQR(text, 6)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pngOne, pngTwo) || len(pngOne) > maxRenderedQRBytes {
		t.Fatalf("PNG QR is nondeterministic or unbounded: bytes=%d", len(pngOne))
	}
	imageValue, err := png.Decode(bytes.NewReader(pngOne))
	if err != nil {
		t.Fatal(err)
	}
	if imageValue.Bounds().Dx() != imageValue.Bounds().Dy() || imageValue.Bounds().Dx() < 100 {
		t.Fatalf("unexpected QR dimensions: %v", imageValue.Bounds())
	}

	svgOne, err := RenderSVGQR(text, 6)
	if err != nil {
		t.Fatal(err)
	}
	svgTwo, err := RenderSVGQR(text, 6)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(svgOne, svgTwo) || !bytes.Contains(svgOne, []byte("<svg")) || bytes.Contains(svgOne, []byte(text)) || len(svgOne) > maxRenderedQRBytes {
		t.Fatalf("SVG QR is unsafe, nondeterministic, or unbounded: bytes=%d", len(svgOne))
	}
}

func TestQRRenderersRejectInvalidBounds(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func() error
	}{
		{"empty", func() error { _, err := RenderTerminalQR(""); return err }},
		{"oversized", func() error { _, err := RenderTerminalQR(strings.Repeat("x", maxQRTextBytes+1)); return err }},
		{"small scale", func() error { _, err := RenderPNGQR("kurd", 1); return err }},
		{"large scale", func() error { _, err := RenderSVGQR("kurd", 17); return err }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); err == nil {
				t.Fatal("invalid QR input was accepted")
			}
		})
	}
}
