// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"strings"

	qrcode "github.com/yeqown/go-qrcode/v2"
)

const (
	maxQRTextBytes     = 4096
	maxRenderedQRBytes = 4 << 20
	qrQuietZone        = 4
)

type matrixWriter struct {
	bitmap [][]bool
}

func (writer *matrixWriter) Write(matrix qrcode.Matrix) error {
	writer.bitmap = matrix.Bitmap()
	return nil
}

func (*matrixWriter) Close() error { return nil }

func qrBitmap(text string) ([][]bool, error) {
	if text == "" || len(text) > maxQRTextBytes {
		return nil, ErrInvalidInput
	}
	code, err := qrcode.New(text)
	if err != nil {
		return nil, fmt.Errorf("selfhost: render QR: %w", err)
	}
	writer := &matrixWriter{}
	if err := code.Save(writer); err != nil || len(writer.bitmap) == 0 || len(writer.bitmap) > 177 {
		return nil, ErrInvalidInput
	}
	for _, row := range writer.bitmap {
		if len(row) != len(writer.bitmap) {
			return nil, ErrInvalidInput
		}
	}
	return writer.bitmap, nil
}

// RenderTerminalQR returns a quiet-zone QR using two module rows per terminal
// cell. It emits no ANSI escapes, file paths, profile metadata, or logging.
func RenderTerminalQR(text string) (string, error) {
	bitmap, err := qrBitmap(text)
	if err != nil {
		return "", err
	}
	width := len(bitmap) + 2*qrQuietZone
	height := len(bitmap) + 2*qrQuietZone
	var output strings.Builder
	output.Grow(width * (height/2 + 2) * 3)
	dark := func(x, y int) bool {
		x -= qrQuietZone
		y -= qrQuietZone
		return y >= 0 && y < len(bitmap) && x >= 0 && x < len(bitmap) && bitmap[y][x]
	}
	for y := 0; y < height; y += 2 {
		for x := 0; x < width; x++ {
			top := dark(x, y)
			bottom := y+1 < height && dark(x, y+1)
			switch {
			case top && bottom:
				output.WriteRune('█')
			case top:
				output.WriteRune('▀')
			case bottom:
				output.WriteRune('▄')
			default:
				output.WriteRune(' ')
			}
		}
		output.WriteByte('\n')
		if output.Len() > maxRenderedQRBytes {
			return "", ErrInvalidInput
		}
	}
	return output.String(), nil
}

func RenderPNGQR(text string, scale int) ([]byte, error) {
	bitmap, err := qrBitmap(text)
	if err != nil || scale < 2 || scale > 16 {
		return nil, ErrInvalidInput
	}
	side := (len(bitmap) + 2*qrQuietZone) * scale
	if side <= 0 || side > 4096 {
		return nil, ErrInvalidInput
	}
	value := image.NewGray(image.Rect(0, 0, side, side))
	for index := range value.Pix {
		value.Pix[index] = 0xff
	}
	for y, row := range bitmap {
		for x, dark := range row {
			if !dark {
				continue
			}
			startX := (x + qrQuietZone) * scale
			startY := (y + qrQuietZone) * scale
			for pixelY := startY; pixelY < startY+scale; pixelY++ {
				for pixelX := startX; pixelX < startX+scale; pixelX++ {
					value.SetGray(pixelX, pixelY, color.Gray{Y: 0})
				}
			}
		}
	}
	var output bytes.Buffer
	encoder := png.Encoder{CompressionLevel: png.BestCompression}
	if err := encoder.Encode(&output, value); err != nil || output.Len() > maxRenderedQRBytes {
		return nil, ErrInvalidInput
	}
	return output.Bytes(), nil
}

func RenderSVGQR(text string, scale int) ([]byte, error) {
	bitmap, err := qrBitmap(text)
	if err != nil || scale < 2 || scale > 16 {
		return nil, ErrInvalidInput
	}
	side := len(bitmap) + 2*qrQuietZone
	var output bytes.Buffer
	fmt.Fprintf(&output, "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\" viewBox=\"0 0 %d %d\" shape-rendering=\"crispEdges\"><rect width=\"100%%\" height=\"100%%\" fill=\"#fff\"/><path fill=\"#000\" d=\"", side*scale, side*scale, side, side)
	for y, row := range bitmap {
		for x, dark := range row {
			if dark {
				fmt.Fprintf(&output, "M%d %dh1v1h-1z", x+qrQuietZone, y+qrQuietZone)
			}
		}
		if output.Len() > maxRenderedQRBytes {
			return nil, ErrInvalidInput
		}
	}
	output.WriteString("\"/></svg>\n")
	if output.Len() > maxRenderedQRBytes {
		return nil, ErrInvalidInput
	}
	return output.Bytes(), nil
}
