// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package envelope

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	MaxIngressQRChunks     = 64
	MaxIngressChunkChars   = 4096
	MaxIngressEncodedChars = (MaxTotalInputBytes*4 + 2) / 3
	artifactURIPrefix      = "kurd://artifact/"
	qrChunkPrefix          = "KURD1/"
)

type IngressKind string

const (
	IngressFile         IngressKind = "file"
	IngressURI          IngressKind = "uri"
	IngressQRChunks     IngressKind = "qr-chunks"
	IngressClipboard    IngressKind = "clipboard"
	IngressSubscription IngressKind = "subscription"
)

type IngressErrorCategory string

const (
	IngressInvalidKind     IngressErrorCategory = "invalid-kind"
	IngressEmpty           IngressErrorCategory = "empty"
	IngressSizeLimit       IngressErrorCategory = "size-limit"
	IngressAmbiguousBase   IngressErrorCategory = "ambiguous-base-encoding"
	IngressMalformedURI    IngressErrorCategory = "malformed-uri"
	IngressMalformedChunks IngressErrorCategory = "malformed-qr-chunks"
	IngressLegacyUntrusted IngressErrorCategory = "legacy-untrusted"
)

type IngressError struct {
	Category IngressErrorCategory
	Detail   string
}

func (e *IngressError) Error() string {
	return "envelope ingress: " + string(e.Category) + ": " + e.Detail
}

func ingressError(category IngressErrorCategory, detail string) error {
	return &IngressError{Category: category, Detail: detail}
}

func IngressErrorIs(err error, category IngressErrorCategory) bool {
	var target *IngressError
	return errors.As(err, &target) && target.Category == category
}

type ProfileIngress struct {
	Kind   IngressKind
	Bytes  []byte
	Text   string
	Chunks []string
}

// NormalizeProfileIngress returns one opaque byte sequence. It performs no
// semantic profile parsing, verification, opening, persistence, or networking.
func NormalizeProfileIngress(input ProfileIngress) ([]byte, error) {
	var normalized []byte
	var err error
	switch input.Kind {
	case IngressFile, IngressSubscription:
		if input.Text != "" || len(input.Chunks) != 0 {
			return nil, ingressError(IngressInvalidKind, "raw ingress carried alternate representations")
		}
		if len(input.Bytes) == 0 {
			return nil, ingressError(IngressEmpty, "opaque artifact")
		}
		if len(input.Bytes) > MaxTotalInputBytes {
			return nil, ingressError(IngressSizeLimit, "opaque artifact")
		}
		normalized = bytes.Clone(input.Bytes)
	case IngressURI, IngressClipboard:
		if len(input.Bytes) != 0 || len(input.Chunks) != 0 {
			return nil, ingressError(IngressInvalidKind, "text ingress carried alternate representations")
		}
		normalized, err = decodeArtifactURI(input.Text)
	case IngressQRChunks:
		if len(input.Bytes) != 0 || input.Text != "" {
			return nil, ingressError(IngressInvalidKind, "QR ingress carried alternate representations")
		}
		normalized, err = decodeQRChunks(input.Chunks)
	default:
		return nil, ingressError(IngressInvalidKind, string(input.Kind))
	}
	if err != nil {
		return nil, err
	}
	if len(normalized) == 0 {
		return nil, ingressError(IngressEmpty, "opaque artifact")
	}
	if len(normalized) > MaxTotalInputBytes {
		return nil, ingressError(IngressSizeLimit, "opaque artifact")
	}
	return bytes.Clone(normalized), nil
}

func EncodeArtifactURI(opaque []byte) (string, error) {
	if len(opaque) == 0 || len(opaque) > MaxTotalInputBytes {
		return "", ingressError(IngressSizeLimit, "opaque artifact")
	}
	return artifactURIPrefix + base64.RawURLEncoding.EncodeToString(opaque), nil
}

func decodeArtifactURI(value string) ([]byte, error) {
	if strings.HasPrefix(strings.ToLower(value), "kurd://") && !strings.HasPrefix(value, artifactURIPrefix) {
		return nil, ingressError(IngressLegacyUntrusted, "legacy metadata link is non-promotable")
	}
	if !strings.HasPrefix(value, artifactURIPrefix) || strings.ContainsAny(value, "?#\r\n\t ") {
		return nil, ingressError(IngressMalformedURI, "expected exact kurd artifact URI")
	}
	encoded := strings.TrimPrefix(value, artifactURIPrefix)
	if encoded == "" || strings.Contains(encoded, "=") {
		return nil, ingressError(IngressAmbiguousBase, "padding or empty payload")
	}
	if len(encoded) > MaxIngressEncodedChars {
		return nil, ingressError(IngressSizeLimit, "encoded URI artifact")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, ingressError(IngressAmbiguousBase, "non-canonical base64url")
	}
	return decoded, nil
}

func EncodeQRChunks(opaque []byte, rawChunkBytes int) ([]string, error) {
	if len(opaque) == 0 || len(opaque) > MaxTotalInputBytes || rawChunkBytes <= 0 {
		return nil, ingressError(IngressSizeLimit, "QR input")
	}
	total := (len(opaque) + rawChunkBytes - 1) / rawChunkBytes
	if total > MaxIngressQRChunks {
		return nil, ingressError(IngressSizeLimit, "QR chunk count")
	}
	chunks := make([]string, total)
	for i := range chunks {
		start := i * rawChunkBytes
		end := start + rawChunkBytes
		if end > len(opaque) {
			end = len(opaque)
		}
		payload := base64.RawURLEncoding.EncodeToString(opaque[start:end])
		chunks[i] = fmt.Sprintf("%s%d/%d/%s", qrChunkPrefix, i+1, total, payload)
		if len(chunks[i]) > MaxIngressChunkChars {
			return nil, ingressError(IngressSizeLimit, "QR chunk characters")
		}
	}
	return chunks, nil
}

func decodeQRChunks(chunks []string) ([]byte, error) {
	if len(chunks) == 0 || len(chunks) > MaxIngressQRChunks {
		return nil, ingressError(IngressMalformedChunks, "chunk count")
	}
	total := 0
	parts := make([][]byte, len(chunks))
	seen := make([]bool, len(chunks))
	for _, chunk := range chunks {
		if len(chunk) == 0 || len(chunk) > MaxIngressChunkChars || !strings.HasPrefix(chunk, qrChunkPrefix) {
			return nil, ingressError(IngressMalformedChunks, "chunk framing")
		}
		fields := strings.Split(strings.TrimPrefix(chunk, qrChunkPrefix), "/")
		if len(fields) != 3 {
			return nil, ingressError(IngressMalformedChunks, "chunk arity")
		}
		index, indexErr := canonicalQRDecimal(fields[0])
		declared, totalErr := canonicalQRDecimal(fields[1])
		if indexErr != nil || totalErr != nil || declared != len(chunks) || declared < 1 || declared > MaxIngressQRChunks || index < 1 || index > declared || seen[index-1] {
			return nil, ingressError(IngressMalformedChunks, "chunk index or total")
		}
		if total == 0 {
			total = declared
		} else if total != declared {
			return nil, ingressError(IngressMalformedChunks, "inconsistent total")
		}
		if fields[2] == "" || strings.Contains(fields[2], "=") {
			return nil, ingressError(IngressAmbiguousBase, "QR payload padding or empty")
		}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(fields[2])
		if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != fields[2] {
			return nil, ingressError(IngressAmbiguousBase, "QR payload base64url")
		}
		seen[index-1] = true
		parts[index-1] = decoded
	}
	var normalized []byte
	for i, part := range parts {
		if !seen[i] {
			return nil, ingressError(IngressMalformedChunks, "missing chunk")
		}
		if len(normalized)+len(part) > MaxTotalInputBytes {
			return nil, ingressError(IngressSizeLimit, "assembled QR artifact")
		}
		normalized = append(normalized, part...)
	}
	return normalized, nil
}

func canonicalQRDecimal(value string) (int, error) {
	if value == "" || len(value) > 3 || (len(value) > 1 && value[0] == '0') {
		return 0, ingressError(IngressMalformedChunks, "non-canonical decimal")
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, ingressError(IngressMalformedChunks, "non-canonical decimal")
		}
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || strconv.Itoa(parsed) != value {
		return 0, ingressError(IngressMalformedChunks, "non-canonical decimal")
	}
	return parsed, nil
}
