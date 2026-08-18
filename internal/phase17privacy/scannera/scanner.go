// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package scannera

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	ReceiptSchema  = "kurdistan-phase17-privacy-scanner-v1"
	MaximumBytes   = 32 << 20
	MaximumRecords = 4096
)

type Privacy struct {
	PayloadRetained     bool `json:"payloadRetained"`
	DestinationRetained bool `json:"destinationRetained"`
	DNSNameRetained     bool `json:"dnsNameRetained"`
	CredentialRetained  bool `json:"credentialRetained"`
	KeyRetained         bool `json:"keyRetained"`
	ProfileRetained     bool `json:"profileRetained"`
	RawLogRetained      bool `json:"rawLogRetained"`
}

type Receipt struct {
	Schema              string  `json:"schema"`
	Name                string  `json:"name"`
	InputSHA256         string  `json:"inputSha256"`
	BytesConsumed       uint64  `json:"bytesConsumed"`
	RecordsConsumed     uint64  `json:"recordsConsumed"`
	Result              string  `json:"result"`
	Truncated           bool    `json:"truncated"`
	ParseFailure        bool    `json:"parseFailure"`
	BackpressureFailure bool    `json:"backpressureFailure"`
	CoverageGap         bool    `json:"coverageGap"`
	Privacy             Privacy `json:"privacy"`
}

type record struct {
	Source string `json:"source"`
	Data   string `json:"data"`
}

var (
	addressCandidatePattern = regexp.MustCompile(`(?i)[0-9a-f:.]+(?:%[a-z0-9_.-]+)?`)
	base64CandidatePattern  = regexp.MustCompile(`[A-Za-z0-9+/_-]{12,}={0,2}`)
	urlPattern              = regexp.MustCompile(`(?i)\b(?:https?|wss?)://[^\s]+`)
	dnsCanaryPattern        = regexp.MustCompile(`(?i)\b(?:[a-z0-9-]+\.)+(?:invalid|example|test)\b`)
	credentialPattern       = regexp.MustCompile(`(?i)(?:authorization\s*:\s*bearer|password\s*[=:]|token\s*[=:]|credential\s*[=:])`)
	keyPattern              = regexp.MustCompile(`(?i)(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|private[_ -]?key\s*[=:]|recipient[_ -]?private)`)
	profilePattern          = regexp.MustCompile(`(?i)(?:\bkurd://|sealed[_ -]?profile|PHASE17_PROFILE_CANARY_)`)
	windowsOwnerPath        = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:[a-z]:\\(?:users|documents and settings)\\[^\\/\s]+)`)
	unixOwnerPath           = regexp.MustCompile(`(?i)(?:^|[\s"'=])/(?:home|root|users)/[^\s"'<>]+`)
)

func Scan(reader io.Reader, expectedBytes int64) Receipt {
	receipt := Receipt{Schema: ReceiptSchema, Name: "GO_A", Result: "FAIL"}
	if reader == nil || expectedBytes < 0 || expectedBytes > MaximumBytes {
		receipt.Truncated = true
		return receipt
	}
	raw, err := io.ReadAll(io.LimitReader(reader, MaximumBytes+1))
	receipt.BytesConsumed = uint64(len(raw))
	digest := sha256.Sum256(raw)
	receipt.InputSHA256 = hex.EncodeToString(digest[:])
	if err != nil {
		receipt.ParseFailure = true
		return receipt
	}
	if len(raw) > MaximumBytes || int64(len(raw)) != expectedBytes {
		receipt.Truncated = true
		return receipt
	}
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		receipt.ParseFailure = true
		return receipt
	}
	seenSources := map[string]bool{"ANDROID_LOGCAT": false, "REMOTE_JOURNAL": false}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64<<10), MaximumBytes)
	for scanner.Scan() {
		if receipt.RecordsConsumed >= MaximumRecords {
			receipt.Truncated = true
			return receipt
		}
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			receipt.ParseFailure = true
			return receipt
		}
		value, err := decodeRecord(line)
		if err != nil || !containsSource(seenSources, value.Source) {
			receipt.ParseFailure = true
			return receipt
		}
		payload, err := base64.StdEncoding.Strict().DecodeString(value.Data)
		if err != nil || len(payload) > 8<<20 {
			receipt.ParseFailure = true
			return receipt
		}
		receipt.RecordsConsumed++
		seenSources[value.Source] = true
		classify(value.Source, payload, &receipt.Privacy)
		clear(payload)
	}
	if scanner.Err() != nil {
		receipt.ParseFailure = true
		return receipt
	}
	if !seenSources["ANDROID_LOGCAT"] || !seenSources["REMOTE_JOURNAL"] {
		receipt.CoverageGap = true
		return receipt
	}
	if receipt.Privacy != (Privacy{}) {
		return receipt
	}
	receipt.Result = "PASS"
	return receipt
}

func decodeRecord(raw []byte) (record, error) {
	var result record
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return record{}, errors.New("record object rejected")
	}
	seen := map[string]bool{"source": false, "data": false}
	for decoder.More() {
		rawKey, err := decoder.Token()
		key, ok := rawKey.(string)
		if err != nil || !ok {
			return record{}, errors.New("record key rejected")
		}
		found, known := seen[key]
		if !known || found {
			return record{}, errors.New("record key inventory rejected")
		}
		seen[key] = true
		switch key {
		case "source":
			err = decoder.Decode(&result.Source)
		case "data":
			err = decoder.Decode(&result.Data)
		}
		if err != nil {
			return record{}, errors.New("record value rejected")
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || !seen["source"] || !seen["data"] {
		return record{}, errors.New("record object incomplete")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return record{}, errors.New("record trailing data rejected")
	}
	return result, nil
}

func classify(source string, raw []byte, result *Privacy) {
	normalized := normalize(raw)
	defer clear(normalized)
	if source == "ANDROID_LOGCAT" {
		normalized = normalizeKnownAndroidFrameworkNoise(normalized)
	}
	classifyNormalized(normalized, result)
	classifyEncodedRepresentations(normalized, result)
}

func classifyNormalized(normalized []byte, result *Privacy) {
	lower := bytes.ToLower(normalized)
	result.PayloadRetained = result.PayloadRetained || bytes.Contains(lower, []byte("phase17_payload_canary_"))
	result.DestinationRetained = result.DestinationRetained || bytes.Contains(lower, []byte("phase17_destination_canary_")) ||
		urlPattern.Match(normalized) || containsIPAddress(normalized)
	result.DNSNameRetained = result.DNSNameRetained || bytes.Contains(lower, []byte("phase17_dns_canary_")) || dnsCanaryPattern.Match(normalized)
	result.CredentialRetained = result.CredentialRetained || credentialPattern.Match(normalized) ||
		windowsOwnerPath.Match(normalized) || unixOwnerPath.Match(normalized)
	result.KeyRetained = result.KeyRetained || bytes.Contains(lower, []byte("phase17_key_canary_")) || keyPattern.Match(normalized)
	result.ProfileRetained = result.ProfileRetained || profilePattern.Match(normalized)
}

func classifyEncodedRepresentations(normalized []byte, result *Privacy) {
	if bytes.Contains(normalized, []byte{'%'}) {
		if decoded, err := url.PathUnescape(string(normalized)); err == nil && decoded != string(normalized) {
			decodedNormalized := normalize([]byte(decoded))
			classifyNormalized(decodedNormalized, result)
			clear(decodedNormalized)
		}
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding.Strict(), base64.RawStdEncoding.Strict(),
		base64.URLEncoding.Strict(), base64.RawURLEncoding.Strict(),
	}
	for _, candidate := range base64CandidatePattern.FindAll(normalized, -1) {
		if len(candidate) > 1<<20 {
			continue
		}
		for _, encoding := range encodings {
			decoded := make([]byte, encoding.DecodedLen(len(candidate)))
			count, err := encoding.Decode(decoded, candidate)
			if err != nil || count == 0 {
				clear(decoded)
				continue
			}
			decodedNormalized := normalize(decoded[:count])
			classifyNormalized(decodedNormalized, result)
			clear(decodedNormalized)
			clear(decoded)
		}
	}
}

func normalize(raw []byte) []byte {
	withoutTerminalControls := stripTerminalControls(raw)
	result := make([]byte, 0, len(withoutTerminalControls))
	for len(withoutTerminalControls) > 0 {
		r, size := utf8.DecodeRune(withoutTerminalControls)
		if r == utf8.RuneError && size == 1 {
			withoutTerminalControls = withoutTerminalControls[1:]
			continue
		}
		withoutTerminalControls = withoutTerminalControls[size:]
		if r == '\ufeff' || unicode.IsControl(r) {
			if r == '\n' || r == '\r' || r == '\t' {
				result = append(result, ' ')
			}
			continue
		}
		result = utf8.AppendRune(result, r)
	}
	return result
}

func stripTerminalControls(raw []byte) []byte {
	result := make([]byte, 0, len(raw))
	for index := 0; index < len(raw); {
		if raw[index] != 0x1b && raw[index] != 0x9b {
			result = append(result, raw[index])
			index++
			continue
		}
		if raw[index] == 0x9b {
			index++
			for index < len(raw) {
				value := raw[index]
				index++
				if value >= 0x40 && value <= 0x7e {
					break
				}
			}
			continue
		}
		index++
		if index >= len(raw) {
			continue
		}
		switch raw[index] {
		case '[':
			index++
			for index < len(raw) {
				value := raw[index]
				index++
				if value >= 0x40 && value <= 0x7e {
					break
				}
			}
		case ']', 'P', 'X', '^', '_':
			index++
			for index < len(raw) {
				if raw[index] == 0x07 {
					index++
					break
				}
				if raw[index] == 0x1b && index+1 < len(raw) && raw[index+1] == '\\' {
					index += 2
					break
				}
				index++
			}
		default:
			index++
		}
	}
	return result
}

func normalizeKnownAndroidFrameworkNoise(raw []byte) []byte {
	result := bytes.Clone(raw)
	normalizeKnownInstrumentationPackageReferences(result)
	for offset := 0; offset < len(result); {
		end := bytes.IndexByte(result[offset:], '\n')
		if end < 0 {
			end = len(result) - offset
		}
		line := result[offset : offset+end]
		if bytes.Contains(line, []byte("/FrameTracker(")) && bytes.Contains(line, []byte("CUJ=J<")) &&
			bytes.Contains(line, []byte("@org.kurdistanvpn.app.internal>")) {
			for index := 0; index+3 < len(line); index++ {
				if line[index] != ':' || line[index+1] != ':' {
					continue
				}
				digits := index + 2
				endDigits := digits
				for endDigits < len(line) && endDigits-digits < 3 && line[endDigits] >= '0' && line[endDigits] <= '9' {
					endDigits++
				}
				if endDigits > digits && endDigits < len(line) && line[endDigits] == '@' {
					line[index] = '-'
					line[index+1] = '-'
				}
			}
		}
		offset += end + 1
	}
	clear(raw)
	return result
}

func normalizeKnownInstrumentationPackageReferences(raw []byte) {
	packageName := []byte("org.kurdistanvpn.app.internal.test")
	for offset := 0; offset < len(raw); {
		relative := bytes.Index(raw[offset:], packageName)
		if relative < 0 {
			return
		}
		start := offset + relative
		end := start + len(packageName)
		beforeStart := max(0, start-256)
		afterEnd := min(len(raw), end+256)
		before := bytes.ToLower(raw[beforeStart:start])
		after := bytes.ToLower(raw[end:afterEnd])
		frameworkReference :=
			(bytes.HasSuffix(before, []byte("package [")) && bytes.HasPrefix(after, []byte("] reported as replaced"))) ||
				bytes.HasSuffix(before, []byte("instrumentation[")) ||
				(bytes.Contains(before, []byte("/data/app/")) && bytes.Contains(after, []byte("/base.apk")))
		if frameworkReference {
			for index := start; index < end; index++ {
				if raw[index] == '.' {
					raw[index] = '-'
				}
			}
		}
		offset = end
	}
}

func containsIPAddress(raw []byte) bool {
	for _, candidateRaw := range addressCandidatePattern.FindAll(raw, -1) {
		candidate := strings.Trim(string(candidateRaw), "[](){}<>,;\"'")
		if !strings.ContainsAny(candidate, ".:") {
			continue
		}
		if address, err := netip.ParseAddr(candidate); err == nil && address.IsValid() {
			return true
		}
	}
	return false
}

func containsSource(values map[string]bool, value string) bool {
	_, found := values[strings.TrimSpace(value)]
	return found && value == strings.TrimSpace(value)
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
