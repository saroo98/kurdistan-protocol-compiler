// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package scannera

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"testing"
)

func TestScanAcceptsCompleteCategoricalStream(t *testing.T) {
	raw := scannerStream(
		[2]string{"ANDROID_LOGCAT", "VPN lifecycle category only"},
		[2]string{"REMOTE_JOURNAL", "relay health category only"},
	)
	receipt := Scan(bytes.NewReader(raw), int64(len(raw)))
	if receipt.Result != "PASS" || receipt.BytesConsumed != uint64(len(raw)) || receipt.RecordsConsumed != 2 ||
		receipt.Truncated || receipt.ParseFailure || receipt.CoverageGap || receipt.Privacy != (Privacy{}) {
		t.Fatalf("receipt=%+v", receipt)
	}
}

func TestScanClassifiesEveryPrivacyPredicate(t *testing.T) {
	cases := map[string]struct {
		value string
		flag  func(Privacy) bool
	}{
		"payload":     {"PHASE17_PAYLOAD_CANARY_deadbeef", func(value Privacy) bool { return value.PayloadRetained }},
		"destination": {"connected to https://198.51.100.7/check", func(value Privacy) bool { return value.DestinationRetained }},
		"dns":         {"lookup phase17-probe.invalid", func(value Privacy) bool { return value.DNSNameRetained }},
		"credential":  {"Authorization: Bearer secret", func(value Privacy) bool { return value.CredentialRetained }},
		"key":         {"-----BEGIN PRIVATE KEY-----", func(value Privacy) bool { return value.KeyRetained }},
		"profile":     {"kurd://private-profile", func(value Privacy) bool { return value.ProfileRetained }},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			raw := scannerStream([2]string{"ANDROID_LOGCAT", test.value}, [2]string{"REMOTE_JOURNAL", "safe"})
			receipt := Scan(bytes.NewReader(raw), int64(len(raw)))
			if receipt.Result != "FAIL" || !test.flag(receipt.Privacy) {
				t.Fatalf("receipt=%+v", receipt)
			}
		})
	}
}

func TestScanRejectsAdversarialEncodingAndAddressVariants(t *testing.T) {
	cases := map[string][]byte{
		"ANSI split credential": []byte("pass\x1b[31mword=secret"),
		"NUL split credential":  []byte("pass\x00word=secret"),
		"invalid UTF8 split":    {0x70, 0x61, 0x73, 0x73, 0xff, 0x77, 0x6f, 0x72, 0x64, 0x3d, 0x78},
		"percent credential":    []byte("%70%61%73%73%77%6f%72%64%3d%73%65%63%72%65%74"),
		"base64 credential":     []byte("cGFzc3dvcmQ9c2VjcmV0"),
		"mapped IPv6":           []byte("::ffff:192.0.2.7"),
		"zoned IPv6":            []byte("fe80::1%wlan0"),
		"owner Windows path":    []byte(`C:\Users\Owner\private`),
		"owner Unix path":       []byte(`/home/owner/private`),
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			raw := scannerByteStream([2]any{"ANDROID_LOGCAT", payload}, [2]any{"REMOTE_JOURNAL", []byte("safe")})
			receipt := Scan(bytes.NewReader(raw), int64(len(raw)))
			if receipt.Result != "FAIL" || receipt.Privacy == (Privacy{}) {
				t.Fatalf("receipt=%+v", receipt)
			}
		})
	}
}

func TestScanFindsCanaryAcrossOneByteReaderChunks(t *testing.T) {
	raw := scannerStream([2]string{"ANDROID_LOGCAT", "password=secret"}, [2]string{"REMOTE_JOURNAL", "safe"})
	receipt := Scan(&oneByteReader{raw: raw}, int64(len(raw)))
	if receipt.Result != "FAIL" || !receipt.Privacy.CredentialRetained || receipt.Truncated || receipt.ParseFailure {
		t.Fatalf("receipt=%+v", receipt)
	}
}

func TestScanAcceptsKnownAndroidFrameworkAddressLookingNoise(t *testing.T) {
	const frameworkLine = "W/FrameTracker(23097): Missed SF frame:JANK_COMPOSER, 140916, 49415893, CUJ=J<IME_INSETS_SHOW_ANIMATION::0@1@org.kurdistanvpn.app.internal>"
	raw := scannerStream([2]string{"ANDROID_LOGCAT", frameworkLine}, [2]string{"REMOTE_JOURNAL", "safe"})
	receipt := Scan(bytes.NewReader(raw), int64(len(raw)))
	if receipt.Result != "PASS" || receipt.Privacy != (Privacy{}) {
		t.Fatalf("receipt=%+v", receipt)
	}
}

func TestScanAcceptsKnownAndroidInstrumentationPackageNoiseButStillDetectsDNSUse(t *testing.T) {
	frameworkLines := []string{
		"D/ActivityThread(23097): Package [org.kurdistanvpn.app.internal.test] reported as REPLACED, but missing application info. Assuming REMOVED.",
		"W/ActivityThread(23097): Package uses different ABI(s) than its instrumentation: package[org.kurdistanvpn.app.internal]: x86_64, null instrumentation[org.kurdistanvpn.app.internal.test]: null, null",
		"D/nativeloader(23097): Configuring clns-9 for other apk /data/app/random/org.kurdistanvpn.app.internal.test-random/base.apk",
		"W/pn.app.internal(23097): ClassLoaderContext classpath size mismatch at /data/app/random/org.kurdistanvpn.app.internal.test-random/base.apk",
	}
	for _, frameworkLine := range frameworkLines {
		raw := scannerStream([2]string{"ANDROID_LOGCAT", frameworkLine}, [2]string{"REMOTE_JOURNAL", "safe"})
		receipt := Scan(bytes.NewReader(raw), int64(len(raw)))
		if receipt.Result != "PASS" || receipt.Privacy != (Privacy{}) {
			t.Fatalf("framework receipt=%+v", receipt)
		}
	}

	raw := scannerStream(
		[2]string{"ANDROID_LOGCAT", "application resolved DNS name org.kurdistanvpn.app.internal.test"},
		[2]string{"REMOTE_JOURNAL", "safe"},
	)
	receipt := Scan(bytes.NewReader(raw), int64(len(raw)))
	if receipt.Result != "FAIL" || !receipt.Privacy.DNSNameRetained {
		t.Fatalf("application receipt=%+v", receipt)
	}
}

func TestScanFailsClosedForMalformedTruncatedAndCoverageGap(t *testing.T) {
	malformed := []byte("not-json\n")
	if receipt := Scan(bytes.NewReader(malformed), int64(len(malformed))); receipt.Result != "FAIL" || !receipt.ParseFailure {
		t.Fatalf("malformed receipt=%+v", receipt)
	}
	complete := scannerStream([2]string{"ANDROID_LOGCAT", "safe"}, [2]string{"REMOTE_JOURNAL", "safe"})
	if receipt := Scan(bytes.NewReader(complete), int64(len(complete)-1)); receipt.Result != "FAIL" || !receipt.Truncated {
		t.Fatalf("truncated receipt=%+v", receipt)
	}
	gap := scannerStream([2]string{"ANDROID_LOGCAT", "safe"})
	if receipt := Scan(bytes.NewReader(gap), int64(len(gap))); receipt.Result != "FAIL" || !receipt.CoverageGap {
		t.Fatalf("gap receipt=%+v", receipt)
	}
	missingFinalNewline := bytes.TrimSuffix(complete, []byte("\n"))
	if receipt := Scan(bytes.NewReader(missingFinalNewline), int64(len(missingFinalNewline))); receipt.Result != "FAIL" || !receipt.ParseFailure {
		t.Fatalf("missing-final-newline receipt=%+v", receipt)
	}
	duplicateKey := []byte(`{"source":"ANDROID_LOGCAT","source":"REMOTE_JOURNAL","data":"c2FmZQ=="}` + "\n")
	if receipt := Scan(bytes.NewReader(duplicateKey), int64(len(duplicateKey))); receipt.Result != "FAIL" || !receipt.ParseFailure {
		t.Fatalf("duplicate-key receipt=%+v", receipt)
	}
	crlf := bytes.ReplaceAll(complete, []byte("\n"), []byte("\r\n"))
	if receipt := Scan(bytes.NewReader(crlf), int64(len(crlf))); receipt.Result != "PASS" {
		t.Fatalf("CRLF receipt=%+v", receipt)
	}
	firstLF := bytes.IndexByte(complete, '\n')
	mixed := append(bytes.Clone(complete[:firstLF]), '\r', '\n')
	mixed = append(mixed, complete[firstLF+1:]...)
	if receipt := Scan(bytes.NewReader(mixed), int64(len(mixed))); receipt.Result != "PASS" {
		t.Fatalf("mixed-ending receipt=%+v", receipt)
	}
}

func TestScanAcceptsBoundedVeryLongCategoricalRecord(t *testing.T) {
	payload := bytes.Repeat([]byte("safe "), 200_000)
	raw := scannerByteStream([2]any{"ANDROID_LOGCAT", payload}, [2]any{"REMOTE_JOURNAL", []byte("safe")})
	receipt := Scan(bytes.NewReader(raw), int64(len(raw)))
	if receipt.Result != "PASS" || receipt.BytesConsumed != uint64(len(raw)) || receipt.RecordsConsumed != 2 {
		t.Fatalf("receipt=%+v", receipt)
	}
}

func scannerStream(records ...[2]string) []byte {
	var output bytes.Buffer
	for _, record := range records {
		fmt.Fprintf(&output, `{"source":%q,"data":%q}`+"\n", record[0], base64.StdEncoding.EncodeToString([]byte(record[1])))
	}
	return output.Bytes()
}

func scannerByteStream(records ...[2]any) []byte {
	var output bytes.Buffer
	for _, record := range records {
		fmt.Fprintf(&output, `{"source":%q,"data":%q}`+"\n", record[0].(string), base64.StdEncoding.EncodeToString(record[1].([]byte)))
	}
	return output.Bytes()
}

type oneByteReader struct {
	raw []byte
}

func (reader *oneByteReader) Read(output []byte) (int, error) {
	if len(reader.raw) == 0 {
		return 0, io.EOF
	}
	output[0] = reader.raw[0]
	reader.raw = reader.raw[1:]
	return 1, nil
}
