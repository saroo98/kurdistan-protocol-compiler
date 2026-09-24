// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func testProductionIDV1(value string) []byte {
	return append([]byte{byte(len(value))}, []byte(value)...)
}

func testProductionPackageV1(value string) []byte {
	out := make([]byte, 2, 2+len(value))
	binary.BigEndian.PutUint16(out, uint16(len(value)))
	return append(out, []byte(value)...)
}

func testProductionAddressV1(family byte, value ...byte) []byte {
	return append([]byte{family}, value...)
}

func testProductionPrefixV1(family byte, value []byte, bits byte) []byte {
	out := testProductionAddressV1(family, value...)
	return append(out, bits)
}

func productionSettingsRowsV1(nondefault bool) [][]byte {
	if !nondefault {
		return [][]byte{
			{1, 0, 0},
			{1, 0, 0, 0, 0, 0, 3},
			{1, 1, 0, 0x05, 0xdc, 0, 0, 0, 0},
			{1, 0, 0, 0},
			{0, 0, 2, 0, 1, 0},
			{1, 1, 0, 3},
			{3, 3},
			{0x01, 0x2c, 0x01, 0x00, 0x00, 0x80, 0x00, 0x50},
			{0, 0, 0},
			{1, 2, 1},
			{0x2a, 0x38, 0x2a, 0x39, 4, 16, 0x01, 0x2c, 0, 32},
			{0, 30, 0, 1},
			{0, 1},
			{0},
			{0, 0, 0},
		}
	}
	row2 := []byte{3, 1, 1, 0, 1}
	row2 = append(row2, testProductionIDV1("strategy-kurd-tls13-tcp")...)
	row2 = append(row2, 10)
	row3 := []byte{4, 4}
	row3 = append(row3, testProductionAddressV1(6, 0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88)...)
	row3 = append(row3, 0x05, 0xdc, 1, 1)
	row3 = append(row3, testProductionIDV1("")...)
	row3 = append(row3, testProductionAddressV1(4, 8, 8, 4, 4)...)
	row4 := []byte{2, 0, 2}
	row4 = append(row4, testProductionPackageV1("a.a")...)
	row4 = append(row4, testProductionPackageV1("aa.a")...)
	row4 = append(row4, 1)
	row4 = append(row4, testProductionPrefixV1(4, []byte{10, 0, 0, 0}, 8)...)
	row6 := []byte{5, 2}
	row6 = append(row6, testProductionIDV1("probe-7")...)
	row6 = append(row6, 30)
	row9 := testProductionIDV1("-active")
	row9 = append(row9, 0, 2)
	row9 = append(row9, testProductionIDV1("z")...)
	row9 = append(row9, testProductionIDV1("aa")...)
	row15 := []byte{1, 0, 2}
	row15 = append(row15, testProductionIDV1("z")...)
	row15 = append(row15, testProductionIDV1("aa")...)
	return [][]byte{
		{3, 1, 1}, row2, row3, row4,
		{1, 0, 168, 1, 0, 1}, row6, {5, 4},
		{0x0e, 0x10, 0x10, 0x00, 0x08, 0x00, 0x02, 0x00}, row9,
		{2, 3, 2}, {0xff, 0xfe, 0xff, 0xff, 16, 64, 0x0e, 0x10, 0, 128},
		{1, 1, 1, 3}, {0, 0}, {1}, row15,
	}
}

func productionSettingsMessageV1(rows [][]byte) []byte {
	total := 12
	for _, row := range rows {
		total += len(row)
	}
	out := make([]byte, 12, total)
	copy(out[:4], "KPS1")
	out[4] = 1
	binary.BigEndian.PutUint32(out[8:12], uint32(total))
	for _, row := range rows {
		out = append(out, row...)
	}
	return out
}

func productionDefaultSettingsBytesV1() []byte {
	return productionSettingsMessageV1(productionSettingsRowsV1(false))
}

func TestProductionSettingsV1DefaultGoldenAndAllRows(t *testing.T) {
	const defaultHex = "4b50533101000000000000510100000100000000000301010005dc0000000001000000000002000100010100030303012c0100008000500000000102012a382a390410012c0020001e0001000100000000"
	if got := hex.EncodeToString(productionDefaultSettingsBytesV1()); got != defaultHex {
		t.Fatalf("independent default fixture changed:\n got %s\nwant %s", got, defaultHex)
	}
	for index, row := range productionSettingsRowsV1(true) {
		rows := productionSettingsRowsV1(false)
		rows[index] = row
		if _, status := decodeProductionSettingsV1(productionSettingsMessageV1(rows)); status != productionSuccessV1 {
			t.Fatalf("nondefault row %d rejected: %d", index+1, status)
		}
	}
	input := productionSettingsMessageV1(productionSettingsRowsV1(true))
	before := append([]byte(nil), input...)
	settings, status := decodeProductionSettingsV1(input)
	if status != productionSuccessV1 {
		t.Fatalf("all-nondefault decode: %d", status)
	}
	if !bytes.Equal(before, input) {
		t.Fatal("decoder mutated input")
	}
	if settings.selection != 3 || string(settings.manualStrategy) != "strategy-kurd-tls13-tcp" || settings.reconnectMaximum != 10 || settings.ipMode != 4 || settings.dnsMode != 4 || settings.customPrimary.family != 6 || settings.customSecondary.family != 4 || settings.mtu != 1500 || !settings.metered || settings.routingMode != 2 || settings.packageCount != 2 || string(settings.packages[0]) != "a.a" || settings.excludedCount != 1 || settings.probeMethod != 5 || string(settings.probeTarget) != "probe-7" || settings.expertIdleSeconds != 3600 || settings.tcpLimit != 4096 || settings.udpLimit != 2048 || settings.memoryMiB != 512 || settings.tunnelMode != 2 || settings.proxyMemoryMiB != 128 {
		t.Fatalf("native fields not retained exactly: %+v", settings)
	}
	manualOffset := bytes.Index(input, []byte("strategy-kurd-tls13-tcp"))
	if manualOffset < 0 || &settings.manualStrategy[0] != &input[manualOffset] {
		t.Fatal("protected manual selector was copied")
	}
	packageOffset := bytes.Index(input, []byte("a.a"))
	if packageOffset < 0 || &settings.packages[0][0] != &input[packageOffset] {
		t.Fatal("package was copied")
	}
}

func TestProductionSettingsV1RejectsEveryTruncationTrailingAndHeaderViolation(t *testing.T) {
	valid := productionDefaultSettingsBytesV1()
	for length := 0; length < len(valid); length++ {
		got, status := decodeProductionSettingsV1(valid[:length])
		if status != productionInvalidRequestV1 || !reflect.DeepEqual(got, productionSettingsV1{}) {
			t.Fatalf("truncation %d: status=%d value=%+v", length, status, got)
		}
	}
	for name, mutate := range map[string]func([]byte){
		"magic":     func(v []byte) { v[0] ^= 1 },
		"version":   func(v []byte) { v[4] = 2 },
		"reserved5": func(v []byte) { v[5] = 1 },
		"reserved6": func(v []byte) { v[6] = 1 },
		"total":     func(v []byte) { binary.BigEndian.PutUint32(v[8:12], uint32(len(v)-1)) },
	} {
		t.Run(name, func(t *testing.T) {
			input := append([]byte(nil), valid...)
			mutate(input)
			if got, status := decodeProductionSettingsV1(input); status != productionInvalidRequestV1 || !reflect.DeepEqual(got, productionSettingsV1{}) {
				t.Fatalf("status=%d value=%+v", status, got)
			}
		})
	}
	trailing := append(append([]byte(nil), valid...), 0)
	binary.BigEndian.PutUint32(trailing[8:12], uint32(len(trailing)))
	if got, status := decodeProductionSettingsV1(trailing); status != productionInvalidRequestV1 || !reflect.DeepEqual(got, productionSettingsV1{}) {
		t.Fatalf("trailing: status=%d value=%+v", status, got)
	}
	over := make([]byte, productionSettingsMaxBytesV1+1)
	if got, status := decodeProductionSettingsV1(over); status != productionSizeLimitV1 || !reflect.DeepEqual(got, productionSettingsV1{}) {
		t.Fatalf("oversize: status=%d value=%+v", status, got)
	}
}

func TestProductionSettingsV1RejectsIndependentInvalidityInEveryRow(t *testing.T) {
	tests := []struct {
		name string
		row  int
		edit func([]byte) []byte
	}{
		{"row1-theme", 0, func(v []byte) []byte { v[0] = 0; return v }},
		{"row2-selection", 1, func(v []byte) []byte { v[0] = 0; return v }},
		{"row3-dns-presence", 2, func(v []byte) []byte { v[1] = 4; return v }},
		{"row4-empty-include", 3, func(v []byte) []byte { v[0] = 2; return v }},
		{"row5-interval", 4, func(v []byte) []byte { v[1], v[2] = 0, 0; return v }},
		{"row6-method", 5, func(v []byte) []byte { v[0] = 0; return v }},
		{"row7-level", 6, func(v []byte) []byte { v[0] = 0; return v }},
		{"row8-tcp", 7, func(v []byte) []byte { v[2], v[3] = 0, 15; return v }},
		{"row9-local-id", 8, func(v []byte) []byte { return []byte{1, 'A', 0, 0} }},
		{"row10-mode", 9, func(v []byte) []byte { v[0] = 0; return v }},
		{"row11-ports", 10, func(v []byte) []byte { copy(v[2:4], v[0:2]); return v }},
		{"row12-authenticator", 11, func(v []byte) []byte { v[2], v[3] = 1, 0; return v }},
		{"row13-bool", 12, func(v []byte) []byte { v[0] = 2; return v }},
		{"row14-bool", 13, func(v []byte) []byte { v[0] = 2; return v }},
		{"row15-bool", 14, func(v []byte) []byte { v[0] = 2; return v }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rows := productionSettingsRowsV1(false)
			rows[test.row] = test.edit(append([]byte(nil), rows[test.row]...))
			if got, status := decodeProductionSettingsV1(productionSettingsMessageV1(rows)); status != productionInvalidRequestV1 || !reflect.DeepEqual(got, productionSettingsV1{}) {
				t.Fatalf("status=%d value=%+v", status, got)
			}
		})
	}
}

func testProductionRoutingRowV1(mode byte, packages []string, prefixes [][]byte) []byte {
	row := []byte{mode, byte(len(packages) >> 8), byte(len(packages))}
	for _, value := range packages {
		row = append(row, testProductionPackageV1(value)...)
	}
	row = append(row, byte(len(prefixes)))
	for _, value := range prefixes {
		row = append(row, value...)
	}
	return row
}

func TestProductionSettingsV1CanonicalPackagesAndPrefixes(t *testing.T) {
	longPackage := "a." + strings.Repeat("a", 253)
	valid256 := make([]string, 256)
	for i := range valid256 {
		valid256[i] = fmt.Sprintf("a.a%03d", i)
	}
	tests := []struct {
		name   string
		mode   byte
		values []string
		prefix [][]byte
		status productionStatusV1
	}{
		{"include-one", 2, []string{"a.a"}, nil, productionSuccessV1},
		{"include-empty", 2, nil, nil, productionInvalidRequestV1},
		{"all-with-package", 1, []string{"a.a"}, nil, productionInvalidRequestV1},
		{"duplicate", 2, []string{"a.a", "a.a"}, nil, productionInvalidRequestV1},
		{"encoded-order", 2, []string{"aa.a", "a.a"}, nil, productionInvalidRequestV1},
		{"invalid-utf8", 2, []string{string([]byte{'a', '.', 0xff})}, nil, productionInvalidRequestV1},
		{"unicode", 2, []string{"å.a"}, nil, productionInvalidRequestV1},
		{"package-255", 2, []string{longPackage}, nil, productionSuccessV1},
		{"package-256", 2, []string{longPackage + "a"}, nil, productionSizeLimitV1},
		{"packages-256", 2, valid256, nil, productionSuccessV1},
		{"packages-257", 2, append(valid256, "a.z999"), nil, productionSizeLimitV1},
		{"host-bits", 3, nil, [][]byte{testProductionPrefixV1(4, []byte{10, 1, 0, 0}, 8)}, productionInvalidRequestV1},
		{"mapped-v6", 3, nil, [][]byte{testProductionPrefixV1(6, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 0}, 120)}, productionInvalidRequestV1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rows := productionSettingsRowsV1(false)
			rows[3] = testProductionRoutingRowV1(test.mode, test.values, test.prefix)
			if _, status := decodeProductionSettingsV1(productionSettingsMessageV1(rows)); status != test.status {
				t.Fatalf("status=%d want=%d", status, test.status)
			}
		})
	}
	valid64 := make([][]byte, 64)
	for i := range valid64 {
		valid64[i] = testProductionPrefixV1(4, []byte{10, 0, byte(i), 0}, 24)
	}
	rows := productionSettingsRowsV1(false)
	rows[3] = testProductionRoutingRowV1(3, nil, valid64)
	if _, status := decodeProductionSettingsV1(productionSettingsMessageV1(rows)); status != productionSuccessV1 {
		t.Fatalf("64 exclusions: %d", status)
	}
	rows = productionSettingsRowsV1(false)
	rows[3] = []byte{3, 0, 0, 65}
	if _, status := decodeProductionSettingsV1(productionSettingsMessageV1(rows)); status != productionSizeLimitV1 {
		t.Fatalf("65 exclusions: %d", status)
	}
}

func testProductionLocalSetRowV1(active string, favorites []string) []byte {
	row := testProductionIDV1(active)
	row = append(row, byte(len(favorites)>>8), byte(len(favorites)))
	for _, value := range favorites {
		row = append(row, testProductionIDV1(value)...)
	}
	return row
}

func testProductionTrustRowV1(enabled byte, values []string) []byte {
	row := []byte{enabled, byte(len(values) >> 8), byte(len(values))}
	for _, value := range values {
		row = append(row, testProductionIDV1(value)...)
	}
	return row
}

func TestProductionSettingsV1CanonicalIdentifiersAndUnionBounds(t *testing.T) {
	favorites := make([]string, 1024)
	for i := range favorites {
		favorites[i] = fmt.Sprintf("id-%04d", i)
	}
	trust := make([]string, 256)
	for i := range trust {
		trust[i] = fmt.Sprintf("rule-%03d", i)
	}
	tests := []struct {
		name   string
		row    int
		value  []byte
		status productionStatusV1
	}{
		{"local-leading-hyphen", 8, testProductionLocalSetRowV1("-a", []string{"z", "aa"}), productionSuccessV1},
		{"local-order-z-before-aa", 8, testProductionLocalSetRowV1("", []string{"z", "aa"}), productionSuccessV1},
		{"local-wrong-order", 8, testProductionLocalSetRowV1("", []string{"aa", "z"}), productionInvalidRequestV1},
		{"favorite-union-1024", 8, testProductionLocalSetRowV1(favorites[0], favorites), productionSuccessV1},
		{"favorite-union-1025", 8, testProductionLocalSetRowV1("different", favorites), productionSizeLimitV1},
		{"catalog-leading-hyphen", 14, testProductionTrustRowV1(1, []string{"-a"}), productionInvalidRequestV1},
		{"trust-order-z-before-aa", 14, testProductionTrustRowV1(1, []string{"z", "aa"}), productionSuccessV1},
		{"trust-wrong-order", 14, testProductionTrustRowV1(1, []string{"aa", "z"}), productionInvalidRequestV1},
		{"trust-256", 14, testProductionTrustRowV1(1, trust), productionSuccessV1},
		{"trust-257", 14, testProductionTrustRowV1(1, append(trust, "rule-999")), productionSizeLimitV1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rows := productionSettingsRowsV1(false)
			rows[test.row] = test.value
			if _, status := decodeProductionSettingsV1(productionSettingsMessageV1(rows)); status != test.status {
				t.Fatalf("status=%d want=%d", status, test.status)
			}
		})
	}
}

func TestProductionSettingsV1NotificationRowsRemainIndependent(t *testing.T) {
	rows := productionSettingsRowsV1(false)
	rows[2][6], rows[4][4], rows[12][0], rows[12][1] = 1, 0, 1, 0
	if _, status := decodeProductionSettingsV1(productionSettingsMessageV1(rows)); status != productionSuccessV1 {
		t.Fatalf("independent notification values rejected: %d", status)
	}
}

func FuzzProductionSettingsV1(f *testing.F) {
	f.Add(productionDefaultSettingsBytesV1())
	f.Add([]byte("KPS1"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = decodeProductionSettingsV1(input)
	})
}
