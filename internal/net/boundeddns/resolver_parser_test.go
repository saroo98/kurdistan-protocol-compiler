// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package boundeddns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestQueryUsesFixedSlabAndExactMaximumQuestion(t *testing.T) {
	var w workspace
	domain := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	copy(w.names[0].Data[:], domain)
	w.names[0].Data[len(domain)] = '.'
	w.names[0].Length = uint8(len(domain) + 1)
	query, id, err := w.buildQuery(dnsmessage.TypeAAAA)
	if err != nil || len(query) != 271 || cap(query) != 512 || &query[0] != &w.query[0] {
		t.Fatalf("query length=%d capacity=%d err=%v", len(query), cap(query), err)
	}
	if binary.BigEndian.Uint16(query[:2]) != id || query[2] != 1 || query[3] != 0 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		t.Fatal("query header changed")
	}
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil || h.Response || !h.RecursionDesired {
		t.Fatal("invalid query header")
	}
	q, err := p.Question()
	if err != nil || q.Name != w.names[0] || q.Type != dnsmessage.TypeAAAA || q.Class != dnsmessage.ClassINET {
		t.Fatal("query question changed")
	}
	if _, err := p.Question(); err != dnsmessage.ErrSectionDone {
		t.Fatal("extra query question")
	}
}

type testRR struct {
	name   string
	kind   dnsmessage.Type
	class  dnsmessage.Class
	data   []byte
	target string
}

func responseBytes(t testing.TB, q dnsmessage.Question, header dnsmessage.Header, answers, authorities, additional []testRR) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, header)
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(q); err != nil {
		t.Fatal(err)
	}
	for section, records := range [][]testRR{answers, authorities, additional} {
		var err error
		switch section {
		case 0:
			err = b.StartAnswers()
		case 1:
			err = b.StartAuthorities()
		case 2:
			err = b.StartAdditionals()
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, rr := range records {
			name := rr.name
			if name == "" {
				name = "example.test."
			}
			class := rr.class
			if class == 0 {
				class = dnsmessage.ClassINET
			}
			h := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Class: class}
			if rr.kind == dnsmessage.TypeCNAME && rr.target != "" {
				err = b.CNAMEResource(h, dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(rr.target)})
			} else {
				err = b.UnknownResource(h, dnsmessage.UnknownResource{Type: rr.kind, Data: rr.data})
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func parseFixture(t testing.TB, kind dnsmessage.Type, answers, authorities, additional []testRR) (*workspace, []byte) {
	t.Helper()
	w := new(workspace)
	w.names[0] = dnsmessage.MustNewName("example.test.")
	q := dnsmessage.Question{Name: w.names[0], Type: kind, Class: dnsmessage.ClassINET}
	return w, responseBytes(t, q, dnsmessage.Header{ID: 123, Response: true, RecursionAvailable: true, Authoritative: true}, answers, authorities, additional)
}

func TestResponseReturnsOnlyExactTerminalAnswerAddresses(t *testing.T) {
	w, msg := parseFixture(t, dnsmessage.TypeA, []testRR{
		{kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}},
		{kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}},
		{name: "unrelated.test.", kind: dnsmessage.TypeA, data: []byte{9, 9, 9, 9}},
	}, nil, []testRR{{kind: dnsmessage.TypeA, data: []byte{8, 8, 8, 8}}})
	tc, err := w.acceptResponse(msg, dnsmessage.TypeA, 123)
	if err != nil || tc || w.count != 1 || w.results[0] != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("terminal answer count=%d tc=%v err=%v", w.count, tc, err)
	}
}

func TestResponseRejectsSeventeenthDistinctAddress(t *testing.T) {
	for _, count := range []int{16, 17} {
		answers := make([]testRR, count)
		for i := range answers {
			answers[i] = testRR{kind: dnsmessage.TypeA, data: []byte{1, 2, 3, byte(i + 1)}}
		}
		w, msg := parseFixture(t, dnsmessage.TypeA, answers, nil, nil)
		_, err := w.acceptResponse(msg, dnsmessage.TypeA, 123)
		if count == 16 && (err != nil || w.count != 16) {
			t.Fatalf("sixteen count=%d err=%v", w.count, err)
		}
		if count == 17 && !errors.Is(err, ErrSizeLimit) {
			t.Fatalf("seventeenth err=%v", err)
		}
	}
}

func TestResponseIPv6SharesSixteenResultLimit(t *testing.T) {
	a := netip.MustParseAddr("2001:4860::1").As16()
	w, msg := parseFixture(t, dnsmessage.TypeAAAA, []testRR{{kind: dnsmessage.TypeAAAA, data: a[:]}}, nil, nil)
	_, err := w.acceptResponse(msg, dnsmessage.TypeAAAA, 123)
	if err != nil || w.count != 1 || w.results[0] != netip.AddrFrom16(a) {
		t.Fatalf("IPv6 count=%d err=%v", w.count, err)
	}
	for i := 0; i < 16; i++ {
		w.results[i] = netip.AddrFrom4([4]byte{1, 2, 3, byte(i + 1)})
	}
	w.count = 16
	if _, err = w.acceptResponse(msg, dnsmessage.TypeAAAA, 123); !errors.Is(err, ErrSizeLimit) {
		t.Fatalf("combined overflow=%v", err)
	}
}

func TestResponseCNAMEOrderingCyclesConflictsAndDepth(t *testing.T) {
	for _, tc := range []struct {
		name                             string
		links                            int
		cycle, conflict, addressConflict bool
		wantErr                          bool
	}{
		{name: "one", links: 1}, {name: "eight", links: 8}, {name: "nine", links: 9, wantErr: true},
		{name: "cycle", links: 2, cycle: true, wantErr: true}, {name: "conflict", links: 1, conflict: true, wantErr: true},
		{name: "address-conflict", links: 1, addressConflict: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := "example.test."
			records := make([]testRR, 0, tc.links+3)
			for i := 0; i < tc.links; i++ {
				target := fmt.Sprintf("alias%d.test.", i)
				if tc.cycle && i == tc.links-1 {
					target = "EXAMPLE.test."
				}
				records = append(records, testRR{name: current, kind: dnsmessage.TypeCNAME, target: target})
				current = target
			}
			records = append(records, testRR{name: strings.ToUpper(current), kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}})
			if tc.conflict {
				records = append(records, testRR{kind: dnsmessage.TypeCNAME, target: "different.test."})
			}
			if tc.addressConflict {
				records = append(records, testRR{kind: dnsmessage.TypeA, data: []byte{5, 6, 7, 8}})
			}
			for l, r := 0, len(records)-1; l < r; l, r = l+1, r-1 {
				records[l], records[r] = records[r], records[l]
			}
			w, msg := parseFixture(t, dnsmessage.TypeA, records, nil, nil)
			_, err := w.acceptResponse(msg, dnsmessage.TypeA, 123)
			if tc.wantErr {
				if err == nil {
					t.Fatal("invalid CNAME accepted")
				}
			} else if err != nil || w.count != 1 || w.results[0] != netip.MustParseAddr("1.2.3.4") {
				t.Fatalf("chain count=%d err=%v", w.count, err)
			}
		})
	}
}

func TestResponseCNAMEOnlyIsNotAuthoritativeEmptyFamily(t *testing.T) {
	w, msg := parseFixture(t, dnsmessage.TypeA, []testRR{{kind: dnsmessage.TypeCNAME, target: "alias.test."}}, nil, nil)
	if _, err := w.acceptResponse(msg, dnsmessage.TypeA, 123); !errors.Is(err, ErrNoData) {
		t.Fatalf("CNAME-only=%v", err)
	}
	w, msg = parseFixture(t, dnsmessage.TypeA, nil, nil, nil)
	if _, err := w.acceptResponse(msg, dnsmessage.TypeA, 123); err != nil || w.count != 0 {
		t.Fatalf("authoritative empty=%v count=%d", err, w.count)
	}
	msg[2] &= ^byte(4)
	if _, err := w.acceptResponse(msg, dnsmessage.TypeA, 123); err != nil {
		t.Fatalf("recursive empty=%v", err)
	}
}

func TestResponseRecursiveNODATAAndRelevantTerminalSOA(t *testing.T) {
	for _, tc := range []struct {
		name, zone                     string
		chain, ns, aa, badSOA, wantErr bool
	}{
		{name: "recursive-empty"},
		{name: "recursive-soa-ns", zone: "test.", ns: true},
		{name: "referral", ns: true, wantErr: true},
		{name: "aa-does-not-cure-referral", ns: true, aa: true, wantErr: true},
		{name: "unrelated-soa", zone: "other.test.", ns: true, wantErr: true},
		{name: "label-boundary", zone: "ample.test.", ns: true, wantErr: true},
		{name: "terminal-cname-zone", zone: "other.", chain: true},
		{name: "terminal-cname-root", zone: ".", chain: true},
		{name: "terminal-cname-unrelated", zone: "test.", chain: true, wantErr: true},
		{name: "bad-soa", zone: "test.", badSOA: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var answers, authority []testRR
			if tc.chain {
				answers = []testRR{{kind: dnsmessage.TypeCNAME, target: "alias.other."}}
			}
			if tc.zone != "" {
				size := 22
				if tc.badSOA {
					size = 21
				}
				authority = append(authority, testRR{name: tc.zone, kind: dnsmessage.TypeSOA, data: make([]byte, size)})
			}
			if tc.ns {
				authority = append(authority, testRR{name: "test.", kind: dnsmessage.TypeNS, data: []byte{0}})
			}
			w, msg := parseFixture(t, dnsmessage.TypeAAAA, answers, authority, nil)
			if !tc.aa {
				msg[2] &= ^byte(4)
			}
			_, err := w.acceptResponse(msg, dnsmessage.TypeAAAA, 123)
			if (err != nil) != tc.wantErr {
				t.Fatalf("NODATA classification err=%v", err)
			}
		})
	}
}

func TestResponseRejectsMalformedDeclaredSections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"counts", func(b []byte) []byte { binary.BigEndian.PutUint16(b[6:8], 65535); return b }},
		{"address-length", func(b []byte) []byte { binary.BigEndian.PutUint16(b[52:54], 3); return b }},
		{"oversized-rdata", func(b []byte) []byte { binary.BigEndian.PutUint16(b[52:54], 65535); return b }},
		{"truncated-body", func(b []byte) []byte { return b[:len(b)-1] }},
		{"reserved-owner", func(b []byte) []byte { b[30] = 0x80; return b }},
		{"pointer-loop", func(b []byte) []byte { b[30] = 0xc0; b[31] = 30; return b }},
		{"pointer-outside", func(b []byte) []byte { b[30] = 0xff; b[31] = 0xff; return b }},
		{"wrong-class", func(b []byte) []byte { binary.BigEndian.PutUint16(b[46:48], 3); return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, msg := parseFixture(t, dnsmessage.TypeA, []testRR{{kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}}}, nil, nil)
			if _, err := w.acceptResponse(tc.mutate(msg), dnsmessage.TypeA, 123); err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
	for _, section := range []int{1, 2} {
		records := []testRR{{kind: dnsmessage.TypeAAAA, data: []byte{1}}}
		var authority, additional []testRR
		if section == 1 {
			authority = records
		} else {
			additional = records
		}
		w, msg := parseFixture(t, dnsmessage.TypeA, nil, authority, additional)
		if _, err := w.acceptResponse(msg, dnsmessage.TypeA, 123); err == nil {
			t.Fatalf("malformed section %d accepted", section)
		}
	}
}

func TestResponseChecksIdentityBeforeAcceptingTruncation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"query-bit", func(b []byte) { b[2] &= 0x7f }},
		{"opcode", func(b []byte) { b[2] |= 8 }},
		{"id", func(b []byte) { b[1]++ }},
		{"question", func(b []byte) { b[13] = 'x' }},
		{"type", func(b []byte) { b[27] = 28 }},
		{"class", func(b []byte) { b[29] = 3 }},
		{"rcode", func(b []byte) { b[3] |= 2 }},
		{"nxdomain", func(b []byte) { b[3] |= 3 }},
		{"question-count", func(b []byte) { b[5] = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, msg := parseFixture(t, dnsmessage.TypeA, nil, nil, nil)
			msg[2] |= 2
			tc.mutate(msg)
			if truncated, err := w.acceptResponse(msg, dnsmessage.TypeA, 123); truncated || err == nil {
				t.Fatal("invalid TC identity accepted")
			}
		})
	}
}

func TestResponseUsesMaintainedCompressedCNAMEAndFullWireRRBound(t *testing.T) {
	w, msg := parseFixture(t, dnsmessage.TypeA, []testRR{
		{kind: dnsmessage.TypeCNAME, data: []byte{0xc0, 56}},
		{name: "alias.test.", kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}},
	}, nil, nil)
	if _, err := w.acceptResponse(msg, dnsmessage.TypeA, 123); err != nil || w.count != 1 {
		t.Fatalf("compressed CNAME count=%d err=%v", w.count, err)
	}
	additional := make([]testRR, 300)
	for i := range additional {
		additional[i] = testRR{name: ".", kind: 65000}
	}
	w, msg = parseFixture(t, dnsmessage.TypeA, []testRR{{kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}}}, nil, additional)
	if _, err := w.acceptResponse(msg, dnsmessage.TypeA, 123); err != nil || w.count != 1 {
		t.Fatalf("full wire RR count=%d err=%v", w.count, err)
	}
	// The maintained accessor validates names and declared extents, not exact
	// CNAME byte consumption or trailing-byte canonicality. Keep that boundary
	// explicit without copying or reaching into its private parser offsets.
	w, msg = parseFixture(t, dnsmessage.TypeA, []testRR{{kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}}}, nil, nil)
	msg = append(msg, 0xff)
	if _, err := w.acceptResponse(msg, dnsmessage.TypeA, 123); err != nil {
		t.Fatalf("unclaimed trailing canonicality check: %v", err)
	}
}

func TestResponseDoesNotMistakeExtendedErrorForNOERROR(t *testing.T) {
	w, msg := parseFixture(t, dnsmessage.TypeA, []testRR{{kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}}}, nil, []testRR{{name: ".", kind: dnsmessage.TypeOPT}})
	// Header RCODE is zero, but the OPT TTL's high byte extends it to 16.
	msg[63] = 1
	if _, err := w.acceptResponse(msg, dnsmessage.TypeA, 123); err == nil {
		t.Fatal("extended DNS error published answer")
	}
}

func TestParserDoesNotAllocatePerDeclaredRecord(t *testing.T) {
	additional := make([]testRR, 300)
	for i := range additional {
		additional[i] = testRR{name: ".", kind: 65000}
	}
	w, msg := parseFixture(t, dnsmessage.TypeA, []testRR{{kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}}}, nil, additional)
	var parseErr error
	allocs := testing.AllocsPerRun(100, func() { w.count = 0; _, parseErr = w.acceptResponse(msg, dnsmessage.TypeA, 123) })
	if parseErr != nil || allocs != 0 {
		t.Fatalf("valid incremental parser allocs=%f err=%v", allocs, parseErr)
	}
}
