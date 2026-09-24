// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestMaintenanceHTTPStrictResponseAndFixedBody(t *testing.T) {
	cases := []struct {
		name, wire string
		cap        int
		want       MaintenanceResultV1
		body       string
	}{
		{"exact", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", 3, MaintenanceSuccess, "abc"},
		{"eof", "HTTP/1.0 200 OK\r\n\r\nabc", 3, MaintenanceSuccess, "abc"},
		{"chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n", 3, MaintenanceSuccess, "abc"},
		{"overflow", "HTTP/1.0 200 OK\r\n\r\nabcd", 3, MaintenanceSizeLimit, ""},
		{"length", "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n", 3, MaintenanceSizeLimit, ""},
		{"short", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab", 3, MaintenanceFetchRejected, ""},
		{"empty", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 3, MaintenanceFetchRejected, ""},
		{"badchunk", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nz\r\nabc", 3, MaintenanceFetchRejected, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dst := make([]byte, c.cap)
			closed := false
			n, result := maintenanceReadHTTPV1(strings.NewReader(c.wire), &http.Request{Method: "GET"}, dst, func() { closed = true })
			if result != c.want || string(dst[:n]) != c.body || !closed {
				t.Fatalf("n=%d result=%d closed=%t", n, result, closed)
			}
			if result != MaintenanceSuccess && !bytes.Equal(dst, make([]byte, len(dst))) {
				t.Fatal("failure retained body")
			}
		})
	}
}
func TestMaintenanceHTTPStatusMIMEEncodingAndHeaderCap(t *testing.T) {
	for _, status := range []int{100, 103, 201, 204, 301, 302, 304, 400, 500} {
		wire := fmt.Sprintf("HTTP/1.1 %d X\r\nContent-Length: 1\r\n\r\nx", status)
		_, r := maintenanceReadHTTPV1(strings.NewReader(wire), &http.Request{Method: "GET"}, make([]byte, 3), func() {})
		if r != MaintenanceFetchRejected {
			t.Fatalf("status %d: %d", status, r)
		}
	}
	for _, h := range []string{"Content-Type: application/octet-stream; x=y\r\n", "Content-Type: text/plain\r\n", "Content-Type: application/octet-stream\r\nContent-Type: application/octet-stream\r\n", "Content-Encoding: gzip\r\n", "Content-Encoding: identity\r\nContent-Encoding: identity\r\n"} {
		_, r := maintenanceReadHTTPV1(strings.NewReader("HTTP/1.1 200 OK\r\n"+h+"Content-Length: 1\r\n\r\nx"), &http.Request{Method: "GET"}, make([]byte, 3), func() {})
		if r != MaintenanceFetchRejected {
			t.Fatal(r)
		}
	}
	for _, size := range []int{16384, 16385} {
		prefix := "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX: "
		wire := prefix + strings.Repeat("a", size-len(prefix)-4) + "\r\n\r\nabc"
		n, r := maintenanceReadHTTPV1(strings.NewReader(wire), &http.Request{Method: "GET"}, make([]byte, 3), func() {})
		if size == 16384 && (r != MaintenanceSuccess || n != 3) || size == 16385 && r != MaintenanceFetchRejected {
			t.Fatalf("header %d n=%d result=%d", size, n, r)
		}
	}
}
func TestMaintenanceHTTPRequestExactAndCredentialFree(t *testing.T) {
	var wire bytes.Buffer
	if r := maintenanceWriteHTTPV1(&wire, "https://example.com:8443/a%2Fb?q=x%2Fy"); r != MaintenanceSuccess {
		t.Fatal(r)
	}
	got := wire.String()
	for _, s := range []string{"GET /a%2Fb?q=x%2Fy HTTP/1.1\r\n", "Host: example.com:8443\r\n", "Accept: application/octet-stream\r\n", "Accept-Encoding: identity\r\n", "Connection: close\r\n"} {
		if !strings.Contains(got, s) {
			t.Fatal("missing request field")
		}
	}
	for _, s := range []string{"User-Agent:", "Authorization:", "Cookie:", "Referer:"} {
		if strings.Contains(got, s) {
			t.Fatal("unexpected request field")
		}
	}
}

var _ io.Reader = (*strings.Reader)(nil)

func TestMaintenanceHTTPPrefetchedBodyIsPreservedAndTrailersBounded(t *testing.T) {
	body := strings.Repeat("b", 65536)
	wire := "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Encoding: identity\r\nContent-Length: 65536\r\n\r\n" + body
	dst := make([]byte, len(body))
	n, r := maintenanceReadHTTPV1(strings.NewReader(wire), &http.Request{Method: "GET"}, dst, func() {})
	if r != MaintenanceSuccess || n != len(body) || string(dst) != body {
		t.Fatal("header limiter truncated body", n, r)
	}
	for _, trailer := range []string{"X-Trailer: yes\r\n", "X-Trailer: " + strings.Repeat("a", 4096) + "\r\n"} {
		wire := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n\r\n3\r\nabc\r\n0\r\n" + trailer + "\r\n"
		_, r := maintenanceReadHTTPV1(strings.NewReader(wire), &http.Request{Method: "GET"}, make([]byte, 3), func() {})
		if len(trailer) < 4096 && r != MaintenanceSuccess || len(trailer) > 4096 && r != MaintenanceFetchRejected {
			t.Fatal(r)
		}
	}
}

type maintenanceCloseOrderReader struct {
	header             *strings.Reader
	closed             bool
	drainedBeforeClose bool
}

func (r *maintenanceCloseOrderReader) Read(dst []byte) (int, error) {
	if r.header.Len() > 0 {
		return r.header.Read(dst)
	}
	if !r.closed {
		r.drainedBeforeClose = true
	}
	return 0, io.EOF
}
func TestMaintenanceHTTPRejectClosesRawBeforeBodyDrain(t *testing.T) {
	r := &maintenanceCloseOrderReader{header: strings.NewReader("HTTP/1.1 302 Found\r\nContent-Length: 5\r\n\r\n")}
	_, result := maintenanceReadHTTPV1(r, &http.Request{Method: "GET"}, make([]byte, 3), func() { r.closed = true })
	if result != MaintenanceFetchRejected || r.drainedBeforeClose || !r.closed {
		t.Fatal("unsafe rejected body cleanup")
	}
}
func BenchmarkMaintenanceHTTPBoundary(b *testing.B) {
	prefix := "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX: "
	wire := prefix + strings.Repeat("a", 16384-len(prefix)-4) + "\r\n\r\nabc"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var body [3]byte
		n, r := maintenanceReadHTTPV1(strings.NewReader(wire), &http.Request{Method: "GET"}, body[:], func() {})
		if n != 3 || r != MaintenanceSuccess {
			b.Fatal(n, r)
		}
	}
}
