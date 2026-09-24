// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package boundeddns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type localDNS struct {
	endpoint    netip.AddrPort
	udp         *net.UDPConn
	tcp         *net.TCPListener
	wg          sync.WaitGroup
	mu          sync.Mutex
	connections []*net.TCPConn
	closed      bool
}

func newLocalDNS(t testing.TB, udpReply, tcpReply func([]byte) [][]byte) *localDNS {
	t.Helper()
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := tcp.Addr().(*net.TCPAddr).AddrPort()
	udp, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(endpoint))
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	s := &localDNS{endpoint: endpoint, udp: udp, tcp: tcp}
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		var buf [512]byte
		for {
			n, peer, err := udp.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				return
			}
			if udpReply != nil {
				for _, reply := range udpReply(buf[:n]) {
					_, _ = udp.WriteToUDPAddrPort(reply, peer)
				}
			}
		}
	}()
	go func() {
		defer s.wg.Done()
		for {
			conn, err := tcp.AcceptTCP()
			if err != nil {
				return
			}
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				_ = conn.Close()
				return
			}
			s.connections = append(s.connections, conn)
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer conn.Close()
				var prefix [2]byte
				if _, err := io.ReadFull(conn, prefix[:]); err != nil {
					return
				}
				query := make([]byte, int(binary.BigEndian.Uint16(prefix[:])))
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				if tcpReply != nil {
					for _, part := range tcpReply(query) {
						if _, err := conn.Write(part); err != nil {
							return
						}
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		s.mu.Lock()
		s.closed = true
		_ = s.tcp.Close()
		_ = s.udp.Close()
		for _, c := range s.connections {
			_ = c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}

func ownerFor(t testing.TB, endpoints ...netip.AddrPort) *testOwner {
	t.Helper()
	check := func(ctx context.Context, s netip.AddrPort) error {
		found := false
		for _, allowed := range endpoints {
			if s == allowed {
				found = true
			}
		}
		deadline, ok := ctx.Deadline()
		if !found || !ok || time.Until(deadline) > time.Second {
			t.Errorf("unexpected endpoint or unbounded numeric dial")
			return errors.New("test owner refused")
		}
		return nil
	}
	return &testOwner{
		udp: func(ctx context.Context, s netip.AddrPort) (*net.UDPConn, error) {
			if err := check(ctx, s); err != nil {
				return nil, err
			}
			return new(net.Dialer).DialUDP(ctx, "udp4", netip.AddrPort{}, s)
		},
		tcp: func(ctx context.Context, s netip.AddrPort) (*net.TCPConn, error) {
			if err := check(ctx, s); err != nil {
				return nil, err
			}
			return new(net.Dialer).DialTCP(ctx, "tcp4", netip.AddrPort{}, s)
		},
	}
}

func answerQuery(t testing.TB, query []byte, records []testRR) []byte {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		t.Fatal(err)
	}
	q, err := p.Question()
	if err != nil {
		t.Fatal(err)
	}
	return responseBytes(t, q, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionAvailable: true}, records, nil, nil)
}

func TestResolverSerialFamiliesUseOwnedNumericUDP(t *testing.T) {
	var mu sync.Mutex
	var kinds []dnsmessage.Type
	s := newLocalDNS(t, func(query []byte) [][]byte {
		var p dnsmessage.Parser
		_, _ = p.Start(query)
		q, err := p.Question()
		if err != nil {
			t.Error("bad emitted query")
			return nil
		}
		mu.Lock()
		kinds = append(kinds, q.Type)
		mu.Unlock()
		var data []byte
		if q.Type == dnsmessage.TypeA {
			data = []byte{1, 2, 3, 4}
		} else {
			a := netip.MustParseAddr("2001:4860::1").As16()
			data = a[:]
		}
		return [][]byte{answerQuery(t, query, []testRR{{kind: q.Type, data: data}})}
	}, nil)
	r, err := NewResolver([]netip.AddrPort{s.endpoint}, ownerFor(t, s.endpoint), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var out [16]netip.Addr
	n, err := r.ResolveInto(ctx, "example.test", IPv4|IPv6, &out)
	if err != nil || n != 2 || out[0] != netip.MustParseAddr("1.2.3.4") || out[1] != netip.MustParseAddr("2001:4860::1") {
		t.Fatalf("resolve count=%d err=%v", n, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(kinds) != 2 || kinds[0] != dnsmessage.TypeA || kinds[1] != dnsmessage.TypeAAAA {
		t.Fatal("family order/count changed")
	}
}

func TestResolverASuccessAndRecursiveAAAANODATAPublishesCompleteSet(t *testing.T) {
	s := newLocalDNS(t, func(query []byte) [][]byte {
		var p dnsmessage.Parser
		h, _ := p.Start(query)
		q, _ := p.Question()
		var answers, authority []testRR
		if q.Type == dnsmessage.TypeA {
			answers = []testRR{{kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}}}
		} else {
			authority = []testRR{{name: "test.", kind: dnsmessage.TypeSOA, data: make([]byte, 22)}, {name: "test.", kind: dnsmessage.TypeNS, data: []byte{0}}}
		}
		return [][]byte{responseBytes(t, q, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true}, answers, authority, nil)}
	}, nil)
	r, err := NewResolver([]netip.AddrPort{s.endpoint}, ownerFor(t, s.endpoint), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var out [16]netip.Addr
	if n, err := r.ResolveInto(ctx, "example.test", IPv4|IPv6, &out); n != 1 || err != nil || out[0] != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("recursive family set count=%d err=%v", n, err)
	}
}

func truncatedQuery(t testing.TB, query []byte) []byte {
	b := answerQuery(t, query, nil)
	b[2] |= 2
	return b
}

func tcpParts(body []byte) [][]byte {
	prefix := []byte{byte(len(body) >> 8), byte(len(body))}
	return [][]byte{prefix[:1], prefix[1:], body[:7], body[7:]}
}

func TestResolverTCPFallbackSameServerFullFrameAndPartialReads(t *testing.T) {
	var udpCalls, tcpCalls atomic.Int32
	s := newLocalDNS(t, func(q []byte) [][]byte { udpCalls.Add(1); return [][]byte{truncatedQuery(t, q)} }, func(query []byte) [][]byte {
		tcpCalls.Add(1)
		var p dnsmessage.Parser
		h, _ := p.Start(query)
		q, _ := p.Question()
		body := responseBytes(t, q, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true}, []testRR{{kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}}}, nil, []testRR{{kind: 65000, data: make([]byte, 65535-82)}})
		if len(body) != 65535 {
			t.Errorf("fixture full frame length=%d", len(body))
		}
		return tcpParts(body)
	})
	r, err := NewResolver([]netip.AddrPort{s.endpoint, netip.MustParseAddrPort("10.77.0.1:53")}, ownerFor(t, s.endpoint), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var out [16]netip.Addr
	if n, err := r.ResolveInto(ctx, "example.test", IPv4, &out); err != nil || n != 1 || out[0] != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("full TCP count=%d err=%v", n, err)
	}
	if udpCalls.Load() != 1 || tcpCalls.Load() != 1 {
		t.Fatalf("transport counts UDP=%d TCP=%d", udpCalls.Load(), tcpCalls.Load())
	}
}

func TestResolverUDP512And513Bounds(t *testing.T) {
	for _, size := range []int{512, 513} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			s := newLocalDNS(t, func(query []byte) [][]byte {
				var p dnsmessage.Parser
				h, _ := p.Start(query)
				q, _ := p.Question()
				return [][]byte{responseBytes(t, q, dnsmessage.Header{ID: h.ID, Response: true}, []testRR{{kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}}}, nil, []testRR{{kind: 65000, data: make([]byte, size-82)}})}
			}, nil)
			r, err := NewResolver([]netip.AddrPort{s.endpoint}, ownerFor(t, s.endpoint), 1)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var out [16]netip.Addr
			n, err := r.ResolveInto(ctx, "example.test", IPv4, &out)
			if size == 512 && (n != 1 || err != nil) {
				t.Fatalf("512 n=%d err=%v", n, err)
			}
			if size == 513 && (n != 0 || !errors.Is(err, ErrSizeLimit) || out != ([16]netip.Addr{})) {
				t.Fatalf("513 n=%d err=%v", n, err)
			}
		})
	}
}

func TestResolverTCPRejectsInvalidPrefixPartialBodyAndTC(t *testing.T) {
	for _, mode := range []string{"zero", "eleven", "partial-prefix", "partial-body", "tc", "closed"} {
		t.Run(mode, func(t *testing.T) {
			var tcpCalls atomic.Int32
			s := newLocalDNS(t, func(q []byte) [][]byte { return [][]byte{truncatedQuery(t, q)} }, func(q []byte) [][]byte {
				tcpCalls.Add(1)
				switch mode {
				case "zero":
					return [][]byte{{0, 0}}
				case "eleven":
					return [][]byte{{0, 11}}
				case "partial-prefix":
					return [][]byte{{0}}
				case "partial-body":
					return [][]byte{{0, 50}, {1, 2, 3}}
				case "closed":
					return nil
				default:
					return tcpParts(truncatedQuery(t, q))
				}
			})
			r, err := NewResolver([]netip.AddrPort{s.endpoint}, ownerFor(t, s.endpoint), 1)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var out [16]netip.Addr
			out[0] = netip.MustParseAddr("1.1.1.1")
			if n, err := r.ResolveInto(ctx, "example.test", IPv4, &out); n != 0 || err == nil || out != ([16]netip.Addr{}) {
				t.Fatalf("partial TCP count=%d err=%v", n, err)
			}
			if tcpCalls.Load() != 1 {
				t.Fatal("TCP failure fixture was not exercised")
			}
		})
	}
}

func TestResolverIrrelevantUDPReplyLimitAndValidatedTC(t *testing.T) {
	for _, bad := range []int{3, 4} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			var tcpCalls atomic.Int32
			s := newLocalDNS(t, func(query []byte) [][]byte {
				wrong := truncatedQuery(t, query)
				wrong[1]++
				replies := make([][]byte, 0, bad+1)
				for i := 0; i < bad; i++ {
					replies = append(replies, wrong)
				}
				return append(replies, truncatedQuery(t, query))
			}, func(q []byte) [][]byte {
				tcpCalls.Add(1)
				return tcpParts(answerQuery(t, q, []testRR{{kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}}}))
			})
			r, err := NewResolver([]netip.AddrPort{s.endpoint}, ownerFor(t, s.endpoint), 1)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var out [16]netip.Addr
			n, err := r.ResolveInto(ctx, "example.test", IPv4, &out)
			if bad == 3 && (err != nil || n != 1 || tcpCalls.Load() != 1) {
				t.Fatalf("matching fourth reply n=%d err=%v TCP=%d", n, err, tcpCalls.Load())
			}
			if bad == 4 && (err == nil || n != 0 || tcpCalls.Load() != 0) {
				t.Fatalf("irrelevant limit n=%d err=%v TCP=%d", n, err, tcpCalls.Load())
			}
		})
	}
}

func TestResolverAlternateServerRestartsWholeFamilySet(t *testing.T) {
	var first, second atomic.Int32
	a := newLocalDNS(t, func(q []byte) [][]byte {
		first.Add(1)
		var p dnsmessage.Parser
		_, _ = p.Start(q)
		question, _ := p.Question()
		if question.Type == dnsmessage.TypeA {
			return [][]byte{answerQuery(t, q, []testRR{{kind: dnsmessage.TypeA, data: []byte{1, 1, 1, 1}}})}
		}
		b := answerQuery(t, q, nil)
		b[3] |= 2
		return [][]byte{b}
	}, nil)
	b := newLocalDNS(t, func(q []byte) [][]byte {
		second.Add(1)
		var p dnsmessage.Parser
		_, _ = p.Start(q)
		question, _ := p.Question()
		if question.Type == dnsmessage.TypeA {
			return [][]byte{answerQuery(t, q, []testRR{{kind: dnsmessage.TypeA, data: []byte{2, 2, 2, 2}}})}
		}
		return [][]byte{answerQuery(t, q, nil)}
	}, nil)
	r, err := NewResolver([]netip.AddrPort{a.endpoint, b.endpoint}, ownerFor(t, a.endpoint, b.endpoint), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var out [16]netip.Addr
	if n, err := r.ResolveInto(ctx, "example.test", IPv4|IPv6, &out); n != 1 || err != nil || out[0] != netip.MustParseAddr("2.2.2.2") {
		t.Fatalf("alternate full set n=%d err=%v", n, err)
	}
	if first.Load() != 2 || second.Load() != 2 {
		t.Fatalf("family attempts first=%d second=%d", first.Load(), second.Load())
	}
}

func TestResolverNXDOMAINAndOverflowDoNotPublishPartialFamily(t *testing.T) {
	for _, failure := range []string{"nxdomain", "overflow"} {
		t.Run(failure, func(t *testing.T) {
			s := newLocalDNS(t, func(q []byte) [][]byte {
				var p dnsmessage.Parser
				_, _ = p.Start(q)
				question, _ := p.Question()
				if question.Type == dnsmessage.TypeA {
					return [][]byte{answerQuery(t, q, []testRR{{kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}}})}
				}
				if failure == "nxdomain" {
					b := answerQuery(t, q, nil)
					b[3] |= 3
					return [][]byte{b}
				}
				return [][]byte{truncatedQuery(t, q)}
			}, func(q []byte) [][]byte {
				records := make([]testRR, 16)
				for i := range records {
					address := netip.AddrFrom16([16]byte{0x20, 1, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i + 1)}).As16()
					records[i] = testRR{kind: dnsmessage.TypeAAAA, data: append([]byte(nil), address[:]...)}
				}
				return tcpParts(answerQuery(t, q, records))
			})
			r, err := NewResolver([]netip.AddrPort{s.endpoint}, ownerFor(t, s.endpoint), 1)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var out [16]netip.Addr
			if n, err := r.ResolveInto(ctx, "example.test", IPv4|IPv6, &out); n != 0 || err == nil || out != ([16]netip.Addr{}) {
				t.Fatalf("partial family published n=%d err=%v", n, err)
			}
		})
	}
}

func TestResolverDeadlineOrCancellationNeverAdvancesServer(t *testing.T) {
	for _, mode := range []string{"deadline", "cancel", "close"} {
		t.Run(mode, func(t *testing.T) {
			queried := make(chan struct{})
			var once sync.Once
			s := newLocalDNS(t, func([]byte) [][]byte { once.Do(func() { close(queried) }); return nil }, nil)
			r, err := NewResolver([]netip.AddrPort{s.endpoint, netip.MustParseAddrPort("10.77.0.1:53")}, ownerFor(t, s.endpoint), 1)
			if err != nil {
				t.Fatal(err)
			}
			timeout := 2 * time.Second
			if mode == "deadline" {
				timeout = 40 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer func() { cancel(); _ = r.Close() }()
			result := make(chan error, 1)
			go func() {
				var out [16]netip.Addr
				n, err := r.ResolveInto(ctx, "example.test", IPv4|IPv6, &out)
				if n != 0 || out != ([16]netip.Addr{}) {
					result <- errors.New("partial cancellation output")
					return
				}
				result <- err
			}()
			waitDNS(t, queried)
			if mode == "cancel" {
				cancel()
			}
			if mode == "close" {
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
			}
			err = <-result
			if mode == "deadline" && !errors.Is(err, ErrTimeout) {
				t.Fatalf("deadline category=%v", err)
			}
			if mode == "cancel" && !errors.Is(err, ErrCancelled) {
				t.Fatalf("cancel category=%v", err)
			}
			if mode == "close" && !errors.Is(err, ErrInvalidState) {
				t.Fatalf("close category=%v", err)
			}
		})
	}
}

func TestResolverAtMostTwoServersAndEightSequentialTransportOpens(t *testing.T) {
	var udp1, tcp1, udp2, tcp2 atomic.Int32
	a := newLocalDNS(t, func(q []byte) [][]byte { udp1.Add(1); return [][]byte{truncatedQuery(t, q)} }, func(q []byte) [][]byte { tcp1.Add(1); return tcpParts(answerQuery(t, q, nil)) })
	b := newLocalDNS(t, func(q []byte) [][]byte { udp2.Add(1); return [][]byte{truncatedQuery(t, q)} }, func(q []byte) [][]byte {
		tcp2.Add(1)
		var p dnsmessage.Parser
		_, _ = p.Start(q)
		question, _ := p.Question()
		var data []byte
		if question.Type == dnsmessage.TypeA {
			data = []byte{1, 2, 3, 4}
		} else {
			data = make([]byte, 16)
			data[0] = 0x20
			data[15] = 1
		}
		return tcpParts(answerQuery(t, q, []testRR{{kind: question.Type, data: data}}))
	})
	r, err := NewResolver([]netip.AddrPort{a.endpoint, b.endpoint, netip.MustParseAddrPort("10.77.0.1:53"), netip.MustParseAddrPort("10.77.0.2:53")}, ownerFor(t, a.endpoint, b.endpoint), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out [16]netip.Addr
	if n, err := r.ResolveInto(ctx, "example.test", IPv4|IPv6, &out); n != 2 || err != nil {
		t.Fatalf("bounded server set n=%d err=%v", n, err)
	}
	if udp1.Load() != 2 || tcp1.Load() != 2 || udp2.Load() != 2 || tcp2.Load() != 2 {
		t.Fatalf("logical transport counts %d %d %d %d", udp1.Load(), tcp1.Load(), udp2.Load(), tcp2.Load())
	}
}

func BenchmarkResolverOwnedUDPOperation(b *testing.B) {
	w, body := parseFixture(b, dnsmessage.TypeA, []testRR{{kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}}}, nil, nil)
	w.clear()
	replies := [][]byte{body}
	s := newLocalDNS(b, func(query []byte) [][]byte { copy(body[:2], query[:2]); return replies }, nil)
	r, err := NewResolver([]netip.AddrPort{s.endpoint}, ownerFor(b, s.endpoint), 1)
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var output [16]netip.Addr
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if n, err := r.ResolveInto(ctx, "example.test", IPv4, &output); n != 1 || err != nil {
			b.Fatalf("operation n=%d err=%v", n, err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(r.OperationOwnedBytes()), "owned-B/op")
	b.ReportMetric(float64(r.FixedOwnedBytes()), "fixed-B")
}

func BenchmarkResolverMalformedGrammarReservation(b *testing.B) {
	r, err := NewResolver([]netip.AddrPort{netip.MustParseAddrPort("10.77.0.1:53")}, &testOwner{}, 1)
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var output [16]netip.Addr
	domain := strings.Repeat(".", 253)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if n, err := r.ResolveInto(ctx, domain, IPv4, &output); n != 0 || !errors.Is(err, ErrInvalidRequest) {
			b.Fatalf("malformed n=%d err=%v", n, err)
		}
	}
}

func TestTCPResponseCannotSucceedAfterExchangeCancellation(t *testing.T) {
	parent, cancelParent := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelParent()
	op := newOperation(parent, time.Now().Add(2*time.Second))
	defer op.finish()
	exchange, cancelExchange := context.WithTimeout(op.ctx, time.Second)
	defer cancelExchange()
	s := newLocalDNS(t, nil, func(q []byte) [][]byte {
		cancelExchange()
		return tcpParts(answerQuery(t, q, []testRR{{kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}}}))
	})
	var w workspace
	w.names[0] = dnsmessage.MustNewName("example.test.")
	query, id, err := w.buildQuery(dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if err := op.tcpExchange(exchange, ownerFor(t, s.endpoint), s.endpoint, &w, query, dnsmessage.TypeA, id); !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancelled exchange returned %v", err)
	}
}
