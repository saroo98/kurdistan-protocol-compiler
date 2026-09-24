//go:build phase18productiontest && (android || linux)

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"kurdistan/internal/product/runtimepolicy"
)

func TestProductionNetworkV1OriginalCloseErrorRetained(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "operation-error", true: "cancel-precedence"}[cancelled], func(t *testing.T) {
			a, _, _, _, _ := productionSignedNetworkFixtureV1(t, true, 9)
			transport, s := a.PrepareV1(context.Background(), productionNetworkFactoryV1{})
			if s != 0 {
				t.Fatal(s)
			}
			n := transport.(*productionAttemptTransportV1)
			fd, s := n.SocketFDV1()
			if s != 0 || n.ConfirmProtectedV1(fd) != 0 {
				t.Fatal("confirmation", s)
			}
			original := n.connector.fileClose
			closeFailure := errors.New("synthetic error after actual original close")
			closes, recycled := 0, -1
			n.connector.fileClose = func(f *os.File) error {
				closes++
				if err := original(f); err != nil {
					return err
				}
				var err error
				recycled, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
				if err != nil {
					return err
				}
				if cancelled {
					n.CloseWakeV1()
				}
				return closeFailure
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			want := int32(9)
			if cancelled {
				want = 7
			}
			if s := n.ConnectProtectedV1(ctx); s != want {
				t.Fatal("operation status", s, want)
			}
			status := n.FinishV1()
			if recycled >= 0 {
				defer unix.Close(recycled)
			}
			if closes != 1 || recycled != fd {
				t.Fatal("original owner or FD not recycled", closes, recycled, fd)
			}
			if _, err := unix.FcntlInt(uintptr(recycled), unix.F_GETFD, 0); err != nil {
				t.Fatal("recycled FD closed", err)
			}
			if status != 9 {
				t.Fatal("original close failure lost at retirement", status)
			}
			if !errors.Is(n.closeError, closeFailure) {
				t.Fatal("original close cause lost", n.closeError)
			}
			if s := n.FinishV1(); s != 9 {
				t.Fatal("repeated retirement lost failure", s)
			}
		})
	}
}

func TestProductionNetworkV1ConnectorCancellationMatrix(t *testing.T) {
	for _, stage := range []string{"before-confirm", "poll", "adoption", "fileconn", "original-close-recycle"} {
		t.Run(stage, func(t *testing.T) {
			a, _, listener, _, _ := productionSignedNetworkFixtureV1(t, true)
			transport, s := a.PrepareV1(context.Background(), productionNetworkFactoryV1{})
			if s != 0 {
				t.Fatal(s)
			}
			n := transport.(*productionAttemptTransportV1)
			fd, s := n.SocketFDV1()
			if s != 0 {
				t.Fatal(s)
			}
			if flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); e != nil || flags&unix.FD_CLOEXEC == 0 {
				t.Fatal("CLOEXEC", flags, e)
			}
			if flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0); e != nil || flags&unix.O_NONBLOCK == 0 {
				t.Fatal("nonblocking", flags, e)
			}
			if stage == "before-confirm" {
				var calls atomic.Int32
				original := n.connector.connect
				n.connector.connect = func(c context.Context, f int, e runtimepolicy.EndpointV2) error {
					calls.Add(1)
					return original(c, f, e)
				}
				if s := n.ConnectProtectedV1(context.Background()); s != 3 || calls.Load() != 0 {
					t.Fatal("unconfirmed Connect", s, calls.Load())
				}
				if s := n.FinishV1(); s != 0 {
					t.Fatal(s)
				}
				return
			}
			if s = n.ConfirmProtectedV1(fd); s != 0 {
				t.Fatal(s)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var originalCloses, rawCloses atomic.Int32
			var recycled = -1
			ops := n.connector
			n.connector.fileClose = func(f *os.File) error { originalCloses.Add(1); return ops.fileClose(f) }
			n.connector.fileConn = func(f *os.File) (net.Conn, error) {
				r, e := ops.fileConn(f)
				if r != nil {
					r = &productionCountedRawV1{Conn: r, calls: &rawCloses}
				}
				return r, e
			}
			switch stage {
			case "poll":
				n.connector.connect = func(c context.Context, f int, e runtimepolicy.EndpointV2) error {
					return productionPollConnectFDV1(c, f, e, func(p []unix.PollFd, m int) (int, error) { close(entered); <-release; return unix.Poll(p, m) })
				}
			case "adoption":
				n.connector.newFile = func(f uintptr, name string) *os.File { close(entered); <-release; return ops.newFile(f, name) }
			case "fileconn":
				original := n.connector.fileConn
				n.connector.fileConn = func(f *os.File) (net.Conn, error) { close(entered); <-release; return original(f) }
			case "original-close-recycle":
				n.connector.fileClose = func(f *os.File) error {
					originalCloses.Add(1)
					e := ops.fileClose(f)
					var openErr error
					recycled, openErr = unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
					if openErr != nil {
						return openErr
					}
					close(entered)
					<-release
					return e
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			connectDone := make(chan int32, 1)
			go func() { connectDone <- n.ConnectProtectedV1(ctx) }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("handoff not reached")
			}
			n.CloseWakeV1()
			select {
			case <-n.closerDone:
				t.Fatal("closer crossed connector lease")
			default:
			}
			select {
			case <-n.done:
				t.Fatal("attempt retired while handoff blocked")
			default:
			}
			close(release)
			if s := <-connectDone; s != 7 {
				t.Fatal("cancelled handoff", s)
			}
			if s := n.FinishV1(); s != 0 {
				t.Fatal(s)
			}
			wantOriginal := int32(1)
			if stage == "poll" {
				wantOriginal = 0
			}
			if originalCloses.Load() != wantOriginal {
				t.Fatal("original file close", originalCloses.Load())
			}
			wantRaw := int32(1)
			if stage == "poll" || stage == "adoption" {
				wantRaw = 0
			}
			if rawCloses.Load() != wantRaw {
				t.Fatal("duplicated raw close", rawCloses.Load())
			}
			if recycled >= 0 {
				defer unix.Close(recycled)
				if recycled != fd {
					t.Fatalf("test did not obtain the released FD: got %d want %d", recycled, fd)
				}
				if _, e := unix.FcntlInt(uintptr(recycled), unix.F_GETFD, 0); e != nil {
					t.Fatal("stale close hit recycled descriptor", e)
				}
			}
			listener.Close()
		})
	}
}

type productionCountedRawV1 struct {
	net.Conn
	calls *atomic.Int32
}

func (c *productionCountedRawV1) Close() error { c.calls.Add(1); return c.Conn.Close() }

type productionHeldRawV1 struct {
	net.Conn
	entered, release, closed chan struct{}
	firstWrite               chan struct{}
	writes, closes           atomic.Int32
}

func (c *productionHeldRawV1) Close() error {
	if c.closes.Add(1) == 1 {
		close(c.entered)
	}
	<-c.release
	err := c.Conn.Close()
	close(c.closed)
	return err
}
func (c *productionHeldRawV1) Write(b []byte) (int, error) {
	if c.firstWrite != nil && c.writes.Add(1) == 1 {
		close(c.firstWrite)
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.Conn.Write(b)
}

func TestProductionNetworkV1IOCancellationAndInternalClose(t *testing.T) {
	for _, fault := range []string{"first-write", "tls-internal-close", "auth", "bind"} {
		t.Run(fault, func(t *testing.T) {
			a, _, listener, snapshot, now := productionSignedNetworkFixtureV1(t, false)
			transport, s := a.PrepareV1(context.Background(), productionNetworkFactoryV1{})
			if s != 0 {
				t.Fatal(s)
			}
			n := transport.(*productionAttemptTransportV1)
			fd, s := n.SocketFDV1()
			if s != 0 {
				t.Fatal(s)
			}
			if s = n.ConfirmProtectedV1(fd); s != 0 {
				t.Fatal(s)
			}
			closeEntered, closeRelease, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
			reached, resume := make(chan struct{}), make(chan struct{})
			var held *productionHeldRawV1
			ops := n.connector
			n.connector.fileConn = func(f *os.File) (net.Conn, error) {
				r, e := ops.fileConn(f)
				if r != nil {
					held = &productionHeldRawV1{Conn: r, entered: closeEntered, release: closeRelease, closed: closed}
					if fault == "first-write" {
						held.firstWrite = reached
					}
					r = held
				}
				return r, e
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			peerDone := make(chan error, 1)
			peerFinished := make(chan struct{})
			go func() {
				defer close(peerFinished)
				peerDone <- productionControlledPeerExchangeV1(ctx, listener, snapshot, now, false, fault, reached, resume)
			}()
			var releaseClose, releasePeer sync.Once
			t.Cleanup(func() {
				releaseClose.Do(func() { close(closeRelease) })
				releasePeer.Do(func() { close(resume) })
				n.CloseWakeV1()
				listener.Close()
				n.FinishV1()
				<-peerFinished
			})
			stages := []func(context.Context) int32{n.ConnectProtectedV1, n.AuthenticateTLSV1, n.AuthenticateKurdV1, n.AttachInstalledV1}
			index := map[string]int{"first-write": 0, "tls-internal-close": 1, "auth": 2, "bind": 3}[fault]
			for _, stage := range stages[:index] {
				if s := stage(ctx); s != 0 {
					t.Fatal("preceding genuine stage", s)
				}
			}
			stageDone := make(chan [2]int32, 1)
			go func() { s := stages[index](ctx); stageDone <- [2]int32{s, n.FinishV1()} }()
			if fault != "tls-internal-close" {
				select {
				case <-reached:
				case <-ctx.Done():
					t.Fatal("I/O boundary not reached")
				}
				n.CloseWakeV1()
			}
			select {
			case <-closeEntered:
			case <-ctx.Done():
				t.Fatal("actual raw Close not entered")
			}
			select {
			case <-n.done:
				t.Fatal("retired before actual Close return")
			default:
			}
			select {
			case <-stageDone:
				t.Fatal("stage escaped blocked Close")
			default:
			}
			if successor, s := a.PrepareV1(context.Background(), productionNetworkFactoryV1{}); successor != nil || s != 3 {
				t.Fatal("successor while close blocked", s)
			}
			releaseClose.Do(func() { close(closeRelease) })
			releasePeer.Do(func() { close(resume) })
			got := <-stageDone
			want := int32(7)
			if fault == "tls-internal-close" {
				want = 14
			}
			if got[0] != want || got[1] != 0 {
				t.Fatal("actual stage/cleanup result", got, "want", want)
			}
			if held == nil || held.closes.Load() != 1 {
				t.Fatal("physical close count")
			}
			<-peerFinished
			if err := <-peerDone; fault == "tls-internal-close" && err != nil {
				t.Fatal("invalid TLS fixture write", err)
			}
		})
	}
}
