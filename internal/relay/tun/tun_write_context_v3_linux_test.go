// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build linux

package tun

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type packetWriterTestV3 interface {
	WritePacketContextV3(context.Context, []byte) (int, error)
	PreparePacketWriteV3(context.Context) error
	WriteFailureV3() <-chan struct{}
}

func TestLinuxPacketWriteResourceInventoryV3(t *testing.T) {
	d, _ := linuxPairV3(t)
	d.initWriteV3()
	gate, closed, failure := d.writeGate, d.closed, d.writeFailure
	d.initWriteV3()
	if gate == nil || closed == nil || failure == nil || gate == closed || gate == failure || closed == failure ||
		d.writeGate != gate || d.closed != closed || d.WriteFailureV3() != failure {
		t.Fatal("write controls missing, aliased, or replaced by repeated initialization")
	}
	// Inventory the actual declared native channels, not runtime/allocator RSS.
	value := reflect.ValueOf(d).Elem()
	channels, slots := 0, 0
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.Kind() == reflect.Slice {
			t.Fatal("unreported retained variable backing in Linux writer")
		}
		if field.Kind() == reflect.Chan {
			channels++
			slots += field.Cap()
			if field.Type().Elem() != reflect.TypeOf(struct{}{}) {
				t.Fatal("native control queue can retain payload")
			}
		}
	}
	if channels != 3 || slots != 1 || cap(gate) != 1 || len(gate) != 0 || cap(closed) != 0 || cap(failure) != 0 {
		t.Fatal("initialized controls exceed declared three signals / one writer slot")
	}
	if err := d.acquireWriteV3(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.acquireWriteV3(ctx); err == nil {
		t.Fatal("second writer bypassed occupied gate")
	}
	if len(gate) != 1 {
		t.Fatal("refused writer changed gate ownership")
	}
	d.releaseWriteV3()
	d.latchWriteFailureV3()
	select {
	case <-failure:
	default:
		t.Fatal("health did not own its terminal signal")
	}
	select {
	case <-closed:
		t.Fatal("write health closed shared device")
	default:
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	default:
		t.Fatal("Close did not retire its control")
	}
	t.Logf("linuxDevice=%d initializedControlChannels=%d totalControlSlots=%d queuedNativePayload=0", unsafe.Sizeof(*d), channels, slots)
}

func TestLinuxPacketWriteIsOneIndivisibleSyscall(t *testing.T) {
	for _, mode := range []string{"short", "zero", "terminal", "positive-error", "eintr"} {
		t.Run(mode, func(t *testing.T) {
			d, _ := linuxPairV3(t)
			calls := 0
			d.writePacket = func(_ int, p []byte) (int, error) {
				calls++
				switch mode {
				case "short":
					return 1, nil
				case "zero":
					return 0, nil
				case "terminal":
					return 0, unix.EIO
				case "positive-error":
					return len(p), unix.EIO
				default:
					if calls == 1 {
						return 0, unix.EINTR
					}
					return len(p), nil
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			n, err := d.WritePacketContextV3(ctx, []byte{1, 2})
			if mode == "eintr" {
				if n != 2 || err != nil || calls != 2 {
					t.Fatalf("EINTR retry %d %v calls=%d", n, err, calls)
				}
			} else if !errors.Is(err, ErrPacketWriteV3) || calls != 1 {
				t.Fatalf("non-atomic write %d %v calls=%d", n, err, calls)
			}
		})
	}
}

func TestLinuxPacketCancellationJoinsHookBeforeResetAndGateRelease(t *testing.T) {
	d, _ := linuxPairV3(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var resets atomic.Int32
	d.setWriteDeadline = func(at time.Time) error {
		if at.Equal(time.Unix(1, 0)) {
			close(entered)
			<-release
		}
		if at.IsZero() {
			resets.Add(1)
		}
		return d.file.SetWriteDeadline(at)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	var calls atomic.Int32
	d.writePacket = func(_ int, p []byte) (int, error) {
		if calls.Add(1) == 1 {
			cancel()
			<-entered
		}
		return len(p), nil
	}
	done := make(chan error, 1)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		cancel()
		_ = d.Close()
	}()
	go func() { _, err := d.WritePacketContextV3(ctx, []byte{1}); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("hook not reached")
	}
	select {
	case <-done:
		t.Fatal("write escaped unjoined callback")
	case <-time.After(20 * time.Millisecond):
	}
	if resets.Load() != 0 {
		t.Fatal("reset preceded callback join")
	}
	next, nextCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer nextCancel()
	if _, err := d.WritePacketContextV3(next, []byte{2}); err == nil {
		t.Fatal("another writer crossed occupied gate")
	}
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled full syscall succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("joined write failed to return")
	}
	if resets.Load() != 1 {
		t.Fatal("deadline not reset once after join")
	}
	next2, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if n, e := d.WritePacketContextV3(next2, []byte{3}); n != 1 || e != nil {
		t.Fatalf("next session %d %v", n, e)
	}
}

func TestLinuxPacketWriteHealthFaultIsPermanent(t *testing.T) {
	for _, mode := range []string{"reset", "callback"} {
		t.Run(mode, func(t *testing.T) {
			d, _ := linuxPairV3(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			d.setWriteDeadline = func(at time.Time) error {
				if (mode == "reset" && at.IsZero()) || (mode == "callback" && at.Equal(time.Unix(1, 0))) {
					return unix.EIO
				}
				return d.file.SetWriteDeadline(at)
			}
			d.writePacket = func(_ int, p []byte) (int, error) {
				if mode == "callback" {
					cancel()
					<-d.WriteFailureV3()
				}
				return len(p), nil
			}
			if _, err := d.WritePacketContextV3(ctx, []byte{1}); !errors.Is(err, ErrWriteHealthV3) {
				t.Fatalf("health category=%v", err)
			}
			select {
			case <-d.WriteFailureV3():
			default:
				t.Fatal("missing health signal")
			}
			if _, err := d.Write([]byte{1}); !errors.Is(err, ErrWriteHealthV3) {
				t.Fatalf("legacy escaped fault=%v", err)
			}
			next, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := d.PreparePacketWriteV3(next); !errors.Is(err, ErrWriteHealthV3) {
				t.Fatalf("prepare restored unhealthy adapter=%v", err)
			}
		})
	}
}

func TestLinuxPacketV3WaiterCancelsBehindLegacyWriter(t *testing.T) {
	d, _ := linuxPairV3(t)
	raw, err := d.file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.Control(func(fd uintptr) {
		var b [4096]byte
		for {
			if _, e := unix.Write(int(fd), b[:]); e != nil {
				return
			}
		}
	})
	legacy := make(chan error, 1)
	go func() { _, e := d.Write([]byte{1}); legacy <- e }()
	deadline := time.Now().Add(time.Second)
	for {
		d.initWriteV3()
		if len(d.writeGate) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("legacy gate not occupied")
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err = d.WritePacketContextV3(ctx, []byte{2}); err == nil {
		t.Fatal("V3 waiter ignored cancellation")
	}
	select {
	case <-legacy:
		t.Fatal("session cancel closed the shared device")
	default:
	}
	_ = d.Close()
	select {
	case <-legacy:
	case <-time.After(time.Second):
		t.Fatal("whole Close did not wake legacy writer")
	}
	select {
	case <-d.WriteFailureV3():
		t.Fatal("whole Close misclassified as health fault")
	default:
	}
}

func linuxPairV3(t *testing.T) (*linuxDevice, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	d := &linuxDevice{file: os.NewFile(uintptr(fds[0]), "local-packet-writer"), name: OwnedName}
	peer := os.NewFile(uintptr(fds[1]), "local-packet-peer")
	t.Cleanup(func() { _ = d.Close(); _ = peer.Close() })
	return d, peer
}

func requireWriterV3(t *testing.T, d *linuxDevice) packetWriterTestV3 {
	t.Helper()
	w, ok := any(d).(packetWriterTestV3)
	if !ok {
		t.Fatal("real Linux device has no cancellable packet writer/control")
	}
	return w
}

func TestLinuxPacketWriterCancelsActiveEAGAINAndKeepsDeviceUsable(t *testing.T) {
	d, peer := linuxPairV3(t)
	w := requireWriterV3(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := w.PreparePacketWriteV3(ctx); err != nil {
		t.Fatal(err)
	}
	// Saturate before starting the real poller write without touching File.Fd.
	raw, err := d.file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fillErr error
	if err = raw.Control(func(fd uintptr) {
		var b [4096]byte
		for {
			_, fillErr = unix.Write(int(fd), b[:])
			if fillErr != nil {
				return
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if fillErr != unix.EAGAIN && fillErr != unix.EWOULDBLOCK {
		t.Fatal("fixture did not reach EAGAIN")
	}
	done := make(chan error, 1)
	go func() { _, e := w.WritePacketContextV3(ctx, []byte{7}); done <- e }()
	select {
	case <-done:
		t.Fatal("saturated write did not wait")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancelled write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not wake active poller write")
	}
	select {
	case <-w.WriteFailureV3():
		t.Fatal("ordinary cancellation poisoned shared device")
	default:
	}
	if err = peer.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [4096]byte
	for {
		if _, err = peer.Read(b[:]); err != nil {
			break
		}
	}
	if err = peer.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	next, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if n, e := w.WritePacketContextV3(next, []byte{8}); n != 1 || e != nil {
		t.Fatalf("next session write %d %v", n, e)
	}
	if n, e := d.Write([]byte{9}); n != 1 || e != nil {
		t.Fatalf("legacy write after reset %d %v", n, e)
	}
	if _, err = peer.Write([]byte{10}); err != nil {
		t.Fatal(err)
	}
	if n, e := d.Read(b[:1]); n != 1 || e != nil || b[0] != 10 {
		t.Fatalf("read affected by write deadline %d %v", n, e)
	}
}

func TestLinuxPacketPrepareUnsupportedDeadlineDoesNotDisableLegacy(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "nonpollable")
	if err != nil {
		t.Fatal(err)
	}
	d := &linuxDevice{file: f, name: OwnedName}
	defer d.Close()
	w := requireWriterV3(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = w.PreparePacketWriteV3(ctx); err == nil {
		t.Fatal("unsupported deadline was admitted")
	}
	select {
	case <-w.WriteFailureV3():
		t.Fatal("initial refusal poisoned legacy device")
	default:
	}
	if n, e := d.Write([]byte{1}); n != 1 || e != nil {
		t.Fatalf("legacy write refused %d %v", n, e)
	}
}
