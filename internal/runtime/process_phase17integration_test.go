// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build linux && phase17integration

package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	goruntime "runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/transport/tlstcp"
)

const (
	phase17NetnsRoleEnv    = "KURD_PHASE17_NETNS_ROLE"
	phase17NetnsAddressEnv = "KURD_PHASE17_NETNS_RELAY_ADDRESS"
	phase17NetnsReadyEnv   = "KURD_PHASE17_NETNS_READY_FILE"
	phase17NetnsStopEnv    = "KURD_PHASE17_NETNS_STOP_FILE"
	phase17NetnsTunEnv     = "KURD_PHASE17_NETNS_TUN"
	phase17NetnsMetricsEnv = "KURD_PHASE17_NETNS_METRICS_FILE"
)

// TestPhase17NamespacePacketPumpV1 is invoked only by scripts/phase17/netns-e2e.sh.
// The script places independent copies of this test binary in the client and
// relay namespaces. The two processes then carry kernel-originated IPv4/IPv6
// packets through the production TLS, handshake, record, replay, and packet-pump
// implementations. No payload is written to test output or retained evidence.
func TestPhase17NamespacePacketPumpV1(t *testing.T) {
	role := os.Getenv(phase17NetnsRoleEnv)
	if role == "" {
		t.Skip("phase17 namespace harness is launched by scripts/phase17/netns-e2e.sh")
	}
	address := os.Getenv(phase17NetnsAddressEnv)
	ready := os.Getenv(phase17NetnsReadyEnv)
	stop := os.Getenv(phase17NetnsStopEnv)
	tunName := os.Getenv(phase17NetnsTunEnv)
	if address == "" || ready == "" || stop == "" || tunName == "" {
		t.Fatal("phase17 namespace harness environment is incomplete")
	}
	finishMetrics := phase17StartNamespaceMetricsV1(os.Getenv(phase17NetnsMetricsEnv))
	defer func() {
		if err := finishMetrics(); err != nil {
			t.Errorf("write aggregate-only process metrics: %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	switch role {
	case "client":
		phase17RunNamespaceClientV1(t, ctx, address, tunName, ready, stop)
	case "relay":
		phase17RunNamespaceRelayV1(t, ctx, address, tunName, ready, stop)
	default:
		t.Fatalf("unsupported phase17 namespace role %q", role)
	}
}

func phase17RunNamespaceClientV1(t *testing.T, ctx context.Context, address, tunName, ready, stop string) {
	t.Helper()
	raw, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	digest := phase11SubprocessDigestV1()
	clientTLS, _ := phase11SubprocessTLSConfigsV1(t)
	carrier, err := tlstcp.Client(ctx, raw, clientTLS, digest, 128<<10)
	if err != nil {
		t.Fatal(err)
	}
	fixture := phase11SubprocessFixtureV1(t)
	config, err := auth.NewProcessHandshakeConfigV1(fixture.input.Client, fixture.input.Server, fixture.input.SelectedPolicy, fixture.input.SelectedCapabilities)
	if err != nil {
		t.Fatal(err)
	}
	handshake, err := NewProcessWireClientHandshakeV1(config, fixture.input.ClientDependencies, digest)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := EstablishProcessClientDuplexEndpointV1(ctx, carrier, handshake, digest, testDuplexProgramV1())
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewProcessTLSTCPDuplexCarrierV1(ctx, carrier, 15*time.Second)
	if err != nil {
		endpoint.Abort()
		t.Fatal(err)
	}
	device := phase17OpenNamespaceTunV1(t, tunName)
	pump := phase17NamespacePumpV1(t, device, adapter, endpoint, DirectionClientV1)
	phase17RunNamespacePumpV1(t, ctx, pump, ready, stop)
}

func phase17RunNamespaceRelayV1(t *testing.T, ctx context.Context, address, tunName, ready, stop string) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	phase17WriteReadyV1(t, ready)
	raw, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	digest := phase11SubprocessDigestV1()
	_, relayTLS := phase11SubprocessTLSConfigsV1(t)
	carrier, err := tlstcp.Server(ctx, raw, relayTLS, digest, 128<<10)
	if err != nil {
		t.Fatal(err)
	}
	fixture := phase11SubprocessFixtureV1(t)
	config, err := auth.NewProcessHandshakeConfigV1(fixture.input.Client, fixture.input.Server, fixture.input.SelectedPolicy, fixture.input.SelectedCapabilities)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	handshake, err := NewProcessWireRelayHandshakeV1(config, fixture.input.ServerDependencies, replay, digest)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := phase17AcceptNamespaceRelayEndpointV1(ctx, carrier, handshake, digest)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewProcessTLSTCPDuplexCarrierV1(ctx, carrier, 15*time.Second)
	if err != nil {
		endpoint.Abort()
		t.Fatal(err)
	}
	device := phase17OpenNamespaceTunV1(t, tunName)
	pump := phase17NamespacePumpV1(t, device, adapter, endpoint, DirectionRelayV1)
	phase17RunNamespacePumpV1(t, ctx, pump, "", stop)
}

func phase17AcceptNamespaceRelayEndpointV1(ctx context.Context, carrier *tlstcp.Conn, handshake *ProcessWireRelayHandshakeV1, digest [32]byte) (*ProcessRelayDuplexEndpointV1, error) {
	clientHello, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		return nil, err
	}
	serverHello, err := handshake.AcceptClientHello(clientHello)
	clear(clientHello)
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, serverHello) != nil {
		clear(serverHello)
		return nil, ErrProcessSessionV1
	}
	clear(serverHello)
	clientFinish, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		return nil, err
	}
	serverFinish, result, err := handshake.AcceptClientFinish(clientFinish)
	clear(clientFinish)
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, serverFinish) != nil {
		clear(serverFinish)
		if result != nil {
			result.Close()
		}
		return nil, ErrProcessSessionV1
	}
	clear(serverFinish)
	endpoint, err := NewProcessRelayDuplexEndpointV1(result, digest, testDuplexProgramV1())
	if err != nil {
		result.Close()
		return nil, err
	}
	binding, err := carrier.CarrierBinding()
	if err != nil {
		endpoint.Abort()
		return nil, err
	}
	bind, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		endpoint.Abort()
		return nil, err
	}
	ready, err := endpoint.AcceptProfileBind(bind, binding)
	clear(bind)
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, ready) != nil {
		clear(ready)
		endpoint.Abort()
		return nil, ErrProcessSessionV1
	}
	clear(ready)
	return endpoint, nil
}

func phase17NamespacePumpV1(t *testing.T, device *os.File, carrier *ProcessTLSTCPDuplexCarrierV1, endpoint ProcessDuplexEndpointV1, direction DirectionV1) *PacketPumpV1 {
	t.Helper()
	pump, err := NewPacketPumpV1(PacketPumpConfigV1{
		TUN: device, Carrier: carrier, Endpoint: endpoint, Program: testDuplexProgramV1(), Direction: direction,
		AssignedIPv4: [4]byte{10, 77, 0, 2}, AssignedIPv6: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		QueuePackets: 8, IncompleteOps: 4, BufferBudget: 128 << 10, IdleTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return pump
}

func phase17RunNamespacePumpV1(t *testing.T, ctx context.Context, pump *PacketPumpV1, ready, stop string) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- pump.Run(ctx) }()
	if ready != "" {
		phase17WriteReadyV1(t, ready)
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			_, stopping := os.Stat(stop)
			if err != nil && !errors.Is(err, context.Canceled) && stopping != nil {
				t.Fatalf("packet pump stopped before the harness: %v", err)
			}
			return
		case <-ctx.Done():
			_ = pump.Close()
			t.Fatal("namespace packet pump timed out")
		case <-ticker.C:
			if _, err := os.Stat(stop); err == nil {
				_ = pump.Close()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("packet pump did not stop")
				}
				return
			}
		}
	}
}

func phase17OpenNamespaceTunV1(t *testing.T, name string) *os.File {
	t.Helper()
	if len(name) == 0 || len(name) > 15 {
		t.Fatal("invalid namespace TUN name")
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	request, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	request.SetUint16(uint16(unix.IFF_TUN | unix.IFF_NO_PI))
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil || request.Name() != name {
		_ = unix.Close(fd)
		t.Fatalf("attach namespace TUN: %v", err)
	}
	file := os.NewFile(uintptr(fd), "phase17-netns-"+strconv.Quote(name))
	if file == nil {
		_ = unix.Close(fd)
		t.Fatal("create namespace TUN file")
	}
	return file
}

func phase17WriteReadyV1(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("ready\n"), 0o600); err != nil {
		t.Fatal(fmt.Errorf("publish namespace readiness: %w", err))
	}
}

func phase17StartNamespaceMetricsV1(path string) func() error {
	if path == "" {
		return func() error { return nil }
	}
	type sample struct {
		goroutines uint64
		heapBytes  uint64
		fds        uint64
	}
	sampleNow := func() (sample, error) {
		var memory goruntime.MemStats
		goruntime.ReadMemStats(&memory)
		fds, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			return sample{}, fmt.Errorf("inspect process file descriptors: %w", err)
		}
		return sample{goroutines: uint64(goruntime.NumGoroutine()), heapBytes: memory.HeapAlloc, fds: uint64(len(fds))}, nil
	}
	maximum, firstErr := sampleNow()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				current, err := sampleNow()
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
				if current.goroutines > maximum.goroutines {
					maximum.goroutines = current.goroutines
				}
				if current.heapBytes > maximum.heapBytes {
					maximum.heapBytes = current.heapBytes
				}
				if current.fds > maximum.fds {
					maximum.fds = current.fds
				}
			case <-stop:
				return
			}
		}
	}()
	return func() error {
		close(stop)
		<-done
		if firstErr != nil {
			return firstErr
		}
		return os.WriteFile(path, []byte(fmt.Sprintf("goroutines=%d\nheap_bytes=%d\nfds=%d\n", maximum.goroutines, maximum.heapBytes, maximum.fds)), 0o600)
	}
}
