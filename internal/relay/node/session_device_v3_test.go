// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"kurdistan/internal/product/runtimepolicy"
	kruntime "kurdistan/internal/runtime"
)

func TestSessionDeviceV3AdmitsDormantWithoutLegacyQueue(t *testing.T) {
	tunnel := &healthTunnelV3{memoryTunnelV1: newMemoryTunnelV1(), failure: make(chan struct{})}
	registry, err := NewSessionRegistry(tunnel, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	spec := SessionSpec{ID: "s", ProfileID: "p", ClientKeyID: "c", AssignedIPv4: [4]byte{10, 89, 0, 2}, DNSIPv4: testRelayDNSIPv4V1}
	device, err := registry.RegisterV3(spec, SessionDeviceConfigV3{Context: ctx, AuthorityDeadline: time.Now().Add(time.Second), MaxPacketBytes: 1280, BudgetBytes: 1 << 20, PayloadProtocols: []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolUDP}})
	if err != nil || device == nil {
		t.Fatalf("valid V3 registration failed: %v", err)
	}
	if registry.sessions["s"].inbound != nil {
		t.Fatal("V3 allocated a second packet queue")
	}
}

type ingressOwnerV3 struct {
	submit func([]byte) error
	cancel func(error)
}

func (o *ingressOwnerV3) TrySubmitReturnPacketV3(p []byte) error {
	if o.submit != nil {
		return o.submit(p)
	}
	return nil
}
func (o *ingressOwnerV3) CancelWithReason(e error) {
	if o.cancel != nil {
		o.cancel(e)
	}
}

type controlledTunnelV3 struct {
	*healthTunnelV3
	prepare func(context.Context) error
	write   func(context.Context, []byte) (int, error)
}

func (t *controlledTunnelV3) PreparePacketWriteV3(ctx context.Context) error {
	if t.prepare != nil {
		return t.prepare(ctx)
	}
	return nil
}
func (t *controlledTunnelV3) WritePacketContextV3(ctx context.Context, p []byte) (int, error) {
	if t.write != nil {
		return t.write(ctx, p)
	}
	return len(p), nil
}
func deviceFixtureV3(t *testing.T, max int) (*SessionRegistry, *controlledTunnelV3, SessionSpec, SessionDeviceConfigV3) {
	t.Helper()
	tunnel := &controlledTunnelV3{healthTunnelV3: &healthTunnelV3{memoryTunnelV1: newMemoryTunnelV1(), failure: make(chan struct{})}}
	r, err := NewSessionRegistry(tunnel, max, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(func() { cancel(); _ = r.Close() })
	spec := SessionSpec{ID: "s", ProfileID: "p", ClientKeyID: "c", AssignedIPv4: [4]byte{10, 89, 0, 2}, DNSIPv4: testRelayDNSIPv4V1}
	c := SessionDeviceConfigV3{Context: ctx, AuthorityDeadline: time.Now().Add(5 * time.Second), MaxPacketBytes: 1280, BudgetBytes: 1 << 20, PayloadProtocols: []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolUDP}}
	return r, tunnel, spec, c
}
func waitDeviceV3(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("device synchronization timeout")
	}
}

func TestSessionDeviceV3DirectIngressDormantDuplicateAndNoClone(t *testing.T) {
	r, _, spec, c := deviceFixtureV3(t, 1)
	d, err := r.RegisterV3(spec, c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { d.Close(); waitDeviceV3(t, d.Done()) }()
	packet := testIPv4PacketV1([4]byte{1, 2, 3, 4}, spec.AssignedIPv4, 17, []byte{1})
	if err = r.RouteReturnPacket(packet); !errors.Is(err, ErrPacketRejected) {
		t.Fatal("dormant ingress admitted")
	}
	var calls int
	owner := &ingressOwnerV3{submit: func(p []byte) error {
		calls++
		if &p[0] != &packet[0] {
			t.Error("registry cloned before pump admission")
		}
		return nil
	}}
	if err = d.AttachReturnIngressV3(owner); err != nil {
		t.Fatal(err)
	}
	if err = d.AttachReturnIngressV3(owner); !errors.Is(err, ErrSessionConflict) {
		t.Fatal("duplicate attach admitted")
	}
	if err = r.RouteReturnPacket(packet); err != nil || calls != 1 {
		t.Fatalf("direct ingress %v calls=%d", err, calls)
	}
	if _, err = d.Read(make([]byte, 1)); !errors.Is(err, ErrPacketRejected) {
		t.Fatal("second return consumer available")
	}
	if b := d.BoundsV3(); b.QueuedPayloadBytes != 0 || b.OwnedBytes == 0 {
		t.Fatal("invalid device accounting")
	}
}

func TestSessionDeviceV3DrainingAndPreparingCountAgainstLegacyCapacity(t *testing.T) {
	for _, mode := range []string{"preparing", "ingress", "stop-effect"} {
		t.Run(mode, func(t *testing.T) {
			r, tunnel, spec, c := deviceFixtureV3(t, 1)
			entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
				waitDeviceV3(t, finished)
			}()
			var d *SessionDeviceV3
			if mode == "preparing" {
				tunnel.prepare = func(ctx context.Context) error {
					close(entered)
					select {
					case <-release:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				go func() {
					var e error
					d, e = r.RegisterV3(spec, c)
					if e != nil {
						t.Error(e)
					}
					close(finished)
				}()
			} else {
				var e error
				d, e = r.RegisterV3(spec, c)
				if e != nil {
					close(finished)
					t.Fatal(e)
				}
				owner := &ingressOwnerV3{}
				if mode == "ingress" {
					owner.submit = func([]byte) error { close(entered); <-release; return kruntime.ServiceResourceLimitV1 }
				} else {
					owner.cancel = func(error) { _ = r.Snapshot(); close(entered); <-release }
				}
				if e = d.AttachReturnIngressV3(owner); e != nil {
					close(finished)
					t.Fatal(e)
				}
				go func() {
					if mode == "ingress" {
						_ = r.RouteReturnPacket(testIPv4PacketV1([4]byte{1, 2, 3, 4}, spec.AssignedIPv4, 17, []byte{1}))
					} else {
						_ = d.Close()
					}
					close(finished)
				}()
			}
			waitDeviceV3(t, entered)
			if mode == "ingress" {
				_ = d.Close()
			}
			replacement := spec
			replacement.ID = "next"
			replacement.ProfileID = "next"
			replacement.ClientKeyID = "next"
			if _, e := r.Register(replacement); !errors.Is(e, ErrSessionLimit) {
				t.Fatalf("legacy escaped %s capacity: %v", mode, e)
			}
			if mode != "preparing" {
				select {
				case <-d.Done():
					t.Fatal("Done preceded counted work")
				default:
				}
			}
			close(release)
			waitDeviceV3(t, finished)
			if d != nil {
				d.Close()
				waitDeviceV3(t, d.Done())
			}
			if next, e := r.Register(replacement); e != nil {
				t.Fatalf("capacity not returned: %v", e)
			} else {
				next.Close()
			}
		})
	}
}

func TestSessionDeviceV3StaleIngressCannotStopTextualIDSuccessor(t *testing.T) {
	r, _, spec, c := deviceFixtureV3(t, 2)
	d, err := r.RegisterV3(spec, c)
	if err != nil {
		t.Fatal(err)
	}
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		waitDeviceV3(t, finished)
	}()
	owner := &ingressOwnerV3{submit: func([]byte) error { close(entered); <-release; return kruntime.ServiceResourceLimitV1 }}
	if err = d.AttachReturnIngressV3(owner); err != nil {
		close(finished)
		t.Fatal(err)
	}
	packet := testIPv4PacketV1([4]byte{1, 2, 3, 4}, spec.AssignedIPv4, 17, []byte{1})
	go func() { _ = r.RouteReturnPacket(packet); close(finished) }()
	waitDeviceV3(t, entered)
	if err = r.RouteReturnPacket(packet); !errors.Is(err, ErrPacketRejected) {
		t.Fatal("parallel ingress admitted")
	}
	d.Close()
	next, err := r.RegisterV3(spec, c)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	close(release)
	waitDeviceV3(t, finished)
	waitDeviceV3(t, d.Done())
	if next.StopCodeV1() != SessionStopNoneV1 {
		t.Fatal("stale callback stopped successor")
	}
	if err = d.AttachReturnIngressV3(&ingressOwnerV3{}); err == nil {
		t.Fatal("stale attach admitted")
	}
}

func TestSessionDeviceV3WriteCancellationJoinsWithoutClosingSharedTUN(t *testing.T) {
	r, tunnel, spec, c := deviceFixtureV3(t, 2)
	entered := make(chan struct{})
	var calls atomic.Int32
	tunnel.write = func(ctx context.Context, p []byte) (int, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-ctx.Done()
			return 0, ctx.Err()
		}
		return len(p), nil
	}
	d, err := r.RegisterV3(spec, c)
	if err != nil {
		t.Fatal(err)
	}
	packet := testIPv4PacketV1(spec.AssignedIPv4, [4]byte{1, 2, 3, 4}, 17, []byte{1})
	finished := make(chan struct{})
	go func() {
		if n, e := d.Write(packet); n != 0 || e == nil {
			t.Error("cancelled write published")
		}
		close(finished)
	}()
	waitDeviceV3(t, entered)
	if _, e := d.Write(packet); e == nil {
		t.Fatal("second write admitted")
	}
	d.Close()
	waitDeviceV3(t, finished)
	waitDeviceV3(t, d.Done())
	select {
	case <-tunnel.closed:
		t.Fatal("session closed shared TUN")
	default:
	}
	next, err := r.RegisterV3(spec, c)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if n, e := next.Write(packet); n != len(packet) || e != nil {
		t.Fatalf("next session write %d %v", n, e)
	}
}

func TestSessionDeviceV3EffectiveProtocolAndPostWriteFence(t *testing.T) {
	r, tunnel, spec, c := deviceFixtureV3(t, 1)
	var calls int
	tunnel.write = func(_ context.Context, p []byte) (int, error) { calls++; return len(p), nil }
	d, err := r.RegisterV3(spec, c)
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []byte{1, 6} {
		if _, err = d.Write(testIPv4PacketV1(spec.AssignedIPv4, [4]byte{1, 2, 3, 4}, protocol, []byte{1})); err == nil {
			t.Fatalf("disabled protocol %d admitted", protocol)
		}
	}
	if calls != 0 {
		t.Fatal("invalid protocol touched TUN")
	}
	tunnel.write = func(_ context.Context, p []byte) (int, error) { d.Close(); return len(p), nil }
	if n, e := d.Write(testIPv4PacketV1(spec.AssignedIPv4, [4]byte{1, 2, 3, 4}, 17, []byte{1})); n != 0 || e == nil {
		t.Fatal("full but stale kernel write reported current success")
	}
	waitDeviceV3(t, d.Done())
	for i := 0; i < 20; i++ {
		spec.ID = fmt.Sprint(i)
		next, e := r.RegisterV3(spec, c)
		if e != nil {
			t.Fatal(e)
		}
		next.Close()
		waitDeviceV3(t, next.Done())
	}
	if r.drainingV3 != 0 || r.preparingV3 != 0 {
		t.Fatal("churn retained capacity")
	}
}

func TestSessionDeviceV3ParentTimeoutDoesNotInventAuthorityExpiry(t *testing.T) {
	r, _, spec, c := deviceFixtureV3(t, 1)
	parent, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	c.Context = parent
	c.AuthorityDeadline = time.Now().Add(time.Hour)
	d, err := r.RegisterV3(spec, c)
	if err != nil {
		t.Fatal(err)
	}
	waitDeviceV3(t, d.Done())
	if err = d.checkAuthorityV3(time.Now()); !errors.Is(err, kruntime.ServiceCancelledV1) {
		t.Fatalf("parent timeout invented signed expiry: %v", err)
	}
}

func TestSessionDeviceV3HandlerRetirementCountsThroughJoinedCleanup(t *testing.T) {
	r, _, spec, c := deviceFixtureV3(t, 1)
	d, err := r.RegisterV3(spec, c)
	if err != nil {
		t.Fatal(err)
	}
	// One real handler owns this reference before constructing its pump. Closing
	// PacketIO is not proof that the pump has retired its workers.
	if err = d.holdAttemptV3(); err != nil {
		t.Fatal(err)
	}
	if err = d.holdAttemptV3(); err == nil {
		t.Fatal("duplicate handler reference")
	}
	d.Close()
	for i := 0; i < 20; i++ {
		select {
		case <-d.Done():
			t.Fatal("device retired before handler cleanup")
		default:
		}
		if _, e := r.RegisterV3(spec, c); !errors.Is(e, ErrSessionLimit) {
			t.Fatal("draining handler capacity reused")
		}
		if _, e := r.Register(spec); !errors.Is(e, ErrSessionLimit) {
			t.Fatal("legacy admission bypassed draining handler")
		}
	}
	d.releaseAttemptV3()
	waitDeviceV3(t, d.Done())
	d.releaseAttemptV3() // A duplicate release cannot consume a successor's slot.
	next, e := r.RegisterV3(spec, c)
	if e != nil {
		t.Fatal(e)
	}
	next.Close()
	waitDeviceV3(t, next.Done())
	if e = d.holdAttemptV3(); e == nil {
		t.Fatal("retired record acquired handler")
	}
}

func TestSessionDeviceV3RefusalPrecedesPreparationAndIP58UsesICMPv6(t *testing.T) {
	r, tunnel, spec, c := deviceFixtureV3(t, 1)
	var prepares, writes int
	tunnel.prepare = func(context.Context) error { prepares++; return nil }
	for _, protocols := range [][]runtimepolicy.PayloadProtocolV2{nil, {"udp", "tcp"}, {"udp", "udp"}, {"other"}} {
		bad := c
		bad.PayloadProtocols = protocols
		if _, err := r.RegisterV3(spec, bad); err == nil {
			t.Fatal("invalid protocol input admitted")
		}
	}
	bad := c
	bad.BudgetBytes = deviceOwnedBytesV3(spec) - 1
	if _, err := r.RegisterV3(spec, bad); !errors.Is(err, ErrSessionLimit) {
		t.Fatal("insufficient reservation admitted")
	}
	if prepares != 0 {
		t.Fatal("rejected registration entered Prepare")
	}
	spec.AssignedIPv4 = [4]byte{}
	spec.DNSIPv4 = [4]byte{}
	spec.AssignedIPv6 = [16]byte{0xfd, 0x42, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	spec.DNSIPv6 = testRelayDNSIPv6V1
	c.PayloadProtocols = []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolICMPv6}
	tunnel.write = func(_ context.Context, p []byte) (int, error) { writes++; return len(p), nil }
	d, err := r.RegisterV3(spec, c)
	if err != nil {
		t.Fatal(err)
	}
	packet := testIPv6PacketV1(spec.AssignedIPv6, [16]byte{0x20, 1, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 58, []byte{128, 0, 0, 0})
	if n, e := d.Write(packet); n != len(packet) || e != nil {
		t.Fatalf("ICMPv6 denied %d %v", n, e)
	}
	d.Close()
	waitDeviceV3(t, d.Done())
	c.PayloadProtocols = []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolICMP}
	d, err = r.RegisterV3(spec, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Write(packet); err == nil {
		t.Fatal("ICMP permission incorrectly grants ICMPv6")
	}
	d.Close()
	waitDeviceV3(t, d.Done())
	if writes != 1 {
		t.Fatal("disabled ICMPv6 reached TUN")
	}
	close(tunnel.failure)
	before := prepares
	if _, err = r.RegisterV3(spec, c); err == nil {
		t.Fatal("unhealthy device admitted")
	}
	if prepares != before {
		t.Fatal("latched write fault entered Prepare")
	}
}
