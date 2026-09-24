// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"context"
	"errors"
	"io"
	"math"
	"sync"
	"sync/atomic"
)

var (
	ErrPacketPortConfig         = errors.New("packet_port_config")
	ErrPacketPortPacket         = errors.New("packet_port_packet")
	ErrPacketPortBusy           = errors.New("packet_port_busy")
	ErrPacketPortToken          = errors.New("packet_port_token")
	ErrPacketPortTokenExhausted = errors.New("packet_port_token_exhausted")
	ErrPacketPortDelivery       = errors.New("packet_port_delivery")
)

// PacketDeliveryTokenV1 is an opaque, process-local destination-write receipt.
// Zero is invalid. Tokens are unique across ports and never reused in a process.
type PacketDeliveryTokenV1 uint64

var packetPortTokensV1 atomic.Uint64

// PacketPortV1 bridges packet-pump I/O to an acknowledged native adapter.
// Submit/Read carry outbound packets; Write/Receive/Acknowledge carry inbound
// packets. It owns exactly two maximum-sized buffers and starts no goroutines.
// Overlapping Read, Write, Submit, or Receive calls of the same kind are rejected
// with ErrPacketPortBusy. Acknowledge and Close serialize under the state lock.
// A second Receive is rejected while a delivered packet awaits completion.
// Construct with NewPacketPortV1 and do not copy a port after first use.
type PacketPortV1 struct {
	mu      sync.Mutex
	changed chan struct{}
	closed  bool
	failure error
	maximum int

	outbound []byte
	inbound  []byte
	outBytes int
	inBytes  int
	token    PacketDeliveryTokenV1
	received bool
	acked    bool

	reading    bool
	writing    bool
	submitting bool
	receiving  bool
	production *productionPacketAdmissionV1
	outFlow    productionFlowRefV1
}

var _ io.ReadWriteCloser = (*PacketPortV1)(nil)

// NewPacketPortV1 accepts maximum packet lengths from 40 through 65535 bytes.
// The port preserves framing but does not validate IP or grant network authority.
func NewPacketPortV1(maxPacketBytes int) (*PacketPortV1, error) {
	if maxPacketBytes < 40 || maxPacketBytes > 65535 {
		return nil, ErrPacketPortConfig
	}
	return &PacketPortV1{
		maximum: maxPacketBytes, changed: make(chan struct{}),
		outbound: make([]byte, maxPacketBytes), inbound: make([]byte, maxPacketBytes),
	}, nil
}

// Submit synchronously copies a nonempty packet into the sole outbound slot.
// It waits for capacity without copying or retaining input after return. The
// caller must not mutate input while Submit runs. Cancellation leaves any
// previously queued packet intact and does not close the port.
func (p *PacketPortV1) Submit(ctx context.Context, input []byte) error {
	if err := p.beginV1(&p.submitting); err != nil {
		return err
	}
	defer p.endV1(&p.submitting)
	if len(input) == 0 || len(input) > p.maximum {
		return ErrPacketPortPacket
	}
	for {
		if p.closed {
			return io.ErrClosedPipe
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if p.outBytes == 0 {
			if p.production != nil {
				ref, err := p.production.reserveV1(input)
				if err != nil {
					return err
				}
				p.outFlow = ref
			}
			p.outBytes = copy(p.outbound, input)
			p.notifyV1()
			return nil
		}
		p.waitV1(ctx)
	}
}

// Read returns one complete outbound packet. A short buffer leaves the packet
// queued and unchanged. Close unblocks a waiting Read with io.ErrClosedPipe.
func (p *PacketPortV1) Read(output []byte) (int, error) {
	if err := p.beginV1(&p.reading); err != nil {
		return 0, err
	}
	defer p.endV1(&p.reading)
	if p.production != nil {
		return 0, ServiceInvalidRequestV1
	}
	if len(output) == 0 {
		return 0, io.ErrShortBuffer
	}
	for {
		if p.closed {
			return 0, io.ErrClosedPipe
		}
		if p.outBytes != 0 {
			if len(output) < p.outBytes {
				return 0, io.ErrShortBuffer
			}
			n := copy(output, p.outbound[:p.outBytes])
			clear(p.outbound[:p.outBytes])
			p.outBytes = 0
			p.notifyV1()
			return n, nil
		}
		p.waitV1(context.Background())
	}
}

// The installed pump is the only consumer that may transfer the private
// reference. Bytes and the reference leave the port as one transaction.
func (p *PacketPortV1) readProductionV1(output []byte, a *productionPacketAdmissionV1) (int, productionFlowRefV1, error) {
	if err := p.beginV1(&p.reading); err != nil {
		return 0, productionFlowRefV1{}, err
	}
	defer p.endV1(&p.reading)
	if a == nil || p.production != a {
		return 0, productionFlowRefV1{}, ServiceInvalidRequestV1
	}
	if len(output) == 0 {
		return 0, productionFlowRefV1{}, io.ErrShortBuffer
	}
	for {
		if p.closed {
			return 0, productionFlowRefV1{}, io.ErrClosedPipe
		}
		if p.outBytes != 0 {
			if len(output) < p.outBytes {
				return 0, productionFlowRefV1{}, io.ErrShortBuffer
			}
			n := copy(output, p.outbound[:p.outBytes])
			r := p.outFlow
			clear(p.outbound[:p.outBytes])
			p.outBytes = 0
			p.outFlow = productionFlowRefV1{}
			p.notifyV1()
			return n, r, nil
		}
		p.waitV1(context.Background())
	}
}

// Write returns success only after Receive and an exact successful Acknowledge.
// This keeps the pump's existing replay-commit point after destination delivery.
// Close or a failed acknowledgment unblocks Write without a partial success.
func (p *PacketPortV1) Write(input []byte) (int, error) {
	if err := p.beginV1(&p.writing); err != nil {
		return 0, err
	}
	defer p.endV1(&p.writing)
	if len(input) == 0 || len(input) > p.maximum {
		return 0, ErrPacketPortPacket
	}
	p.inBytes = copy(p.inbound, input)
	p.notifyV1()
	defer func() {
		clear(p.inbound)
		p.inBytes, p.token, p.received, p.acked = 0, 0, false, false
		p.notifyV1()
	}()
	for {
		// An acknowledgment linearized before Close remains a completed write.
		if p.acked {
			return len(input), nil
		}
		if p.closed {
			return 0, p.failure
		}
		p.waitV1(context.Background())
	}
}

// Receive copies one entire inbound packet and returns its nonzero receipt and
// exact length. It neither completes Write nor retains output. A short buffer
// or cancellation before receipt issuance leaves the packet available to retry.
// The caller owns delivery after success and must acknowledge it or close the
// port, even if its context is canceled immediately after Receive returns.
func (p *PacketPortV1) Receive(ctx context.Context, output []byte) (PacketDeliveryTokenV1, int, error) {
	if err := p.beginV1(&p.receiving); err != nil {
		return 0, 0, err
	}
	defer p.endV1(&p.receiving)
	if len(output) == 0 {
		return 0, 0, io.ErrShortBuffer
	}
	for {
		if p.closed {
			return 0, 0, io.ErrClosedPipe
		}
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		if p.received {
			return 0, 0, ErrPacketPortBusy
		}
		if p.inBytes != 0 {
			if len(output) < p.inBytes {
				return 0, 0, io.ErrShortBuffer
			}
			token, err := nextPacketPortTokenV1(&packetPortTokensV1)
			if err != nil {
				p.closeV1(err)
				return 0, 0, err
			}
			n := copy(output, p.inbound[:p.inBytes])
			p.token, p.received = token, true
			return token, n, nil
		}
		p.waitV1(ctx)
	}
}

// Acknowledge records the adapter's actual completed destination byte count and
// write error. Only an exact count with nil error completes Write successfully.
// A short/failed write closes the port with ErrPacketPortDelivery; external error
// details are never retained or exposed. Invalid receipts leave delivery intact.
// Cancellation of a valid acknowledgment closes the port, avoiding an orphaned
// native Write when the adapter can no longer confirm destination delivery.
func (p *PacketPortV1) Acknowledge(ctx context.Context, token PacketDeliveryTokenV1, completedBytes int, writeErr error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.changed == nil {
		return io.ErrClosedPipe
	}
	if token == 0 || token != p.token || !p.received || p.acked {
		return ErrPacketPortToken
	}
	if err := ctx.Err(); err != nil {
		p.closeV1(io.ErrClosedPipe)
		return err
	}
	if writeErr != nil || completedBytes != p.inBytes {
		p.closeV1(ErrPacketPortDelivery)
		return ErrPacketPortDelivery
	}
	clear(p.inbound[:p.inBytes])
	p.acked = true
	p.notifyV1()
	return nil
}

// Close is concurrent-safe and idempotent. It clears owned buffers after all
// active copies cease and wakes every blocked operation. Subsequent operations
// fail with io.ErrClosedPipe. A zero-value port is already unusable and closable.
func (p *PacketPortV1) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeV1(io.ErrClosedPipe)
	return nil
}

// beginV1/endV1 bracket an operation with mu held; waitV1 releases it while
// blocked. Packet copies are bounded by maximum. No mutex is held across waits
// or external callbacks. notifyV1 and closeV1 require mu to be held.
func (p *PacketPortV1) beginV1(active *bool) error {
	p.mu.Lock()
	if p.closed || p.changed == nil {
		p.mu.Unlock()
		return io.ErrClosedPipe
	}
	if *active {
		p.mu.Unlock()
		return ErrPacketPortBusy
	}
	*active = true
	return nil
}

func (p *PacketPortV1) endV1(active *bool) {
	*active = false
	if p.production != nil && p.closed {
		p.notifyV1()
	}
	p.mu.Unlock()
}

// Called after Close and outside installation/pump/table locks.
func (p *PacketPortV1) joinV1() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.reading || p.writing || p.submitting || p.receiving {
		p.waitV1(context.Background())
	}
}

func (p *PacketPortV1) waitV1(ctx context.Context) {
	changed := p.changed
	p.mu.Unlock()
	select {
	case <-changed:
	case <-ctx.Done():
	}
	p.mu.Lock()
}

func (p *PacketPortV1) notifyV1() {
	close(p.changed)
	p.changed = make(chan struct{})
}

func (p *PacketPortV1) closeV1(failure error) {
	if p.closed {
		return
	}
	p.closed, p.failure = true, failure
	if p.production != nil {
		p.production.releaseV1(p.outFlow)
		p.outFlow = productionFlowRefV1{}
	}
	clear(p.outbound)
	clear(p.inbound)
	p.outbound, p.inbound = nil, nil
	p.outBytes = 0
	if p.changed != nil {
		p.notifyV1()
	}
}

func nextPacketPortTokenV1(counter *atomic.Uint64) (PacketDeliveryTokenV1, error) {
	for {
		previous := counter.Load()
		if previous == math.MaxUint64 {
			return 0, ErrPacketPortTokenExhausted
		}
		if counter.CompareAndSwap(previous, previous+1) {
			return PacketDeliveryTokenV1(previous + 1), nil
		}
	}
}
