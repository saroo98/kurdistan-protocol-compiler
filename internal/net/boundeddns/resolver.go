// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package boundeddns owns bounded numeric-server DNS operations. It grants no
// destination authority and does not select platform or default resolvers.
package boundeddns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/net/dns/dnsmessage"
	"kurdistan/internal/product/runtimepolicy"
)

var ErrInvalidRequest = errors.New("bounded DNS invalid request")
var ErrInvalidState = errors.New("bounded DNS invalid state")
var ErrResourceLimit = errors.New("bounded DNS resource limit")
var ErrCancelled = errors.New("bounded DNS cancelled")
var ErrTimeout = errors.New("bounded DNS timeout")
var ErrNetwork = errors.New("bounded DNS network unavailable")

type FamilyMask uint8

const (
	IPv4 FamilyMask = 1
	IPv6 FamilyMask = 2
)

// SocketOwner is trusted constructor wiring. Numeric dial and platform network
// binding must honor the supplied context, including late-success cancellation.
type SocketOwner interface {
	DialUDP(context.Context, netip.AddrPort) (*net.UDPConn, error)
	DialTCP(context.Context, netip.AddrPort) (*net.TCPConn, error)
}

type operationSlot struct {
	used bool
	op   *operation
}

type Resolver struct {
	mu          sync.Mutex
	servers     [4]netip.AddrPort
	serverCount int
	owner       SocketOwner
	slots       []operationSlot
	active      int
	closed      bool
	done        chan struct{}
}

func NewResolver(servers []netip.AddrPort, owner SocketOwner, maxConcurrent int) (*Resolver, error) {
	if owner == nil || len(servers) < 1 || len(servers) > 4 || maxConcurrent < 1 || maxConcurrent > 16 {
		return nil, ErrInvalidRequest
	}
	for i, s := range servers {
		a := s.Addr()
		if !s.IsValid() || s.Port() == 0 || a.IsUnspecified() || a.IsMulticast() || a.Is4In6() || a.Zone() != "" {
			return nil, ErrInvalidRequest
		}
		for j := 0; j < i; j++ {
			if servers[j] == s {
				return nil, ErrInvalidRequest
			}
		}
	}
	r := &Resolver{serverCount: len(servers), owner: owner, slots: make([]operationSlot, maxConcurrent), done: make(chan struct{})}
	copy(r.servers[:], servers)
	return r, nil
}

func (r *Resolver) Close() error {
	if r == nil || r.done == nil {
		return nil
	}
	var operations [16]*operation
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		for i := range r.slots {
			operations[i] = r.slots[i].op
		}
		if r.active == 0 {
			close(r.done)
		}
	}
	r.mu.Unlock()
	for _, op := range operations {
		if op != nil {
			// Socket close belongs to the resolving worker and its joined
			// cancellation hook, so admission covers every closing actor.
			op.cancel()
		}
	}
	<-r.done
	return nil
}

func (r *Resolver) Done() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.done
}

const (
	// 254 malformed-input string headers occupy 4064 bytes on 64-bit;
	// the pinned scanned allocation, including its header, rounds to 4096.
	validatorCapacityBytes = 4096
	// Bounded operation-created context/timer/stop/channel/socket-wrapper
	// metadata. This is not an accounting of opaque netFD or runtime stacks.
	operationMetadataBytes = 4096
	fixedMetadataBytes     = 256 // Done channel and fixed Close snapshot holders.
)

// parserScratch conservatively inventories overlapping typed return values and
// copies in the maintained Parser/Builder call chain. These are not extra
// retained records or a payload queue. In particular SOA has two Name fields.
type parserScratch struct {
	parsers   [4]dnsmessage.Parser
	builder   dnsmessage.Builder
	questions [2]dnsmessage.Question
	resources [3]dnsmessage.ResourceHeader
	soa       [2]dnsmessage.SOAResource
	cname     dnsmessage.CNAMEResource
	ns        dnsmessage.NSResource
	names     [6]dnsmessage.Name
	addresses [4]netip.Addr
	header    dnsmessage.Header
	a         dnsmessage.AResource
	aaaa      dnsmessage.AAAAResource
}

// OperationOwnedBytes is reserved by each fixed admission slot before any
// allocating grammar check, workspace copy, context or callback setup. The
// containing service must also charge this reservation before launching calls.
// Caller output, opaque net runtime, OS buffers and Go heap/GC/RSS are excluded.
func (r *Resolver) OperationOwnedBytes() uint64 {
	return uint64(unsafe.Sizeof(workspace{})) + uint64(unsafe.Sizeof(operation{})) +
		uint64(unsafe.Sizeof(parserScratch{})) + validatorCapacityBytes + operationMetadataBytes
}

// FixedOwnedBytes belongs to the owning server/platform once, independently of
// active operation reservations. Slots never grow and Close does not free them.
func (r *Resolver) FixedOwnedBytes() uint64 {
	if r == nil {
		return 0
	}
	return uint64(unsafe.Sizeof(Resolver{})) + uint64(len(r.slots))*uint64(unsafe.Sizeof(operationSlot{})) + fixedMetadataBytes
}

func (r *Resolver) reserve() (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, ErrInvalidState
	}
	for i := range r.slots {
		if !r.slots[i].used {
			r.slots[i].used = true
			r.active++
			return i, nil
		}
	}
	return 0, ErrResourceLimit
}

func (r *Resolver) release(index int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.slots[index] = operationSlot{}
	r.active--
	if r.closed && r.active == 0 {
		close(r.done)
	}
}

// ResolveInto runs synchronously in the caller's owned worker. A slot reserves
// its complete fixed operation inventory before grammar allocation or copies.
// Output is cleared on every failure, and remains caller-owned throughout.
func (r *Resolver) ResolveInto(parent context.Context, domain string, family FamilyMask, output *[16]netip.Addr) (int, error) {
	if output != nil {
		clear(output[:])
	}
	if r == nil || r.done == nil {
		return 0, ErrInvalidState
	}
	if parent == nil || output == nil || family < IPv4 || family > IPv4|IPv6 || len(domain) < 1 || len(domain) > 253 {
		return 0, ErrInvalidRequest
	}
	deadline, ok := parent.Deadline()
	if !ok {
		return 0, ErrInvalidRequest
	}
	if err := contextError(parent); err != nil {
		return 0, err
	}
	if !deadline.After(time.Now()) {
		return 0, ErrTimeout
	}
	index, err := r.reserve()
	if err != nil {
		return 0, err
	}
	defer r.release(index)
	// This existing shared grammar helper allocates Split's bounded backing.
	if !runtimepolicy.IsCanonicalProxyDomain(domain) {
		return 0, ErrInvalidRequest
	}
	w := new(workspace)
	defer w.clear()
	copy(w.names[0].Data[:], domain)
	w.names[0].Data[len(domain)] = '.'
	w.names[0].Length = uint8(len(domain) + 1)
	if maximum := time.Now().Add(5 * time.Second); maximum.Before(deadline) {
		deadline = maximum
	}
	op := newOperation(parent, deadline)
	r.mu.Lock()
	if r.closed {
		err = ErrInvalidState
	} else {
		r.slots[index].op = op
	}
	r.mu.Unlock()
	if err == nil {
		err = r.resolve(op, w, family)
	}
	if cancelled := contextError(op.ctx); cancelled != nil {
		err = cancelled
	}
	op.finish()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, ErrInvalidState
	}
	if cancelled := contextError(parent); cancelled != nil {
		return 0, cancelled
	}
	if !deadline.After(time.Now()) {
		return 0, ErrTimeout
	}
	if err != nil {
		return 0, err
	}
	copy(output[:], w.results[:w.count])
	return w.count, nil
}

func (r *Resolver) resolve(op *operation, w *workspace, family FamilyMask) error {
	var last error
	for server := 0; server < min(r.serverCount, 2); server++ {
		clear(w.results[:])
		w.count = 0
		last = nil
		for _, f := range [...]struct {
			mask FamilyMask
			kind dnsmessage.Type
		}{{IPv4, dnsmessage.TypeA}, {IPv6, dnsmessage.TypeAAAA}} {
			if family&f.mask == 0 {
				continue
			}
			if err := contextError(op.ctx); err != nil {
				return err
			}
			clear(w.names[1:])
			query, id, err := w.buildQuery(f.kind)
			if err == nil {
				err = op.exchange(r.owner, r.servers[server], w, query, f.kind, id)
			}
			if err != nil {
				last = err
				break
			}
		}
		if last == nil {
			if w.count > 0 {
				return nil
			}
			last = ErrNoData
		}
		if last == ErrCancelled || last == ErrTimeout {
			return last
		}
	}
	return last
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return ErrTimeout
		}
		return ErrCancelled
	}
	// Timer callbacks may be scheduled after the absolute deadline. Socket
	// and post-parser/publication fences must not rely on that scheduling.
	if deadline, ok := ctx.Deadline(); ok && !deadline.After(time.Now()) {
		return ErrTimeout
	}
	return nil
}
