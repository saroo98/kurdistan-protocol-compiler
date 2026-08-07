// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"kurdistan/internal/protocol/framing"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/wirev1"
)

var (
	ErrPacketPumpConfig = errors.New("packet_pump_config")
	ErrPacketPumpIO     = errors.New("packet_pump_io")
	ErrPacketQueueFull  = errors.New("packet_queue_full")
)

type PacketPumpConfigV1 struct {
	TUN           io.ReadWriteCloser
	Carrier       io.ReadWriteCloser
	Endpoint      ProcessDuplexEndpointV1
	Program       liveprogram.ProgramV1
	Direction     DirectionV1
	AssignedIPv4  [4]byte
	AssignedIPv6  [16]byte
	QueuePackets  uint16
	IncompleteOps uint16
	BufferBudget  uint64
	IdleTimeout   time.Duration
}

type PacketPumpV1 struct {
	config    PacketPumpConfigV1
	maxPacket int
	maxRecord int
	closed    chan struct{}
	closeOnce sync.Once
	stream    atomic.Uint32
	activity  atomic.Int64
}

func NewPacketPumpV1(config PacketPumpConfigV1) (*PacketPumpV1, error) {
	if config.TUN == nil || config.Carrier == nil || config.Endpoint == nil || liveprogram.ValidateV1(config.Program) != nil ||
		(config.Direction != DirectionClientV1 && config.Direction != DirectionRelayV1) || config.QueuePackets == 0 || config.IncompleteOps == 0 ||
		config.QueuePackets > uint16(config.Program.Stream.MaxConcurrentStreams) || config.IncompleteOps > uint16(config.Program.Scheduler.MaxInFlightFrames) || config.IdleTimeout <= 0 {
		return nil, ErrPacketPumpConfig
	}
	maxPacket := config.Program.Limits.MaxPayloadBytes
	if maxPacket > 65535 {
		maxPacket = 65535
	}
	if maxPacket < 40 || config.BufferBudget < uint64(maxPacket)*uint64(config.QueuePackets+config.IncompleteOps) {
		return nil, ErrPacketPumpConfig
	}
	maxRecord := int(config.BufferBudget)
	if maximum := wirev1.HeaderBytes + wirev1.MaxPayloadBytes; maxRecord > maximum {
		maxRecord = maximum
	}
	pump := &PacketPumpV1{config: config, maxPacket: maxPacket, maxRecord: maxRecord, closed: make(chan struct{})}
	pump.stream.Store(1)
	pump.activity.Store(time.Now().UnixNano())
	return pump, nil
}

func (pump *PacketPumpV1) Run(ctx context.Context) error {
	if pump == nil || pump.closed == nil {
		return ErrPacketPumpConfig
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	outbound := make(chan []byte, pump.config.QueuePackets)
	inbound := make(chan *AuthenticatedInnerFrameV1, pump.config.IncompleteOps)
	errorsOut := make(chan error, 5)
	go pump.readTUNV1(ctx, outbound, errorsOut)
	go pump.sealCarrierV1(ctx, outbound, errorsOut)
	go pump.readCarrierV1(ctx, inbound, errorsOut)
	go pump.writeTUNV1(ctx, inbound, errorsOut)
	go pump.watchIdleV1(ctx, errorsOut)
	select {
	case <-ctx.Done():
		_ = pump.Close()
		return ctx.Err()
	case <-pump.closed:
		return nil
	case err := <-errorsOut:
		_ = pump.Close()
		if errors.Is(err, io.EOF) || errors.Is(err, ErrLinkClosed) {
			return nil
		}
		return err
	}
}

func (pump *PacketPumpV1) Close() error {
	if pump == nil {
		return nil
	}
	var first error
	pump.closeOnce.Do(func() {
		close(pump.closed)
		pump.config.Endpoint.Abort()
		if err := pump.config.Carrier.Close(); err != nil {
			first = err
		}
		if err := pump.config.TUN.Close(); err != nil && first == nil {
			first = err
		}
	})
	return first
}

func (pump *PacketPumpV1) readTUNV1(ctx context.Context, output chan<- []byte, failures chan<- error) {
	buffer := make([]byte, pump.maxPacket)
	defer clear(buffer)
	for {
		count, err := pump.config.TUN.Read(buffer)
		if err != nil {
			pump.reportFailureV1(ctx, failures, fmt.Errorf("tun_read: %w", err))
			return
		}
		if count <= 0 || count > pump.maxPacket {
			pump.reportFailureV1(ctx, failures, fmt.Errorf("tun_read: %w", ErrPacketPumpIO))
			return
		}
		packet := append([]byte(nil), buffer[:count]...)
		pump.touchV1()
		if err := pump.validateOutboundPacketV1(packet); err != nil {
			clear(packet)
			pump.reportFailureV1(ctx, failures, fmt.Errorf("tun_outbound_validate: %w", err))
			return
		}
		select {
		case output <- packet:
		case <-ctx.Done():
			clear(packet)
			return
		case <-pump.closed:
			clear(packet)
			return
		default:
			clear(packet)
			pump.reportFailureV1(ctx, failures, fmt.Errorf("tun_outbound_queue: %w", ErrPacketQueueFull))
			return
		}
	}
}

func (pump *PacketPumpV1) sealCarrierV1(ctx context.Context, input <-chan []byte, failures chan<- error) {
	for {
		select {
		case packet := <-input:
			stream := pump.nextStreamV1()
			records, err := pump.config.Endpoint.SealOperation(framing.Operation{Semantic: "data", StreamID: stream, Sequence: uint64(stream), Payload: packet}, int64(stream))
			clear(packet)
			if err != nil {
				pump.reportFailureV1(ctx, failures, fmt.Errorf("seal: %w", err))
				return
			}
			for _, record := range records {
				err = writeBoundedRecordV1(pump.config.Carrier, record)
				clear(record)
				if err != nil {
					pump.reportFailureV1(ctx, failures, fmt.Errorf("carrier_write: %w", err))
					return
				}
				pump.touchV1()
			}
		case <-ctx.Done():
			return
		case <-pump.closed:
			return
		}
	}
}

func (pump *PacketPumpV1) readCarrierV1(ctx context.Context, output chan<- *AuthenticatedInnerFrameV1, failures chan<- error) {
	for {
		record, err := readBoundedCarrierRecordV1(pump.config.Carrier, pump.maxRecord)
		if err != nil {
			pump.reportFailureV1(ctx, failures, fmt.Errorf("carrier_read: %w", err))
			return
		}
		pump.touchV1()
		pending, err := pump.config.Endpoint.OpenFrame(record)
		clear(record)
		if err != nil {
			pump.reportFailureV1(ctx, failures, fmt.Errorf("record_open: %w", err))
			return
		}
		if pending == nil {
			continue
		}
		select {
		case output <- pending:
		case <-ctx.Done():
			_ = pending.Discard()
			return
		case <-pump.closed:
			_ = pending.Discard()
			return
		default:
			_ = pending.Discard()
			pump.reportFailureV1(ctx, failures, fmt.Errorf("authenticated_queue: %w", ErrPacketQueueFull))
			return
		}
	}
}

func (pump *PacketPumpV1) writeTUNV1(ctx context.Context, input <-chan *AuthenticatedInnerFrameV1, failures chan<- error) {
	for {
		select {
		case pending := <-input:
			operation := pending.Operation()
			if operation.Semantic != "data" || len(operation.Payload) == 0 {
				clear(operation.Payload)
				_ = pending.Discard()
				pump.reportFailureV1(ctx, failures, fmt.Errorf("inner_operation: %w", ErrPacketInvalid))
				return
			}
			var validateErr error
			if pump.config.Direction == DirectionClientV1 {
				_, validateErr = validateReturnIPPacketV1(operation.Payload, pump.config.AssignedIPv4, pump.config.AssignedIPv6)
			} else {
				_, validateErr = ValidateIPPacketV1(operation.Payload, DirectionRelayV1, pump.config.AssignedIPv4, pump.config.AssignedIPv6, pump.config.AssignedIPv4 != [4]byte{}, pump.config.AssignedIPv6 != [16]byte{})
			}
			if validateErr != nil {
				clear(operation.Payload)
				_ = pending.Discard()
				pump.reportFailureV1(ctx, failures, fmt.Errorf("inner_packet_validate: %w", validateErr))
				return
			}
			count, err := pump.config.TUN.Write(operation.Payload)
			clear(operation.Payload)
			if err != nil || count != len(operation.Payload) {
				_ = pending.Discard()
				pump.reportFailureV1(ctx, failures, fmt.Errorf("tun_write: %w", ErrPacketPumpIO))
				return
			}
			if err := pending.Commit(); err != nil {
				pump.reportFailureV1(ctx, failures, fmt.Errorf("replay_commit: %w", err))
				return
			}
			pump.touchV1()
		case <-ctx.Done():
			return
		case <-pump.closed:
			return
		}
	}
}

func (pump *PacketPumpV1) watchIdleV1(ctx context.Context, failures chan<- error) {
	interval := pump.config.IdleTimeout / 4
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			last := time.Unix(0, pump.activity.Load())
			if now.Sub(last) >= pump.config.IdleTimeout {
				pump.reportFailureV1(ctx, failures, ErrLinkFailure)
				return
			}
		case <-ctx.Done():
			return
		case <-pump.closed:
			return
		}
	}
}

func (pump *PacketPumpV1) touchV1() { pump.activity.Store(time.Now().UnixNano()) }

func (pump *PacketPumpV1) validateOutboundPacketV1(packet []byte) error {
	if pump.config.Direction == DirectionClientV1 {
		_, err := validateClientOutboundIPPacketV1(packet, pump.config.AssignedIPv4, pump.config.AssignedIPv6)
		return err
	}
	info, err := validateReturnIPPacketV1(packet, pump.config.AssignedIPv4, pump.config.AssignedIPv6)
	if err != nil {
		return err
	}
	if info.Version == 4 && (pump.config.AssignedIPv4 == [4]byte{} || info.dest != netipAddrFrom4V1(pump.config.AssignedIPv4)) {
		return ErrPacketDestination
	}
	if info.Version == 6 && (pump.config.AssignedIPv6 == [16]byte{} || info.dest != netipAddrFrom16V1(pump.config.AssignedIPv6)) {
		return ErrPacketDestination
	}
	return nil
}

func (pump *PacketPumpV1) nextStreamV1() uint32 {
	for {
		current := pump.stream.Add(1)
		if current > 0 && current < uint32(processControlSlotV1) {
			return current
		}
		pump.stream.Store(1)
	}
}

func writeBoundedRecordV1(writer io.Writer, record []byte) error {
	if len(record) == 0 || len(record) > wirev1.HeaderBytes+wirev1.MaxPayloadBytes {
		return ErrPacketPumpIO
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(record)))
	if err := writeFullV1(writer, header[:]); err != nil {
		return ErrPacketPumpIO
	}
	if err := writeFullV1(writer, record); err != nil {
		return ErrPacketPumpIO
	}
	return nil
}

func readBoundedCarrierRecordV1(reader io.ReadWriteCloser, maximum int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := uint64(binary.BigEndian.Uint32(header[:]))
	if length == 0 || length > uint64(maximum) {
		return nil, ErrPacketPumpIO
	}
	record := make([]byte, int(length))
	if _, err := io.ReadFull(reader, record); err != nil {
		clear(record)
		return nil, err
	}
	return record, nil
}

func writeFullV1(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		count, err := writer.Write(data)
		if err != nil {
			return err
		}
		if count <= 0 || count > len(data) {
			return io.ErrShortWrite
		}
		data = data[count:]
	}
	return nil
}

func (pump *PacketPumpV1) reportFailureV1(ctx context.Context, output chan<- error, err error) {
	select {
	case output <- err:
	case <-ctx.Done():
	case <-pump.closed:
	}
}

func netipAddrFrom4V1(value [4]byte) netip.Addr   { return netip.AddrFrom4(value) }
func netipAddrFrom16V1(value [16]byte) netip.Addr { return netip.AddrFrom16(value) }
