// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
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

type PacketPumpStageV1 string

type PacketPumpTUNWriteFailureCodeV1 string

const (
	PacketPumpStageTUNReadV1            PacketPumpStageV1 = "tun_read"
	PacketPumpStageTUNValidateV1        PacketPumpStageV1 = "tun_validate"
	PacketPumpStageOutboundQueueV1      PacketPumpStageV1 = "outbound_queue"
	PacketPumpStageSealV1               PacketPumpStageV1 = "seal"
	PacketPumpStageCarrierWriteV1       PacketPumpStageV1 = "carrier_write"
	PacketPumpStageCarrierReadV1        PacketPumpStageV1 = "carrier_read"
	PacketPumpStageRecordOpenV1         PacketPumpStageV1 = "record_open"
	PacketPumpStageAuthenticatedQueueV1 PacketPumpStageV1 = "authenticated_queue"
	PacketPumpStageInnerOperationV1     PacketPumpStageV1 = "inner_operation"
	PacketPumpStageInnerValidateV1      PacketPumpStageV1 = "inner_validate"
	PacketPumpStageTUNWriteV1           PacketPumpStageV1 = "tun_write"
	PacketPumpStageReplayCommitV1       PacketPumpStageV1 = "replay_commit"
	PacketPumpStageIdleV1               PacketPumpStageV1 = "idle"
)

const (
	PacketPumpTUNWriteFailureNoneV1        PacketPumpTUNWriteFailureCodeV1 = "none"
	PacketPumpTUNWriteFailureShortV1       PacketPumpTUNWriteFailureCodeV1 = "short"
	PacketPumpTUNWriteFailureClosedV1      PacketPumpTUNWriteFailureCodeV1 = "closed"
	PacketPumpTUNWriteFailureInterruptedV1 PacketPumpTUNWriteFailureCodeV1 = "interrupted"
	PacketPumpTUNWriteFailureInvalidV1     PacketPumpTUNWriteFailureCodeV1 = "invalid"
	PacketPumpTUNWriteFailureNoBufferV1    PacketPumpTUNWriteFailureCodeV1 = "no-buffer"
	PacketPumpTUNWriteFailurePermissionV1  PacketPumpTUNWriteFailureCodeV1 = "permission"
	PacketPumpTUNWriteFailureIOV1          PacketPumpTUNWriteFailureCodeV1 = "io"
	PacketPumpTUNWriteFailureOtherV1       PacketPumpTUNWriteFailureCodeV1 = "other"
)

const (
	packetPumpTUNWriteFailureNoneCodeV1 uint32 = iota
	packetPumpTUNWriteFailureShortCodeV1
	packetPumpTUNWriteFailureClosedCodeV1
	packetPumpTUNWriteFailureInterruptedCodeV1
	packetPumpTUNWriteFailureInvalidCodeV1
	packetPumpTUNWriteFailureNoBufferCodeV1
	packetPumpTUNWriteFailurePermissionCodeV1
	packetPumpTUNWriteFailureIOCodeV1
	packetPumpTUNWriteFailureOtherCodeV1
)

type packetPumpFailureV1 struct {
	stage PacketPumpStageV1
	cause error
}

func (failure *packetPumpFailureV1) Error() string {
	if failure == nil {
		return "packet_pump_failure"
	}
	return "packet_pump_" + string(failure.stage)
}

func (failure *packetPumpFailureV1) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

func newPacketPumpFailureV1(stage PacketPumpStageV1, cause error) error {
	if cause == nil {
		cause = ErrPacketPumpIO
	}
	return &packetPumpFailureV1{stage: stage, cause: cause}
}

func PacketPumpFailureStageV1(err error) (PacketPumpStageV1, bool) {
	var failure *packetPumpFailureV1
	if !errors.As(err, &failure) || failure == nil {
		return "", false
	}
	return failure.stage, true
}

const (
	maxRejectedTUNPacketsV1    = 16
	maximumPacketQueueV1       = 256
	maximumIncompletePacketsV1 = 64
)

type PacketRejectionCodeV1 uint32

const (
	PacketRejectionNoneV1 PacketRejectionCodeV1 = iota
	PacketRejectionInvalidV1
	PacketRejectionFamilyV1
	PacketRejectionProtocolV1
	PacketRejectionSourceV1
	PacketRejectionDestinationV1
	PacketRejectionFragmentedV1
)

type PacketPumpConfigV1 struct {
	TUN           io.ReadWriteCloser
	Carrier       io.ReadWriteCloser
	Endpoint      ProcessDuplexEndpointV1
	Program       liveprogram.ProgramV1
	Direction     DirectionV1
	AssignedIPv4  [4]byte
	DNSIPv4       [4]byte
	AssignedIPv6  [16]byte
	DNSIPv6       [16]byte
	QueuePackets  uint16
	IncompleteOps uint16
	BufferBudget  uint64
	IdleTimeout   time.Duration
}

type PacketPumpV1 struct {
	config                  PacketPumpConfigV1
	maxPacket               int
	maxRecord               int
	closed                  chan struct{}
	closeOnce               sync.Once
	stream                  atomic.Uint32
	activity                atomic.Int64
	rejected                atomic.Uint32
	tunPacketsRead          atomic.Uint64
	outboundPacketsAccepted atomic.Uint64
	carrierRecordsWritten   atomic.Uint64
	carrierRecordsRead      atomic.Uint64
	authenticatedOperations atomic.Uint64
	innerPacketsAccepted    atomic.Uint64
	innerPacketsRejected    atomic.Uint64
	tunWriteAttempts        atomic.Uint64
	tunWriteFailures        atomic.Uint64
	tunWriteFailureCode     atomic.Uint32
	tunWriteErrno           atomic.Uint32
	tunPacketsWritten       atomic.Uint64
	rejectedTUNPackets      atomic.Uint64
	rejectedTUNPacketCode   atomic.Uint32
	relayGatewayDNSPackets  atomic.Uint64
	relayDNSChecksumFailed  atomic.Uint64
	relayTransportMalformed atomic.Uint64
	relayReturnTCPPackets   atomic.Uint64
	relayReturnTCPSYN       atomic.Uint64
	relayReturnTCPACK       atomic.Uint64
	relayReturnTCPRST       atomic.Uint64
	relayReturnTCPFIN       atomic.Uint64
	relayReturnTCPChecksum  atomic.Uint64
	relayReturnOversize     atomic.Uint64
}

type PacketPumpSnapshotV1 struct {
	TUNPacketsRead                  uint64
	OutboundPacketsAccepted         uint64
	CarrierRecordsWritten           uint64
	CarrierRecordsRead              uint64
	AuthenticatedOperations         uint64
	InnerPacketsAccepted            uint64
	InnerPacketsRejected            uint64
	TUNWriteAttempts                uint64
	TUNWriteFailures                uint64
	TUNWriteFailureCode             PacketPumpTUNWriteFailureCodeV1
	TUNWriteErrno                   uint32
	TUNPacketsWritten               uint64
	RejectedTUNPackets              uint64
	RejectedTUNPacketCode           PacketRejectionCodeV1
	RelayGatewayDNSPackets          uint64
	RelayGatewayDNSChecksumFailures uint64
	RelayTransportMalformedPackets  uint64
	RelayReturnTCPPackets           uint64
	RelayReturnTCPSYNPackets        uint64
	RelayReturnTCPACKPackets        uint64
	RelayReturnTCPRSTPackets        uint64
	RelayReturnTCPFINPackets        uint64
	RelayReturnTCPChecksumFailures  uint64
	RelayReturnOversizePackets      uint64
}

type authenticatedPacketV1 struct {
	frame     *AuthenticatedInnerFrameV1
	completed chan error
}

func NewPacketPumpV1(config PacketPumpConfigV1) (*PacketPumpV1, error) {
	if config.TUN == nil || config.Carrier == nil || config.Endpoint == nil || liveprogram.ValidateV1(config.Program) != nil ||
		(config.Direction != DirectionClientV1 && config.Direction != DirectionRelayV1) || config.QueuePackets == 0 || config.IncompleteOps == 0 ||
		config.QueuePackets > maximumPacketQueueV1 || config.IncompleteOps > maximumIncompletePacketsV1 || config.IdleTimeout <= 0 ||
		!validPacketPumpAddressAuthorityV1(config.AssignedIPv4, config.DNSIPv4, config.AssignedIPv6, config.DNSIPv6) {
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

func validPacketPumpAddressAuthorityV1(assignedIPv4, dnsIPv4 [4]byte, assignedIPv6, dnsIPv6 [16]byte) bool {
	hasIPv4 := assignedIPv4 != [4]byte{}
	hasIPv6 := assignedIPv6 != [16]byte{}
	if !hasIPv4 && !hasIPv6 || hasIPv4 != (dnsIPv4 != [4]byte{}) || hasIPv6 != (dnsIPv6 != [16]byte{}) {
		return false
	}
	return (!hasIPv4 || assignedIPv4 != dnsIPv4) && (!hasIPv6 || assignedIPv6 != dnsIPv6)
}

func (pump *PacketPumpV1) Run(ctx context.Context) error {
	if pump == nil || pump.closed == nil {
		return ErrPacketPumpConfig
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	outbound := make(chan []byte, pump.config.QueuePackets)
	inbound := make(chan authenticatedPacketV1, pump.config.IncompleteOps)
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

func (pump *PacketPumpV1) SnapshotV1() PacketPumpSnapshotV1 {
	if pump == nil {
		return PacketPumpSnapshotV1{}
	}
	return PacketPumpSnapshotV1{
		TUNPacketsRead:                  pump.tunPacketsRead.Load(),
		OutboundPacketsAccepted:         pump.outboundPacketsAccepted.Load(),
		CarrierRecordsWritten:           pump.carrierRecordsWritten.Load(),
		CarrierRecordsRead:              pump.carrierRecordsRead.Load(),
		AuthenticatedOperations:         pump.authenticatedOperations.Load(),
		InnerPacketsAccepted:            pump.innerPacketsAccepted.Load(),
		InnerPacketsRejected:            pump.innerPacketsRejected.Load(),
		TUNWriteAttempts:                pump.tunWriteAttempts.Load(),
		TUNWriteFailures:                pump.tunWriteFailures.Load(),
		TUNWriteFailureCode:             packetPumpTUNWriteFailureCodeV1(pump.tunWriteFailureCode.Load()),
		TUNWriteErrno:                   pump.tunWriteErrno.Load(),
		TUNPacketsWritten:               pump.tunPacketsWritten.Load(),
		RejectedTUNPackets:              pump.rejectedTUNPackets.Load(),
		RejectedTUNPacketCode:           PacketRejectionCodeV1(pump.rejectedTUNPacketCode.Load()),
		RelayGatewayDNSPackets:          pump.relayGatewayDNSPackets.Load(),
		RelayGatewayDNSChecksumFailures: pump.relayDNSChecksumFailed.Load(),
		RelayTransportMalformedPackets:  pump.relayTransportMalformed.Load(),
		RelayReturnTCPPackets:           pump.relayReturnTCPPackets.Load(),
		RelayReturnTCPSYNPackets:        pump.relayReturnTCPSYN.Load(),
		RelayReturnTCPACKPackets:        pump.relayReturnTCPACK.Load(),
		RelayReturnTCPRSTPackets:        pump.relayReturnTCPRST.Load(),
		RelayReturnTCPFINPackets:        pump.relayReturnTCPFIN.Load(),
		RelayReturnTCPChecksumFailures:  pump.relayReturnTCPChecksum.Load(),
		RelayReturnOversizePackets:      pump.relayReturnOversize.Load(),
	}
}

func (pump *PacketPumpV1) readTUNV1(ctx context.Context, output chan<- []byte, failures chan<- error) {
	buffer := make([]byte, pump.maxPacket)
	defer clear(buffer)
	for {
		count, err := pump.config.TUN.Read(buffer)
		if err != nil {
			pump.reportFailureV1(ctx, failures, newPacketPumpFailureV1(PacketPumpStageTUNReadV1, err))
			return
		}
		if count <= 0 || count > pump.maxPacket {
			pump.reportFailureV1(ctx, failures, newPacketPumpFailureV1(PacketPumpStageTUNReadV1, ErrPacketPumpIO))
			return
		}
		pump.tunPacketsRead.Add(1)
		packet := append([]byte(nil), buffer[:count]...)
		pump.touchV1()
		if pump.config.Direction == DirectionRelayV1 {
			pump.recordRelayReturnTransportV1(packet)
		}
		if err := pump.validateOutboundPacketV1(packet); err != nil {
			clear(packet)
			pump.rejectedTUNPackets.Add(1)
			pump.rejectedTUNPacketCode.Store(uint32(packetRejectionCodeV1(err)))
			if pump.rejected.Add(1) > maxRejectedTUNPacketsV1 {
				pump.reportFailureV1(ctx, failures, newPacketPumpFailureV1(PacketPumpStageTUNValidateV1, err))
				return
			}
			continue
		}
		pump.rejected.Store(0)
		pump.outboundPacketsAccepted.Add(1)
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
			pump.reportFailureV1(ctx, failures, newPacketPumpFailureV1(PacketPumpStageOutboundQueueV1, ErrPacketQueueFull))
			return
		}
	}
}

func packetRejectionCodeV1(err error) PacketRejectionCodeV1 {
	switch {
	case errors.Is(err, ErrPacketFamily):
		return PacketRejectionFamilyV1
	case errors.Is(err, ErrPacketProtocol):
		return PacketRejectionProtocolV1
	case errors.Is(err, ErrPacketSource):
		return PacketRejectionSourceV1
	case errors.Is(err, ErrPacketDestination):
		return PacketRejectionDestinationV1
	case errors.Is(err, ErrPacketFragmented):
		return PacketRejectionFragmentedV1
	default:
		return PacketRejectionInvalidV1
	}
}

func (pump *PacketPumpV1) recordRelayReturnTransportV1(packet []byte) {
	classification := classifyRelayReturnTransportV1(packet)
	if classification.PacketBytes > 1280 {
		pump.relayReturnOversize.Add(1)
	}
	if !classification.TCP {
		return
	}
	pump.relayReturnTCPPackets.Add(1)
	if classification.SYN {
		pump.relayReturnTCPSYN.Add(1)
	}
	if classification.ACK {
		pump.relayReturnTCPACK.Add(1)
	}
	if classification.RST {
		pump.relayReturnTCPRST.Add(1)
	}
	if classification.FIN {
		pump.relayReturnTCPFIN.Add(1)
	}
	if !classification.Malformed && !classification.ChecksumValid {
		pump.relayReturnTCPChecksum.Add(1)
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
				pump.reportFailureV1(ctx, failures, newPacketPumpFailureV1(PacketPumpStageSealV1, err))
				return
			}
			for _, record := range records {
				err = writeBoundedRecordV1(pump.config.Carrier, record)
				clear(record)
				if err != nil {
					pump.reportFailureV1(ctx, failures, newPacketPumpFailureV1(PacketPumpStageCarrierWriteV1, err))
					return
				}
				pump.carrierRecordsWritten.Add(1)
				pump.touchV1()
			}
		case <-ctx.Done():
			return
		case <-pump.closed:
			return
		}
	}
}

func (pump *PacketPumpV1) readCarrierV1(ctx context.Context, output chan<- authenticatedPacketV1, failures chan<- error) {
	for {
		record, err := readBoundedCarrierRecordV1(pump.config.Carrier, pump.maxRecord)
		if err != nil {
			pump.reportFailureV1(ctx, failures, newPacketPumpFailureV1(PacketPumpStageCarrierReadV1, err))
			return
		}
		pump.carrierRecordsRead.Add(1)
		pump.touchV1()
		pending, err := pump.config.Endpoint.OpenFrame(record)
		clear(record)
		if err != nil {
			pump.reportFailureV1(ctx, failures, newPacketPumpFailureV1(PacketPumpStageRecordOpenV1, err))
			return
		}
		if pending == nil {
			continue
		}
		pump.authenticatedOperations.Add(1)
		packet := authenticatedPacketV1{frame: pending, completed: make(chan error, 1)}
		select {
		case output <- packet:
		case <-ctx.Done():
			_ = pending.Discard()
			return
		case <-pump.closed:
			_ = pending.Discard()
			return
		default:
			_ = pending.Discard()
			pump.reportFailureV1(ctx, failures, newPacketPumpFailureV1(PacketPumpStageAuthenticatedQueueV1, ErrPacketQueueFull))
			return
		}
		select {
		case err := <-packet.completed:
			if err != nil {
				return
			}
		case <-ctx.Done():
			return
		case <-pump.closed:
			return
		}
	}
}

func (pump *PacketPumpV1) writeTUNV1(ctx context.Context, input <-chan authenticatedPacketV1, failures chan<- error) {
	for {
		select {
		case packet := <-input:
			pending := packet.frame
			operation := pending.Operation()
			if operation.Semantic != "data" || len(operation.Payload) == 0 {
				clear(operation.Payload)
				_ = pending.Discard()
				err := newPacketPumpFailureV1(PacketPumpStageInnerOperationV1, ErrPacketInvalid)
				packet.completed <- err
				pump.reportFailureV1(ctx, failures, err)
				return
			}
			var validateErr error
			if pump.config.Direction == DirectionClientV1 {
				_, validateErr = validateReturnIPPacketV1(operation.Payload, pump.config.AssignedIPv4, pump.config.AssignedIPv6)
			} else {
				_, validateErr = ValidateRelayOutboundIPPacketV1(operation.Payload, pump.config.AssignedIPv4, pump.config.DNSIPv4, pump.config.AssignedIPv6, pump.config.DNSIPv6)
			}
			if validateErr != nil {
				pump.innerPacketsRejected.Add(1)
				clear(operation.Payload)
				_ = pending.Discard()
				err := newPacketPumpFailureV1(PacketPumpStageInnerValidateV1, validateErr)
				packet.completed <- err
				pump.reportFailureV1(ctx, failures, err)
				return
			}
			pump.innerPacketsAccepted.Add(1)
			if pump.config.Direction == DirectionRelayV1 {
				classification := classifyRelayTransportV1(operation.Payload, pump.config.DNSIPv4, pump.config.DNSIPv6)
				if classification.GatewayDNS {
					pump.relayGatewayDNSPackets.Add(1)
					if !classification.ChecksumValid {
						pump.relayDNSChecksumFailed.Add(1)
					}
				}
				if classification.Malformed {
					pump.relayTransportMalformed.Add(1)
				}
			}
			pump.tunWriteAttempts.Add(1)
			payloadLength := len(operation.Payload)
			count, err := pump.config.TUN.Write(operation.Payload)
			clear(operation.Payload)
			if err != nil || count != payloadLength {
				pump.tunWriteFailures.Add(1)
				failureCode, errno := classifyPacketPumpTUNWriteFailureV1(count, payloadLength, err)
				pump.tunWriteFailureCode.Store(failureCode)
				pump.tunWriteErrno.Store(errno)
				_ = pending.Discard()
				err = newPacketPumpFailureV1(PacketPumpStageTUNWriteV1, ErrPacketPumpIO)
				packet.completed <- err
				pump.reportFailureV1(ctx, failures, err)
				return
			}
			pump.tunPacketsWritten.Add(1)
			if err := pending.Commit(); err != nil {
				packet.completed <- err
				pump.reportFailureV1(ctx, failures, newPacketPumpFailureV1(PacketPumpStageReplayCommitV1, err))
				return
			}
			packet.completed <- nil
			pump.touchV1()
		case <-ctx.Done():
			return
		case <-pump.closed:
			return
		}
	}
}

func classifyPacketPumpTUNWriteFailureV1(count, expected int, err error) (uint32, uint32) {
	if err == nil {
		if count != expected {
			return packetPumpTUNWriteFailureShortCodeV1, 0
		}
		return packetPumpTUNWriteFailureNoneCodeV1, 0
	}
	var errno syscall.Errno
	_ = errors.As(err, &errno)
	number := uint32(errno)
	switch {
	case errors.Is(err, os.ErrClosed), errors.Is(err, io.ErrClosedPipe), errors.Is(err, syscall.EBADF):
		return packetPumpTUNWriteFailureClosedCodeV1, number
	case errors.Is(err, syscall.EINTR):
		return packetPumpTUNWriteFailureInterruptedCodeV1, number
	case errors.Is(err, syscall.EINVAL):
		return packetPumpTUNWriteFailureInvalidCodeV1, number
	case errors.Is(err, syscall.ENOBUFS):
		return packetPumpTUNWriteFailureNoBufferCodeV1, number
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return packetPumpTUNWriteFailurePermissionCodeV1, number
	case errors.Is(err, syscall.EIO):
		return packetPumpTUNWriteFailureIOCodeV1, number
	default:
		return packetPumpTUNWriteFailureOtherCodeV1, number
	}
}

func packetPumpTUNWriteFailureCodeV1(code uint32) PacketPumpTUNWriteFailureCodeV1 {
	switch code {
	case packetPumpTUNWriteFailureShortCodeV1:
		return PacketPumpTUNWriteFailureShortV1
	case packetPumpTUNWriteFailureClosedCodeV1:
		return PacketPumpTUNWriteFailureClosedV1
	case packetPumpTUNWriteFailureInterruptedCodeV1:
		return PacketPumpTUNWriteFailureInterruptedV1
	case packetPumpTUNWriteFailureInvalidCodeV1:
		return PacketPumpTUNWriteFailureInvalidV1
	case packetPumpTUNWriteFailureNoBufferCodeV1:
		return PacketPumpTUNWriteFailureNoBufferV1
	case packetPumpTUNWriteFailurePermissionCodeV1:
		return PacketPumpTUNWriteFailurePermissionV1
	case packetPumpTUNWriteFailureIOCodeV1:
		return PacketPumpTUNWriteFailureIOV1
	case packetPumpTUNWriteFailureOtherCodeV1:
		return PacketPumpTUNWriteFailureOtherV1
	default:
		return PacketPumpTUNWriteFailureNoneV1
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
				pump.reportFailureV1(ctx, failures, newPacketPumpFailureV1(PacketPumpStageIdleV1, ErrLinkFailure))
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
		_, err := validateClientOutboundIPPacketV1(packet, pump.config.AssignedIPv4, pump.config.DNSIPv4, pump.config.AssignedIPv6, pump.config.DNSIPv6)
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
