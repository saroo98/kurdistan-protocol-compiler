// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	kruntime "kurdistan/internal/runtime"
)

var (
	ErrRegistryConfig   = errors.New("relay node: invalid registry configuration")
	ErrRegistryClosed   = errors.New("relay node: session registry closed")
	ErrSessionLimit     = errors.New("relay node: session capacity reached")
	ErrSessionConflict  = errors.New("relay node: session authority conflict")
	ErrSessionQueueFull = errors.New("relay node: session queue full")
	ErrPacketRejected   = errors.New("relay node: packet rejected")
)

type SessionSpec struct {
	ID, ProfileID, ClientKeyID string
	AssignedIPv4               [4]byte
	DNSIPv4                    [4]byte
	AssignedIPv6               [16]byte
	DNSIPv6                    [16]byte
	Cancel                     context.CancelFunc
}

type RegistrySnapshot struct {
	ActiveSessions, QueueDrops, UnknownDestinations, StoppedSessions uint64
}

type SessionStopCodeV1 string

const (
	SessionStopNoneV1     SessionStopCodeV1 = ""
	SessionStopLocalV1    SessionStopCodeV1 = "local"
	SessionStopQueueV1    SessionStopCodeV1 = "queue"
	SessionStopProfileV1  SessionStopCodeV1 = "profile"
	SessionStopAllV1      SessionStopCodeV1 = "all"
	SessionStopRegistryV1 SessionStopCodeV1 = "registry"
)

type sessionRecord struct {
	spec      SessionSpec
	inbound   chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	stopCode  SessionStopCodeV1
}

type SessionDevice struct {
	registry *SessionRegistry
	session  *sessionRecord
}

type SessionRegistry struct {
	mu         sync.RWMutex
	tunWriteMu sync.Mutex
	tun        io.ReadWriteCloser
	max        int
	queue      int
	sessions   map[string]*sessionRecord
	profiles   map[string]string
	clients    map[string]string
	ipv4       map[[4]byte]string
	ipv6       map[[16]byte]string
	closed     bool
	stats      RegistrySnapshot
}

func NewSessionRegistry(tun io.ReadWriteCloser, maxSessions, queuePackets int) (*SessionRegistry, error) {
	if tun == nil || maxSessions <= 0 || maxSessions > 4096 || queuePackets <= 0 || queuePackets > 4096 {
		return nil, ErrRegistryConfig
	}
	return &SessionRegistry{
		tun: tun, max: maxSessions, queue: queuePackets,
		sessions: make(map[string]*sessionRecord), profiles: make(map[string]string), clients: make(map[string]string),
		ipv4: make(map[[4]byte]string), ipv6: make(map[[16]byte]string),
	}, nil
}

func (registry *SessionRegistry) Register(spec SessionSpec) (*SessionDevice, error) {
	if registry == nil || !boundedSessionIDV1(spec.ID) || !boundedSessionIDV1(spec.ProfileID) || !boundedSessionIDV1(spec.ClientKeyID) ||
		!validSessionAddressAuthorityV1(spec) {
		return nil, ErrRegistryConfig
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.closed {
		return nil, ErrRegistryClosed
	}
	if len(registry.sessions) >= registry.max {
		return nil, ErrSessionLimit
	}
	if registry.sessions[spec.ID] != nil || registry.profiles[spec.ProfileID] != "" || registry.clients[spec.ClientKeyID] != "" ||
		spec.AssignedIPv4 != ([4]byte{}) && registry.ipv4[spec.AssignedIPv4] != "" ||
		spec.AssignedIPv6 != ([16]byte{}) && registry.ipv6[spec.AssignedIPv6] != "" {
		return nil, ErrSessionConflict
	}
	record := &sessionRecord{spec: spec, inbound: make(chan []byte, registry.queue), closed: make(chan struct{})}
	registry.sessions[spec.ID] = record
	registry.profiles[spec.ProfileID] = spec.ID
	registry.clients[spec.ClientKeyID] = spec.ID
	if spec.AssignedIPv4 != ([4]byte{}) {
		registry.ipv4[spec.AssignedIPv4] = spec.ID
	}
	if spec.AssignedIPv6 != ([16]byte{}) {
		registry.ipv6[spec.AssignedIPv6] = spec.ID
	}
	registry.stats.ActiveSessions = uint64(len(registry.sessions))
	return &SessionDevice{registry: registry, session: record}, nil
}

func validSessionAddressAuthorityV1(spec SessionSpec) bool {
	hasIPv4 := spec.AssignedIPv4 != [4]byte{}
	hasIPv6 := spec.AssignedIPv6 != [16]byte{}
	if !hasIPv4 && !hasIPv6 || hasIPv4 != (spec.DNSIPv4 != [4]byte{}) || hasIPv6 != (spec.DNSIPv6 != [16]byte{}) {
		return false
	}
	return (!hasIPv4 || spec.AssignedIPv4 != spec.DNSIPv4) && (!hasIPv6 || spec.AssignedIPv6 != spec.DNSIPv6)
}

func (registry *SessionRegistry) Run(ctx context.Context) error {
	if registry == nil || ctx == nil {
		return ErrRegistryConfig
	}
	buffer := make([]byte, 65535)
	defer clear(buffer)
	for {
		count, err := registry.tun.Read(buffer)
		if err != nil {
			registry.mu.RLock()
			closed := registry.closed
			registry.mu.RUnlock()
			if closed {
				return ErrRegistryClosed
			}
			return err
		}
		if count <= 0 || count > len(buffer) {
			return ErrPacketRejected
		}
		if err := registry.RouteReturnPacket(buffer[:count]); err != nil && !errors.Is(err, ErrPacketRejected) && !errors.Is(err, ErrSessionQueueFull) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

func (registry *SessionRegistry) RouteReturnPacket(packet []byte) error {
	destination4, destination6, err := packetDestinationV1(packet)
	if err != nil {
		return ErrPacketRejected
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.closed {
		return ErrRegistryClosed
	}
	sessionID := ""
	if destination4 != ([4]byte{}) {
		sessionID = registry.ipv4[destination4]
	} else {
		sessionID = registry.ipv6[destination6]
	}
	record := registry.sessions[sessionID]
	if record == nil {
		registry.stats.UnknownDestinations++
		return ErrPacketRejected
	}
	copyPacket := append([]byte(nil), packet...)
	select {
	case record.inbound <- copyPacket:
		return nil
	default:
		clear(copyPacket)
		registry.stats.QueueDrops++
		registry.stopLocked(record, SessionStopQueueV1)
		return ErrSessionQueueFull
	}
}

func (registry *SessionRegistry) StopProfile(profileID string) int {
	if registry == nil || profileID == "" {
		return 0
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	record := registry.sessions[registry.profiles[profileID]]
	if record == nil {
		return 0
	}
	registry.stopLocked(record, SessionStopProfileV1)
	return 1
}

func (registry *SessionRegistry) StopAll() int {
	if registry == nil {
		return 0
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.closed {
		return 0
	}
	stopped := len(registry.sessions)
	for _, record := range registry.sessions {
		registry.stopLocked(record, SessionStopAllV1)
	}
	return stopped
}

func (registry *SessionRegistry) Snapshot() RegistrySnapshot {
	if registry == nil {
		return RegistrySnapshot{}
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return registry.stats
}

func (registry *SessionRegistry) Close() error {
	if registry == nil {
		return nil
	}
	registry.mu.Lock()
	if registry.closed {
		registry.mu.Unlock()
		return nil
	}
	registry.closed = true
	for _, record := range registry.sessions {
		registry.stopLocked(record, SessionStopRegistryV1)
	}
	registry.mu.Unlock()
	return registry.tun.Close()
}

func (registry *SessionRegistry) stopLocked(record *sessionRecord, code SessionStopCodeV1) {
	if record == nil || registry.sessions[record.spec.ID] != record {
		return
	}
	if code == SessionStopNoneV1 {
		code = SessionStopLocalV1
	}
	record.stopCode = code
	delete(registry.sessions, record.spec.ID)
	delete(registry.profiles, record.spec.ProfileID)
	delete(registry.clients, record.spec.ClientKeyID)
	if record.spec.AssignedIPv4 != ([4]byte{}) {
		delete(registry.ipv4, record.spec.AssignedIPv4)
	}
	if record.spec.AssignedIPv6 != ([16]byte{}) {
		delete(registry.ipv6, record.spec.AssignedIPv6)
	}
	for {
		select {
		case packet := <-record.inbound:
			clear(packet)
		default:
			goto drained
		}
	}
drained:
	record.closeOnce.Do(func() {
		close(record.closed)
		if record.spec.Cancel != nil {
			record.spec.Cancel()
		}
	})
	registry.stats.ActiveSessions = uint64(len(registry.sessions))
	registry.stats.StoppedSessions++
}

func (device *SessionDevice) Read(buffer []byte) (int, error) {
	if device == nil || device.registry == nil || device.session == nil || len(buffer) == 0 {
		return 0, ErrRegistryConfig
	}
	select {
	case <-device.session.closed:
		return 0, io.EOF
	default:
	}
	select {
	case <-device.session.closed:
		return 0, io.EOF
	case packet := <-device.session.inbound:
		if len(packet) > len(buffer) {
			clear(packet)
			return 0, ErrPacketRejected
		}
		count := copy(buffer, packet)
		clear(packet)
		return count, nil
	}
}

func (device *SessionDevice) Write(packet []byte) (int, error) {
	if device == nil || device.registry == nil || device.session == nil || len(packet) == 0 {
		return 0, ErrPacketRejected
	}
	spec := device.session.spec
	if _, err := kruntime.ValidateRelayOutboundIPPacketV1(packet, spec.AssignedIPv4, spec.DNSIPv4, spec.AssignedIPv6, spec.DNSIPv6); err != nil {
		return 0, ErrPacketRejected
	}
	select {
	case <-device.session.closed:
		return 0, io.EOF
	default:
	}
	device.registry.mu.RLock()
	if device.registry.closed || device.registry.sessions[spec.ID] != device.session {
		device.registry.mu.RUnlock()
		return 0, io.EOF
	}
	device.registry.mu.RUnlock()
	device.registry.tunWriteMu.Lock()
	defer device.registry.tunWriteMu.Unlock()
	device.registry.mu.RLock()
	active := !device.registry.closed && device.registry.sessions[spec.ID] == device.session
	device.registry.mu.RUnlock()
	if !active {
		return 0, io.EOF
	}
	count, err := device.registry.tun.Write(packet)
	if err != nil || count != len(packet) {
		return 0, ErrPacketRejected
	}
	return count, nil
}

func (device *SessionDevice) Close() error {
	if device == nil || device.registry == nil || device.session == nil {
		return nil
	}
	device.registry.mu.Lock()
	device.registry.stopLocked(device.session, SessionStopLocalV1)
	device.registry.mu.Unlock()
	return nil
}

func (device *SessionDevice) StopCodeV1() SessionStopCodeV1 {
	if device == nil || device.registry == nil || device.session == nil {
		return SessionStopNoneV1
	}
	device.registry.mu.RLock()
	defer device.registry.mu.RUnlock()
	return device.session.stopCode
}

func packetDestinationV1(packet []byte) ([4]byte, [16]byte, error) {
	if len(packet) < 1 {
		return [4]byte{}, [16]byte{}, ErrPacketRejected
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return [4]byte{}, [16]byte{}, ErrPacketRejected
		}
		header := int(packet[0]&0x0f) * 4
		if header < 20 || header > 60 || len(packet) < header || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) || checksumIPv4NodeV1(packet[:header]) != 0 {
			return [4]byte{}, [16]byte{}, ErrPacketRejected
		}
		var destination [4]byte
		copy(destination[:], packet[16:20])
		return destination, [16]byte{}, nil
	case 6:
		if len(packet) < 40 || int(binary.BigEndian.Uint16(packet[4:6]))+40 != len(packet) {
			return [4]byte{}, [16]byte{}, ErrPacketRejected
		}
		var destination [16]byte
		copy(destination[:], packet[24:40])
		return [4]byte{}, destination, nil
	default:
		return [4]byte{}, [16]byte{}, ErrPacketRejected
	}
}

func checksumIPv4NodeV1(header []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(header); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[index : index+2]))
	}
	if len(header)%2 != 0 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func boundedSessionIDV1(value string) bool { return len(value) > 0 && len(value) <= 128 }

var _ io.ReadWriteCloser = (*SessionDevice)(nil)
