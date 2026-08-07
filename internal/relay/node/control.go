// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"time"
)

var (
	ErrControlProtocol     = errors.New("relay node: invalid control protocol")
	ErrControlConfig       = errors.New("relay node: invalid control configuration")
	ErrControlUnauthorized = errors.New("relay node: control peer unauthorized")
)

type ControlCommandV1 uint8

const (
	ControlStatusV1      ControlCommandV1 = 1
	ControlDrainV1       ControlCommandV1 = 2
	ControlResumeV1      ControlCommandV1 = 3
	ControlReloadV1      ControlCommandV1 = 4
	ControlStopProfileV1 ControlCommandV1 = 5
)

type ControlCodeV1 uint8

const (
	ControlCodeOKV1           ControlCodeV1 = 0
	ControlCodeUnavailableV1  ControlCodeV1 = 1
	ControlCodeReloadFailedV1 ControlCodeV1 = 2
)

type ControlRequestV1 struct {
	Command   ControlCommandV1
	ProfileID string
}

type ControlResponseV1 struct {
	OK       bool
	Code     ControlCodeV1
	Health   HealthSnapshot
	Registry RegistrySnapshot
	Stopped  uint16
}

type ControlActionsV1 struct {
	Health   *HealthMachine
	Registry *SessionRegistry
	Reload   func() error
}

var (
	controlRequestMagicV1  = [8]byte{'K', 'U', 'R', 'D', 'C', 'T', 'L', '1'}
	controlResponseMagicV1 = [8]byte{'K', 'U', 'R', 'D', 'R', 'E', 'S', '1'}
)

const controlResponseSizeV1 = 47

func EncodeControlRequestV1(request ControlRequestV1) ([]byte, error) {
	if err := validateControlRequestV1(request); err != nil {
		return nil, err
	}
	wire := make([]byte, 10+len(request.ProfileID))
	copy(wire[:8], controlRequestMagicV1[:])
	wire[8] = byte(request.Command)
	wire[9] = byte(len(request.ProfileID))
	copy(wire[10:], request.ProfileID)
	return wire, nil
}

func DecodeControlRequestV1(wire []byte) (ControlRequestV1, error) {
	if len(wire) < 10 || len(wire) > 138 || !equalFixedV1(wire[:8], controlRequestMagicV1[:]) || int(wire[9])+10 != len(wire) {
		return ControlRequestV1{}, ErrControlProtocol
	}
	request := ControlRequestV1{Command: ControlCommandV1(wire[8]), ProfileID: string(wire[10:])}
	if err := validateControlRequestV1(request); err != nil {
		return ControlRequestV1{}, err
	}
	return request, nil
}

func EncodeControlResponseV1(response ControlResponseV1) ([]byte, error) {
	healthCode, ok := encodeHealthStateV1(response.Health.State)
	if !ok || response.Health.Missing > 6 || response.Code > ControlCodeReloadFailedV1 || response.OK != (response.Code == ControlCodeOKV1) {
		return nil, ErrControlProtocol
	}
	wire := make([]byte, controlResponseSizeV1)
	copy(wire[:8], controlResponseMagicV1[:])
	if response.OK {
		wire[8] = 1
	}
	wire[9] = byte(response.Code)
	wire[10] = healthCode
	if response.Health.AcceptingSessions {
		wire[11] = 1
	}
	wire[12] = response.Health.Missing
	binary.BigEndian.PutUint16(wire[13:15], response.Stopped)
	binary.BigEndian.PutUint64(wire[15:23], response.Registry.ActiveSessions)
	binary.BigEndian.PutUint64(wire[23:31], response.Registry.QueueDrops)
	binary.BigEndian.PutUint64(wire[31:39], response.Registry.UnknownDestinations)
	binary.BigEndian.PutUint64(wire[39:47], response.Registry.StoppedSessions)
	return wire, nil
}

func DecodeControlResponseV1(wire []byte) (ControlResponseV1, error) {
	if len(wire) != controlResponseSizeV1 || !equalFixedV1(wire[:8], controlResponseMagicV1[:]) || wire[8] > 1 || wire[11] > 1 {
		return ControlResponseV1{}, ErrControlProtocol
	}
	health, ok := decodeHealthStateV1(wire[10])
	if !ok {
		return ControlResponseV1{}, ErrControlProtocol
	}
	response := ControlResponseV1{
		OK: wire[8] == 1, Code: ControlCodeV1(wire[9]),
		Health:  HealthSnapshot{State: health, AcceptingSessions: wire[11] == 1, Missing: wire[12]},
		Stopped: binary.BigEndian.Uint16(wire[13:15]),
		Registry: RegistrySnapshot{
			ActiveSessions: binary.BigEndian.Uint64(wire[15:23]), QueueDrops: binary.BigEndian.Uint64(wire[23:31]),
			UnknownDestinations: binary.BigEndian.Uint64(wire[31:39]), StoppedSessions: binary.BigEndian.Uint64(wire[39:47]),
		},
	}
	if response.Health.Missing > 6 || response.Code > ControlCodeReloadFailedV1 || response.OK != (response.Code == ControlCodeOKV1) {
		return ControlResponseV1{}, ErrControlProtocol
	}
	return response, nil
}

func (actions ControlActionsV1) Execute(request ControlRequestV1) (ControlResponseV1, error) {
	if actions.Health == nil {
		return ControlResponseV1{}, ErrControlConfig
	}
	if err := validateControlRequestV1(request); err != nil {
		return ControlResponseV1{}, err
	}
	response := ControlResponseV1{OK: true, Code: ControlCodeOKV1}
	switch request.Command {
	case ControlStatusV1:
	case ControlDrainV1:
		actions.Health.SetDrain(true)
	case ControlResumeV1:
		actions.Health.SetDrain(false)
	case ControlReloadV1:
		if actions.Reload == nil {
			response.OK, response.Code = false, ControlCodeUnavailableV1
		} else if actions.Reload() != nil {
			response.OK, response.Code = false, ControlCodeReloadFailedV1
		}
	case ControlStopProfileV1:
		if actions.Registry == nil {
			response.OK, response.Code = false, ControlCodeUnavailableV1
		} else {
			response.Stopped = uint16(actions.Registry.StopProfile(request.ProfileID))
		}
	}
	response.Health = actions.Health.Snapshot()
	if actions.Registry != nil {
		response.Registry = actions.Registry.Snapshot()
	}
	return response, nil
}

func ServeControlV1(ctx context.Context, listener net.Listener, authorize func(net.Conn) error, actions ControlActionsV1, timeout time.Duration, maxWorkers int) error {
	if ctx == nil || listener == nil || authorize == nil || actions.Health == nil || timeout < 100*time.Millisecond || timeout > 10*time.Second || maxWorkers <= 0 || maxWorkers > 32 {
		return ErrControlConfig
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stop:
		}
	}()
	defer close(stop)

	workers := make(chan struct{}, maxWorkers)
	var wait sync.WaitGroup
	defer wait.Wait()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.Join(ErrControlConfig, err)
		}
		select {
		case workers <- struct{}{}:
			wait.Add(1)
			go func() {
				defer func() { <-workers; wait.Done() }()
				handleControlConnectionV1(connection, authorize, actions, timeout)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func handleControlConnectionV1(connection net.Conn, authorize func(net.Conn) error, actions ControlActionsV1, timeout time.Duration) {
	if connection == nil {
		return
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil || authorize(connection) != nil {
		return
	}
	header := make([]byte, 10)
	if _, err := io.ReadFull(connection, header); err != nil || int(header[9])+10 > 138 {
		return
	}
	wire := make([]byte, int(header[9])+10)
	copy(wire, header)
	if _, err := io.ReadFull(connection, wire[10:]); err != nil {
		return
	}
	request, err := DecodeControlRequestV1(wire)
	if err != nil {
		return
	}
	response, err := actions.Execute(request)
	if err != nil {
		return
	}
	encoded, err := EncodeControlResponseV1(response)
	if err != nil {
		return
	}
	for len(encoded) > 0 {
		count, writeErr := connection.Write(encoded)
		if writeErr != nil || count <= 0 {
			return
		}
		encoded = encoded[count:]
	}
}

func validateControlPeerUIDV1(ownerUID, peerUID uint32) error {
	if peerUID != 0 && peerUID != ownerUID {
		return ErrControlUnauthorized
	}
	return nil
}

func validateControlSocketPathV1(path string) error {
	if path == "" || len(path) > 100 || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "control.sock" {
		return ErrControlConfig
	}
	return nil
}

func validateControlRequestV1(request ControlRequestV1) error {
	switch request.Command {
	case ControlStatusV1, ControlDrainV1, ControlResumeV1, ControlReloadV1:
		if request.ProfileID != "" {
			return ErrControlProtocol
		}
	case ControlStopProfileV1:
		if !boundedSessionIDV1(request.ProfileID) {
			return ErrControlProtocol
		}
	default:
		return ErrControlProtocol
	}
	return nil
}

func encodeHealthStateV1(state HealthState) (byte, bool) {
	switch state {
	case HealthStarting:
		return 1, true
	case HealthReady:
		return 2, true
	case HealthDraining:
		return 3, true
	case HealthDisabled:
		return 4, true
	case HealthDegraded:
		return 5, true
	case HealthStopping:
		return 6, true
	default:
		return 0, false
	}
}

func decodeHealthStateV1(value byte) (HealthState, bool) {
	switch value {
	case 1:
		return HealthStarting, true
	case 2:
		return HealthReady, true
	case 3:
		return HealthDraining, true
	case 4:
		return HealthDisabled, true
	case 5:
		return HealthDegraded, true
	case 6:
		return HealthStopping, true
	default:
		return "", false
	}
}

func equalFixedV1(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}
