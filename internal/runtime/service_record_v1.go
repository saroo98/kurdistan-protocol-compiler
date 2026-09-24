// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"kurdistan/internal/product/runtimepolicy"
)

var ErrServiceRecordV1 = errors.New("service_record_invalid")

type ServiceOpcodeV1 uint8

const (
	ServiceOpenV1 ServiceOpcodeV1 = iota + 1
	ServiceOpenResultV1
	ServiceDataV1
	ServiceFINV1
	ServiceResetV1
	ServiceProbeV1
	ServiceProbeResultV1
)

type ServiceResultV1 uint16

const (
	ServiceSuccessV1 ServiceResultV1 = iota
	ServiceNotAdmittedV1
	ServiceInvalidRequestV1
	ServiceDestinationDeniedV1
	ServiceResourceLimitV1
	ServiceTimeoutV1
	ServiceUnreachableV1
	ServiceCancelledV1
	ServiceAuthorityExpiredV1
	ServiceAuthorityRevokedV1
	ServiceInternalFailureV1
)

type ServiceDirectionV1 uint8

const (
	ServiceClientToRelayV1 ServiceDirectionV1 = iota + 1
	ServiceRelayToClientV1
)

type ServicePayloadKindV1 uint8

const (
	ServicePayloadInvalidV1 ServicePayloadKindV1 = iota
	ServicePayloadIPv4V1
	ServicePayloadIPv6V1
	ServicePayloadRecordV1
)

// ServiceRecordViewV1 borrows Body. It is valid only while the source buffer is
// unchanged and alive. It is not owned stable storage and must not be queued.
type ServiceRecordViewV1 struct {
	Opcode ServiceOpcodeV1
	ID     uint32
	Body   []byte
}
type ServiceRecordCodecV1 struct{ maximum int }

// NewServiceRecordCodecV1 receives the selected signed data minimum and the
// lesser of its maximum and the live-program maximum. MTU/framing/session
// admission remains the pump constructor's obligation, not this grammar check.
func NewServiceRecordCodecV1(minimum, maximum int) (ServiceRecordCodecV1, error) {
	if minimum < 0 || minimum > 8 || maximum < 272 || maximum > 8<<20 {
		return ServiceRecordCodecV1{}, ErrServiceRecordV1
	}
	return ServiceRecordCodecV1{maximum: maximum}, nil
}

// DecodeBorrowed validates without copying. probeTimeoutMillis is the admitted
// pending attempt's timeout for PROBE_RESULT, not a peer-supplied replacement.
// State, ID monotonicity and pending-operation matching belong to the pump.
func (c ServiceRecordCodecV1) DecodeBorrowed(raw []byte, direction ServiceDirectionV1, probeTimeoutMillis uint16) (ServiceRecordViewV1, error) {
	if c.maximum < 272 || len(raw) < 8 || len(raw) > c.maximum || len(raw) > 16392 || raw[0] != 1 || int(binary.BigEndian.Uint16(raw[6:8])) != len(raw)-8 {
		return ServiceRecordViewV1{}, ErrServiceRecordV1
	}
	r := ServiceRecordViewV1{Opcode: ServiceOpcodeV1(raw[1]), ID: binary.BigEndian.Uint32(raw[2:6]), Body: raw[8:]}
	if !c.valid(r, direction, probeTimeoutMillis) {
		return ServiceRecordViewV1{}, ErrServiceRecordV1
	}
	return r, nil
}

// Encode leaves dst entirely unchanged on every validation/size failure. Input
// body may overlap dst: the body is copied before the header is written.
func (c ServiceRecordCodecV1) Encode(dst []byte, record ServiceRecordViewV1, direction ServiceDirectionV1, probeTimeoutMillis uint16) (int, error) {
	if !c.valid(record, direction, probeTimeoutMillis) || len(dst) < 8+len(record.Body) {
		return 0, ErrServiceRecordV1
	}
	copy(dst[8:], record.Body)
	dst[0] = 1
	dst[1] = byte(record.Opcode)
	binary.BigEndian.PutUint32(dst[2:6], record.ID)
	binary.BigEndian.PutUint16(dst[6:8], uint16(len(record.Body)))
	return 8 + len(record.Body), nil
}
func (c ServiceRecordCodecV1) valid(r ServiceRecordViewV1, d ServiceDirectionV1, timeout uint16) bool {
	if c.maximum < 272 || r.ID == 0 || len(r.Body) > 16384 || len(r.Body) > c.maximum-8 || (d != ServiceClientToRelayV1 && d != ServiceRelayToClientV1) {
		return false
	}
	b := r.Body
	switch r.Opcode {
	case ServiceOpenV1:
		if d != ServiceClientToRelayV1 || len(b) < 5 || int(binary.BigEndian.Uint16(b[1:3])) != len(b)-5 {
			return false
		}
		return validServiceAddressV1(b[0], b[3:len(b)-2], binary.BigEndian.Uint16(b[len(b)-2:]))
	case ServiceOpenResultV1:
		return d == ServiceRelayToClientV1 && len(b) == 2 && binary.BigEndian.Uint16(b) <= 10
	case ServiceDataV1:
		return len(b) > 0
	case ServiceFINV1:
		return len(b) == 0
	case ServiceResetV1:
		return len(b) == 2 && binary.BigEndian.Uint16(b) > 0 && binary.BigEndian.Uint16(b) <= 10
	case ServiceProbeV1:
		return d == ServiceClientToRelayV1 && len(b) == 5 && binary.BigEndian.Uint16(b) > 0 && b[2] == 1 && binary.BigEndian.Uint16(b[3:]) >= 1000 && binary.BigEndian.Uint16(b[3:]) <= 30000
	case ServiceProbeResultV1:
		if d != ServiceRelayToClientV1 || len(b) != 6 || binary.BigEndian.Uint16(b) > 10 {
			return false
		}
		duration := binary.BigEndian.Uint32(b[2:])
		if binary.BigEndian.Uint16(b) != 0 {
			return duration == 0
		}
		return timeout >= 1000 && timeout <= 30000 && duration <= uint32(timeout)*1000
	default:
		return false
	}
}
func validServiceAddressV1(kind uint8, address []byte, port uint16) bool {
	if port == 0 {
		return false
	}
	switch kind {
	case 1:
		return len(address) == 4
	case 2:
		return len(address) <= 253 && runtimepolicy.IsCanonicalProxyDomain(string(address))
	case 3:
		a, ok := netip.AddrFromSlice(address)
		return ok && len(address) == 16 && !a.Is4In6()
	default:
		return false
	}
}

// ClassifyServicePayloadV1 only selects a grammar. An IP nibble is not proof of
// complete IP framing, address authority or packet validity.
func ClassifyServicePayloadV1(raw []byte) ServicePayloadKindV1 {
	if len(raw) == 0 {
		return ServicePayloadInvalidV1
	}
	if raw[0]>>4 == 4 {
		return ServicePayloadIPv4V1
	}
	if raw[0]>>4 == 6 {
		return ServicePayloadIPv6V1
	}
	if raw[0] == 1 {
		return ServicePayloadRecordV1
	}
	return ServicePayloadInvalidV1
}
