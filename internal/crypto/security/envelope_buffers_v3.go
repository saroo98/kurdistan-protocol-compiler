// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package security

import (
	"encoding/binary"
	"unsafe"
)

// SealApplicationIntoV1 borrows disjoint caller storage and never allocates an
// output buffer. All overlap, including exact in-place input, is rejected.
// Short destinations leave output and nonce state unchanged.
func (c *EnvelopeCodecV1) SealApplicationIntoV1(dst []byte, slot uint16, plaintext []byte) (EnvelopeRecordV1, error) {
	return c.sealDestinationV1(dst, true, nonceApplicationRecordV1, 1, slot, plaintext, nil)
}

// AuthenticateApplicationIntoV1 returns borrowed plaintext and fresh one-shot
// replay authority. Authentication is not delivery. On tag failure the writable
// plaintext prefix is cleared. Input and destination must be disjoint.
func (c *EnvelopeCodecV1) AuthenticateApplicationIntoV1(dst []byte, record EnvelopeRecordV1) ([]byte, AuthenticatedReplayV1, error) {
	return c.authenticateDestinationV1(dst, true, nonceApplicationRecordV1, record, nil)
}

func envelopeSlicesOverlapV3(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	ap, bp := uintptr(unsafe.Pointer(unsafe.SliceData(a))), uintptr(unsafe.Pointer(unsafe.SliceData(b)))
	if ap <= bp {
		return bp-ap < uintptr(len(a))
	}
	return ap-bp < uintptr(len(b))
}

// The only application-AAD writer, used by allocating and borrowed APIs.
func (c *EnvelopeCodecV1) writeApplicationAADV1(out []byte, record EnvelopeRecordV1) []byte {
	binary.BigEndian.PutUint16(out[0:2], 1)
	binary.BigEndian.PutUint16(out[2:4], 1)
	copy(out[4:36], c.context.EffectivePolicyHash[:])
	copy(out[36:68], c.context.TranscriptHash[:])
	class, _ := c.ExpectedClassV1()
	binary.BigEndian.PutUint16(out[68:70], class)
	binary.BigEndian.PutUint64(out[70:78], record.Epoch)
	binary.BigEndian.PutUint16(out[78:80], record.Direction)
	binary.BigEndian.PutUint16(out[80:82], record.Slot)
	binary.BigEndian.PutUint64(out[82:90], record.Sequence)
	binary.BigEndian.PutUint32(out[90:94], record.SealedLength)
	n := 94
	if c.context.EffectivePolicy.SecureEnvelopeMode == "full_context_bound_envelope" {
		copy(out[94:126], c.context.CapabilityHash[:])
		copy(out[126:158], c.context.ProfileHash[:])
		copy(out[158:190], c.context.FramingHash[:])
		copy(out[190:222], c.context.CarrierContextHash[:])
		n = 222
	}
	return out[:n:n]
}
