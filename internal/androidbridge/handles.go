// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import "sync"

type HandleType uint8

const (
	HandleVerifyPreview HandleType = iota + 1
	HandleActivation
	HandleDiagnostic
	HandleBackup
	HandleRuntimeSession
	HandleRecipient
)

type Handle uint64

type handleSlot struct {
	generation uint32
	kind       HandleType
	value      any
	cancelled  bool
	occupied   bool
}

type handleDestroyer interface {
	Destroy()
}

type handleResultDestroyer interface {
	DestroyResult() ErrorCode
}

type handleCanceller interface {
	Cancel() ErrorCode
}

type HandleRegistry struct {
	mu    sync.Mutex
	slots [MaxBridgeHandles]handleSlot
}

func (r *HandleRegistry) Open(kind HandleType, value any) (Handle, ErrorCode) {
	if r == nil || kind < HandleVerifyPreview || kind > HandleRecipient || value == nil {
		return 0, CodeInvalidArgument
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range r.slots {
		slot := &r.slots[index]
		if slot.occupied {
			continue
		}
		slot.generation++
		if slot.generation == 0 {
			slot.generation = 1
		}
		slot.kind = kind
		slot.value = value
		slot.cancelled = false
		slot.occupied = true
		return encodeHandle(uint16(index), slot.generation, kind), CodeOK
	}
	return 0, CodeSizeLimit
}

func (r *HandleRegistry) Get(handle Handle, kind HandleType) (any, ErrorCode) {
	if r == nil {
		return nil, CodeInvalidHandle
	}
	index, generation, encodedKind, ok := decodeHandle(handle)
	if !ok {
		return nil, CodeInvalidHandle
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	slot := &r.slots[index]
	if !slot.occupied || slot.generation != generation {
		return nil, CodeAlreadyClosed
	}
	if encodedKind != slot.kind || kind != slot.kind {
		return nil, CodeWrongHandleType
	}
	if slot.cancelled {
		return nil, CodeCancelled
	}
	return slot.value, CodeOK
}

func (r *HandleRegistry) Cancel(handle Handle) ErrorCode {
	if r == nil {
		return CodeInvalidHandle
	}
	index, generation, kind, ok := decodeHandle(handle)
	if !ok {
		return CodeInvalidHandle
	}
	r.mu.Lock()
	slot := &r.slots[index]
	if !slot.occupied || slot.generation != generation {
		r.mu.Unlock()
		return CodeAlreadyClosed
	}
	if slot.kind != kind {
		r.mu.Unlock()
		return CodeWrongHandleType
	}
	slot.cancelled = true
	value := slot.value
	r.mu.Unlock()
	if canceller, ok := value.(handleCanceller); ok {
		return canceller.Cancel()
	}
	return CodeOK
}

func (r *HandleRegistry) Free(handle Handle) ErrorCode {
	if r == nil {
		return CodeInvalidHandle
	}
	index, generation, kind, ok := decodeHandle(handle)
	if !ok {
		return CodeInvalidHandle
	}
	r.mu.Lock()
	slot := &r.slots[index]
	if !slot.occupied || slot.generation != generation {
		r.mu.Unlock()
		return CodeAlreadyClosed
	}
	if slot.kind != kind {
		r.mu.Unlock()
		return CodeWrongHandleType
	}
	value := slot.value
	slot.kind = 0
	slot.value = nil
	slot.cancelled = false
	slot.occupied = false
	r.mu.Unlock()
	if destroyer, ok := value.(handleResultDestroyer); ok {
		return destroyer.DestroyResult()
	}
	if destroyer, ok := value.(handleDestroyer); ok {
		destroyer.Destroy()
	}
	return CodeOK
}

func encodeHandle(index uint16, generation uint32, kind HandleType) Handle {
	return Handle(uint64(kind)<<56 | uint64(generation)<<16 | uint64(index+1))
}

func decodeHandle(handle Handle) (uint16, uint32, HandleType, bool) {
	raw := uint64(handle)
	indexPlusOne := uint16(raw)
	generation := uint32(raw >> 16)
	kind := HandleType(raw >> 56)
	if indexPlusOne == 0 || int(indexPlusOne) > MaxBridgeHandles ||
		generation == 0 || kind < HandleVerifyPreview || kind > HandleRecipient {
		return 0, 0, 0, false
	}
	return indexPlusOne - 1, generation, kind, true
}
