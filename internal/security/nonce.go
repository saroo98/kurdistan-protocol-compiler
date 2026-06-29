// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"sync"
)

type NonceManager struct {
	mu        sync.Mutex
	Direction string
	Base      []byte
	Counter   uint64
	Mode      string
}

func NewNonceManager(direction string, base []byte, mode string) *NonceManager {
	cp := append([]byte(nil), base...)
	if len(cp) != 12 {
		sum := sha256.Sum256(cp)
		cp = append([]byte(nil), sum[:12]...)
	}
	if mode == "" {
		mode = "directional_counter"
	}
	return &NonceManager{Direction: direction, Base: cp, Mode: mode}
}

func (n *NonceManager) Next() ([]byte, uint64, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Counter == math.MaxUint64 {
		return nil, 0, ErrNonceOverflow
	}
	n.Counter++
	nonce, err := n.nonceForLocked(n.Counter)
	if err != nil {
		return nil, 0, err
	}
	return nonce, n.Counter, nil
}

func (n *NonceManager) SetCounterForTest(counter uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Counter = counter
}

func (n *NonceManager) nonceForLocked(seq uint64) ([]byte, error) {
	switch n.Mode {
	case "counter_xor_base", "directional_counter", "stream_partitioned_counter":
		out := append([]byte(nil), n.Base...)
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], seq)
		for i := 0; i < 8; i++ {
			out[len(out)-8+i] ^= buf[i]
		}
		if n.Direction == "server" {
			out[0] ^= 0x80
		}
		return out, nil
	case "counter_append_base":
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], seq)
		sum := sha256.Sum256(append(append([]byte(n.Direction+"/"), n.Base...), buf[:]...))
		return append([]byte(nil), sum[:12]...), nil
	default:
		return nil, fmt.Errorf("%w: unknown nonce mode %q", ErrInvalidConfig, n.Mode)
	}
}
