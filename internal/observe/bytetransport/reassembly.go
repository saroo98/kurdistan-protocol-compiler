// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransport

import "fmt"

type Reassembler struct {
	cfg    ByteTransportConfig
	groups map[string]*fragmentGroup
}

type fragmentGroup struct {
	first      ByteFrame
	seen       map[int]ByteFrame
	totalBytes int
}

func NewReassembler(cfg ByteTransportConfig) (*Reassembler, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	return &Reassembler{cfg: cfg, groups: map[string]*fragmentGroup{}}, nil
}

func (r *Reassembler) Add(frame ByteFrame) (DecodeResult, error) {
	if r == nil {
		return rejectResult("nil_reassembler", ErrReassemblyRejected), ErrReassemblyRejected
	}
	if frame.FragmentCount <= 1 {
		return DecodeResult{Frame: frame, Complete: true}, nil
	}
	if frame.FragmentCount > r.cfg.MaxFragments {
		err := fmt.Errorf("%w: too many fragments", ErrReassemblyRejected)
		return rejectResult("too_many_fragments", err), err
	}
	key := fmt.Sprintf("%s/%d/%d", frame.SessionID, frame.StreamID, frame.Sequence)
	group := r.groups[key]
	if group == nil {
		group = &fragmentGroup{first: frame, seen: map[int]ByteFrame{}}
		r.groups[key] = group
	}
	if _, exists := group.seen[frame.FragmentIndex]; exists {
		err := fmt.Errorf("%w: duplicate fragment", ErrReassemblyRejected)
		return rejectResult("duplicate_fragment", err), err
	}
	if !r.cfg.AllowOutOfOrder && frame.FragmentIndex != len(group.seen) {
		err := fmt.Errorf("%w: out of order fragment", ErrReassemblyRejected)
		return rejectResult("out_of_order", err), err
	}
	group.seen[frame.FragmentIndex] = frame
	group.totalBytes += frame.ByteCount
	if group.totalBytes > r.cfg.MaxReassemblyBytes {
		delete(r.groups, key)
		err := fmt.Errorf("%w: reassembly bytes", ErrReassemblyRejected)
		return rejectResult("reassembly_bytes", err), err
	}
	if len(group.seen) != frame.FragmentCount {
		return DecodeResult{Frame: frame, Complete: false}, nil
	}
	total := 0
	for i := 0; i < frame.FragmentCount; i++ {
		part, ok := group.seen[i]
		if !ok {
			return DecodeResult{Frame: frame, Complete: false}, nil
		}
		total += part.ByteCount
	}
	done := group.first
	done.FragmentIndex = 0
	done.FragmentCount = 1
	done.ByteCount = total
	done.Final = true
	delete(r.groups, key)
	return DecodeResult{Frame: done, Complete: true, Reassembled: true}, nil
}

func (r *Reassembler) Clear(streamID uint64) {
	if r == nil {
		return
	}
	for key, group := range r.groups {
		if group.first.StreamID == streamID {
			delete(r.groups, key)
		}
	}
}
