// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransport

import "fmt"

const (
	FragmentNoFragment        = "no_fragment"
	FragmentFixed             = "fixed_fragment"
	FragmentProfileBucket     = "profile_bucket_fragment"
	FragmentCarrierAware      = "carrier_aware_fragment"
	FragmentBackpressureAware = "backpressure_aware_fragment"
)

func FragmentFrame(cfg ByteTransportConfig, frame ByteFrame, policy string) ([]ByteFrame, error) {
	if frame.SessionID == "" {
		frame.SessionID = cfg.RuntimeID
	}
	if policy == "" {
		policy = FragmentFixed
	}
	if policy == FragmentNoFragment {
		frame.FragmentIndex = 0
		frame.FragmentCount = 1
		if err := ValidateFrame(cfg, frame); err != nil {
			return nil, err
		}
		return []ByteFrame{frame}, nil
	}
	chunkSize := fragmentSize(cfg, policy)
	if chunkSize <= 0 {
		return nil, fmt.Errorf("%w: fragment size", ErrInvalidConfig)
	}
	count := (frame.ByteCount + chunkSize - 1) / chunkSize
	if count <= 0 {
		count = 1
	}
	if count > cfg.MaxFragments {
		return nil, fmt.Errorf("%w: too many fragments", ErrReassemblyRejected)
	}
	out := make([]ByteFrame, 0, count)
	remaining := frame.ByteCount
	for i := 0; i < count; i++ {
		size := chunkSize
		if remaining < size {
			size = remaining
		}
		remaining -= size
		next := frame
		next.FragmentIndex = i
		next.FragmentCount = count
		next.ByteCount = size
		next.Final = frame.Final && i == count-1
		if err := ValidateFrame(cfg, next); err != nil {
			return nil, err
		}
		out = append(out, next)
	}
	return out, nil
}

func fragmentSize(cfg ByteTransportConfig, policy string) int {
	base := cfg.MaxPayloadBytes
	switch policy {
	case FragmentFixed:
		return maxInt(1, base/2)
	case FragmentProfileBucket:
		return maxInt(1, base/3)
	case FragmentCarrierAware:
		return maxInt(1, base/4)
	case FragmentBackpressureAware:
		return maxInt(1, base/8)
	default:
		return maxInt(1, base/2)
	}
}
