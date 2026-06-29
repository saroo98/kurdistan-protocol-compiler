// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransport

import "hash/fnv"

func checksum(raw []byte) uint32 {
	h := fnv.New32a()
	_, _ = h.Write(raw)
	return h.Sum32()
}

func deterministicPayload(seed, sequence uint64, n int) []byte {
	out := make([]byte, n)
	x := seed ^ (sequence * 0x9e3779b97f4a7c15)
	for i := range out {
		x = x*6364136223846793005 + 1442695040888963407
		out[i] = byte(x >> 56)
	}
	return out
}
