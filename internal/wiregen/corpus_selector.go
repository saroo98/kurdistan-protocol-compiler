// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"

	"kurdistan/internal/protocorpus"
)

func SelectCorpusEntry(seed int64, corpus protocorpus.CorpusManifest) (protocorpus.ProtocolShapeEntry, error) {
	if err := protocorpus.ValidateManifest(corpus); err != nil {
		return protocorpus.ProtocolShapeEntry{}, fmt.Errorf("%w: %v", ErrMissingCorpus, err)
	}
	entries := append([]protocorpus.ProtocolShapeEntry(nil), corpus.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	if len(entries) == 0 {
		return protocorpus.ProtocolShapeEntry{}, ErrMissingCorpus
	}
	index := stableIndex(seed, string(corpus.Version), len(entries))
	return entries[index], nil
}

func stableIndex(seed int64, salt string, modulo int) int {
	if modulo <= 1 {
		return 0
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", salt, seed)))
	value := binary.BigEndian.Uint64(sum[:8])
	return int(value % uint64(modulo))
}
