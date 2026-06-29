// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapter

import (
	"fmt"

	"kurdistan/internal/adapter"
)

func FlowDescriptor(id adapter.FlowID, bytes int) adapter.FlowDescriptor {
	if bytes <= 0 {
		bytes = 128
	}
	priority := "interactive"
	if bytes > 4096 {
		priority = "bulk"
	}
	return adapter.FlowDescriptor{
		ID:             id,
		Class:          "local",
		Direction:      "bidirectional",
		RequestClass:   priority,
		PriorityClass:  priority,
		TargetHint:     "synthetic-local",
		MaxReadBytes:   bytes,
		MaxWriteBytes:  bytes,
		MetadataPolicy: "bucketed",
	}
}

func FlowID(index int) adapter.FlowID {
	return adapter.FlowID(fmt.Sprintf("local-flow-%02d", index))
}
