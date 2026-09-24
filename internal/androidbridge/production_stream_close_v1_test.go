// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"context"
	runtimeengine "kurdistan/internal/runtime"
	"testing"
)

func TestProductionStreamClosePostRuntimeFenceV1(t *testing.T) {
	for _, fault := range []string{"none", "child", "attempt", "wire", "opening", "delivery", "use", "context", "query-failure", "query-terminal"} {
		t.Run(fault, func(t *testing.T) {
			v, _, inv, _ := productionOutputPumpFixtureV1(t)
			child, status := OpenProductionStreamV1(inv.registry, v.handle, []byte{1, 1, 0, 4, 8, 8, 8, 8, 1, 187})
			if status != 0 {
				t.Fatal("open", status)
			}
			i, use, ctx, status := v.streamUseOutputV1(child, 0, inv)
			if status != 0 {
				t.Fatal("use", status)
			}
			defer v.parent.finishUseV1(use)
			v.parent.mu.Lock()
			row := v.streams[i]
			v.parent.mu.Unlock()
			actual := v.pump.CancelStream(row.wire)
			if actual != nil {
				t.Fatal("actual cancellation", actual)
			}
			// This tests the final native fence after actual runtime cleanup, not
			// a fabricated cleanup proof or an additional production query API.
			v.parent.mu.Lock()
			switch fault {
			case "child":
				v.streams[i].child++
			case "attempt":
				v.streams[i].attempt++
			case "wire":
				v.streams[i].wire++
			case "opening":
				v.streams[i].opening = true
			case "delivery":
				v.streams[i].delivery.token = 99
			}
			v.parent.mu.Unlock()
			defer func() { v.parent.mu.Lock(); v.streams[i] = row; v.parent.mu.Unlock() }()
			claimed := use
			if fault == "use" {
				claimed.serial++
			}
			if fault == "context" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if fault == "query-failure" {
				_, actual = v.pump.StreamRetiredV1(^uint32(0))
				if actual == nil {
					t.Fatal("unissued wire accepted")
				}
			}
			if fault == "query-terminal" {
				v.pump.CancelWithReason(runtimeengine.ServiceCancelledV1)
				_, actual = v.pump.StreamRetiredV1(row.wire)
				if actual == nil {
					t.Fatal("terminal query accepted")
				}
			}
			status = v.finishStreamCloseOutputV1(i, claimed, ctx, inv, child, row, actual)
			v.parent.mu.Lock()
			closed := v.streams[i].closed
			v.parent.mu.Unlock()
			if fault == "none" {
				if status != 0 || !closed {
					t.Fatal("actual clean refused", status, closed)
				}
			} else if status == 0 || closed {
				t.Fatal("fence admitted", status, closed)
			}
		})
	}
}
