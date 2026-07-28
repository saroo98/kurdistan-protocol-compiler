// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"reflect"
	"sync"
	"testing"
)

func TestABIInfoRoundTripAndBounds(t *testing.T) {
	want := CurrentABIInfo()
	encoded, err := EncodeABIInfo(want)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > MaxABIInfoBytes {
		t.Fatalf("encoded ABI info is %d bytes", len(encoded))
	}
	got, err := DecodeABIInfo(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ABI mismatch:\ngot=%+v\nwant=%+v", got, want)
	}
	for _, index := range []int{0, 1, 2, 3, 4, 5, 6, 7} {
		mutated := append([]byte(nil), encoded...)
		mutated[index] ^= 0xff
		if _, err := DecodeABIInfo(mutated); err == nil {
			t.Fatalf("mutation at byte %d was accepted", index)
		}
	}
	for length := 0; length < len(encoded); length++ {
		if _, err := DecodeABIInfo(encoded[:length]); err == nil {
			t.Fatalf("truncation at byte %d was accepted", length)
		}
	}
	if _, err := DecodeABIInfo(append(encoded, 0)); err == nil {
		t.Fatal("trailing byte was accepted")
	}
}

func TestHandleRegistryRejectsWrongTypeReplayAndDoubleFree(t *testing.T) {
	registry := &HandleRegistry{}
	handle, code := registry.Open(HandleActivation, "value")
	if code != CodeOK {
		t.Fatal(code)
	}
	if _, code := registry.Get(handle, HandleBackup); code != CodeWrongHandleType {
		t.Fatalf("wrong type code=%v", code)
	}
	if code := registry.Free(handle); code != CodeOK {
		t.Fatal(code)
	}
	if code := registry.Free(handle); code != CodeAlreadyClosed {
		t.Fatalf("double free code=%v", code)
	}
	reused, code := registry.Open(HandleActivation, "next")
	if code != CodeOK || reused == handle {
		t.Fatalf("reused handle=%x old=%x code=%v", reused, handle, code)
	}
	if _, code := registry.Get(handle, HandleActivation); code != CodeAlreadyClosed {
		t.Fatalf("stale generation code=%v", code)
	}
}

type destroyingHandle struct {
	count int
}

func (handle *destroyingHandle) Destroy() {
	handle.count++
}

func TestHandleRegistryDestroysSensitiveStateExactlyOnce(t *testing.T) {
	registry := &HandleRegistry{}
	value := &destroyingHandle{}
	handle, code := registry.Open(HandleBackup, value)
	if code != CodeOK {
		t.Fatal(code)
	}
	if code := registry.Free(handle); code != CodeOK {
		t.Fatal(code)
	}
	if value.count != 1 {
		t.Fatalf("destroy count=%d want=1", value.count)
	}
	if code := registry.Free(handle); code != CodeAlreadyClosed {
		t.Fatalf("double free code=%v", code)
	}
	if value.count != 1 {
		t.Fatalf("destroy count after double free=%d want=1", value.count)
	}
}

func TestHandleRegistryCapacityCancellationAndConcurrency(t *testing.T) {
	registry := &HandleRegistry{}
	handles := make([]Handle, MaxBridgeHandles)
	for index := range handles {
		handle, code := registry.Open(HandleDiagnostic, index)
		if code != CodeOK {
			t.Fatalf("open %d code=%v", index, code)
		}
		handles[index] = handle
	}
	if _, code := registry.Open(HandleDiagnostic, "overflow"); code != CodeSizeLimit {
		t.Fatalf("overflow code=%v", code)
	}

	var wait sync.WaitGroup
	for _, handle := range handles {
		wait.Add(1)
		go func(handle Handle) {
			defer wait.Done()
			if code := registry.Cancel(handle); code != CodeOK {
				t.Errorf("cancel code=%v", code)
			}
			if _, code := registry.Get(handle, HandleDiagnostic); code != CodeCancelled {
				t.Errorf("cancelled get code=%v", code)
			}
			if code := registry.Free(handle); code != CodeOK {
				t.Errorf("free code=%v", code)
			}
		}(handle)
	}
	wait.Wait()
}
