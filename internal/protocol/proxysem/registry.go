// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxysem

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

type Handler func(TargetDescriptor, TargetRequest, int64) ([]TargetChunk, TargetResult, error)

type Registry struct {
	handlers map[string]Handler
}

func DefaultRegistry() Registry {
	return Registry{handlers: map[string]Handler{
		TargetEcho:            runEcho,
		TargetDiscard:         runDiscard,
		TargetFixedResponse:   runFixedResponse,
		TargetSlowResponse:    runSlowResponse,
		TargetChunkedResponse: runChunkedResponse,
		TargetLargeObject:     runLargeObject,
		TargetErrorResponse:   runErrorResponse,
		TargetResetMidstream:  runResetMidstream,
		TargetDripResponse:    runDripResponse,
		TargetJitteryResponse: runJitteryResponse,
	}}
}

func (r Registry) Lookup(class string) (Handler, bool) {
	handler, ok := r.handlers[class]
	return handler, ok
}

func (r Registry) Validate(desc TargetDescriptor) error {
	if desc.Class == "" {
		return fmt.Errorf("%w: target class is required", ErrInvalidDescriptor)
	}
	if _, ok := r.handlers[desc.Class]; !ok {
		return fmt.Errorf("%w: %s", ErrUnknownTarget, desc.Class)
	}
	for key, value := range desc.Parameters {
		if unsafeParameterName(key) {
			return fmt.Errorf("%w: unsafe parameter %q", ErrInvalidDescriptor, key)
		}
		if len(value) > 64 {
			return fmt.Errorf("%w: parameter %q too long", ErrInvalidDescriptor, key)
		}
	}
	if _, err := sizeParam(desc, "bytes", 0); err != nil {
		return err
	}
	if _, err := sizeParam(desc, "partial", 0); err != nil {
		return err
	}
	if _, err := boundedIntParam(desc, "chunks", 1, 256, 0); err != nil {
		return err
	}
	if _, err := boundedIntParam(desc, "ticks", 1, 64, 0); err != nil {
		return err
	}
	if _, err := boundedIntParam(desc, "seed", 0, 1<<30, 0); err != nil {
		return err
	}
	return nil
}

func (r Registry) Run(desc TargetDescriptor, req TargetRequest, seed int64) ([]TargetChunk, TargetResult, error) {
	if err := r.Validate(desc); err != nil {
		return nil, TargetResult{}, err
	}
	if req.StreamID == 0 {
		return nil, TargetResult{}, fmt.Errorf("%w: stream id is required", ErrInvalidIntent)
	}
	if req.Bytes < 0 || req.Bytes > DefaultMaxRequestBytes {
		return nil, TargetResult{}, fmt.Errorf("%w: invalid request bytes", ErrOversizedTarget)
	}
	handler := r.handlers[desc.Class]
	return handler(desc, req, seed)
}

func runEcho(desc TargetDescriptor, req TargetRequest, seed int64) ([]TargetChunk, TargetResult, error) {
	chunks := chunksFor(req.StreamID, req.Bytes, requestedChunks(desc, 1), false, "echo")
	return chunks, resultFor(req.StreamID, chunks, "", false), nil
}

func runDiscard(desc TargetDescriptor, req TargetRequest, seed int64) ([]TargetChunk, TargetResult, error) {
	return nil, TargetResult{StreamID: req.StreamID, Closed: true}, nil
}

func runFixedResponse(desc TargetDescriptor, req TargetRequest, seed int64) ([]TargetChunk, TargetResult, error) {
	size := mustSizeParam(desc, "bytes", 1024)
	chunks := chunksFor(req.StreamID, size, requestedChunks(desc, 1), false, "fixed")
	return chunks, resultFor(req.StreamID, chunks, "", false), nil
}

func runSlowResponse(desc TargetDescriptor, req TargetRequest, seed int64) ([]TargetChunk, TargetResult, error) {
	size := mustSizeParam(desc, "bytes", 2048)
	ticks := mustBoundedIntParam(desc, "ticks", 2, 1, 64)
	chunks := chunksFor(req.StreamID, size, ticks, true, "slow_tick")
	for i := range chunks {
		chunks[i].Tick = i + 1
	}
	return chunks, resultFor(req.StreamID, chunks, "", false), nil
}

func runChunkedResponse(desc TargetDescriptor, req TargetRequest, seed int64) ([]TargetChunk, TargetResult, error) {
	size := mustSizeParam(desc, "bytes", 4096)
	chunks := chunksFor(req.StreamID, size, requestedChunks(desc, 4), false, "chunk")
	return chunks, resultFor(req.StreamID, chunks, "", false), nil
}

func runLargeObject(desc TargetDescriptor, req TargetRequest, seed int64) ([]TargetChunk, TargetResult, error) {
	size := mustSizeParam(desc, "bytes", 256*1024)
	chunks := chunksFor(req.StreamID, size, max(4, size/(32*1024)), true, "large_object")
	return chunks, resultFor(req.StreamID, chunks, "", false), nil
}

func runErrorResponse(desc TargetDescriptor, req TargetRequest, seed int64) ([]TargetChunk, TargetResult, error) {
	code := desc.Parameters["code"]
	if code == "" {
		code = "synthetic_target_error"
	}
	return nil, TargetResult{StreamID: req.StreamID, ErrorCode: code, Closed: true}, nil
}

func runResetMidstream(desc TargetDescriptor, req TargetRequest, seed int64) ([]TargetChunk, TargetResult, error) {
	partial := mustSizeParam(desc, "partial", min(req.Bytes, 256))
	chunks := chunksFor(req.StreamID, partial, 1, false, "partial_before_reset")
	if len(chunks) == 0 {
		chunks = []TargetChunk{{StreamID: req.StreamID, ChunkIndex: 0, Final: true, MetadataClass: "partial_before_reset"}}
	}
	chunks[len(chunks)-1].Reset = true
	return chunks, resultFor(req.StreamID, chunks, "target_reset_midstream", true), nil
}

func runDripResponse(desc TargetDescriptor, req TargetRequest, seed int64) ([]TargetChunk, TargetResult, error) {
	size := mustSizeParam(desc, "bytes", 1024)
	chunks := chunksFor(req.StreamID, size, requestedChunks(desc, 16), false, "drip")
	return chunks, resultFor(req.StreamID, chunks, "", false), nil
}

func runJitteryResponse(desc TargetDescriptor, req TargetRequest, seed int64) ([]TargetChunk, TargetResult, error) {
	size := mustSizeParam(desc, "bytes", 2048)
	localSeed := int64(mustBoundedIntParam(desc, "seed", int(seed%997), 0, 1<<30))
	rng := rand.New(rand.NewSource(seed + localSeed))
	chunkCount := 2 + rng.Intn(5)
	chunks := make([]TargetChunk, 0, chunkCount)
	remaining := size
	for i := 0; i < chunkCount; i++ {
		part := remaining
		if i < chunkCount-1 {
			part = 1 + rng.Intn(max(1, remaining/(chunkCount-i)))
		}
		remaining -= part
		chunks = append(chunks, TargetChunk{
			StreamID:      req.StreamID,
			ChunkIndex:    i,
			Bytes:         part,
			Final:         i == chunkCount-1,
			MetadataClass: "jitter_bucket_" + strconv.Itoa((int(localSeed)+i)%4),
			Tick:          i + 1 + rng.Intn(3),
		})
	}
	return chunks, resultFor(req.StreamID, chunks, "", false), nil
}

func chunksFor(streamID uint64, total, count int, backpressure bool, metadata string) []TargetChunk {
	if total <= 0 {
		return nil
	}
	if count <= 0 {
		count = 1
	}
	if count > total {
		count = total
	}
	chunks := make([]TargetChunk, 0, count)
	remaining := total
	for i := 0; i < count; i++ {
		part := remaining / (count - i)
		if part == 0 {
			part = remaining
		}
		remaining -= part
		chunks = append(chunks, TargetChunk{
			StreamID:      streamID,
			ChunkIndex:    i,
			Bytes:         part,
			Final:         i == count-1,
			Backpressure:  backpressure && i == 0,
			MetadataClass: metadata,
		})
	}
	return chunks
}

func resultFor(streamID uint64, chunks []TargetChunk, errorCode string, reset bool) TargetResult {
	result := TargetResult{StreamID: streamID, ChunkCount: len(chunks), ErrorCode: errorCode, Reset: reset, Closed: !reset}
	for _, chunk := range chunks {
		result.ResponseBytes += chunk.Bytes
		if chunk.ErrorCode != "" {
			result.ErrorCode = chunk.ErrorCode
		}
		if chunk.Reset {
			result.Reset = true
			result.Closed = false
		}
	}
	return result
}

func requestedChunks(desc TargetDescriptor, fallback int) int {
	return mustBoundedIntParam(desc, "chunks", fallback, 1, 256)
}

func sizeParam(desc TargetDescriptor, key string, fallback int) (int, error) {
	value, ok := desc.Parameters[key]
	if !ok || value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid %s", ErrInvalidDescriptor, key)
	}
	if parsed < 0 || parsed > DefaultMaxResponseBytes {
		return 0, fmt.Errorf("%w: %s exceeds safety bound", ErrOversizedTarget, key)
	}
	return parsed, nil
}

func mustSizeParam(desc TargetDescriptor, key string, fallback int) int {
	value, err := sizeParam(desc, key, fallback)
	if err != nil {
		return fallback
	}
	return value
}

func boundedIntParam(desc TargetDescriptor, key string, minValue, maxValue, fallback int) (int, error) {
	value, ok := desc.Parameters[key]
	if !ok || value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid %s", ErrInvalidDescriptor, key)
	}
	if parsed < minValue || parsed > maxValue {
		return 0, fmt.Errorf("%w: %s outside bounds", ErrInvalidDescriptor, key)
	}
	return parsed, nil
}

func mustBoundedIntParam(desc TargetDescriptor, key string, fallback, minValue, maxValue int) int {
	value, err := boundedIntParam(desc, key, minValue, maxValue, fallback)
	if err != nil {
		return fallback
	}
	return value
}

func unsafeParameterName(key string) bool {
	lower := strings.ToLower(key)
	for _, unsafe := range []string{"host", "hostname", "address", "addr", "url", "uri", "ip", "port", "dns", "domain"} {
		if strings.Contains(lower, unsafe) {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
