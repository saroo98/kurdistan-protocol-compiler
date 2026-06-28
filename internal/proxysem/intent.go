// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxysem

import "fmt"

type RequestClass string

const (
	RequestInteractive RequestClass = "interactive"
	RequestBulk        RequestClass = "bulk"
	RequestControl     RequestClass = "control"
	RequestErrorTest   RequestClass = "error_test"
	RequestGenerated   RequestClass = "generated_bucket"
)

type PriorityClass string

const (
	PriorityInteractive PriorityClass = "interactive"
	PriorityBulk        PriorityClass = "bulk"
	PriorityControl     PriorityClass = "control"
)

type ResponseMode string

const (
	ResponseImmediate   ResponseMode = "immediate"
	ResponseChunked     ResponseMode = "chunked"
	ResponseDelayed     ResponseMode = "delayed"
	ResponseResettable  ResponseMode = "resettable"
	ResponseErrorable   ResponseMode = "errorable"
	ResponseLargeObject ResponseMode = "large_object"
)

type RelayIntent struct {
	StreamID         uint64           `json:"stream_id"`
	RelayIntentID    uint64           `json:"relay_intent_id"`
	Target           TargetDescriptor `json:"target"`
	RequestClass     RequestClass     `json:"request_class"`
	PriorityClass    PriorityClass    `json:"priority_class"`
	ResponseMode     ResponseMode     `json:"response_mode"`
	MaxRequestBytes  int              `json:"max_request_bytes"`
	MaxResponseBytes int              `json:"max_response_bytes"`
}

type TargetDescriptor struct {
	Class      string            `json:"class"`
	Variant    string            `json:"variant,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

type TargetRequest struct {
	StreamID uint64       `json:"stream_id"`
	Bytes    int          `json:"bytes"`
	Class    RequestClass `json:"class"`
}

func ValidateRelayIntent(intent RelayIntent) error {
	if intent.StreamID == 0 {
		return fmt.Errorf("%w: stream id is required", ErrInvalidIntent)
	}
	if intent.MaxRequestBytes <= 0 || intent.MaxResponseBytes <= 0 {
		return fmt.Errorf("%w: positive request and response limits are required", ErrInvalidIntent)
	}
	if intent.MaxRequestBytes > DefaultMaxRequestBytes || intent.MaxResponseBytes > DefaultMaxResponseBytes {
		return fmt.Errorf("%w: proxy intent exceeds lab safety bounds", ErrOversizedTarget)
	}
	if !validRequestClass(intent.RequestClass) {
		return fmt.Errorf("%w: invalid request class %q", ErrInvalidIntent, intent.RequestClass)
	}
	if !validPriorityClass(intent.PriorityClass) {
		return fmt.Errorf("%w: invalid priority class %q", ErrInvalidIntent, intent.PriorityClass)
	}
	if !validResponseMode(intent.ResponseMode) {
		return fmt.Errorf("%w: invalid response mode %q", ErrInvalidIntent, intent.ResponseMode)
	}
	return DefaultRegistry().Validate(intent.Target)
}

func validRequestClass(class RequestClass) bool {
	switch class {
	case RequestInteractive, RequestBulk, RequestControl, RequestErrorTest, RequestGenerated:
		return true
	default:
		return false
	}
}

func validPriorityClass(class PriorityClass) bool {
	switch class {
	case PriorityInteractive, PriorityBulk, PriorityControl:
		return true
	default:
		return false
	}
}

func validResponseMode(mode ResponseMode) bool {
	switch mode {
	case ResponseImmediate, ResponseChunked, ResponseDelayed, ResponseResettable, ResponseErrorable, ResponseLargeObject:
		return true
	default:
		return false
	}
}
