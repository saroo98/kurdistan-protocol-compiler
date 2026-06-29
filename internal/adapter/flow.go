// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapter

import "fmt"

type Flow struct {
	Descriptor FlowDescriptor `json:"descriptor"`
	State      FlowState      `json:"state"`
	ReadBytes  int            `json:"read_bytes"`
	WriteBytes int            `json:"write_bytes"`
	Events     int            `json:"events"`
}

func NewFlow(desc FlowDescriptor) (*Flow, error) {
	if err := ValidateFlowDescriptor(desc); err != nil {
		return nil, err
	}
	return &Flow{Descriptor: desc, State: FlowNew}, nil
}

func ValidateFlowDescriptor(desc FlowDescriptor) error {
	if desc.ID == "" {
		return fmt.Errorf("%w: flow id required", ErrInvalidFlow)
	}
	if containsSensitiveMarker(string(desc.ID)) || containsSensitiveMarker(desc.TargetHint) {
		return fmt.Errorf("%w: secret-like flow value rejected", ErrInvalidFlow)
	}
	if desc.Class == "" || desc.Direction == "" || desc.RequestClass == "" || desc.PriorityClass == "" {
		return fmt.Errorf("%w: class, direction, request, and priority are required", ErrInvalidFlow)
	}
	if desc.Direction != "ingress" && desc.Direction != "egress" && desc.Direction != "bidirectional" {
		return fmt.Errorf("%w: unsupported flow direction", ErrInvalidFlow)
	}
	if desc.MaxReadBytes <= 0 || desc.MaxReadBytes > MaxAdapterFlowBytes {
		return fmt.Errorf("%w: max read bytes out of bounds", ErrInvalidFlow)
	}
	if desc.MaxWriteBytes <= 0 || desc.MaxWriteBytes > MaxAdapterFlowBytes {
		return fmt.Errorf("%w: max write bytes out of bounds", ErrInvalidFlow)
	}
	if desc.MetadataPolicy == "" {
		return fmt.Errorf("%w: metadata policy required", ErrInvalidFlow)
	}
	return nil
}

func (f *Flow) Terminal() bool {
	return f.State == FlowClosed || f.State == FlowReset || f.State == FlowFailed
}

func (f *Flow) CanWrite() bool {
	return f != nil && (f.State == FlowOpen || f.State == FlowDraining)
}

func (f *Flow) RecordRead(n int) error {
	if f == nil {
		return fmt.Errorf("%w: nil flow", ErrInvalidFlow)
	}
	if n < 0 || f.ReadBytes+n > f.Descriptor.MaxReadBytes {
		return fmt.Errorf("%w: flow read limit", ErrResourceLimit)
	}
	f.ReadBytes += n
	f.Events++
	return nil
}

func (f *Flow) RecordWrite(n int) error {
	if f == nil {
		return fmt.Errorf("%w: nil flow", ErrInvalidFlow)
	}
	if !f.CanWrite() {
		return fmt.Errorf("%w: write after terminal or unopened state", ErrFlowTerminal)
	}
	if n < 0 || f.WriteBytes+n > f.Descriptor.MaxWriteBytes {
		return fmt.Errorf("%w: flow write limit", ErrResourceLimit)
	}
	f.WriteBytes += n
	f.Events++
	return nil
}
