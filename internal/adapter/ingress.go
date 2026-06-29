// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapter

type IngressAdapter interface {
	Name() string
	ValidateConfig(AdapterConfig) error
	OpenFlow(FlowDescriptor) error
	ReadFlow(FlowID, int) (AdapterChunk, error)
	CloseFlow(FlowID) error
	ResetFlow(FlowID, string) error
	Summary() AdapterSummary
}
