// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapter

type EgressAdapter interface {
	Name() string
	ValidateConfig(AdapterConfig) error
	WriteFlow(FlowID, AdapterChunk) error
	CloseFlow(FlowID) error
	ResetFlow(FlowID, string) error
	Summary() AdapterSummary
}
