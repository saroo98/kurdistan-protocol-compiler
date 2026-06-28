// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package codegen

import "kurdistan/internal/ir"

const (
	Version       = "0.9.0-lab"
	SourceBackend = "go-static-v0"
)

type Manifest struct {
	ProfileID        string         `json:"profile_id"`
	ProfileSeed      int64          `json:"profile_seed"`
	GeneratorVersion string         `json:"generator_version"`
	GeneratedAt      string         `json:"generated_at"`
	SourceBackend    string         `json:"source_backend"`
	States           int            `json:"states"`
	Transitions      int            `json:"transitions"`
	FrameGrammar     string         `json:"frame_grammar"`
	Scheduler        string         `json:"scheduler"`
	Stream           string         `json:"stream"`
	Padding          string         `json:"padding"`
	InvalidInput     string         `json:"invalid_input"`
	Safety           ManifestSafety `json:"safety"`
}

type ManifestSafety struct {
	ExternalNetworking bool `json:"external_networking"`
	Deployment         bool `json:"deployment"`
	PayloadLogging     bool `json:"payload_logging"`
}

func NewManifest(p *ir.Profile, generatedAt string) Manifest {
	return Manifest{
		ProfileID:        p.ID,
		ProfileSeed:      p.Seed,
		GeneratorVersion: Version,
		GeneratedAt:      generatedAt,
		SourceBackend:    SourceBackend,
		States:           len(p.States),
		Transitions:      len(p.Transitions),
		FrameGrammar:     p.FrameGrammar.LengthMode + "/" + p.FrameGrammar.TypeMode + "/" + p.FrameGrammar.FragmentationMode + "/" + p.FrameGrammar.PaddingPlacement,
		Scheduler:        p.Scheduler.Mode,
		Stream:           p.Stream.IDEncodingMode + "/" + p.Stream.PriorityPolicy + "/" + p.Stream.WindowUpdatePolicy,
		Padding:          p.Padding.Mode,
		InvalidInput:     p.InvalidInput.UnknownFirstMessage + "/" + p.InvalidInput.MalformedFrame + "/" + p.InvalidInput.FailedAuth + "/" + p.InvalidInput.Replay,
		Safety: ManifestSafety{
			ExternalNetworking: false,
			Deployment:         false,
			PayloadLogging:     false,
		},
	}
}
