// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localpipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func HashValue(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fixtureHashInput(set PipelineFixtureSet) PipelineFixtureSet {
	set.GeneratedAt = ""
	set.FixtureHash = ""
	return set
}

func runHashInput(run PipelineRunSummary) PipelineRunSummary {
	run.RunHash = ""
	return run
}
