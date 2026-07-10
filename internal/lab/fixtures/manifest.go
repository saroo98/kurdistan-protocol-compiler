// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package fixtures

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

type FixtureManifest struct {
	Version        string                   `json:"version"`
	GeneratedAt    string                   `json:"generated_at"`
	FixtureSet     string                   `json:"fixture_set"`
	ProfileSeeds   []int                    `json:"profile_seeds"`
	ScenarioNames  []string                 `json:"scenario_names"`
	BackendVersion string                   `json:"backend_version"`
	FixtureCount   int                      `json:"fixture_count"`
	PayloadLogged  bool                     `json:"payload_logged"`
	SecretLogged   bool                     `json:"secret_logged"`
	Entries        []FixtureEntry           `json:"entries"`
	Summaries      []BytePathFixtureSummary `json:"summaries"`
	MalformedCases []MalformedByteCase      `json:"malformed_cases,omitempty"`
	Performance    *PerformanceBaseline     `json:"performance,omitempty"`
}

func NewManifest(opts ManifestOptions) FixtureManifest {
	if opts.FixtureSet == "" {
		opts.FixtureSet = "bytepath-golden"
	}
	if opts.Backend == "" {
		opts.Backend = BackendLab
	}
	if opts.GeneratedAt == "" {
		opts.GeneratedAt = FixedGeneratedAt()
	}
	if len(opts.ProfileSeeds) == 0 {
		opts.ProfileSeeds = DefaultSeeds()
	}
	if len(opts.ScenarioNames) == 0 {
		opts.ScenarioNames = DefaultScenarios()
	}
	return FixtureManifest{
		Version:        SchemaVersion,
		GeneratedAt:    opts.GeneratedAt,
		FixtureSet:     opts.FixtureSet,
		ProfileSeeds:   append([]int(nil), opts.ProfileSeeds...),
		ScenarioNames:  append([]string(nil), opts.ScenarioNames...),
		BackendVersion: opts.BackendVersion,
	}
}

func (m *FixtureManifest) Normalize() {
	sort.Ints(m.ProfileSeeds)
	sort.Strings(m.ScenarioNames)
	sort.Slice(m.Entries, func(i, j int) bool {
		return m.Entries[i].Name < m.Entries[j].Name
	})
	sort.Slice(m.Summaries, func(i, j int) bool {
		if m.Summaries[i].ProfileSeed != m.Summaries[j].ProfileSeed {
			return m.Summaries[i].ProfileSeed < m.Summaries[j].ProfileSeed
		}
		if m.Summaries[i].Scenario != m.Summaries[j].Scenario {
			return m.Summaries[i].Scenario < m.Summaries[j].Scenario
		}
		return m.Summaries[i].Backend < m.Summaries[j].Backend
	})
	sort.Slice(m.MalformedCases, func(i, j int) bool {
		return m.MalformedCases[i].Name < m.MalformedCases[j].Name
	})
	m.FixtureCount = len(m.Entries)
	m.PayloadLogged = false
	m.SecretLogged = false
	for _, entry := range m.Entries {
		m.PayloadLogged = m.PayloadLogged || entry.PayloadLogged
		m.SecretLogged = m.SecretLogged || entry.SecretLogged
	}
}

func LoadManifest(path string) (FixtureManifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return FixtureManifest{}, err
	}
	var manifest FixtureManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return FixtureManifest{}, err
	}
	return manifest, nil
}

func WriteManifest(path string, manifest FixtureManifest, force bool) error {
	if path == "" {
		return ErrMissingPath
	}
	if !force {
		if _, err := os.Stat(path); err == nil {
			return ErrRefuseOverwrite
		}
	}
	manifest.Normalize()
	if err := ValidateManifest(manifest); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := StableJSON(manifest)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func StableJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
