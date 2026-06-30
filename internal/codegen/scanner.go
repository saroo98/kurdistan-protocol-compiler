// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package codegen

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type SourceScanReport struct {
	GeneratedModules                  int            `json:"generated_modules"`
	ProfileSpecificConstantsPresent   bool           `json:"profile_specific_constants_present"`
	SpecializedFilesDiffer            bool           `json:"specialized_files_differ"`
	WrapperOnly                       bool           `json:"wrapper_only"`
	DirectFSMUse                      bool           `json:"direct_fsm_use"`
	RuntimeProfileLoad                bool           `json:"runtime_profile_load"`
	PayloadLogging                    bool           `json:"payload_logging"`
	ForbiddenMagicStrings             []string       `json:"forbidden_magic_strings,omitempty"`
	SpecializedFileUniqueFingerprints map[string]int `json:"specialized_file_unique_fingerprints"`
	ModuleReports                     []ModuleScan   `json:"module_reports"`
	Failures                          []string       `json:"failures,omitempty"`
	Passed                            bool           `json:"passed"`
}

type ModuleScan struct {
	Directory                       string   `json:"directory"`
	GoFileCount                     int      `json:"go_file_count"`
	ProfileSpecificConstantsPresent bool     `json:"profile_specific_constants_present"`
	WrapperOnly                     bool     `json:"wrapper_only"`
	DirectFSMUse                    bool     `json:"direct_fsm_use"`
	RuntimeProfileLoad              bool     `json:"runtime_profile_load"`
	PayloadLogging                  bool     `json:"payload_logging"`
	ForbiddenMagicStrings           []string `json:"forbidden_magic_strings,omitempty"`
	Failures                        []string `json:"failures,omitempty"`
}

func ScanGeneratedOutputs(dirs []string) (SourceScanReport, error) {
	report := SourceScanReport{
		GeneratedModules:                  len(dirs),
		ProfileSpecificConstantsPresent:   true,
		SpecializedFileUniqueFingerprints: map[string]int{},
		Passed:                            true,
	}
	if len(dirs) == 0 {
		report.Passed = false
		report.Failures = append(report.Failures, "no generated modules provided")
		return report, nil
	}
	specialized := []string{
		"protocol/profile_static.go",
		"protocol/states_generated.go",
		"protocol/framing_generated.go",
		"protocol/stream_generated.go",
		"protocol/proxysem_generated.go",
		"protocol/carrier_generated.go",
		"protocol/security_generated.go",
		"protocol/runtime_generated.go",
		"protocol/hardening_generated.go",
		"protocol/adapter_generated.go",
		"protocol/localadapter_generated.go",
		"protocol/bytetransport_generated.go",
		"protocol/protocorpus_generated.go",
		"protocol/wirefeatures_generated.go",
		"protocol/wiregen_generated.go",
		"protocol/wireeval_generated.go",
		"protocol/hostdetect_generated.go",
		"protocol/relayfleet_generated.go",
		"protocol/proxyingress_generated.go",
		"protocol/localproxyingress_generated.go",
		"protocol/localproxyingressadv_generated.go",
		"protocol/adaptivepath_generated.go",
		"protocol/transportbundle_generated.go",
		"protocol/scheduler_generated.go",
		"protocol/invalid_input_generated.go",
		"protocol/auth_generated.go",
	}
	fingerprints := map[string]map[string]bool{}
	for _, rel := range specialized {
		fingerprints[rel] = map[string]bool{}
	}
	for _, dir := range dirs {
		module, sources, err := scanModule(dir)
		if err != nil {
			return SourceScanReport{}, err
		}
		report.ModuleReports = append(report.ModuleReports, module)
		report.ProfileSpecificConstantsPresent = report.ProfileSpecificConstantsPresent && module.ProfileSpecificConstantsPresent
		report.WrapperOnly = report.WrapperOnly || module.WrapperOnly
		report.DirectFSMUse = report.DirectFSMUse || module.DirectFSMUse
		report.RuntimeProfileLoad = report.RuntimeProfileLoad || module.RuntimeProfileLoad
		report.PayloadLogging = report.PayloadLogging || module.PayloadLogging
		report.ForbiddenMagicStrings = appendUnique(report.ForbiddenMagicStrings, module.ForbiddenMagicStrings...)
		report.Failures = append(report.Failures, module.Failures...)
		for _, rel := range specialized {
			if content, ok := sources[rel]; ok {
				fingerprints[rel][sourceHash(content)] = true
			}
		}
	}
	for rel, values := range fingerprints {
		report.SpecializedFileUniqueFingerprints[rel] = len(values)
		if len(dirs) > 1 && len(values) > 1 {
			report.SpecializedFilesDiffer = true
		}
	}
	if !report.ProfileSpecificConstantsPresent {
		report.Failures = append(report.Failures, "profile-specific constants missing")
	}
	if !report.SpecializedFilesDiffer && len(dirs) > 1 {
		report.Failures = append(report.Failures, "specialized generated files did not differ")
	}
	if report.WrapperOnly {
		report.Failures = append(report.Failures, "generated source appears to be wrapper-only")
	}
	if report.DirectFSMUse {
		report.Failures = append(report.Failures, "generated source directly imports or invokes internal/fsm")
	}
	if report.RuntimeProfileLoad {
		report.Failures = append(report.Failures, "generated source loads profile.json or calls LoadProfile at runtime")
	}
	if report.PayloadLogging {
		report.Failures = append(report.Failures, "generated source appears to perform payload logging")
	}
	if len(report.ForbiddenMagicStrings) > 0 {
		report.Failures = append(report.Failures, "generated source contains forbidden universal magic strings")
	}
	report.Failures = uniqueSorted(report.Failures)
	report.ForbiddenMagicStrings = uniqueSorted(report.ForbiddenMagicStrings)
	report.Passed = len(report.Failures) == 0
	return report, nil
}

func scanModule(dir string) (ModuleScan, map[string]string, error) {
	label := filepath.Base(dir)
	module := ModuleScan{Directory: label}
	sources := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sources[rel] = string(raw)
		module.GoFileCount++
		return nil
	})
	if err != nil {
		return ModuleScan{}, nil, err
	}
	joined := strings.Join(mapValues(sources), "\n")
	module.ProfileSpecificConstantsPresent = strings.Contains(joined, "const ProfileID") &&
		strings.Contains(joined, "var transitionTable") &&
		strings.Contains(joined, "var semanticWireSymbols") &&
		strings.Contains(joined, "const StreamIDEncodingMode") &&
		strings.Contains(joined, "const ProxyRelayIntentEncoding") &&
		strings.Contains(joined, "const CarrierFamily") &&
		strings.Contains(joined, "const SecurityTranscriptMode") &&
		strings.Contains(joined, "const RuntimeProfileID") &&
		strings.Contains(joined, "const HardeningProfileID") &&
		strings.Contains(joined, "const AdapterGeneratedProfileID") &&
		strings.Contains(joined, "const LocalAdapterGeneratedProfileID") &&
		strings.Contains(joined, "const ByteTransportGeneratedProfileID") &&
		strings.Contains(joined, "const BytePathFixtureSchemaVersion") &&
		strings.Contains(joined, "const ProtocolCorpusSchemaVersion") &&
		strings.Contains(joined, "const WireFeatureSchemaVersion") &&
		strings.Contains(joined, "const WireGenPolicyVersion") &&
		strings.Contains(joined, "const WireGenPolicyHash") &&
		strings.Contains(joined, "const WireEvalDatasetVersion") &&
		strings.Contains(joined, "const HostDetectSchemaVersion") &&
		strings.Contains(joined, "const RelayFleetSchemaVersion") &&
		strings.Contains(joined, "const ProxyIngressSchemaVersion") &&
		strings.Contains(joined, "const LocalProxyIngressSchemaVersion") &&
		strings.Contains(joined, "const LocalProxyIngressAdversarialSchemaVersion") &&
		strings.Contains(joined, "const AdaptivePathSchemaVersion") &&
		strings.Contains(joined, "const TransportBundleSchemaVersion")
	module.DirectFSMUse = strings.Contains(joined, "internal/fsm") || strings.Contains(joined, "fsm.New(")
	module.RuntimeProfileLoad = strings.Contains(joined, "LoadProfile(") || strings.Contains(joined, "profile.json")
	module.WrapperOnly = IsGeneratedWrapperOnly(joined) || (!module.ProfileSpecificConstantsPresent && module.RuntimeProfileLoad)
	module.PayloadLogging = looksLikePayloadLogging(joined)
	module.ForbiddenMagicStrings = forbiddenMagicStrings(joined)
	if !module.ProfileSpecificConstantsPresent {
		module.Failures = append(module.Failures, fmt.Sprintf("%s: profile-specific constants missing", label))
	}
	if module.DirectFSMUse {
		module.Failures = append(module.Failures, fmt.Sprintf("%s: internal/fsm direct use", label))
	}
	if module.RuntimeProfileLoad {
		module.Failures = append(module.Failures, fmt.Sprintf("%s: runtime profile.json load", label))
	}
	if module.WrapperOnly {
		module.Failures = append(module.Failures, fmt.Sprintf("%s: wrapper-only generated source", label))
	}
	if module.PayloadLogging {
		module.Failures = append(module.Failures, fmt.Sprintf("%s: payload logging detected", label))
	}
	for _, value := range module.ForbiddenMagicStrings {
		module.Failures = append(module.Failures, fmt.Sprintf("%s: forbidden magic %s", label, value))
	}
	return module, sources, nil
}

func looksLikePayloadLogging(source string) bool {
	lines := strings.Split(source, "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "payload") {
			continue
		}
		if strings.Contains(line, "fmt.Print") || strings.Contains(line, "log.Print") || strings.Contains(line, "Printf(") {
			return true
		}
	}
	return false
}

func forbiddenMagicStrings(source string) []string {
	forbidden := []string{"HELLO", "AUTH", "OPEN", "KURD", "VPN", "PROXY", "CONNECT"}
	var out []string
	for _, value := range forbidden {
		if strings.Contains(source, value) {
			out = append(out, value)
		}
	}
	return out
}

func mapValues(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, values[key])
	}
	return out
}

func sourceHash(source string) string {
	sum := 0
	for _, r := range source {
		sum = (sum*131 + int(r)) % 1000000007
	}
	return fmt.Sprint(sum)
}

func appendUnique(values []string, additions ...string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range additions {
		if !seen[value] {
			values = append(values, value)
			seen[value] = true
		}
	}
	return values
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
