// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

const Version = "0.14.0-lab"

type AuditConfig struct {
	Mode         string          `json:"mode"`
	StartSeed    int64           `json:"start_seed"`
	ProfileCount int             `json:"profile_count"`
	TraceCount   int             `json:"trace_count"`
	OutputPath   string          `json:"output_path,omitempty"`
	StatusPath   string          `json:"status_path,omitempty"`
	BaselinePath string          `json:"baseline_path,omitempty"`
	Thresholds   AuditThresholds `json:"thresholds"`
}

type AuditThresholds struct {
	MinFirstContactPatterns           int     `json:"min_first_contact_patterns"`
	MinFrameGrammarCombinations       int     `json:"min_frame_grammar_combinations"`
	MinSchedulerCombinations          int     `json:"min_scheduler_combinations"`
	MinPaddingCombinations            int     `json:"min_padding_combinations"`
	MinInvalidInputCombinations       int     `json:"min_invalid_input_combinations"`
	MaxSameFirstFrameSizeRatio        float64 `json:"max_same_first_frame_size_ratio"`
	MaxSameFirstContactCountRatio     float64 `json:"max_same_first_contact_count_ratio"`
	MaxSameStatePathRatio             float64 `json:"max_same_state_path_ratio"`
	MaxSameInvalidOutcomeRatio        float64 `json:"max_same_invalid_outcome_ratio"`
	MaxSameFrameSizeHistogramRatio    float64 `json:"max_same_frame_size_histogram_ratio"`
	MaxSamePaddingHistogramRatio      float64 `json:"max_same_padding_histogram_ratio"`
	MaxSameCloseBehaviorRatio         float64 `json:"max_same_close_behavior_ratio"`
	MaxSameFirstByteRatio             float64 `json:"max_same_first_byte_ratio"`
	MaxSameSemanticSequenceRatio      float64 `json:"max_same_semantic_sequence_ratio"`
	MaxSameWireSymbolSequenceRatio    float64 `json:"max_same_wire_symbol_sequence_ratio"`
	MaxSameMalformedFramePolicyRatio  float64 `json:"max_same_malformed_frame_policy_ratio"`
	MinStructurallyDifferentPairRatio float64 `json:"min_structurally_different_pair_ratio"`
	MinDifferentTraceSeparationRatio  float64 `json:"min_different_trace_separation_ratio"`
	AdversaryClusterThreshold         float64 `json:"adversary_cluster_threshold"`
	MaxKurdistanFamilyCollapseRatio   float64 `json:"max_kurdistan_family_collapse_ratio"`
	MinDifferentProfileDistance       float64 `json:"min_different_profile_distance"`
	MaxSameProfileDistance            float64 `json:"max_same_profile_distance"`
	MaxNoisyFixedClusterSpread        float64 `json:"max_noisy_fixed_cluster_spread"`
	MaxFixedControlClusterSpread      float64 `json:"max_fixed_control_cluster_spread"`
	MinStreamPolicyCombinations       int     `json:"min_stream_policy_combinations"`
	MinStreamIDEncodingModes          int     `json:"min_stream_id_encoding_modes"`
	MinMultiStreamTracePatterns       int     `json:"min_multi_stream_trace_patterns"`
	MaxStreamAdversaryDominantRatio   float64 `json:"max_stream_adversary_dominant_ratio"`
	MinStreamAdversaryDiversityScore  float64 `json:"min_stream_adversary_diversity_score"`
	MinStreamAdversaryScenarioSuccess float64 `json:"min_stream_adversary_scenario_success"`
	MinProxyPolicyCombinations        int     `json:"min_proxy_policy_combinations"`
	MinProxyTargetDescriptorEncodings int     `json:"min_proxy_target_descriptor_encodings"`
	MinProxyErrorPolicies             int     `json:"min_proxy_error_policies"`
	MaxProxyAdversaryDominantRatio    float64 `json:"max_proxy_adversary_dominant_ratio"`
	MinProxyAdversaryDiversityScore   float64 `json:"min_proxy_adversary_diversity_score"`
	MinProxyAdversaryScenarioSuccess  float64 `json:"min_proxy_adversary_scenario_success"`
	MinCarrierPolicyCombinations      int     `json:"min_carrier_policy_combinations"`
	MinCarrierFamilies                int     `json:"min_carrier_families"`
	MinCarrierEnvelopeEncodings       int     `json:"min_carrier_envelope_encodings"`
	MaxCarrierAdversaryDominantRatio  float64 `json:"max_carrier_adversary_dominant_ratio"`
	MinCarrierAdversaryDiversityScore float64 `json:"min_carrier_adversary_diversity_score"`
	MinCarrierScenarioSuccess         float64 `json:"min_carrier_scenario_success"`
	MinSecurityPolicyCombinations     int     `json:"min_security_policy_combinations"`
	MinSecurityTranscriptModes        int     `json:"min_security_transcript_modes"`
	MinSecurityNonceModes             int     `json:"min_security_nonce_modes"`
	MinSecurityReplayPolicies         int     `json:"min_security_replay_policies"`
	MaxRuntimeAdversaryDominantRatio  float64 `json:"max_runtime_adversary_dominant_ratio"`
	MinRuntimeAdversaryDiversityScore float64 `json:"min_runtime_adversary_diversity_score"`
	MinRuntimeScenarioSuccess         float64 `json:"min_runtime_scenario_success"`
}

func DefaultConfig(mode string) AuditConfig {
	if mode == "" {
		mode = "quick"
	}
	cfg := AuditConfig{
		Mode:         mode,
		StartSeed:    1,
		ProfileCount: 100,
		TraceCount:   20,
		Thresholds:   DefaultThresholds(),
	}
	if mode == "full" {
		cfg.ProfileCount = 1000
		cfg.TraceCount = 100
	}
	return cfg
}

func DefaultThresholds() AuditThresholds {
	return AuditThresholds{
		MinFirstContactPatterns:           3,
		MinFrameGrammarCombinations:       10,
		MinSchedulerCombinations:          8,
		MinPaddingCombinations:            6,
		MinInvalidInputCombinations:       20,
		MaxSameFirstFrameSizeRatio:        0.80,
		MaxSameFirstContactCountRatio:     0.80,
		MaxSameStatePathRatio:             0.80,
		MaxSameInvalidOutcomeRatio:        0.80,
		MaxSameFrameSizeHistogramRatio:    0.80,
		MaxSamePaddingHistogramRatio:      0.80,
		MaxSameCloseBehaviorRatio:         0.80,
		MaxSameFirstByteRatio:             0.80,
		MaxSameSemanticSequenceRatio:      0.80,
		MaxSameWireSymbolSequenceRatio:    0.80,
		MaxSameMalformedFramePolicyRatio:  0.80,
		MinStructurallyDifferentPairRatio: 0.95,
		MinDifferentTraceSeparationRatio:  0.70,
		AdversaryClusterThreshold:         0.18,
		MaxKurdistanFamilyCollapseRatio:   0.90,
		MinDifferentProfileDistance:       0.08,
		MaxSameProfileDistance:            0.12,
		MaxNoisyFixedClusterSpread:        0.25,
		MaxFixedControlClusterSpread:      0.01,
		MinStreamPolicyCombinations:       8,
		MinStreamIDEncodingModes:          3,
		MinMultiStreamTracePatterns:       2,
		MaxStreamAdversaryDominantRatio:   0.85,
		MinStreamAdversaryDiversityScore:  0.20,
		MinStreamAdversaryScenarioSuccess: 0.95,
		MinProxyPolicyCombinations:        8,
		MinProxyTargetDescriptorEncodings: 3,
		MinProxyErrorPolicies:             3,
		MaxProxyAdversaryDominantRatio:    0.90,
		MinProxyAdversaryDiversityScore:   0.18,
		MinProxyAdversaryScenarioSuccess:  0.90,
		MinCarrierPolicyCombinations:      8,
		MinCarrierFamilies:                3,
		MinCarrierEnvelopeEncodings:       3,
		MaxCarrierAdversaryDominantRatio:  0.90,
		MinCarrierAdversaryDiversityScore: 0.18,
		MinCarrierScenarioSuccess:         0.90,
		MinSecurityPolicyCombinations:     8,
		MinSecurityTranscriptModes:        3,
		MinSecurityNonceModes:             3,
		MinSecurityReplayPolicies:         3,
		MaxRuntimeAdversaryDominantRatio:  0.92,
		MinRuntimeAdversaryDiversityScore: 0.12,
		MinRuntimeScenarioSuccess:         0.90,
	}
}

func NormalizeConfig(cfg AuditConfig) AuditConfig {
	defaults := DefaultConfig(cfg.Mode)
	if cfg.Mode == "" {
		cfg.Mode = defaults.Mode
	}
	if cfg.StartSeed == 0 {
		cfg.StartSeed = defaults.StartSeed
	}
	if cfg.ProfileCount == 0 {
		cfg.ProfileCount = defaults.ProfileCount
	}
	if cfg.TraceCount == 0 {
		cfg.TraceCount = defaults.TraceCount
	}
	if cfg.Thresholds == (AuditThresholds{}) {
		cfg.Thresholds = defaults.Thresholds
	}
	return cfg
}
