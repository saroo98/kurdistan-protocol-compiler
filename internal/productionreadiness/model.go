// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package productionreadiness

const (
	Version                     = "productionreadiness-v1"
	RecommendedNextMilestone    = "M36: concrete local socket adapter"
	DefaultReviewID             = "production_integration_readiness_review_v1"
	StatusReadyForReview        = "ready-for-review"
	StatusNeedsDesign           = "needs-design"
	StatusBlocked               = "blocked"
	BoundaryStrictLocalOnly     = "strict_local_only"
	BoundaryNoRealNetworkIO     = "no_real_network_io"
	BoundaryNoDeployment        = "no_deployment"
	BoundaryNoPayloadLogging    = "no_payload_logging"
	BoundaryNoProductionKeyXchg = "no_production_key_exchange"
)

type ReadinessItem struct {
	Name          string   `json:"name"`
	Layer         string   `json:"layer"`
	Status        string   `json:"status"`
	Evidence      []string `json:"evidence"`
	RemainingRisk string   `json:"remaining_risk"`
	NextAction    string   `json:"next_action"`
}

type DependencyEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"`
}

type BoundaryReview struct {
	Name          string   `json:"name"`
	Policy        string   `json:"policy"`
	Allowed       bool     `json:"allowed"`
	Forbidden     []string `json:"forbidden,omitempty"`
	Evidence      []string `json:"evidence"`
	Conclusion    string   `json:"conclusion"`
	PayloadLogged bool     `json:"payload_logged"`
	SecretLogged  bool     `json:"secret_logged"`
}

type FutureContract struct {
	Milestone       string   `json:"milestone"`
	Name            string   `json:"name"`
	AllowedScope    string   `json:"allowed_scope"`
	RequiredGates   []string `json:"required_gates"`
	ForbiddenScopes []string `json:"forbidden_scopes"`
	Status          string   `json:"status"`
}

type Blocker struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Summary  string `json:"summary"`
	Required bool   `json:"required"`
	Resolved bool   `json:"resolved"`
}

type ReadinessMisuseReport struct {
	ObjectsChecked    int      `json:"objects_checked"`
	SuspiciousMetrics []string `json:"suspicious_metrics,omitempty"`
	PayloadLogged     bool     `json:"payload_logged"`
	SecretLogged      bool     `json:"secret_logged"`
	Conclusion        string   `json:"conclusion"`
}

type ReadinessParityReport struct {
	ItemsCompared         int      `json:"items_compared"`
	ContractsCompared     int      `json:"contracts_compared"`
	SemanticMatches       int      `json:"semantic_matches"`
	UnexpectedDifferences []string `json:"unexpected_differences,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

type ProductionReadinessReview struct {
	Version       string                `json:"version"`
	ReviewID      string                `json:"review_id"`
	Items         []ReadinessItem       `json:"items"`
	Dependencies  []DependencyEdge      `json:"dependencies"`
	Boundaries    []BoundaryReview      `json:"boundaries"`
	Contracts     []FutureContract      `json:"contracts"`
	Blockers      []Blocker             `json:"blockers"`
	Misuse        ReadinessMisuseReport `json:"misuse"`
	Parity        ReadinessParityReport `json:"parity"`
	ReviewHash    string                `json:"review_hash"`
	PayloadLogged bool                  `json:"payload_logged"`
	SecretLogged  bool                  `json:"secret_logged"`
	Conclusion    string                `json:"conclusion"`
}

type ReadinessComparisonReport struct {
	Version         string   `json:"version"`
	OldHash         string   `json:"old_hash"`
	NewHash         string   `json:"new_hash"`
	UnexpectedDrift []string `json:"unexpected_drift,omitempty"`
	PayloadLogged   bool     `json:"payload_logged"`
	SecretLogged    bool     `json:"secret_logged"`
	Conclusion      string   `json:"conclusion"`
}
