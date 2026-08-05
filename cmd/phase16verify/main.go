// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase16verify validates the local Phase 16 production-trust
// authority and, when explicitly requested, the private owner input contract.
// It never calls a cloud API and never treats local evidence as production
// evidence.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	statusPath        = "testdata/evidence/phase16/production-trust-status.json"
	ownerInputDefault = ".tools/phase16/private/owner-inputs.json"
)

var requiredFiles = []string{
	"config/production/actions.json",
	"config/production/key-policy.json",
	"config/production/regions.json",
	"config/production/retention.json",
	"config/production/roles.json",
	"config/production/services.json",
	"config/production/tools.json",
	"docs/KIP-0092-phase16-production-trust.md",
	"docs/PHASE16_PRODUCTION_TRUST_COMPLETION_PLAN.md",
	"docs/PHASE16_THREAT_MODEL.md",
	"testdata/fixtures/phase16/owner-inputs.example.json",
	"testdata/schemas/phase16-external-receipt-v1.schema.json",
	"testdata/schemas/phase16-operation-v1.schema.json",
	"testdata/schemas/phase16-owner-inputs-v1.schema.json",
	"testdata/schemas/phase16-production-trust-status-v1.schema.json",
	statusPath,
}

var expectedRoles = []string{"approver", "auditor", "deployer", "emergency", "executor", "publisher", "recovery", "requester", "viewer"}

var privilegedActions = map[string]bool{
	"emergency.deny":       true,
	"key.destroy.schedule": true,
	"key.issuer.rotate":    true,
	"key.root.rotate":      true,
	"profile.issue":        true,
	"profile.revoke":       true,
	"profile.rotate":       true,
	"publication.publish":  true,
	"recovery.prepare":     true,
	"retention.lock":       true,
}

type status struct {
	Schema         string `json:"schema"`
	Phase          int    `json:"phase"`
	BaselineCommit string `json:"baselineCommit"`
	State          string `json:"state"`
	PolicyDigests  struct {
		Actions   string `json:"actions"`
		KeyPolicy string `json:"keyPolicy"`
		Regions   string `json:"regions"`
		Retention string `json:"retention"`
		Roles     string `json:"roles"`
		Services  string `json:"services"`
		Tools     string `json:"tools"`
	} `json:"policyDigests"`
	LocalAuthority   []string           `json:"localAuthority"`
	ExternalEvidence []externalEvidence `json:"externalEvidence"`
	ReleaseDecision  string             `json:"releaseDecision"`
	Limitations      []string           `json:"limitations"`
	Findings         struct {
		Critical int `json:"critical"`
		High     int `json:"high"`
	} `json:"findings"`
}

type externalEvidence struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	EvidenceDigest string `json:"evidenceDigest"`
}

type rolePolicy struct {
	Schema                    string     `json:"schema"`
	Roles                     []string   `json:"roles"`
	ForbiddenRoleCombinations [][]string `json:"forbiddenRoleCombinations"`
	IdentityRules             struct {
		OpaqueActorsOnly                          bool `json:"opaqueActorsOnly"`
		RawEmailForbidden                         bool `json:"rawEmailForbidden"`
		RequesterSelfApprovalForbidden            bool `json:"requesterSelfApprovalForbidden"`
		ExecutorApprovalForbidden                 bool `json:"executorApprovalForbidden"`
		MinimumDistinctApprovers                  int  `json:"minimumDistinctApprovers"`
		PrivilegedAuthenticationMaximumAgeSeconds int  `json:"privilegedAuthenticationMaximumAgeSeconds"`
		BreakGlassMaximumSeconds                  int  `json:"breakGlassMaximumSeconds"`
	} `json:"identityRules"`
}

type actionPolicy struct {
	Schema               string       `json:"schema"`
	Actions              []actionRule `json:"actions"`
	MutationRequirements struct {
		IdempotencyKey   bool   `json:"idempotencyKey"`
		ExpectedRevision bool   `json:"expectedRevision"`
		ExpectedEpoch    bool   `json:"expectedEpoch"`
		BoundedBodyBytes int    `json:"boundedBodyBytes"`
		ContentType      string `json:"contentType"`
		APIVersion       string `json:"apiVersion"`
	} `json:"mutationRequirements"`
}

type actionRule struct {
	ID                  string   `json:"id"`
	RequestRoles        []string `json:"requestRoles"`
	ApprovalRoles       []string `json:"approvalRoles"`
	ExecuteRole         string   `json:"executeRole"`
	Approvals           int      `json:"approvals"`
	RequiresAnchor      bool     `json:"requiresAnchor"`
	RequiresPublication bool     `json:"requiresPublication"`
}

type ownerInputs struct {
	Schema                string          `json:"schema"`
	OrganizationRef       string          `json:"organizationRef"`
	BillingAccountRef     string          `json:"billingAccountRef"`
	QualificationProjects projects        `json:"qualificationProjects"`
	ProductionProjects    projects        `json:"productionProjects"`
	Region                string          `json:"region"`
	SpannerConfiguration  string          `json:"spannerConfiguration"`
	DomainZoneRef         string          `json:"domainZoneRef"`
	IdentityTenantRef     string          `json:"identityTenantRef"`
	ApprovalClasses       []approvalClass `json:"approvalClasses"`
	WIF                   wifInputs       `json:"wif"`
	SecretResourceRefs    []string        `json:"secretResourceRefs"`
	AlertChannelRefs      []string        `json:"alertChannelRefs"`
	Budget                struct {
		QualificationMonthlyMinorUnits      int64  `json:"qualificationMonthlyMinorUnits"`
		ProductionMonthlyMinorUnits         int64  `json:"productionMonthlyMinorUnits"`
		Currency                            string `json:"currency"`
		AutomaticQualificationTeardownHours int    `json:"automaticQualificationTeardownHours"`
	} `json:"budget"`
	Retention struct {
		AuditDays        int    `json:"auditDays"`
		PublicationDays  int    `json:"publicationDays"`
		BackupDays       int    `json:"backupDays"`
		LegalOwnerRef    string `json:"legalOwnerRef"`
		IncidentOwnerRef string `json:"incidentOwnerRef"`
	} `json:"retention"`
	Backup struct {
		TargetProjectRef  string   `json:"targetProjectRef"`
		RecoveryOwnerRefs []string `json:"recoveryOwnerRefs"`
	} `json:"backup"`
	Authorizations struct {
		ProductionMutation string `json:"productionMutation"`
		RetentionLock      string `json:"retentionLock"`
		KeyDestruction     string `json:"keyDestruction"`
		ProductionDNS      string `json:"productionDNS"`
	} `json:"authorizations"`
}

type projects struct {
	Trust       string `json:"trust"`
	Control     string `json:"control"`
	Publication string `json:"publication"`
	Audit       string `json:"audit"`
	Ops         string `json:"ops"`
}
type approvalClass struct {
	Class             string   `json:"class"`
	ApproverActorRefs []string `json:"approverActorRefs"`
	ExecutorActorRef  string   `json:"executorActorRef"`
}
type wifInputs struct {
	PoolRef       string   `json:"poolRef"`
	ProviderRef   string   `json:"providerRef"`
	Repository    string   `json:"repository"`
	Ref           string   `json:"ref"`
	WorkflowPaths []string `json:"workflowPaths"`
	Environment   string   `json:"environment"`
}

func main() {
	root := flag.String("root", ".", "repository root")
	mode := flag.String("mode", "offline", "offline or external")
	ownerPath := flag.String("owner-inputs", ownerInputDefault, "private owner input file")
	flag.Parse()
	if err := verify(*root, *mode, *ownerPath); err != nil {
		fmt.Fprintln(os.Stderr, "PHASE 16 VERIFICATION FAILED:", err)
		os.Exit(1)
	}
	fmt.Printf("PHASE 16 %s VERIFICATION PASSED\n", strings.ToUpper(*mode))
}

func verify(root, mode, ownerPath string) error {
	if mode != "offline" && mode != "external" {
		return fmt.Errorf("unsupported mode %q", mode)
	}
	for _, rel := range requiredFiles {
		if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil || info.IsDir() {
			return fmt.Errorf("required file unavailable: %s", rel)
		}
	}
	var value status
	if err := decodeFile(root, statusPath, &value); err != nil {
		return err
	}
	if err := validateStatus(root, value); err != nil {
		return err
	}
	var roles rolePolicy
	if err := decodeFile(root, "config/production/roles.json", &roles); err != nil {
		return err
	}
	if err := validateRoles(roles); err != nil {
		return err
	}
	var actions actionPolicy
	if err := decodeFile(root, "config/production/actions.json", &actions); err != nil {
		return err
	}
	if err := validateActions(actions); err != nil {
		return err
	}
	if err := verifyDocuments(root); err != nil {
		return err
	}
	if err := verifySchemas(root); err != nil {
		return err
	}
	if mode == "external" {
		var owner ownerInputs
		if err := decodeFile(root, ownerPath, &owner); err != nil {
			return fmt.Errorf("private owner inputs: %w", err)
		}
		if err := validateOwner(owner); err != nil {
			return err
		}
	}
	return nil
}

func validateStatus(root string, value status) error {
	if value.Schema != "phase16-production-trust-status-v1" || value.Phase != 16 {
		return errors.New("invalid status identity")
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(value.BaselineCommit) {
		return errors.New("invalid baseline commit")
	}
	cmd := exec.Command("git", "cat-file", "-e", value.BaselineCommit+"^{commit}")
	cmd.Dir = root
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("baseline commit unavailable: %s", strings.TrimSpace(string(output)))
	}
	if value.ReleaseDecision != "NO_GO" {
		return errors.New("Phase 16 cannot widen the full VPN release decision")
	}
	if value.State == "COMPLETE" {
		return errors.New("local status cannot mark Phase 16 complete without external verification")
	}
	if value.Findings.Critical < 0 || value.Findings.High < 0 || len(value.Limitations) < 1 {
		return errors.New("invalid findings or limitations")
	}
	want := map[string]string{
		"config/production/actions.json":    value.PolicyDigests.Actions,
		"config/production/key-policy.json": value.PolicyDigests.KeyPolicy,
		"config/production/regions.json":    value.PolicyDigests.Regions,
		"config/production/retention.json":  value.PolicyDigests.Retention,
		"config/production/roles.json":      value.PolicyDigests.Roles,
		"config/production/services.json":   value.PolicyDigests.Services,
		"config/production/tools.json":      value.PolicyDigests.Tools,
	}
	for path, digest := range want {
		observed, err := fileDigest(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		if observed != digest {
			return fmt.Errorf("policy digest drift: %s", path)
		}
	}
	seen := map[string]bool{}
	for _, item := range value.ExternalEvidence {
		if item.ID == "" || seen[item.ID] {
			return errors.New("invalid or duplicate external evidence id")
		}
		seen[item.ID] = true
		if item.Status == "UNVERIFIED" {
			if item.EvidenceDigest != "UNVERIFIED" {
				return fmt.Errorf("unverified evidence has digest: %s", item.ID)
			}
		} else if item.Status != "PASS" && item.Status != "FAIL" {
			return fmt.Errorf("invalid external evidence state: %s", item.ID)
		} else if !validDigest(item.EvidenceDigest) {
			return fmt.Errorf("invalid evidence digest: %s", item.ID)
		}
	}
	return nil
}

func validateRoles(value rolePolicy) error {
	if value.Schema != "phase16-role-policy-v1" || !equalStrings(value.Roles, expectedRoles) {
		return errors.New("role inventory drift")
	}
	r := value.IdentityRules
	if !r.OpaqueActorsOnly || !r.RawEmailForbidden || !r.RequesterSelfApprovalForbidden || !r.ExecutorApprovalForbidden || r.MinimumDistinctApprovers != 2 || r.PrivilegedAuthenticationMaximumAgeSeconds > 900 || r.BreakGlassMaximumSeconds > 1800 {
		return errors.New("identity rules are weaker than Phase 16 authority")
	}
	for _, pair := range value.ForbiddenRoleCombinations {
		if len(pair) != 2 || pair[0] >= pair[1] {
			return errors.New("invalid forbidden role combination")
		}
	}
	return nil
}

func validateActions(value actionPolicy) error {
	if value.Schema != "phase16-action-policy-v1" || len(value.Actions) < len(privilegedActions) {
		return errors.New("action policy identity or inventory invalid")
	}
	last := ""
	for _, action := range value.Actions {
		if action.ID <= last || action.ID == "" || action.ExecuteRole == "" {
			return errors.New("actions must be uniquely sorted and bounded")
		}
		last = action.ID
		if privilegedActions[action.ID] && (action.Approvals != 2 || !action.RequiresAnchor) {
			return fmt.Errorf("privileged action weakens dual control or anchoring: %s", action.ID)
		}
		deleteCopy := false
		for _, role := range action.ApprovalRoles {
			if role == action.ExecuteRole {
				deleteCopy = true
			}
		}
		if deleteCopy {
			return fmt.Errorf("executor may approve action %s", action.ID)
		}
	}
	r := value.MutationRequirements
	if !r.IdempotencyKey || !r.ExpectedRevision || !r.ExpectedEpoch || r.BoundedBodyBytes < 1024 || r.BoundedBodyBytes > 65536 || r.ContentType != "application/json" || r.APIVersion != "v1" {
		return errors.New("mutation requirements are incomplete")
	}
	return nil
}

func validateOwner(value ownerInputs) error {
	if value.Schema != "phase16-owner-inputs-v1" || value.Region != "europe-west2" || value.SpannerConfiguration != "eur6" {
		return errors.New("owner input identity or residency invalid")
	}
	refs := append(projectValues(value.QualificationProjects), projectValues(value.ProductionProjects)...)
	if duplicates(refs) {
		return errors.New("qualification and production projects must be distinct")
	}
	classes := map[string]bool{}
	for _, item := range value.ApprovalClasses {
		if classes[item.Class] || len(item.ApproverActorRefs) != 2 || item.ApproverActorRefs[0] == item.ApproverActorRefs[1] || item.ExecutorActorRef == item.ApproverActorRefs[0] || item.ExecutorActorRef == item.ApproverActorRefs[1] {
			return fmt.Errorf("invalid separation of duties for %s", item.Class)
		}
		classes[item.Class] = true
	}
	for _, required := range []string{"root", "issuer", "publication", "revocation", "recovery", "emergency", "retention-lock", "key-destruction"} {
		if !classes[required] {
			return fmt.Errorf("missing approval class %s", required)
		}
	}
	if value.WIF.Repository != "saroo98/kurdistan-protocol-compiler" || value.WIF.Ref != "refs/heads/main" || value.WIF.Environment != "phase16-production" {
		return errors.New("WIF claims are not sufficiently restricted")
	}
	if value.Budget.QualificationMonthlyMinorUnits <= 0 || value.Budget.ProductionMonthlyMinorUnits <= 0 || value.Budget.AutomaticQualificationTeardownHours < 1 || value.Budget.AutomaticQualificationTeardownHours > 72 {
		return errors.New("budget is absent or unbounded")
	}
	return nil
}

func verifyDocuments(root string) error {
	required := map[string][]string{
		"docs/KIP-0092-phase16-production-trust.md":        {"Spanner", "Cloud KMS HSM", "NO_GO", "two distinct approvers"},
		"docs/PHASE16_THREAT_MODEL.md":                     {"Fail-closed", "Spanner commit time", "split brain", "Explicit non-claims"},
		"docs/PHASE16_PRODUCTION_TRUST_COMPLETION_PLAN.md": {"Anything less is progress, not Phase 16 completion.", "Do not invent credentials", "Phase 17"},
	}
	for path, needles := range required {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		text := string(raw)
		for _, needle := range needles {
			if !strings.Contains(text, needle) {
				return fmt.Errorf("%s missing authority text %q", path, needle)
			}
		}
	}
	return nil
}

func verifySchemas(root string) error {
	for _, path := range requiredFiles {
		if !strings.Contains(path, "testdata/schemas/phase16-") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		if err := rejectDuplicateKeys(raw); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		if value["$schema"] != "https://json-schema.org/draft/2020-12/schema" || value["additionalProperties"] != false {
			return fmt.Errorf("schema is not strict: %s", path)
		}
	}
	return nil
}

func decodeFile(root, path string, target any) error {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return err
	}
	if err := rejectSecretMaterial(raw); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode %s: trailing JSON", path)
	}
	return nil
}

func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return fmt.Errorf("duplicate or invalid object key %q", key)
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		default:
			return fmt.Errorf("unexpected delimiter %q", delim)
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func rejectSecretMaterial(raw []byte) error {
	lower := strings.ToLower(string(raw))
	for _, marker := range []string{"-----begin private key", "-----begin encrypted private key", "service_account", "private_key_id", "\"password\"", "\"access_token\"", "\"refresh_token\"", "ghp_", "github_pat_", "aiza"} {
		if strings.Contains(lower, marker) {
			return errors.New("secret-like material is forbidden")
		}
	}
	return nil
}
func fileDigest(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func validDigest(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func projectValues(p projects) []string {
	return []string{p.Trust, p.Control, p.Publication, p.Audit, p.Ops}
}
func duplicates(values []string) bool {
	seen := map[string]bool{}
	for _, v := range values {
		if v == "" || seen[v] {
			return true
		}
		seen[v] = true
	}
	return false
}
