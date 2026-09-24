// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

type externalReceipt struct {
	Schema          string   `json:"schema"`
	Kind            string   `json:"kind"`
	SubjectCommit   string   `json:"subjectCommit"`
	SubjectTree     string   `json:"subjectTree"`
	PolicyDigest    string   `json:"policyDigest"`
	StartedAt       string   `json:"startedAt"`
	FinishedAt      string   `json:"finishedAt"`
	Result          string   `json:"result"`
	ArtifactDigests []string `json:"artifactDigests"`
	Limitations     []string `json:"limitations"`
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
	Deployment            struct {
		BootstrapIdentityRef    string `json:"bootstrapIdentityRef"`
		TerraformStateBucketRef string `json:"terraformStateBucketRef"`
		PrivatePlanBucketRef    string `json:"privatePlanBucketRef"`
	} `json:"deployment"`
	WIF                wifInputs `json:"wif"`
	SecretResourceRefs []string  `json:"secretResourceRefs"`
	AlertChannelRefs   []string  `json:"alertChannelRefs"`
	Budget             struct {
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
	Environments  []string `json:"environments"`
}

func validateExternalReceipt(id string, receipt externalReceipt, commit, tree, policyDigest string, now time.Time) error {
	wantKind := strings.ToUpper(strings.ReplaceAll(id, "-", "_"))
	if receipt.Schema != "phase16-external-receipt-v1" || receipt.Kind != wantKind ||
		receipt.SubjectCommit != commit || receipt.SubjectTree != tree || receipt.PolicyDigest != policyDigest ||
		receipt.Result != "PASS" || len(receipt.ArtifactDigests) == 0 || len(receipt.ArtifactDigests) > 64 || len(receipt.Limitations) > 32 {
		return errors.New("receipt identity, subject, policy, or result mismatch")
	}
	started, err := time.Parse(time.RFC3339, receipt.StartedAt)
	if err != nil {
		return errors.New("invalid receipt start time")
	}
	finished, err := time.Parse(time.RFC3339, receipt.FinishedAt)
	if err != nil || finished.Before(started) || finished.Sub(started) > 24*time.Hour || finished.After(now.Add(5*time.Minute)) || now.Sub(finished) > 14*24*time.Hour {
		return errors.New("receipt time window is invalid or stale")
	}
	digests := append([]string(nil), receipt.ArtifactDigests...)
	sort.Strings(digests)
	for index, digest := range digests {
		if !validDigest(digest) || index > 0 && digest == digests[index-1] {
			return errors.New("receipt artifact digest inventory is invalid")
		}
	}
	limitations := append([]string(nil), receipt.Limitations...)
	sort.Strings(limitations)
	for index, limitation := range limitations {
		if len(limitation) < 3 || len(limitation) > 256 || index > 0 && limitation == limitations[index-1] {
			return errors.New("receipt limitations are invalid")
		}
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
	if value.WIF.Repository != "saroo98/kurdistan-protocol-compiler" || value.WIF.Ref != "refs/heads/main" ||
		!sameSet(value.WIF.Environments, []string{"phase16-production-plan", "phase16-production", "phase16-drill"}) ||
		!sameSet(value.WIF.WorkflowPaths, []string{".github/workflows/phase16-production-plan.yml", ".github/workflows/phase16-production-apply.yml", ".github/workflows/phase16-drill.yml"}) {
		return errors.New("WIF claims are not sufficiently restricted")
	}
	if duplicates([]string{value.Deployment.BootstrapIdentityRef, value.Deployment.TerraformStateBucketRef, value.Deployment.PrivatePlanBucketRef}) {
		return errors.New("deployment bootstrap references are absent or reused")
	}
	if value.Budget.QualificationMonthlyMinorUnits <= 0 || value.Budget.ProductionMonthlyMinorUnits <= 0 || value.Budget.AutomaticQualificationTeardownHours < 1 || value.Budget.AutomaticQualificationTeardownHours > 72 {
		return errors.New("budget is absent or unbounded")
	}
	return nil
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	want := make(map[string]bool, len(b))
	for _, value := range b {
		want[value] = true
	}
	for _, value := range a {
		if !want[value] {
			return false
		}
		delete(want, value)
	}
	return len(want) == 0
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

func TestValidateOwnerRejectsProjectReuseAndApprovalCollision(t *testing.T) {
	var value ownerInputs
	root := repositoryRoot(t)
	if err := decodeFile(root, "testdata/fixtures/phase16/owner-inputs.example.json", &value); err != nil {
		t.Fatal(err)
	}
	value.ProductionProjects.Trust = value.QualificationProjects.Trust
	if err := validateOwner(value); err == nil {
		t.Fatal("project reuse accepted")
	}
	if err := decodeFile(root, "testdata/fixtures/phase16/owner-inputs.example.json", &value); err != nil {
		t.Fatal(err)
	}
	value.ApprovalClasses[0].ExecutorActorRef = value.ApprovalClasses[0].ApproverActorRefs[0]
	if err := validateOwner(value); err == nil {
		t.Fatal("approver/executor collision accepted")
	}
}

func TestValidateOwnerRequiresExactProtectedWorkflowAndEnvironmentSet(t *testing.T) {
	var value ownerInputs
	root := repositoryRoot(t)
	if err := decodeFile(root, "testdata/fixtures/phase16/owner-inputs.example.json", &value); err != nil {
		t.Fatal(err)
	}
	value.WIF.Environments[0] = "phase16-production"
	if err := validateOwner(value); err == nil {
		t.Fatal("duplicate protected environment accepted")
	}
	if err := decodeFile(root, "testdata/fixtures/phase16/owner-inputs.example.json", &value); err != nil {
		t.Fatal(err)
	}
	value.WIF.WorkflowPaths[0] = ".github/workflows/ordinary.yml"
	if err := validateOwner(value); err == nil {
		t.Fatal("unapproved production workflow accepted")
	}
}

func TestValidateExternalReceiptBindsExactSubjectPolicyAndFreshness(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	receipt := externalReceipt{
		Schema: "phase16-external-receipt-v1", Kind: "CLOUD_IDENTITY_READBACK",
		SubjectCommit: strings.Repeat("a", 40), SubjectTree: strings.Repeat("b", 40), PolicyDigest: strings.Repeat("c", 64),
		StartedAt: now.Add(-time.Hour).Format(time.RFC3339), FinishedAt: now.Add(-time.Minute).Format(time.RFC3339), Result: "PASS",
		ArtifactDigests: []string{strings.Repeat("d", 64)},
	}
	if err := validateExternalReceipt("cloud-identity-readback", receipt, receipt.SubjectCommit, receipt.SubjectTree, receipt.PolicyDigest, now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*externalReceipt){
		"wrong subject": func(value *externalReceipt) { value.SubjectTree = strings.Repeat("e", 40) },
		"wrong policy":  func(value *externalReceipt) { value.PolicyDigest = strings.Repeat("e", 64) },
		"failed":        func(value *externalReceipt) { value.Result = "FAIL" },
		"stale":         func(value *externalReceipt) { value.FinishedAt = now.Add(-15 * 24 * time.Hour).Format(time.RFC3339) },
		"duplicate": func(value *externalReceipt) {
			value.ArtifactDigests = append(value.ArtifactDigests, value.ArtifactDigests[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := receipt
			candidate.ArtifactDigests = append([]string(nil), receipt.ArtifactDigests...)
			mutate(&candidate)
			if err := validateExternalReceipt("cloud-identity-readback", candidate, receipt.SubjectCommit, receipt.SubjectTree, receipt.PolicyDigest, now); err == nil {
				t.Fatal("invalid external receipt accepted")
			}
		})
	}
}
