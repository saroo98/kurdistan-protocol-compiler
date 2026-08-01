// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command koperator exercises the bounded Phase 12 operator control plane.
// It has no network or deployment capability.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"kurdistan/internal/contracts/carrier/carrierreview"
	"kurdistan/internal/operator/controlplane"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/relaydescriptor"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/product/strategy"
)

type demoResult struct {
	Schema           string                     `json:"schema"`
	Scope            string                     `json:"scope"`
	Health           controlplane.HealthSummary `json:"health"`
	ExternalEvidence map[string]string          `json:"external_evidence"`
	Claims           map[string]bool            `json:"claims"`
}

type phase12AcceptanceStatusV1 struct {
	Schema          string            `json:"schema"`
	Scope           string            `json:"scope"`
	Local           map[string]string `json:"local"`
	SecurityReviews map[string]struct {
		FindingCount int               `json:"finding_count"`
		Scope        string            `json:"scope"`
		Status       string            `json:"status"`
		Findings     map[string]string `json:"findings"`
	} `json:"security_reviews"`
	External map[string]string `json:"external"`
	Claims   map[string]bool   `json:"claims"`
}

var phase12LocalEvidenceNamesV1 = []string{
	"local_actor_duty_separation",
	"two_distinct_local_approval_ids",
	"phase8_profile_boundary",
	"phase11_relay_plan_boundary",
	"profile_desired_state_lifecycle",
	"relay_desired_state_lifecycle",
	"deny_only_emergency",
	"single_process_atomic_state_audit_outbox",
	"journal_partial_tail_and_reopen_recovery",
	"audit_hash_chain_validation",
	"forbidden_text_canaries",
	"publication_checks_against_supplied_trust_state",
	"pre_effect_recover_authorization",
	"root_bound_emergency_delegation",
	"authoritative_time_binding",
	"exact_profile_lifecycle_provenance",
	"redacted_effect_dto",
	"safety_priority_per_target_order_bounded_terminal_attempts",
	"expired_effect_rejection_before_dispatch",
	"publication_chronology_validation",
	"journal_copy_revision_continuity",
	"bounded_disposable_workflow",
}

var phase12ExternalEvidenceNamesV1 = []string{
	"production_oidc_webauthn",
	"production_trusted_time_source",
	"hsm_kms_custody",
	"postgresql_ha_pitr",
	"immutable_update_distribution",
	"infrastructure_provisioning",
	"owned_non_loopback_relay",
	"capacity_and_slo",
	"incident_and_disaster_recovery",
	"controlled_private_pilot",
	"multiwriter_database_transactions",
	"immutable_audit_and_rollback_anchor",
	"audit_export_pseudonymization",
	"authenticated_backup_restore",
	"external_provider_idempotency",
}

var phase12ClaimNamesV1 = []string{
	"production_ready",
	"publicly_deployed",
	"uncensorable",
	"undetectable",
	"anonymous",
	"fully_audited",
}

var phase12SecondReviewFindingNamesV1 = []string{
	"pre_effect_recover_authorization",
	"root_bound_emergency_delegation",
	"authoritative_time_binding",
	"exact_profile_lifecycle_provenance",
	"redacted_effect_dto",
	"safety_priority_per_target_order_bounded_terminal_attempts",
	"expired_effect_rejection_before_dispatch",
	"publication_chronology_validation",
	"journal_copy_revision_continuity",
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "verify" {
		if err := runVerify(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("PHASE 12 LOCAL CONTROL-PLANE VERIFICATION PASSED")
		return
	}
	if len(os.Args) < 2 || os.Args[1] != "demo" {
		fmt.Fprintln(os.Stderr, "usage: koperator verify | koperator demo -journal <path> -out <path> [-now <unix-seconds>]")
		os.Exit(2)
	}
	flags := flag.NewFlagSet("demo", flag.ExitOnError)
	journal := flags.String("journal", "", "new local journal path")
	out := flags.String("out", "", "new redacted evidence path")
	now := flags.Int64("now", 1_900_000_000, "deterministic local clock")
	if err := flags.Parse(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := runDemo(*journal, *out, *now); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runVerify() error {
	root, err := os.MkdirTemp("", "kurdistan-phase12-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	journal := root + string(os.PathSeparator) + "control-plane.journal"
	output := root + string(os.PathSeparator) + "evidence.json"
	if err := runDemo(journal, output, 1_900_000_000); err != nil {
		return err
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		return err
	}
	var result demoResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return err
	}
	if result.Schema != "kurdistan-phase12-disposable-evidence-v1" ||
		result.Scope != "local-disposable-control-plane" ||
		result.Health.PendingEffects != 0 ||
		result.Health.ExecutedOperations != 9 ||
		result.Health.ContainsUserData ||
		result.Health.ContainsPayloadData {
		return fmt.Errorf("%w: disposable evidence mismatch", controlplane.ErrInvalidInput)
	}
	for name, value := range result.ExternalEvidence {
		if value != "[UNVERIFIED]" {
			return fmt.Errorf("%w: external evidence %s overstated", controlplane.ErrInvalidInput, name)
		}
	}
	for name, claimed := range result.Claims {
		if claimed {
			return fmt.Errorf("%w: unsupported claim %s enabled", controlplane.ErrInvalidInput, name)
		}
	}
	if err := validateCommittedPhase12EvidenceV1(); err != nil {
		return err
	}
	reopened, err := controlplane.OpenJournalStore(journal)
	if err != nil {
		return err
	}
	return reopened.Snapshot().Validate()
}

func validateCommittedPhase12EvidenceV1() error {
	root, err := phase12RepositoryRootV1()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(root, "testdata", "evidence", "phase12", "acceptance-status.json"))
	if err != nil {
		return fmt.Errorf("%w: read Phase 12 acceptance evidence: %v", controlplane.ErrInvalidInput, err)
	}
	status, err := decodePhase12AcceptanceStatusV1(raw)
	if err != nil {
		return fmt.Errorf("%w: parse Phase 12 acceptance evidence: %v", controlplane.ErrInvalidInput, err)
	}
	return validatePhase12AcceptanceStatusV1(status)
}

func decodePhase12AcceptanceStatusV1(raw []byte) (phase12AcceptanceStatusV1, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var status phase12AcceptanceStatusV1
	if err := decoder.Decode(&status); err != nil {
		return phase12AcceptanceStatusV1{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return phase12AcceptanceStatusV1{}, fmt.Errorf("trailing JSON value")
		}
		return phase12AcceptanceStatusV1{}, err
	}
	return status, nil
}

func phase12RepositoryRootV1() (string, error) {
	root, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			return root, nil
		}
		parent := filepath.Dir(root)
		if parent == root {
			return "", fmt.Errorf("%w: repository root not found", controlplane.ErrInvalidInput)
		}
		root = parent
	}
}

func validatePhase12AcceptanceStatusV1(status phase12AcceptanceStatusV1) error {
	const (
		schema      = "kurdistan.phase12.acceptance-status.v1"
		scope       = "local-disposable-control-plane"
		localValue  = "verified-by-local-test"
		reviewName  = "second_adversarial_review"
		reviewState = "remediated-by-local-test"
	)
	if status.Schema != schema || status.Scope != scope {
		return fmt.Errorf("%w: unexpected Phase 12 acceptance evidence identity", controlplane.ErrInvalidInput)
	}
	if err := validateExactPhase12StringMapV1("local", status.Local, phase12LocalEvidenceNamesV1, localValue); err != nil {
		return err
	}
	if err := validateExactPhase12StringMapV1("external", status.External, phase12ExternalEvidenceNamesV1, "[UNVERIFIED]"); err != nil {
		return err
	}
	if err := validateExactPhase12BoolMapV1("claims", status.Claims, phase12ClaimNamesV1, false); err != nil {
		return err
	}
	if len(status.SecurityReviews) != 1 {
		return fmt.Errorf("%w: security review vocabulary mismatch", controlplane.ErrInvalidInput)
	}
	review, ok := status.SecurityReviews[reviewName]
	if !ok || review.FindingCount != len(phase12SecondReviewFindingNamesV1) ||
		review.Scope != scope || review.Status != reviewState {
		return fmt.Errorf("%w: second adversarial review identity mismatch", controlplane.ErrInvalidInput)
	}
	if err := validateExactPhase12StringMapV1(
		"second adversarial review findings",
		review.Findings,
		phase12SecondReviewFindingNamesV1,
		localValue,
	); err != nil {
		return err
	}
	return nil
}

func validateExactPhase12StringMapV1(name string, actual map[string]string, expected []string, value string) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("%w: %s vocabulary cardinality mismatch", controlplane.ErrInvalidInput, name)
	}
	for _, key := range expected {
		if actual[key] != value {
			return fmt.Errorf("%w: %s vocabulary/value mismatch for %s", controlplane.ErrInvalidInput, name, key)
		}
	}
	return nil
}

func validateExactPhase12BoolMapV1(name string, actual map[string]bool, expected []string, value bool) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("%w: %s vocabulary cardinality mismatch", controlplane.ErrInvalidInput, name)
	}
	for _, key := range expected {
		got, ok := actual[key]
		if !ok || got != value {
			return fmt.Errorf("%w: %s vocabulary/value mismatch for %s", controlplane.ErrInvalidInput, name, key)
		}
	}
	return nil
}

func runDemo(journalPath, outputPath string, now int64) error {
	if journalPath == "" || outputPath == "" || now <= 0 {
		return controlplane.ErrInvalidInput
	}
	if _, err := os.Lstat(outputPath); err == nil {
		return fmt.Errorf("%w: output already exists", controlplane.ErrConflict)
	} else if !os.IsNotExist(err) {
		return err
	}
	store, err := controlplane.CreateJournalStore(journalPath)
	if err != nil {
		return err
	}
	service, err := controlplane.NewService(store)
	if err != nil {
		return err
	}
	credentials, err := newDemoCredentials()
	if err != nil {
		return err
	}
	actors := demoActors{
		requester: controlplane.Actor{ID: "operator-requester", AuthorityRole: profile.RoleOperator, Duties: []controlplane.Duty{controlplane.DutyRequest}},
		approverA: controlplane.Actor{ID: "operator-approver-a", AuthorityRole: profile.RoleOperator, Duties: []controlplane.Duty{controlplane.DutyApprove}},
		approverB: controlplane.Actor{ID: "operator-approver-b", AuthorityRole: profile.RoleOperator, Duties: []controlplane.Duty{controlplane.DutyApprove}},
		issuer:    controlplane.Actor{ID: "executor-issuer", AuthorityRole: profile.RoleIssuer, Duties: []controlplane.Duty{controlplane.DutyExecute}},
		root:      controlplane.Actor{ID: "executor-root", AuthorityRole: profile.RoleRoot, Duties: []controlplane.Duty{controlplane.DutyExecute}},
		publisher: controlplane.Actor{ID: "executor-publisher", AuthorityRole: profile.RoleOperator, Duties: []controlplane.Duty{controlplane.DutyExecute, controlplane.DutyPublish}},
		relay:     controlplane.Actor{ID: "executor-relay", AuthorityRole: profile.RoleRelay, Duties: []controlplane.Duty{controlplane.DutyExecute}},
		emergency: controlplane.Actor{ID: "executor-emergency", AuthorityRole: profile.RoleEmergency, Duties: []controlplane.Duty{controlplane.DutyExecute}},
		recoverer: controlplane.Actor{ID: "operator-recoverer", AuthorityRole: profile.RoleOperator, Duties: []controlplane.Duty{controlplane.DutyRecover}},
	}
	activationRequest, profileValue, err := buildDemoActivationRequest(credentials, now)
	if err != nil {
		return err
	}
	issueInput, inspection, err := controlplane.NewVerifiedProfileIssueRequest(
		"operation-issue-001", activationRequest,
		service.State().Revision, "idem-operation-issue-001",
	)
	if err != nil {
		return err
	}
	if err := executeDemoRequest(service, actors, issueInput); err != nil {
		return err
	}
	publication := &controlplane.PublicationInput{
		Version:        1,
		RootVersion:    1,
		SnapshotDigest: controlplane.DigestLabel("snapshot-one"),
		TargetsDigest:  controlplane.DigestLabel("targets-one"),
		ValidUntil:     now + 3600,
	}
	publicationInput := newDemoPublicationRequest(
		service.State().Revision, now+10, publication,
	)
	if err := executeDemoRequest(service, actors, publicationInput); err != nil {
		return err
	}
	relayRequest, err := buildDemoRelayRequest(profileValue, inspection.ContentSHA256, now+20)
	if err != nil {
		return err
	}
	relayEpoch := uint64(0)
	for index, action := range []controlplane.Action{
		controlplane.ActionEnrollRelay,
		controlplane.ActionPromoteRelay,
		controlplane.ActionPromoteRelay,
		controlplane.ActionDrainRelay,
		controlplane.ActionQuarantineRelay,
		controlplane.ActionRevokeRelay,
	} {
		id := fmt.Sprintf("operation-relay-%03d", index+1)
		input, err := controlplane.NewVerifiedRelayRequest(
			id, action, relayRequest, service.State().Revision, relayEpoch,
			"idem-"+id,
		)
		if err != nil {
			return err
		}
		if err := executeDemoRequest(service, actors, input); err != nil {
			return err
		}
		relayEpoch++
	}
	emergencyAt := now + 100
	trustedEmergency, signedEmergency, err := buildDemoEmergencyAction(
		credentials, activationRequest.Root, emergencyAt,
	)
	if err != nil {
		return err
	}
	if _, err := service.InstallEmergencyAuthority(
		actors.root, trustedEmergency, service.State().Revision, emergencyAt,
	); err != nil {
		return err
	}
	emergencyInput, err := service.NewVerifiedEmergencyRequest(
		"operation-emergency-001", trustedEmergency, signedEmergency, credentials,
		service.State().Revision, 0, "idem-operation-emergency-001", emergencyAt,
	)
	if err != nil {
		return err
	}
	if err := executeDemoRequest(service, actors, emergencyInput); err != nil {
		return err
	}
	handler := conformanceHandler{}
	for {
		applied, err := controlplane.ReconcileNext(context.Background(), service, actors.recoverer, handler, now+200)
		if err != nil {
			return err
		}
		if !applied {
			break
		}
	}
	health, err := controlplane.SummarizeHealth(service.State())
	if err != nil {
		return err
	}
	result := demoResult{
		Schema: "kurdistan-phase12-disposable-evidence-v1",
		Scope:  "local-disposable-control-plane",
		Health: health,
		ExternalEvidence: map[string]string{
			"production_identity":    "[UNVERIFIED]",
			"hsm_kms_custody":        "[UNVERIFIED]",
			"external_database":      "[UNVERIFIED]",
			"update_distribution":    "[UNVERIFIED]",
			"owned_relay_deployment": "[UNVERIFIED]",
			"private_pilot":          "[UNVERIFIED]",
		},
		Claims: map[string]bool{
			"production_ready":  false,
			"publicly_deployed": false,
			"uncensorable":      false,
			"undetectable":      false,
		},
	}
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

type demoActors struct {
	requester, approverA, approverB controlplane.Actor
	root, issuer, publisher, relay  controlplane.Actor
	emergency, recoverer            controlplane.Actor
}

func executeDemoRequest(service *controlplane.Service, actors demoActors, input controlplane.RequestInput) error {
	executor := actors.issuer
	switch input.Action {
	case controlplane.ActionPublishSnapshot:
		executor = actors.publisher
	case controlplane.ActionEnrollRelay, controlplane.ActionPromoteRelay,
		controlplane.ActionDrainRelay, controlplane.ActionRetireRelay,
		controlplane.ActionQuarantineRelay, controlplane.ActionRevokeRelay:
		executor = actors.relay
	case controlplane.ActionEmergencyDeny, controlplane.ActionEmergencyNarrow:
		executor = actors.emergency
	}
	if _, err := service.Request(actors.requester, input); err != nil {
		return err
	}
	if _, err := service.Approve(actors.approverA, input.ID, input.IdempotencyKey+"-approve-a", service.State().Revision, input.CreatedAt+1); err != nil {
		return err
	}
	if _, err := service.Approve(actors.approverB, input.ID, input.IdempotencyKey+"-approve-b", service.State().Revision, input.CreatedAt+2); err != nil {
		return err
	}
	_, err := service.Execute(executor, input.ID, input.IdempotencyKey+"-execute", service.State().Revision, input.CreatedAt+3)
	return err
}

func newDemoPublicationRequest(expectedRevision uint64, now int64, publication *controlplane.PublicationInput) controlplane.RequestInput {
	return controlplane.RequestInput{
		ID: "operation-publish-001", Action: controlplane.ActionPublishSnapshot,
		TargetID:         "publication-alpha-001",
		SubjectDigest:    controlplane.DigestLabel("operation-publish-001-subject"),
		ScopeDigest:      controlplane.DigestLabel("scope-alpha"),
		ExpectedRevision: expectedRevision,
		CreatedAt:        now,
		ExpiresAt:        now + 600,
		IdempotencyKey:   "idem-operation-publish-001",
		Publication:      publication,
	}
}

type demoCredentials struct {
	private map[string]*ecdsa.PrivateKey
	public  map[string]*ecdsa.PublicKey
}

func newDemoCredentials() (*demoCredentials, error) {
	credentials := &demoCredentials{
		private: make(map[string]*ecdsa.PrivateKey),
		public:  make(map[string]*ecdsa.PublicKey),
	}
	for _, id := range []string{
		"local-root-key-0001",
		"local-issuer-key-0001",
		"local-emergency-key-0001",
	} {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		credentials.private[id] = privateKey
		credentials.public[id] = &privateKey.PublicKey
	}
	return credentials, nil
}

func (credentials *demoCredentials) Sign(key profile.KeyReference, message []byte) ([]byte, error) {
	if key.SuiteID != uint16(envelope.SuiteClassicalV1) {
		return nil, controlplane.ErrInvalidInput
	}
	privateKey, ok := credentials.private[key.KeyID]
	if !ok {
		return nil, controlplane.ErrInvalidInput
	}
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		return nil, err
	}
	return envelope.EncodeRawES256Signature(r, s)
}

func (credentials *demoCredentials) Verify(key profile.KeyReference, message, signature []byte) error {
	if key.SuiteID != uint16(envelope.SuiteClassicalV1) {
		return controlplane.ErrInvalidInput
	}
	publicKey, ok := credentials.public[key.KeyID]
	r, s, err := envelope.DecodeRawES256Signature(signature)
	if !ok || err != nil {
		return controlplane.ErrInvalidInput
	}
	digest := sha256.Sum256(message)
	if !ecdsa.Verify(publicKey, digest[:], r, s) {
		return controlplane.ErrInvalidInput
	}
	return nil
}

func demoKeyReference(id string) profile.KeyReference {
	return profile.KeyReference{KeyID: id, SuiteID: uint16(envelope.SuiteClassicalV1)}
}

func demoAuthorityScope() profile.AuthorityScope {
	return profile.AuthorityScope{
		ProviderID:       "provider-alpha-001",
		LineageID:        "lineage-alpha-001",
		ProfileNamespace: "profiles.",
	}
}

func buildDemoActivationRequest(credentials *demoCredentials, now int64) (profile.ActivationRequest, envelope.CanonicalProfileV1, error) {
	rootKey := demoKeyReference("local-root-key-0001")
	issuerKey := demoKeyReference("local-issuer-key-0001")
	scope := demoAuthorityScope()
	root := profile.RootSetArtifact{
		Epoch: 1, ViewID: "local-root-view-0001",
		ValidFrom: now - 120, ValidUntil: now + 7200,
		Keys: []profile.KeyReference{rootKey},
	}
	delegation := profile.IssuerDelegationArtifact{
		RootEpoch: 1, RootKeyID: rootKey.KeyID, IssuerKey: issuerKey,
		Scope: scope, ValidFrom: now - 120, ValidUntil: now + 3600,
		DelegationEpoch: 1, MaxProfileValiditySecs: 1800,
	}
	delegationPayload, err := profile.EncodeIssuerDelegationV1(delegation)
	if err != nil {
		return profile.ActivationRequest{}, envelope.CanonicalProfileV1{}, err
	}
	delegationSignature, err := credentials.Sign(rootKey, delegationPayload)
	if err != nil {
		return profile.ActivationRequest{}, envelope.CanonicalProfileV1{}, err
	}
	profileValue := envelope.CanonicalProfileV1{
		ContentID: "content-alpha-001", ProfileID: "profiles.alpha",
		LineageID: scope.LineageID, ProviderID: scope.ProviderID,
		ContractVersion: "product-profile-admission-v1",
		RevocationScope: "revocation-alpha-001", SnapshotMode: "full-snapshot", UpdateKind: "initial",
		Generation: 1, RequiredSafetyFloor: 2,
		ValidFrom: now - 10, ValidUntil: now + 1200,
		RootEpoch: 1, RevocationEpoch: 1,
		RelayIDs: []string{"relay-alpha-001"}, StrategyIDs: []string{"strategy-alpha-001"},
		Policy: []byte{0xa1, 0x01, 0x01},
	}
	issuance := profile.OfflineIssuanceSpec{
		Profile: profileValue, Class: envelope.ArtifactSignedPublic,
		Audience: envelope.AudiencePublic, Suite: envelope.SuiteClassicalV1,
		IssuerRole: profile.RoleIssuer, IssuerScope: scope, IssuerKey: issuerKey,
		MinimumGeneration: 1, Now: now,
	}
	artifact, err := profile.IssueOffline(issuance, credentials, nil)
	if err != nil {
		return profile.ActivationRequest{}, envelope.CanonicalProfileV1{}, err
	}
	revocations := profile.RevocationSetV1{
		Version: 1, Scope: profileValue.RevocationScope, RootEpoch: root.Epoch, Epoch: 1,
		IssuedAt: now - 10, ExpiresAt: now + 1200, MaxOfflineStalenessSecs: 600,
		RevokedIssuerKeyIDs: []string{}, RevokedContentIDs: []string{},
	}
	revocationPayload, err := profile.EncodeRevocationSetV1(revocations)
	if err != nil {
		return profile.ActivationRequest{}, envelope.CanonicalProfileV1{}, err
	}
	revocationSignature, err := credentials.Sign(rootKey, revocationPayload)
	if err != nil {
		return profile.ActivationRequest{}, envelope.CanonicalProfileV1{}, err
	}
	return profile.ActivationRequest{
		Artifact: artifact,
		Dispatch: envelope.ArtifactMetadata{
			Class: envelope.ArtifactSignedPublic, AudienceClass: envelope.AudiencePublic,
		},
		Now: now, Root: root,
		Delegation: profile.SignedIssuerDelegationV1{
			Artifact: delegation, RootKey: rootKey,
			Payload: delegationPayload, Signature: delegationSignature,
		},
		Revocations: profile.SignedRevocationSetV1{
			Set: revocations, RootKey: rootKey,
			Payload: revocationPayload, Signature: revocationSignature,
		},
		Verifier: credentials, ContractVersion: "product-profile-admission-v1",
		MinSafetyFloor: 2, MinRootEpoch: 1, MinRevocationEpoch: 1,
	}, profileValue, nil
}

func buildDemoRelayRequest(profileValue envelope.CanonicalProfileV1, evidenceReference string, now int64) (sessionplan.Request, error) {
	state := lifecycle.State{
		Status: lifecycle.Admitted, ProfileID: profileValue.ProfileID,
		Scope: profileValue.RevocationScope, EvidenceReference: evidenceReference,
		Generation: profileValue.Generation,
	}
	strategyRequest := strategy.Request{
		Lifecycle: state,
		Policy: strategy.Policy{
			Version: strategy.Version, ProfileID: state.ProfileID, Scope: state.Scope,
			EvidenceReference: state.EvidenceReference, Generation: state.Generation,
			MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2,
			Permitted: []strategy.Candidate{{
				Family:               carrierreview.FamilyHTTPSLikeTCP,
				RequiredCapabilities: []string{"capability-alpha"},
				MinimumSafetyFloor:   2, MinimumPrivacyFloor: 2,
			}},
		},
		Client: strategy.Client{
			SupportedVersion:  strategy.Version,
			SupportedFamilies: []string{carrierreview.FamilyHTTPSLikeTCP},
			Capabilities:      []string{"capability-alpha"},
			SafetyFloor:       2, PrivacyFloor: 2,
		},
	}
	selected, err := strategy.Select(strategyRequest)
	if err != nil {
		return sessionplan.Request{}, err
	}
	descriptor := relaydescriptor.Descriptor{
		Version: relaydescriptor.Version, DescriptorID: "relay-alpha-001",
		ProfileID: state.ProfileID, Scope: state.Scope, EvidenceReference: state.EvidenceReference,
		Generation: state.Generation, Family: selected.SelectedFamily, ClientID: "client-alpha-001",
		ClientCapabilities: []string{"capability-alpha"},
		EndpointReference:  "relayref:local-disposable-relay",
		NotBefore:          now - 60, ExpiresAt: now + 3600,
	}
	relayRequest := relaydescriptor.Request{
		Version: relaydescriptor.Version, StrategyRequest: strategyRequest, ClaimedResult: selected,
		EvaluationTime: now, Client: relaydescriptor.ClientBinding{ID: "client-alpha-001"},
		Policy: relaydescriptor.Policy{
			Version: relaydescriptor.Version, ProfileID: state.ProfileID, Scope: state.Scope,
			EvidenceReference: state.EvidenceReference, Generation: state.Generation,
			FallbackPolicy: strategyRequest.Policy, SelectedFamily: selected.SelectedFamily,
			ClientCapabilities:    []string{"capability-alpha"},
			AuthorizedClientIDs:   []string{"client-alpha-001"},
			AuthorizedDescriptors: []relaydescriptor.Descriptor{descriptor},
		},
		Revocation: relaydescriptor.RevocationState{
			Version: relaydescriptor.Version, Complete: true, ProfileID: state.ProfileID,
			Scope: state.Scope, EvidenceReference: state.EvidenceReference,
			Generation: state.Generation, EvaluatedAt: now,
		},
		Descriptors: []relaydescriptor.Descriptor{descriptor},
	}
	admitted, err := relaydescriptor.Admit(relayRequest)
	if err != nil {
		return sessionplan.Request{}, err
	}
	return sessionplan.Request{
		StrategyRequest: strategyRequest, ClaimedStrategy: selected,
		RelayRequest: relayRequest, ClaimedAdmission: admitted,
		DescriptorID: descriptor.DescriptorID, DialTimeoutMs: 5_000, MaxFrameBytes: 64 << 10,
	}, nil
}

func buildDemoEmergencyAction(
	credentials *demoCredentials,
	root profile.RootSetArtifact,
	now int64,
) (profile.VerifiedEmergencyAuthority, profile.SignedEmergencyAction, error) {
	authority := profile.EmergencyAuthorityArtifact{
		Key: demoKeyReference("local-emergency-key-0001"), Scope: demoAuthorityScope(),
		ValidFrom: now - 120, ValidUntil: now + 1200, AuthorizationEpoch: 1,
	}
	delegation := profile.EmergencyAuthorityDelegationArtifact{
		RootEpoch: root.Epoch, RootKeyID: root.Keys[0].KeyID, Authority: authority,
	}
	delegationPayload, err := profile.EncodeEmergencyAuthorityDelegationV1(delegation)
	if err != nil {
		return profile.VerifiedEmergencyAuthority{}, profile.SignedEmergencyAction{}, err
	}
	delegationSignature, err := credentials.Sign(root.Keys[0], delegationPayload)
	if err != nil {
		return profile.VerifiedEmergencyAuthority{}, profile.SignedEmergencyAction{}, err
	}
	trusted, err := profile.VerifyEmergencyAuthorityDelegation(
		root,
		profile.SignedEmergencyAuthorityDelegation{
			Artifact: delegation, RootKey: root.Keys[0],
			Payload: delegationPayload, Signature: delegationSignature,
		},
		credentials,
		now,
	)
	if err != nil {
		return profile.VerifiedEmergencyAuthority{}, profile.SignedEmergencyAction{}, err
	}
	action := profile.EmergencyAction{
		Kind: profile.EmergencyDeny, Scope: authority.Scope, Epoch: 1,
		ValidFrom: now - 10, ValidUntil: now + 600,
	}
	payload, err := profile.EncodeEmergencyAuthorizationV1(authority, action)
	if err != nil {
		return profile.VerifiedEmergencyAuthority{}, profile.SignedEmergencyAction{}, err
	}
	signature, err := credentials.Sign(authority.Key, payload)
	if err != nil {
		return profile.VerifiedEmergencyAuthority{}, profile.SignedEmergencyAction{}, err
	}
	return trusted, profile.SignedEmergencyAction{
		Authority: authority, Action: action, Payload: payload, Signature: signature,
	}, nil
}

type conformanceHandler struct{}

func (conformanceHandler) Apply(_ context.Context, effect controlplane.Effect) error {
	if effect.EventID == "" || effect.Action == "" ||
		effect.TargetDigest == "" || effect.SubjectDigest == "" {
		return controlplane.ErrConflict
	}
	return nil
}
