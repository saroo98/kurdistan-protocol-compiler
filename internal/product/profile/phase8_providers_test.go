// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"kurdistan/internal/product/envelope"
)

const trustTestNow int64 = 2_000_000_000

func validRootSet() RootSetArtifact {
	return RootSetArtifact{
		Epoch: 7, ViewID: "root-view-7", ValidFrom: trustTestNow - 100, ValidUntil: trustTestNow + 10_000,
		Keys: []KeyReference{{KeyID: "root-key-7", SuiteID: 1}},
	}
}

func validScope() AuthorityScope {
	return AuthorityScope{ProviderID: "provider-1", LineageID: "lineage-1", ProfileNamespace: "kurd/"}
}

func validIssuerDelegation() IssuerDelegationArtifact {
	return IssuerDelegationArtifact{
		RootEpoch: 7, RootKeyID: "root-key-7", IssuerKey: KeyReference{KeyID: "issuer-key-1", SuiteID: 1}, Scope: validScope(),
		ValidFrom: trustTestNow - 10, ValidUntil: trustTestNow + 1000, DelegationEpoch: 1, MaxProfileValiditySecs: 3600,
	}
}

func validScopedAuthority(role AuthorityRole) ScopedAuthorityArtifact {
	keyID := "provider-key-1"
	if role == RoleRecipientRegistrar {
		keyID = "registrar-key-1"
	}
	return ScopedAuthorityArtifact{
		Role: role, RootEpoch: 7, RootKeyID: "root-key-7", SubjectKey: KeyReference{KeyID: keyID, SuiteID: 1}, Scope: validScope(),
		ValidFrom: trustTestNow - 10, ValidUntil: trustTestNow + 1000, AuthorizationEpoch: 1,
	}
}

func validBinding(class envelope.ArtifactClass, epoch uint64) RecipientBinding {
	hint, keyID := "rotating_hint_device_01", "device-key-1"
	switch class {
	case envelope.ArtifactProviderGroup:
		hint, keyID = "rotating_hint_group_01", "group-key-1"
	case envelope.ArtifactEncryptedBackup:
		hint, keyID = "rotating_hint_backup_01", "backup-key-1"
	}
	return RecipientBinding{Class: class, ProviderID: "provider-1", LineageID: "lineage-1", ProfileNamespace: "kurd/", Hint: hint, KeyID: keyID, Epoch: epoch}
}

func TestWO804ValidTrustTransitions(t *testing.T) {
	root := validRootSet()
	next := root
	next.Epoch, next.ViewID = root.Epoch+1, "root-view-8"
	next.Keys = []KeyReference{{KeyID: "root-key-8", SuiteID: 1}}
	if err := ValidateRootSetUpdate(root, next, "root-key-7"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateIssuerDelegation(root, validIssuerDelegation(), trustTestNow, "provider-1", "lineage-1", "kurd/profile-1"); err != nil {
		t.Fatal(err)
	}
	for _, class := range []envelope.ArtifactClass{envelope.ArtifactProviderGroup, envelope.ArtifactDeviceRecipient, envelope.ArtifactEncryptedBackup} {
		role := RoleRecipientRegistrar
		if class == envelope.ArtifactProviderGroup {
			role = RoleProvider
		}
		authority := validScopedAuthority(role)
		enrolled := validBinding(class, 1)
		if err := ValidateRecipientTransition(root, authority, nil, enrolled, RecipientEnroll, trustTestNow); err != nil {
			t.Fatalf("%s enrollment: %v", class, err)
		}
		rotated := enrolled
		rotated.Epoch++
		rotated.Hint += "_next"
		rotated.KeyID += "-next"
		if err := ValidateRecipientTransition(root, authority, &enrolled, rotated, RecipientRotate, trustTestNow); err != nil {
			t.Fatalf("%s rotation: %v", class, err)
		}
		revoked := rotated
		revoked.Epoch++
		revoked.Revoked = true
		if err := ValidateRecipientTransition(root, authority, &rotated, revoked, RecipientRevoke, trustTestNow); err != nil {
			t.Fatalf("%s revocation: %v", class, err)
		}
	}
}

func TestValidateIssuerDelegationAcceptsCanonicalDotNamespace(t *testing.T) {
	root := validRootSet()
	delegation := validIssuerDelegation()
	delegation.Scope.ProfileNamespace = "profiles."
	if err := ValidateIssuerDelegation(root, delegation, trustTestNow, "provider-1", "lineage-1", "profiles.one"); err != nil {
		t.Fatalf("dot-terminated canonical namespace rejected: %v", err)
	}
	delegation.Scope.ProfileNamespace = "kurd/"
	if err := ValidateIssuerDelegation(root, delegation, trustTestNow, "provider-1", "lineage-1", "kurd/profile-1"); err != nil {
		t.Fatalf("slash namespace regressed: %v", err)
	}
}

func TestEncodeScopedAuthorityV1IsCanonicalAndRoleBound(t *testing.T) {
	authority := validScopedAuthority(RoleRecipientRegistrar)
	first, err := EncodeScopedAuthorityV1(authority)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncodeScopedAuthorityV1(authority)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("scoped authority encoding is not canonical: err=%v", err)
	}
	changed := authority
	changed.Role = RoleProvider
	changed.SubjectKey.KeyID = "provider-key-1"
	other, err := EncodeScopedAuthorityV1(changed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, other) {
		t.Fatal("scoped authority encoding did not bind the authority role")
	}
	invalid := authority
	invalid.Role = RoleIssuer
	if _, err := EncodeScopedAuthorityV1(invalid); err == nil {
		t.Fatal("issuer role encoded as a scoped recipient authority")
	}
}

func TestWO804EmergencyAuthorityIsDenyOnly(t *testing.T) {
	authority := validEmergencyAuthority()
	deny := EmergencyAction{Kind: EmergencyDeny, Scope: validScope(), Epoch: 4, ValidFrom: trustTestNow - 1, ValidUntil: trustTestNow + 10}
	if err := ValidateEmergencyAction(authority, 3, deny, trustTestNow); err != nil {
		t.Fatal(err)
	}
	narrow := deny
	narrow.Kind = EmergencyNarrow
	narrow.Scope.ProfileNamespace = "kurd/region/"
	if err := ValidateEmergencyAction(authority, 3, narrow, trustTestNow); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []AuthorityOperation{OperationIssueProfile, OperationAuthorizeGroup, OperationSignAppRelease, OperationUpdateRoot} {
		if err := AuthorizeRoleOperation(RoleEmergency, operation); err == nil {
			t.Fatalf("emergency authority admitted %s", operation)
		}
	}
}

func validEmergencyAuthority() EmergencyAuthorityArtifact {
	return EmergencyAuthorityArtifact{Key: KeyReference{KeyID: "emergency-key-1", SuiteID: 1}, Scope: validScope(), ValidFrom: trustTestNow - 100, ValidUntil: trustTestNow + 100, AuthorizationEpoch: 2}
}

type memoryKeyProvider struct {
	secrets map[string][]byte
	epochs  map[string]memoryEpoch
	events  []string
}

type memoryEpoch struct {
	epoch  uint64
	digest string
}

func newMemoryKeyProvider() *memoryKeyProvider {
	return &memoryKeyProvider{
		secrets: map[string][]byte{
			"issuer-key-1": []byte("TEST-ONLY-ISSUER-SECRET-32-BYTES"),
			"device-key-1": []byte("TEST-ONLY-DEVICE-SECRET-32-BYTES"),
		},
		epochs: make(map[string]memoryEpoch),
	}
}

func (p *memoryKeyProvider) String() string { return "deterministic-memory-key-provider(redacted)" }

func (p *memoryKeyProvider) secret(key KeyReference) ([]byte, error) {
	value, ok := p.secrets[key.KeyID]
	if !ok {
		return nil, errors.New("test provider: unknown key handle")
	}
	return value, nil
}

func (p *memoryKeyProvider) record(operation, keyID string) {
	p.events = append(p.events, operation+":"+keyID)
}

func (p *memoryKeyProvider) Sign(key KeyReference, message []byte) ([]byte, error) {
	secret, err := p.secret(key)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(message)
	p.record("sign", key.KeyID)
	return mac.Sum(nil), nil
}

func (p *memoryKeyProvider) Verify(key KeyReference, message, signature []byte) error {
	expected, err := p.Sign(key, message)
	if err != nil {
		return err
	}
	p.events[len(p.events)-1] = "verify:" + key.KeyID
	if !hmac.Equal(expected, signature) {
		return errors.New("test provider: invalid signature")
	}
	return nil
}

func testStream(secret, label []byte, size int) []byte {
	out := make([]byte, 0, size)
	for counter := byte(0); len(out) < size; counter++ {
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write(label)
		_, _ = mac.Write([]byte{counter})
		out = append(out, mac.Sum(nil)...)
	}
	return out[:size]
}

func xorBytes(input, mask []byte) []byte {
	out := make([]byte, len(input))
	for i := range input {
		out[i] = input[i] ^ mask[i]
	}
	return out
}

func (p *memoryKeyProvider) Seal(binding RecipientBinding, plaintext []byte) ([]byte, []byte, error) {
	secret, err := p.secret(KeyReference{KeyID: binding.KeyID, SuiteID: 1})
	if err != nil {
		return nil, nil, err
	}
	enc := sha256.Sum256([]byte(binding.KeyID + "|" + binding.Hint))
	ciphertext := xorBytes(plaintext, testStream(secret, enc[:], len(plaintext)))
	p.record("seal", binding.KeyID)
	return enc[:], ciphertext, nil
}

func (p *memoryKeyProvider) Open(binding RecipientBinding, encapsulation, ciphertext []byte) ([]byte, error) {
	secret, err := p.secret(KeyReference{KeyID: binding.KeyID, SuiteID: 1})
	if err != nil {
		return nil, err
	}
	want := sha256.Sum256([]byte(binding.KeyID + "|" + binding.Hint))
	if !bytes.Equal(want[:], encapsulation) {
		return nil, errors.New("test provider: encapsulation mismatch")
	}
	p.record("open", binding.KeyID)
	return xorBytes(ciphertext, testStream(secret, encapsulation, len(ciphertext))), nil
}

func (p *memoryKeyProvider) Wrap(key KeyReference, plaintext []byte) ([]byte, error) {
	secret, err := p.secret(key)
	if err != nil {
		return nil, err
	}
	p.record("wrap", key.KeyID)
	return xorBytes(plaintext, testStream(secret, []byte("local-wrap"), len(plaintext))), nil
}

func (p *memoryKeyProvider) Unwrap(key KeyReference, ciphertext []byte) ([]byte, error) {
	plaintext, err := p.Wrap(key, ciphertext)
	if err == nil {
		p.events[len(p.events)-1] = "unwrap:" + key.KeyID
	}
	return plaintext, err
}

func (p *memoryKeyProvider) Load(name string) (uint64, string, bool, error) {
	value, ok := p.epochs[name]
	return value.epoch, value.digest, ok, nil
}

func (p *memoryKeyProvider) CompareAndAdvance(name string, expected, next uint64, digest string) error {
	current := p.epochs[name]
	if current.epoch != expected || next != expected+1 || digest == "" {
		return ErrMonotonicTransition
	}
	p.epochs[name] = memoryEpoch{epoch: next, digest: digest}
	p.record("advance", name)
	return nil
}

type memoryResolver struct{ bindings []RecipientBinding }

func (r memoryResolver) ResolveRecipient(class envelope.ArtifactClass, hint string) (RecipientBinding, error) {
	return ResolveRecipientBinding(r.bindings, class, hint)
}

type fixedResolver struct {
	binding RecipientBinding
	err     error
}

func (r fixedResolver) ResolveRecipient(envelope.ArtifactClass, string) (RecipientBinding, error) {
	return r.binding, r.err
}

type countingOpener struct {
	provider *memoryKeyProvider
	attempts int
}

func (o *countingOpener) Open(binding RecipientBinding, enc, ciphertext []byte) ([]byte, error) {
	o.attempts++
	return o.provider.Open(binding, enc, ciphertext)
}

func TestWO804DeterministicTestProvidersAndNoTryAll(t *testing.T) {
	provider := newMemoryKeyProvider()
	key := KeyReference{KeyID: "issuer-key-1", SuiteID: 1}
	message := []byte("profile-fixture-bytes")
	one, err := provider.Sign(key, message)
	if err != nil {
		t.Fatal(err)
	}
	two, err := provider.Sign(key, message)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one, two) || provider.Verify(key, message, one) != nil {
		t.Fatal("deterministic test signature did not reproduce and verify")
	}
	binding := validBinding(envelope.ArtifactDeviceRecipient, 1)
	enc, ciphertext, err := provider.Seal(binding, message)
	if err != nil {
		t.Fatal(err)
	}
	opener := &countingOpener{provider: provider}
	plaintext, err := OpenResolvedRecipient(memoryResolver{bindings: []RecipientBinding{binding}}, opener, binding.Class, binding.Hint, enc, ciphertext)
	if err != nil || !bytes.Equal(plaintext, message) || opener.attempts != 1 {
		t.Fatalf("resolved open: plaintext=%q attempts=%d err=%v", plaintext, opener.attempts, err)
	}
	before := opener.attempts
	if _, err := OpenResolvedRecipient(memoryResolver{bindings: []RecipientBinding{binding}}, opener, binding.Class, "unknown_hint_000", enc, ciphertext); err == nil || opener.attempts != before {
		t.Fatal("unknown hint attempted recipient keys")
	}
	colliding := []RecipientBinding{binding, binding}
	if _, err := OpenResolvedRecipient(memoryResolver{bindings: colliding}, opener, binding.Class, binding.Hint, enc, ciphertext); err == nil || opener.attempts != before {
		t.Fatal("colliding hint attempted recipient keys")
	}
	if err := provider.CompareAndAdvance("recipient/provider-1", 0, 1, "digest-1"); err != nil {
		t.Fatal(err)
	}
	if err := provider.CompareAndAdvance("recipient/provider-1", 0, 1, "digest-conflict"); err == nil {
		t.Fatal("monotonic provider accepted conflicting compare-and-advance")
	}
	combined := provider.String() + strings.Join(provider.events, "\n")
	for _, secret := range provider.secrets {
		if bytes.Contains([]byte(combined), secret) {
			t.Fatal("provider diagnostic surface exposed test secret")
		}
	}
	if strings.Contains(combined, string(message)) {
		t.Fatal("provider diagnostic surface exposed profile bytes")
	}
}

func TestWO804RecipientResolverCandidateBounds(t *testing.T) {
	bindings := make([]RecipientBinding, MaxRecipientBindingCandidates)
	for i := range bindings {
		bindings[i] = validBinding(envelope.ArtifactDeviceRecipient, 1)
		bindings[i].Hint = fmt.Sprintf("device_hint_%03d", i)
		bindings[i].KeyID = fmt.Sprintf("device-key-%03d", i)
	}
	want := bindings[len(bindings)-1]
	got, err := ResolveRecipientBinding(bindings, want.Class, want.Hint)
	if err != nil || got != want {
		t.Fatalf("exact candidate boundary rejected: got=%+v err=%v", got, err)
	}
	over := append(append([]RecipientBinding(nil), bindings...), validBinding(envelope.ArtifactDeviceRecipient, 1))
	opener := &countingOpener{provider: newMemoryKeyProvider()}
	if _, err := OpenResolvedRecipient(memoryResolver{bindings: over}, opener, want.Class, want.Hint, nil, nil); err == nil || opener.attempts != 0 {
		t.Fatalf("one-over candidate boundary reached opener: attempts=%d err=%v", opener.attempts, err)
	}
}

type executableEvidenceCase struct {
	name string
	run  func() error
}

type recordedEvidence struct {
	Schema string `json:"schema"`
	Cases  []struct {
		Name   string `json:"name"`
		Result string `json:"result"`
	} `json:"cases"`
	Summary map[string]int `json:"summary"`
}

func loadRecordedEvidence(t *testing.T, name string) recordedEvidence {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var report recordedEvidence
	if err := json.Unmarshal(content, &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func verifyRejectedEvidence(t *testing.T, filename, schema string, cases []executableEvidenceCase, minimum int) {
	t.Helper()
	report := loadRecordedEvidence(t, filename)
	if report.Schema != schema || len(report.Cases) < minimum || len(report.Cases) != len(cases) || report.Summary["accepted"] != 0 || report.Summary["rejected"] != len(cases) {
		t.Fatalf("invalid %s summary: schema=%q cases=%d summary=%v", filename, report.Schema, len(report.Cases), report.Summary)
	}
	executable := make(map[string]func() error, len(cases))
	for _, testCase := range cases {
		executable[testCase.name] = testCase.run
	}
	for _, recorded := range report.Cases {
		run, ok := executable[recorded.Name]
		if !ok || recorded.Result != "rejected" {
			t.Fatalf("unbound evidence case %+v", recorded)
		}
		if err := run(); err == nil {
			t.Fatalf("evidence case %q unexpectedly accepted", recorded.Name)
		}
	}
}

func roleConfusionCases() []executableEvidenceCase {
	profileOperations := []AuthorityOperation{OperationIssueProfile, OperationAuthorizeGroup, OperationEnrollDevice, OperationEnrollBackup}
	nonProfileRoles := []AuthorityRole{RoleRoot, RoleEmergency, RoleRelay, RoleAppRelease, RoleDeviceWrap, RoleBackup, RoleOperator}
	var cases []executableEvidenceCase
	for _, role := range nonProfileRoles {
		for _, operation := range profileOperations {
			role, operation := role, operation
			cases = append(cases, executableEvidenceCase{name: string(role) + " cannot " + string(operation), run: func() error { return AuthorizeRoleOperation(role, operation) }})
		}
	}
	for _, item := range []struct {
		role AuthorityRole
		op   AuthorityOperation
	}{
		{RoleIssuer, OperationAuthorizeGroup}, {RoleIssuer, OperationEnrollDevice}, {RoleIssuer, OperationEnrollBackup},
		{RoleProvider, OperationIssueProfile}, {RoleProvider, OperationEnrollDevice}, {RoleProvider, OperationEnrollBackup},
		{RoleRecipientRegistrar, OperationIssueProfile}, {RoleRecipientRegistrar, OperationAuthorizeGroup},
	} {
		item := item
		cases = append(cases, executableEvidenceCase{name: string(item.role) + " cannot " + string(item.op), run: func() error { return AuthorizeRoleOperation(item.role, item.op) }})
	}
	return cases
}

func delegationNegativeCases() []executableEvidenceCase {
	root := validRootSet()
	return []executableEvidenceCase{
		{name: "issuer provider scope mismatch", run: func() error {
			d := validIssuerDelegation()
			return ValidateIssuerDelegation(root, d, trustTestNow, "provider-other", "lineage-1", "kurd/profile-1")
		}},
		{name: "issuer delegation expired", run: func() error {
			d := validIssuerDelegation()
			d.ValidUntil = trustTestNow
			return ValidateIssuerDelegation(root, d, trustTestNow, "provider-1", "lineage-1", "kurd/profile-1")
		}},
		{name: "issuer key id collides with root", run: func() error {
			d := validIssuerDelegation()
			d.IssuerKey.KeyID = "root-key-7"
			return ValidateIssuerDelegation(root, d, trustTestNow, "provider-1", "lineage-1", "kurd/profile-1")
		}},
		{name: "issuer delegation names unknown root", run: func() error {
			d := validIssuerDelegation()
			d.RootKeyID = "root-unknown"
			return ValidateIssuerDelegation(root, d, trustTestNow, "provider-1", "lineage-1", "kurd/profile-1")
		}},
		{name: "revoked issuer delegation", run: func() error {
			d := validIssuerDelegation()
			d.Revoked = true
			return ValidateIssuerDelegation(root, d, trustTestNow, "provider-1", "lineage-1", "kurd/profile-1")
		}},
		{name: "unauthorized root set update", run: func() error {
			next := root
			next.Epoch++
			next.ViewID = "root-view-8"
			return ValidateRootSetUpdate(root, next, "root-unknown")
		}},
		{name: "issuer delegation expired root", run: func() error {
			expired := root
			expired.ValidUntil = trustTestNow
			return ValidateIssuerDelegation(expired, validIssuerDelegation(), trustTestNow, "provider-1", "lineage-1", "kurd/profile-1")
		}},
		{name: "issuer delegation future root", run: func() error {
			future := root
			future.ValidFrom = trustTestNow + 1
			future.ValidUntil = trustTestNow + 100
			return ValidateIssuerDelegation(future, validIssuerDelegation(), trustTestNow, "provider-1", "lineage-1", "kurd/profile-1")
		}},
	}
}

func rootEmergencyNegativeCases() []executableEvidenceCase {
	root := validRootSet()
	authority := validEmergencyAuthority()
	action := EmergencyAction{Kind: EmergencyDeny, Scope: validScope(), Epoch: 4, ValidFrom: trustTestNow - 1, ValidUntil: trustTestNow + 10}
	return []executableEvidenceCase{
		{name: "root rollback", run: func() error {
			next := root
			next.Epoch--
			next.ViewID = "root-view-6"
			return ValidateRootSetUpdate(root, next, "root-key-7")
		}},
		{name: "unauthorized root update", run: func() error {
			next := root
			next.Epoch++
			next.ViewID = "root-view-8"
			return ValidateRootSetUpdate(root, next, "root-unknown")
		}},
		{name: "equal epoch root conflict", run: func() error {
			next := root
			next.ViewID = "root-view-conflict"
			return ValidateRootSetUpdate(root, next, "root-key-7")
		}},
		{name: "conflicting observed root view", run: func() error {
			observed := root
			observed.ViewID = "root-view-split"
			return ValidateRootView(root, observed)
		}},
		{name: "same root view id with different keys", run: func() error {
			observed := root
			observed.Keys = append([]KeyReference(nil), root.Keys...)
			observed.Keys[0].KeyID = "root-key-other"
			return ValidateRootView(root, observed)
		}},
		{name: "same root view id with different validity", run: func() error {
			observed := root
			observed.ValidUntil++
			return ValidateRootView(root, observed)
		}},
		{name: "stale emergency action", run: func() error {
			stale := action
			stale.Epoch = 3
			return ValidateEmergencyAction(authority, 3, stale, trustTestNow)
		}},
	}
}

func registrarNegativeCases() []executableEvidenceCase {
	root := validRootSet()
	registrar := validScopedAuthority(RoleRecipientRegistrar)
	provider := validScopedAuthority(RoleProvider)
	device := validBinding(envelope.ArtifactDeviceRecipient, 1)
	backup := validBinding(envelope.ArtifactEncryptedBackup, 1)
	group := validBinding(envelope.ArtifactProviderGroup, 1)
	rotate := func(binding RecipientBinding) RecipientBinding {
		binding.Epoch++
		binding.Hint += "_next"
		binding.KeyID += "-next"
		return binding
	}
	cases := []executableEvidenceCase{
		{name: "provider group unknown transition", run: func() error {
			return ValidateRecipientTransition(root, provider, &group, rotate(group), RecipientTransition("unknown"), trustTestNow)
		}},
		{name: "provider authority malformed root", run: func() error {
			malformed := root
			malformed.Keys = append(malformed.Keys, malformed.Keys[0])
			return ValidateRecipientTransition(malformed, provider, nil, group, RecipientEnroll, trustTestNow)
		}},
		{name: "registrar authority malformed root", run: func() error {
			malformed := root
			malformed.Epoch = 0
			return ValidateRecipientTransition(malformed, registrar, nil, device, RecipientEnroll, trustTestNow)
		}},
		{name: "provider authority expired root", run: func() error {
			expired := root
			expired.ValidUntil = trustTestNow
			return ValidateRecipientTransition(expired, provider, nil, group, RecipientEnroll, trustTestNow)
		}},
		{name: "provider authority future root", run: func() error {
			future := root
			future.ValidFrom = trustTestNow + 1
			future.ValidUntil = trustTestNow + 100
			return ValidateRecipientTransition(future, provider, nil, group, RecipientEnroll, trustTestNow)
		}},
		{name: "registrar authority expired root", run: func() error {
			expired := root
			expired.ValidUntil = trustTestNow
			return ValidateRecipientTransition(expired, registrar, nil, device, RecipientEnroll, trustTestNow)
		}},
		{name: "registrar authority future root", run: func() error {
			future := root
			future.ValidFrom = trustTestNow + 1
			future.ValidUntil = trustTestNow + 100
			return ValidateRecipientTransition(future, registrar, nil, device, RecipientEnroll, trustTestNow)
		}},
		{name: "issuer attempts device enrollment", run: func() error {
			a := registrar
			a.Role = RoleIssuer
			return ValidateRecipientTransition(root, a, nil, device, RecipientEnroll, trustTestNow)
		}},
		{name: "provider attempts device enrollment", run: func() error {
			return ValidateRecipientTransition(root, provider, nil, device, RecipientEnroll, trustTestNow)
		}},
		{name: "registrar attempts group authorization", run: func() error {
			return ValidateRecipientTransition(root, registrar, nil, group, RecipientEnroll, trustTestNow)
		}},
		{name: "issuer attempts group authorization", run: func() error { return AuthorizeRoleOperation(RoleIssuer, OperationAuthorizeGroup) }},
		{name: "provider attempts profile issuance", run: func() error { return AuthorizeRoleOperation(RoleProvider, OperationIssueProfile) }},
		{name: "registrar attempts profile issuance", run: func() error { return AuthorizeRoleOperation(RoleRecipientRegistrar, OperationIssueProfile) }},
		{name: "expired registrar delegation", run: func() error {
			a := registrar
			a.ValidUntil = trustTestNow
			return ValidateRecipientTransition(root, a, nil, device, RecipientEnroll, trustTestNow)
		}},
		{name: "revoked registrar delegation", run: func() error {
			a := registrar
			a.Revoked = true
			return ValidateRecipientTransition(root, a, nil, device, RecipientEnroll, trustTestNow)
		}},
		{name: "registrar wrong provider scope", run: func() error {
			next := device
			next.ProviderID = "provider-other"
			return ValidateRecipientTransition(root, registrar, nil, next, RecipientEnroll, trustTestNow)
		}},
		{name: "registrar wrong lineage scope", run: func() error {
			next := device
			next.LineageID = "lineage-other"
			return ValidateRecipientTransition(root, registrar, nil, next, RecipientEnroll, trustTestNow)
		}},
		{name: "signed public nonzero recipient epoch", run: func() error {
			next := device
			next.Class = envelope.ArtifactSignedPublic
			return ValidateRecipientTransition(root, registrar, nil, next, RecipientEnroll, trustTestNow)
		}},
		{name: "provider group zero epoch", run: func() error {
			next := group
			next.Epoch = 0
			return ValidateRecipientTransition(root, provider, nil, next, RecipientEnroll, trustTestNow)
		}},
		{name: "device zero epoch", run: func() error {
			next := device
			next.Epoch = 0
			return ValidateRecipientTransition(root, registrar, nil, next, RecipientEnroll, trustTestNow)
		}},
		{name: "backup zero epoch", run: func() error {
			next := backup
			next.Epoch = 0
			return ValidateRecipientTransition(root, registrar, nil, next, RecipientEnroll, trustTestNow)
		}},
		{name: "stale recipient epoch", run: func() error {
			next := rotate(device)
			next.Epoch = device.Epoch
			return ValidateRecipientTransition(root, registrar, &device, next, RecipientRotate, trustTestNow)
		}},
		{name: "skipped recipient epoch", run: func() error {
			next := rotate(device)
			next.Epoch = device.Epoch + 2
			return ValidateRecipientTransition(root, registrar, &device, next, RecipientRotate, trustTestNow)
		}},
		{name: "conflicting equal recipient epoch", run: func() error {
			next := rotate(device)
			next.Epoch = device.Epoch
			return ValidateRecipientTransition(root, registrar, &device, next, RecipientRotate, trustTestNow)
		}},
		{name: "wrong role for backup rotation", run: func() error {
			next := rotate(backup)
			return ValidateRecipientTransition(root, provider, &backup, next, RecipientRotate, trustTestNow)
		}},
		{name: "wrong class transition", run: func() error {
			next := rotate(backup)
			return ValidateRecipientTransition(root, registrar, &device, next, RecipientRotate, trustTestNow)
		}},
		{name: "unauthorized enrollment", run: func() error {
			a := registrar
			a.AuthorizationEpoch = 0
			return ValidateRecipientTransition(root, a, nil, device, RecipientEnroll, trustTestNow)
		}},
		{name: "unauthorized rotation", run: func() error {
			a := registrar
			a.RootKeyID = "root-unknown"
			next := rotate(device)
			return ValidateRecipientTransition(root, a, &device, next, RecipientRotate, trustTestNow)
		}},
		{name: "unauthorized revocation", run: func() error {
			a := registrar
			a.Revoked = true
			next := rotate(device)
			next.Revoked = true
			return ValidateRecipientTransition(root, a, &device, next, RecipientRevoke, trustTestNow)
		}},
		{name: "cross class hint substitution", run: func() error {
			_, err := ResolveRecipientBinding([]RecipientBinding{device}, envelope.ArtifactEncryptedBackup, device.Hint)
			return err
		}},
		{name: "unknown recipient hint", run: func() error {
			_, err := ResolveRecipientBinding([]RecipientBinding{device}, device.Class, "unknown_hint_001")
			return err
		}},
		{name: "ambiguous recipient hint", run: func() error {
			_, err := ResolveRecipientBinding([]RecipientBinding{device, device}, device.Class, device.Hint)
			return err
		}},
		{name: "colliding recipient hint", run: func() error {
			other := device
			other.KeyID = "device-key-collision"
			_, err := ResolveRecipientBinding([]RecipientBinding{device, other}, device.Class, device.Hint)
			return err
		}},
		{name: "try all prohibited on unknown hint", run: func() error {
			p := newMemoryKeyProvider()
			o := &countingOpener{provider: p}
			_, err := OpenResolvedRecipient(memoryResolver{bindings: []RecipientBinding{device}}, o, device.Class, "unknown_hint_002", nil, nil)
			if err == nil || o.attempts != 0 {
				return nil
			}
			return err
		}},
		{name: "try all prohibited on collision", run: func() error {
			p := newMemoryKeyProvider()
			o := &countingOpener{provider: p}
			_, err := OpenResolvedRecipient(memoryResolver{bindings: []RecipientBinding{device, device}}, o, device.Class, device.Hint, nil, nil)
			if err == nil || o.attempts != 0 {
				return nil
			}
			return err
		}},
		{name: "malicious resolver wrong class", run: func() error {
			returned := device
			returned.Class = envelope.ArtifactEncryptedBackup
			o := &countingOpener{provider: newMemoryKeyProvider()}
			_, err := OpenResolvedRecipient(fixedResolver{binding: returned}, o, device.Class, device.Hint, nil, nil)
			if err == nil || o.attempts != 0 {
				return nil
			}
			return err
		}},
		{name: "malicious resolver wrong hint", run: func() error {
			returned := device
			returned.Hint = "device_hint_wrong"
			o := &countingOpener{provider: newMemoryKeyProvider()}
			_, err := OpenResolvedRecipient(fixedResolver{binding: returned}, o, device.Class, device.Hint, nil, nil)
			if err == nil || o.attempts != 0 {
				return nil
			}
			return err
		}},
		{name: "malicious resolver revoked binding", run: func() error {
			returned := device
			returned.Revoked = true
			o := &countingOpener{provider: newMemoryKeyProvider()}
			_, err := OpenResolvedRecipient(fixedResolver{binding: returned}, o, device.Class, device.Hint, nil, nil)
			if err == nil || o.attempts != 0 {
				return nil
			}
			return err
		}},
		{name: "malicious resolver malformed binding", run: func() error {
			returned := device
			returned.KeyID = ""
			o := &countingOpener{provider: newMemoryKeyProvider()}
			_, err := OpenResolvedRecipient(fixedResolver{binding: returned}, o, device.Class, device.Hint, nil, nil)
			if err == nil || o.attempts != 0 {
				return nil
			}
			return err
		}},
		{name: "empty recipient candidate list", run: func() error {
			o := &countingOpener{provider: newMemoryKeyProvider()}
			_, err := OpenResolvedRecipient(memoryResolver{}, o, device.Class, device.Hint, nil, nil)
			if err == nil || o.attempts != 0 {
				return nil
			}
			return err
		}},
		{name: "recipient candidate list exceeds maximum", run: func() error {
			bindings := make([]RecipientBinding, MaxRecipientBindingCandidates+1)
			for i := range bindings {
				bindings[i] = device
			}
			o := &countingOpener{provider: newMemoryKeyProvider()}
			_, err := OpenResolvedRecipient(memoryResolver{bindings: bindings}, o, device.Class, device.Hint, nil, nil)
			if err == nil || o.attempts != 0 {
				return nil
			}
			return err
		}},
	}
	return cases
}

type executableEmergencyCase struct {
	name      string
	permitted bool
	run       func() error
}

func emergencyAuthorityCases() []executableEmergencyCase {
	authority := validEmergencyAuthority()
	base := EmergencyAction{Kind: EmergencyDeny, Scope: validScope(), Epoch: 4, ValidFrom: trustTestNow - 1, ValidUntil: trustTestNow + 10}
	return []executableEmergencyCase{
		{name: "deny scoped profile", permitted: true, run: func() error {
			return ValidateEmergencyAction(authority, 3, base, trustTestNow)
		}},
		{name: "narrow provider namespace", permitted: true, run: func() error {
			action := base
			action.Kind = EmergencyNarrow
			action.Scope.ProfileNamespace = "kurd/restricted/"
			return ValidateEmergencyAction(authority, 3, action, trustTestNow)
		}},
		{name: "sign profile", run: func() error {
			return AuthorizeRoleOperation(RoleEmergency, OperationIssueProfile)
		}},
		{name: "enable service", run: func() error {
			action := base
			action.Kind = EmergencyActionKind("enable-service")
			return ValidateEmergencyAction(authority, 3, action, trustTestNow)
		}},
		{name: "downgrade policy", run: func() error {
			action := base
			action.Kind = EmergencyActionKind("downgrade-policy")
			return ValidateEmergencyAction(authority, 3, action, trustTestNow)
		}},
		{name: "erase state", run: func() error {
			action := base
			action.Kind = EmergencyActionKind("erase-state")
			return ValidateEmergencyAction(authority, 3, action, trustTestNow)
		}},
		{name: "expand scope", run: func() error {
			action := base
			action.Scope.ProviderID = "provider-other"
			return ValidateEmergencyAction(authority, 3, action, trustTestNow)
		}},
		{name: "malformed child scope", run: func() error {
			action := base
			action.Scope.ProviderID = ""
			return ValidateEmergencyAction(authority, 3, action, trustTestNow)
		}},
		{name: "non-terminated child scope", run: func() error {
			action := base
			action.Scope.ProfileNamespace = "kurd/restricted"
			return ValidateEmergencyAction(authority, 3, action, trustTestNow)
		}},
		{name: "oversized child scope", run: func() error {
			action := base
			action.Scope.ProfileNamespace = "kurd/" + strings.Repeat("x", 300) + "/"
			return ValidateEmergencyAction(authority, 3, action, trustTestNow)
		}},
	}
}

func TestWO804RecordedNegativeEvidence(t *testing.T) {
	verifyRejectedEvidence(t, "role-confusion-report.json", "kurdistan.phase8.role-confusion-report.v1", roleConfusionCases(), 30)
	verifyRejectedEvidence(t, "delegation-negative-report.json", "kurdistan.phase8.delegation-negative-report.v1", delegationNegativeCases(), 8)
	verifyRejectedEvidence(t, "root-emergency-negative-report.json", "kurdistan.phase8.root-emergency-negative-report.v1", rootEmergencyNegativeCases(), 7)
	registrar := registrarNegativeCases()
	verifyRejectedEvidence(t, "recipient-registrar-negative-report.json", "kurdistan.phase8.recipient-registrar-negative-report.v1", registrar, 20)
	report := loadRecordedEvidence(t, "recipient-registrar-negative-report.json")
	if report.Summary["open_attempts"] != 0 || report.Summary["state_mutations"] != 0 {
		t.Fatalf("registrar negatives reached open/state: %v", report.Summary)
	}
}

func TestWO804EmergencyAndProviderHygieneEvidence(t *testing.T) {
	emergency := loadRecordedEvidence(t, "emergency-authority-report.json")
	cases := emergencyAuthorityCases()
	if emergency.Schema != "kurdistan.phase8.emergency-authority-report.v1" || len(emergency.Cases) != len(cases) {
		t.Fatalf("invalid emergency report: %+v", emergency)
	}
	recorded := make(map[string]string, len(emergency.Cases))
	for _, item := range emergency.Cases {
		recorded[item.Name] = item.Result
	}
	permitted, rejected, prohibitedSuccesses := 0, 0, 0
	for _, item := range cases {
		want := "rejected"
		if item.permitted {
			want = "permitted"
		}
		if recorded[item.name] != want {
			t.Fatalf("emergency case %q result=%q want %q", item.name, recorded[item.name], want)
		}
		err := item.run()
		if item.permitted {
			permitted++
			if err != nil {
				t.Fatalf("permitted emergency case %q rejected: %v", item.name, err)
			}
		} else {
			rejected++
			if err == nil {
				prohibitedSuccesses++
			}
		}
	}
	if prohibitedSuccesses != 0 || emergency.Summary["permitted"] != permitted || emergency.Summary["rejected"] != rejected || emergency.Summary["prohibited_successes"] != prohibitedSuccesses {
		t.Fatalf("emergency execution/report mismatch: permitted=%d rejected=%d prohibited=%d report=%v", permitted, rejected, prohibitedSuccesses, emergency.Summary)
	}

	content, err := os.ReadFile(filepath.Join("testdata", "test-provider-hygiene-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var hygiene struct {
		Schema     string                                                  `json:"schema"`
		Providers  []struct{ Name, Classification, SecretExposure string } `json:"providers"`
		SecretScan struct {
			KeyByteFindings        int `json:"key_byte_findings"`
			ProfileByteLogFindings int `json:"profile_byte_log_findings"`
		} `json:"secret_scan"`
	}
	if err := json.Unmarshal(content, &hygiene); err != nil {
		t.Fatal(err)
	}
	if hygiene.Schema != "kurdistan.phase8.test-provider-hygiene-report.v1" || len(hygiene.Providers) < 5 || hygiene.SecretScan.KeyByteFindings != 0 || hygiene.SecretScan.ProfileByteLogFindings != 0 {
		t.Fatalf("invalid provider hygiene report: %+v", hygiene)
	}
}

func TestWO804EvidenceCaseNamesAreUnique(t *testing.T) {
	all := append(append(append([]executableEvidenceCase{}, roleConfusionCases()...), delegationNegativeCases()...), rootEmergencyNegativeCases()...)
	all = append(all, registrarNegativeCases()...)
	names := make([]string, 0, len(all))
	seen := make(map[string]struct{}, len(all))
	for _, item := range all {
		if _, duplicate := seen[item.name]; duplicate {
			t.Fatalf("duplicate evidence case %q", item.name)
		}
		seen[item.name] = struct{}{}
		names = append(names, item.name)
	}
	for _, item := range emergencyAuthorityCases() {
		if _, duplicate := seen[item.name]; duplicate {
			t.Fatalf("duplicate evidence case %q", item.name)
		}
		seen[item.name] = struct{}{}
		names = append(names, item.name)
	}
	sort.Strings(names)
	if len(names) < 60 {
		t.Fatalf("evidence case coverage = %d", len(names))
	}
}

func ExampleAuthorizeRoleOperation() {
	err := AuthorizeRoleOperation(RoleProvider, OperationIssueProfile)
	fmt.Println(errors.Is(err, ErrUnauthorizedRole))
	// Output: true
}
