// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command playrelease contains an inactive, loopback-only Play transaction
// model. It deliberately has no default HTTP client, credentials, or live API
// endpoint. Activation requires later release authority outside this command.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const (
	maxArtifactBytes = 512 << 20
	maxMetadataBytes = 4 << 20
	maxResponseBytes = 1 << 20
)

var (
	playSHA256Pattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	transactionIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	packageNamePattern   = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$`)
	trackPattern         = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}$`)
	remoteIDPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Client struct {
	baseURL string
	http    HTTPDoer
}

func NewClient(rawBaseURL string, doer HTTPDoer) (*Client, error) {
	if doer == nil {
		return nil, errors.New("an injected HTTP client is required")
	}
	parsed, err := url.Parse(rawBaseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("invalid test API base URL")
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, errors.New("Play client is inert and permits loopback test APIs only")
	}
	return &Client{baseURL: strings.TrimSuffix(rawBaseURL, "/"), http: doer}, nil
}

type State string

const (
	StateNew               State = "NEW"
	StateEditCreated       State = "EDIT_CREATED"
	StateArtifactUploaded  State = "ARTIFACT_UPLOADED"
	StateMetadataUploaded  State = "METADATA_UPLOADED"
	StateTrackAssigned     State = "TRACK_ASSIGNED"
	StateCommitted         State = "COMMITTED"
	StateVerified          State = "VERIFIED"
	StateReconcileRequired State = "RECONCILE_REQUIRED"
	StateHalted            State = "HALTED"
)

type Plan struct {
	Schema                 string `json:"schema"`
	TransactionID          string `json:"transactionId"`
	PackageName            string `json:"packageName"`
	VersionCode            int64  `json:"versionCode"`
	Track                  string `json:"track"`
	SourceTrack            string `json:"sourceTrack,omitempty"`
	ArtifactSHA256         string `json:"artifactSha256"`
	MetadataSHA256         string `json:"metadataSha256"`
	PromoteExistingVersion bool   `json:"promoteExistingVersion,omitempty"`
}

func (plan Plan) validate() error {
	if plan.Schema != "kurdistan-play-release-plan-v1" || !transactionIDPattern.MatchString(plan.TransactionID) || !packageNamePattern.MatchString(plan.PackageName) || plan.VersionCode < 1 || plan.VersionCode > 2_147_483_647 || !trackPattern.MatchString(plan.Track) || !playSHA256Pattern.MatchString(plan.ArtifactSHA256) || !playSHA256Pattern.MatchString(plan.MetadataSHA256) {
		return errors.New("invalid Play release plan identity or digest binding")
	}
	if plan.PromoteExistingVersion != (plan.SourceTrack != "") || (plan.SourceTrack != "" && (!trackPattern.MatchString(plan.SourceTrack) || plan.SourceTrack == plan.Track)) {
		return errors.New("invalid existing-version promotion plan")
	}
	return nil
}

type Transaction struct {
	mu         sync.Mutex
	client     *Client
	plan       Plan
	state      State
	editID     string
	haltReason string
}

type TransactionSnapshot struct {
	Schema     string `json:"schema"`
	Plan       Plan   `json:"plan"`
	State      State  `json:"state"`
	EditID     string `json:"editId,omitempty"`
	HaltReason string `json:"haltReason,omitempty"`
}

func NewTransaction(client *Client, plan Plan) (*Transaction, error) {
	if client == nil {
		return nil, errors.New("Play client is required")
	}
	if err := plan.validate(); err != nil {
		return nil, err
	}
	return &Transaction{client: client, plan: plan, state: StateNew}, nil
}

func ResumeTransaction(client *Client, snapshot TransactionSnapshot) (*Transaction, error) {
	if client == nil || snapshot.Schema != "kurdistan-play-release-transaction-v1" {
		return nil, errors.New("invalid Play release transaction snapshot")
	}
	if err := snapshot.Plan.validate(); err != nil {
		return nil, err
	}
	validState := map[State]bool{
		StateNew: true, StateEditCreated: true, StateArtifactUploaded: true,
		StateMetadataUploaded: true, StateTrackAssigned: true, StateCommitted: true,
		StateVerified: true, StateReconcileRequired: true, StateHalted: true,
	}
	if !validState[snapshot.State] {
		return nil, errors.New("invalid Play release transaction state")
	}
	if snapshot.State == StateNew {
		if snapshot.EditID != "" {
			return nil, errors.New("new transaction snapshot cannot contain an edit id")
		}
	} else if snapshot.EditID != "" && !remoteIDPattern.MatchString(snapshot.EditID) {
		return nil, errors.New("invalid transaction snapshot edit id")
	} else if snapshot.State != StateHalted && snapshot.EditID == "" {
		return nil, errors.New("active transaction snapshot is missing its edit id")
	}
	if (snapshot.State == StateHalted) != (snapshot.HaltReason != "") {
		return nil, errors.New("transaction snapshot halt state is inconsistent")
	}
	return &Transaction{client: client, plan: snapshot.Plan, state: snapshot.State, editID: snapshot.EditID, haltReason: snapshot.HaltReason}, nil
}

func (transaction *Transaction) Snapshot() TransactionSnapshot {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	return TransactionSnapshot{
		Schema: "kurdistan-play-release-transaction-v1", Plan: transaction.plan,
		State: transaction.state, EditID: transaction.editID, HaltReason: transaction.haltReason,
	}
}

func (transaction *Transaction) State() State {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	return transaction.state
}

func (transaction *Transaction) CreateEdit(ctx context.Context) error {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != StateNew {
		return transaction.invalidTransition("create edit")
	}
	var response struct {
		EditID string `json:"editId"`
	}
	path := "/applications/" + url.PathEscape(transaction.plan.PackageName) + "/edits"
	if err := transaction.client.do(ctx, http.MethodPost, path, nil, "application/json", transaction.plan.TransactionID+":create", &response); err != nil {
		return err
	}
	if !remoteIDPattern.MatchString(response.EditID) {
		return errors.New("remote edit id is invalid")
	}
	transaction.editID = response.EditID
	transaction.state = StateEditCreated
	return nil
}

func (transaction *Transaction) UploadArtifact(ctx context.Context, artifact []byte) error {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != StateEditCreated || transaction.plan.PromoteExistingVersion {
		return transaction.invalidTransition("upload artifact")
	}
	if len(artifact) == 0 || len(artifact) > maxArtifactBytes || fmt.Sprintf("%x", sha256.Sum256(artifact)) != transaction.plan.ArtifactSHA256 {
		return errors.New("artifact bytes do not match the bounded plan digest")
	}
	var response struct {
		VersionCode int64  `json:"versionCode"`
		SHA256      string `json:"sha256"`
	}
	path := transaction.editPath() + "/bundles"
	if err := transaction.client.do(ctx, http.MethodPost, path, artifact, "application/octet-stream", transaction.plan.TransactionID+":artifact", &response); err != nil {
		return err
	}
	if response.VersionCode != transaction.plan.VersionCode || response.SHA256 != transaction.plan.ArtifactSHA256 {
		return errors.New("remote artifact identity mismatch")
	}
	transaction.state = StateArtifactUploaded
	return nil
}

func (transaction *Transaction) UploadMetadata(ctx context.Context, metadata []byte) error {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != StateArtifactUploaded || transaction.plan.PromoteExistingVersion {
		return transaction.invalidTransition("upload metadata")
	}
	if len(metadata) == 0 || len(metadata) > maxMetadataBytes || fmt.Sprintf("%x", sha256.Sum256(metadata)) != transaction.plan.MetadataSHA256 {
		return errors.New("metadata bytes do not match the bounded plan digest")
	}
	var response struct {
		SHA256 string `json:"sha256"`
	}
	if err := transaction.client.do(ctx, http.MethodPut, transaction.editPath()+"/metadata", metadata, "application/json", transaction.plan.TransactionID+":metadata", &response); err != nil {
		return err
	}
	if response.SHA256 != transaction.plan.MetadataSHA256 {
		return errors.New("remote metadata identity mismatch")
	}
	transaction.state = StateMetadataUploaded
	return nil
}

func (transaction *Transaction) AssignTrack(ctx context.Context) error {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != StateMetadataUploaded || transaction.plan.PromoteExistingVersion {
		return transaction.invalidTransition("assign track")
	}
	body, _ := json.Marshal(struct {
		VersionCodes []int64 `json:"versionCodes"`
	}{VersionCodes: []int64{transaction.plan.VersionCode}})
	var response trackResponse
	path := transaction.editPath() + "/tracks/" + url.PathEscape(transaction.plan.Track)
	if err := transaction.client.do(ctx, http.MethodPut, path, body, "application/json", transaction.plan.TransactionID+":track", &response); err != nil {
		return err
	}
	if !response.matches(transaction.plan.Track, transaction.plan.VersionCode) {
		return errors.New("remote track assignment mismatch")
	}
	transaction.state = StateTrackAssigned
	return nil
}

func (transaction *Transaction) PromoteExistingVersion(ctx context.Context) error {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != StateEditCreated || !transaction.plan.PromoteExistingVersion {
		return transaction.invalidTransition("promote existing version")
	}
	body, _ := json.Marshal(struct {
		SourceTrack string `json:"sourceTrack"`
		TargetTrack string `json:"targetTrack"`
		VersionCode int64  `json:"versionCode"`
	}{SourceTrack: transaction.plan.SourceTrack, TargetTrack: transaction.plan.Track, VersionCode: transaction.plan.VersionCode})
	var response trackResponse
	if err := transaction.client.do(ctx, http.MethodPost, transaction.editPath()+"/promotions", body, "application/json", transaction.plan.TransactionID+":promote", &response); err != nil {
		return err
	}
	if !response.matches(transaction.plan.Track, transaction.plan.VersionCode) {
		return errors.New("remote existing-version promotion mismatch")
	}
	transaction.state = StateTrackAssigned
	return nil
}

func (transaction *Transaction) Commit(ctx context.Context) error {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != StateTrackAssigned {
		return transaction.invalidTransition("commit")
	}
	var response struct {
		Committed bool `json:"committed"`
	}
	if err := transaction.client.do(ctx, http.MethodPost, transaction.editPath()+":commit", nil, "application/json", transaction.plan.TransactionID+":commit", &response); err != nil {
		transaction.state = StateReconcileRequired
		return fmt.Errorf("commit outcome requires reconciliation: %w", err)
	}
	if !response.Committed {
		transaction.state = StateReconcileRequired
		return errors.New("commit outcome requires reconciliation")
	}
	transaction.state = StateCommitted
	return nil
}

func (transaction *Transaction) Readback(ctx context.Context) error {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != StateCommitted {
		return transaction.invalidTransition("readback")
	}
	return transaction.readbackLocked(ctx)
}

func (transaction *Transaction) Reconcile(ctx context.Context) error {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != StateReconcileRequired {
		return transaction.invalidTransition("reconcile")
	}
	var response struct {
		Committed bool `json:"committed"`
	}
	if err := transaction.client.do(ctx, http.MethodGet, transaction.editPath()+"/status", nil, "application/json", "", &response); err != nil {
		return fmt.Errorf("reconcile commit state: %w", err)
	}
	if !response.Committed {
		return errors.New("remote commit is not confirmed; automatic retry remains prohibited")
	}
	transaction.state = StateCommitted
	return transaction.readbackLocked(ctx)
}

func (transaction *Transaction) Halt(reason string) error {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if reason == "" || reason != strings.TrimSpace(reason) || len(reason) > 256 || strings.ContainsRune(reason, '\x00') {
		return errors.New("halt reason is invalid")
	}
	if transaction.state == StateReconcileRequired || transaction.state == StateCommitted || transaction.state == StateVerified || transaction.state == StateHalted {
		return transaction.invalidTransition("halt")
	}
	transaction.state = StateHalted
	transaction.haltReason = reason
	return nil
}

func (transaction *Transaction) readbackLocked(ctx context.Context) error {
	var response versionReadback
	path := "/applications/" + url.PathEscape(transaction.plan.PackageName) + "/tracks/" + url.PathEscape(transaction.plan.Track) + "/versions/" + strconv.FormatInt(transaction.plan.VersionCode, 10)
	if err := transaction.client.do(ctx, http.MethodGet, path, nil, "application/json", "", &response); err != nil {
		return err
	}
	if !response.matches(transaction.plan) {
		transaction.state = StateHalted
		transaction.haltReason = "remote readback mismatch"
		return errors.New(transaction.haltReason)
	}
	transaction.state = StateVerified
	return nil
}

func (transaction *Transaction) editPath() string {
	return "/applications/" + url.PathEscape(transaction.plan.PackageName) + "/edits/" + url.PathEscape(transaction.editID)
}

func (transaction *Transaction) invalidTransition(operation string) error {
	return fmt.Errorf("cannot %s from state %s", operation, transaction.state)
}

type trackResponse struct {
	Track        string  `json:"track"`
	VersionCodes []int64 `json:"versionCodes"`
}

func (response trackResponse) matches(track string, versionCode int64) bool {
	return response.Track == track && len(response.VersionCodes) == 1 && response.VersionCodes[0] == versionCode
}

type versionReadback struct {
	VersionCode    int64  `json:"versionCode"`
	Track          string `json:"track"`
	ArtifactSHA256 string `json:"artifactSha256"`
	MetadataSHA256 string `json:"metadataSha256"`
	Status         string `json:"status"`
}

func (response versionReadback) matches(plan Plan) bool {
	return response.VersionCode == plan.VersionCode && response.Track == plan.Track && response.ArtifactSHA256 == plan.ArtifactSHA256 && response.MetadataSHA256 == plan.MetadataSHA256 && response.Status == "COMPLETED"
}

func (client *Client) do(ctx context.Context, method, path string, body []byte, contentType, idempotencyKey string, output any) error {
	request, err := http.NewRequestWithContext(ctx, method, client.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Accept", "application/json")
	if idempotencyKey != "" {
		request.Header.Set("X-Idempotency-Key", idempotencyKey)
	}
	response, err := client.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxResponseBytes {
		return errors.New("remote response exceeds size bound")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("test API returned HTTP %d", response.StatusCode)
	}
	if err := rejectDuplicateResponseKeys(raw); err != nil {
		return fmt.Errorf("decode test API response: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode test API response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("test API response has trailing JSON")
	}
	return nil
}

func rejectDuplicateResponseKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanResponseJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func scanResponseJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if seen[key] {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = true
			if err := scanResponseJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object terminator")
		}
	case '[':
		for decoder.More() {
			if err := scanResponseJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array terminator")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func main() {
	fmt.Fprintln(os.Stderr, "playrelease: inactive loopback-only future tooling; no Play authority configured")
	os.Exit(2)
}
