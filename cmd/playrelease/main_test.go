// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestTransactionCompletesExactCreateUploadMetadataTrackCommitReadback(t *testing.T) {
	artifact := []byte("signed-aab-fixture")
	metadata := []byte(`{"releaseNotes":"fixture"}`)
	plan := testPlan(artifact, metadata)
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls = append(calls, request.Method+" "+request.URL.Path)
		if request.Header.Get("Authorization") != "" {
			t.Error("credentials must never be attached")
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.Method + " " + request.URL.Path {
		case "POST /applications/org.kurdistanvpn.app/edits":
			io.WriteString(writer, `{"editId":"edit-123"}`)
		case "POST /applications/org.kurdistanvpn.app/edits/edit-123/bundles":
			body, _ := io.ReadAll(request.Body)
			if !reflect.DeepEqual(body, artifact) {
				t.Errorf("artifact body mismatch: %q", body)
			}
			fmt.Fprintf(writer, `{"versionCode":42,"sha256":%q}`, plan.ArtifactSHA256)
		case "PUT /applications/org.kurdistanvpn.app/edits/edit-123/metadata":
			body, _ := io.ReadAll(request.Body)
			if !reflect.DeepEqual(body, metadata) {
				t.Errorf("metadata body mismatch: %q", body)
			}
			fmt.Fprintf(writer, `{"sha256":%q}`, plan.MetadataSHA256)
		case "PUT /applications/org.kurdistanvpn.app/edits/edit-123/tracks/internal":
			io.WriteString(writer, `{"track":"internal","versionCodes":[42]}`)
		case "POST /applications/org.kurdistanvpn.app/edits/edit-123:commit":
			io.WriteString(writer, `{"committed":true}`)
		case "GET /applications/org.kurdistanvpn.app/tracks/internal/versions/42":
			fmt.Fprintf(writer, `{"versionCode":42,"track":"internal","artifactSha256":%q,"metadataSha256":%q,"status":"COMPLETED"}`, plan.ArtifactSHA256, plan.MetadataSHA256)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := NewTransaction(client, plan)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := transaction.CreateEdit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := transaction.UploadArtifact(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	if err := transaction.UploadMetadata(ctx, metadata); err != nil {
		t.Fatal(err)
	}
	if err := transaction.AssignTrack(ctx); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Readback(ctx); err != nil {
		t.Fatal(err)
	}
	if transaction.State() != StateVerified {
		t.Fatalf("state = %s", transaction.State())
	}
	wantCalls := []string{
		"POST /applications/org.kurdistanvpn.app/edits",
		"POST /applications/org.kurdistanvpn.app/edits/edit-123/bundles",
		"PUT /applications/org.kurdistanvpn.app/edits/edit-123/metadata",
		"PUT /applications/org.kurdistanvpn.app/edits/edit-123/tracks/internal",
		"POST /applications/org.kurdistanvpn.app/edits/edit-123:commit",
		"GET /applications/org.kurdistanvpn.app/tracks/internal/versions/42",
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %v, want %v", calls, wantCalls)
	}
}

func TestCommitFailureRequiresReadbackReconciliationWithoutRetry(t *testing.T) {
	artifact := []byte("signed-aab-fixture")
	metadata := []byte(`{"releaseNotes":"fixture"}`)
	plan := testPlan(artifact, metadata)
	commitCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.Method + " " + request.URL.Path {
		case "POST /applications/org.kurdistanvpn.app/edits":
			io.WriteString(writer, `{"editId":"edit-123"}`)
		case "POST /applications/org.kurdistanvpn.app/edits/edit-123/bundles":
			fmt.Fprintf(writer, `{"versionCode":42,"sha256":%q}`, plan.ArtifactSHA256)
		case "PUT /applications/org.kurdistanvpn.app/edits/edit-123/metadata":
			fmt.Fprintf(writer, `{"sha256":%q}`, plan.MetadataSHA256)
		case "PUT /applications/org.kurdistanvpn.app/edits/edit-123/tracks/internal":
			io.WriteString(writer, `{"track":"internal","versionCodes":[42]}`)
		case "POST /applications/org.kurdistanvpn.app/edits/edit-123:commit":
			commitCalls++
			http.Error(writer, "ambiguous", http.StatusInternalServerError)
		case "GET /applications/org.kurdistanvpn.app/edits/edit-123/status":
			io.WriteString(writer, `{"committed":true}`)
		case "GET /applications/org.kurdistanvpn.app/tracks/internal/versions/42":
			fmt.Fprintf(writer, `{"versionCode":42,"track":"internal","artifactSha256":%q,"metadataSha256":%q,"status":"COMPLETED"}`, plan.ArtifactSHA256, plan.MetadataSHA256)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := NewTransaction(client, plan)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := advanceToTrack(ctx, transaction, artifact, metadata); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(ctx); err == nil || transaction.State() != StateReconcileRequired {
		t.Fatalf("ambiguous commit err=%v state=%s", err, transaction.State())
	}
	resumed, err := ResumeTransaction(client, transaction.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if err := resumed.Commit(ctx); err == nil {
		t.Fatal("commit retry must be blocked pending reconciliation")
	}
	if err := resumed.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if resumed.State() != StateVerified || commitCalls != 1 {
		t.Fatalf("state=%s commitCalls=%d", resumed.State(), commitCalls)
	}
}

func TestTransactionPromotesExistingVersionWithoutUploadingNewBytes(t *testing.T) {
	plan := testPlan([]byte("existing-artifact"), []byte("existing-metadata"))
	plan.PromoteExistingVersion = true
	plan.SourceTrack = "internal"
	plan.Track = "production"
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls = append(calls, request.Method+" "+request.URL.Path)
		writer.Header().Set("Content-Type", "application/json")
		switch request.Method + " " + request.URL.Path {
		case "POST /applications/org.kurdistanvpn.app/edits":
			io.WriteString(writer, `{"editId":"edit-promote"}`)
		case "POST /applications/org.kurdistanvpn.app/edits/edit-promote/promotions":
			io.WriteString(writer, `{"track":"production","versionCodes":[42]}`)
		case "POST /applications/org.kurdistanvpn.app/edits/edit-promote:commit":
			io.WriteString(writer, `{"committed":true}`)
		case "GET /applications/org.kurdistanvpn.app/tracks/production/versions/42":
			fmt.Fprintf(writer, `{"versionCode":42,"track":"production","artifactSha256":%q,"metadataSha256":%q,"status":"COMPLETED"}`, plan.ArtifactSHA256, plan.MetadataSHA256)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := NewTransaction(client, plan)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := transaction.CreateEdit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := transaction.PromoteExistingVersion(ctx); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Readback(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"POST /applications/org.kurdistanvpn.app/edits",
		"POST /applications/org.kurdistanvpn.app/edits/edit-promote/promotions",
		"POST /applications/org.kurdistanvpn.app/edits/edit-promote:commit",
		"GET /applications/org.kurdistanvpn.app/tracks/production/versions/42",
	}
	if transaction.State() != StateVerified || !reflect.DeepEqual(calls, want) {
		t.Fatalf("state=%s calls=%v", transaction.State(), calls)
	}
}

func TestHaltIsLocalTerminalAndMakesNoRemoteRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		http.Error(writer, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := NewTransaction(client, testPlan([]byte("artifact"), []byte("metadata")))
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Halt("operator stopped inactive test transaction"); err != nil {
		t.Fatal(err)
	}
	if err := transaction.CreateEdit(context.Background()); err == nil {
		t.Fatal("halted transaction accepted a later mutation")
	}
	if transaction.State() != StateHalted || requests != 0 {
		t.Fatalf("state=%s requests=%d", transaction.State(), requests)
	}
}

func TestClientRejectsDuplicateRemoteJSONKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		io.WriteString(writer, `{"editId":"edit-123","editId":"edit-replayed"}`)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := NewTransaction(client, testPlan([]byte("artifact"), []byte("metadata")))
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.CreateEdit(context.Background()); err == nil {
		t.Fatal("expected duplicate remote JSON key rejection")
	}
	if transaction.State() != StateNew {
		t.Fatalf("state = %s", transaction.State())
	}
}

func TestClientRejectsNonLoopbackEndpointsWithoutCallingThem(t *testing.T) {
	if _, err := NewClient("https://androidpublisher.googleapis.com", http.DefaultClient); err == nil {
		t.Fatal("expected non-loopback endpoint rejection")
	}
}

func TestReadbackMismatchHaltsPromotion(t *testing.T) {
	artifact := []byte("signed-aab-fixture")
	metadata := []byte(`{"releaseNotes":"fixture"}`)
	plan := testPlan(artifact, metadata)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.Method + " " + request.URL.Path {
		case "POST /applications/org.kurdistanvpn.app/edits":
			io.WriteString(writer, `{"editId":"edit-123"}`)
		case "POST /applications/org.kurdistanvpn.app/edits/edit-123/bundles":
			fmt.Fprintf(writer, `{"versionCode":42,"sha256":%q}`, plan.ArtifactSHA256)
		case "PUT /applications/org.kurdistanvpn.app/edits/edit-123/metadata":
			fmt.Fprintf(writer, `{"sha256":%q}`, plan.MetadataSHA256)
		case "PUT /applications/org.kurdistanvpn.app/edits/edit-123/tracks/internal":
			io.WriteString(writer, `{"track":"internal","versionCodes":[42]}`)
		case "POST /applications/org.kurdistanvpn.app/edits/edit-123:commit":
			io.WriteString(writer, `{"committed":true}`)
		case "GET /applications/org.kurdistanvpn.app/tracks/internal/versions/42":
			fmt.Fprintf(writer, `{"versionCode":42,"track":"internal","artifactSha256":%q,"metadataSha256":%q,"status":"COMPLETED"}`, strings.Repeat("f", 64), plan.MetadataSHA256)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := NewTransaction(client, plan)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := advanceToTrack(ctx, transaction, artifact, metadata); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Readback(ctx); err == nil || transaction.State() != StateHalted {
		t.Fatalf("readback err=%v state=%s", err, transaction.State())
	}
}

func testPlan(artifact, metadata []byte) Plan {
	return Plan{
		Schema: "kurdistan-play-release-plan-v1", TransactionID: "release-42",
		PackageName: "org.kurdistanvpn.app", VersionCode: 42, Track: "internal",
		ArtifactSHA256: fmt.Sprintf("%x", sha256.Sum256(artifact)),
		MetadataSHA256: fmt.Sprintf("%x", sha256.Sum256(metadata)),
	}
}

func advanceToTrack(ctx context.Context, transaction *Transaction, artifact, metadata []byte) error {
	if err := transaction.CreateEdit(ctx); err != nil {
		return err
	}
	if err := transaction.UploadArtifact(ctx, artifact); err != nil {
		return err
	}
	if err := transaction.UploadMetadata(ctx, metadata); err != nil {
		return err
	}
	return transaction.AssignTrack(ctx)
}
