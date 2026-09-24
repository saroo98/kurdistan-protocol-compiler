//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"context"
	"crypto/rand"
	"io"
	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/selfhost"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestTask7UpdateIssuerSignsBoundedPolicyWithoutChangingV1(t *testing.T) {
	for _, leaf := range []string{"task7-installed-v1", "task7-installed-update-v2", "task12-installed-proxy-v1"} {
		t.Run(leaf, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			request, private, err := enrollment.Generate(now, 24*time.Hour, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(private.RecipientPrivate)
			defer clear(private.ClientAuthSeed)
			wire, err := enrollment.EncodeRequestV1(request)
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(t.TempDir(), leaf)
			artifact, err := task7IssueForEnrollmentV1(dir, wire)
			if err != nil {
				t.Fatal("genuine issuance", err)
			}
			defer clear(artifact)
			_, verified, err := selfhost.VerifyLiveBundleForRecipient(artifact, now, 1, request, private)
			if err != nil {
				t.Fatal("genuine recipient verification", err)
			}
			policy, err := runtimepolicy.DecodeV3At(verified.Profile.Policy, now)
			if err != nil {
				t.Fatal(err)
			}
			if policy.Services == nil || policy.Services.Probes == nil || len(policy.Services.Probes.Targets) != 1 {
				t.Fatal("probe policy lost")
			}
			probe := policy.Services.Probes.Targets[0]
			if probe.ID != 1 || probe.Port != 443 || string(probe.Address) != string([]byte{8, 8, 8, 8}) {
				t.Fatal("probe changed")
			}
			update := policy.Services.Update
			proxy := policy.Services.Proxy
			if leaf == "task12-installed-proxy-v1" {
				if proxy == nil || len(proxy.AddressKinds) != 1 || proxy.AddressKinds[0] != 1 ||
					len(proxy.DestinationCIDRs) != 1 || proxy.DestinationCIDRs[0].PrefixLen != 32 ||
					string(proxy.DestinationCIDRs[0].Address) != string([]byte{8, 8, 8, 8}) ||
					len(proxy.DestinationPorts) != 1 || proxy.DestinationPorts[0].First != 443 || proxy.DestinationPorts[0].Last != 443 {
					t.Fatal("proxy fixture authority must be exact")
				}
			} else if proxy != nil {
				t.Fatal("historical proxy authority widened")
			}
			if leaf != "task7-installed-update-v2" {
				if update != nil {
					t.Fatal("v1 update authority widened")
				}
			} else if update == nil || update.URL != "https://updates.example/profile" || update.ProfileID != verified.Profile.ProfileID ||
				update.MaxArtifactBytes != 65536 || update.TimeoutMillis != 30000 || update.MinCheckIntervalSeconds != 60 {
				t.Fatal("signed update policy does not match bounded fixture")
			}
			if _, err = task7IssueForEnrollmentV1(dir, wire); err == nil {
				t.Fatal("fixture overwritten")
			}
			if leaf == "task12-installed-proxy-v1" {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				relay, err := task7StartRelayV1(ctx, dir)
				if err != nil {
					t.Fatal(err)
				}
				defer relay.close()
				client, err := net.DialTimeout("tcp", relay.target.Addr().String(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				client.SetDeadline(time.Now().Add(2 * time.Second))
				want := [16]byte{75, 49, 50}
				if _, err = client.Write(want[:]); err != nil {
					t.Fatal(err)
				}
				var got [16]byte
				if _, err = io.ReadFull(client, got[:]); err != nil || got != want {
					t.Fatal("bounded fixture echo failed", err)
				}
			}
		})
	}
}

func TestTask7RelayRejectsMissingAuthorityBeforeListening(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if relay, err := task7StartRelayV1(ctx, filepath.Join(t.TempDir(), "task7-installed-v1")); err == nil || relay != nil {
		t.Fatal("relay admitted missing authority")
	}
}

func TestTask7RelayModeRejectsCrossVersionAndPressureBeforeStart(t *testing.T) {
	base := t.TempDir()
	for _, c := range []struct {
		leaf        string
		mode, level int
		valid       bool
	}{
		{"task7-installed-v1", 0, 0, true}, {"task7-installed-v1", 0, 64, true},
		{"task7-installed-update-v2", 1, 0, true}, {"task7-installed-update-v2", 2, 0, true},
		{"task7-installed-v1", 1, 0, false}, {"task7-installed-v1", 2, 0, false},
		{"task7-installed-update-v2", 0, 0, false}, {"task7-installed-update-v2", 3, 0, false},
		{"task7-installed-update-v2", -1, 0, false}, {"task7-installed-update-v2", 1, 16, false},
		{"task7-installed-v1", 0, 1, false}, {"other", 0, 0, false},
	} {
		dir := filepath.Join(base, c.leaf)
		if task7RelayModeValidV1(dir, c.level, c.mode) != c.valid {
			t.Fatalf("mode boundary: %s/%d/%d", c.leaf, c.mode, c.level)
		}
		if !c.valid {
			if r, err := task7StartRelayModeV1(context.Background(), dir, c.mode); err == nil || r != nil {
				t.Fatal("invalid relay admitted")
			}
		}
	}
	if task7RelayModeValidV1("task7-installed-v1", 0, 0) {
		t.Fatal("relative directory accepted")
	}
}

func TestTask7RelayCancelJoinsUnacceptedLocalListener(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	request, private, err := enrollment.Generate(now, 24*time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private.RecipientPrivate)
	defer clear(private.ClientAuthSeed)
	wire, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "task7-installed-v1")
	artifact, err := task7IssueForEnrollmentV1(dir, wire)
	if err != nil {
		t.Fatal(err)
	}
	clear(artifact)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	relay, err := task7StartRelayV1(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if relay.accepted.Load() != 0 {
		t.Fatal("accept before client")
	}
	relay.close()
	select {
	case <-relay.done:
	case <-ctx.Done():
		t.Fatal("relay cleanup did not join")
	}
	if !relay.joined.Load() {
		t.Fatal("cleanup completion absent")
	}
}

func TestTask7IssuerRejectsInvalidEnrollmentWithoutCreatingAuthority(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "task7-installed-v1")
	if _, err := task7IssueForEnrollmentV1(dir, []byte{1}); err == nil {
		t.Fatal("bad public enrollment accepted")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("invalid request created fixture state")
	}
}

func TestTask7RelayCancellationJoinsBlockedPrefaceAndConcurrentClosers(t *testing.T) {
	request, private, err := enrollment.Generate(time.Now().UTC().Truncate(time.Second), 24*time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private.RecipientPrivate)
	defer clear(private.ClientAuthSeed)
	wire, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "task7-installed-v1")
	artifact, err := task7IssueForEnrollmentV1(dir, wire)
	if err != nil {
		t.Fatal(err)
	}
	clear(artifact)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	relay, err := task7StartRelayV1(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.close()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", task7RelayEndpointV1)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for relay.accepted.Load() != 1 && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatal("local acceptance not observed")
	}
	var closers sync.WaitGroup
	for i := 0; i < 3; i++ {
		closers.Go(relay.close)
	}
	closers.Wait()
	select {
	case <-relay.done:
	case <-ctx.Done():
		t.Fatal("blocked read cleanup did not join")
	}
	if !relay.joined.Load() || relay.targetAccepted.Load() != 0 {
		t.Fatal("unproven cleanup or target reached without authentication")
	}
}

func TestTask7RelayNetworkRejectsUnlistedAddressesAndResolution(t *testing.T) {
	network := task7RelayNetworkV1{endpoint: "127.0.0.1:1"}
	for _, address := range []string{"8.8.8.8:80", "1.1.1.1:443", "[::1]:443"} {
		conn, err := network.DialTCP(context.Background(), netip.MustParseAddrPort(address))
		if conn != nil || err == nil {
			t.Fatal("unlisted destination admitted")
		}
	}
	var out [16]netip.Addr
	if count, err := network.ResolveProxy(context.Background(), []byte("example.invalid"), &out); count != 0 || err == nil {
		t.Fatal("fixture DNS admitted")
	}
}

func TestTask7IssuerUsesRealRecipientAndRefusesOverwrite(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	request, private, err := enrollment.Generate(now, 24*time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private.RecipientPrivate)
	defer clear(private.ClientAuthSeed)
	wire, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "task7-installed-v1")
	artifact, err := task7IssueForEnrollmentV1(dir, wire)
	if err != nil || len(artifact) == 0 {
		t.Fatal("genuine issuance", err)
	}
	defer clear(artifact)
	snapshot, err := selfhost.OpenRelayRuntimeSnapshotV1(filepath.Join(dir, "node"), now)
	if err != nil {
		t.Fatal("genuine relay state", err)
	}
	snapshot.Close()
	if _, err = task7IssueForEnrollmentV1(dir, wire); err == nil {
		t.Fatal("existing fixture overwritten")
	}
}
