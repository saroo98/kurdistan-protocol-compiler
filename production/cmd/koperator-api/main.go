// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/spanner"

	"kurdistan/production/internal/authn"
	"kurdistan/production/internal/authoritysource"
	"kurdistan/production/internal/authz"
	"kurdistan/production/internal/entitlements"
	"kurdistan/production/internal/kmsprovider"
	"kurdistan/production/internal/runtimeconfig"
	"kurdistan/production/internal/server"
	"kurdistan/production/internal/spannerstore"
)

func main() {
	if err := run(); err != nil {
		slog.Error("operator API stopped", "class", "startup-or-runtime-failure")
		os.Exit(1)
	}
}

func run() error {
	raw := []byte(os.Getenv("KURDISTAN_OPERATOR_CONFIG"))
	config, err := runtimeconfig.Parse(raw)
	clear(raw)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spannerClient, err := spanner.NewClient(ctx, config.SpannerDatabase)
	if err != nil {
		return err
	}
	defer spannerClient.Close()
	googleStore, err := spannerstore.NewGoogleClient(spannerClient)
	if err != nil {
		return err
	}
	store, err := spannerstore.New(googleStore, config.Environment)
	if err != nil {
		return err
	}
	replay, err := authn.NewSpannerReplayGuard(spannerClient, config.Environment, authn.SystemClock{}, config.TokenReplayTimeout())
	if err != nil {
		return err
	}
	entitlementRaw, err := config.Entitlements()
	if err != nil {
		return err
	}
	entitlementStore, err := entitlements.New(config.Environment, entitlementRaw)
	clear(entitlementRaw)
	if err != nil {
		return err
	}
	actorKey, err := config.ActorKey()
	if err != nil {
		return err
	}
	validator, err := authn.NewGoogleTokenValidator(http.DefaultClient)
	if err != nil {
		clear(actorKey)
		return err
	}
	authenticator, err := authn.New(authn.Config{
		Audience: config.IAPAudience, Issuers: config.Issuers, AuthorizedParties: config.AuthorizedParties,
		Environment: config.Environment, ActorKey: actorKey,
		PrivilegedMaximumAgeSeconds: config.PrivilegedMaximumAgeSeconds,
		Clock:                       authn.SystemClock{}, Replay: replay, Entitlements: entitlementStore,
	}, validator)
	clear(actorKey)
	if err != nil {
		return err
	}
	authorizer, err := authz.New(server.ProductionActionRoles())
	if err != nil {
		return err
	}
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return err
	}
	defer kmsClient.Close()
	rpc, err := kmsprovider.NewGoogleRPC(kmsClient)
	if err != nil {
		return err
	}
	catalog, err := config.Catalog()
	if err != nil {
		return err
	}
	provider, err := kmsprovider.New(rpc, catalog, config.KMSRequestTimeout())
	if err != nil {
		return err
	}
	authorityRPC, err := authoritysource.NewGoogleRPC(kmsClient)
	if err != nil {
		return err
	}
	protector, err := authoritysource.New(authorityRPC, config.AuthoritySourceKeyVersion, config.Environment, config.KMSRequestTimeout())
	if err != nil {
		return err
	}
	backend, err := server.NewProductionBackend(store, store, server.VerifiedSourceAdmitter{Verifier: provider}, protector)
	if err != nil {
		return err
	}
	limiter, err := server.NewMemoryRateLimiter(authn.SystemClock{}, 20, 500*time.Millisecond)
	if err != nil {
		return err
	}
	handler, err := server.NewHandler(authenticator, authorizer, backend, limiter)
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr: config.ListenAddress, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdown)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
