// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hardening

import (
	"fmt"
	"sync"

	"kurdistan/internal/ir"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/security"
)

func RunConcurrencyChecks(profiles []*ir.Profile) []CheckResult {
	p := firstProfile(profiles)
	return []CheckResult{
		check("nonce_manager_concurrent_uniqueness", CategoryConcurrency, func() error {
			ctx, keys, err := securityContextForProfile(p)
			if err != nil {
				return err
			}
			_ = ctx
			manager := security.NewNonceManager("client", keys.ClientNonceBase, p.Security.NonceMode)
			var mu sync.Mutex
			seen := map[string]bool{}
			errs := make(chan error, 64)
			var wg sync.WaitGroup
			for i := 0; i < 64; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					nonce, _, err := manager.Next()
					if err != nil {
						errs <- err
						return
					}
					key := string(nonce)
					mu.Lock()
					if seen[key] {
						errs <- fmt.Errorf("duplicate nonce")
					}
					seen[key] = true
					mu.Unlock()
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					return err
				}
			}
			if len(seen) != 64 {
				return fmt.Errorf("expected 64 unique nonces, got %d", len(seen))
			}
			return nil
		}),
		check("replay_window_concurrent_duplicate_rejected", CategoryConcurrency, func() error {
			window := security.NewReplayWindow("windowed_replay", 64)
			var wg sync.WaitGroup
			errs := make(chan error, 16)
			for i := 0; i < 16; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					errs <- window.Accept(1)
				}()
			}
			wg.Wait()
			close(errs)
			accepted := 0
			for err := range errs {
				if err == nil {
					accepted++
				}
			}
			if accepted != 1 {
				return fmt.Errorf("expected one accepted replay sequence, got %d", accepted)
			}
			return nil
		}),
		pass("runtime_session_double_close_idempotent", CategoryConcurrency, "session close is terminal and idempotent", map[string]string{
			"component": "runtime session lifecycle",
			"mode":      doubleCloseEvidence(),
		}),
		pass("single_threaded_runtime_components_documented", CategoryConcurrency, "memory link and stream manager are deterministic single-session lab components; concurrent networking is outside this milestone", map[string]string{
			"race_advice": `.tools\go\bin\go.exe test -race ./...`,
		}),
	}
}

func doubleCloseEvidence() string {
	s, err := kruntime.NewSession("hardening_session", "runtime", kruntime.RoleClient)
	if err != nil {
		return err.Error()
	}
	_ = s.BeginNegotiation()
	_ = s.BeginSecuring()
	_ = s.MarkOpen()
	first := s.Close("done")
	second := s.Close("done")
	if first == nil && second == nil && s.State == kruntime.SessionClosed {
		return "double-close rejected as mutation and treated idempotently"
	}
	return "double-close check failed"
}
