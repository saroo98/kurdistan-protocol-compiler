// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingress

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

func HashValue(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func safeHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func ContractHash(contract ProxyIngressContract) string {
	contract.ContractHash = ""
	return HashValue(contract)
}

func StableJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func WriteJSON(path string, value any, force bool) error {
	if path == "" {
		return nil
	}
	if !force {
		if _, err := os.Stat(path); err == nil {
			return ErrRefuseOverwrite
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := StableJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}
