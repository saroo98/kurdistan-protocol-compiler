// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

import (
	"encoding/json"
	"os"
	"path/filepath"

	"kurdistan/internal/proxyingress"
)

func HashValue(value any) string {
	return proxyingress.HashValue(value)
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
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	raw, err := StableJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}
