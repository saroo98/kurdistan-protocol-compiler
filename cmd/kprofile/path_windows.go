//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func rejectWindowsNetworkPath(path string) error {
	cleaned := strings.ReplaceAll(path, "/", "\\")
	volume := filepath.VolumeName(cleaned)
	if strings.HasPrefix(cleaned, "\\\\") || strings.HasPrefix(cleaned, "\\?\\") || strings.HasPrefix(cleaned, "\\.\\") || strings.HasPrefix(volume, "\\") || len(volume) != 2 || volume[1] != ':' {
		return errors.New("local drive path required")
	}
	return nil
}

func localPathRoot(path string) (string, error) {
	if !filepath.IsAbs(path) || rejectWindowsNetworkPath(path) != nil {
		return "", errors.New("absolute local path required")
	}
	volume := filepath.VolumeName(filepath.Clean(path))
	return volume + string(os.PathSeparator), nil
}
