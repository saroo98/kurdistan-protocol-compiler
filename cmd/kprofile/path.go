// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"errors"
	"os"
	"path/filepath"
)

// openLocalParent returns an open handle to path's parent and its final path
// element. It reaches that parent one component at a time from the filesystem
// root, so os.Root's no-follow implementation binds all later operations to
// the opened directory rather than to the original pathname.
func openLocalParent(path string) (*os.Root, string, error) {
	anchor, err := localPathRoot(path)
	if err != nil {
		return nil, "", err
	}
	cleaned := filepath.Clean(path)
	parentPath := filepath.Dir(cleaned)
	leaf := filepath.Base(cleaned)
	if leaf == "." || leaf == string(os.PathSeparator) {
		return nil, "", errors.New("regular file path required")
	}
	relativeParent, err := filepath.Rel(anchor, parentPath)
	if err != nil || !filepath.IsLocal(relativeParent) {
		return nil, "", errors.New("local path required")
	}
	root, err := os.OpenRoot(anchor)
	if err != nil {
		return nil, "", err
	}
	if relativeParent == "." {
		return root, leaf, nil
	}
	parent, err := root.OpenRoot(relativeParent)
	closeErr := root.Close()
	if err != nil {
		return nil, "", err
	}
	if closeErr != nil {
		_ = parent.Close()
		return nil, "", closeErr
	}
	return parent, leaf, nil
}
