// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var errUnsupportedFilesystem = errors.New("unsupported filesystem")

type privateOutputRoot struct {
	path string
	root *os.Root
}

func (root *privateOutputRoot) Close() error {
	if root == nil || root.root == nil {
		return nil
	}
	return root.root.Close()
}

func openLocalParent(path string) (*os.Root, string, error) {
	anchor, err := localPathRoot(path)
	if err != nil {
		return nil, "", errUnsupportedFilesystem
	}
	cleaned := filepath.Clean(path)
	parentPath, leaf := filepath.Dir(cleaned), filepath.Base(cleaned)
	if leaf == "." || leaf == string(os.PathSeparator) {
		return nil, "", errUnsupportedFilesystem
	}
	relativeParent, err := filepath.Rel(anchor, parentPath)
	if err != nil || !filepath.IsLocal(relativeParent) {
		return nil, "", errUnsupportedFilesystem
	}
	root, err := os.OpenRoot(anchor)
	if err != nil {
		return nil, "", errUnsupportedFilesystem
	}
	if relativeParent == "." {
		return root, leaf, nil
	}
	current := root
	for _, component := range strings.Split(relativeParent, string(os.PathSeparator)) {
		before, statErr := current.Lstat(component)
		if statErr != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			_ = current.Close()
			return nil, "", errUnsupportedFilesystem
		}
		next, openErr := current.OpenRoot(component)
		if openErr != nil {
			_ = current.Close()
			return nil, "", errUnsupportedFilesystem
		}
		after, statErr := next.Stat(".")
		if statErr != nil || !after.IsDir() || !os.SameFile(before, after) {
			_ = next.Close()
			_ = current.Close()
			return nil, "", errUnsupportedFilesystem
		}
		if closeErr := current.Close(); closeErr != nil {
			_ = next.Close()
			return nil, "", errUnsupportedFilesystem
		}
		current = next
	}
	return current, leaf, nil
}

func readBoundedRequest(path string, maximum int) ([]byte, error) {
	if path == "" || maximum <= 0 {
		return nil, errRequestRejected
	}
	parent, leaf, err := openLocalParent(path)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	before, err := parent.Lstat(leaf)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > int64(maximum) {
		return nil, errRequestRejected
	}
	file, err := parent.OpenFile(leaf, os.O_RDONLY, 0)
	if err != nil {
		return nil, errRequestRejected
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, errRequestRejected
	}
	value, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(value) == 0 || len(value) > maximum {
		zero(value)
		return nil, errRequestRejected
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || int64(len(value)) != after.Size() {
		zero(value)
		return nil, errRequestRejected
	}
	return value, nil
}

// selfhostInvalidInput keeps path helpers independent from command parsing
// while preserving one stable CLI category.
func selfhostInvalidInput() error { return errCLIInvalidInput }
