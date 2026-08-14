// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

type atomicFileOps struct {
	createTemp    func(string, string) (*os.File, error)
	publish       func(string, string) error
	remove        func(string) error
	syncDirectory func(string) error
}

func defaultAtomicFileOps() atomicFileOps {
	return atomicFileOps{
		createTemp: os.CreateTemp,
		publish:    os.Link,
		remove:     os.Remove,
		syncDirectory: func(directory string) error {
			if runtime.GOOS == "windows" {
				return nil
			}
			file, err := os.Open(directory)
			if err != nil {
				return err
			}
			syncErr := file.Sync()
			closeErr := file.Close()
			return errors.Join(syncErr, closeErr)
		},
	}
}

// WriteExclusiveFile publishes complete, file-synchronized bytes without ever
// exposing a partially written target and without replacing an existing path.
func WriteExclusiveFile(path string, raw []byte) error {
	return writeExclusiveFileWithOps(path, filepath.Dir(path), raw, defaultAtomicFileOps())
}

func writeExclusiveFileWithOps(path, stagingDirectory string, raw []byte, ops atomicFileOps) (resultErr error) {
	if path == "" || stagingDirectory == "" || len(raw) == 0 || ops.createTemp == nil || ops.publish == nil ||
		ops.remove == nil || ops.syncDirectory == nil {
		return errors.New("qualification exclusive publication rejected")
	}
	targetDirectory := filepath.Dir(path)
	if err := os.MkdirAll(targetDirectory, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(stagingDirectory, 0o700); err != nil {
		return err
	}
	file, err := ops.createTemp(stagingDirectory, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := file.Name()
	removeTemporary := true
	committed := false
	defer func() {
		_ = file.Close()
		if removeTemporary {
			removeErr := ops.remove(temporaryPath)
			if !committed && !errors.Is(removeErr, os.ErrNotExist) {
				resultErr = errors.Join(resultErr, removeErr)
			}
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	written, err := io.Copy(file, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if written != int64(len(raw)) {
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := ops.publish(temporaryPath, path); err != nil {
		return err
	}
	if err := ops.syncDirectory(targetDirectory); err != nil {
		removeErr := ops.remove(path)
		if !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
		if syncErr := ops.syncDirectory(targetDirectory); syncErr != nil {
			err = errors.Join(err, syncErr)
		}
		return err
	}
	committed = true
	if err := ops.remove(temporaryPath); err == nil || errors.Is(err, os.ErrNotExist) {
		removeTemporary = false
	}
	_ = ops.syncDirectory(stagingDirectory)
	return nil
}
