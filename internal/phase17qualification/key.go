// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func GenerateAndWriteKeyPair(privatePath, publicPath string, random io.Reader) (resultErr error) {
	if privatePath == "" || publicPath == "" || samePath(privatePath, publicPath) || random == nil {
		return errors.New("qualification key paths rejected")
	}
	if err := prepareKeyParent(filepath.Dir(privatePath)); err != nil {
		return err
	}
	if err := prepareKeyParent(filepath.Dir(publicPath)); err != nil {
		return err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return err
	}
	defer Clear(privateKey)
	privateWritten := false
	defer func() {
		if resultErr != nil && privateWritten {
			_ = os.Remove(privatePath)
		}
	}()
	if err := writeExclusiveSynced(privatePath, privateKey, 0o600); err != nil {
		return err
	}
	privateWritten = true
	if err := writeExclusiveSynced(publicPath, publicKey, 0o644); err != nil {
		return err
	}
	if err := syncKeyDirectory(filepath.Dir(privatePath)); err != nil {
		return err
	}
	if !samePath(filepath.Dir(privatePath), filepath.Dir(publicPath)) {
		if err := syncKeyDirectory(filepath.Dir(publicPath)); err != nil {
			return err
		}
	}
	return nil
}

func LoadPrivateKey(path string) ([]byte, error) {
	raw, err := loadRegularKey(path, ed25519.PrivateKeySize)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" {
		info, err := os.Lstat(path)
		if err != nil {
			Clear(raw)
			return nil, err
		}
		if info.Mode().Perm() != 0o600 {
			Clear(raw)
			return nil, errors.New("qualification private key permissions rejected")
		}
	}
	return raw, nil
}

func LoadPublicKey(path string) ([]byte, error) {
	return loadRegularKey(path, ed25519.PublicKeySize)
}

func Clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}

func prepareKeyParent(directory string) error {
	if directory == "" {
		return errors.New("qualification key directory rejected")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	abs, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	if err := ValidateNoLinkedPath(abs); err != nil {
		return errors.New("qualification key directory contains a symbolic link")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(directory, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func writeExclusiveSynced(path string, raw []byte, mode os.FileMode) (resultErr error) {
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return errors.New("qualification key file already exists")
		}
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}

func loadRegularKey(path string, exactSize int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != exactSize {
		return nil, errors.New("qualification key file rejected")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != exactSize {
		Clear(raw)
		return nil, errors.New("qualification key size rejected")
	}
	return raw, nil
}

func syncKeyDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func samePath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	leftClean := filepath.Clean(leftAbs)
	rightClean := filepath.Clean(rightAbs)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(leftClean, rightClean)
	}
	return leftClean == rightClean
}
