// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateAndLoadQualificationKeyPairIsExclusiveAndPrivate(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "qualification")
	privatePath := filepath.Join(directory, "key.ed25519")
	publicPath := filepath.Join(directory, "key.ed25519.pub")
	random := bytes.NewReader(bytes.Repeat([]byte{0x42}, 128))
	if err := GenerateAndWriteKeyPair(privatePath, publicPath, random); err != nil {
		t.Fatal(err)
	}
	privateKey, err := LoadPrivateKey(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer Clear(privateKey)
	publicKey, err := LoadPublicKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateKey) != ed25519.PrivateKeySize || len(publicKey) != ed25519.PublicKeySize ||
		!bytes.Equal(privateKey[32:], publicKey) {
		t.Fatal("qualification key pair is inconsistent")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(privatePath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("private key permissions=%o", info.Mode().Perm())
		}
	}
	if err := GenerateAndWriteKeyPair(privatePath, publicPath, bytes.NewReader(bytes.Repeat([]byte{0x24}, 128))); err == nil {
		t.Fatal("existing qualification key pair was overwritten")
	}
}

func TestQualificationKeyLoadRejectsSymlinkAndWrongSize(t *testing.T) {
	directory := t.TempDir()
	shortPath := filepath.Join(directory, "short")
	if err := os.WriteFile(shortPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(shortPath); err == nil {
		t.Fatal("short private key accepted")
	}
	if _, err := LoadPublicKey(shortPath); err == nil {
		t.Fatal("short public key accepted")
	}
	linkPath := filepath.Join(directory, "link")
	if err := os.Symlink(shortPath, linkPath); err == nil {
		if _, err := LoadPrivateKey(linkPath); err == nil {
			t.Fatal("symlinked private key accepted")
		}
	}
}

func TestClearZeroesSecretBytes(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5a}, ed25519.PrivateKeySize)
	Clear(secret)
	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatal("qualification private bytes were not cleared")
	}
}
