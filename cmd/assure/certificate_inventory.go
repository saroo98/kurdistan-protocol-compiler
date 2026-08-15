// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"kurdistan/internal/assurance"
)

type certifiedDeviceInventory struct {
	proofID     string
	requestedOS string
	receiptPath string
	bundlePath  string
}

func validateCertificateDeviceInventories(root, receiptsRoot, inventoriesRoot string, certificate assurance.Certificate) error {
	receiptDirectory, err := resolveRootDirectory(root, receiptsRoot)
	if err != nil {
		return fmt.Errorf("resolve receipt directory: %w", err)
	}
	required := map[string]certifiedDeviceInventory{}
	for _, api := range []int{26, 34, 36} {
		proofID := fmt.Sprintf("android-device-api%d", api)
		required[proofID] = certifiedDeviceInventory{
			proofID:     proofID,
			requestedOS: fmt.Sprintf("api-%d-x86_64", api),
			receiptPath: fmt.Sprintf(".tools/phase17/emulator-api%d-identity.json", api),
			bundlePath:  fmt.Sprintf("emulator-api%d-identity.json", api),
		}
	}

	seen := make(map[string]bool, len(required))
	declared := make([]candidateArtifact, 0, len(required))
	for _, reference := range certificate.Receipts {
		expected, ok := required[reference.ProofID]
		if !ok {
			continue
		}
		if seen[reference.ProofID] {
			return fmt.Errorf("duplicate certified device receipt %q", reference.ProofID)
		}
		raw, err := readRootFile(receiptDirectory, reference.Path)
		if err != nil {
			return fmt.Errorf("read certified device receipt %q: %w", reference.Path, err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(raw)) != reference.SHA256 {
			return fmt.Errorf("certified device receipt digest mismatch for %q", reference.Path)
		}
		receipt, err := assurance.DecodeReceipt(bytes.NewReader(raw))
		if err != nil {
			return fmt.Errorf("decode certified device receipt %q: %w", reference.Path, err)
		}
		if receipt.ReceiptID != reference.ReceiptID || receipt.Proof.ID != reference.ProofID || reference.OperatingSystem != "android-emulator" || receipt.Runner.OperatingSystem != "android-emulator" || receipt.Runner.RequestedLabel != expected.requestedOS {
			return fmt.Errorf("certified device receipt identity mismatch for %q", reference.Path)
		}
		var identity *assurance.Artifact
		for index := range receipt.Artifacts {
			if receipt.Artifacts[index].Path == expected.receiptPath {
				if identity != nil {
					return fmt.Errorf("certified device receipt %q repeats its identity artifact", reference.Path)
				}
				identity = &receipt.Artifacts[index]
			}
		}
		if identity == nil || identity.Size < 1 {
			return fmt.Errorf("certified device receipt %q is missing its identity artifact", reference.Path)
		}
		declared = append(declared, candidateArtifact{Path: expected.bundlePath, Size: identity.Size, SHA256: identity.SHA256})
		seen[reference.ProofID] = true
	}
	if len(seen) != len(required) {
		return errors.New("assurance certificate is missing a required device identity receipt")
	}
	if err := validateDeclaredArtifacts(root, inventoriesRoot, declared, true); err != nil {
		return fmt.Errorf("certified device inventory: %w", err)
	}
	return nil
}
