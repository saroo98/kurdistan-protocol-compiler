// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"path/filepath"
	"testing"
)

func TestVerifyAcceptsCanonicalOfflineMetadata(t *testing.T) {
	root := filepath.Join("testdata", "valid")
	if err := verify(root); err != nil {
		t.Fatalf("verify canonical metadata: %v", err)
	}
}

func TestVersionPropertiesRejectsDuplicateKeys(t *testing.T) {
	path := filepath.Join("testdata", "invalid", "duplicate-version.properties")
	if _, err := loadVersionProperties(path); err == nil {
		t.Fatal("duplicate version property passed")
	}
}

func TestVersionPropertiesRejectsUnknownKeys(t *testing.T) {
	path := filepath.Join("testdata", "invalid", "unknown-version.properties")
	if _, err := loadVersionProperties(path); err == nil {
		t.Fatal("unknown version property passed")
	}
}

func TestVersionPropertiesRejectsNonCanonicalWhitespace(t *testing.T) {
	path := filepath.Join("testdata", "invalid", "noncanonical-version.properties")
	if _, err := loadVersionProperties(path); err == nil {
		t.Fatal("non-canonical version property passed")
	}
}

func TestVersionPropertiesRejectsNonPositiveCode(t *testing.T) {
	path := filepath.Join("testdata", "invalid", "nonpositive-version-code.properties")
	if _, err := loadVersionProperties(path); err == nil {
		t.Fatal("non-positive versionCode passed")
	}
}

func TestVersionPropertiesRejectsInvalidVersionName(t *testing.T) {
	path := filepath.Join("testdata", "invalid", "invalid-version-name.properties")
	if _, err := loadVersionProperties(path); err == nil {
		t.Fatal("invalid versionName passed")
	}
}

func TestVersionPropertiesRejectsCodeOutsideGradleIntegerRange(t *testing.T) {
	path := filepath.Join("testdata", "invalid", "oversized-version-code.properties")
	if _, err := loadVersionProperties(path); err == nil {
		t.Fatal("versionCode outside the Gradle integer range passed")
	}
}

func TestVersionPropertiesRejectsNonCanonicalOrdering(t *testing.T) {
	path := filepath.Join("testdata", "invalid", "reordered-version.properties")
	if _, err := loadVersionProperties(path); err == nil {
		t.Fatal("non-canonical version property order passed")
	}
}

func TestProductsRejectUnknownFields(t *testing.T) {
	path := filepath.Join("testdata", "invalid", "unknown-products.json")
	if _, err := loadProducts(path); err == nil {
		t.Fatal("release products with an unknown field passed")
	}
}

func TestProductsRejectTrailingJSONValue(t *testing.T) {
	path := filepath.Join("testdata", "invalid", "trailing-products.json")
	if _, err := loadProducts(path); err == nil {
		t.Fatal("release products with a trailing JSON value passed")
	}
}

func TestProductsRejectDuplicateObjectKeys(t *testing.T) {
	path := filepath.Join("testdata", "invalid", "duplicate-products.json")
	if _, err := loadProducts(path); err == nil {
		t.Fatal("release products with a duplicate object key passed")
	}
}

func TestProductsRejectConfiguredPlayTestTrack(t *testing.T) {
	path := filepath.Join("testdata", "valid", "config", "release", "products.json")
	products, err := loadProducts(path)
	if err != nil {
		t.Fatal(err)
	}
	products.Android.Play.TestTrack = "internal"
	if err := validateProducts(products); err == nil {
		t.Fatal("configured Play test track passed the offline-only contract")
	}
}

func TestProductsRejectUndeclaredPublicGoProducts(t *testing.T) {
	path := filepath.Join("testdata", "valid", "config", "release", "products.json")
	products, err := loadProducts(path)
	if err != nil {
		t.Fatal(err)
	}
	products.Go.ApprovedCommands = []string{"kclient"}
	if err := validateProducts(products); err == nil {
		t.Fatal("unapproved public Go product passed")
	}
}

func TestProductsRejectUnexpectedAndroidIdentity(t *testing.T) {
	path := filepath.Join("testdata", "valid", "config", "release", "products.json")
	products, err := loadProducts(path)
	if err != nil {
		t.Fatal(err)
	}
	products.Android.InternalApplicationID = "org.example.internal"
	if err := validateProducts(products); err == nil {
		t.Fatal("unexpected Android application identity passed")
	}
}

func TestProductsRejectInvalidAndroidSDKRange(t *testing.T) {
	path := filepath.Join("testdata", "valid", "config", "release", "products.json")
	products, err := loadProducts(path)
	if err != nil {
		t.Fatal(err)
	}
	products.Android.TargetSDK = products.Android.MinSDK - 1
	if err := validateProducts(products); err == nil {
		t.Fatal("Android targetSdk below minSdk passed")
	}
}

func TestProductsRejectEmptyReleaseABIInventory(t *testing.T) {
	path := filepath.Join("testdata", "valid", "config", "release", "products.json")
	products, err := loadProducts(path)
	if err != nil {
		t.Fatal(err)
	}
	products.Android.ReleaseABIs = []string{}
	if err := validateProducts(products); err == nil {
		t.Fatal("empty Android release ABI inventory passed")
	}
}

func TestProductsRejectUnexpectedAndroidPublicationInventory(t *testing.T) {
	path := filepath.Join("testdata", "valid", "config", "release", "products.json")
	products, err := loadProducts(path)
	if err != nil {
		t.Fatal(err)
	}
	publishInspectionAPK := true
	products.Android.PublishInspectionAPK = &publishInspectionAPK
	if err := validateProducts(products); err == nil {
		t.Fatal("public inspection APK declaration passed")
	}
}

func TestProductsRejectMissingFalsePublicationFlag(t *testing.T) {
	path := filepath.Join("testdata", "invalid", "missing-inspection-apk-flag.json")
	products, err := loadProducts(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProducts(products); err == nil {
		t.Fatal("missing publishInspectionApk flag passed")
	}
}

func TestProductsRejectMissingProductionTrackIdentity(t *testing.T) {
	path := filepath.Join("testdata", "valid", "config", "release", "products.json")
	products, err := loadProducts(path)
	if err != nil {
		t.Fatal(err)
	}
	products.Android.Play.ProductionTrack = ""
	if err := validateProducts(products); err == nil {
		t.Fatal("missing Play production track identity passed")
	}
}

func TestGradleVersionWiringRejectsHardcodedVersions(t *testing.T) {
	root := filepath.Join("testdata", "hardcoded-gradle")
	version := versionProperties{Name: "0.9.0", Code: 1}
	productsPath := filepath.Join("testdata", "valid", "config", "release", "products.json")
	products, err := loadProducts(productsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyGradleWiring(root, version, products); err == nil {
		t.Fatal("hard-coded Gradle release versions passed")
	}
}

func TestGradleVersionWiringAcceptsCentralizedVersions(t *testing.T) {
	root := filepath.Join("testdata", "valid")
	version, err := loadVersionProperties(filepath.Join(root, filepath.FromSlash(versionPropertiesPath)))
	if err != nil {
		t.Fatal(err)
	}
	products, err := loadProducts(filepath.Join(root, filepath.FromSlash(productsPath)))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyGradleWiring(root, version, products); err != nil {
		t.Fatalf("verify centralized Gradle release version: %v", err)
	}
}

func TestVerifyRequiresAndroidGradleWiring(t *testing.T) {
	root := filepath.Join("testdata", "metadata-only")
	if err := verify(root); err == nil {
		t.Fatal("release metadata without Android Gradle wiring passed")
	}
}
