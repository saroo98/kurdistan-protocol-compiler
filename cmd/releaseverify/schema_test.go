// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReleaseProductsSchemaTracksStrictOfflineContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "schemas", "release-products-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Dialect              string         `json:"$schema"`
		AdditionalProperties bool           `json:"additionalProperties"`
		Properties           map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.Dialect != "https://json-schema.org/draft/2020-12/schema" || schema.AdditionalProperties || schema.Properties["android"] == nil || schema.Properties["go"] == nil {
		t.Fatalf("release products schema does not track the strict parser: %+v", schema)
	}
	products, err := loadProducts(filepath.Join("testdata", "valid", "config", "release", "products.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProducts(products); err != nil {
		t.Fatalf("valid release products fixture disagrees with parser contract: %v", err)
	}
}
