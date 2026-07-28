// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type androidResources struct {
	Strings []struct {
		Name string `xml:"name,attr"`
	} `xml:"string"`
	Plurals []struct {
		Name string `xml:"name,attr"`
	} `xml:"plurals"`
}

func TestPhase9LocalesHaveExactResourceParity(t *testing.T) {
	root := filepath.Join("..", "..", "android", "core", "ui", "src", "main", "res")
	locales := []string{"values", "values-ckb", "values-b+ku+Latn", "values-fa", "values-ar"}
	var expected []string
	for index, locale := range locales {
		data, err := os.ReadFile(filepath.Join(root, locale, "strings.xml"))
		if err != nil {
			t.Fatal(err)
		}
		var resources androidResources
		if err := xml.Unmarshal(data, &resources); err != nil {
			t.Fatalf("%s: %v", locale, err)
		}
		var names []string
		for _, value := range resources.Strings {
			names = append(names, "string:"+value.Name)
		}
		for _, value := range resources.Plurals {
			names = append(names, "plurals:"+value.Name)
		}
		sort.Strings(names)
		if index == 0 {
			expected = names
			continue
		}
		if strings.Join(names, "\n") != strings.Join(expected, "\n") {
			t.Fatalf("%s resource keys differ from the base locale", locale)
		}
	}
}

func TestPhase9LocaleConfigurationIncludesRequiredLocales(t *testing.T) {
	path := filepath.Join(
		"..", "..", "android", "app", "src", "main", "res", "xml", "locales_config.xml",
	)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, locale := range []string{"en", "ckb", "ku-Latn", "fa", "ar"} {
		if !strings.Contains(string(data), `android:name="`+locale+`"`) {
			t.Errorf("locale configuration is missing %s", locale)
		}
	}
}
