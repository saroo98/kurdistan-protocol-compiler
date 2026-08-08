// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package androidartifact provides bounded, deterministic inspection of Android
// build artifacts. It does not execute APK contents.
package androidartifact

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Limits bounds decompressed APK data inspected by ReadAPK.
type Limits struct {
	MaxEntryBytes int64
	MaxTotalBytes int64
}

// APK is a bounded in-memory index of one APK.
type APK struct {
	all     [][]byte
	dex     [][]byte
	natives map[string][]byte
	entries map[string]struct{}
}

// ReadAPK reads one APK without executing it and rejects unsafe entry names,
// duplicate entries, and decompression beyond the supplied limits.
func ReadAPK(filePath string, limits Limits) (APK, error) {
	if limits.MaxEntryBytes <= 0 || limits.MaxTotalBytes <= 0 || limits.MaxEntryBytes > limits.MaxTotalBytes {
		return APK{}, fmt.Errorf("invalid APK inspection limits")
	}
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return APK{}, err
	}
	defer reader.Close()
	result := APK{
		natives: make(map[string][]byte),
		entries: make(map[string]struct{}),
	}
	var total int64
	for _, entry := range reader.File {
		if err := validateEntryName(entry.Name); err != nil {
			return APK{}, err
		}
		if _, exists := result.entries[entry.Name]; exists {
			return APK{}, fmt.Errorf("duplicate APK entry %q", entry.Name)
		}
		result.entries[entry.Name] = struct{}{}
		if entry.UncompressedSize64 > uint64(limits.MaxEntryBytes) {
			return APK{}, fmt.Errorf("entry %q exceeds inspection bound", entry.Name)
		}
		stream, err := entry.Open()
		if err != nil {
			return APK{}, err
		}
		content, readErr := io.ReadAll(io.LimitReader(stream, limits.MaxEntryBytes+1))
		closeErr := stream.Close()
		if readErr != nil {
			return APK{}, readErr
		}
		if closeErr != nil {
			return APK{}, closeErr
		}
		if int64(len(content)) > limits.MaxEntryBytes {
			return APK{}, fmt.Errorf("entry %q exceeds inspection bound", entry.Name)
		}
		total += int64(len(content))
		if total > limits.MaxTotalBytes {
			return APK{}, fmt.Errorf("APK contents exceed total inspection bound")
		}
		result.all = append(result.all, content)
		if strings.HasPrefix(entry.Name, "classes") && strings.HasSuffix(entry.Name, ".dex") {
			result.dex = append(result.dex, content)
		}
		if strings.HasPrefix(entry.Name, "lib/") && strings.HasSuffix(entry.Name, ".so") {
			result.natives[entry.Name] = content
		}
	}
	return result, nil
}

func validateEntryName(name string) error {
	if name == "" || strings.Contains(name, `\`) || strings.HasPrefix(name, "/") || path.Clean(name) != name {
		return fmt.Errorf("unsafe APK entry %q", name)
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == ".." {
			return fmt.Errorf("unsafe APK entry %q", name)
		}
	}
	return nil
}

// Contains reports whether any inspected entry contains marker.
func (a APK) Contains(marker string) bool {
	return contains(a.all, marker)
}

// DEXContains reports whether any DEX entry contains marker.
func (a APK) DEXContains(marker string) bool {
	return contains(a.dex, marker)
}

// AllContents returns defensive copies of all inspected entry contents.
func (a APK) AllContents() [][]byte {
	return cloneContents(a.all)
}

// DEXContents returns defensive copies of all inspected DEX contents.
func (a APK) DEXContents() [][]byte {
	return cloneContents(a.dex)
}

func cloneContents(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index, value := range values {
		result[index] = append([]byte(nil), value...)
	}
	return result
}

func contains(values [][]byte, marker string) bool {
	needle := []byte(marker)
	for _, value := range values {
		if bytes.Contains(value, needle) {
			return true
		}
	}
	return false
}

// Native returns a defensive copy of one native library.
func (a APK) Native(name string) ([]byte, bool) {
	value, ok := a.natives[name]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), value...), true
}

// EntryNames returns the canonical sorted APK entry inventory.
func (a APK) EntryNames() []string {
	result := make([]string, 0, len(a.entries))
	for name := range a.entries {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

// Manifest describes the security-relevant surface of one merged manifest.
type Manifest struct {
	Permissions          []string
	UsesCleartextTraffic *bool
	AllowBackup          *bool
	Services             []Service
}

// Service is the bounded security-relevant service declaration.
type Service struct {
	Name                  string
	Permission            string
	Exported              bool
	Process               string
	ForegroundServiceType string
}

type xmlManifest struct {
	Permissions []xmlPermission `xml:"uses-permission"`
	Application xmlApplication  `xml:"application"`
}

type xmlPermission struct {
	Name string `xml:"name,attr"`
}

type xmlApplication struct {
	UsesCleartextTraffic string       `xml:"usesCleartextTraffic,attr"`
	AllowBackup          string       `xml:"allowBackup,attr"`
	Services             []xmlService `xml:"service"`
}

type xmlService struct {
	Name                  string `xml:"name,attr"`
	Permission            string `xml:"permission,attr"`
	Exported              string `xml:"exported,attr"`
	Process               string `xml:"process,attr"`
	ForegroundServiceType string `xml:"foregroundServiceType,attr"`
}

// ParseManifest parses a text merged Android manifest into a canonical surface.
func ParseManifest(raw []byte) (Manifest, error) {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.Strict = true
	var parsed xmlManifest
	if err := decoder.Decode(&parsed); err != nil {
		return Manifest{}, err
	}
	result := Manifest{}
	seenPermissions := make(map[string]struct{}, len(parsed.Permissions))
	for _, permission := range parsed.Permissions {
		if permission.Name == "" {
			return Manifest{}, fmt.Errorf("manifest contains unnamed permission")
		}
		if _, exists := seenPermissions[permission.Name]; exists {
			return Manifest{}, fmt.Errorf("manifest contains duplicate permission %q", permission.Name)
		}
		seenPermissions[permission.Name] = struct{}{}
		result.Permissions = append(result.Permissions, permission.Name)
	}
	sort.Strings(result.Permissions)
	var err error
	if result.UsesCleartextTraffic, err = parseOptionalBool(parsed.Application.UsesCleartextTraffic); err != nil {
		return Manifest{}, fmt.Errorf("usesCleartextTraffic: %w", err)
	}
	if result.AllowBackup, err = parseOptionalBool(parsed.Application.AllowBackup); err != nil {
		return Manifest{}, fmt.Errorf("allowBackup: %w", err)
	}
	for _, service := range parsed.Application.Services {
		exported, err := parseRequiredBool(service.Exported)
		if err != nil {
			return Manifest{}, fmt.Errorf("service %q exported: %w", service.Name, err)
		}
		result.Services = append(result.Services, Service{
			Name:                  service.Name,
			Permission:            service.Permission,
			Exported:              exported,
			Process:               service.Process,
			ForegroundServiceType: service.ForegroundServiceType,
		})
	}
	sort.Slice(result.Services, func(i, j int) bool { return result.Services[i].Name < result.Services[j].Name })
	return result, nil
}

// ReadManifest reads and parses one merged text manifest.
func ReadManifest(filePath string) (Manifest, error) {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return Manifest{}, err
	}
	return ParseManifest(raw)
}

func parseOptionalBool(value string) (*bool, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return nil, fmt.Errorf("invalid boolean %q", value)
	}
	return &parsed, nil
}

func parseRequiredBool(value string) (bool, error) {
	if value == "" {
		return false, fmt.Errorf("missing boolean")
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("invalid boolean %q", value)
	}
	return parsed, nil
}
