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
	if !validAPKLimits(limits) {
		return APK{}, fmt.Errorf("invalid APK inspection limits")
	}
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return APK{}, err
	}
	defer reader.Close()
	return inspectAPK(&reader.Reader, limits)
}

// ParseAPK inspects an independently copied archive without creating files or
// executing its contents. It shares the production inspection path with ReadAPK.
func ParseAPK(raw []byte, limits Limits) (APK, error) {
	if !validAPKLimits(limits) {
		return APK{}, fmt.Errorf("invalid APK inspection limits")
	}
	snapshot := bytes.Clone(raw)
	reader, err := zip.NewReader(bytes.NewReader(snapshot), int64(len(snapshot)))
	if err != nil {
		return APK{}, err
	}
	return inspectAPK(reader, limits)
}

func validAPKLimits(limits Limits) bool {
	return limits.MaxEntryBytes > 0 && limits.MaxEntryBytes < int64(^uint64(0)>>1) && limits.MaxTotalBytes > 0 && limits.MaxEntryBytes <= limits.MaxTotalBytes
}

func inspectAPK(reader *zip.Reader, limits Limits) (APK, error) {
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
		if int64(len(content)) > limits.MaxTotalBytes-total {
			return APK{}, fmt.Errorf("APK contents exceed total inspection bound")
		}
		total += int64(len(content))
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
	PackageName                     string
	ApplicationProcess              string
	ApplicationPermission           string
	ApplicationDirectBootAware      *bool
	ApplicationEnabled              *bool
	DefaultToDeviceProtectedStorage *bool
	Permissions                     []string
	UsesCleartextTraffic            *bool
	AllowBackup                     *bool
	Services                        []Service
}

// Service is the bounded security-relevant service declaration.
type Service struct {
	Name                  string
	Permission            string
	Exported              bool
	Process               string
	ForegroundServiceType string
	SupportsAlwaysOn      *bool
	DirectBootAware       *bool
	Enabled               *bool
	IsolatedProcess       *bool
	ExternalService       *bool
	StopWithTask          *bool
	PermissionDeclared    bool
	ProcessDeclared       bool
	IntentFilterCount     int
	IntentActions         []string
	IntentCategories      []string
	IntentDataCount       int
	SpecialUseSubtype     string
}

type xmlManifest struct {
	XMLName     xml.Name        `xml:"manifest"`
	PackageName string          `xml:"package,attr"`
	Permissions []xmlPermission `xml:"uses-permission"`
	Application xmlApplication  `xml:"application"`
}

type xmlPermission struct {
	Name string `xml:"http://schemas.android.com/apk/res/android name,attr"`
}

type xmlApplication struct {
	UsesCleartextTraffic            string       `xml:"http://schemas.android.com/apk/res/android usesCleartextTraffic,attr"`
	AllowBackup                     string       `xml:"http://schemas.android.com/apk/res/android allowBackup,attr"`
	Process                         string       `xml:"http://schemas.android.com/apk/res/android process,attr"`
	Permission                      string       `xml:"http://schemas.android.com/apk/res/android permission,attr"`
	DirectBootAware                 string       `xml:"http://schemas.android.com/apk/res/android directBootAware,attr"`
	Enabled                         string       `xml:"http://schemas.android.com/apk/res/android enabled,attr"`
	DefaultToDeviceProtectedStorage string       `xml:"http://schemas.android.com/apk/res/android defaultToDeviceProtectedStorage,attr"`
	Services                        []xmlService `xml:"service"`
}

type xmlService struct {
	Name                  string            `xml:"http://schemas.android.com/apk/res/android name,attr"`
	Permission            *string           `xml:"http://schemas.android.com/apk/res/android permission,attr"`
	Exported              string            `xml:"http://schemas.android.com/apk/res/android exported,attr"`
	Process               *string           `xml:"http://schemas.android.com/apk/res/android process,attr"`
	ForegroundServiceType string            `xml:"http://schemas.android.com/apk/res/android foregroundServiceType,attr"`
	DirectBootAware       string            `xml:"http://schemas.android.com/apk/res/android directBootAware,attr"`
	Enabled               string            `xml:"http://schemas.android.com/apk/res/android enabled,attr"`
	IsolatedProcess       string            `xml:"http://schemas.android.com/apk/res/android isolatedProcess,attr"`
	ExternalService       string            `xml:"http://schemas.android.com/apk/res/android externalService,attr"`
	StopWithTask          string            `xml:"http://schemas.android.com/apk/res/android stopWithTask,attr"`
	MetaData              []xmlMetaData     `xml:"meta-data"`
	Properties            []xmlMetaData     `xml:"property"`
	IntentFilters         []xmlIntentFilter `xml:"intent-filter"`
}

type xmlMetaData struct {
	Name     string `xml:"http://schemas.android.com/apk/res/android name,attr"`
	Value    string `xml:"http://schemas.android.com/apk/res/android value,attr"`
	Resource string `xml:"http://schemas.android.com/apk/res/android resource,attr"`
}

type xmlIntentFilter struct {
	Actions    []xmlPermission `xml:"action"`
	Categories []xmlPermission `xml:"category"`
	Data       []struct{}      `xml:"data"`
}

const maxManifestBytes = 1 << 20
const androidManifestNamespace = "http://schemas.android.com/apk/res/android"

// Reject ambiguous XML before struct decoding can ignore an extra root, select
// a duplicate declaration, or match a security attribute by local name alone.
func validateManifestXML(raw []byte) error {
	if len(raw) == 0 || len(raw) > maxManifestBytes {
		return fmt.Errorf("manifest length outside bound")
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.Strict = true
	var stack []string
	rootSeen, applications, nodes := false, 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case xml.StartElement:
			nodes++
			if nodes > 65536 || len(stack) >= 32 || len(value.Attr) > 64 || value.Name.Space != "" {
				return fmt.Errorf("manifest XML shape outside bound")
			}
			parent := ""
			if len(stack) == 0 {
				if rootSeen || value.Name.Local != "manifest" {
					return fmt.Errorf("manifest must have exactly one manifest root")
				}
				rootSeen = true
			} else {
				parent = stack[len(stack)-1]
			}
			if value.Name.Local == "manifest" && len(stack) != 0 {
				return fmt.Errorf("nested manifest root")
			}
			if value.Name.Local == "application" {
				applications++
				if parent != "manifest" || applications != 1 {
					return fmt.Errorf("manifest must have exactly one application")
				}
			}
			if value.Name.Local == "service" && parent != "application" {
				return fmt.Errorf("service outside application")
			}
			seen := make(map[xml.Name]bool, len(value.Attr))
			for _, attr := range value.Attr {
				if seen[attr.Name] {
					return fmt.Errorf("duplicate XML attribute %q", attr.Name.Local)
				}
				seen[attr.Name] = true
				if manifestSecurityAttribute(value.Name.Local, attr.Name.Local) && attr.Name.Space != androidManifestNamespace {
					return fmt.Errorf("security attribute %q has wrong namespace", attr.Name.Local)
				}
			}
			stack = append(stack, value.Name.Local)
		case xml.EndElement:
			if len(stack) == 0 {
				return fmt.Errorf("unbalanced manifest")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if strings.TrimSpace(string(value)) != "" {
				return fmt.Errorf("unexpected manifest text")
			}
		case xml.Directive:
			return fmt.Errorf("manifest directives are forbidden")
		case xml.ProcInst:
			if value.Target != "xml" || rootSeen {
				return fmt.Errorf("unexpected manifest processing instruction")
			}
		}
	}
	if !rootSeen || applications != 1 || len(stack) != 0 {
		return fmt.Errorf("incomplete manifest")
	}
	return nil
}

func manifestSecurityAttribute(element, attribute string) bool {
	switch element {
	case "uses-permission", "action", "category":
		return attribute == "name"
	case "meta-data", "property":
		return attribute == "name" || attribute == "value" || attribute == "resource"
	case "service", "application":
		switch attribute {
		case "name", "process", "permission", "exported", "directBootAware", "enabled", "isolatedProcess", "externalService", "stopWithTask", "foregroundServiceType", "usesCleartextTraffic", "allowBackup", "defaultToDeviceProtectedStorage":
			return true
		}
	}
	return false
}

// ParseManifest parses a text merged Android manifest into a canonical surface.
func ParseManifest(raw []byte) (Manifest, error) {
	if len(raw) == 0 || len(raw) > maxManifestBytes {
		return Manifest{}, fmt.Errorf("manifest length outside bound")
	}
	// Both parsing passes inspect the same owned snapshot. A caller cannot alter
	// a declaration after preflight by retaining its original input buffer.
	snapshot := bytes.Clone(raw)
	if err := validateManifestXML(snapshot); err != nil {
		return Manifest{}, err
	}
	decoder := xml.NewDecoder(bytes.NewReader(snapshot))
	decoder.Strict = true
	var parsed xmlManifest
	if err := decoder.Decode(&parsed); err != nil {
		return Manifest{}, err
	}
	result := Manifest{PackageName: parsed.PackageName, ApplicationProcess: parsed.Application.Process, ApplicationPermission: parsed.Application.Permission}
	if len(parsed.Permissions) > 256 || len(parsed.Application.Services) > 256 {
		return Manifest{}, fmt.Errorf("manifest declarations exceed bound")
	}
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
	for _, field := range []struct {
		name, raw string
		target    **bool
	}{
		{"application directBootAware", parsed.Application.DirectBootAware, &result.ApplicationDirectBootAware},
		{"application enabled", parsed.Application.Enabled, &result.ApplicationEnabled},
		{"application defaultToDeviceProtectedStorage", parsed.Application.DefaultToDeviceProtectedStorage, &result.DefaultToDeviceProtectedStorage},
	} {
		if *field.target, err = parseOptionalBool(field.raw); err != nil {
			return Manifest{}, fmt.Errorf("%s: %w", field.name, err)
		}
	}
	seenServices := make(map[string]bool, len(parsed.Application.Services))
	for _, service := range parsed.Application.Services {
		if service.Name == "" || strings.TrimSpace(service.Name) != service.Name || len(service.Name) > 512 || seenServices[service.Name] {
			return Manifest{}, fmt.Errorf("missing, invalid or duplicate service name %q", service.Name)
		}
		seenServices[service.Name] = true
		exported, err := parseRequiredBool(service.Exported)
		if err != nil {
			return Manifest{}, fmt.Errorf("service %q exported: %w", service.Name, err)
		}
		var supportsAlwaysOn *bool
		seenSupportsAlwaysOn := false
		for _, metadata := range service.MetaData {
			if metadata.Name == "android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" {
				return Manifest{}, fmt.Errorf("specialUse subtype must be a property")
			}
			if metadata.Name != "android.net.VpnService.SUPPORTS_ALWAYS_ON" {
				continue
			}
			if seenSupportsAlwaysOn {
				return Manifest{}, fmt.Errorf("service %q contains duplicate always-on metadata", service.Name)
			}
			seenSupportsAlwaysOn = true
			supportsAlwaysOn, err = parseOptionalBool(metadata.Value)
			if err != nil {
				return Manifest{}, fmt.Errorf("service %q always-on metadata: %w", service.Name, err)
			}
			if supportsAlwaysOn == nil || metadata.Resource != "" {
				return Manifest{}, fmt.Errorf("service %q always-on metadata is missing a value", service.Name)
			}
		}
		item := Service{
			Name:                  service.Name,
			Exported:              exported,
			ForegroundServiceType: service.ForegroundServiceType,
			SupportsAlwaysOn:      supportsAlwaysOn,
			PermissionDeclared:    service.Permission != nil, ProcessDeclared: service.Process != nil,
			IntentFilterCount: len(service.IntentFilters),
		}
		if service.Permission != nil {
			item.Permission = *service.Permission
		}
		if service.Process != nil {
			item.Process = *service.Process
		}
		for _, field := range []struct {
			name, raw string
			target    **bool
		}{
			{"directBootAware", service.DirectBootAware, &item.DirectBootAware},
			{"enabled", service.Enabled, &item.Enabled},
			{"isolatedProcess", service.IsolatedProcess, &item.IsolatedProcess},
			{"externalService", service.ExternalService, &item.ExternalService},
			{"stopWithTask", service.StopWithTask, &item.StopWithTask},
		} {
			if *field.target, err = parseOptionalBool(field.raw); err != nil {
				return Manifest{}, fmt.Errorf("service %q %s: %w", service.Name, field.name, err)
			}
		}
		for _, property := range service.Properties {
			if property.Name != "android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" {
				continue
			}
			if item.SpecialUseSubtype != "" || strings.TrimSpace(property.Value) == "" || len(property.Value) > 1024 || property.Resource != "" || strings.HasPrefix(property.Value, "@") || strings.HasPrefix(property.Value, "?") {
				return Manifest{}, fmt.Errorf("service %q has duplicate, empty or unresolved specialUse property", service.Name)
			}
			item.SpecialUseSubtype = property.Value
		}
		seenActions, seenCategories := map[string]bool{}, map[string]bool{}
		for _, filter := range service.IntentFilters {
			for _, action := range filter.Actions {
				if action.Name == "" || strings.TrimSpace(action.Name) != action.Name || seenActions[action.Name] {
					return Manifest{}, fmt.Errorf("service %q invalid or duplicate intent action", service.Name)
				}
				seenActions[action.Name] = true
				item.IntentActions = append(item.IntentActions, action.Name)
			}
			for _, category := range filter.Categories {
				if category.Name == "" || strings.TrimSpace(category.Name) != category.Name || seenCategories[category.Name] {
					return Manifest{}, fmt.Errorf("service %q invalid or duplicate intent category", service.Name)
				}
				seenCategories[category.Name] = true
				item.IntentCategories = append(item.IntentCategories, category.Name)
			}
			item.IntentDataCount += len(filter.Data)
		}
		result.Services = append(result.Services, item)
	}
	sort.Slice(result.Services, func(i, j int) bool { return result.Services[i].Name < result.Services[j].Name })
	return result, nil
}

// ReadManifest reads and parses one merged text manifest.
func ReadManifest(filePath string) (Manifest, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return Manifest{}, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	if err != nil {
		return Manifest{}, err
	}
	return ParseManifest(raw)
}

func parseOptionalBool(value string) (*bool, error) {
	if value == "" {
		return nil, nil
	}
	if value != "true" && value != "false" {
		return nil, fmt.Errorf("invalid canonical boolean %q", value)
	}
	parsed := value == "true"
	return &parsed, nil
}

func parseRequiredBool(value string) (bool, error) {
	if value == "" {
		return false, fmt.Errorf("missing boolean")
	}
	parsed, err := parseOptionalBool(value)
	if err != nil {
		return false, err
	}
	return *parsed, nil
}
