// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"kurdistan/internal/androidartifact"
)

const workJobService = "androidx.work.impl.background.systemjob.SystemJobService"
const workForegroundService = "androidx.work.impl.foreground.SystemForegroundService"

func bindWorkManagerOutput(resources, compiled []byte) (androidartifact.ServiceEnabledResolver, error) {
	ids, err := workResourceIDs(resources)
	if err != nil {
		return nil, err
	}
	if err := verifyCompiledWorkServices(compiled, ids); err != nil {
		return nil, err
	}
	return func(service, reference string) (bool, error) {
		name := workResource(service)
		if name == "" || reference != "@"+name || ids[name] == "" {
			return false, fmt.Errorf("unapproved service enabled reference")
		}
		return true, nil
	}, nil
}

const aapt2Version = "Android Asset Packaging Tool (aapt) 2.20-13193326"
const aapt2OutputLimit = 16 << 20
const aapt2Namespace = "http://schemas.android.com/apk/res/android:"

// Returning a writer error alone need not kill a child that keeps its pipes
// open. Cancel on overflow as well, and bound inherited-pipe shutdown.
type aapt2Output struct {
	buffer   bytes.Buffer
	limit    int
	cancel   context.CancelFunc
	overflow bool
}

func (out *aapt2Output) Write(raw []byte) (int, error) {
	if len(raw) > out.limit-out.buffer.Len() {
		out.overflow = true
		out.cancel()
		return 0, fmt.Errorf("aapt2 output exceeds bound")
	}
	return out.buffer.Write(raw)
}

type aapt2Result struct{ stdout, stderr []byte }

func runAAPT2(ctx context.Context, executable string, stdoutLimit int, args ...string) (aapt2Result, error) {
	if !filepath.IsAbs(executable) {
		return aapt2Result{}, fmt.Errorf("aapt2 requires an explicit absolute executable path")
	}
	info, err := os.Stat(executable)
	if err != nil || !info.Mode().IsRegular() {
		return aapt2Result{}, fmt.Errorf("aapt2 executable unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stdout := &aapt2Output{limit: stdoutLimit, cancel: cancel}
	stderr := &aapt2Output{limit: 64 << 10, cancel: cancel}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.WaitDelay = time.Second
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err = cmd.Run()
	if stdout.overflow || stderr.overflow {
		return aapt2Result{}, fmt.Errorf("aapt2 output exceeds bound")
	}
	if ctx.Err() != nil {
		return aapt2Result{}, fmt.Errorf("aapt2 deadline or cancellation: %w", ctx.Err())
	}
	if err != nil {
		return aapt2Result{}, fmt.Errorf("aapt2 execution failed (%d diagnostic bytes): %w", stderr.buffer.Len(), err)
	}
	// Tool output may contain artifact strings. Do not include it in diagnostics.
	return aapt2Result{stdout.buffer.Bytes(), stderr.buffer.Bytes()}, nil
}

func inspectWorkManagerAPK(executable, snapshot string) (androidartifact.ServiceEnabledResolver, error) {
	ctx := context.Background()
	version, err := runAAPT2(ctx, executable, 4096, "version")
	if err != nil {
		return nil, err
	}
	// SDK36 writes its version to stderr, even on success. Dump payloads use stdout.
	if len(version.stdout) != 0 || string(bytes.ReplaceAll(version.stderr, []byte("\r\n"), []byte("\n"))) != aapt2Version+"\n" {
		return nil, fmt.Errorf("unsupported aapt2 version")
	}
	resources, err := runAAPT2(ctx, executable, aapt2OutputLimit, "dump", "resources", snapshot)
	if err != nil {
		return nil, err
	}
	compiled, err := runAAPT2(ctx, executable, aapt2OutputLimit, "dump", "xmltree", snapshot, "--file", "AndroidManifest.xml")
	if err != nil {
		return nil, err
	}
	return bindWorkManagerOutput(resources.stdout, compiled.stdout)
}

// Both inspectors receive one bounded owned snapshot, never two reads of a
// mutable release path. Cleanup names only the privately created file/directory.
func withReleaseSnapshot(path string, inspect func([]byte, string) error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, phase17MaxReleaseAPKBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(raw) > phase17MaxReleaseAPKBytes {
		return fmt.Errorf("release APK exceeds byte budget")
	}
	directory, err := os.MkdirTemp("", "phase17-artifact-")
	if err != nil {
		return err
	}
	defer os.Remove(directory)
	snapshot := filepath.Join(directory, "release.apk")
	defer os.Remove(snapshot)
	if err := os.WriteFile(snapshot, raw, 0600); err != nil {
		return err
	}
	return inspect(raw, snapshot)
}

func aapt2Lines(raw []byte) ([]string, error) {
	if len(raw) == 0 || len(raw) > aapt2OutputLimit || raw[len(raw)-1] != '\n' || !utf8.Valid(raw) || bytes.ContainsRune(raw, 0) {
		return nil, fmt.Errorf("malformed or truncated aapt2 output")
	}
	value := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if strings.ContainsAny(value, "\r\t") {
		return nil, fmt.Errorf("malformed aapt2 whitespace")
	}
	return strings.Split(value[:len(value)-1], "\n"), nil
}

var aapt2TypePattern = regexp.MustCompile(`^  type ([a-zA-Z0-9_]+) id=([0-9a-f]{2}) entryCount=([0-9]+)$`)
var aapt2ResourcePattern = regexp.MustCompile(`^    resource (0x[0-9a-f]{8}) ([a-zA-Z0-9_]+/[a-zA-Z0-9_.]+)(?: PUBLIC)?$`)

func workResourceIDs(raw []byte) (map[string]string, error) {
	lines, err := aapt2Lines(raw)
	if err != nil {
		return nil, err
	}
	if len(lines) < 2 || lines[0] != "Binary APK" || lines[1] != "Package name="+phase17AppPackage+" id=7f" {
		return nil, fmt.Errorf("unexpected resource package")
	}
	ids := map[string]string{}
	seenIDs, seenNames := map[string]bool{}, map[string]bool{}
	seenTypes, seenTypeIDs := map[string]bool{}, map[string]bool{}
	typeName, typeID, resource := "", "", ""
	typeCount, resourceCount := 0, 0
	values := 0
	finish := func() error {
		if resource != "" && values != 1 {
			return fmt.Errorf("WorkManager boolean must have exactly one default scalar")
		}
		return nil
	}
	for _, line := range lines[2:] {
		if match := aapt2TypePattern.FindStringSubmatch(line); match != nil {
			if err := finish(); err != nil {
				return nil, err
			}
			if resourceCount != typeCount || seenTypes[match[1]] || seenTypeIDs[match[2]] {
				return nil, fmt.Errorf("incomplete or duplicate resource type")
			}
			typeCount, err = strconv.Atoi(match[3])
			if err != nil || typeCount < 1 || typeCount > 65536 {
				return nil, fmt.Errorf("invalid resource type count")
			}
			resourceCount = 0
			seenTypes[match[1]], seenTypeIDs[match[2]] = true, true
			typeName, typeID, resource = match[1], match[2], ""
			continue
		}
		if match := aapt2ResourcePattern.FindStringSubmatch(line); match != nil {
			if err := finish(); err != nil {
				return nil, err
			}
			id, name := match[1], match[2]
			if typeName == "" || !strings.HasPrefix(name, typeName+"/") || !strings.HasPrefix(id, "0x7f"+typeID) || seenIDs[id] || seenNames[name] {
				return nil, fmt.Errorf("ambiguous resource identity")
			}
			seenIDs[id], seenNames[name] = true, true
			resourceCount++
			resource, values = "", 0
			if name == workResource(workJobService) || name == workResource(workForegroundService) {
				resource, ids[name] = name, id
			}
			continue
		}
		if !strings.HasPrefix(line, "      ") || typeName == "" {
			return nil, fmt.Errorf("malformed resource table structure")
		}
		if resource != "" {
			values++
			if line != "      () true" {
				return nil, fmt.Errorf("WorkManager boolean is not a default canonical true scalar")
			}
		}
	}
	if err := finish(); err != nil {
		return nil, err
	}
	if resourceCount != typeCount {
		return nil, fmt.Errorf("incomplete resource type")
	}
	if len(ids) != 2 {
		return nil, fmt.Errorf("missing WorkManager boolean resource")
	}
	return ids, nil
}

type aapt2Element struct {
	name       string
	indent     int
	attributes map[string]string
	children   []*aapt2Element
}

var aapt2ElementPattern = regexp.MustCompile(`^E: ([a-zA-Z0-9_-]+) \(line=[0-9]+\)$`)
var aapt2AttributePattern = regexp.MustCompile(`^A: ([^= ]+)=(.+)$`)
var aapt2NamespacePattern = regexp.MustCompile(`^N: android=` + regexp.QuoteMeta(strings.TrimSuffix(aapt2Namespace, ":")) + ` \(line=[0-9]+\)$`)

func compiledManifest(raw []byte) (*aapt2Element, error) {
	lines, err := aapt2Lines(raw)
	if err != nil {
		return nil, err
	}
	if len(lines) < 2 || !aapt2NamespacePattern.MatchString(lines[0]) {
		return nil, fmt.Errorf("unexpected compiled namespace")
	}
	var stack []*aapt2Element
	var root *aapt2Element
	for _, line := range lines[1:] {
		trimmed := strings.TrimLeft(line, " ")
		indent := len(line) - len(trimmed)
		if match := aapt2ElementPattern.FindStringSubmatch(trimmed); match != nil {
			for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
				stack = stack[:len(stack)-1]
			}
			node := &aapt2Element{name: match[1], indent: indent, attributes: map[string]string{}}
			if len(stack) == 0 {
				if root != nil || indent != 2 || node.name != "manifest" {
					return nil, fmt.Errorf("invalid compiled root")
				}
				root = node
			} else {
				parent := stack[len(stack)-1]
				if indent != parent.indent+4 || len(stack) >= 32 {
					return nil, fmt.Errorf("invalid compiled element depth")
				}
				if node.name == "manifest" || node.name == "application" && parent.name != "manifest" || node.name == "service" && parent.name != "application" {
					return nil, fmt.Errorf("misplaced compiled element")
				}
				parent.children = append(parent.children, node)
			}
			stack = append(stack, node)
			continue
		}
		match := aapt2AttributePattern.FindStringSubmatch(trimmed)
		if match == nil || len(stack) == 0 {
			return nil, fmt.Errorf("malformed compiled attribute")
		}
		node := stack[len(stack)-1]
		if indent != node.indent+2 || len(node.children) > 0 || node.attributes[match[1]] != "" {
			return nil, fmt.Errorf("ambiguous compiled attribute")
		}
		node.attributes[match[1]] = match[2]
	}
	if root == nil {
		return nil, fmt.Errorf("missing compiled manifest")
	}
	return root, nil
}

func aapt2String(value string) string { return `"` + value + `" (Raw: "` + value + `")` }

func verifyCompiledWorkServices(raw []byte, ids map[string]string) error {
	root, err := compiledManifest(raw)
	if err != nil {
		return err
	}
	if root.attributes["package"] != aapt2String(phase17AppPackage) {
		return fmt.Errorf("unexpected compiled application package")
	}
	var app *aapt2Element
	for _, node := range root.children {
		if node.name == "application" {
			if app != nil {
				return fmt.Errorf("duplicate compiled application")
			}
			app = node
		}
	}
	if app == nil {
		return fmt.Errorf("missing compiled application")
	}
	// Inherited defaults must not change the compiled WorkManager boundary.
	defaults := map[string][]string{
		"process(0x01010011)":                         {aapt2String(phase17AppPackage)},
		"permission(0x01010006)":                      {aapt2String("")},
		"enabled(0x0101000e)":                         {"true"},
		"directBootAware(0x01010505)":                 {"false"},
		"defaultToDeviceProtectedStorage(0x01010504)": {"false"},
	}
	for key, allowed := range defaults {
		if value, ok := app.attributes[aapt2Namespace+key]; ok && value != allowed[0] {
			return fmt.Errorf("invalid compiled application default")
		}
	}
	seen := map[string]bool{}
	for _, node := range app.children {
		if node.name != "service" {
			continue
		}
		nameValue := node.attributes[aapt2Namespace+"name(0x01010003)"]
		name := ""
		for _, candidate := range []string{workJobService, workForegroundService} {
			if nameValue == aapt2String(candidate) {
				name = candidate
			}
		}
		if name == "" {
			for _, value := range node.attributes {
				if strings.Contains(value, "androidx.work.") {
					return fmt.Errorf("unexpected compiled WorkManager service")
				}
			}
			continue
		}
		if seen[name] || len(node.children) != 0 {
			return fmt.Errorf("duplicate compiled WorkManager service or unexpected interface")
		}
		seen[name] = true
		want := map[string]string{
			aapt2Namespace + "name(0x01010003)":            aapt2String(name),
			aapt2Namespace + "enabled(0x0101000e)":         "@" + ids[workResource(name)],
			aapt2Namespace + "exported(0x01010010)":        "false",
			aapt2Namespace + "directBootAware(0x01010505)": "false",
		}
		if name == workJobService {
			want[aapt2Namespace+"exported(0x01010010)"] = "true"
			want[aapt2Namespace+"permission(0x01010006)"] = aapt2String("android.permission.BIND_JOB_SERVICE")
		}
		if process, ok := node.attributes[aapt2Namespace+"process(0x01010011)"]; ok && process == aapt2String(phase17AppPackage) {
			want[aapt2Namespace+"process(0x01010011)"] = process
		}
		if len(node.attributes) != len(want) {
			return fmt.Errorf("unexpected compiled WorkManager attribute")
		}
		for key, value := range want {
			if node.attributes[key] != value {
				return fmt.Errorf("compiled WorkManager boundary or resource ID mismatch")
			}
		}
	}
	if len(seen) != 2 {
		return fmt.Errorf("missing compiled WorkManager service")
	}
	return nil
}

func workResource(name string) string {
	switch name {
	case workJobService:
		return "bool/enable_system_job_service_default"
	case workForegroundService:
		return "bool/enable_system_foreground_service_default"
	}
	return ""
}

// Current dependency permissions are removed from an owned slice before applying
// the unchanged historical policy. This does not broaden historical receipts.
func verifyCurrentArtifactManifest(manifest androidartifact.Manifest) error {
	permissions := make([]string, 0, len(manifest.Permissions))
	wake, boot := 0, 0
	for _, permission := range manifest.Permissions {
		switch permission {
		case "android.permission.WAKE_LOCK":
			wake++
		case "android.permission.RECEIVE_BOOT_COMPLETED":
			boot++
		default:
			permissions = append(permissions, permission)
		}
	}
	if wake != 1 || boot != 1 {
		return fmt.Errorf("current artifact requires exactly one wake and boot permission")
	}
	manifest.Permissions = permissions
	if err := verifyPhase17Manifest(manifest); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, service := range manifest.Services {
		if !strings.HasPrefix(service.Name, "androidx.work.") {
			continue
		}
		if workResource(service.Name) == "" || seen[service.Name] {
			return fmt.Errorf("unexpected or duplicate WorkManager service")
		}
		seen[service.Name] = true
		if err := verifyWorkService(service); err != nil {
			return err
		}
	}
	if !seen[workJobService] || !seen[workForegroundService] {
		return fmt.Errorf("missing WorkManager service")
	}
	return nil
}

func verifyWorkService(service androidartifact.Service) error {
	job := service.Name == workJobService
	if workResource(service.Name) == "" || !boolTrue(service.Enabled) || !boolFalse(service.DirectBootAware) || service.Exported != job ||
		service.Process != "" && service.Process != phase17AppPackage || service.IsolatedProcess != nil || service.ExternalService != nil || service.StopWithTask != nil ||
		service.IntentFilterCount != 0 || len(service.IntentActions) != 0 || len(service.IntentCategories) != 0 || service.IntentDataCount != 0 ||
		service.SpecialUseSubtype != "" || service.SupportsAlwaysOn != nil || service.ForegroundServiceType != "" {
		return fmt.Errorf("invalid WorkManager service boundary")
	}
	if job && (!service.PermissionDeclared || service.Permission != "android.permission.BIND_JOB_SERVICE") || !job && service.Permission != "" {
		return fmt.Errorf("invalid WorkManager service permission")
	}
	return nil
}
