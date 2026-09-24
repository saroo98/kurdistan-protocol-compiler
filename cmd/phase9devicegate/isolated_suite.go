// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type deviceBatch struct {
	tests            []string
	clearData        bool
	extras           []string
	wide, credential bool
}

func verifyOwnedEmulator(selected, actual, hardware, app string) error {
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`).MatchString(selected) || selected != strings.TrimSpace(actual) ||
		(strings.TrimSpace(hardware) != "ranchu" && strings.TrimSpace(hardware) != "goldfish") || app != "org.kurdistanvpn.app.internal" {
		return errors.New("isolated suite requires the exact explicitly owned emulator and internal package")
	}
	return nil
}

func planIsolatedDeviceBatches(tests []string) ([]deviceBatch, error) {
	if len(tests) == 0 {
		return nil, errors.New("isolated suite requires an exact nonempty inventory")
	}
	names := append([]string(nil), tests...)
	sort.Strings(names)
	var batches []deviceBatch
	const prefix = "org.kurdistanvpn.app."
	for i := 0; i < len(names); {
		class, method, ok := strings.Cut(names[i], "#")
		if !ok || method == "" || !strings.HasPrefix(class, prefix) {
			return nil, errors.New("invalid isolated test name")
		}
		end := i + 1
		for end < len(names) && strings.HasPrefix(names[end], class+"#") {
			if names[end] == names[end-1] {
				return nil, errors.New("duplicate isolated test")
			}
			end++
		}
		group := names[i:end]
		if class == prefix+"SettingsDraftProcessDeviceTest" {
			if len(group) != 2 || group[0] != class+"#resumeAfterProcessDeath" || group[1] != class+"#stageBeforeProcessDeath" {
				return nil, errors.New("draft process proof requires both ordered phases")
			}
			batches = append(batches,
				deviceBatch{tests: []string{group[1]}, clearData: true, extras: []string{"-e", "draftPhase", "stage"}},
				deviceBatch{tests: []string{group[0]}, extras: []string{"-e", "draftPhase", "resume"}})
		} else if class == prefix+"Task7VpnNetworkLeaseDeviceTest" {
			// Basic leases and signed updates require different protected-state fixtures.
			// Keep the DNS cases in one process so their native rate history is still checked.
			split := sort.SearchStrings(group, class+"#signedUpdate")
			for _, fixture := range [][]string{group[:split], group[split:]} {
				if len(fixture) > 0 {
					batches = append(batches, deviceBatch{tests: fixture, clearData: true})
				}
			}
		} else {
			batches = append(batches, deviceBatch{tests: group, clearData: true,
				wide: class == prefix+"ProductFoldDeviceTest", credential: class == prefix+"SensitiveActionDeviceTest"})
		}
		i = end
	}
	return batches, nil
}

func runIsolatedDeviceSuite(ctx context.Context, client adbClient, value options, expected []string) (string, error) {
	batches, err := planIsolatedDeviceBatches(expected)
	if err != nil {
		return "", err
	}
	root := filepath.Join(client.evidenceDir, "batches")
	if err := os.Mkdir(root, 0o700); err != nil {
		return "", fmt.Errorf("require fresh isolated evidence directory: %w", err)
	}
	var output strings.Builder
	for index, batch := range batches {
		name := fmt.Sprintf("%02d-%s", index+1, strings.TrimPrefix(strings.Split(batch.tests[0], "#")[0], "org.kurdistanvpn.app."))
		fmt.Printf("DEVICE BATCH %s (%d methods)\n", name, len(batch.tests))
		part := client
		part.evidenceDir = filepath.Join(root, name)
		if err := os.Mkdir(part.evidenceDir, 0o700); err != nil {
			return "", err
		}
		raw, err := runIsolatedDeviceBatch(ctx, part, value, batch)
		if err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		if output.Len()+len(raw) > maxCommandEvidence {
			return "", errors.New("combined instrumentation exceeds evidence bound")
		}
		output.WriteString(raw)
		output.WriteByte('\n')
	}
	result := output.String()
	if err := verifyExpectedTests(result, expected); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(client.evidenceDir, "13-instrumentation-summary.txt"), []byte(summarizeInstrumentation(result)), 0o600); err != nil {
		return "", err
	}
	return result, nil
}

func runIsolatedDeviceBatch(ctx context.Context, client adbClient, value options, batch deviceBatch) (_ string, resultErr error) {
	if _, err := client.capture(ctx, "00-force-stop.txt", "shell", "am", "force-stop", value.appPackage); err != nil {
		return "", err
	}
	if batch.clearData {
		if err := configureInstalledPackages(ctx, client, value); err != nil {
			return "", err
		}
	}
	extras := append([]string{"-e", "class", strings.Join(batch.tests, ",")}, batch.extras...)
	if batch.wide {
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			for _, setting := range []string{"size", "density"} {
				_, err := client.capture(cleanup, "90-restore-"+setting+".txt", "shell", "wm", setting, "reset")
				resultErr = errors.Join(resultErr, err)
			}
		}()
		if _, err := client.capture(ctx, "00-wide-size.txt", "shell", "wm", "size", "1920x2400"); err != nil {
			return "", err
		}
		if _, err := client.capture(ctx, "00-wide-density.txt", "shell", "wm", "density", "240"); err != nil {
			return "", err
		}
	}
	if batch.credential {
		var random [4]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", err
		}
		pin := fmt.Sprintf("%06d", 100000+binary.BigEndian.Uint32(random[:])%900000)
		// No old credential is supplied: an existing screen lock is never replaced.
		raw, err := client.captureOutput(ctx, "shell", "locksettings", "set-pin", pin)
		if err != nil || !strings.Contains(strings.ToLower(raw), "pin set to") {
			return "", errors.New("could not set test-only emulator PIN; existing credential left untouched")
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			raw, err := client.captureOutput(cleanup, "shell", "locksettings", "clear", "--old", pin)
			if err != nil || !strings.Contains(strings.ToLower(raw), "cleared") {
				resultErr = errors.Join(resultErr, errors.New("temporary emulator PIN cleanup failed"))
			}
		}()
		extras = append(extras, "-e", "testOnlyEmulatorPin", pin)
	}
	if err := prepareLogcatBaseline(ctx, client, "12-pre-test-clear-logcat.txt", value.appPackage); err != nil {
		return "", err
	}
	return runDeviceInstrumentation(ctx, client, value, batch.tests, len(batch.tests), extras)
}

func runDeviceInstrumentation(ctx context.Context, client adbClient, value options, expected []string, minimum int, extras []string) (string, error) {
	args, err := prepareNativeFilesystemInstrumentation(ctx, client, value.appPackage, value.testPackage, value.testPackage+"/"+value.runner)
	if err != nil {
		return "", err
	}
	runner := args[len(args)-1]
	args = append(append(args[:len(args)-1], extras...), runner)
	output, runErr := client.captureInstrumentation(ctx, "13-instrumentation-summary.txt", args...)
	logcat, logErr := client.captureDiagnostic(ctx, "14-device-diagnostics.txt", value.appPackage, diagnosticLogcatArgs("all")...)
	crashes, crashErr := client.captureDiagnostic(ctx, "15-crash-diagnostics.txt", value.appPackage, diagnosticLogcatArgs("crash")...)
	if err := errors.Join(logErr, crashErr); err != nil {
		return output, err
	}
	if err := evaluateInstrumentation(output, logcat+"\n"+crashes, value.appPackage, minimum); err != nil {
		return output, errors.Join(err, runErr)
	}
	if len(expected) > 0 {
		if err := verifyExpectedTests(output, expected); err != nil {
			return output, err
		}
	}
	return output, runErr
}
