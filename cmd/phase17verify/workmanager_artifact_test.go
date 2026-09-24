// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"kurdistan/internal/androidartifact"
)

// Literal excerpts of SDK36 aapt2 output, with unrelated declarations omitted.
const workResourcesFixture = `Binary APK
Package name=org.kurdistanvpn.app id=7f
  type bool id=05 entryCount=2
    resource 0x7f050003 bool/enable_system_foreground_service_default
      () true
    resource 0x7f050004 bool/enable_system_job_service_default
      () true
`

const workXMLFixture = `N: android=http://schemas.android.com/apk/res/android (line=2)
  E: manifest (line=2)
    A: package="org.kurdistanvpn.app" (Raw: "org.kurdistanvpn.app")
      E: application (line=40)
          E: service (line=127)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)="androidx.work.impl.background.systemjob.SystemJobService" (Raw: "androidx.work.impl.background.systemjob.SystemJobService")
            A: http://schemas.android.com/apk/res/android:permission(0x01010006)="android.permission.BIND_JOB_SERVICE" (Raw: "android.permission.BIND_JOB_SERVICE")
            A: http://schemas.android.com/apk/res/android:enabled(0x0101000e)=@0x7f050004
            A: http://schemas.android.com/apk/res/android:exported(0x01010010)=true
            A: http://schemas.android.com/apk/res/android:directBootAware(0x01010505)=false
          E: service (line=133)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)="androidx.work.impl.foreground.SystemForegroundService" (Raw: "androidx.work.impl.foreground.SystemForegroundService")
            A: http://schemas.android.com/apk/res/android:enabled(0x0101000e)=@0x7f050003
            A: http://schemas.android.com/apk/res/android:exported(0x01010010)=false
            A: http://schemas.android.com/apk/res/android:directBootAware(0x01010505)=false
`

func TestWorkManagerBindsCompiledReferenceToDefaultBoolean(t *testing.T) {
	resolver, err := bindWorkManagerOutput([]byte(workResourcesFixture), []byte(workXMLFixture))
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{
		{"androidx.work.impl.background.systemjob.SystemJobService", "@bool/enable_system_job_service_default"},
		{"androidx.work.impl.foreground.SystemForegroundService", "@bool/enable_system_foreground_service_default"},
	} {
		if value, err := resolver(pair[0], pair[1]); err != nil || !value {
			t.Fatalf("resolution = %v, %v", value, err)
		}
	}
	for _, pair := range [][2]string{{"owner.Service", "@bool/enable_system_job_service_default"}, {"androidx.work.impl.foreground.SystemForegroundService", "@bool/enable_system_job_service_default"}, {"androidx.work.impl.background.systemjob.SystemJobService", "?bool/enable_system_job_service_default"}} {
		if _, err := resolver(pair[0], pair[1]); err == nil {
			t.Fatal("unapproved pair resolved")
		}
	}
}

func TestWorkManagerRejectsUnboundOrAmbiguousSDKOutput(t *testing.T) {
	for _, test := range []struct {
		name, old, new string
		xml            bool
	}{
		{"resource-package", "Package name=org.kurdistanvpn.app", "Package name=other.package", false},
		{"resource-package-id", "id=7f", "id=80", false},
		{"resource-type", "type bool", "type integer", false},
		{"resource-type-id", "type bool id=05", "type bool id=06", false},
		{"resource-count", "entryCount=2", "entryCount=3", false},
		{"resource-name", "bool/enable_system_job_service_default", "bool/unapproved", false},
		{"resource-id", "0x7f050004", "0x7f050006", false},
		{"resource-wrong-package-id", "0x7f050004", "0x80050004", false},
		{"duplicate-id", "0x7f050004", "0x7f050003", false},
		{"missing-value", "      () true\n", "", false},
		{"false-value", "() true", "() false", false},
		{"noncanonical-value", "() true", "() 1", false},
		{"alias-value", "() true", "() @0x7f050004", false},
		{"qualified-value", "() true", "(v36) true", false},
		{"extra-configuration", "      () true", "      () true\n      (v36) true", false},
		{"duplicate-value", "      () true", "      () true\n      () true", false},
		{"duplicate-resource", "    resource 0x7f050004 bool/enable_system_job_service_default\n      () true", "    resource 0x7f050004 bool/enable_system_job_service_default\n      () true\n    resource 0x7f050005 bool/enable_system_job_service_default\n      () true", false},
		{"truncated-resource", "      () true\n", "      () tru", false},
		{"compiled-package", `package="org.kurdistanvpn.app"`, `package="other.package"`, true},
		{"compiled-namespace", "N: android=http://schemas.android.com/apk/res/android", "N: android=unexpected", true},
		{"compiled-lookalike-namespace", "schemas.android.com", "schemasXandroidXcom", true},
		{"compiled-inherited-process", "      E: application (line=40)", "      E: application (line=40)\n        A: http://schemas.android.com/apk/res/android:process(0x01010011)=\":worker\" (Raw: \":worker\")", true},
		{"compiled-inherited-permission", "      E: application (line=40)", "      E: application (line=40)\n        A: http://schemas.android.com/apk/res/android:permission(0x01010006)=\"other\" (Raw: \"other\")", true},
		{"compiled-inherited-enabled", "      E: application (line=40)", "      E: application (line=40)\n        A: http://schemas.android.com/apk/res/android:enabled(0x0101000e)=false", true},
		{"compiled-inherited-boot", "      E: application (line=40)", "      E: application (line=40)\n        A: http://schemas.android.com/apk/res/android:directBootAware(0x01010505)=true", true},
		{"compiled-inherited-storage", "      E: application (line=40)", "      E: application (line=40)\n        A: http://schemas.android.com/apk/res/android:defaultToDeviceProtectedStorage(0x01010504)=true", true},
		{"compiled-literal", "=@0x7f050004", "=true", true},
		{"compiled-wrong-reference", "=@0x7f050004", "=@0x7f050003", true},
		{"compiled-unknown-reference", "=@0x7f050004", "=@0x7f050099", true},
		{"compiled-missing-service", "E: service (line=127)", "E: receiver (line=127)", true},
		{"compiled-extra-work-service", "E: service (line=133)", "E: service (line=133)\n            A: name=\"androidx.work.Unapproved\"", true},
		{"compiled-job-exported", "exported(0x01010010)=true", "exported(0x01010010)=false", true},
		{"compiled-direct-boot", "directBootAware(0x01010505)=false", "directBootAware(0x01010505)=true", true},
		{"compiled-wrong-attribute-id", "enabled(0x0101000e)", "enabled(0x0101000f)", true},
		{"compiled-job-permission", "android.permission.BIND_JOB_SERVICE", "android.permission.BIND_VPN_SERVICE", true},
		{"compiled-extra-interface", "          E: service (line=133)", "              E: intent-filter (line=130)\n          E: service (line=133)", true},
		{"compiled-extra-attribute", "            A: http://schemas.android.com/apk/res/android:enabled(0x0101000e)=@0x7f050004", "            A: http://schemas.android.com/apk/res/android:enabled(0x0101000e)=@0x7f050004\n            A: http://schemas.android.com/apk/res/android:stopWithTask(0x01010036)=false", true},
		{"compiled-duplicate-attribute", "            A: http://schemas.android.com/apk/res/android:enabled(0x0101000e)=@0x7f050004", "            A: http://schemas.android.com/apk/res/android:enabled(0x0101000e)=@0x7f050004\n            A: http://schemas.android.com/apk/res/android:enabled(0x0101000e)=@0x7f050004", true},
		{"compiled-truncated", "directBootAware(0x01010505)=false\n", "directBootAware(0x01010505)=fals", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			resources, xml := workResourcesFixture, workXMLFixture
			if test.xml {
				xml = strings.Replace(xml, test.old, test.new, 1)
			} else {
				resources = strings.Replace(resources, test.old, test.new, 1)
			}
			if _, err := bindWorkManagerOutput([]byte(resources), []byte(xml)); err == nil {
				t.Fatal("invalid SDK output accepted")
			}
		})
	}
	job := workXMLFixture[strings.Index(workXMLFixture, "          E: service (line=127)"):strings.Index(workXMLFixture, "          E: service (line=133)")]
	if _, err := bindWorkManagerOutput([]byte(workResourcesFixture), []byte(workXMLFixture+job)); err == nil {
		t.Fatal("duplicate compiled service accepted")
	}
	outside := "      E: service (line=140)\n        A: http://schemas.android.com/apk/res/android:name(0x01010003)=\"androidx.work.Unapproved\" (Raw: \"androidx.work.Unapproved\")\n"
	if _, err := bindWorkManagerOutput([]byte(workResourcesFixture), []byte(workXMLFixture+outside)); err == nil {
		t.Fatal("misplaced compiled WorkManager service accepted")
	}
}

func currentWorkManifest(t *testing.T) androidartifact.Manifest {
	t.Helper()
	manifest := phase17ManifestFixture(t, []string{"android.permission.WAKE_LOCK", "android.permission.RECEIVE_BOOT_COMPLETED"}, false)
	yes, no := true, false
	manifest.Services = append(manifest.Services, androidartifact.Service{Name: "androidx.work.impl.background.systemjob.SystemJobService", Permission: "android.permission.BIND_JOB_SERVICE", PermissionDeclared: true, Exported: true, Enabled: &yes, DirectBootAware: &no}, androidartifact.Service{Name: "androidx.work.impl.foreground.SystemForegroundService", Enabled: &yes, DirectBootAware: &no})
	return manifest
}

func TestCurrentPolicyRejectsWorkServiceAndPermissionMutations(t *testing.T) {
	yes, no := true, false
	for _, test := range []struct {
		name   string
		mutate func(*androidartifact.Service)
	}{
		{"name", func(s *androidartifact.Service) { s.Name = "androidx.work.Unapproved" }},
		{"disabled", func(s *androidartifact.Service) { s.Enabled = &no }},
		{"enabled-absent", func(s *androidartifact.Service) { s.Enabled = nil }},
		{"exported", func(s *androidartifact.Service) { s.Exported = !s.Exported }},
		{"direct-boot", func(s *androidartifact.Service) { s.DirectBootAware = &yes }},
		{"direct-boot-absent", func(s *androidartifact.Service) { s.DirectBootAware = nil }},
		{"permission", func(s *androidartifact.Service) { s.Permission = "other.permission" }},
		{"process", func(s *androidartifact.Service) { s.Process = ":worker" }},
		{"isolated", func(s *androidartifact.Service) { s.IsolatedProcess = &yes }},
		{"isolated-false", func(s *androidartifact.Service) { s.IsolatedProcess = &no }},
		{"external", func(s *androidartifact.Service) { s.ExternalService = &yes }},
		{"external-false", func(s *androidartifact.Service) { s.ExternalService = &no }},
		{"stop-with-task", func(s *androidartifact.Service) { s.StopWithTask = &yes }},
		{"stop-with-task-false", func(s *androidartifact.Service) { s.StopWithTask = &no }},
		{"intent", func(s *androidartifact.Service) { s.IntentFilterCount = 1 }},
		{"intent-action", func(s *androidartifact.Service) { s.IntentActions = []string{"action"} }},
		{"intent-category", func(s *androidartifact.Service) { s.IntentCategories = []string{"category"} }},
		{"intent-data", func(s *androidartifact.Service) { s.IntentDataCount = 1 }},
		{"subtype", func(s *androidartifact.Service) { s.SpecialUseSubtype = "subtype" }},
		{"vpn-metadata", func(s *androidartifact.Service) { s.SupportsAlwaysOn = &no }},
		{"foreground-type", func(s *androidartifact.Service) { s.ForegroundServiceType = "specialUse" }},
	} {
		for _, index := range []int{2, 3} {
			t.Run(fmt.Sprintf("%s-%d", test.name, index), func(t *testing.T) {
				m := currentWorkManifest(t)
				test.mutate(&m.Services[index])
				if err := verifyCurrentArtifactManifest(m); err == nil {
					t.Fatal("mutated service accepted")
				}
			})
		}
	}
	for _, permission := range []string{"android.permission.WAKE_LOCK", "android.permission.RECEIVE_BOOT_COMPLETED"} {
		for _, duplicate := range []bool{false, true} {
			m := currentWorkManifest(t)
			if duplicate {
				m.Permissions = append(m.Permissions, permission)
			} else {
				for i, p := range m.Permissions {
					if p == permission {
						m.Permissions = append(m.Permissions[:i], m.Permissions[i+1:]...)
						break
					}
				}
			}
			if err := verifyCurrentArtifactManifest(m); err == nil {
				t.Fatal("missing or duplicate permission accepted")
			}
		}
	}
	m := currentWorkManifest(t)
	m.Permissions = append(m.Permissions, "android.permission.UNKNOWN")
	if err := verifyCurrentArtifactManifest(m); err == nil {
		t.Fatal("unexpected permission accepted")
	}
	for _, index := range []int{2, 3} {
		m := currentWorkManifest(t)
		m.Services = append(m.Services, m.Services[index])
		if err := verifyCurrentArtifactManifest(m); err == nil {
			t.Fatal("duplicate service accepted")
		}
		m = currentWorkManifest(t)
		m.Services = append(m.Services[:index], m.Services[index+1:]...)
		if err := verifyCurrentArtifactManifest(m); err == nil {
			t.Fatal("missing service accepted")
		}
	}
	m = currentWorkManifest(t)
	m.Services[2].PermissionDeclared = false
	if err := verifyCurrentArtifactManifest(m); err == nil {
		t.Fatal("undeclared job permission accepted")
	}
	m = currentWorkManifest(t)
	m.Services[2].Process = "org.kurdistanvpn.app"
	m.Services[3].Process = "org.kurdistanvpn.app"
	before := append([]string(nil), m.Permissions...)
	if err := verifyCurrentArtifactManifest(m); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, m.Permissions) {
		t.Fatal("permissions changed")
	}
}

func TestMain(m *testing.M) {
	if mode := os.Getenv("PHASE17_AAPT2_TEST_HELPER"); mode != "" {
		runAAPT2TestHelper(mode)
		return
	}
	os.Exit(m.Run())
}

func runAAPT2TestHelper(mode string) {
	switch mode {
	case "overflow-stdout", "overflow-stderr":
		stream := os.Stdout
		if mode == "overflow-stderr" {
			stream = os.Stderr
		}
		for i := 0; i < 20000; i++ {
			_, _ = stream.Write(bytes.Repeat([]byte("x"), 1024))
		}
		time.Sleep(time.Minute)
	case "timeout":
		time.Sleep(time.Minute)
	case "failure":
		fmt.Fprintln(os.Stderr, "bounded diagnostic")
		os.Exit(7)
	case "invalid-version":
		fmt.Println("unsupported version")
	default:
		args := os.Args[1:]
		if reflect.DeepEqual(args, []string{"version"}) {
			fmt.Fprintln(os.Stderr, "Android Asset Packaging Tool (aapt) 2.20-13193326")
			return
		}
		if len(args) < 3 {
			os.Exit(8)
		}
		raw, err := os.ReadFile(args[2])
		if err != nil || string(raw) != "owned-apk" {
			os.Exit(9)
		}
		if reflect.DeepEqual(args, []string{"dump", "resources", args[2]}) {
			if mode == "malformed" {
				fmt.Println("malformed")
			} else {
				fmt.Print(workResourcesFixture)
			}
			return
		}
		if reflect.DeepEqual(args, []string{"dump", "xmltree", args[2], "--file", "AndroidManifest.xml"}) {
			fmt.Print(workXMLFixture)
			return
		}
		os.Exit(10)
	}
}

func TestAAPT2ProcessBoundariesTerminateAndReject(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"overflow-stdout", "overflow-stderr", "timeout", "failure"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("PHASE17_AAPT2_TEST_HELPER", mode)
			duration := 2 * time.Second
			if mode == "timeout" {
				duration = 300 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), duration)
			defer cancel()
			start := time.Now()
			_, err := runAAPT2(ctx, executable, 4096, "helper")
			if err == nil {
				t.Fatal("invalid process accepted")
			}
			if strings.HasPrefix(mode, "overflow") && !strings.Contains(err.Error(), "output exceeds bound") {
				t.Fatalf("overflow did not terminate process: %v", err)
			}
			if mode == "timeout" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("deadline lost: %v", err)
			}
			if time.Since(start) > 4*time.Second {
				t.Fatal("child was not bounded")
			}
		})
	}
	if _, err := runAAPT2(context.Background(), "aapt2", 4096, "version"); err == nil {
		t.Fatal("PATH lookup accepted")
	}
	if _, err := runAAPT2(context.Background(), filepath.Join(t.TempDir(), "missing"), 4096, "version"); err == nil {
		t.Fatal("missing executable accepted")
	}
}

func TestAAPT2InspectsSameOwnedSnapshotAndCleansEveryReturn(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "invalid-version", "malformed", "failure"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("PHASE17_AAPT2_TEST_HELPER", mode)
			original := filepath.Join(t.TempDir(), "release.apk")
			if err := os.WriteFile(original, []byte("owned-apk"), 0600); err != nil {
				t.Fatal(err)
			}
			var snapshot string
			err := withReleaseSnapshot(original, func(raw []byte, path string) error {
				snapshot = path
				if !bytes.Equal(raw, []byte("owned-apk")) {
					t.Fatal("snapshot mismatch")
				}
				if err := os.WriteFile(original, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
				_, err := inspectWorkManagerAPK(executable, path)
				return err
			})
			if (err == nil) != (mode == "success") {
				t.Fatalf("%s: %v", mode, err)
			}
			if _, err := os.Stat(snapshot); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("snapshot retained")
			}
			if _, err := os.Stat(filepath.Dir(snapshot)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("private directory retained")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "large.apk")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(40*1024*1024 + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := withReleaseSnapshot(path, func([]byte, string) error { t.Fatal("oversized APK inspected"); return nil }); err == nil {
		t.Fatal("oversized APK accepted")
	}
}
