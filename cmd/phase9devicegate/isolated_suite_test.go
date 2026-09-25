// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestIsolatedDevicePlanPreservesMethodsAndDraftProcessBoundary(t *testing.T) {
	const p = "org.kurdistanvpn.app."
	batches, err := planIsolatedDeviceBatches([]string{
		p + "ProductStorageDeviceTest#first", p + "ProductStorageDeviceTest#second",
		p + "SensitiveActionDeviceTest#realCredentialPromptPreservesPendingActionAndDeliversOnce",
		p + "SettingsDraftProcessDeviceTest#resumeAfterProcessDeath",
		p + "SettingsDraftProcessDeviceTest#stageBeforeProcessDeath",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []deviceBatch{
		{tests: []string{p + "ProductStorageDeviceTest#first", p + "ProductStorageDeviceTest#second"}, clearData: true},
		{tests: []string{p + "SensitiveActionDeviceTest#realCredentialPromptPreservesPendingActionAndDeliversOnce"}, clearData: true, credential: true},
		{tests: []string{p + "SettingsDraftProcessDeviceTest#stageBeforeProcessDeath"}, clearData: true, extras: []string{"-e", "draftPhase", "stage"}},
		{tests: []string{p + "SettingsDraftProcessDeviceTest#resumeAfterProcessDeath"}, clearData: false, extras: []string{"-e", "draftPhase", "resume"}},
	}
	if !reflect.DeepEqual(batches, want) {
		t.Fatalf("got %+v want %+v", batches, want)
	}
	for _, invalid := range [][]string{nil, {p + "A#one", p + "A#one"}, {p + "SettingsDraftProcessDeviceTest#resumeAfterProcessDeath"}} {
		if _, err := planIsolatedDeviceBatches(invalid); err == nil {
			t.Fatalf("accepted incomplete/duplicate plan %v", invalid)
		}
	}
}

func TestOwnedEmulatorMustMatchBeforeAnyDestructiveSetup(t *testing.T) {
	for _, test := range []struct {
		name, hardware, app, selected string
		ok                            bool
	}{
		{"kurdistan_phase17_api34", "ranchu", "org.kurdistanvpn.app.internal", "kurdistan_phase17_api34", true},
		{"kurdistan_phase17_api34", "goldfish", "org.kurdistanvpn.app.internal", "kurdistan_phase17_api34", true},
		{"kurdistan_phase17_api34", "real-phone", "org.kurdistanvpn.app.internal", "kurdistan_phase17_api34", false},
		{"old-personal-avd", "ranchu", "org.kurdistanvpn.app.internal", "kurdistan_phase17_api34", false},
		{"kurdistan_phase17_api34", "ranchu", "org.kurdistanvpn.app", "kurdistan_phase17_api34", false},
		{"", "ranchu", "org.kurdistanvpn.app.internal", "", false},
	} {
		err := verifyOwnedEmulator(test.selected, test.name, test.hardware, test.app)
		if (err == nil) != test.ok {
			t.Fatalf("identity %+v: %v", test, err)
		}
	}
}

func TestNetworkLeasePlanSeparatesIncompatibleFixturesAndKeepsDnsHistory(t *testing.T) {
	const p = "org.kurdistanvpn.app.Task7VpnNetworkLeaseDeviceTest#"
	basic := []string{p + "associatedMaintenanceLeaseUsesOwnedTunAndRetiresWithOwner", p + "disconnectedMaintenanceAcquiresAndClosesWithoutNetworkIO"}
	dns := []string{p + "signedUpdateTruncatedDnsReachesTcpSynThenCancels", p + "signedUpdateTunLossInvalidatesLeaseAndCannotPublish", p + "signedUpdateUdpDnsReachesOwnedTunThenHttpsSynCancels"}
	batches, err := planIsolatedDeviceBatches(append(append([]string{}, basic...), dns...))
	want := []deviceBatch{{tests: basic, clearData: true, wifiOnly: true}, {tests: dns, clearData: true}}
	if err != nil || !reflect.DeepEqual(batches, want) {
		t.Fatalf("network fixture groups = %+v, %v", batches, err)
	}
}

func TestFoldBatchRequiresWideWindowWithoutDroppingTheMethod(t *testing.T) {
	name := "org.kurdistanvpn.app.ProductFoldDeviceTest#postureChangesKeepOneDraftOwnerAndAvoidThePhysicalHinge"
	batches, err := planIsolatedDeviceBatches([]string{name})
	if err != nil || len(batches) != 1 || !batches[0].wide || !batches[0].clearData || !reflect.DeepEqual(batches[0].tests, []string{name}) {
		t.Fatalf("wide batch = %+v, %v", batches, err)
	}
}

func TestAlwaysOnPlatformControlIsIsolatedFromOrdinaryAppChecks(t *testing.T) {
	const prefix = "org.kurdistanvpn.app.ProductionProxyServiceDeviceTest#"
	ordinary := []string{prefix + "authenticatedLoopbackProxyTransfersThroughNativeAndStopsWithSession", prefix + "survivingControllerRestoresKilledProcessAndProxyTraffic"}
	alwaysOn := prefix + "systemAlwaysOnRestartsTheKilledProcessWithLockdownStillEnabled"
	batches, err := planIsolatedDeviceBatches(append(append([]string{}, ordinary...), alwaysOn))
	want := []deviceBatch{
		{tests: ordinary, clearData: true},
		{tests: []string{alwaysOn}, clearData: true, extras: []string{"--no-hidden-api-checks"}},
	}
	if err != nil || !reflect.DeepEqual(batches, want) {
		t.Fatalf("platform control batches = %+v, %v", batches, err)
	}
	batches, err = planIsolatedDeviceBatches(ordinary)
	if err != nil || !reflect.DeepEqual(batches, want[:1]) {
		t.Fatalf("ordinary checks changed: %+v, %v", batches, err)
	}
}

func TestTemporaryCredentialIsClearedWhenLaterSetupFails(t *testing.T) {
	client := newADBClient("fixture-adb", "", t.TempDir(), &diagnosticTimeline{Started: time.Now()})
	var installed, cleared string
	client.transport = &commandTransport{run: func(_ context.Context, _ string, args []string, stdout, _ io.Writer, _ time.Duration) error {
		command := strings.Join(args, " ")
		switch {
		case strings.Contains(command, "am force-stop"):
			return nil
		case strings.Contains(command, "locksettings set-pin"):
			installed = args[len(args)-1]
			_, _ = io.WriteString(stdout, "Pin set to test credential")
			return nil
		case strings.Contains(command, "locksettings clear"):
			cleared = args[len(args)-1]
			_, _ = io.WriteString(stdout, "Lock credential cleared")
			return nil
		default:
			return errors.New("injected post-credential setup failure")
		}
	}}
	_, err := runIsolatedDeviceBatch(context.Background(), client, options{appPackage: "org.kurdistanvpn.app.internal"},
		deviceBatch{tests: []string{"org.kurdistanvpn.app.SensitiveActionDeviceTest#realCredentialPromptPreservesPendingActionAndDeliversOnce"}, credential: true})
	if err == nil || len(installed) != 6 || installed != cleared {
		t.Fatalf("credential cleanup missing: failed=%t installed=%t cleared=%t", err != nil, installed != "", cleared != "")
	}
}

func TestMaintenanceUnderlayRestoresOwnedEmulatorDataAfterSetupFailure(t *testing.T) {
	for _, initial := range []string{"1", "0", "unknown"} {
		t.Run(initial, func(t *testing.T) {
			client := newADBClient("fixture-adb", "", t.TempDir(), &diagnosticTimeline{Started: time.Now()})
			state, disabled, restored := initial, 0, 0
			client.transport = &commandTransport{run: func(_ context.Context, _ string, args []string, stdout, _ io.Writer, _ time.Duration) error {
				switch strings.Join(args, " ") {
				case "shell am force-stop org.kurdistanvpn.app.internal":
				case "emu avd name":
					_, _ = io.WriteString(stdout, "owned-fixture\nOK\n")
				case "shell getprop ro.hardware":
					_, _ = io.WriteString(stdout, "ranchu\n")
				case "shell settings get global wifi_on":
					_, _ = io.WriteString(stdout, "1\n")
				case "shell settings get global mobile_data":
					_, _ = io.WriteString(stdout, state+"\n")
				case "shell svc data disable":
					disabled++
					state = "0"
				case "shell svc data enable":
					restored++
					state = "1"
				default:
					return errors.New("injected later setup failure")
				}
				return nil
			}}
			batches, err := planIsolatedDeviceBatches([]string{"org.kurdistanvpn.app.Task7VpnNetworkLeaseDeviceTest#associatedMaintenanceLeaseUsesOwnedTunAndRetiresWithOwner"})
			if err != nil {
				t.Fatal(err)
			}
			batch := batches[0]
			batch.clearData = false
			_, err = runIsolatedDeviceBatch(context.Background(), client, options{appPackage: "org.kurdistanvpn.app.internal", ownedEmulatorName: "owned-fixture"}, batch)
			want := 0
			if initial == "1" {
				want = 1
			}
			if err == nil || disabled != want || restored != want || state != initial {
				t.Fatalf("failed=%t disabled=%d restored=%d state=%q", err != nil, disabled, restored, state)
			}
		})
	}
}
