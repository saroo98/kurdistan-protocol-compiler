// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// This replays the observed API 26/34/36 boundary: the ordinary ADB shell is
// identified correctly, the crash buffer is available, and main/system probes
// report permission denial. The v1 gate blocks solely because it makes all
// three log buffers mandatory. The versioned composite observer must instead
// retain those denials and admit only the non-qualifying instrumentation step.
func TestCompositeStartupObserverAllowsOptionalMainSystemDenialOnlyWithCompleteReplacement(t *testing.T) {
	for _, test := range []struct {
		api      int
		scenario string
	}{
		{26, "ci-api26-permission-denied"},
		{34, "ci-api34-permission-denied"},
		{36, "ci-api36-permission-denied"},
	} {
		t.Run(fmt.Sprintf("api%d", test.api), func(t *testing.T) {
			err, observation := runLaunchScenario(t, test.scenario, test.api)
			if err != nil || observation.Status != "CAPTURED" || observation.GateResult != "LAUNCH_OBSERVED_NOT_QUALIFIED" {
				t.Fatalf("complete composite with optional main/system denial rejected: err=%v gate=%s status=%s issues=%q streams=%+v events=%+v", err, observation.GateResult, observation.Status, observation.Issues, observation.StreamLifecycle, observation.SystemEvents)
			}
			denied := map[string]bool{"main": false, "system": false}
			for _, stream := range observation.StreamLifecycle {
				if _, optional := denied[stream.Buffer]; optional && stream.TerminalStatus != "DRAINED" {
					denied[stream.Buffer] = strings.Contains(strings.Join(stream.StderrExcerpt, " "), "permission denied")
				}
			}
			if !denied["main"] || !denied["system"] {
				t.Fatalf("permission-denied optional sources were not retained: %+v", observation.StreamLifecycle)
			}
			var eventLifecycle *diagnosticStreamLifecycle
			for index := range observation.StreamLifecycle {
				if observation.StreamLifecycle[index].Buffer == "events" {
					eventLifecycle = &observation.StreamLifecycle[index]
					break
				}
			}
			if eventLifecycle == nil || !knownNonPrivilegedSystemEventDenial(*eventLifecycle) ||
				observation.SystemEvents.Status != "OPTIONAL_SOURCE_UNAVAILABLE" {
				t.Fatalf("events permission denial was not retained as the exact optional source state: lifecycle=%+v events=%+v", eventLifecycle, observation.SystemEvents)
			}
			optionalSources := 0
			for _, source := range observation.CompositeSources {
				if source.Status == "OPTIONAL_SOURCE_UNAVAILABLE" {
					optionalSources++
					if source.Source != "ACTIVITY_MANAGER_EVENTS" || source.Parser != startupEventParserV2 ||
						source.Rejection != "NONPRIVILEGED_EVENT_BUFFER_PERMISSION_DENIED" || !startupDigestPattern.MatchString(source.RawDigest) {
						t.Fatalf("optional composite source was not narrowly bound: %+v", source)
					}
				}
			}
			if optionalSources != 1 {
				t.Fatalf("optional composite source count=%d, want the denied events source only", optionalSources)
			}
			assertVersionedCompositeBinding(t, observation)
		})
	}
}

func TestKnownNonPrivilegedSystemEventDenialRequiresTheExactBoundedShellLifecycle(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	valid := diagnosticStreamLifecycle{
		Buffer: "events", ExecutionBoundary: "ADB_SHELL", CommandIdentityStatus: "CAPTURED",
		CommandUID: 2000, CommandGID: 2000, CommandSELinuxContext: "u:r:shell:s0",
		StartStatus: "STARTED", ReadinessStatus: "OUTPUT_SINK_READY", TerminalStatus: "INCOMPLETE",
		TerminalReason: "STDERR_BEFORE_OWNED_CANCELLATION", CommandStatus: "CANCELLED", ExitCode: -1,
		ContextCancellationState: "CANCELED", CancellationRequestedUTC: now.Add(time.Second),
		FirstStderrUTC: now, LastStderrUTC: now.Add(time.Millisecond), CommandExitedUTC: now.Add(2 * time.Second),
		CancellationSequence: 2, FirstStderrSequence: 1, LastStderrSequence: 1, CommandExitSequence: 3,
		ExitRelativeToCancellation: "AFTER_OWNED_CANCELLATION", StderrObserved: true, StderrBytes: 27,
		StderrSHA256: strings.Repeat("a", 64), StderrExcerpt: []string{"permission denied"},
		StartCapturedBeforeStop: true, EndCapturedBeforeStop: true, IntentionallyStopped: true,
	}
	if !knownNonPrivilegedSystemEventDenial(valid) {
		t.Fatal("exact CI ordinary-shell permission denial was not recognized")
	}
	logcatPrefixed := valid
	logcatPrefixed.StderrExcerpt = []string{"logcat permission denied"}
	if !knownNonPrivilegedSystemEventDenial(logcatPrefixed) {
		t.Fatal("exact logcat-prefixed ordinary-shell permission denial was not recognized")
	}
	partialBeforeDenial := valid
	partialBeforeDenial.ParserComplete = true
	partialBeforeDenial.StdoutBytes = 128
	partialBeforeDenial.LastParsedRecord = diagnosticLaunchStreamRecord{DeviceNanos: 1, PID: 999, TID: 999, Category: "ACTIVITY_MANAGER"}
	if !knownNonPrivilegedSystemEventDenial(partialBeforeDenial) {
		t.Fatal("bounded partial output was incorrectly treated as proof that a denied stream was complete")
	}
	for _, test := range []struct {
		name   string
		mutate func(*diagnosticStreamLifecycle)
	}{
		{"wrong-buffer", func(value *diagnosticStreamLifecycle) { value.Buffer = "main" }},
		{"unknown-identity", func(value *diagnosticStreamLifecycle) { value.CommandIdentityStatus = "INCOMPLETE" }},
		{"wrong-uid", func(value *diagnosticStreamLifecycle) { value.CommandUID = 10123 }},
		{"wrong-selinux-domain", func(value *diagnosticStreamLifecycle) { value.CommandSELinuxContext = "u:r:untrusted_app:s0" }},
		{"missing-readiness", func(value *diagnosticStreamLifecycle) { value.ReadinessStatus = "NOT_AVAILABLE" }},
		{"unknown-order", func(value *diagnosticStreamLifecycle) { value.ExitRelativeToCancellation = "UNKNOWN" }},
		{"stderr-after-cancel", func(value *diagnosticStreamLifecycle) { value.FirstStderrSequence = 3 }},
		{"truncated-stderr", func(value *diagnosticStreamLifecycle) { value.StderrTruncated = true }},
		{"not-intentional", func(value *diagnosticStreamLifecycle) { value.IntentionallyStopped = false }},
		{"missing-marker", func(value *diagnosticStreamLifecycle) { value.EndCapturedBeforeStop = false }},
		{"wrong-reason", func(value *diagnosticStreamLifecycle) { value.TerminalReason = "PARSER_INCOMPLETE" }},
		{"ambiguous-diagnostic", func(value *diagnosticStreamLifecycle) { value.StderrExcerpt = []string{"error permission denied"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if knownNonPrivilegedSystemEventDenial(candidate) {
				t.Fatalf("ambiguous lifecycle was accepted: %+v", candidate)
			}
		})
	}
}

func TestStartupPackageStateParsesSupportedAPI26AndExtensionAwareOutput(t *testing.T) {
	for _, test := range []struct {
		name         string
		identityLine string
		versionLines string
	}{
		{"api26-user-id", "userId=10123", "versionCode=42 minSdk=26 targetSdk=36"},
		{"api34-app-id-empty-extensions", "appId=10123", "versionCode=42 minSdk=26 targetSdk=36\n    minExtensionVersions=[]"},
		{"api36-app-id-bound-extensions", "appId=10123", "versionCode=42 minSdk=26 targetSdk=36\n    minExtensionVersions=[30=7, 31=9]"},
		{"legacy-same-line-extensions", "userId=10123", "versionCode=42 minSdk=26 targetSdk=36 minExtensionVersions=[]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := "Packages:\n  Package [" + defaultAppPackage + "] (abc):\n" +
				"    " + test.identityLine + "\n    " + test.versionLines + "\n" +
				"    versionName=0.9.0-internal\n" +
				"    User 0: ceDataInode=123 installed=true hidden=false suspended=false distractionFlags=0 stopped=false notLaunched=false enabled=0 instant=false virtual=false\n"
			state := parseStartupPackageState(raw, defaultAppPackage, "terminal")
			if state.Status != "CAPTURED" || state.UserID != 10123 || state.VersionCode != 42 || state.VersionName != "0.9.0-internal" ||
				!state.Installed || state.Suspended || state.Stopped || state.Enabled != 0 {
				t.Fatalf("supported package output was not captured: %+v", state)
			}
		})
	}
}

func TestStartupPackageStateRejectsMalformedOrAmbiguousExtensionMetadata(t *testing.T) {
	for _, versionLines := range []string{
		"versionCode=42 minSdk=26 targetSdk=36 minExtensionVersions=[broken]",
		"versionCode=42 minSdk=26 targetSdk=36\n    minExtensionVersions=[broken]",
		"versionCode=42 minSdk=26 targetSdk=36\n    minExtensionVersions=[]\n    minExtensionVersions=[]",
		"versionCode=42 minSdk=26 targetSdk=36 unexpected=true",
	} {
		raw := "Packages:\n  Package [" + defaultAppPackage + "] (abc):\n" +
			"    appId=10123\n    " + versionLines + "\n" +
			"    versionName=0.9.0-internal\n" +
			"    User 0: installed=true suspended=false stopped=false enabled=0\n"
		if state := parseStartupPackageState(raw, defaultAppPackage, "terminal"); state.Status != "INCOMPLETE" {
			t.Fatalf("malformed extension metadata was accepted: %q -> %+v", versionLines, state)
		}
	}
}

func TestStartupPackageStateRejectsAmbiguousLegacyAndCurrentIdentityFields(t *testing.T) {
	raw := "Packages:\n  Package [" + defaultAppPackage + "] (abc):\n" +
		"    userId=10123\n    appId=10123\n" +
		"    versionCode=42 minSdk=26 targetSdk=36\n    minExtensionVersions=[]\n" +
		"    versionName=0.9.0-internal\n" +
		"    User 0: installed=true suspended=false stopped=false enabled=0\n"
	if state := parseStartupPackageState(raw, defaultAppPackage, "terminal"); state.Status != "INCOMPLETE" {
		t.Fatalf("ambiguous package identity fields were accepted: %+v", state)
	}
}

func TestCompositeStartupObserverDoesNotTurnIncompleteReplacementIntoAdmission(t *testing.T) {
	for _, scenario := range []string{"ci-api34-permission-denied-missing-events", "ci-api34-permission-denied-missing-crash", "ci-api34-permission-denied-missing-proc-status"} {
		t.Run(scenario, func(t *testing.T) {
			err, observation := runLaunchScenario(t, scenario, 34)
			if err == nil || !errors.Is(err, errLaunchIncomplete) || observation.GateResult != "BLOCKED" {
				t.Fatalf("missing required replacement observer was not blocked: err=%v gate=%s status=%s", err, observation.GateResult, observation.Status)
			}
		})
	}
}

func TestCompositeStartupObserverDefinitiveUnhealthyEvidenceFails(t *testing.T) {
	for _, scenario := range []string{"events-crash", "events-anr", "events-process-death", "dialog", "not-responding", "process-death"} {
		t.Run(scenario, func(t *testing.T) {
			err, observation := runLaunchScenario(t, scenario, 34)
			if err == nil || errors.Is(err, errLaunchIncomplete) || observation.GateResult != "FAIL" {
				t.Fatalf("complete correlated unhealthy evidence was not definitive FAIL: err=%v gate=%s status=%s issues=%q", err, observation.GateResult, observation.Status, observation.Issues)
			}
		})
	}
}

func TestCompositeStartupObserverIncompleteOrContradictoryEvidenceStaysClosed(t *testing.T) {
	blocked := []string{"conflicting-proc-uid", "wrong-proc-task-name", "truncated-proc-status", "truncated-events", "unknown-activity-format", "app-authored-only"}
	for _, scenario := range blocked {
		t.Run(scenario, func(t *testing.T) {
			err, observation := runLaunchScenario(t, scenario, 34)
			if err == nil || !errors.Is(err, errLaunchIncomplete) || observation.GateResult != "BLOCKED" {
				t.Fatalf("incomplete or conflicting composite did not block: err=%v gate=%s status=%s issues=%q", err, observation.GateResult, observation.Status, observation.Issues)
			}
		})
	}
	for _, scenario := range []string{"conflicting-activity", "stopped-package"} {
		t.Run(scenario, func(t *testing.T) {
			err, observation := runLaunchScenario(t, scenario, 34)
			if err == nil || errors.Is(err, errLaunchIncomplete) || observation.GateResult != "FAIL" {
				t.Fatalf("definitive wrong activity or stopped package did not fail: err=%v gate=%s status=%s issues=%q", err, observation.GateResult, observation.Status, observation.Issues)
			}
		})
	}
}

func TestCompositeStartupObserverDiscardsUnrelatedStructuredEventsWithoutLosingTargetOrder(t *testing.T) {
	err, observation := runLaunchScenario(t, "unrelated-events", 34)
	if err != nil || observation.GateResult != "LAUNCH_OBSERVED_NOT_QUALIFIED" || observation.SystemEvents.Status != "CAPTURED" {
		t.Fatalf("unrelated event changed target admission: err=%v gate=%s events=%+v", err, observation.GateResult, observation.SystemEvents)
	}
	if len(observation.SystemEvents.Events) != 1 || observation.SystemEvents.Events[0].Process != defaultAppPackage || observation.SystemEvents.Events[0].ReceivedOrder != 1 {
		t.Fatalf("unrelated event was retained or target order changed: %+v", observation.SystemEvents.Events)
	}
}

func TestStartupActivityParsersCanonicalizeOnlyTheExpectedPackage(t *testing.T) {
	for _, test := range []struct {
		api int
		raw string
	}{
		{26, "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n  mResumedActivity: ActivityRecord{abc u0 " + defaultAppPackage + "/.MainActivity t42}\n"},
		{34, "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n  topResumedActivity=ActivityRecord{abc u0 " + defaultAppPackage + "/.MainActivity t42}\n"},
		{36, "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n  topResumedActivity=ActivityRecord{abc u0 " + defaultAppPackage + "/org.kurdistanvpn.app.MainActivity t42}\n"},
	} {
		state := parseStartupActivityState(test.raw, defaultAppPackage, "terminal", test.api)
		if state.Status != "CAPTURED" || state.Component != defaultAppPackage+"/org.kurdistanvpn.app.MainActivity" || !state.Active || state.TaskID != 42 {
			t.Fatalf("API %d activity parser did not preserve exact canonical identity: %+v", test.api, state)
		}
	}
}

func TestStartupEvidenceDigestBindsDomainOrderAndFieldBoundaries(t *testing.T) {
	base := startupFramedDigest(startupEvidenceDigestV2, []byte("ab"), []byte("c"))
	for _, changed := range []string{
		startupFramedDigest(startupEvidenceDigestV2, []byte("a"), []byte("bc")),
		startupFramedDigest(startupEvidenceDigestV2, []byte("c"), []byte("ab")),
		startupFramedDigest(startupIdentityDigestV2, []byte("ab"), []byte("c")),
	} {
		if changed == base || !startupDigestPattern.MatchString(changed) {
			t.Fatalf("versioned digest framing failed to bind domain, order, or length: base=%s changed=%s", base, changed)
		}
	}
}

func TestStartupSubjectBindingRejectsEveryUnboundIdentity(t *testing.T) {
	valid := fixtureStartupSubject(34)
	observation := &launchObservation{api: 34, app: defaultAppPackage}
	if !validStartupSubject(valid, observation) {
		t.Fatal("complete synthetic subject was rejected")
	}
	mutations := []startupSubjectBinding{valid, valid, valid, valid, valid, valid}
	mutations[0].Status = "INCOMPLETE"
	mutations[1].Commit = strings.Repeat("0", 39)
	mutations[2].Tree = strings.Repeat("g", 40)
	mutations[3].AppAPKDigest = strings.Repeat("0", 63)
	mutations[4].Package = "org.kurdistanvpn.app.other"
	mutations[5].API = 36
	for index, mutation := range mutations {
		if validStartupSubject(mutation, observation) {
			t.Fatalf("unbound subject mutation %d was accepted: %+v", index, mutation)
		}
	}
}

func assertVersionedCompositeBinding(t *testing.T, observation launchObservation) {
	t.Helper()
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	if value["Schema"] != "kurdistan-launch-observation-v2" {
		t.Fatalf("launch observation schema=%v, want v2", value["Schema"])
	}
	for _, field := range []string{"Subject", "BootSession", "CompositeSources", "ActivityStates", "ProcessCrossChecks", "PackageState"} {
		if value[field] == nil {
			t.Fatalf("versioned launch observation omitted %s", field)
		}
	}
	packageSources := 0
	for _, source := range observation.CompositeSources {
		if source.Source != "PACKAGE_MANAGER" {
			continue
		}
		packageSources++
		if source.Parser != startupPackageParserV2 || source.Status != "CAPTURED" {
			t.Fatalf("package-state source was not bound to the current strict parser: %+v", source)
		}
	}
	if packageSources != 2 {
		t.Fatalf("package-state source count=%d, want before-launch and terminal", packageSources)
	}
}
