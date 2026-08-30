// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
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
				t.Fatalf("complete composite with optional main/system denial rejected: err=%v gate=%s status=%s issues=%q", err, observation.GateResult, observation.Status, observation.Issues)
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
			assertVersionedCompositeBinding(t, observation)
		})
	}
}

func TestCompositeStartupObserverDoesNotTurnIncompleteReplacementIntoAdmission(t *testing.T) {
	for _, scenario := range []string{"ci-api34-permission-denied-missing-events", "ci-api34-permission-denied-missing-crash"} {
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
	blocked := []string{"conflicting-proc-uid", "wrong-proc-command", "truncated-proc-status", "truncated-events", "unknown-activity-format", "app-authored-only"}
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
}
