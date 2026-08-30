// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLaunchGateRejectsRetainedCrashingProcess(t *testing.T) {
	err, observation := runLaunchScenario(t, "crashing", 26)
	if err == nil {
		t.Error("retained crashing process returned no error")
	}
	if observation.GateResult != "FAIL" {
		t.Errorf("complete retained-crash fixture gate_result=%s, want definitive FAIL", observation.GateResult)
	}
	if len(observation.ProcessHealth) != 1 {
		t.Errorf("retained-crash fixture health_count=%d, want exactly one observation", len(observation.ProcessHealth))
	} else if !observation.ProcessHealth[0].Crashing {
		t.Error("retained-crash fixture observation is not marked crashing")
	}
}

func logLaunchScenario(t *testing.T, err error, observation launchObservation) {
	t.Helper()
	errorCategory := "FAILURE"
	switch {
	case err == nil:
		errorCategory = "NONE"
	case errors.Is(err, context.DeadlineExceeded):
		errorCategory = "DEADLINE"
	case errors.Is(err, context.Canceled):
		errorCategory = "CANCELED"
	case errors.Is(err, errLaunchIncomplete):
		errorCategory = "INCOMPLETE"
	}
	t.Logf("fixture_package=%s fixture_pid=999 fixture_uid=10123 fixture_epoch=12345", defaultAppPackage)
	t.Logf("error_category=%s gate_result=%s evidence_status=%s incomplete=%t activity_status=%s health_count=%d issues=%q",
		errorCategory, observation.GateResult, observation.Status, observation.Status == "INCOMPLETE",
		observation.ActivityProcessStatus, len(observation.ProcessHealth), observation.Issues)
	for _, command := range observation.Commands {
		complete, statusOK := false, false
		for _, line := range command.Stdout {
			complete = complete || line == "Complete"
			statusOK = statusOK || line == "Status: ok"
		}
		t.Logf("command_phase=%s status=%s exit=%d duration_ms=%d truncated=%t terminal_complete=%t status_ok=%t",
			command.Phase, command.Status, command.ExitCode, command.DurationMS, command.Truncated, complete, statusOK)
	}
	for _, snapshot := range observation.Processes {
		t.Logf("snapshot_phase=%s status=%s process_count=%d", snapshot.Phase, snapshot.Status, len(snapshot.Processes))
		for _, process := range snapshot.Processes {
			t.Logf("process_target_package=%t pid_matches_fixture=%t uid_matches_fixture=%t epoch_matches_fixture=%t",
				process.Name == defaultAppPackage, process.PID == 999, process.UID == 10123, process.StartTicks == 12345)
		}
	}
	for index, health := range observation.ProcessHealth {
		t.Logf("health_index=%d target_package=%t pid_matches_fixture=%t uid_matches_fixture=%t crashing=%t not_responding=%t error_dialog=%t killed=%t",
			index, health.Process == defaultAppPackage, health.PID == 999, health.UID == 10123,
			health.Crashing, health.NotResponding, health.ErrorDialog, health.Killed)
	}
	for _, buffer := range observation.Logs {
		t.Logf("log_buffer=%s source=%s status=%s event_count=%d", buffer.Buffer, buffer.Source, buffer.Status, len(buffer.Events))
		for _, event := range buffer.Events {
			inWindow := event.DeviceNanos > observation.WindowStartNanos && event.DeviceNanos <= observation.WindowEndNanos
			t.Logf("event_in_window=%t target_crash=%t target_death=%t target_start=%t",
				inWindow, event.Tag == "AndroidRuntime" && event.PID == 999,
				event.Text == "process_lifecycle event=died pid=999 process="+defaultAppPackage,
				event.Text == "process_lifecycle event=Start_proc pid=999 process="+defaultAppPackage+" uid=10123")
		}
	}
	t.Logf("exit_status=%s exit_count=%d", observation.ExitStatus, len(observation.ExitRecords))
	for _, exit := range observation.ExitRecords {
		t.Logf("exit_target_package=%t pid_matches_fixture=%t uid_matches_fixture=%t in_window=%t reason=%d status=%d",
			exit.Process == defaultAppPackage, exit.PID == 999, exit.UID == 10123,
			exit.DeviceNanos >= observation.WindowStartNanos && exit.DeviceNanos <= observation.WindowEndNanos,
			exit.Reason, exit.Status)
	}
}

func TestLaunchGateRejectsTargetApplicationErrorDialog(t *testing.T) {
	err, observation := runLaunchScenario(t, "dialog", 26)
	if err == nil || observation.GateResult != "FAIL" || len(observation.ProcessHealth) != 1 || !observation.ProcessHealth[0].ErrorDialog {
		t.Fatal("launch accepted nonempty PID 999 while its target ProcessRecord owns AppErrorDialog")
	}
}

func TestLaunchGateCompleteCurrentCrashProducesDefinitiveFailure(t *testing.T) {
	err, observation := runLaunchScenario(t, "current-crash", 34)
	if err == nil || errors.Is(err, errLaunchIncomplete) || observation.GateResult != "FAIL" || observation.Status != "CAPTURED" {
		t.Fatalf("complete current crash must produce definitive FAIL: err=%v gate=%s evidence=%s issues=%q", err, observation.GateResult, observation.Status, observation.Issues)
	}
}

func TestCommandTransportAbsentFailsClosed(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	client := adbClient{path: executable, evidenceDir: t.TempDir(), timeline: &diagnosticTimeline{Started: time.Now()}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stdout, stderr, record, err := client.diagnosticCommand(ctx, "absent-transport", 64, "-test.run=^TestDiagnosticCommandFixtureProcess$", "--", "success")
	if err == nil || record.Status == "CAPTURED" || stdout != "" || stderr != "" {
		t.Fatalf("absent transport executed a child or supplied evidence: err=%v status=%s stdout_bytes=%d stderr_bytes=%d", err, record.Status, len(stdout), len(stderr))
	}
}

func TestLaunchGateHealthyPlatformVariantsRemainUnqualified(t *testing.T) {
	for _, api := range []int{26, 34, 36} {
		t.Run(strconv.Itoa(api), func(t *testing.T) {
			scenario := "healthy"
			if api >= 34 {
				scenario = "modern-healthy"
			}
			err, observation := runLaunchScenario(t, scenario, api)
			if err != nil || observation.Status != "CAPTURED" || observation.GateResult != "LAUNCH_OBSERVED_NOT_QUALIFIED" {
				t.Fatalf("complete healthy platform fixture rejected: %v %s %v", err, observation.GateResult, observation.Issues)
			}
		})
	}
}

func runLaunchTest(t *testing.T, scenario string, api int) error {
	err, _ := runLaunchScenario(t, scenario, api)
	return err
}

func TestLaunchGateFailsClosedWithoutCompleteHealthyObservations(t *testing.T) {
	for _, scenario := range []string{
		"not-responding", "modern-crashing", "modern-dialog", "process-death", "epoch-change", "uid-change",
		"empty-launch", "status-only", "no-complete", "duplicate-status", "unknown-launch", "wrong-activity", "malformed-timing",
		"missing-process-observation", "missing-activity-observation", "unterminated-process-record",
		"missing-markers", "malformed-log", "terminated-stream", "missing-exit-observation", "current-crash", "current-exit", "malformed-crash-flag",
	} {
		t.Run(scenario, func(t *testing.T) {
			if err := runLaunchTest(t, scenario, 34); err == nil {
				t.Fatal("incomplete or unhealthy launch was accepted: " + scenario)
			}
		})
	}
}

func TestLaunchGateHealthyCurrentAttemptIgnoresStaleOrUnrelatedCrashes(t *testing.T) {
	for _, scenario := range []string{"healthy", "modern-healthy", "starting-intent", "stale-crash", "unrelated-crash", "stale-exit", "unrelated-exit"} {
		t.Run(scenario, func(t *testing.T) {
			if err, observation := runLaunchScenario(t, scenario, 34); err != nil {
				t.Fatalf("healthy current attempt rejected: %v; status=%s issues=%v", err, observation.Status, observation.Issues)
			}
		})
	}
}

func TestLaunchGateTimedOutCommandCannotPassWithRetainedPID(t *testing.T) {
	started := time.Now()
	err, observation := runLaunchScenario(t, "timeout", 26)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 8*time.Second {
		t.Fatalf("launch timeout was accepted, replaced, or unbounded: %v", err)
	}
	for _, command := range observation.Commands {
		if command.Phase == "am-start-W" && command.Status == "DEADLINE" && command.ExitCode != 0 {
			return
		}
	}
	t.Fatal("test did not exercise the launch command deadline")
}

func runLaunchScenario(t *testing.T, scenario string, api int) (error, launchObservation) {
	t.Helper()
	err, observation, _ := runLaunchFixture(t, scenario, api)
	return err, observation
}

func fixtureNonCancellationExitError(t *testing.T) error {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	err = exec.Command(executable, "-test.run=^TestDiagnosticCommandFixtureProcess$", "--", "nonzero").Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 7 {
		t.Fatalf("fixture did not produce the required non-cancellation exit failure: %v", err)
	}
	return err
}

func runLaunchFixture(t *testing.T, scenario string, api int) (error, launchObservation, *launchFixtureTransport) {
	t.Helper()
	root := t.TempDir()
	fixture := newLaunchFixtureTransport(scenario)
	fixture.api = api
	if scenario == "post-cancellation-exit-failure" {
		fixture.streamTerminalOverride = fixtureNonCancellationExitError(t)
	}
	client := newADBClient("fixture-adb", "emulator-5554", root, &diagnosticTimeline{Started: time.Now()})
	client.transport = &commandTransport{run: fixture.run, start: fixture.start}
	budget := 12 * time.Second
	if scenario == "timeout" {
		budget = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	err := launchSmokeWithDiagnostics(ctx, client, options{
		appPackage: defaultAppPackage, testPackage: defaultTestPackage, expectedAPI: api, expectedABI: "x86_64",
		startupSubject: fixtureStartupSubject(api),
	})
	var observation launchObservation
	data, readErr := os.ReadFile(filepath.Join(root, "10-launch-details.txt"))
	if readErr != nil || json.Unmarshal(data, &observation) != nil {
		t.Fatal("launch observation was not preserved")
	}
	fixture.assertClosed(t)
	logLaunchScenario(t, err, observation)
	return err, observation, fixture
}

func fixtureStartupSubject(api int) startupSubjectBinding {
	return startupSubjectBinding{
		Status: "CAPTURED", Repository: startupRepositoryIdentity,
		Commit: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40),
		AppAPKDigest: strings.Repeat("3", 64), AppAPKBytes: 1024,
		TestAPKDigest: strings.Repeat("4", 64), TestAPKBytes: 2048,
		Package: defaultAppPackage, TestPackage: defaultTestPackage, API: api, ABI: "x86_64",
	}
}

type fixtureCommand struct {
	kind      string
	args      []string
	waitDelay time.Duration
	deadline  time.Time
	remaining time.Duration
}

type fixtureOutputChunk struct {
	raw       string
	delivered chan error
}

type fixtureStream struct {
	mu          sync.Mutex
	chunks      chan fixtureOutputChunk
	ready       chan struct{}
	done        chan struct{}
	stderr      io.Writer
	stderrMode  string
	writeErr    error
	terminalErr error
	waits       atomic.Int32
	completed   atomic.Int32
	cancelled   atomic.Int32
	closes      atomic.Int32
	eofs        atomic.Int32
	admitted    atomic.Int64
	delivered   atomic.Int64
	rejected    atomic.Int64
}

func newFixtureStream(ctx context.Context, output, stderr io.Writer, terminate <-chan struct{}, stderrMode, stderrBefore string, terminalOverride error) *fixtureStream {
	stream := &fixtureStream{
		chunks: make(chan fixtureOutputChunk), ready: make(chan struct{}), done: make(chan struct{}),
		stderr: stderr, stderrMode: stderrMode,
	}
	// Start owns the output reader. Wait only observes its terminal state.
	go func() {
		close(stream.ready)
		for chunk := range stream.chunks {
			n, err := io.WriteString(output, chunk.raw)
			stream.delivered.Add(int64(n))
			if err == nil && n != len(chunk.raw) {
				err = io.ErrShortWrite
			}
			stream.writeErr = errors.Join(stream.writeErr, err)
			chunk.delivered <- err
		}
		stream.eofs.Add(1)
		stream.completed.Add(1)
		close(stream.done)
	}()
	<-stream.ready
	if stderrMode == "before-owned-cancellation" {
		if stderrBefore == "" {
			stderrBefore = "logcat: invalid stream before owned cancellation credential=synthetic-secret\n"
		}
		_, stream.writeErr = io.WriteString(stderr, stderrBefore)
	}
	go func() {
		if terminate == nil {
			<-ctx.Done()
			stream.cancelled.Add(1)
		} else {
			select {
			case <-terminate:
			case <-ctx.Done():
				stream.cancelled.Add(1)
			}
		}
		if stderrMode == "after-owned-cancellation" {
			_, stream.writeErr = io.WriteString(stream.stderr, "logcat: stream terminated by owned cancellation credential=synthetic-secret\n")
		}
		// Do not close output until the current accepted chunk is fully copied.
		// A later write returns an explicit error instead of losing bytes.
		stream.mu.Lock()
		defer stream.mu.Unlock()
		if terminalOverride != nil {
			stream.terminalErr = terminalOverride
		} else if terminate == nil || ctx.Err() != nil {
			stream.terminalErr = ctx.Err()
		}
		stream.closes.Add(1)
		close(stream.chunks)
	}()
	return stream
}

func (stream *fixtureStream) write(raw string) error {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closes.Load() != 0 {
		stream.rejected.Add(int64(len(raw)))
		if stream.terminalErr != nil {
			return stream.terminalErr
		}
		return io.ErrClosedPipe
	}
	stream.admitted.Add(int64(len(raw)))
	chunk := fixtureOutputChunk{raw: raw, delivered: make(chan error, 1)}
	stream.chunks <- chunk
	return <-chunk.delivered
}

func (stream *fixtureStream) wait() error {
	if stream.waits.Add(1) != 1 {
		return errors.New("stream waited more than once")
	}
	<-stream.done
	return errors.Join(stream.writeErr, stream.terminalErr)
}

// Only raw command bytes cross this seam. Production owns the parsers,
// bounded writers, context budgets, identity correlation and gate result.
type launchFixtureTransport struct {
	mu                     sync.Mutex
	scenario               string
	api                    int
	clock                  time.Time
	wallClock              time.Time
	launched               time.Time
	wallLaunch             time.Time
	processes              int
	logs                   map[string]string
	markers                []fixtureMarker
	streams                map[string]*fixtureStream
	commands               []fixtureCommand
	blocked                chan struct{}
	terminate              chan struct{}
	terminated             bool
	streamTerminalOverride error
}

type fixtureMarker struct {
	tag       string
	text      string
	monotonic time.Time
	wall      time.Time
}

func newLaunchFixtureTransport(scenario string) *launchFixtureTransport {
	return &launchFixtureTransport{
		scenario:  scenario,
		clock:     time.Unix(101, 0).UTC(),
		wallClock: time.Unix(1_700_000_000, 0).UTC(),
		logs:      make(map[string]string),
		streams:   make(map[string]*fixtureStream),
		blocked:   make(chan struct{}),
		terminate: make(chan struct{}),
	}
}

func (fixture *launchFixtureTransport) record(kind, path string, args []string, waitDelay time.Duration, ctx context.Context) error {
	if path != "fixture-adb" || len(args) < 3 || args[0] != "-s" || args[1] != "emulator-5554" || args[2] != "shell" {
		return errors.New("unexpected fixture command identity or argument order")
	}
	deadline, _ := ctx.Deadline()
	fixture.commands = append(fixture.commands, fixtureCommand{
		kind: kind, args: append([]string(nil), args...), waitDelay: waitDelay,
		deadline: deadline, remaining: time.Until(deadline),
	})
	return nil
}

func fixtureStamp(at time.Time) string {
	return fmt.Sprintf("%d.%09d", at.Unix(), at.Nanosecond())
}

func fixtureAPIForScenario(scenario string) int {
	for _, api := range []int{26, 34, 36} {
		if strings.Contains(scenario, "api"+strconv.Itoa(api)) {
			return api
		}
	}
	return 34
}

// Called with fixture.mu held. Raw log creation, live delivery and fallback
// snapshots share the same bytes, without parsed-result injection.
func (fixture *launchFixtureTransport) appendLog(buffer, raw string) error {
	fixture.logs[buffer] += raw
	if stream := fixture.streams[buffer]; stream != nil {
		return stream.write(raw)
	}
	return nil
}

func (fixture *launchFixtureTransport) run(ctx context.Context, path string, args []string, stdout, stderr io.Writer, waitDelay time.Duration) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if err := fixture.record("run", path, args, waitDelay, ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Device timestamps follow command causality, not the host wall clock's
	// resolution. Real context deadlines and the survival interval are untouched.
	fixture.clock = fixture.clock.Add(time.Millisecond)
	fixture.wallClock = fixture.wallClock.Add(time.Millisecond)
	args = args[3:]
	command := strings.Join(args, " ")
	scenario := fixture.scenario
	afterSurvival := fixture.processes >= 3
	switch {
	case command == "fixture-block":
		close(fixture.blocked)
		<-ctx.Done()
		return ctx.Err()
	case command == "fixture-bounds":
		fmt.Fprint(stdout, "ab")
		fmt.Fprint(stderr, "cd")
		fmt.Fprint(stdout, "efg")
	case command == "id":
		if scenario == "unknown-shell-identity" {
			fmt.Fprintln(stdout, "uid=1234(unknown) gid=1234(unknown) groups=1234(unknown)")
		} else {
			fmt.Fprintln(stdout, "uid=2000(shell) gid=2000(shell) groups=2000(shell)")
		}
	case command == "cat /proc/self/attr/current":
		if scenario == "unknown-shell-context" {
			fmt.Fprintln(stdout, "unconfined")
		} else {
			fmt.Fprintln(stdout, "u:r:shell:s0")
		}
	case command == "logcat --help":
		fmt.Fprintln(stdout, "Usage: logcat [options] [filterspecs]\n  -b <buffer>  load an alternate log buffer")
	case strings.HasPrefix(command, "logcat -b ") && strings.Contains(command, " -d -t 1 "):
		if (scenario == "permission-denied-preflight" && (args[2] == "main" || args[2] == "system")) ||
			(scenario == "ci-api36-permission-denied" && args[2] == "system") ||
			(strings.HasSuffix(scenario, "missing-events") && args[2] == "events") ||
			(strings.HasSuffix(scenario, "missing-crash") && args[2] == "crash") {
			fmt.Fprintln(stderr, "logcat: permission denied credential=synthetic-secret")
			return errors.New("exit status 1")
		}
	case command == "date +%z":
		fmt.Fprintln(stdout, "+0000")
	case strings.HasPrefix(command, "log -p i -t KurdistanClockProbe "):
		marker := args[len(args)-1]
		fixture.markers = append(fixture.markers, fixtureMarker{
			tag: clockProbeTag, text: marker, monotonic: fixture.clock, wall: fixture.wallClock,
		})
		if err := fixture.appendLog("main", fixtureStamp(fixture.clock)+" 11 11 I "+clockProbeTag+": "+marker+"\n"); err != nil {
			return err
		}
		if scenario == "api34-clock-tail-eviction" {
			for sequence := 0; sequence < 65; sequence++ {
				fixture.logs["main"] += fmt.Sprintf("%s 22 22 I UnrelatedTag: noise-%02d\n", fixtureStamp(fixture.clock), sequence)
			}
		}
		return nil
	case strings.HasPrefix(command, "log -p i -t KurdistanLaunchProbe "):
		if scenario == "missing-markers" {
			return nil
		}
		marker := args[len(args)-1]
		markerType := ""
		if fields := strings.Split(marker, ":"); len(fields) >= 2 {
			markerType = fields[1]
		}
		if scenario == "terminated-stream" && markerType == "END" {
			if !fixture.terminated {
				close(fixture.terminate)
				fixture.terminated = true
			}
			for _, stream := range fixture.streams {
				select {
				case <-stream.done:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
		fixture.markers = append(fixture.markers, fixtureMarker{
			tag: launchProbeTag, text: marker, monotonic: fixture.clock, wall: fixture.wallClock,
		})
		raw := fixtureStamp(fixture.clock) + " 11 11 I " + launchProbeTag + ": " + marker + "\n"
		if scenario == "terminated-stream" && markerType == "END" {
			fixture.logs["main"] += raw
			return nil
		}
		if scenario == "api34-start-stream-loss" && markerType == "START" {
			fixture.logs["main"] += raw
			return nil
		}
		return fixture.appendLog("main", raw)
	case command == "cmd package resolve-activity --brief -n "+defaultAppPackage+"/org.kurdistanvpn.app.MainActivity":
		fmt.Fprintln(stdout, defaultAppPackage+"/org.kurdistanvpn.app.MainActivity")
	case command == "ps -A -o UID,PID,PPID,NAME":
		fixture.processes++
		afterSurvival = fixture.processes >= 3
		if scenario == "missing-process-observation" {
			return errors.New("fixture process query failed")
		}
		if scenario == "truncated-process-output" && fixture.processes == 4 {
			fmt.Fprint(stdout, strings.Repeat("x", (256<<10)+1))
			return nil
		}
		fmt.Fprintln(stdout, "UID PID PPID NAME")
		if !fixture.launched.IsZero() && !(scenario == "process-death" && afterSurvival) {
			uid := 10123
			if scenario == "uid-change" && afterSurvival {
				uid++
			}
			fmt.Fprintf(stdout, "%d 999 111 %s\n", uid, defaultAppPackage)
			if scenario == "extra-process-output" && fixture.processes == 4 {
				fmt.Fprintf(stdout, "%d 999 111 %s\n", uid, defaultAppPackage)
			}
		}
	case command == "cat /proc/999/stat":
		if fixture.processes == 4 {
			switch scenario {
			case "missing-terminal-epoch":
				return errors.New("fixture terminal epoch unavailable")
			case "terminal-command-timeout":
				<-ctx.Done()
				return ctx.Err()
			case "malformed-terminal-epoch":
				fmt.Fprintln(stdout, "malformed stat")
				return nil
			}
		}
		ticks := 12345
		if (scenario == "epoch-change" && afterSurvival) || (scenario == "pid-reuse" && fixture.processes == 4) {
			ticks++
		}
		fmt.Fprintf(stdout, "999 (synthetic process) S 111 111 111 0 -1 0 0 0 0 0 1 2 3 4 5 6 1 0 %d\n", ticks)
	case command == "cat /proc/999/status":
		if scenario == "ci-api34-permission-denied-missing-proc-status" {
			return errors.New("fixture proc status unavailable")
		}
		if scenario == "truncated-proc-status" {
			fmt.Fprint(stdout, strings.Repeat("x", (256<<10)+1))
			return nil
		}
		uid := 10123
		if scenario == "conflicting-proc-uid" {
			uid++
		}
		name, ok := androidKernelTaskName(defaultAppPackage)
		if !ok {
			return errors.New("fixture package does not have a valid Android kernel task name")
		}
		if scenario == "wrong-proc-task-name" {
			name = "unrelated"
		}
		fmt.Fprintf(stdout, "Name:\t%s\nState:\tS (sleeping)\nTgid:\t999\nPid:\t999\nPPid:\t111\nUid:\t%d\t%d\t%d\t%d\n", name, uid, uid, uid, uid)
	case command == "cat /proc/sys/kernel/random/boot_id":
		if scenario == "app-authored-only" {
			return errors.New("fixture boot identity unavailable")
		}
		fmt.Fprintln(stdout, "12345678-1234-4abc-8def-1234567890ab")
	case command == "getprop ro.build.fingerprint":
		api := fixture.api
		if api == 0 {
			api = fixtureAPIForScenario(scenario)
		}
		fmt.Fprintf(stdout, "google/sdk_gphone_x86_64/emu64xa:%d/TEST/123:userdebug/test-keys\n", api)
	case command == "dumpsys package "+defaultAppPackage:
		if scenario == "app-authored-only" {
			return errors.New("fixture package state unavailable")
		}
		stopped := "false"
		if scenario == "stopped-package" || (strings.HasPrefix(scenario, "ci-api") && fixture.launched.IsZero()) {
			stopped = "true"
		}
		identityName := "userId"
		versionSuffix := ""
		versionMetadata := ""
		if fixture.api >= 34 || strings.Contains(scenario, "api34") || strings.Contains(scenario, "api36") {
			identityName = "appId"
			versionMetadata = "\n    minExtensionVersions=[]"
		}
		fmt.Fprintf(stdout, "Activity Resolver Table:\nPackages:\n  Package [%s] (abc):\n    %s=10123\n    versionCode=42 minSdk=26 targetSdk=36%s%s\n    versionName=0.9.0-internal\n    User 0: ceDataInode=123 installed=true hidden=false suspended=false distractionFlags=0 stopped=%s notLaunched=false enabled=0 instant=false virtual=false\n", defaultAppPackage, identityName, versionSuffix, versionMetadata, stopped)
	case command == "pidof "+defaultAppPackage:
		if scenario == "process-death" {
			return errors.New("fixture target no longer exists")
		}
		fmt.Fprintln(stdout, "999")
	case command == "am start -W -f 0x10008000 -n "+defaultAppPackage+"/org.kurdistanvpn.app.MainActivity":
		fixture.launched = fixture.clock
		fixture.wallLaunch = fixture.wallClock
		system := fixtureStamp(fixture.launched) + " 10 10 I ActivityManager: Start proc 999:" + defaultAppPackage + "/u0a123 for activity\n"
		if scenario == "stale-dialog" {
			system = fixtureStamp(fixture.launched.Add(-time.Second)) +
				" 10 10 I ActivityManager: AppErrorDialog for " + defaultAppPackage + "\n" + system
		}
		if err := fixture.appendLog("system", system); err != nil {
			return err
		}
		event := fixtureStamp(fixture.launched) + " 1000 1000 I am_proc_start: [0,999,10123," + defaultAppPackage + ",activity," + defaultAppPackage + "/.MainActivity]\n"
		if scenario == "unrelated-events" {
			event = fixtureStamp(fixture.launched) + " 1000 1000 I am_proc_start: [0,888,10124,example.unrelated,service,example.unrelated/.Worker]\n" + event
		}
		if scenario == "events-anr" {
			event += fixtureStamp(fixture.launched.Add(time.Millisecond)) + " 1000 1000 I am_anr: [0,999," + defaultAppPackage + ",0,synthetic]\n"
		}
		if scenario == "events-crash" {
			event += fixtureStamp(fixture.launched.Add(time.Millisecond)) + " 1000 1000 I am_crash: [0,999," + defaultAppPackage + ",0,java.lang.IllegalStateException,redacted,File.kt,1,0]\n"
		}
		if scenario == "events-process-death" {
			event += fixtureStamp(fixture.launched.Add(time.Millisecond)) + " 1000 1000 I am_proc_died: [0,999," + defaultAppPackage + ",0,2]\n"
		}
		if scenario == "truncated-events" {
			event += strings.Repeat("x", (512<<10)+1)
		}
		if err := fixture.appendLog("events", event); err != nil {
			return err
		}
		if strings.HasSuffix(scenario, "crash") {
			at, pid, app := fixture.clock, 999, defaultAppPackage
			if scenario == "stale-crash" {
				at = at.Add(-time.Second)
			}
			if scenario == "unrelated-crash" {
				pid, app = 888, "example.unrelated"
			}
			prefix := fmt.Sprintf("%s %d %d E AndroidRuntime: ", fixtureStamp(at), pid, pid)
			// A complete, privacy-safe exception, not a message requiring redaction.
			raw := prefix + "FATAL EXCEPTION: main\n" + prefix + fmt.Sprintf("Process: %s, PID: %d\n", app, pid) +
				prefix + "java.lang.IllegalStateException: Check failed.\n" +
				prefix + "at org.kurdistanvpn.app.ProductRootViewModel.onCreate(Phase9ViewModel.kt:95)\n"
			if err := fixture.appendLog("crash", raw); err != nil {
				return err
			}
		}
		if scenario == "malformed-log" {
			if err := fixture.appendLog("crash", "unparseable evidence\n"); err != nil {
				return err
			}
		}
		if scenario == "timeout" {
			<-ctx.Done()
			return ctx.Err()
		}
		switch scenario {
		case "empty-launch":
			return nil
		case "status-only":
			fmt.Fprintln(stdout, "Status: ok")
			return nil
		case "no-complete":
			fmt.Fprintln(stdout, "Status: ok\nActivity: "+defaultAppPackage+"/org.kurdistanvpn.app.MainActivity\nWaitTime: 30")
			return nil
		case "duplicate-status":
			fmt.Fprintln(stdout, "Status: error")
		case "unknown-launch":
			fmt.Fprintln(stdout, "UNKNOWN_RESULT")
		case "wrong-activity":
			fmt.Fprintln(stdout, "Status: ok\nActivity: example.other/MainActivity\nWaitTime: 30\nComplete")
			return nil
		case "malformed-timing":
			fmt.Fprintln(stdout, "Status: ok\nActivity: "+defaultAppPackage+"/org.kurdistanvpn.app.MainActivity\nTotalTime: UNKNOWN\nWaitTime: 30\nComplete")
			return nil
		case "starting-intent":
			fmt.Fprintln(stdout, "Starting: Intent { flg=0x10008000 cmp="+defaultAppPackage+"/org.kurdistanvpn.app.MainActivity }")
		}
		fmt.Fprintln(stdout, "Status: ok\nActivity: "+defaultAppPackage+"/org.kurdistanvpn.app.MainActivity\nThisTime: 15\nTotalTime: 25\nWaitTime: 30\nComplete")
	case command == "dumpsys activity processes "+defaultAppPackage:
		if scenario == "missing-activity-observation" {
			return errors.New("fixture activity query failed")
		}
		pidState := "pid=999 starting=false\n    curProcState=2 repProcState=2"
		if strings.HasPrefix(scenario, "modern-") {
			pidState = "pid=999\n    curProcState=TOP setProcState=TOP"
		}
		fmt.Fprintln(stdout, "ACTIVITY MANAGER RUNNING PROCESSES (dumpsys activity processes)\n  All known processes:\n  *APP* UID 10123 ProcessRecord{abc 999:"+defaultAppPackage+"/u0a123}\n    user #0 uid=10123 gids={}\n    "+pidState+"\n    packageList={"+defaultAppPackage+"}")
		switch scenario {
		case "crashing":
			fmt.Fprintln(stdout, "    debugging=false crashing=true null notResponding=false null bad=false")
		case "dialog":
			fmt.Fprintln(stdout, "    debugging=false crashing=false com.android.server.am.AppErrorDialog@abc notResponding=false null bad=false")
		case "not-responding":
			fmt.Fprintln(stdout, "    crashing=false null notResponding=true null bad=false")
		case "malformed-crash-flag":
			fmt.Fprintln(stdout, "    crashing=unknown notResponding=false")
		case "modern-crashing":
			fmt.Fprintln(stdout, "    mCrashing=true null mNotResponding=false null bad=false")
		case "modern-dialog":
			fmt.Fprintln(stdout, "    mCrashing=false [com.android.server.am.AppErrorDialog@abc] mNotResponding=false null bad=false")
		case "unterminated-process-record":
			return nil
		}
		if scenario == "unrelated-dialog" {
			fmt.Fprintln(stdout, "  *APP* UID 10124 ProcessRecord{def 888:example.unrelated/u0a124}\n    user #0 uid=10124\n    pid=888\n    curProcState=TOP setProcState=TOP\n    mCrashing=false [com.android.server.am.AppErrorDialog@def] mNotResponding=false")
		}
		fmt.Fprintln(stdout, "  Process LRU list (sorted by oom_adj, 1 total, non-act at 0, non-svc at 0):")
	case command == "dumpsys activity activities "+defaultAppPackage:
		if scenario == "app-authored-only" {
			return errors.New("fixture activity state unavailable")
		}
		if scenario == "unknown-activity-format" {
			fmt.Fprintln(stdout, "ACTIVITY MANAGER ACTIVITIES (unknown future format)")
			return nil
		}
		component := defaultAppPackage + "/.MainActivity"
		if scenario == "conflicting-activity" {
			component = "example.unrelated/.OtherActivity"
		}
		if fixture.api == 26 || strings.HasPrefix(scenario, "ci-api26-") {
			fmt.Fprintf(stdout, "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n  Stack #1:\n    mResumedActivity: ActivityRecord{abc u0 %s t42}\n", component)
		} else {
			fmt.Fprintf(stdout, "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n  topResumedActivity=ActivityRecord{abc u0 %s t42}\n  * Hist #0: ActivityRecord{abc u0 %s t42}\n    state=RESUMED\n", component, component)
		}
	case command == "dumpsys activity exit-info "+defaultAppPackage:
		if scenario == "missing-exit-observation" {
			return nil
		}
		fmt.Fprintln(stdout, "ACTIVITY MANAGER PROCESS EXIT INFO (dumpsys activity exit-info)\nLast Timestamp of Persistence Into Persistent Storage: 1970-01-01 00:00:00.000")
		if strings.HasSuffix(scenario, "exit") {
			at, uid := fixture.wallLaunch.Add(time.Millisecond), 10123
			if scenario == "stale-exit" {
				at = at.Add(-time.Hour)
			}
			if scenario == "unrelated-exit" {
				uid++
			}
			fmt.Fprintf(stdout, "ApplicationExitInfo #0:\n timestamp=%s pid=999 realUid=%d\n process=%s reason=4 (CRASH) status=0\n", at.Format("2006-01-02 15:04:05.000"), uid, defaultAppPackage)
		}
	case command == "logcat -b all -t 4096 -v brief *:W":
		fmt.Fprint(stdout, fixture.logs["crash"])
	case len(args) > 3 && args[0] == "logcat" && args[1] == "-b":
		monotonic := strings.Contains(command, "-v threadtime -v monotonic -v usec")
		epoch := strings.Contains(command, "-v threadtime -v epoch -v usec")
		if (!monotonic && !epoch) || !strings.Contains(" "+command+" ", " -d ") {
			return errors.New("unexpected fixture log snapshot options")
		}
		value, known := fixture.logs[args[2]]
		if !known && args[2] != "crash" && args[2] != "main" && args[2] != "system" {
			return errors.New("unexpected fixture log buffer")
		}
		for _, tag := range []string{clockProbeTag, "KurdistanLaunchProbe"} {
			if !strings.Contains(command, tag+":I") {
				continue
			}
			if tag == clockProbeTag && scenario == "api34-clock-tail-eviction" {
				value = fixtureClockSnapshot(value, args)
				continue
			}
			value = ""
			for _, marker := range fixture.markers {
				if marker.tag != tag {
					continue
				}
				if scenario == "api36-start-snapshot-loss" && strings.Contains(" "+command+" ", " -t ") &&
					strings.Contains(marker.text, ":START:") {
					continue
				}
				stamp := marker.monotonic
				if epoch {
					stamp = marker.wall
				}
				value += fixtureStamp(stamp) + " 11 11 I " + marker.tag + ": " + marker.text + "\n"
			}
		}
		fmt.Fprint(stdout, value)
	default:
		return fmt.Errorf("unexpected fixture command: %q", args)
	}
	return nil
}

func fixtureClockSnapshot(raw string, args []string) string {
	lines := strings.Split(strings.TrimSuffix(strings.ReplaceAll(raw, "\r\n", "\n"), "\n"), "\n")
	for index := 0; index+1 < len(args); index++ {
		if args[index] != "-t" {
			continue
		}
		count, err := strconv.Atoi(args[index+1])
		if err == nil && count >= 0 && len(lines) > count {
			lines = lines[len(lines)-count:]
		}
		break
	}
	var filter *regexp.Regexp
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "-e" {
			filter = regexp.MustCompile(args[index+1])
			break
		}
	}
	var selected []string
	for _, line := range lines {
		const prefix = " I KurdistanClockProbe: "
		position := strings.Index(line, prefix)
		if position < 0 {
			continue
		}
		message := line[position+len(prefix):]
		if filter == nil || filter.MatchString(message) {
			selected = append(selected, line)
		}
	}
	if len(selected) == 0 {
		return ""
	}
	return strings.Join(selected, "\n") + "\n"
}

func (fixture *launchFixtureTransport) start(ctx context.Context, path string, args []string, stdout, stderr io.Writer, waitDelay time.Duration) (func() error, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if err := fixture.record("start", path, args, waitDelay, ctx); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fixture.scenario == "unavailable-stream" ||
		(strings.HasSuffix(fixture.scenario, "missing-events") && strings.Contains(strings.Join(args, " "), "logcat -b events ")) ||
		(strings.HasSuffix(fixture.scenario, "missing-crash") && strings.Contains(strings.Join(args, " "), "logcat -b crash ")) {
		return nil, errors.New("fixture stream unavailable")
	}
	if fixture.scenario == "stream-without-wait" {
		return nil, nil
	}
	args = args[3:]
	if len(args) < 3 {
		return nil, errors.New("incomplete stream arguments")
	}
	buffer := args[2]
	want := []string{"logcat", "-b", buffer, "-v", "threadtime", "-v", "monotonic", "-v", "usec", "-T", "1",
		"AndroidRuntime:E", "ActivityManager:I", "ActivityTaskManager:I", "KurdistanLaunchProbe:I", "*:S"}
	if buffer == "events" {
		want = []string{"logcat", "-b", "events", "-v", "threadtime", "-v", "monotonic", "-v", "usec", "-T", "1",
			"am_proc_start:I", "am_proc_died:I", "am_kill:I", "am_anr:I", "am_crash:I", "*:S"}
	}
	if (buffer != "crash" && buffer != "events" && buffer != "main" && buffer != "system") || !reflect.DeepEqual(args, want) || fixture.streams[buffer] != nil {
		return nil, errors.New("unexpected or duplicate fixture stream")
	}
	if fixture.scenario == "invalid-stream-command" {
		_, _ = io.WriteString(stderr, "logcat: invalid buffer configuration credential=synthetic-secret\n")
		return nil, errors.New("fixture logcat command rejected")
	}
	var terminate <-chan struct{}
	if fixture.scenario == "terminated-stream" {
		terminate = fixture.terminate
	}
	stderrMode, stderrBefore := "", ""
	if buffer == "main" || buffer == "system" || (buffer == "events" && strings.HasPrefix(fixture.scenario, "ci-api")) {
		switch fixture.scenario {
		case "ci-api26-permission-denied", "ci-api34-permission-denied", "ci-api36-permission-denied", "ci-api34-permission-denied-missing-events", "ci-api34-permission-denied-missing-proc-status":
			stderrMode = "before-owned-cancellation"
			stderrBefore = "Permission denied\n"
		case "owned-shutdown-stderr":
			stderrMode = "after-owned-cancellation"
		case "post-cancellation-exit-failure":
			stderrMode = "after-owned-cancellation"
		case "pre-cancellation-stderr":
			stderrMode = "before-owned-cancellation"
		}
	}
	terminalOverride := fixture.streamTerminalOverride
	if fixture.scenario == "post-cancellation-exit-failure" && buffer != "main" && buffer != "system" {
		terminalOverride = nil
	}
	stream := newFixtureStream(ctx, stdout, stderr, terminate, stderrMode, stderrBefore, terminalOverride)
	fixture.streams[buffer] = stream
	return stream.wait, nil
}

func (fixture *launchFixtureTransport) assertClosed(t *testing.T) {
	t.Helper()
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	want := 4
	if fixture.scenario == "unavailable-stream" || fixture.scenario == "stream-without-wait" || fixture.scenario == "invalid-stream-command" {
		want = 0
	} else if strings.HasSuffix(fixture.scenario, "missing-events") || strings.HasSuffix(fixture.scenario, "missing-crash") {
		want = 3
	}
	if len(fixture.streams) != want {
		t.Errorf("stream count=%d, want %d", len(fixture.streams), want)
	}
	for name, stream := range fixture.streams {
		if stream.waits.Load() != 1 || stream.completed.Load() != 1 {
			t.Errorf("%s stream wait=%d completion=%d, want exactly once", name, stream.waits.Load(), stream.completed.Load())
		}
		if stream.closes.Load() != 1 || stream.eofs.Load() != 1 || stream.admitted.Load() != stream.delivered.Load() {
			t.Errorf("%s stream close=%d EOF=%d admitted_bytes=%d delivered_bytes=%d", name,
				stream.closes.Load(), stream.eofs.Load(), stream.admitted.Load(), stream.delivered.Load())
		}
		if fixture.scenario != "terminated-stream" && stream.cancelled.Load() != 1 {
			t.Errorf("%s stream was not cancelled exactly once", name)
		}
	}
}

func TestLaunchTransportIncompleteRawEvidenceRemainsBlocked(t *testing.T) {
	for _, scenario := range []string{"missing-terminal-epoch", "terminal-command-timeout", "malformed-terminal-epoch", "truncated-process-output", "extra-process-output", "unavailable-stream", "stream-without-wait"} {
		t.Run(scenario, func(t *testing.T) {
			err, observation := runLaunchScenario(t, scenario, 26)
			if !errors.Is(err, errLaunchIncomplete) || observation.GateResult != "BLOCKED" || observation.Status != "INCOMPLETE" {
				t.Fatalf("incomplete raw evidence: err=%v gate=%s evidence=%s", err, observation.GateResult, observation.Status)
			}
			if scenario == "terminal-command-timeout" {
				found := false
				for _, command := range observation.Commands {
					found = found || (command.Phase == "terminal-epoch" && command.Status == "DEADLINE" && command.ExitCode != 0)
				}
				if !found {
					t.Fatal("fixture did not exercise the real shared command deadline")
				}
			}
		})
	}
}

func TestLaunchTransportPIDReuseDoesNotEstablishContinuity(t *testing.T) {
	err, observation := runLaunchScenario(t, "pid-reuse", 34)
	if err == nil || errors.Is(err, errLaunchIncomplete) || observation.GateResult != "FAIL" {
		t.Fatalf("changed epoch for reused PID not rejected: err=%v gate=%s", err, observation.GateResult)
	}
}

func TestLaunchTransportStaleAndUnrelatedDialogsDoNotRejectHealthyTarget(t *testing.T) {
	for _, scenario := range []string{"stale-dialog", "unrelated-dialog"} {
		t.Run(scenario, func(t *testing.T) {
			err, observation := runLaunchScenario(t, scenario, 34)
			if err != nil || observation.GateResult != "LAUNCH_OBSERVED_NOT_QUALIFIED" || observation.Status != "CAPTURED" {
				t.Fatalf("uncorrelated dialog rejected current healthy target: err=%v gate=%s", err, observation.GateResult)
			}
		})
	}
}

func TestLaunchTransportPreservesArgumentOrderAndSharedSnapshotBudget(t *testing.T) {
	err, observation, fixture := runLaunchFixture(t, "healthy", 34)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	var snapshotDeadline time.Time
	pidOfDirect, pidOfComposite := 0, 0
	for _, call := range fixture.commands {
		got = append(got, call.kind+" "+strings.Join(call.args, " "))
		wantDelay := time.Second
		if strings.Join(call.args, " ") == "-s emulator-5554 shell pidof "+defaultAppPackage {
			if call.waitDelay == 0 {
				pidOfDirect++
				wantDelay = 0
			} else {
				pidOfComposite++
			}
		}
		if call.waitDelay != wantDelay {
			t.Errorf("changed wait delay for %v: %s", call.args, call.waitDelay)
		}
		if strings.Join(call.args[3:], " ") == "ps -A -o UID,PID,PPID,NAME" {
			if call.remaining <= 0 || call.remaining > time.Second {
				t.Errorf("snapshot budget=%s, must remain bounded by the existing second", call.remaining)
			}
			snapshotDeadline = call.deadline
		}
		if strings.Join(call.args[3:], " ") == "cat /proc/999/stat" && !call.deadline.Equal(snapshotDeadline) {
			t.Error("epoch query did not retain its process-list query's shared deadline")
		}
	}
	if pidOfDirect != 1 || pidOfComposite != 3 {
		t.Fatalf("pidof command boundaries direct=%d composite=%d, want 1 and 3", pidOfDirect, pidOfComposite)
	}
	prefix := "run -s emulator-5554 shell "
	streamPrefix := "start -s emulator-5554 shell logcat -b "
	streamSuffix := " -v threadtime -v monotonic -v usec -T 1 AndroidRuntime:E ActivityManager:I ActivityTaskManager:I KurdistanLaunchProbe:I *:S"
	eventProbe := "logcat -b events -d -t 1 -v threadtime -v monotonic -v usec am_proc_start:I am_proc_died:I am_kill:I am_anr:I am_crash:I *:S"
	eventStream := "start -s emulator-5554 shell logcat -b events -v threadtime -v monotonic -v usec -T 1 am_proc_start:I am_proc_died:I am_kill:I am_anr:I am_crash:I *:S"
	startMarker, endMarker := "", ""
	for _, call := range fixture.commands {
		if len(call.args) == 0 {
			continue
		}
		identity, valid := parseLaunchMarkerIdentity(call.args[len(call.args)-1])
		if !valid {
			continue
		}
		if identity.Type == "START" {
			startMarker = identity.String()
		} else {
			endMarker = identity.String()
		}
	}
	if startMarker == "" || endMarker == "" {
		t.Fatal("canonical launch markers unavailable from exact command sequence")
	}
	markerStart := strconv.FormatInt(observation.DeviceStartNanos/1_000_000_000, 10) + "." + fmt.Sprintf("%09d", observation.DeviceStartNanos%1_000_000_000)
	want := []string{
		prefix + "log -p i -t KurdistanClockProbe CLOCK:clock-before:" + observation.Invocation,
		prefix + "logcat -b main -d -e ^CLOCK:clock-before:" + observation.Invocation + "$ -v threadtime -v monotonic -v usec KurdistanClockProbe:I *:S",
		prefix + "date +%z",
		prefix + "id",
		prefix + "cat /proc/self/attr/current",
		prefix + "logcat --help",
		prefix + "logcat -b crash -d -t 1 -v threadtime -v monotonic -v usec AndroidRuntime:E ActivityManager:I ActivityTaskManager:I KurdistanLaunchProbe:I *:S",
		prefix + eventProbe,
		prefix + "logcat -b main -d -t 1 -v threadtime -v monotonic -v usec AndroidRuntime:E ActivityManager:I ActivityTaskManager:I KurdistanLaunchProbe:I *:S",
		prefix + "logcat -b system -d -t 1 -v threadtime -v monotonic -v usec AndroidRuntime:E ActivityManager:I ActivityTaskManager:I KurdistanLaunchProbe:I *:S",
		prefix + "cat /proc/sys/kernel/random/boot_id",
		prefix + "getprop ro.build.fingerprint",
		prefix + "dumpsys package " + defaultAppPackage,
		streamPrefix + "crash" + streamSuffix, eventStream, streamPrefix + "main" + streamSuffix, streamPrefix + "system" + streamSuffix,
		prefix + "log -p i -t KurdistanLaunchProbe " + startMarker,
		prefix + "ps -A -o UID,PID,PPID,NAME",
		prefix + "cmd package resolve-activity --brief -n " + defaultAppPackage + "/org.kurdistanvpn.app.MainActivity",
		prefix + "am start -W -f 0x10008000 -n " + defaultAppPackage + "/org.kurdistanvpn.app.MainActivity",
		prefix + "ps -A -o UID,PID,PPID,NAME", prefix + "cat /proc/999/stat",
		prefix + "pidof " + defaultAppPackage, prefix + "cat /proc/999/status",
		prefix + "pidof " + defaultAppPackage,
		prefix + "ps -A -o UID,PID,PPID,NAME", prefix + "cat /proc/999/stat",
		prefix + "pidof " + defaultAppPackage, prefix + "cat /proc/999/status",
		prefix + "ps -A -o UID,PID,PPID,NAME", prefix + "cat /proc/999/stat",
		prefix + "pidof " + defaultAppPackage, prefix + "cat /proc/999/status",
		prefix + "dumpsys activity processes " + defaultAppPackage,
		prefix + "dumpsys activity activities " + defaultAppPackage,
		prefix + "dumpsys package " + defaultAppPackage,
		prefix + "cat /proc/sys/kernel/random/boot_id",
		prefix + "getprop ro.build.fingerprint",
		prefix + "log -p i -t KurdistanLaunchProbe " + endMarker,
		prefix + "logcat -b main -d -T " + markerStart + " -e " + observation.Invocation + " -v threadtime -v monotonic -v usec KurdistanLaunchProbe:I *:S",
		prefix + "log -p i -t KurdistanClockProbe CLOCK:clock-after:" + observation.Invocation,
		prefix + "logcat -b main -d -e ^CLOCK:clock-after:" + observation.Invocation + "$ -v threadtime -v monotonic -v usec KurdistanClockProbe:I *:S",
		prefix + "logcat -b main -d -T " + markerStart + " -e " + observation.Invocation + " -v threadtime -v epoch -v usec KurdistanLaunchProbe:I *:S",
		prefix + "dumpsys activity exit-info " + defaultAppPackage,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("launch command sequence changed:\ngot=%q\nwant=%q", got, want)
	}
}

func TestLaunchTransportStreamsRawEvidenceBeforeWait(t *testing.T) {
	fixture := newLaunchFixtureTransport("current-crash")
	client := newADBClient("fixture-adb", "emulator-5554", t.TempDir(), &diagnosticTimeline{Started: time.Now()})
	client.transport = &commandTransport{run: fixture.run, start: fixture.start}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	outputs := make(map[string]*readyChildWriter)
	var waits []func() error
	defer func() {
		cancel()
		for _, wait := range waits {
			if err := wait(); !errors.Is(err, context.Canceled) {
				t.Errorf("stream cleanup result=%v, want cancellation", err)
			}
		}
		fixture.assertClosed(t)
		for buffer, output := range outputs {
			if output.String() != fixture.logs[buffer] {
				t.Errorf("%s Wait changed or discarded already-delivered raw output", buffer)
			}
		}
	}()
	for _, buffer := range []string{"crash", "events", "main", "system"} {
		output := &readyChildWriter{ready: make(chan struct{})}
		outputs[buffer] = output
		args := []string{"-s", "emulator-5554", "shell", "logcat", "-b", buffer,
			"-v", "threadtime", "-v", "monotonic", "-v", "usec", "-T", "1",
			"AndroidRuntime:E", "ActivityManager:I", "ActivityTaskManager:I", "KurdistanLaunchProbe:I", "*:S"}
		if buffer == "events" {
			args = []string{"-s", "emulator-5554", "shell", "logcat", "-b", "events",
				"-v", "threadtime", "-v", "monotonic", "-v", "usec", "-T", "1",
				"am_proc_start:I", "am_proc_died:I", "am_kill:I", "am_anr:I", "am_crash:I", "*:S"}
		}
		wait, err := client.startCommand(ctx, args, output, io.Discard, time.Second)
		if err != nil || wait == nil {
			t.Fatalf("%s Start did not provide a running command: %v", buffer, err)
		}
		waits = append(waits, wait)
		select {
		case <-fixture.streams[buffer].ready:
		default:
			t.Fatalf("%s output reader is unavailable after Start", buffer)
		}
		call := fixture.commands[len(fixture.commands)-1]
		if call.kind != "start" || !reflect.DeepEqual(call.args, args) || call.waitDelay != time.Second {
			t.Fatalf("%s Start changed command identity, argument order or wait bound", buffer)
		}
	}
	invocation := strings.Repeat("1", 32)
	startMarker := fixtureCanonicalLaunchMarker("START", invocation, strings.Repeat("2", 32), strings.Repeat("3", 32))
	endMarker := fixtureCanonicalLaunchMarker("END", invocation, strings.Repeat("4", 32), strings.Repeat("5", 32))
	for _, args := range [][]string{
		{"-s", "emulator-5554", "shell", "log", "-p", "i", "-t", "KurdistanLaunchProbe", startMarker},
		{"-s", "emulator-5554", "shell", "am", "start", "-W", "-f", "0x10008000", "-n", defaultAppPackage + "/org.kurdistanvpn.app.MainActivity"},
		{"-s", "emulator-5554", "shell", "log", "-p", "i", "-t", "KurdistanLaunchProbe", endMarker},
	} {
		if err := client.runCommand(ctx, args, io.Discard, io.Discard, time.Second); err != nil {
			t.Fatalf("raw fixture command failed: %v", err)
		}
	}
	start, end, windowOK := launchMarkerWindow(fixture.logs["main"], fixture.logs["main"], invocation, 1, int64(9_000_000_000_000_000_000))
	if !windowOK {
		t.Error("raw fixture invocation window is invalid")
	}
	if start != 101_001_000_000 || end != 101_003_000_000 {
		t.Errorf("synthetic command clock changed: start=%d end=%d", start, end)
	}
	for _, buffer := range []string{"main", "system", "crash", "events"} {
		raw := fixture.logs[buffer]
		if buffer == "events" {
			if evidence := parseStartupSystemEvents(raw, defaultAppPackage, start, end); evidence.Status != "CAPTURED" || len(evidence.Events) != 1 || evidence.Events[0].Type != "PROCESS_START" {
				t.Errorf("events fixture did not traverse the canonical system parser: %+v", evidence)
			}
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
			event, ok := parseEpochLog(line)
			t.Logf("buffer=%s parsed=%t relative_start_ns=%d relative_end_ns=%d", buffer, ok, event.DeviceNanos-start, end-event.DeviceNanos)
			if !ok {
				t.Errorf("%s fixture emits a malformed raw log line", buffer)
			}
			if buffer != "main" && (event.DeviceNanos <= start || event.DeviceNanos > end) {
				t.Errorf("%s raw event is outside the invocation window", buffer)
			}
		}
		if outputs[buffer].String() != raw {
			t.Errorf("%s output unavailable before Wait: emitted_bytes=%d readable_bytes=%d", buffer, len(raw), len(outputs[buffer].String()))
		}
		if fixture.streams[buffer].waits.Load() != 0 {
			t.Errorf("%s Wait unexpectedly initiated output delivery", buffer)
		}
	}
	wantEvents := map[string][]launchLogEvent{
		"system": {
			{DeviceNanos: 101_002_000_000, PID: 10, TID: 10, Tag: "ActivityManager", Text: "process_lifecycle event=Start_proc pid=999 process=" + defaultAppPackage + " uid=10123"},
		},
		"crash": {
			{DeviceNanos: 101_002_000_000, PID: 999, TID: 999, Tag: "AndroidRuntime", Text: "FATAL EXCEPTION"},
			{DeviceNanos: 101_002_000_000, PID: 999, TID: 999, Tag: "AndroidRuntime", Text: "Process: " + defaultAppPackage + ", PID: 999"},
			{DeviceNanos: 101_002_000_000, PID: 999, TID: 999, Tag: "AndroidRuntime", Text: "java.lang.IllegalStateException: Check failed."},
			{DeviceNanos: 101_002_000_000, PID: 999, TID: 999, Tag: "AndroidRuntime", Text: "at org.kurdistanvpn.app.ProductRootViewModel.onCreate(Phase9ViewModel.kt:95)"},
		},
	}
	for _, buffer := range []string{"system", "crash"} {
		events, complete := launchWindowEvents(outputs[buffer].String(), defaultAppPackage, start, end)
		if !complete || !reflect.DeepEqual(events, wantEvents[buffer]) {
			t.Errorf("%s real parser/sanitizer: complete=%t events=%+v, want fixed raw-record interpretation", buffer, complete, events)
		}
	}
	cancel()
	for buffer, stream := range fixture.streams {
		select {
		case <-stream.done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s cancellation did not close its reader before Wait", buffer)
		}
		if stream.waits.Load() != 0 || stream.eofs.Load() != 1 || stream.closes.Load() != 1 || stream.completed.Load() != 1 {
			t.Errorf("%s completion depends on Wait or is not exact-once", buffer)
		}
	}
}

type heldFixtureWriter struct {
	output  readyChildWriter
	entered chan struct{}
	release chan struct{}
}

func (writer *heldFixtureWriter) Write(value []byte) (int, error) {
	close(writer.entered)
	<-writer.release
	return writer.output.Write(value)
}

func TestLaunchTransportCancellationDrainsAcceptedRawOutput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fixture := newLaunchFixtureTransport("healthy")
	client := newADBClient("fixture-adb", "emulator-5554", t.TempDir(), &diagnosticTimeline{Started: time.Now()})
	client.transport = &commandTransport{run: fixture.run, start: fixture.start}
	output := &heldFixtureWriter{
		output: readyChildWriter{ready: make(chan struct{})}, entered: make(chan struct{}), release: make(chan struct{}),
	}
	release := sync.OnceFunc(func() { close(output.release) })
	defer release()
	args := []string{"-s", "emulator-5554", "shell", "logcat", "-b", "system",
		"-v", "threadtime", "-v", "monotonic", "-v", "usec", "-T", "1",
		"AndroidRuntime:E", "ActivityManager:I", "ActivityTaskManager:I", "KurdistanLaunchProbe:I", "*:S"}
	wait, err := client.startCommand(ctx, args, output, io.Discard, time.Second)
	if err != nil || wait == nil {
		t.Fatalf("start output-copy boundary: %v", err)
	}
	waited := false
	defer func() {
		release()
		cancel()
		if !waited {
			if err := wait(); !errors.Is(err, context.Canceled) {
				t.Errorf("cleanup wait: %v", err)
			}
		}
	}()
	stream := fixture.streams["system"]
	raw := "101.002000000 10 10 I ActivityManager: Start proc 999:" + defaultAppPackage + "/u0a123 for activity\n"
	written := make(chan error, 1)
	go func() { written <- stream.write(raw) }()
	select {
	case <-output.entered:
	case <-ctx.Done():
		t.Fatal("raw output did not enter the live reader")
	}
	cancel()
	if stream.delivered.Load() != 0 || stream.completed.Load() != 0 || stream.admitted.Load() != int64(len(raw)) {
		t.Error("output was declared delivered or complete before its writer returned")
	}
	release()
	select {
	case err := <-written:
		if err != nil {
			t.Errorf("accepted raw chunk was discarded during cancellation: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("accepted output did not finish after explicit release")
	}
	err = wait()
	waited = true
	if !errors.Is(err, context.Canceled) || output.output.String() != raw || stream.admitted.Load() != stream.delivered.Load() {
		t.Fatalf("cancellation lost raw output or terminal state: err=%v admitted=%d delivered=%d", err, stream.admitted.Load(), stream.delivered.Load())
	}
	if stream.waits.Load() != 1 || stream.eofs.Load() != 1 || stream.closes.Load() != 1 || stream.completed.Load() != 1 || stream.cancelled.Load() != 1 {
		t.Fatal("stream cancellation, EOF, close or wait was not exact-once")
	}
	if err := stream.write("late"); !errors.Is(err, context.Canceled) || stream.rejected.Load() != 4 || output.output.String() != raw {
		t.Fatal("post-cancellation output was silently accepted or discarded")
	}
}

func TestCommandTransportCancellationAndOutputBoundsRemainProductionOwned(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		fixture := newLaunchFixtureTransport("healthy")
		client := newADBClient("fixture-adb", "emulator-5554", t.TempDir(), &diagnosticTimeline{Started: time.Now()})
		client.transport = &commandTransport{run: fixture.run, start: fixture.start}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		var record diagnosticCommand
		var err error
		go func() {
			_, _, record, err = client.diagnosticCommand(ctx, "cancelled-query", 64, "shell", "fixture-block")
			close(done)
		}()
		select {
		case <-fixture.blocked:
		case <-time.After(10 * time.Second):
			t.Fatal("test transport never entered its cancellation boundary")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("cancelled transport did not complete")
		}
		if !errors.Is(err, context.Canceled) || record.Status != "CANCELLED" || record.ExitCode == 0 {
			t.Fatalf("cancellation lost: err=%v status=%s exit=%d", err, record.Status, record.ExitCode)
		}
	})
	t.Run("bounded-output", func(t *testing.T) {
		client := newADBClient("fixture-adb", "emulator-5554", t.TempDir(), &diagnosticTimeline{Started: time.Now()})
		fixture := newLaunchFixtureTransport("healthy")
		client.transport = &commandTransport{run: fixture.run, start: fixture.start}
		stdout, stderr, record, err := client.diagnosticCommand(context.Background(), "bounded-query", 6, "shell", "fixture-bounds")
		if err != nil || stdout != "abefg" || stderr != "cd" || record.combined != "abcdef" || !record.Truncated || record.Status != "INCOMPLETE" {
			t.Fatalf("production output bounds changed: err=%v record=%+v", err, record)
		}
	})
}

func TestClearKnownEvidenceFilesRemovesOnlyGateEvidence(t *testing.T) {
	directory := t.TempDir()
	stale := filepath.Join(directory, "11-instrumentation.txt")
	unrelated := filepath.Join(directory, "notes.md")
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unrelated, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := clearKnownEvidenceFiles(directory); err != nil {
		t.Fatalf("clearKnownEvidenceFiles() error = %v", err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale evidence still exists: %v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("unrelated file was removed: %v", err)
	}
}

func TestValidateLaunchSmokeAcceptsExpectedActivityAndLiveProcess(t *testing.T) {
	launch := "Status: ok\nActivity: org.kurdistanvpn.app.debug/org.kurdistanvpn.app.MainActivity\nTotalTime: 25\nWaitTime: 30\nComplete\n"
	if err := validateLaunchSmoke(launch, "7781\n", defaultAppPackage, nil); err != nil {
		t.Fatalf("validateLaunchSmoke() error = %v", err)
	}
}

func TestValidateLaunchSmokeRejectsStaleSystemPicker(t *testing.T) {
	launch := "Activity: com.google.android.documentsui/com.android.documentsui.picker.PickActivity"
	if err := validateLaunchSmoke(launch, "7781\n", defaultAppPackage, nil); err == nil {
		t.Fatal("validateLaunchSmoke() accepted a system picker as the app launch")
	}
}

func TestValidateLaunchSmokeRejectsMissingProcess(t *testing.T) {
	if err := validateLaunchSmoke("", "", defaultAppPackage, errors.New("pidof failed")); err == nil {
		t.Fatal("validateLaunchSmoke() accepted a missing app process")
	}
}

func TestLogcatClearUsesDeviceShellForMinimumSdkCompatibility(t *testing.T) {
	arguments := logcatClearArgs()
	if got := strings.Join(arguments, " "); got != "shell logcat -b all -c" {
		t.Fatalf("logcatClearArgs() = %q, want device-shell clearing", got)
	}
}

func TestDiagnosticBaselineAcceptsUnsupportedClearWithoutAppCrash(t *testing.T) {
	main := "schema=kurdistan-device-diagnostic-summary-v1\napp_crash=false\n"
	crash := "schema=kurdistan-device-diagnostic-summary-v1\napp_crash=false\n"
	if !diagnosticBaselineIsClean(main, crash) {
		t.Fatal("diagnosticBaselineIsClean rejected a clean bounded baseline")
	}
}

func TestDiagnosticBaselineRejectsPreExistingAppCrash(t *testing.T) {
	main := "schema=kurdistan-device-diagnostic-summary-v1\napp_crash=false\n"
	crash := "schema=kurdistan-device-diagnostic-summary-v1\napp_crash=true\n"
	if diagnosticBaselineIsClean(main, crash) {
		t.Fatal("diagnosticBaselineIsClean accepted a pre-existing app crash")
	}
}

func TestFrameworkServicesReadyRequiresExactHealthyServices(t *testing.T) {
	if !frameworkServicesReady("Service activity: found\n", nil, "Service package: found\n", nil) {
		t.Fatal("frameworkServicesReady rejected healthy activity and package services")
	}
	for _, test := range []struct {
		activityOutput string
		activityErr    error
		packageOutput  string
		packageErr     error
	}{
		{activityOutput: "Service activity: not found", packageOutput: "Service package: found"},
		{activityOutput: "activity: found", packageOutput: "Service package: found"},
		{activityOutput: "Service activity: found", packageOutput: "Service package: not found"},
		{activityOutput: "Service activity: found", activityErr: errors.New("broken pipe"), packageOutput: "Service package: found"},
		{activityOutput: "Service activity: found", packageOutput: "Service package: found", packageErr: errors.New("broken pipe")},
	} {
		if frameworkServicesReady(test.activityOutput, test.activityErr, test.packageOutput, test.packageErr) {
			t.Fatalf("frameworkServicesReady accepted unhealthy services: %+v", test)
		}
	}
}

func TestTransientPackageServiceFailureIsNarrow(t *testing.T) {
	if !transientPackageServiceFailure("Failure calling service package: Broken pipe (32)") {
		t.Fatal("transientPackageServiceFailure rejected the observed package-service restart")
	}
	for _, output := range []string{
		"INSTALL_FAILED_INVALID_APK",
		"Failure calling service activity: Broken pipe (32)",
		"Failure calling service package: Permission denied",
	} {
		if transientPackageServiceFailure(output) {
			t.Fatalf("transientPackageServiceFailure accepted permanent failure %q", output)
		}
	}
}

func TestEvaluateInstrumentationAcceptsCompletedCrashFreeRun(t *testing.T) {
	output := `
INSTRUMENTATION_STATUS_CODE: 0
INSTRUMENTATION_STATUS_CODE: 0
INSTRUMENTATION_STATUS_CODE: 0
INSTRUMENTATION_STATUS_CODE: 0
OK (4 tests)
`
	if err := evaluateInstrumentation(output, "clean device log", defaultAppPackage, 4); err != nil {
		t.Fatalf("evaluateInstrumentation() error = %v", err)
	}
}

func TestExpectedTestManifestRequiresExactCompletedTests(t *testing.T) {
	output := strings.Join([]string{
		"INSTRUMENTATION_STATUS: class=org.example.ProductTest",
		"INSTRUMENTATION_STATUS: test=first",
		"INSTRUMENTATION_STATUS_CODE: 0",
		"INSTRUMENTATION_STATUS: class=org.example.ProductTest",
		"INSTRUMENTATION_STATUS: test=second",
		"INSTRUMENTATION_STATUS_CODE: 0",
	}, "\n")
	if err := verifyExpectedTests(output, []string{
		"org.example.ProductTest#first",
		"org.example.ProductTest#second",
	}); err != nil {
		t.Fatalf("verifyExpectedTests() error = %v", err)
	}
	if err := verifyExpectedTests(output, []string{"org.example.ProductTest#first"}); err == nil {
		t.Fatal("verifyExpectedTests accepted an unexpected executed test")
	}
}

func TestReadExpectedTestsRejectsDuplicateEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tests.txt")
	if err := os.WriteFile(path, []byte("a.b.Test#one\na.b.Test#one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readExpectedTests(path); err == nil {
		t.Fatal("readExpectedTests accepted duplicates")
	}
}

func TestExpectedTestsForSDKFiltersGuardedCasesWithoutWeakeningExactManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tests.txt")
	manifest := "a.b.Test#always\nminSdk=34 a.b.Test#accessibility\n"
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	tests, err := readExpectedTests(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(expectedTestsForSDK(tests, 26), "\n"); got != "a.b.Test#always" {
		t.Fatalf("API 26 manifest = %q", got)
	}
	if got := strings.Join(expectedTestsForSDK(tests, 34), "\n"); got != "a.b.Test#accessibility\na.b.Test#always" {
		t.Fatalf("API 34 manifest = %q", got)
	}
}

func TestPhase17FieldQualificationRunsOnTheMinimumSupportedAPI(t *testing.T) {
	tests, err := readExpectedTests(filepath.Join("..", "..", "android", "config", "phase17-required-device-tests.txt"))
	if err != nil {
		t.Fatal(err)
	}
	const fieldAction = "org.kurdistanvpn.app.Phase17FieldActionDeviceTest#runRequestedFieldAction"
	for _, test := range expectedTestsForSDK(tests, 26) {
		if test == fieldAction {
			return
		}
	}
	t.Fatal("Phase 17 field qualification is skipped on the supported API 26 lane")
}

func TestEvaluateInstrumentationRejectsZeroTests(t *testing.T) {
	if err := evaluateInstrumentation("OK (0 tests)", "clean", defaultAppPackage, 1); err == nil {
		t.Fatal("evaluateInstrumentation() accepted a zero-test run")
	}
}

func TestEvaluateInstrumentationRejectsReportedProcessCrash(t *testing.T) {
	output := "Test run failed to complete. Instrumentation run failed due to Process crashed."
	if err := evaluateInstrumentation(output, "", defaultAppPackage, 1); err == nil {
		t.Fatal("evaluateInstrumentation() accepted an instrumentation process crash")
	}
}

func TestEvaluateInstrumentationRejectsFalsePassWithConcurrentNativeCrash(t *testing.T) {
	output := "INSTRUMENTATION_STATUS_CODE: 0\nOK (1 test)"
	logcat := "Fatal signal 4 (SIGILL) in org.kurdistanvpn.app.debug"
	if err := evaluateInstrumentation(output, logcat, defaultAppPackage, 1); err == nil {
		t.Fatal("evaluateInstrumentation() accepted an apparent pass with a native crash")
	}
}

func TestEvaluateInstrumentationDoesNotAttributeAnotherAppsCrash(t *testing.T) {
	output := "INSTRUMENTATION_STATUS_CODE: 0\nOK (1 test)"
	logcat := "FATAL EXCEPTION in com.example.unrelated"
	if err := evaluateInstrumentation(output, logcat, defaultAppPackage, 1); err != nil {
		t.Fatalf("evaluateInstrumentation() error = %v", err)
	}
}

func TestEvaluateInstrumentationDoesNotAttributeSystemNativeCrash(t *testing.T) {
	output := "INSTRUMENTATION_STATUS_CODE: 0\nOK (1 test)"
	logcat := `
org.kurdistanvpn.app.debug completed a test
Fatal signal 6 (SIGABRT), code -1 (SI_QUEUE) in tid 687, pid 624
*** *** *** *** *** *** *** ***
Executable: /vendor/bin/hw/android.hardware.camera.provider.ranchu
Cmdline: /vendor/bin/hw/android.hardware.camera.provider.ranchu
pid: 624, tid: 687, name: binder:624_1  >>> /vendor/bin/hw/android.hardware.camera.provider.ranchu <<<
`
	if err := evaluateInstrumentation(output, logcat, defaultAppPackage, 1); err != nil {
		t.Fatalf("evaluateInstrumentation() attributed a system camera crash to the app: %v", err)
	}
}

func TestEvaluateInstrumentationRejectsJavaAppCrash(t *testing.T) {
	output := "INSTRUMENTATION_STATUS_CODE: 0\nOK (1 test)"
	logcat := `
FATAL EXCEPTION: main
Process: org.kurdistanvpn.app.debug, PID: 7781
java.lang.IllegalStateException: regression fixture
`
	if err := evaluateInstrumentation(output, logcat, defaultAppPackage, 1); err == nil {
		t.Fatal("evaluateInstrumentation() accepted a Java app crash")
	}
}

func TestEvaluateInstrumentationRejectsNativeAppSubprocessCrash(t *testing.T) {
	output := "INSTRUMENTATION_STATUS_CODE: 0\nOK (1 test)"
	logcat := `
Fatal signal 6 (SIGABRT), code -1 (SI_QUEUE) in tid 7782, pid 7781
Cmdline: org.kurdistanvpn.app.debug:vpn
pid: 7781, tid: 7782, name: vpn  >>> org.kurdistanvpn.app.debug:vpn <<<
`
	if err := evaluateInstrumentation(output, logcat, defaultAppPackage, 1); err == nil {
		t.Fatal("evaluateInstrumentation() accepted a native app subprocess crash")
	}
}

func TestEvaluateInstrumentationRejectsAppANR(t *testing.T) {
	output := "INSTRUMENTATION_STATUS_CODE: 0\nOK (1 test)"
	logcat := "ANR in org.kurdistanvpn.app.debug (org.kurdistanvpn.app.debug/.MainActivity)"
	if err := evaluateInstrumentation(output, logcat, defaultAppPackage, 1); err == nil {
		t.Fatal("evaluateInstrumentation() accepted an app ANR")
	}
}

func TestDiagnosticSummaryPreservesCrashClassWithoutRawLogData(t *testing.T) {
	raw := strings.Join([]string{
		"FATAL EXCEPTION: main",
		"Process: org.kurdistanvpn.app.debug, PID: 7781",
		"java.lang.IllegalStateException: token=secret-value https://10.0.0.8/profile",
		"at org.kurdistanvpn.app.MainActivity.onCreate(MainActivity.kt:42)",
	}, "\n")
	summary := summarizeDiagnostics(raw, defaultAppPackage, false)
	for _, required := range []string{
		"schema=kurdistan-device-diagnostic-summary-v1",
		"app_crash=true",
		"java_crash=true",
		"input_truncated=false",
	} {
		if !strings.Contains(summary, required) {
			t.Fatalf("summary %q is missing %q", summary, required)
		}
	}
	for _, forbidden := range []string{"secret-value", "10.0.0.8", "https://", "7781", "MainActivity.kt"} {
		if strings.Contains(summary, forbidden) {
			t.Fatalf("summary retained private raw log content %q: %q", forbidden, summary)
		}
	}
	if len(summary) > maxDiagnosticBytes {
		t.Fatalf("summary size = %d, limit = %d", len(summary), maxDiagnosticBytes)
	}
}

func TestLaunchFailureRetainsSafeExceptionCauseWithoutTurningFailureIntoPass(t *testing.T) {
	raw := "FATAL EXCEPTION: main\nProcess: " + defaultAppPackage + ", PID: 7781\n" +
		"java.lang.RuntimeException: Unable to create application org.kurdistanvpn.app.KurdistanApplication\n" +
		"Caused by: java.lang.IllegalArgumentException: Failed requirement.\n" +
		"\tat org.kurdistanvpn.data.settings.Phase9SettingsStore.openOwnedProjection(Phase9SettingsStore.kt:271)\n"
	summary := summarizeDiagnostics(raw, defaultAppPackage, false)
	for _, want := range []string{"exception_class=java.lang.RuntimeException", "exception_class=java.lang.IllegalArgumentException", "exception_message=Failed requirement."} {
		if !strings.Contains(summary, want) {
			t.Errorf("missing launch failure detail %q", want)
		}
	}
	if err := validateLaunchSmoke("Status: ok\n", "", defaultAppPackage, nil); err == nil {
		t.Fatal("diagnostic collection changed a missing-process failure into success")
	}
	if err := evaluateInstrumentation("INSTRUMENTATION_STATUS_CODE: 0\nOK (1 test)", summary, defaultAppPackage, 1); err == nil {
		t.Fatal("exception details changed a crash failure into success")
	}
}

func TestLaunchWindowRejectsOldUnrelatedAndUnparseableRecords(t *testing.T) {
	raw := strings.Join([]string{
		"100.000001 777 777 E AndroidRuntime: Process: " + defaultAppPackage + ", PID: 777",
		"100.000002 777 777 E AndroidRuntime: java.lang.IllegalStateException: old",
		"102.000001 888 888 E AndroidRuntime: Process: example.unrelated, PID: 888",
		"102.000002 888 888 E AndroidRuntime: java.lang.SecurityException: unrelated-secret",
		"102.000003 999 999 E AndroidRuntime: FATAL EXCEPTION: main",
		"102.000004 999 999 E AndroidRuntime: Process: " + defaultAppPackage + ", PID: 999",
		"102.000005 999 999 E AndroidRuntime: java.lang.IllegalArgumentException: Failed requirement.",
		"102.000006 999 999 E AndroidRuntime:     at org.kurdistanvpn.app.KurdistanApplication.onCreate(KurdistanApplication.kt:81)",
	}, "\n")
	events, complete := launchWindowEvents(raw, defaultAppPackage, 101_000_000_000, 103_000_000_000)
	if !complete || len(events) != 4 {
		t.Fatalf("window events=%+v complete=%t", events, complete)
	}
	for _, event := range events {
		if event.PID != 999 || strings.Contains(event.Text, "secret") || strings.Contains(event.Text, "old") {
			t.Fatalf("wrong invocation retained: %+v", event)
		}
	}
	_, complete = launchWindowEvents(raw+"\nunparseable record", defaultAppPackage, 101_000_000_000, 103_000_000_000)
	if complete {
		t.Fatal("unparseable launch evidence was not INCOMPLETE")
	}
}

func TestLaunchExceptionMessagesAndFramesCannotExportSecretsOrPaths(t *testing.T) {
	raw := "java.lang.IllegalStateException: token=synthetic-secret https://192.0.2.9/profile\n" +
		"\tat org.kurdistanvpn.app.MainActivity.onCreate(MainActivity.kt:42)\n" +
		"Caused by: java.lang.IllegalArgumentException: Failed requirement.\n" +
		"\tat example.untrusted.secretMethod(/private/profile.json:1)\n"
	details, complete := javaFailureDetails(raw)
	if complete || len(details) != 2 || len(details[0].Stack) != 1 || details[1].Message != "Failed requirement." {
		t.Fatalf("details=%+v complete=%t", details, complete)
	}
	for _, forbidden := range []string{"synthetic-secret", "192.0.2.9", "https://", "private/profile", "secretMethod"} {
		if strings.Contains(fmt.Sprint(details), forbidden) {
			t.Fatalf("private detail survived: %s", forbidden)
		}
	}
}

func TestDiagnosticJava17ModuleFramesAndTargetProcessLifecycle(t *testing.T) {
	details, complete := javaFailureDetails("java.lang.IllegalArgumentException: Failed requirement.\n at java.base@17.0.20/java.lang.reflect.Method.invoke(Method.java:569)\n")
	if !complete || len(details) != 1 || !reflect.DeepEqual(details[0].Stack, []string{"at java.lang.reflect.Method.invoke(Method.java:569)"}) {
		t.Fatalf("Java 17 module frame lost: %+v %t", details, complete)
	}
	raw := "102.000001 10 10 I ActivityManager: Start proc 99:" + defaultAppPackage + "/u0a123 for activity private-extra\n" +
		"102.000002 10 10 I ActivityManager: Process " + defaultAppPackage + " (pid 99) has died: private-reason\n" +
		"102.000003 10 10 I ActivityManager: Killing 88:example.other/u0a124 private-detail\n"
	events, complete := launchWindowEvents(raw, defaultAppPackage, 101_000_000_000, 103_000_000_000)
	if !complete || len(events) != 2 || !strings.Contains(events[0].Text, "event=Start_proc") || !strings.Contains(events[1].Text, "event=died") || strings.Contains(fmt.Sprint(events), "private") {
		t.Fatalf("target lifecycle not safely preserved: %+v %t", events, complete)
	}
	state := sanitizeActivityProcessState("ProcessRecord{abc 99:"+defaultAppPackage+"/u0a123}\n curAdj=100 setAdj=100\n killed=true\n token=synthetic-secret\n ProcessRecord{def 88:example.other/u0a124}\n curAdj=999\n", defaultAppPackage)
	if !strings.Contains(fmt.Sprint(state), "curAdj=100") || !strings.Contains(fmt.Sprint(state), "killed=true") || strings.Contains(fmt.Sprint(state), "999") || strings.Contains(fmt.Sprint(state), "synthetic-secret") {
		t.Fatalf("activity state not scoped: %v", state)
	}
}

func TestLaunchDiagnosticsNeverReplaceOriginalFailure(t *testing.T) {
	want := errors.New("application process did not survive launch")
	for _, diagnosticErr := range []error{nil, errors.New("missing diagnostics"), context.DeadlineExceeded} {
		called := false
		got := retainLaunchFailure(want, func() error { called = true; return diagnosticErr })
		if got != want || !called {
			t.Fatalf("diagnostic changed original failure: %v", got)
		}
	}
}

func TestLaunchOutputKeepsTimingButRedactsUnknownStderr(t *testing.T) {
	lines, complete := sanitizeLaunchOutput("Status: ok\nActivity: "+defaultAppPackage+"/org.kurdistanvpn.app.MainActivity\nThisTime: 15\nTotalTime: 25\nWaitTime: 30\nComplete\n", defaultAppPackage)
	if !complete || !strings.Contains(strings.Join(lines, "\n"), "WaitTime: 30") {
		t.Fatalf("lost launch timing: %v %t", lines, complete)
	}
	lines, complete = sanitizeLaunchOutput("token=synthetic-secret endpoint=https://192.0.2.9\n", defaultAppPackage)
	if complete || strings.Contains(fmt.Sprint(lines), "synthetic-secret") || strings.Contains(fmt.Sprint(lines), "192.0.2.9") {
		t.Fatal("unsafe launch stderr was retained or called complete")
	}
}

func TestExitReasonRequiresExactProcessAndWindow(t *testing.T) {
	start := time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)
	const monotonicStart = int64(101_000_000_000)
	offset := start.UnixNano() - monotonicStart
	raw := "ApplicationExitInfo #0:\n timestamp=2026-01-02 03:04:01.250 pid=999 realUid=10123 packageUid=10123 definingUid=10123 user=0\n" +
		" process=" + defaultAppPackage + " reason=4 (CRASH) subreason=0 (UNKNOWN) status=0\n description=token=synthetic-secret\n" +
		"ApplicationExitInfo #1:\n timestamp=2026-01-02 02:04:01.250 pid=777 realUid=10123\n process=" + defaultAppPackage + " reason=4 (CRASH) status=0\n" +
		"ApplicationExitInfo #2:\n timestamp=2026-01-02 03:04:01.250 pid=888 realUid=10124\n process=" + defaultAppPackage + "ger reason=4 (CRASH) status=0\n"
	correlation := diagnosticClockCorrelation{
		Status: "CAPTURED", WallMinusMonotonicNanos: offset,
		WallMinusMonotonicLowerNanos: offset, WallMinusMonotonicUpperNanos: offset,
	}
	records, complete := parseExitRecords(raw, defaultAppPackage, monotonicStart, monotonicStart+int64(5*time.Second), correlation, time.UTC)
	if !complete || len(records) != 1 || records[0].PID != 999 || records[0].Reason != 4 ||
		records[0].DeviceNanos != monotonicStart+int64(1250*time.Millisecond) || records[0].DeviceEndNanos != records[0].DeviceNanos ||
		strings.Contains(fmt.Sprint(records), "secret") {
		t.Fatalf("exit records=%+v complete=%t", records, complete)
	}
}

func TestProcessIdentityRequiresExactNameAndStartTicks(t *testing.T) {
	rows, complete := parseProcessRows("UID PID PPID NAME\n10123 999 111 "+defaultAppPackage+"\n10124 888 111 "+defaultAppPackage+"ger\n", defaultAppPackage)
	if !complete || len(rows) != 1 || rows[0].PID != 999 || rows[0].UID != 10123 {
		t.Fatalf("process identity=%+v complete=%t", rows, complete)
	}
	// Linux proc_pid_stat field 22 is starttime; fields 3..21 are explicit.
	stat := "999 (synthetic process) S 111 111 111 0 -1 0 0 0 0 0 1 2 3 4 5 6 1 0 12345"
	if ticks, err := procStartTicks(stat, 999); err != nil || ticks != 12345 {
		t.Fatalf("start ticks=%d err=%v", ticks, err)
	}
	if _, err := procStartTicks(stat, 888); err == nil {
		t.Fatal("substituted PID accepted")
	}
}

func TestLaunchMarkersRequireOneCurrentInvocationAndRetainWindowAfterStreamExit(t *testing.T) {
	id := strings.Repeat("1", 32)
	startIdentity := fixtureCanonicalLaunchMarker("START", id, strings.Repeat("2", 32), strings.Repeat("3", 32))
	endIdentity := fixtureCanonicalLaunchMarker("END", id, strings.Repeat("4", 32), strings.Repeat("5", 32))
	start := "101.000001 11 11 I KurdistanLaunchProbe: " + startIdentity + "\n"
	end := "103.000001 12 12 I KurdistanLaunchProbe: " + endIdentity + "\n"
	first, last, ok := launchMarkerWindow(start, start+end, id, 100_000_000_000, 104_000_000_000)
	if !ok || first != 101_000_001_000 || last != 103_000_001_000 {
		t.Fatalf("verified marker window lost after stream exit: %d %d %t", first, last, ok)
	}
	for _, input := range []struct{ stream, snapshot, invocation string }{
		{start, "", id},
		{start, end, strings.Repeat("2", 32)},
		{start, end + "102.000001 13 13 I KurdistanLaunchProbe: " + fixtureCanonicalLaunchMarker("START", id, strings.Repeat("6", 32), strings.Repeat("7", 32)), id},
		{start, "99.000001 12 12 I KurdistanLaunchProbe: END:" + id, id},
	} {
		if _, _, ok := launchMarkerWindow(input.stream, input.snapshot, input.invocation, 100_000_000_000, 104_000_000_000); ok {
			t.Fatal("missing, duplicate, wrong-invocation or reversed markers accepted")
		}
	}
	if events, ok := launchWindowEvents("unbound crash", defaultAppPackage, 0, 0); ok || len(events) != 0 {
		t.Fatal("unbound logs attributed to current launch")
	}
}

func fixtureCanonicalLaunchMarker(kind, invocation, nonce, epoch string) string {
	return "KLG1:" + kind + ":" + invocation + ":" + nonce + ":phase9devicegate:" + epoch
}

func TestCanonicalLaunchMarkerIdentityMergesAPI26CollectorObservations(t *testing.T) {
	invocation := strings.Repeat("1", 32)
	start := fixtureCanonicalLaunchMarker("START", invocation, strings.Repeat("2", 32), strings.Repeat("3", 32))
	end := fixtureCanonicalLaunchMarker("END", invocation, strings.Repeat("4", 32), strings.Repeat("5", 32))
	stream := "106.349197000 11 11 I KurdistanLaunchProbe: " + start + "\n" +
		"110.394732000 11 11 I KurdistanLaunchProbe: " + end + "\n"
	snapshot := "106.349200000 11 11 I KurdistanLaunchProbe: " + start + "\n" +
		"110.394736000 11 11 I KurdistanLaunchProbe: " + end + "\n"

	window := diagnoseLaunchMarkerWindow(stream, snapshot, invocation, 106_349_190_000, 110_394_740_000)
	first, last := window.MatchingWindow()
	if window.Status != "CAPTURED" || window.Rejection != "" || first != 106_349_200_000 || last != 110_394_732_000 {
		t.Fatalf("same emitted markers were not merged by canonical identity: window=%+v first=%d last=%d", window, first, last)
	}
	if len(window.Markers) != 4 || window.Markers[0].Source != "stream" || window.Markers[2].Source != "snapshot" {
		t.Fatalf("collector provenance was not retained: %+v", window.Markers)
	}
}

func TestCanonicalLaunchMarkerIdentityRejectsAmbiguityConflictAndWrongInvocation(t *testing.T) {
	invocation := strings.Repeat("6", 32)
	otherInvocation := strings.Repeat("7", 32)
	startOne := fixtureCanonicalLaunchMarker("START", invocation, strings.Repeat("8", 32), strings.Repeat("9", 32))
	startTwo := fixtureCanonicalLaunchMarker("START", invocation, strings.Repeat("a", 32), strings.Repeat("b", 32))
	end := fixtureCanonicalLaunchMarker("END", invocation, strings.Repeat("c", 32), strings.Repeat("d", 32))
	wrong := fixtureCanonicalLaunchMarker("START", otherInvocation, strings.Repeat("e", 32), strings.Repeat("f", 32))
	line := func(at, marker string) string { return at + " 11 11 I KurdistanLaunchProbe: " + marker + "\n" }

	for name, input := range map[string]struct {
		stream   string
		snapshot string
		want     string
	}{
		"distinct-start-identities": {
			stream:   line("101.000001000", startOne) + line("103.000001000", end),
			snapshot: line("101.000002000", startTwo) + line("103.000002000", end),
			want:     "START_IDENTITY_AMBIGUOUS",
		},
		"same-source-conflicting-observation": {
			stream: line("101.000001000", startOne) + line("101.000002000", startOne) + line("103.000001000", end),
			want:   "START_SOURCE_CONFLICT",
		},
		"wrong-invocation": {
			stream: line("101.000001000", wrong) + line("103.000001000", end),
			want:   "INVOCATION_MISMATCH",
		},
		"malformed-identity": {
			stream: line("101.000001000", "KLG1:START:"+invocation+":missing-fields") + line("103.000001000", end),
			want:   "MARKER_IDENTITY_MALFORMED",
		},
	} {
		t.Run(name, func(t *testing.T) {
			window := diagnoseLaunchMarkerWindow(input.stream, input.snapshot, invocation, 100_000_000_000, 104_000_000_000)
			if window.Status != "REJECTED" || window.Rejection != input.want {
				t.Fatalf("invalid canonical marker evidence not rejected categorically: %+v", window)
			}
		})
	}
}

func TestLaunchObservationUsesCanonicalMarkersAndInvocationBoundSnapshot(t *testing.T) {
	err, observation, fixture := runLaunchFixture(t, "healthy", 34)
	if err != nil {
		t.Fatal(err)
	}
	var emitted []string
	var snapshot []string
	for _, call := range fixture.commands {
		command := strings.Join(call.args[3:], " ")
		if strings.HasPrefix(command, "log -p i -t "+launchProbeTag+" ") {
			emitted = append(emitted, call.args[len(call.args)-1])
		}
		if strings.HasPrefix(command, "logcat -b main -d ") && strings.Contains(command, launchProbeTag+":I") {
			snapshot = append([]string(nil), call.args[3:]...)
		}
	}
	if len(emitted) != 2 {
		t.Fatalf("marker emission count=%d commands=%+v", len(emitted), fixture.commands)
	}
	startIdentity, startOK := parseLaunchMarkerIdentity(emitted[0])
	endIdentity, endOK := parseLaunchMarkerIdentity(emitted[1])
	if !startOK || !endOK || startIdentity.Type != "START" || endIdentity.Type != "END" ||
		startIdentity.Invocation != observation.Invocation || endIdentity.Invocation != observation.Invocation ||
		startIdentity.EventNonce == endIdentity.EventNonce || startIdentity.CommandEpoch == endIdentity.CommandEpoch {
		t.Fatalf("START/END marker identities are not unique and invocation-bound: start=%q end=%q", emitted[0], emitted[1])
	}
	joined := strings.Join(snapshot, " ")
	if len(snapshot) == 0 || strings.Contains(joined, " -t ") || !strings.Contains(joined, " -T ") ||
		!strings.Contains(joined, launchProbeTag+":I") || !strings.Contains(joined, observation.Invocation) {
		t.Fatalf("marker snapshot is not start-bounded, tag-filtered and invocation-bound: %q", snapshot)
	}
}

func TestCollectorStartLossIsRecoveredOnlyByInvocationBoundSnapshot(t *testing.T) {
	for _, test := range []struct {
		name     string
		scenario string
		api      int
		source   string
	}{
		{name: "api34-stream-loss", scenario: "api34-start-stream-loss", api: 34, source: "snapshot"},
		{name: "api36-snapshot-loss", scenario: "api36-start-snapshot-loss", api: 36, source: "stream"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err, observation := runLaunchScenario(t, test.scenario, test.api)
			if err != nil || observation.GateResult != "LAUNCH_OBSERVED_NOT_QUALIFIED" || observation.MarkerWindow.Status != "CAPTURED" {
				t.Fatalf("bounded collector loss did not retain one canonical event: err=%v observation=%+v", err, observation)
			}
			found := false
			for _, marker := range observation.MarkerWindow.Markers {
				found = found || (marker.MarkerType == "START" && marker.Source == test.source)
			}
			if !found {
				t.Fatalf("START provenance did not identify surviving collector %q: %+v", test.source, observation.MarkerWindow.Markers)
			}
		})
	}
}

func TestLaunchCollectorsExposeCausalLifecycleAndCategoricalCompletion(t *testing.T) {
	type lifecycle struct {
		Buffer          string
		StartStatus     string
		ReadinessStatus string
		TerminalStatus  string
		TerminalReason  string
		OutputTruncated bool
		StderrObserved  bool
	}
	decode := func(t *testing.T, observation launchObservation) []lifecycle {
		t.Helper()
		raw, err := json.Marshal(observation)
		if err != nil {
			t.Fatal(err)
		}
		var report struct{ StreamLifecycle []lifecycle }
		if err := json.Unmarshal(raw, &report); err != nil {
			t.Fatal(err)
		}
		return report.StreamLifecycle
	}

	err, healthy := runLaunchScenario(t, "healthy", 34)
	if err != nil {
		t.Fatal(err)
	}
	states := decode(t, healthy)
	if len(states) != 4 {
		t.Fatalf("collector lifecycle count=%d, want four causal records", len(states))
	}
	for _, state := range states {
		if state.StartStatus != "STARTED" || state.ReadinessStatus != "OUTPUT_SINK_READY" ||
			state.TerminalStatus != "DRAINED" || state.TerminalReason != "CANCELLED_AFTER_CAPTURE" ||
			state.OutputTruncated || state.StderrObserved {
			t.Fatalf("healthy collector lifecycle is ambiguous: %+v", state)
		}
	}

	for _, test := range []struct{ scenario, reason string }{
		{scenario: "terminated-stream", reason: "EOF_BEFORE_STOP"},
		{scenario: "unavailable-stream", reason: "START_FAILED"},
	} {
		t.Run(test.scenario, func(t *testing.T) {
			err, observation := runLaunchScenario(t, test.scenario, 34)
			if !errors.Is(err, errLaunchIncomplete) || observation.GateResult != "BLOCKED" {
				t.Fatalf("incomplete collector changed gate semantics: err=%v gate=%s", err, observation.GateResult)
			}
			states := decode(t, observation)
			if len(states) != 4 {
				t.Fatalf("incomplete collector lifecycle count=%d", len(states))
			}
			for _, state := range states {
				if state.TerminalReason != test.reason {
					t.Fatalf("collector reason=%q, want %q: %+v", state.TerminalReason, test.reason, state)
				}
			}
		})
	}
}

type decodedLaunchStreamRecord struct {
	DeviceNanos int64
	PID         int
	TID         int
	Category    string
}

type decodedLaunchStreamLifecycle struct {
	Buffer                     string
	CommandCategory            string
	Command                    []string
	ExecutionBoundary          string
	CommandIdentityStatus      string
	CommandUID                 int
	CommandGID                 int
	CommandSELinuxContext      string
	StartStatus                string
	ReadinessStatus            string
	TerminalStatus             string
	TerminalReason             string
	CommandStatus              string
	ExitCode                   int
	ExitSignal                 string
	ContextCancellationState   string
	CancellationRequestedUTC   time.Time
	FirstStderrUTC             time.Time
	LastStderrUTC              time.Time
	CommandExitedUTC           time.Time
	CancellationSequence       uint64
	FirstStderrSequence        uint64
	LastStderrSequence         uint64
	CommandExitSequence        uint64
	ExitRelativeToCancellation string
	OutputTruncated            bool
	StderrTruncated            bool
	StderrObserved             bool
	StdoutBytes                int64
	StderrBytes                int64
	StderrSHA256               string
	StderrExcerpt              []string
	LastParsedRecord           decodedLaunchStreamRecord
	StartCapturedBeforeStop    bool
	EndCapturedBeforeStop      bool
	IntentionallyStopped       bool
	ParserComplete             bool
}

type decodedCollectorIdentity struct {
	Status         string
	Rejection      string
	Execution      string
	UID            int
	User           string
	GID            int
	Group          string
	SELinuxContext string
}

type decodedCollectorProbe struct {
	Buffer        string
	Status        string
	Rejection     string
	Argv          []string
	ExitCode      int
	CommandStatus string
	StdoutBytes   int64
	StderrBytes   int64
	StderrExcerpt []string
	Truncated     bool
}

func decodeCollectorCapability(t *testing.T, observation launchObservation) (decodedCollectorIdentity, []decodedCollectorProbe) {
	t.Helper()
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		CollectorIdentity decodedCollectorIdentity
		CollectorProbes   []decodedCollectorProbe
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	return report.CollectorIdentity, report.CollectorProbes
}

func TestLaunchCollectorsUseVerifiedOrdinaryADBShellIdentityAndExactBoundedFilters(t *testing.T) {
	err, observation, fixture := runLaunchFixture(t, "healthy", 34)
	if err != nil {
		t.Fatal(err)
	}
	identity, probes := decodeCollectorCapability(t, observation)
	if identity.Status != "CAPTURED" || identity.Execution != "ADB_SHELL" || identity.UID != 2000 || identity.User != "shell" ||
		identity.GID != 2000 || identity.Group != "shell" || identity.SELinuxContext != "u:r:shell:s0" || identity.Rejection != "" {
		t.Fatalf("collector shell identity is not explicit and complete: %+v", identity)
	}
	wantProbe := func(buffer string) []string {
		if buffer == "events" {
			return []string{"adb", "-s", "emulator-5554", "shell", "logcat", "-b", "events", "-d", "-t", "1",
				"-v", "threadtime", "-v", "monotonic", "-v", "usec", "am_proc_start:I", "am_proc_died:I",
				"am_kill:I", "am_anr:I", "am_crash:I", "*:S"}
		}
		return []string{"adb", "-s", "emulator-5554", "shell", "logcat", "-b", buffer, "-d", "-t", "1",
			"-v", "threadtime", "-v", "monotonic", "-v", "usec", "AndroidRuntime:E", "ActivityManager:I",
			"ActivityTaskManager:I", "KurdistanLaunchProbe:I", "*:S"}
	}
	if len(probes) != 4 {
		t.Fatalf("collector probe count=%d, want one bounded probe per required buffer", len(probes))
	}
	for index, buffer := range []string{"crash", "events", "main", "system"} {
		probe := probes[index]
		if probe.Buffer != buffer || probe.Status != "CAPTURED" || probe.Rejection != "" ||
			!reflect.DeepEqual(probe.Argv, wantProbe(buffer)) || probe.ExitCode != 0 || probe.CommandStatus != "CAPTURED" ||
			probe.StderrBytes != 0 || len(probe.StderrExcerpt) != 0 || probe.Truncated {
			t.Fatalf("%s collector probe is not exact, bounded and complete: %+v", buffer, probe)
		}
	}
	for _, call := range fixture.commands {
		joined := " " + strings.Join(call.args, " ") + " "
		for _, forbidden := range []string{" run-as ", " exec-out ", " su "} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("collector capability or stream crossed an app/root wrapper: %q", call.args)
			}
		}
	}
	for _, lifecycle := range decodeLaunchStreamLifecycle(t, observation) {
		want := []string{"adb", "-s", "emulator-5554", "shell", "logcat", "-b", lifecycle.Buffer, "-v", "threadtime", "-v", "monotonic", "-v", "usec", "-T", "1", "AndroidRuntime:E", "ActivityManager:I", "ActivityTaskManager:I", "KurdistanLaunchProbe:I", "*:S"}
		if lifecycle.Buffer == "events" {
			want = []string{"adb", "-s", "emulator-5554", "shell", "logcat", "-b", "events", "-v", "threadtime", "-v", "monotonic", "-v", "usec", "-T", "1", "am_proc_start:I", "am_proc_died:I", "am_kill:I", "am_anr:I", "am_crash:I", "*:S"}
		}
		if !reflect.DeepEqual(lifecycle.Command, want) || lifecycle.ExecutionBoundary != "ADB_SHELL" ||
			lifecycle.CommandIdentityStatus != "CAPTURED" || lifecycle.CommandUID != 2000 || lifecycle.CommandGID != 2000 ||
			lifecycle.CommandSELinuxContext != "u:r:shell:s0" {
			t.Fatalf("%s stream identity is not bound to the verified ordinary shell: %+v", lifecycle.Buffer, lifecycle)
		}
	}
}

func TestLaunchCollectorCapabilityFailureRemainsBlockedAndSanitized(t *testing.T) {
	for _, scenario := range []string{"unknown-shell-identity", "unknown-shell-context"} {
		t.Run(scenario, func(t *testing.T) {
			err, observation := runLaunchScenario(t, scenario, 34)
			if !errors.Is(err, errLaunchIncomplete) || observation.GateResult != "BLOCKED" || observation.Status != "INCOMPLETE" {
				t.Fatalf("collector capability uncertainty did not fail closed: err=%v gate=%s status=%s", err, observation.GateResult, observation.Status)
			}
			identity, _ := decodeCollectorCapability(t, observation)
			if identity.Status != "INCOMPLETE" || identity.Rejection == "" {
				t.Fatalf("unknown shell identity lacks a categorical rejection: %+v", identity)
			}
			encoded, marshalErr := json.Marshal(observation)
			if marshalErr != nil || strings.Contains(string(encoded), "synthetic-secret") {
				t.Fatal("collector capability evidence retained an unsanitized diagnostic")
			}
		})
	}
}

func TestLaunchOptionalCollectorProbePermissionDenialIsRetainedWithoutBlockingCompleteComposite(t *testing.T) {
	err, observation := runLaunchScenario(t, "permission-denied-preflight", 34)
	if err != nil || observation.GateResult != "LAUNCH_OBSERVED_NOT_QUALIFIED" || observation.Status != "CAPTURED" {
		t.Fatalf("optional probe denial blocked complete replacement evidence: err=%v gate=%s status=%s", err, observation.GateResult, observation.Status)
	}
	_, probes := decodeCollectorCapability(t, observation)
	var rejected int
	for _, probe := range probes {
		if probe.Status == "INCOMPLETE" && probe.Rejection == "COMMAND_FAILED" &&
			strings.Contains(strings.Join(probe.StderrExcerpt, " "), "permission") &&
			strings.Contains(strings.Join(probe.StderrExcerpt, " "), "denied") {
			rejected++
			if probe.Buffer != "main" && probe.Buffer != "system" {
				t.Fatalf("required collector was treated as optional: %+v", probe)
			}
		}
	}
	if rejected != 2 {
		t.Fatalf("permission denial probe count=%d, want main and system only: %+v", rejected, probes)
	}
}

func decodeLaunchStreamLifecycle(t *testing.T, observation launchObservation) []decodedLaunchStreamLifecycle {
	t.Helper()
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		StreamLifecycle []decodedLaunchStreamLifecycle
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	return report.StreamLifecycle
}

func TestLaunchStreamExpectedOwnedShutdownRetainsBoundedStderrWithoutInvalidatingEvidence(t *testing.T) {
	for _, api := range []int{26, 34, 36} {
		t.Run(strconv.Itoa(api), func(t *testing.T) {
			err, observation := runLaunchScenario(t, "owned-shutdown-stderr", api)
			if err != nil || observation.Status != "CAPTURED" || observation.GateResult != "LAUNCH_OBSERVED_NOT_QUALIFIED" {
				t.Fatalf("complete evidence was invalidated by owned shutdown stderr: err=%v gate=%s status=%s issues=%q", err, observation.GateResult, observation.Status, observation.Issues)
			}
			states := decodeLaunchStreamLifecycle(t, observation)
			if len(states) != 4 {
				t.Fatalf("stream lifecycle count=%d, want 4", len(states))
			}
			for _, state := range states {
				wantCommand := []string{"adb", "-s", "emulator-5554", "shell", "logcat", "-b", state.Buffer, "-v", "threadtime", "-v", "monotonic", "-v", "usec", "-T", "1", "AndroidRuntime:E", "ActivityManager:I", "ActivityTaskManager:I", "KurdistanLaunchProbe:I", "*:S"}
				if state.Buffer == "events" {
					wantCommand = []string{"adb", "-s", "emulator-5554", "shell", "logcat", "-b", "events", "-v", "threadtime", "-v", "monotonic", "-v", "usec", "-T", "1", "am_proc_start:I", "am_proc_died:I", "am_kill:I", "am_anr:I", "am_crash:I", "*:S"}
				}
				if state.CommandCategory != "ADB_LOGCAT_STREAM" || !reflect.DeepEqual(state.Command, wantCommand) ||
					!state.StartCapturedBeforeStop || !state.EndCapturedBeforeStop || !state.IntentionallyStopped || !state.ParserComplete {
					t.Fatalf("owned collector identity or completion is incomplete: %+v", state)
				}
				if state.CancellationRequestedUTC.IsZero() || state.CommandExitedUTC.Before(state.CancellationRequestedUTC) ||
					state.CancellationSequence == 0 || state.CommandExitSequence <= state.CancellationSequence ||
					state.ExitRelativeToCancellation != "AFTER_OWNED_CANCELLATION" || state.ContextCancellationState != "CANCELED" {
					t.Fatalf("owned cancellation ordering is not proven: %+v", state)
				}
				if state.Buffer == "crash" || state.Buffer == "events" {
					if state.StderrObserved || state.StderrBytes != 0 || state.TerminalStatus != "DRAINED" {
						t.Fatalf("crash collector acquired unexpected stderr: %+v", state)
					}
					continue
				}
				if state.TerminalStatus != "DRAINED" || state.TerminalReason != "EXPECTED_OWNED_SHUTDOWN" ||
					state.CommandStatus != "CANCELLED" || state.ExitCode != -1 || state.ExitSignal != "" ||
					!state.StderrObserved || state.StderrBytes == 0 || state.StderrTruncated || len(state.StderrExcerpt) == 0 ||
					state.FirstStderrUTC.Before(state.CancellationRequestedUTC) || state.LastStderrUTC.Before(state.FirstStderrUTC) ||
					state.FirstStderrSequence <= state.CancellationSequence || state.LastStderrSequence < state.FirstStderrSequence ||
					state.StdoutBytes == 0 || state.LastParsedRecord.DeviceNanos == 0 {
					t.Fatalf("owned shutdown was not retained as complete bounded evidence: %+v", state)
				}
				evidence := strings.Join(state.StderrExcerpt, " ")
				if !strings.Contains(evidence, "logcat") || !strings.Contains(evidence, "owned") ||
					strings.Contains(evidence, "synthetic-secret") || state.StderrSHA256 == "" {
					t.Fatalf("stderr evidence was not bounded and sanitized: %+v", state)
				}
			}
		})
	}
}

func TestLaunchOptionalStreamPreCancellationTransportFailureRemainsVisibleWithoutBlockingCompleteComposite(t *testing.T) {
	for _, api := range []int{26, 34, 36} {
		t.Run(strconv.Itoa(api), func(t *testing.T) {
			err, observation := runLaunchScenario(t, "pre-cancellation-stderr", api)
			if err != nil || observation.GateResult != "LAUNCH_OBSERVED_NOT_QUALIFIED" || observation.Status != "CAPTURED" {
				t.Fatalf("optional pre-cancellation transport failure blocked complete replacement: err=%v gate=%s status=%s", err, observation.GateResult, observation.Status)
			}
			for _, state := range decodeLaunchStreamLifecycle(t, observation) {
				if state.Buffer == "crash" || state.Buffer == "events" {
					continue
				}
				if state.TerminalReason != "STDERR_BEFORE_OWNED_CANCELLATION" || state.TerminalStatus != "INCOMPLETE" ||
					state.FirstStderrSequence == 0 || state.CancellationSequence == 0 || state.FirstStderrSequence >= state.CancellationSequence ||
					!state.FirstStderrUTC.Before(state.CancellationRequestedUTC) || strings.Contains(strings.Join(state.StderrExcerpt, " "), "synthetic-secret") {
					t.Fatalf("pre-cancellation failure ordering was not retained: %+v", state)
				}
			}
		})
	}
}

func TestLaunchOptionalStreamPostCancellationExitFailureRemainsVisibleWithoutBlockingCompleteComposite(t *testing.T) {
	for _, api := range []int{26, 34, 36} {
		t.Run(strconv.Itoa(api), func(t *testing.T) {
			err, observation := runLaunchScenario(t, "post-cancellation-exit-failure", api)
			if err != nil || observation.GateResult != "LAUNCH_OBSERVED_NOT_QUALIFIED" || observation.Status != "CAPTURED" {
				t.Fatalf("optional post-cancellation failure blocked complete replacement: err=%v gate=%s status=%s", err, observation.GateResult, observation.Status)
			}
			for _, state := range decodeLaunchStreamLifecycle(t, observation) {
				if state.Buffer == "crash" || state.Buffer == "events" {
					continue
				}
				if state.TerminalReason != "POST_CANCELLATION_TRANSPORT_UNPROVEN" || state.TerminalStatus != "INCOMPLETE" ||
					state.CommandStatus != "ERROR" || state.ExitCode != 7 || state.ExitSignal != "" ||
					state.ExitRelativeToCancellation != "AFTER_OWNED_CANCELLATION" || !state.IntentionallyStopped ||
					state.FirstStderrSequence <= state.CancellationSequence {
					t.Fatalf("non-cancellation exit failure was not retained as incomplete evidence: %+v", state)
				}
			}
		})
	}
}

func TestLaunchStreamInvalidCommandConfigurationRemainsBlockedWithSanitizedReason(t *testing.T) {
	for _, api := range []int{26, 34, 36} {
		t.Run(strconv.Itoa(api), func(t *testing.T) {
			err, observation := runLaunchScenario(t, "invalid-stream-command", api)
			if !errors.Is(err, errLaunchIncomplete) || observation.GateResult != "BLOCKED" || observation.Status != "INCOMPLETE" {
				t.Fatalf("invalid stream command did not fail closed: err=%v gate=%s status=%s", err, observation.GateResult, observation.Status)
			}
			states := decodeLaunchStreamLifecycle(t, observation)
			if len(states) != 4 {
				t.Fatalf("invalid command lifecycle count=%d, want 4", len(states))
			}
			for _, state := range states {
				excerpt := strings.Join(state.StderrExcerpt, " ")
				if state.StartStatus != "START_FAILED" || state.TerminalStatus != "INCOMPLETE" ||
					state.TerminalReason != "COMMAND_OR_BUFFER_REJECTED" || state.CommandStatus == "CAPTURED" ||
					state.StderrBytes == 0 || state.FirstStderrSequence == 0 || state.CancellationSequence == 0 ||
					state.FirstStderrSequence >= state.CancellationSequence ||
					!strings.Contains(excerpt, "logcat") || !strings.Contains(excerpt, "invalid") || !strings.Contains(excerpt, "buffer") ||
					strings.Contains(excerpt, "synthetic-secret") {
					t.Fatalf("invalid command reason was not preserved safely: %+v", state)
				}
			}
		})
	}
}

func TestDiagnosticSplitStreamsPreserveCombinedBoundAndReceivedOrder(t *testing.T) {
	output := diagnosticOutput{combined: boundedBuffer{limit: 6}, stdout: boundedBuffer{limit: 6}, stderr: boundedBuffer{limit: 6}}
	stdout, stderr := diagnosticSink{owner: &output}, diagnosticSink{owner: &output, stderr: true}
	_, _ = stdout.Write([]byte("ab"))
	_, _ = stderr.Write([]byte("cd"))
	_, _ = stdout.Write([]byte("efg"))
	if output.combined.String() != "abcdef" || output.stdout.String() != "abefg" || output.stderr.String() != "cd" || !output.combined.exceeded {
		t.Fatal("diagnostics changed the existing combined-output limit or order")
	}
}

func TestDiagnosticCommandFixtureProcess(t *testing.T) {
	at := -1
	for index, arg := range os.Args {
		if arg == "--" {
			at = index
		}
	}
	if at < 0 || at+1 >= len(os.Args) {
		return
	}
	switch os.Args[at+1] {
	case "success":
		fmt.Fprintf(os.Stdout, "child pid=%d\n", os.Getpid())
		fmt.Fprintln(os.Stderr, "child stderr")
		os.Exit(0)
	case "nonzero":
		fmt.Fprintln(os.Stdout, "Status: error")
		fmt.Fprintln(os.Stderr, "credential=synthetic-secret")
		os.Exit(7)
	case "wait":
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt)
		fmt.Fprintln(os.Stdout, "child ready")
		<-interrupt
		signal.Stop(interrupt)
		os.Exit(0)
	}
	os.Exit(9)
}

func TestProductionCommandTransportInvokesRealChildAndKeepsExitState(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	client := newADBClient(executable, "", t.TempDir(), &diagnosticTimeline{Started: time.Now()})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stdout, stderr, record, err := client.diagnosticCommand(ctx, "real-child", 128, "-test.run=^TestDiagnosticCommandFixtureProcess$", "--", "success")
	childPID, parseErr := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(stdout, "child pid=")))
	if err != nil || record.Status != "CAPTURED" || record.ExitCode != 0 || parseErr != nil || childPID <= 0 || childPID == os.Getpid() || stderr != "child stderr\n" {
		t.Fatalf("real child contract failed: err=%v status=%s exit=%d distinct_child=%t stderr_bytes=%d", err, record.Status, record.ExitCode, parseErr == nil && childPID > 0 && childPID != os.Getpid(), len(stderr))
	}
}

type readyChildWriter struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	ready  chan struct{}
	once   sync.Once
}

func (writer *readyChildWriter) Write(value []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	n, err := writer.buffer.Write(value)
	if err == nil && n > 0 {
		writer.once.Do(func() { close(writer.ready) })
	}
	return n, err
}

func (writer *readyChildWriter) String() string {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.buffer.String()
}

func TestReadyChildWriterDoesNotPromoteReaderFromAndSignalsOnce(t *testing.T) {
	writer := &readyChildWriter{ready: make(chan struct{})}
	if _, promoted := any(writer).(io.ReaderFrom); promoted {
		t.Fatal("readiness writer promotes io.ReaderFrom and bypasses its Write method")
	}
	if n, err := writer.Write(nil); err != nil || n != 0 {
		t.Fatalf("empty Write: n=%d err=%v", n, err)
	}
	select {
	case <-writer.ready:
		t.Fatal("empty output signalled readiness")
	default:
	}
	if n, err := writer.Write([]byte("first")); err != nil || n != 5 {
		t.Fatalf("first Write: n=%d err=%v", n, err)
	}
	select {
	case <-writer.ready:
	default:
		t.Fatal("successful nonempty Write did not signal readiness")
	}
	snapshot := writer.String()
	var pending sync.WaitGroup
	for range 8 {
		pending.Add(1)
		go func() {
			defer pending.Done()
			if n, err := writer.Write([]byte("x")); err != nil || n != 1 {
				t.Errorf("concurrent Write: n=%d err=%v", n, err)
			}
			_ = writer.String()
		}()
	}
	pending.Wait()
	if snapshot != "first" || writer.String() != "first"+strings.Repeat("x", 8) {
		t.Fatal("snapshot changed or concurrent output was lost")
	}
}

func TestProductionCommandTransportCancelsAnActuallyStartedStream(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	client := newADBClient(executable, "", t.TempDir(), &diagnosticTimeline{Started: time.Now()})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stdout := &readyChildWriter{ready: make(chan struct{})}
	if _, promoted := any(stdout).(io.ReaderFrom); promoted {
		t.Fatal("real child output could bypass the readiness Write method")
	}
	var stderr bytes.Buffer
	wait, err := client.startCommand(ctx, []string{"-test.run=^TestDiagnosticCommandFixtureProcess$", "--", "wait"}, stdout, &stderr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- wait() }()
	select {
	case <-stdout.ready:
	case <-ctx.Done():
		t.Fatal("real child did not report readiness within its boundary-test context")
	}
	cancel()
	select {
	case err := <-done:
		var exit *exec.ExitError
		if !errors.Is(ctx.Err(), context.Canceled) || !errors.As(err, &exit) || exit.Success() || stderr.Len() != 0 {
			t.Fatalf("real child cancellation lost: context=%v wait=%v stderr_bytes=%d", ctx.Err(), err, stderr.Len())
		}
		if stdout.String() != "child ready\n" {
			t.Fatalf("real subprocess output-copy lost readiness bytes: length=%d", len(stdout.String()))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled real child did not complete its wait")
	}
}

func TestUnavailableCommandTransportOperationsFailClosed(t *testing.T) {
	for _, transport := range []*commandTransport{nil, {}} {
		client := adbClient{path: "must-not-execute", transport: transport}
		ctx, cancel := context.WithCancel(context.Background())
		var output bytes.Buffer
		err := client.runCommand(ctx, []string{"argument"}, &output, &output, time.Second)
		wait, startErr := client.startCommand(ctx, []string{"argument"}, &output, &output, time.Second)
		cancel()
		if err == nil || startErr == nil || wait != nil || output.Len() != 0 {
			t.Fatal("unavailable transport supplied execution, stream ownership, or output")
		}
	}
}

func TestDiagnosticCommandsPreserveExitAndDeadlineAndDoNotPublishRawOutput(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	client := newADBClient(executable, "", t.TempDir(), &diagnosticTimeline{Started: time.Now()})
	args := []string{"-test.run=^TestDiagnosticCommandFixtureProcess$", "--", "nonzero"}
	stdout, stderr, record, commandErr := client.diagnosticCommand(context.Background(), "fixture", maxCommandEvidence, args...)
	if commandErr == nil || record.ExitCode != 7 || record.Status != "ERROR" || !strings.Contains(stdout, "Status: error") || !strings.Contains(stderr, "synthetic-secret") {
		t.Fatalf("lost original command failure: %+v %v", record, commandErr)
	}
	serialized, err := json.Marshal(record)
	if err != nil || strings.Contains(string(serialized), "synthetic-secret") {
		t.Fatal("raw captured bytes escaped into diagnostic JSON")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, record, commandErr = client.diagnosticCommand(ctx, "deadline", maxCommandEvidence, "-test.run=^TestDiagnosticCommandFixtureProcess$", "--", "wait")
	if !errors.Is(commandErr, context.DeadlineExceeded) || record.Status != "DEADLINE" || time.Since(start) > 3*time.Second {
		t.Fatalf("diagnostic timeout not bounded: %v %+v", commandErr, record)
	}
	observation := &launchObservation{client: client, app: defaultAppPackage, Status: "CAPTURED"}
	_, commandErr = observation.captureLaunch(context.Background(), "08-launch.txt", args...)
	raw, readErr := os.ReadFile(filepath.Join(client.evidenceDir, "08-launch.txt"))
	if commandErr == nil || readErr != nil || strings.Contains(string(raw), "synthetic-secret") || observation.Status != "INCOMPLETE" {
		t.Fatalf("diagnostics changed failure or leaked stderr: %v %v", commandErr, readErr)
	}
}

func TestDiagnosticMalformedAndBoundedInputsStayIncomplete(t *testing.T) {
	if hasCapturedFailureCause(nil, nil) {
		t.Fatal("absent failure details called complete")
	}
	classOnly := []diagnosticLogBuffer{{Events: []launchLogEvent{{Tag: "AndroidRuntime", Text: "java.lang.IllegalArgumentException: Failed requirement."}}}}
	if hasCapturedFailureCause(classOnly, nil) {
		t.Fatal("missing stack called complete")
	}
	for _, input := range []string{
		"malformed\nUID PID PPID NAME\n",
		"UID PID PPID NAME\nUID PID PPID NAME\n",
		"10123 999 111 " + defaultAppPackage + "\n",
		"UID PID PPID NAME\n-1 999 111 " + defaultAppPackage + "\n",
	} {
		if _, complete := parseProcessRows(input, defaultAppPackage); complete {
			t.Fatal("ambiguous process inventory called complete")
		}
	}
	for _, stamp := range []string{"1.%N", "-1.0", "9000000001.0", "1.1234567890", "1.0\ninjected"} {
		if _, err := epochNanos(stamp); err == nil {
			t.Fatal("invalid diagnostic time accepted")
		}
	}
	if _, complete := launchWindowEvents(strings.Repeat("x", maxLogcatInput+1), defaultAppPackage, 1, 2); complete {
		t.Fatal("oversized logs called complete")
	}
	if _, complete := javaFailureDetails(strings.Repeat("java.lang.IllegalArgumentException: Failed requirement.\n", 17)); complete {
		t.Fatal("truncated cause chain called complete")
	}
}

func TestMissingJUnitDiagnosticsCannotBecomeTestPass(t *testing.T) {
	root := t.TempDir()
	t.Setenv("JAVA_HOME", root)
	output := filepath.Join(root, "failure.txt")
	if code := runJUnitDiagnostics([]string{"-in", filepath.Join(root, "missing.xml"), "-out", output}); code != 0 {
		t.Fatalf("cannot preserve missing-report state: %d", code)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var report junitDiagnosticReport
	if err := json.Unmarshal(raw, &report); err != nil || report.Status != "INCOMPLETE" || report.Tests != 0 || len(report.Cases) != 0 {
		t.Fatalf("missing report misrepresented: %+v %v", report, err)
	}
	for _, forbidden := range []string{root, "PASS", "device_gate=passed", "synthetic-secret"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("diagnostic missing-data output contains path, secret or success")
		}
	}
}

func TestDiagnosticOnlyJUnitKeepsCauseChainAndRejectsMalformedInput(t *testing.T) {
	fixture := `<testsuite name="org.kurdistanvpn.app.RuntimeAuthorityReissueServiceTest" tests="1" failures="1" errors="0"><testcase name="timedOutMintPoisonsEpochEvenWhenProviderReturnsAfterCancellation" classname="org.kurdistanvpn.app.RuntimeAuthorityReissueServiceTest"><failure type="java.lang.AssertionError" message="java.lang.AssertionError: Failed requirement.">java.lang.AssertionError: Failed requirement.
	 at org.kurdistanvpn.app.RuntimeAuthorityReissueServiceTest.timedOutMintPoisonsEpochEvenWhenProviderReturnsAfterCancellation(RuntimeAuthorityReissueServiceTest.kt:123)
	</failure></testcase><system-out>credential=synthetic-secret</system-out></testsuite>`
	report, err := junitFailureReport([]byte(fixture))
	if err != nil || report.Status != "CAPTURED" || report.Failures != 1 || len(report.Cases) != 1 || len(report.Cases[0].Exceptions[0].Stack) != 1 {
		t.Fatalf("JUnit report=%+v err=%v", report, err)
	}
	if strings.Contains(fmt.Sprint(report), "synthetic-secret") {
		t.Fatal("JUnit system output was exported")
	}
	for _, raw := range []string{"<bad>", fixture + fixture, strings.Repeat("x", maxLogcatInput+1)} {
		if _, err := junitFailureReport([]byte(raw)); err == nil {
			t.Fatal("malformed or oversized JUnit evidence accepted")
		}
	}
}

func TestDiagnosticOnlyJUnitPreservesBoundedQuiescenceStateWithoutHostDetails(t *testing.T) {
	message := "KURDISTAN_QUIESCENCE_DIAGNOSTIC poisoned=1 outcome=TIMEOUT timeout=true interruption=false thread_interrupted=false elapsed_ms=0 future_began=false replied=false replied_late=false cleanup=NOT_REQUIRED late_authorization=false"
	fixture := `<testsuite name="org.kurdistanvpn.app.RuntimeAuthorityReissueServiceTest" tests="1" failures="1" errors="0"><testcase name="boundedQuiescenceActualTimeoutPoisonsAndLateReplyOnlyReleases" classname="org.kurdistanvpn.app.RuntimeAuthorityReissueServiceTest"><failure type="java.lang.AssertionError">java.lang.AssertionError: ` + message + `
	 at org.kurdistanvpn.app.RuntimeAuthorityReissueServiceTest.boundedQuiescenceActualTimeoutPoisonsAndLateReplyOnlyReleases(RuntimeAuthorityReissueServiceTest.kt:123)
	</failure></testcase><system-out>C:\Users\someone\private credential=synthetic-secret</system-out></testsuite>`
	report, err := junitFailureReport([]byte(fixture))
	if err != nil || report.Status != "CAPTURED" || len(report.Cases) != 1 || len(report.Cases[0].Exceptions) != 1 ||
		report.Cases[0].Exceptions[0].Message != message || report.Cases[0].Exceptions[0].MessageRedacted {
		t.Fatalf("bounded quiescence diagnostic was not preserved exactly: report=%+v err=%v", report, err)
	}
	encoded, err := json.Marshal(report)
	if err != nil || strings.Contains(string(encoded), "Users") || strings.Contains(string(encoded), "synthetic-secret") {
		t.Fatalf("JUnit diagnostic retained host or private output: %s err=%v", encoded, err)
	}
}

func TestEvaluateInstrumentationRejectsCategoricalCrashSummary(t *testing.T) {
	output := "INSTRUMENTATION_STATUS_CODE: 0\nOK (1 test)"
	summary := "schema=kurdistan-device-diagnostic-summary-v1\napp_crash=true\n"
	if err := evaluateInstrumentation(output, summary, defaultAppPackage, 1); err == nil {
		t.Fatal("evaluateInstrumentation accepted a categorical app-crash result")
	}
}

func TestInstrumentationSummaryKeepsOnlyBoundedTestIdentity(t *testing.T) {
	raw := strings.Join([]string{
		"INSTRUMENTATION_STATUS: class=org.kurdistanvpn.app.ProfileImportTest",
		"INSTRUMENTATION_STATUS: test=rejectsForgedProfile",
		"INSTRUMENTATION_STATUS: stack=token=secret-value https://10.0.0.8/profile",
		"INSTRUMENTATION_STATUS_CODE: -2",
		"FAILURES!!!",
	}, "\n")
	summary := summarizeInstrumentation(raw)
	if !strings.Contains(summary, "failed_test=org.kurdistanvpn.app.ProfileImportTest#rejectsForgedProfile") {
		t.Fatalf("summary omitted safe failed-test identity: %q", summary)
	}
	for _, forbidden := range []string{"secret-value", "10.0.0.8", "https://", "stack="} {
		if strings.Contains(summary, forbidden) {
			t.Fatalf("summary retained raw instrumentation data %q: %q", forbidden, summary)
		}
	}
	if safeTestIdentity("org.example.Test#method\ninjected=true") {
		t.Fatal("safeTestIdentity accepted a line-injection payload")
	}
}

func TestInstrumentationSummaryClassifiesAccessibilityAssertionWithoutRetainingRawStack(t *testing.T) {
	raw := strings.Join([]string{
		"INSTRUMENTATION_STATUS: class=org.kurdistanvpn.app.Phase13ProductSurfaceDeviceTest",
		"INSTRUMENTATION_STATUS: test=api34AutomatedAccessibilityChecksPassForPrimarySettingsSurface",
		"INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: AccessibilityViewCheckException token=secret-value https://10.0.0.8/profile MainActivity.kt:7781",
		"INSTRUMENTATION_STATUS_CODE: -2",
		"FAILURES!!!",
	}, "\n")

	summary := summarizeInstrumentation(raw)
	for _, expected := range []string{
		"failure_category=accessibility_assertion",
		"failure_exception=java.lang.AssertionError",
	} {
		if !strings.Contains(summary, expected) {
			t.Fatalf("summary omitted %q: %q", expected, summary)
		}
	}
	for _, forbidden := range []string{"secret-value", "10.0.0.8", "https://", "MainActivity.kt", "7781", "stack="} {
		if strings.Contains(summary, forbidden) {
			t.Fatalf("summary retained raw instrumentation data %q: %q", forbidden, summary)
		}
	}
}

func TestInstrumentationSummaryRecordsOnlySafeProgressIdentities(t *testing.T) {
	raw := strings.Join([]string{
		"INSTRUMENTATION_STATUS: class=org.kurdistanvpn.app.FirstTest",
		"INSTRUMENTATION_STATUS: test=completedCase",
		"INSTRUMENTATION_STATUS_CODE: 1",
		"INSTRUMENTATION_STATUS: class=org.kurdistanvpn.app.FirstTest",
		"INSTRUMENTATION_STATUS: test=completedCase",
		"INSTRUMENTATION_STATUS_CODE: 0",
		"INSTRUMENTATION_STATUS: class=org.kurdistanvpn.app.SecondTest",
		"INSTRUMENTATION_STATUS: test=runningCase",
		"INSTRUMENTATION_STATUS_CODE: 1",
	}, "\n")
	summary := summarizeInstrumentation(raw)
	for _, expected := range []string{
		"last_started_test=org.kurdistanvpn.app.SecondTest#runningCase",
		"last_completed_test=org.kurdistanvpn.app.FirstTest#completedCase",
	} {
		if !strings.Contains(summary, expected) {
			t.Fatalf("summary omitted %q: %q", expected, summary)
		}
	}
}

func TestClockDiagnosticsPreserveSafeRawParserRejectionAndRedactUnsafeInput(t *testing.T) {
	record := diagnosticCommand{
		Phase:       "clock-before",
		StartedUTC:  time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC),
		FinishedUTC: time.Date(2026, 8, 29, 10, 0, 0, int(time.Millisecond), time.UTC),
		DurationMS:  1,
		ExitCode:    0,
		Status:      "CAPTURED",
	}
	for _, observed := range []string{"1787966142.N", "1787966146.N"} {
		rejected := clockDiagnostic(observed+"\n", record)
		if rejected.Raw != observed || rejected.RawStatus != "CAPTURED" ||
			rejected.ParseStatus != "REJECTED" || rejected.Rejection != "FRACTION_NON_NUMERIC" ||
			rejected.CommandStatus != "CAPTURED" || rejected.CommandExitCode != 0 {
			t.Fatalf("API 26 clock rejection detail was not preserved exactly for %q: %+v", observed, rejected)
		}
	}
	valid := clockDiagnostic("1787946040.084506886\n", record)
	if valid.ParseStatus != "CAPTURED" || valid.ParsedNanos != 1_787_946_040_084_506_886 || valid.Rejection != "" {
		t.Fatalf("valid clock was not represented canonically: %+v", valid)
	}
	unsafe := clockDiagnostic("token=synthetic-secret endpoint=https://192.0.2.9\n", record)
	encoded, err := json.Marshal(unsafe)
	if err != nil || unsafe.RawStatus != "REDACTED" || unsafe.ParseStatus != "REJECTED" ||
		strings.Contains(string(encoded), "synthetic-secret") || strings.Contains(string(encoded), "192.0.2.9") {
		t.Fatalf("unsafe clock evidence escaped sanitization: %+v err=%v", unsafe, err)
	}
}

func TestClockProbeUsesOneMonotonicLogdDomainOnAllSupportedAPIs(t *testing.T) {
	invocation := strings.Repeat("a", 32)
	marker, commands, err := monotonicClockProbePlan("clock-before", invocation)
	if err != nil {
		t.Fatal(err)
	}
	wantMarker := "CLOCK:clock-before:" + invocation
	want := [][]string{
		{"shell", "log", "-p", "i", "-t", "KurdistanClockProbe", wantMarker},
		{"shell", "logcat", "-b", "main", "-d", "-e", "^" + wantMarker + "$", "-v", "threadtime", "-v", "monotonic", "-v", "usec", "KurdistanClockProbe:I", "*:S"},
	}
	if marker != wantMarker || !reflect.DeepEqual(commands, want) {
		t.Fatalf("clock probe changed domain or command boundaries: marker=%q commands=%q", marker, commands)
	}
	for _, command := range commands {
		joined := strings.Join(command, " ")
		if strings.Contains(joined, "date ") || strings.Contains(joined, " epoch ") || strings.Contains(joined, "%N") {
			t.Fatalf("clock probe retained wall-clock or unsupported fractional dependency: %q", command)
		}
	}
	record := diagnosticCommand{Phase: "clock-before-snapshot", ExitCode: 0, Status: "CAPTURED"}
	raw := "101.123456 11 11 I KurdistanClockProbe: " + marker + "\n"
	evidence := monotonicClockDiagnostic(raw, marker, record)
	if evidence.Domain != "CLOCK_MONOTONIC_LOGCAT" || evidence.ParseStatus != "CAPTURED" ||
		evidence.ParsedNanos != 101_123_456_000 || evidence.Rejection != "" {
		t.Fatalf("monotonic clock evidence changed: %+v", evidence)
	}
	for name, malformed := range map[string]string{
		"missing":   "",
		"duplicate": raw + raw,
		"wrong":     "101.123456 11 11 I KurdistanClockProbe: CLOCK:clock-after:" + invocation + "\n",
		"fraction":  "101.N 11 11 I KurdistanClockProbe: " + marker + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			got := monotonicClockDiagnostic(malformed, marker, record)
			if got.ParseStatus != "REJECTED" || got.Rejection == "" || got.ParsedNanos != 0 {
				t.Fatalf("malformed monotonic clock evidence accepted: %+v", got)
			}
		})
	}
}

func TestClockProbeSurvivesRawTailEvictionWithExactInvocationFilter(t *testing.T) {
	err, observation := runLaunchScenario(t, "api34-clock-tail-eviction", 34)
	clockStatus := make(map[string]string, len(observation.Clocks))
	for _, clock := range observation.Clocks {
		clockStatus[clock.Phase] = clock.ParseStatus
	}
	if err != nil || observation.GateResult != "LAUNCH_OBSERVED_NOT_QUALIFIED" ||
		clockStatus["clock-before"] != "CAPTURED" || clockStatus["clock-after"] != "CAPTURED" {
		t.Fatalf("raw pre-filter tail evicted exact clock evidence: err=%v gate=%s start=%+v end=%+v",
			err, observation.GateResult, clockStatus["clock-before"], clockStatus["clock-after"])
	}
}

func TestLaunchMarkerClockCorrelationMapsWallRecordsIntoMonotonicDomain(t *testing.T) {
	invocation := strings.Repeat("b", 32)
	start := fixtureCanonicalLaunchMarker("START", invocation, strings.Repeat("c", 32), strings.Repeat("d", 32))
	end := fixtureCanonicalLaunchMarker("END", invocation, strings.Repeat("e", 32), strings.Repeat("f", 32))
	monotonic := "101.001000 11 11 I KurdistanLaunchProbe: " + start + "\n" +
		"105.001000 11 11 I KurdistanLaunchProbe: " + end + "\n"
	wall := "1700000001.001000 11 11 I KurdistanLaunchProbe: " + start + "\n" +
		"1700000005.001000 11 11 I KurdistanLaunchProbe: " + end + "\n"
	correlation := correlateLaunchMarkerClocks(monotonic, wall, invocation)
	if correlation.Status != "CAPTURED" || correlation.Rejection != "" ||
		correlation.WallMinusMonotonicNanos != 1_699_999_900_000_000_000 {
		t.Fatalf("clock-domain correlation changed: %+v", correlation)
	}
	for name, changed := range map[string]string{
		"missing":   "",
		"duplicate": wall + "1700000001.002000 11 11 I KurdistanLaunchProbe: " + start + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			got := correlateLaunchMarkerClocks(monotonic, changed, invocation)
			if got.Status != "REJECTED" || got.Rejection == "" || got.WallMinusMonotonicNanos != 0 {
				t.Fatalf("ambiguous wall/monotonic mapping accepted: %+v", got)
			}
		})
	}
	compatible := "1700000001.001000 11 11 I KurdistanLaunchProbe: " + start + "\n" +
		"1700000005.001001 11 11 I KurdistanLaunchProbe: " + end + "\n"
	bounded := correlateLaunchMarkerClocks(monotonic, compatible, invocation)
	if bounded.Status != "CAPTURED" || bounded.Rejection != "" ||
		bounded.StartOffsetNanos != 1_699_999_900_000_000_000 || bounded.EndOffsetNanos != 1_699_999_900_000_001_000 ||
		bounded.WallMinusMonotonicLowerNanos != bounded.EndOffsetNanos-999 ||
		bounded.WallMinusMonotonicUpperNanos != bounded.StartOffsetNanos+999 {
		t.Fatalf("mathematically compatible before/after clock intervals were rejected: %+v", bounded)
	}

	drifted := "1700000001.001000 11 11 I KurdistanLaunchProbe: " + start + "\n" +
		"1700000005.002000 11 11 I KurdistanLaunchProbe: " + end + "\n"
	incompatible := correlateLaunchMarkerClocks(monotonic, drifted, invocation)
	if incompatible.Status != "REJECTED" || incompatible.Rejection != "OFFSET_INTERVAL_INCOMPATIBLE" ||
		incompatible.WallMinusMonotonicNanos != 0 {
		t.Fatalf("mathematically incompatible before/after clock intervals were accepted: %+v", incompatible)
	}
}

func TestNativeFilesystemInstrumentationPlanIsInvocationBoundAndFailClosed(t *testing.T) {
	const targetPackage = "org.example.app"
	const testPackage = "org.example.test"
	const dataDir = "/data/user/0/org.example.app"
	const invocation = "0123456789abcdef0123456789abcdef"
	plan, err := nativeFilesystemInstrumentationPlan(targetPackage, testPackage, dataDir, invocation)
	if err != nil {
		t.Fatal(err)
	}
	wantRoot := dataDir + "/cache/phase17-disposable-" + invocation
	if plan.OwnerPackage != targetPackage || plan.TestPackage != testPackage ||
		plan.Root != wantRoot || plan.Authorization != "5c4c66627867800fad2b3f2d2f92d3f02346c727ce201281493a2cf954fdefbf" {
		t.Fatalf("filesystem plan root or authorization changed: %+v", plan)
	}
	wantChildren := []string{"existing-directory", "leaf-owner", "read-link-identity", "writer-replacement"}
	if !reflect.DeepEqual(plan.Children, wantChildren) {
		t.Fatalf("filesystem child roots changed: %q", plan.Children)
	}
	wantPreparation := [][]string{
		{"shell", "run-as", targetPackage, "mkdir", "cache/phase17-disposable-" + invocation},
		{"shell", "run-as", targetPackage, "chmod", "700", "cache/phase17-disposable-" + invocation},
	}
	for _, child := range wantChildren {
		wantPreparation = append(wantPreparation,
			[]string{"shell", "run-as", targetPackage, "mkdir", "cache/phase17-disposable-" + invocation + "/" + child},
			[]string{"shell", "run-as", targetPackage, "chmod", "700", "cache/phase17-disposable-" + invocation + "/" + child},
		)
	}
	if got := nativeFilesystemPreparationArgs(plan); !reflect.DeepEqual(got, wantPreparation) {
		t.Fatalf("filesystem preparation changed argument order or boundaries:\ngot=%q\nwant=%q", got, wantPreparation)
	}
	runner := testPackage + "/androidx.test.runner.AndroidJUnitRunner"
	args := nativeFilesystemInstrumentationArgs(plan, runner)
	wantArgs := []string{"shell", "am", "instrument", "-w", "-r",
		"-e", "phase17.disposableRoot", wantRoot,
		"-e", "phase17.filesystemAuthorization", plan.Authorization,
		runner,
	}
	if !reflect.DeepEqual(args, wantArgs) || validateNativeFilesystemInstrumentationArgs(args, targetPackage, testPackage) != nil {
		t.Fatalf("instrumentation arguments changed ordering, quoting, or binding: %q", args)
	}
	for _, value := range args {
		if strings.ContainsAny(value, "\"'") {
			t.Fatalf("instrumentation argument requires shell quoting instead of an exact argv boundary: %q", value)
		}
	}
	mutations := map[string][]string{
		"missing-root":       append([]string(nil), args[3:]...),
		"duplicate-root":     append(append([]string(nil), args[:5]...), append([]string{"-e", "phase17.disposableRoot", wantRoot}, args[5:]...)...),
		"malformed-root":     append([]string(nil), args...),
		"substituted-root":   append([]string(nil), args...),
		"unauthorized-token": append([]string(nil), args...),
		"extra-argument":     append(append([]string(nil), args...), "unexpected"),
	}
	mutations["malformed-root"][7] = "../escape"
	mutations["substituted-root"][7] = dataDir + "/cache/phase17-disposable-ffffffffffffffffffffffffffffffff"
	mutations["unauthorized-token"][10] = strings.Repeat("0", 64)
	for name, mutated := range mutations {
		t.Run(name, func(t *testing.T) {
			if err := validateNativeFilesystemInstrumentationArgs(mutated, targetPackage, testPackage); err == nil {
				t.Fatalf("invalid instrumentation arguments accepted: %q", mutated)
			}
		})
	}
}

func TestMarkerDiagnosticsPreserveExactFailedCorrelationWithoutUntrustedText(t *testing.T) {
	invocation := strings.Repeat("a", 32)
	start := fixtureCanonicalLaunchMarker("START", invocation, strings.Repeat("b", 32), strings.Repeat("c", 32))
	end := fixtureCanonicalLaunchMarker("END", invocation, strings.Repeat("d", 32), strings.Repeat("e", 32))
	stream := "101.000001 11 11 I KurdistanLaunchProbe: " + start + "\n" +
		"101.500001 11 11 I UntrustedTag: token=synthetic-secret endpoint=https://192.0.2.9\n"
	snapshot := "105.000001 12 12 I KurdistanLaunchProbe: " + end + "\n"
	window := diagnoseLaunchMarkerWindow(stream, snapshot, invocation, 100_000_000_000, 104_000_000_000)
	if window.Status != "REJECTED" || window.Rejection != "END_AFTER_DEVICE_CLOCK" || len(window.Markers) != 2 {
		t.Fatalf("marker correlation failure was not preserved: %+v", window)
	}
	if window.Markers[0].Source != "stream" || window.Markers[0].Value != start ||
		window.Markers[0].DeviceNanos != 101_000_001_000 || window.Markers[1].Source != "snapshot" ||
		window.Markers[1].Value != end || window.Markers[1].DeviceNanos != 105_000_001_000 {
		t.Fatalf("marker values, sources, or timestamps changed: %+v", window.Markers)
	}
	encoded, err := json.Marshal(window)
	if err != nil || strings.Contains(string(encoded), "synthetic-secret") || strings.Contains(string(encoded), "192.0.2.9") {
		t.Fatalf("untrusted marker-adjacent text escaped: %s err=%v", encoded, err)
	}
}

func TestInstrumentationDiagnosticsPreserveBoundedPerTestFailureTimeline(t *testing.T) {
	started := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	chunks := []instrumentationDiagnosticChunk{
		{ObservedUTC: started, Raw: strings.Join([]string{
			"INSTRUMENTATION_STATUS: class=org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest",
			"INSTRUMENTATION_STATUS: test=dnsFailClosedAcceptsBoundedNetworkFailuresOnlyWhenUnavailabilityIsExpected",
			"INSTRUMENTATION_STATUS_CODE: 1",
		}, "\n") + "\n"},
		{ObservedUTC: started.Add(275 * time.Millisecond), Raw: strings.Join([]string{
			"INSTRUMENTATION_STATUS: class=org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest",
			"INSTRUMENTATION_STATUS: test=dnsFailClosedAcceptsBoundedNetworkFailuresOnlyWhenUnavailabilityIsExpected",
			"INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: KURDISTAN_TEST_SETUP expected=ACTIVE_KURD_LIVE actual=FAILED setup=DNS_EXPECTED_AVAILABLE",
			" at org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest.dnsFailClosedAcceptsBoundedNetworkFailuresOnlyWhenUnavailabilityIsExpected(Phase17LiveDataPlaneDeviceTest.kt:514)",
			" at org.junit.Assert.fail(Assert.java:87)",
			"INSTRUMENTATION_STATUS_CODE: -2",
			"FAILURES!!!",
		}, "\n") + "\n"},
	}
	command := diagnosticCommand{Phase: "instrumentation", StartedUTC: started, FinishedUTC: started.Add(300 * time.Millisecond), DurationMS: 300, ExitCode: 1, Status: "ERROR"}
	report := buildInstrumentationDiagnostic(chunks, command, false)
	if report.Status != "CAPTURED" || !report.InstrumentationStarted || report.TestsBegan != 1 ||
		report.TestsCompleted != 1 || report.LastObserved == nil || report.LastObserved.Status != "FAIL" ||
		len(report.Failures) != 1 {
		t.Fatalf("instrumentation progress or failure count was not preserved: %+v", report)
	}
	failure := report.Failures[0]
	if failure.Class != "org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest" ||
		failure.Method != "dnsFailClosedAcceptsBoundedNetworkFailuresOnlyWhenUnavailabilityIsExpected" ||
		failure.Status != "FAIL" || failure.DurationMS != 275 || failure.Category != "assertion" ||
		failure.ExceptionType != "java.lang.AssertionError" ||
		failure.Message != "KURDISTAN_TEST_SETUP expected=ACTIVE_KURD_LIVE actual=FAILED setup=DNS_EXPECTED_AVAILABLE" ||
		failure.Expected != "ACTIVE_KURD_LIVE" || failure.Actual != "FAILED" ||
		!reflect.DeepEqual(failure.SetupState, []string{"DNS_EXPECTED_AVAILABLE"}) ||
		!reflect.DeepEqual(failure.ApplicationStack, []string{
			"at org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest.dnsFailClosedAcceptsBoundedNetworkFailuresOnlyWhenUnavailabilityIsExpected(Phase17LiveDataPlaneDeviceTest.kt:514)",
		}) {
		t.Fatalf("per-test failure detail changed or was incomplete: %+v", failure)
	}

	unsafeChunks := append([]instrumentationDiagnosticChunk(nil), chunks[:1]...)
	unsafeChunks = append(unsafeChunks, instrumentationDiagnosticChunk{ObservedUTC: started.Add(time.Second), Raw: strings.Join([]string{
		"INSTRUMENTATION_STATUS: class=org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest",
		"INSTRUMENTATION_STATUS: test=dnsFailClosedAcceptsBoundedNetworkFailuresOnlyWhenUnavailabilityIsExpected",
		"INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: token=synthetic-secret endpoint=https://192.0.2.9",
		" at example.untrusted.secretMethod(C:\\Users\\someone\\private.kt:4)",
		"INSTRUMENTATION_STATUS_CODE: -2",
	}, "\n") + "\n"})
	unsafe := buildInstrumentationDiagnostic(unsafeChunks, command, false)
	encoded, err := json.Marshal(unsafe)
	if err != nil || unsafe.Status != "INCOMPLETE" || len(unsafe.Failures) != 1 ||
		unsafe.Failures[0].ExceptionType != "java.lang.AssertionError" ||
		strings.Contains(string(encoded), "synthetic-secret") || strings.Contains(string(encoded), "192.0.2.9") ||
		strings.Contains(string(encoded), "Users") || strings.Contains(string(encoded), "secretMethod") {
		t.Fatalf("unsafe instrumentation detail escaped or was treated as complete: %s err=%v", encoded, err)
	}
}

func TestInstrumentationDiagnosticsPreserveKnownRunnerStatusCodes(t *testing.T) {
	started := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name         string
		code         int
		stack        string
		wantStatus   string
		wantFailures int
	}{
		{name: "ignored", code: -3, wantStatus: "IGNORED", wantFailures: 0},
		{name: "assumption", code: -4, stack: "org.junit.AssumptionViolatedException: Failed requirement.", wantStatus: "ASSUMPTION_FAILURE", wantFailures: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lines := []string{
				"INSTRUMENTATION_STATUS: class=org.kurdistanvpn.app.DiagnosticStatusDeviceTest",
				"INSTRUMENTATION_STATUS: test=" + test.name,
				"INSTRUMENTATION_STATUS_CODE: 1",
				"INSTRUMENTATION_STATUS: class=org.kurdistanvpn.app.DiagnosticStatusDeviceTest",
				"INSTRUMENTATION_STATUS: test=" + test.name,
			}
			if test.stack != "" {
				lines = append(lines, "INSTRUMENTATION_STATUS: stack="+test.stack)
			}
			lines = append(lines, fmt.Sprintf("INSTRUMENTATION_STATUS_CODE: %d", test.code))
			report := buildInstrumentationDiagnostic([]instrumentationDiagnosticChunk{
				{ObservedUTC: started, Raw: strings.Join(lines[:3], "\n") + "\n"},
				{ObservedUTC: started.Add(25 * time.Millisecond), Raw: strings.Join(lines[3:], "\n") + "\n"},
			}, diagnosticCommand{Phase: "instrumentation", StartedUTC: started, FinishedUTC: started.Add(30 * time.Millisecond), DurationMS: 30, ExitCode: 0, Status: "CAPTURED"}, false)
			if report.Status != "CAPTURED" || report.LastObserved == nil || report.LastObserved.Status != test.wantStatus ||
				report.LastObserved.DurationMS != 25 || len(report.Failures) != test.wantFailures {
				t.Fatalf("runner status %d was not represented exactly: %+v", test.code, report)
			}
		})
	}
}

func TestInstrumentationDetailsSurviveLegacySummaryLimitFailure(t *testing.T) {
	root := t.TempDir()
	client := newADBClient("fixture-adb", "emulator-5554", root, &diagnosticTimeline{Started: time.Now()})
	client.transport = &commandTransport{run: func(_ context.Context, _ string, _ []string, stdout, _ io.Writer, _ time.Duration) error {
		className := "org.kurdistanvpn.app." + strings.Repeat("Diagnostic", 18)
		for index := 0; index < 64; index++ {
			method := fmt.Sprintf("failure%02d%s", index, strings.Repeat("Case", 10))
			_, _ = fmt.Fprintf(stdout, "INSTRUMENTATION_STATUS: class=%s\nINSTRUMENTATION_STATUS: test=%s\nINSTRUMENTATION_STATUS: stack=java.lang.AssertionError: Failed requirement.\nINSTRUMENTATION_STATUS_CODE: -2\n", className, method)
		}
		return errors.New("instrumentation failed")
	}}
	_, commandErr := client.captureInstrumentation(context.Background(), "13-instrumentation-summary.txt", "shell", "am", "instrument")
	if commandErr == nil || !strings.Contains(commandErr.Error(), "summary exceeded") {
		t.Fatalf("legacy summary limit did not remain fail-closed: %v", commandErr)
	}
	raw, readErr := os.ReadFile(filepath.Join(root, "13-instrumentation-details.json"))
	if readErr != nil {
		t.Fatalf("bounded diagnostic detail was lost when legacy summary overflowed: %v", readErr)
	}
	var report instrumentationDiagnosticReport
	if json.Unmarshal(raw, &report) != nil || report.Status != "INCOMPLETE" || report.TestsCompleted != 64 {
		t.Fatalf("retained diagnostic does not describe the bounded overflow: %s", raw)
	}
}

func TestLaunchObservationSerializesClockAndMarkerRejectionEvidenceWithoutChangingGate(t *testing.T) {
	err, observation := runLaunchScenario(t, "modern-healthy", 36)
	if err != nil || observation.GateResult != "LAUNCH_OBSERVED_NOT_QUALIFIED" {
		t.Fatalf("diagnostic preservation changed a healthy launch result: err=%v gate=%s", err, observation.GateResult)
	}
	encoded, marshalErr := json.Marshal(observation)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, required := range []string{"\"Clocks\"", "\"RawStatus\"", "\"ParseStatus\"", "\"MarkerWindow\"", "\"Markers\""} {
		if !strings.Contains(string(encoded), required) {
			t.Fatalf("launch evidence omitted diagnostic field %s: %s", required, encoded)
		}
	}
}

func TestCaptureInstrumentationAlwaysWritesBoundedSanitizedFailureDetails(t *testing.T) {
	root := t.TempDir()
	client := newADBClient("fixture-adb", "emulator-5554", root, &diagnosticTimeline{Started: time.Now()})
	client.transport = &commandTransport{run: func(_ context.Context, _ string, _ []string, stdout, _ io.Writer, _ time.Duration) error {
		_, _ = io.WriteString(stdout, strings.Join([]string{
			"INSTRUMENTATION_STATUS: class=org.kurdistanvpn.app.ProtectedStateStartupDeviceTest",
			"INSTRUMENTATION_STATUS: test=firstUseViewModelIsDisconnectedAndDoesNotProvisionProtectedState",
			"INSTRUMENTATION_STATUS_CODE: 1",
		}, "\n")+"\n")
		_, _ = io.WriteString(stdout, strings.Join([]string{
			"INSTRUMENTATION_STATUS: class=org.kurdistanvpn.app.ProtectedStateStartupDeviceTest",
			"INSTRUMENTATION_STATUS: test=firstUseViewModelIsDisconnectedAndDoesNotProvisionProtectedState",
			"INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: token=synthetic-secret endpoint=https://192.0.2.9",
			"INSTRUMENTATION_STATUS_CODE: -2",
			"FAILURES!!!",
		}, "\n")+"\n")
		return errors.New("instrumentation failed")
	}}
	_, commandErr := client.captureInstrumentation(context.Background(), "13-instrumentation-summary.txt", "shell", "am", "instrument")
	if commandErr == nil {
		t.Fatal("fixture did not preserve the instrumentation command failure")
	}
	raw, readErr := os.ReadFile(filepath.Join(root, "13-instrumentation-details.json"))
	if readErr != nil {
		t.Fatalf("bounded failure detail was not written: %v", readErr)
	}
	var report instrumentationDiagnosticReport
	if json.Unmarshal(raw, &report) != nil || !report.InstrumentationStarted || report.TestsBegan != 1 ||
		report.TestsCompleted != 1 || len(report.Failures) != 1 {
		t.Fatalf("failure detail does not represent the attempted instrumentation: %s", raw)
	}
	for _, forbidden := range []string{"synthetic-secret", "192.0.2.9", "https://", "device_gate=passed", "PASS"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("failure detail leaked %q or fabricated success: %s", forbidden, raw)
		}
	}
	if len(raw) > maxInstrumentationDiagnosticBytes {
		t.Fatalf("failure detail size=%d exceeds bound=%d", len(raw), maxInstrumentationDiagnosticBytes)
	}
}

func TestGeneralDiagnosticLogcatExcludesDebugNoise(t *testing.T) {
	want := []string{"logcat", "-b", "all", "-t", "4096", "-v", "brief", "*:W"}
	if got := diagnosticLogcatArgs("all"); !reflect.DeepEqual(got, want) {
		t.Fatalf("diagnosticLogcatArgs() = %v, want %v", got, want)
	}
}

func TestInstrumentationPreparationDisablesAnimationsAndCompilesExactPackages(t *testing.T) {
	commands := instrumentationPreparationCommands("org.example.app", "org.example.app.test")
	if len(commands) != 5 {
		t.Fatalf("preparation command count = %d, want 5", len(commands))
	}
	joined := make([]string, 0, len(commands))
	for _, command := range commands {
		joined = append(joined, command.evidence+":"+strings.Join(command.args, " "))
	}
	actual := strings.Join(joined, "\n")
	for _, expected := range []string{
		"settings put global window_animation_scale 0",
		"settings put global transition_animation_scale 0",
		"settings put global animator_duration_scale 0",
		"cmd package compile -m speed -f org.example.app",
		"cmd package compile -m speed -f org.example.app.test",
	} {
		if !strings.Contains(actual, expected) {
			t.Fatalf("preparation commands omitted %q: %q", expected, actual)
		}
	}
}

func TestTransientPackageServiceFailureMatchesPreparationRestart(t *testing.T) {
	if !transientPackageServiceFailure("cmd: Failure calling service package: Broken pipe (32)") {
		t.Fatal("transientPackageServiceFailure rejected the package compilation restart observed on API 36")
	}
}

func TestInstrumentationPreparationRetriesTransientPackageServiceRestart(t *testing.T) {
	commands := []instrumentationPreparationCommand{{
		evidence: "04g-compile-application.txt",
		args:     []string{"shell", "cmd", "package", "compile", "example"},
	}}
	var evidence []string
	waitPrefix := ""
	calls := 0
	recovered, err := prepareInstrumentationRuntimeWith(
		context.Background(),
		commands,
		func(_ context.Context, name string, _ ...string) (string, error) {
			calls++
			evidence = append(evidence, name)
			if calls == 1 {
				return "cmd: Failure calling service package: Broken pipe (32)", errors.New("exit status 224")
			}
			return "Success", nil
		},
		func(prefix string) error {
			waitPrefix = prefix
			return nil
		},
	)
	if err != nil {
		t.Fatalf("prepareInstrumentationRuntimeWith transient retry: %v", err)
	}
	if !recovered {
		t.Fatal("prepareInstrumentationRuntimeWith did not report package service recovery")
	}
	if calls != 2 || waitPrefix != "04g-compile-application-retry" {
		t.Fatalf("retry calls=%d waitPrefix=%q", calls, waitPrefix)
	}
	wantEvidence := []string{"04g-compile-application.txt", "04g-compile-application-retry.txt"}
	if !reflect.DeepEqual(evidence, wantEvidence) {
		t.Fatalf("retry evidence = %v, want %v", evidence, wantEvidence)
	}
}

func TestInstrumentationPreparationDoesNotRetryPermanentFailure(t *testing.T) {
	waited := false
	recovered, err := prepareInstrumentationRuntimeWith(
		context.Background(),
		[]instrumentationPreparationCommand{{evidence: "04g-compile-application.txt"}},
		func(context.Context, string, ...string) (string, error) {
			return "Error: package is unknown", errors.New("exit status 1")
		},
		func(string) error {
			waited = true
			return nil
		},
	)
	if err == nil || waited || recovered {
		t.Fatalf("permanent failure err=%v waited=%t recovered=%t", err, waited, recovered)
	}
}

func TestInstrumentationPreparationReportsNoRecoveryOnCleanSuccess(t *testing.T) {
	recovered, err := prepareInstrumentationRuntimeWith(
		context.Background(),
		[]instrumentationPreparationCommand{{evidence: "04g-compile-application.txt"}},
		func(context.Context, string, ...string) (string, error) { return "Success", nil },
		func(string) error { return errors.New("unexpected wait") },
	)
	if err != nil || recovered {
		t.Fatalf("clean preparation err=%v recovered=%t", err, recovered)
	}
}

func TestPackageConfigurationCommandsRespectNotificationPermissionAPI(t *testing.T) {
	legacy := packageConfigurationCommands("org.example.app", 26)
	modern := packageConfigurationCommands("org.example.app", 36)
	if len(legacy) != 2 || len(modern) != 3 {
		t.Fatalf("legacy commands=%d modern commands=%d", len(legacy), len(modern))
	}
	if modern[2].evidence != "04b-grant-notification-permission.txt" {
		t.Fatalf("modern notification evidence=%q", modern[2].evidence)
	}
}

func TestPackageConfigurationReplaysAllStateAfterPackageServiceRecovery(t *testing.T) {
	commands := packageConfigurationCommands("org.example.app", 36)
	var evidence []string
	recoveryPrefix := ""
	grantCalls := 0
	err := configureInstalledPackagesWith(
		context.Background(),
		commands,
		func(_ context.Context, name string, _ ...string) (string, error) {
			evidence = append(evidence, name)
			if strings.HasPrefix(name, "04b-grant-notification-permission") {
				grantCalls++
				if grantCalls == 1 {
					return "cmd: Failure calling service package: Broken pipe (32)", errors.New("exit status 224")
				}
			}
			return "Success", nil
		},
		func(prefix string) error {
			recoveryPrefix = prefix
			return nil
		},
	)
	if err != nil {
		t.Fatalf("configureInstalledPackagesWith transient recovery: %v", err)
	}
	if recoveryPrefix != "04b-grant-notification-permission-recovery" {
		t.Fatalf("recovery prefix=%q", recoveryPrefix)
	}
	want := []string{
		"04-clear-app-data.txt",
		"04a-authorize-test-vpn.txt",
		"04b-grant-notification-permission.txt",
		"04-clear-app-data-retry.txt",
		"04a-authorize-test-vpn-retry.txt",
		"04b-grant-notification-permission-retry.txt",
	}
	if !reflect.DeepEqual(evidence, want) {
		t.Fatalf("configuration evidence=%v want=%v", evidence, want)
	}
}

func TestPackageConfigurationDoesNotRecoverPermanentFailure(t *testing.T) {
	recovered := false
	err := configureInstalledPackagesWith(
		context.Background(),
		packageConfigurationCommands("org.example.app", 36),
		func(context.Context, string, ...string) (string, error) {
			return "permission denied", errors.New("exit status 1")
		},
		func(string) error {
			recovered = true
			return nil
		},
	)
	if err == nil || recovered {
		t.Fatalf("permanent configuration failure err=%v recovered=%t", err, recovered)
	}
}

func TestBoundedBufferRetainsPrefixAndSignalsOverflow(t *testing.T) {
	buffer := boundedBuffer{limit: 4}
	if written, err := buffer.Write([]byte("abcdef")); err != nil || written != 6 {
		t.Fatalf("Write() = (%d, %v), want (6, nil)", written, err)
	}
	if got := buffer.String(); got != "abcd" {
		t.Fatalf("buffer = %q, want %q", got, "abcd")
	}
	if !buffer.exceeded {
		t.Fatal("bounded buffer did not report overflow")
	}
}

func TestInstalledPackageIdentityParsersDoNotRetainPaths(t *testing.T) {
	paths := "package:/data/app/~~stable-device-token/base.apk\npackage:/data/app/split.apk\n"
	if got := installedPathCount(paths); got != 2 {
		t.Fatalf("installedPathCount() = %d, want 2", got)
	}
	runner := "instrumentation:org.kurdistanvpn.app.internal.test/androidx.test.runner.AndroidJUnitRunner (target=org.kurdistanvpn.app.internal)"
	if !containsExactLine(runner+"\n", runner) {
		t.Fatal("containsExactLine rejected the exact instrumentation identity")
	}
	if containsExactLine(runner+".suffix\n", runner) {
		t.Fatal("containsExactLine accepted an instrumentation identity suffix collision")
	}
}

func TestContainsAppCrashRejectsPackagePrefixCollision(t *testing.T) {
	logcat := "FATAL EXCEPTION in org.kurdistanvpn.app.debugger"
	if containsAppCrash(logcat, defaultAppPackage) {
		t.Fatal("containsAppCrash() accepted a longer package name with the same prefix")
	}
}

func TestEvidenceLabelIsBoundedAndNonExecutable(t *testing.T) {
	for _, value := range []string{"PHASE 9", "PHASE 11", "ANDROID-LOCAL"} {
		if !validLabel(value) {
			t.Fatalf("valid label rejected: %q", value)
		}
	}
	for _, value := range []string{
		"",
		"phase 11",
		"PHASE_11",
		"PHASE 11\nINJECTED",
		strings.Repeat("A", 33),
	} {
		if validLabel(value) {
			t.Fatalf("invalid label accepted: %q", value)
		}
	}
}

func TestDeviceEvidencePropertyAllowListExcludesStableIdentifiers(t *testing.T) {
	joined := strings.ToLower(fmt.Sprint(deviceEvidenceProperties))
	for _, forbidden := range []string{"serial", "fingerprint", "android_id", "imei"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("device evidence allow-list contains stable identifier %q", forbidden)
		}
	}
}

func TestPackageListContainsExactRejectsPrefixAndSuffixCollisions(t *testing.T) {
	output := strings.Join([]string{
		"package:org.kurdistanvpn.app.internal.debug",
		"package:example.org.kurdistanvpn.app.internal",
		"package:org.kurdistanvpn.app.internal.test",
	}, "\n")
	if packageListContainsExact(output, "org.kurdistanvpn.app.internal") {
		t.Fatal("packageListContainsExact accepted a package-name collision")
	}
	if !packageListContainsExact(
		output+"\npackage:org.kurdistanvpn.app.internal\n",
		"org.kurdistanvpn.app.internal",
	) {
		t.Fatal("packageListContainsExact rejected the exact package")
	}
	if packageListContainsExact(output, "") {
		t.Fatal("packageListContainsExact accepted an empty package")
	}
}

func TestExpectedDeviceIdentityRejectsWrongAPI(t *testing.T) {
	if err := verifyExpectedDeviceIdentity(34, "x86_64", 36, "x86_64"); err == nil {
		t.Fatal("API 34 lane accepted an API 36 device")
	}
}

func TestExpectedDeviceIdentityRejectsWrongPrimaryABI(t *testing.T) {
	if err := verifyExpectedDeviceIdentity(34, "x86_64", 34, "arm64-v8a"); err == nil {
		t.Fatal("x86_64 lane accepted an arm64-v8a device")
	}
}

func TestExpectedDeviceIdentityRequiresAPIBandABIAsPair(t *testing.T) {
	for _, expected := range []struct {
		api int
		abi string
	}{
		{api: 34},
		{abi: "x86_64"},
	} {
		if err := verifyExpectedDeviceIdentity(expected.api, expected.abi, 34, "x86_64"); err == nil {
			t.Fatalf("incomplete expected identity passed: API %d ABI %q", expected.api, expected.abi)
		}
	}
}

func TestExpectedDeviceIdentityRejectsInvalidExpectation(t *testing.T) {
	if err := verifyExpectedDeviceIdentity(-1, "x86_64", 34, "x86_64"); err == nil {
		t.Fatal("negative expected API passed")
	}
}

func TestExpectedDeviceIdentityRejectsUnknownABI(t *testing.T) {
	if err := verifyExpectedDeviceIdentity(34, "x86_64;unexpected", 34, "x86_64;unexpected"); err == nil {
		t.Fatal("unknown expected ABI passed")
	}
}
