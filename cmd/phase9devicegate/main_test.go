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
			exit.Timestamp.UnixNano() >= observation.WindowStartNanos && exit.Timestamp.UnixNano() <= observation.WindowEndNanos,
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

func runLaunchFixture(t *testing.T, scenario string, api int) (error, launchObservation, *launchFixtureTransport) {
	t.Helper()
	root := t.TempDir()
	fixture := newLaunchFixtureTransport(scenario)
	client := newADBClient("fixture-adb", "emulator-5554", root, &diagnosticTimeline{Started: time.Now()})
	client.transport = &commandTransport{run: fixture.run, start: fixture.start}
	budget := 12 * time.Second
	if scenario == "timeout" {
		budget = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	err := launchSmokeWithDiagnostics(ctx, client, options{appPackage: defaultAppPackage, expectedAPI: api})
	var observation launchObservation
	data, readErr := os.ReadFile(filepath.Join(root, "10-launch-details.txt"))
	if readErr != nil || json.Unmarshal(data, &observation) != nil {
		t.Fatal("launch observation was not preserved")
	}
	fixture.assertClosed(t)
	logLaunchScenario(t, err, observation)
	return err, observation, fixture
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

func newFixtureStream(ctx context.Context, output io.Writer, terminate bool) *fixtureStream {
	stream := &fixtureStream{
		chunks: make(chan fixtureOutputChunk), ready: make(chan struct{}), done: make(chan struct{}),
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
	go func() {
		if !terminate {
			<-ctx.Done()
			stream.cancelled.Add(1)
		}
		// Do not close output until the current accepted chunk is fully copied.
		// A later write returns an explicit error instead of losing bytes.
		stream.mu.Lock()
		defer stream.mu.Unlock()
		if !terminate {
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
	mu        sync.Mutex
	scenario  string
	clock     time.Time
	launched  time.Time
	processes int
	logs      map[string]string
	streams   map[string]*fixtureStream
	commands  []fixtureCommand
	blocked   chan struct{}
}

func newLaunchFixtureTransport(scenario string) *launchFixtureTransport {
	return &launchFixtureTransport{
		scenario: scenario,
		clock:    time.Unix(1_700_000_000, 0).UTC(),
		logs:     make(map[string]string),
		streams:  make(map[string]*fixtureStream),
		blocked:  make(chan struct{}),
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
	case command == "date +%s.%N":
		fmt.Fprintln(stdout, fixtureStamp(fixture.clock))
	case command == "date +%z":
		fmt.Fprintln(stdout, "+0000")
	case strings.HasPrefix(command, "log -p i -t KurdistanLaunchProbe "):
		if scenario == "missing-markers" {
			return nil
		}
		if scenario == "terminated-stream" && strings.HasPrefix(args[len(args)-1], "END:") {
			for _, stream := range fixture.streams {
				select {
				case <-stream.done:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
		return fixture.appendLog("main", fixtureStamp(fixture.clock)+" 11 11 I KurdistanLaunchProbe: "+args[len(args)-1]+"\n")
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
	case command == "pidof "+defaultAppPackage:
		if scenario == "process-death" {
			return errors.New("fixture target no longer exists")
		}
		fmt.Fprintln(stdout, "999")
	case command == "am start -W -f 0x10008000 -n "+defaultAppPackage+"/org.kurdistanvpn.app.MainActivity":
		fixture.launched = fixture.clock
		system := fixtureStamp(fixture.launched) + " 10 10 I ActivityManager: Start proc 999:" + defaultAppPackage + "/u0a123 for activity\n"
		if scenario == "stale-dialog" {
			system = fixtureStamp(fixture.launched.Add(-time.Hour)) +
				" 10 10 I ActivityManager: AppErrorDialog for " + defaultAppPackage + "\n" + system
		}
		if err := fixture.appendLog("system", system); err != nil {
			return err
		}
		if strings.HasSuffix(scenario, "crash") {
			at, pid, app := fixture.clock, 999, defaultAppPackage
			if scenario == "stale-crash" {
				at = at.Add(-time.Hour)
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
	case command == "dumpsys activity exit-info "+defaultAppPackage:
		if scenario == "missing-exit-observation" {
			return nil
		}
		fmt.Fprintln(stdout, "ACTIVITY MANAGER PROCESS EXIT INFO (dumpsys activity exit-info)\nLast Timestamp of Persistence Into Persistent Storage: 1970-01-01 00:00:00.000")
		if strings.HasSuffix(scenario, "exit") {
			at, uid := fixture.launched.Add(time.Millisecond), 10123
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
		if !strings.Contains(command, "-v threadtime -v epoch -v usec") || !strings.Contains(" "+command+" ", " -d ") {
			return errors.New("unexpected fixture log snapshot options")
		}
		value, known := fixture.logs[args[2]]
		if !known && args[2] != "crash" && args[2] != "main" && args[2] != "system" {
			return errors.New("unexpected fixture log buffer")
		}
		fmt.Fprint(stdout, value)
	default:
		return fmt.Errorf("unexpected fixture command: %q", args)
	}
	return nil
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
	if fixture.scenario == "unavailable-stream" {
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
	want := []string{"logcat", "-b", buffer, "-v", "threadtime", "-v", "epoch", "-v", "usec", "-T", "1",
		"AndroidRuntime:E", "ActivityManager:I", "ActivityTaskManager:I", "KurdistanLaunchProbe:I", "*:S"}
	if (buffer != "crash" && buffer != "main" && buffer != "system") || !reflect.DeepEqual(args, want) || fixture.streams[buffer] != nil {
		return nil, errors.New("unexpected or duplicate fixture stream")
	}
	stream := newFixtureStream(ctx, stdout, fixture.scenario == "terminated-stream")
	fixture.streams[buffer] = stream
	return stream.wait, nil
}

func (fixture *launchFixtureTransport) assertClosed(t *testing.T) {
	t.Helper()
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	want := 3
	if fixture.scenario == "unavailable-stream" || fixture.scenario == "stream-without-wait" {
		want = 0
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
	for _, call := range fixture.commands {
		got = append(got, call.kind+" "+strings.Join(call.args, " "))
		wantDelay := time.Second
		if strings.Join(call.args, " ") == "-s emulator-5554 shell pidof "+defaultAppPackage {
			wantDelay = 0
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
	prefix := "run -s emulator-5554 shell "
	streamPrefix := "start -s emulator-5554 shell logcat -b "
	streamSuffix := " -v threadtime -v epoch -v usec -T 1 AndroidRuntime:E ActivityManager:I ActivityTaskManager:I KurdistanLaunchProbe:I *:S"
	want := []string{
		prefix + "date +%s.%N", prefix + "date +%z",
		streamPrefix + "crash" + streamSuffix, streamPrefix + "main" + streamSuffix, streamPrefix + "system" + streamSuffix,
		prefix + "log -p i -t KurdistanLaunchProbe START:" + observation.Invocation,
		prefix + "ps -A -o UID,PID,PPID,NAME",
		prefix + "cmd package resolve-activity --brief -n " + defaultAppPackage + "/org.kurdistanvpn.app.MainActivity",
		prefix + "am start -W -f 0x10008000 -n " + defaultAppPackage + "/org.kurdistanvpn.app.MainActivity",
		prefix + "ps -A -o UID,PID,PPID,NAME", prefix + "cat /proc/999/stat",
		prefix + "pidof " + defaultAppPackage,
		prefix + "ps -A -o UID,PID,PPID,NAME", prefix + "cat /proc/999/stat",
		prefix + "ps -A -o UID,PID,PPID,NAME", prefix + "cat /proc/999/stat",
		prefix + "dumpsys activity processes " + defaultAppPackage,
		prefix + "log -p i -t KurdistanLaunchProbe END:" + observation.Invocation,
		prefix + "logcat -b main -d -t 128 -v threadtime -v epoch -v usec KurdistanLaunchProbe:I *:S",
		prefix + "date +%s.%N", prefix + "dumpsys activity exit-info " + defaultAppPackage,
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
	for _, buffer := range []string{"crash", "main", "system"} {
		output := &readyChildWriter{ready: make(chan struct{})}
		outputs[buffer] = output
		args := []string{"-s", "emulator-5554", "shell", "logcat", "-b", buffer,
			"-v", "threadtime", "-v", "epoch", "-v", "usec", "-T", "1",
			"AndroidRuntime:E", "ActivityManager:I", "ActivityTaskManager:I", "KurdistanLaunchProbe:I", "*:S"}
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
	for _, args := range [][]string{
		{"-s", "emulator-5554", "shell", "log", "-p", "i", "-t", "KurdistanLaunchProbe", "START:" + invocation},
		{"-s", "emulator-5554", "shell", "am", "start", "-W", "-f", "0x10008000", "-n", defaultAppPackage + "/org.kurdistanvpn.app.MainActivity"},
		{"-s", "emulator-5554", "shell", "log", "-p", "i", "-t", "KurdistanLaunchProbe", "END:" + invocation},
	} {
		if err := client.runCommand(ctx, args, io.Discard, io.Discard, time.Second); err != nil {
			t.Fatalf("raw fixture command failed: %v", err)
		}
	}
	start, end, windowOK := launchMarkerWindow(fixture.logs["main"], fixture.logs["main"], invocation, 1, int64(9_000_000_000_000_000_000))
	if !windowOK {
		t.Error("raw fixture invocation window is invalid")
	}
	if start != 1_700_000_000_001_000_000 || end != 1_700_000_000_003_000_000 {
		t.Errorf("synthetic command clock changed: start=%d end=%d", start, end)
	}
	for _, buffer := range []string{"main", "system", "crash"} {
		raw := fixture.logs[buffer]
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
			{DeviceNanos: 1_700_000_000_002_000_000, PID: 10, TID: 10, Tag: "ActivityManager", Text: "process_lifecycle event=Start_proc pid=999 process=" + defaultAppPackage + " uid=10123"},
		},
		"crash": {
			{DeviceNanos: 1_700_000_000_002_000_000, PID: 999, TID: 999, Tag: "AndroidRuntime", Text: "FATAL EXCEPTION"},
			{DeviceNanos: 1_700_000_000_002_000_000, PID: 999, TID: 999, Tag: "AndroidRuntime", Text: "Process: " + defaultAppPackage + ", PID: 999"},
			{DeviceNanos: 1_700_000_000_002_000_000, PID: 999, TID: 999, Tag: "AndroidRuntime", Text: "java.lang.IllegalStateException: Check failed."},
			{DeviceNanos: 1_700_000_000_002_000_000, PID: 999, TID: 999, Tag: "AndroidRuntime", Text: "at org.kurdistanvpn.app.ProductRootViewModel.onCreate(Phase9ViewModel.kt:95)"},
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
		"-v", "threadtime", "-v", "epoch", "-v", "usec", "-T", "1",
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
	raw := "1700000000.002000000 10 10 I ActivityManager: Start proc 999:" + defaultAppPackage + "/u0a123 for activity\n"
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
	raw := "ApplicationExitInfo #0:\n timestamp=2026-01-02 03:04:01.250 pid=999 realUid=10123 packageUid=10123 definingUid=10123 user=0\n" +
		" process=" + defaultAppPackage + " reason=4 (CRASH) subreason=0 (UNKNOWN) status=0\n description=token=synthetic-secret\n" +
		"ApplicationExitInfo #1:\n timestamp=2026-01-02 02:04:01.250 pid=777 realUid=10123\n process=" + defaultAppPackage + " reason=4 (CRASH) status=0\n" +
		"ApplicationExitInfo #2:\n timestamp=2026-01-02 03:04:01.250 pid=888 realUid=10124\n process=" + defaultAppPackage + "ger reason=4 (CRASH) status=0\n"
	records, complete := parseExitRecords(raw, defaultAppPackage, start, start.Add(5*time.Second), time.UTC)
	if !complete || len(records) != 1 || records[0].PID != 999 || records[0].Reason != 4 || strings.Contains(fmt.Sprint(records), "secret") {
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
	start := "101.000001 11 11 I KurdistanLaunchProbe: START:" + id + "\n"
	end := "103.000001 12 12 I KurdistanLaunchProbe: END:" + id + "\n"
	first, last, ok := launchMarkerWindow(start, start+end, id, 100_000_000_000, 104_000_000_000)
	if !ok || first != 101_000_001_000 || last != 103_000_001_000 {
		t.Fatalf("verified marker window lost after stream exit: %d %d %t", first, last, ok)
	}
	for _, input := range []struct{ stream, snapshot, invocation string }{
		{start, "", id},
		{start, end, strings.Repeat("2", 32)},
		{start, end + "102.000001 13 13 I KurdistanLaunchProbe: START:" + id, id},
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
	fixture := `<testsuite name="org.kurdistanvpn.data.settings.Phase13SettingsCodecTest" tests="1" failures="1" errors="0"><testcase name="explicitlyOwnedProjectionClosesBeforeIndependentDiskReadAndReopen" classname="org.kurdistanvpn.data.settings.Phase13SettingsCodecTest"><failure type="java.lang.IllegalArgumentException" message="java.lang.IllegalArgumentException: Failed requirement.">java.lang.IllegalArgumentException: Failed requirement.
 at org.kurdistanvpn.data.settings.Phase9SettingsStore$Companion.openOwnedProjection(Phase9SettingsStore.kt:271)
 at org.kurdistanvpn.data.settings.Phase13SettingsCodecTest.explicitlyOwnedProjectionClosesBeforeIndependentDiskReadAndReopen(Phase13SettingsCodecTest.kt:34)
</failure></testcase><system-out>credential=synthetic-secret</system-out></testsuite>`
	report, err := junitFailureReport([]byte(fixture))
	if err != nil || report.Status != "CAPTURED" || report.Failures != 1 || len(report.Cases) != 1 || len(report.Cases[0].Exceptions[0].Stack) != 2 {
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
