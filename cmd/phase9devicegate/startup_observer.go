// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	startupObserverSchema      = "kurdistan-launch-observation-v2"
	startupEvidenceDigestV2    = "KURDISTAN_STARTUP_OBSERVER_EVIDENCE_V2\x00"
	startupIdentityDigestV2    = "KURDISTAN_STARTUP_OBSERVER_IDENTITY_V2\x00"
	startupRepositoryIdentity  = "saroo98/kurdistan-protocol-compiler"
	startupActivityParserAPI26 = "ACTIVITY_STATE_API26_V1"
	startupActivityParserAPI30 = "ACTIVITY_STATE_API30_PLUS_V1"
	startupEventParserV2       = "ACTIVITY_MANAGER_EVENTS_V2"
	startupPackageParserV2     = "PACKAGE_STATE_V2"
	startupProcessParserV1     = "PROC_PROCESS_CROSSCHECK_V1"
	startupBootBuildParserV2   = "BOOT_BUILD_IDENTITY_V2"
)

var (
	startupCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	startupDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	startupBootIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type startupSubjectBinding struct {
	Status        string
	Repository    string
	Commit        string
	Tree          string
	AppAPKDigest  string
	AppAPKBytes   int64
	TestAPKDigest string
	TestAPKBytes  int64
	Package       string
	TestPackage   string
	API           int
	ABI           string
	Rejection     string
}

type startupBootSession struct {
	Status             string
	StartBootIdentity  string
	EndBootIdentity    string
	StartBuildIdentity string
	EndBuildIdentity   string
	API                int
	ABI                string
	Rejection          string
}

type startupCompositeSource struct {
	ReceivedOrder int
	Phase         string
	Source        string
	Parser        string
	Status        string
	Rejection     string
	ObservedUTC   time.Time
	RecordCount   int
	RawBytes      int
	RawDigest     string
}

type startupActivityState struct {
	Phase       string
	Status      string
	Parser      string
	Component   string
	TaskID      int
	Active      bool
	ObservedUTC time.Time
	Rejection   string
}

type startupProcessCrossCheck struct {
	Phase       string
	Status      string
	Process     string
	PID         int
	UID         int
	ParentPID   int
	StartTicks  uint64
	PIDOf       int
	ProcName    string
	ObservedUTC time.Time
	Rejection   string
}

type startupPackageState struct {
	Phase       string
	Status      string
	Package     string
	UserID      int
	VersionCode uint64
	VersionName string
	Installed   bool
	Suspended   bool
	Stopped     bool
	Enabled     int
	ObservedUTC time.Time
	Rejection   string
}

type startupSystemEvent struct {
	ReceivedOrder int
	DeviceNanos   int64
	Type          string
	UserID        int
	PID           int
	UID           int
	Process       string
	Component     string
}

type startupSystemEventEvidence struct {
	Status    string
	Parser    string
	Rejection string
	Events    []startupSystemEvent
}

func startupFramedDigest(domain string, fields ...[]byte) string {
	hash := sha256.New()
	write := func(value []byte) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(value)
	}
	write([]byte(domain))
	for _, field := range fields {
		write(field)
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func startupFileIdentity(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		return "", 0, errors.New("startup artifact is not a nonempty regular file")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, file)
	if err != nil || written != info.Size() {
		return "", 0, errors.New("startup artifact identity unavailable")
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), info.Size(), nil
}

func exactGitObject(ctx context.Context, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "git", args...)
	command.Stderr = io.Discard
	raw, err := command.Output()
	value := strings.TrimSpace(string(raw))
	if err != nil || !startupCommitPattern.MatchString(value) {
		return "", errors.New("immutable Git subject unavailable")
	}
	return value, nil
}

func resolveStartupSubjectBinding(value options) (startupSubjectBinding, error) {
	binding := startupSubjectBinding{
		Status: "INCOMPLETE", Repository: startupRepositoryIdentity,
		Package: value.appPackage, TestPackage: value.testPackage, API: value.expectedAPI, ABI: value.expectedABI,
	}
	if !safeDiagnosticClass(value.appPackage) || !safeDiagnosticClass(value.testPackage) || value.expectedAPI < 26 || value.expectedABI == "" {
		binding.Rejection = "SUBJECT_PARAMETERS_INVALID"
		return binding, errors.New("startup subject parameters invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var err error
	if binding.Commit, err = exactGitObject(ctx, "rev-parse", "HEAD"); err != nil {
		binding.Rejection = "COMMIT_UNAVAILABLE"
		return binding, err
	}
	if binding.Tree, err = exactGitObject(ctx, "rev-parse", "HEAD^{tree}"); err != nil {
		binding.Rejection = "TREE_UNAVAILABLE"
		return binding, err
	}
	clean := exec.CommandContext(ctx, "git", "diff", "--quiet", "--no-ext-diff", "HEAD", "--")
	clean.Stdout, clean.Stderr = io.Discard, io.Discard
	if err := clean.Run(); err != nil {
		binding.Rejection = "TRACKED_SUBJECT_DIRTY"
		return binding, errors.New("tracked startup subject is not immutable")
	}
	if binding.AppAPKDigest, binding.AppAPKBytes, err = startupFileIdentity(value.appAPK); err != nil {
		binding.Rejection = "APP_APK_IDENTITY_UNAVAILABLE"
		return binding, err
	}
	if binding.TestAPKDigest, binding.TestAPKBytes, err = startupFileIdentity(value.testAPK); err != nil {
		binding.Rejection = "TEST_APK_IDENTITY_UNAVAILABLE"
		return binding, err
	}
	binding.Status = "CAPTURED"
	binding.Rejection = ""
	return binding, nil
}

func validStartupSubject(binding startupSubjectBinding, observation *launchObservation) bool {
	return binding.Status == "CAPTURED" && binding.Repository == startupRepositoryIdentity &&
		startupCommitPattern.MatchString(binding.Commit) && startupCommitPattern.MatchString(binding.Tree) &&
		startupDigestPattern.MatchString(binding.AppAPKDigest) && binding.AppAPKBytes > 0 &&
		startupDigestPattern.MatchString(binding.TestAPKDigest) && binding.TestAPKBytes > 0 &&
		binding.Package == observation.app && safeDiagnosticClass(binding.TestPackage) &&
		binding.API == observation.api && binding.API >= 26 && binding.ABI != ""
}

func (observation *launchObservation) recordCompositeSource(phase, source, parser, raw string, ok bool, parsed bool, rejection string, records int) {
	status := "CAPTURED"
	if !ok || !parsed {
		status = "INCOMPLETE"
		if rejection == "" {
			rejection = "SOURCE_UNAVAILABLE_OR_MALFORMED"
		}
	}
	observation.CompositeSources = append(observation.CompositeSources, startupCompositeSource{
		ReceivedOrder: len(observation.CompositeSources) + 1,
		Phase:         phase, Source: source, Parser: parser, Status: status, Rejection: rejection,
		ObservedUTC: time.Now().UTC(), RecordCount: records, RawBytes: len(raw),
		RawDigest: startupFramedDigest(startupEvidenceDigestV2, []byte(phase), []byte(source), []byte(parser), []byte(raw)),
	})
}

func parseStartupIdentity(raw string) (string, bool) {
	value := strings.ToLower(strings.TrimSpace(raw))
	return startupFramedDigest(startupIdentityDigestV2, []byte(value)), startupBootIDPattern.MatchString(value)
}

func parseStartupBuildIdentity(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") ||
		!regexp.MustCompile(`^[A-Za-z0-9_./:+,=@-]+$`).MatchString(value) {
		return "", false
	}
	return startupFramedDigest(startupIdentityDigestV2, []byte(value)), true
}

func parseStartupBootBuildIdentity(raw string) (boot string, build string, ok bool) {
	if len(raw) > 1024 || strings.Contains(raw, "\x00") {
		return "", "", false
	}
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	if strings.Contains(normalized, "\r") {
		return "", "", false
	}
	normalized = strings.TrimSuffix(normalized, "\n")
	lines := strings.Split(normalized, "\n")
	if len(lines) != 2 || lines[0] == "" || lines[1] == "" {
		return "", "", false
	}
	return lines[0], lines[1], true
}

func (observation *launchObservation) captureStartupBoot(parent context.Context, phase string) {
	raw, queryOK := observation.query(parent, phase+"-boot-build-identity", "shell",
		"cat /proc/sys/kernel/random/boot_id && getprop ro.build.fingerprint")
	bootRaw, buildRaw, framed := parseStartupBootBuildIdentity(raw)
	bootIdentity, bootParsed := parseStartupIdentity(bootRaw)
	buildIdentity, buildParsed := parseStartupBuildIdentity(buildRaw)
	parsed := framed && bootParsed && buildParsed
	observation.recordCompositeSource(phase, "PROC_BOOT_ID_AND_BUILD_FINGERPRINT", startupBootBuildParserV2,
		raw, queryOK, parsed, "BOOT_OR_BUILD_IDENTITY_INVALID", 2)
	if !queryOK || !parsed {
		observation.BootSession.Status = "INCOMPLETE"
		observation.BootSession.Rejection = "BOOT_OR_BUILD_IDENTITY_UNAVAILABLE"
		observation.incomplete("boot session identity unavailable")
		return
	}
	if phase == "before-launch" {
		observation.BootSession = startupBootSession{
			Status: "INCOMPLETE", StartBootIdentity: bootIdentity, StartBuildIdentity: buildIdentity,
			API: observation.api, ABI: observation.Subject.ABI, Rejection: "TERMINAL_IDENTITY_PENDING",
		}
		return
	}
	observation.BootSession.EndBootIdentity = bootIdentity
	observation.BootSession.EndBuildIdentity = buildIdentity
	if observation.BootSession.StartBootIdentity != bootIdentity || observation.BootSession.StartBuildIdentity != buildIdentity {
		observation.BootSession.Status = "INCOMPLETE"
		observation.BootSession.Rejection = "BOOT_OR_BUILD_IDENTITY_CHANGED"
		observation.incomplete("boot session identity changed")
		return
	}
	observation.BootSession.Status = "CAPTURED"
	observation.BootSession.Rejection = ""
}

func parseStartupPackageState(raw, app, phase string) startupPackageState {
	state := startupPackageState{Phase: phase, Status: "INCOMPLETE", Package: app, ObservedUTC: time.Now().UTC(), Rejection: "PACKAGE_STATE_MALFORMED"}
	if len(raw) > maxLogcatInput || !strings.Contains(raw, "Package ["+app+"]") {
		return state
	}
	userID, version, versionName, userState := -1, uint64(0), "", ""
	extensionMetadataSeen := false
	for _, rawLine := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "userId=") || strings.HasPrefix(line, "appId=") {
			match := regexp.MustCompile(`^(?:userId|appId)=([0-9]{1,10})$`).FindStringSubmatch(line)
			if match == nil || userID != -1 {
				return state
			}
			var err error
			userID, err = strconv.Atoi(match[1])
			if err != nil {
				return state
			}
		}
		if strings.HasPrefix(line, "versionCode=") {
			match := regexp.MustCompile(`^versionCode=([0-9]{1,20}) minSdk=[0-9]{1,3} targetSdk=[0-9]{1,3}(?: minExtensionVersions=\[(?:[0-9]{1,3}=[0-9]{1,10}(?:, [0-9]{1,3}=[0-9]{1,10})*)?\])?$`).FindStringSubmatch(line)
			if match == nil || version != 0 {
				return state
			}
			var err error
			version, err = strconv.ParseUint(match[1], 10, 64)
			if err != nil || version == 0 {
				return state
			}
			if strings.Contains(line, " minExtensionVersions=") {
				extensionMetadataSeen = true
			}
		}
		if strings.HasPrefix(line, "minExtensionVersions=") {
			if extensionMetadataSeen || !regexp.MustCompile(`^minExtensionVersions=\[(?:[0-9]{1,3}=[0-9]{1,10}(?:, [0-9]{1,3}=[0-9]{1,10})*)?\]$`).MatchString(line) {
				return state
			}
			extensionMetadataSeen = true
		}
		if strings.HasPrefix(line, "versionName=") {
			match := regexp.MustCompile(`^versionName=([A-Za-z0-9_.+-]{1,128})$`).FindStringSubmatch(line)
			if match == nil || versionName != "" {
				return state
			}
			versionName = match[1]
		}
		if strings.HasPrefix(line, "User 0: ") {
			if userState != "" {
				return state
			}
			userState = line
		}
	}
	flag := func(name string) (bool, bool) {
		match := regexp.MustCompile(`(?:^| )` + regexp.QuoteMeta(name) + `=(true|false)(?: |$)`).FindStringSubmatch(userState)
		return match != nil && match[1] == "true", match != nil
	}
	installed, installedOK := flag("installed")
	suspended, suspendedOK := flag("suspended")
	stopped, stoppedOK := flag("stopped")
	enabledMatch := regexp.MustCompile(`(?:^| )enabled=(-?[0-9]{1,3})(?: |$)`).FindStringSubmatch(userState)
	if userID < 10000 || version == 0 || versionName == "" || !installedOK || !suspendedOK || !stoppedOK || enabledMatch == nil {
		return state
	}
	enabled, err := strconv.Atoi(enabledMatch[1])
	if err != nil {
		return state
	}
	state.UserID, state.VersionCode, state.VersionName = userID, version, versionName
	state.Installed, state.Suspended, state.Stopped, state.Enabled = installed, suspended, stopped, enabled
	state.Status, state.Rejection = "CAPTURED", ""
	return state
}

func (observation *launchObservation) captureStartupPackage(parent context.Context, phase string) {
	raw, ok := observation.query(parent, phase+"-package-state", "shell", "dumpsys", "package", observation.app)
	state := parseStartupPackageState(raw, observation.app, phase)
	parsed := state.Status == "CAPTURED"
	observation.recordCompositeSource(phase, "PACKAGE_MANAGER", startupPackageParserV2, raw, ok, parsed, state.Rejection, 1)
	observation.PackageState = append(observation.PackageState, state)
	if !ok || !parsed {
		observation.incomplete(phase + " package state unavailable")
	}
}

func parseStartupActivityState(raw, app, phase string, api int) startupActivityState {
	state := startupActivityState{Phase: phase, Status: "INCOMPLETE", ObservedUTC: time.Now().UTC(), Rejection: "ACTIVITY_STATE_FORMAT_UNKNOWN"}
	if len(raw) > maxLogcatInput || !strings.HasPrefix(raw, "ACTIVITY MANAGER ACTIVITIES") {
		return state
	}
	var pattern *regexp.Regexp
	if api < 30 {
		state.Parser = startupActivityParserAPI26
		pattern = regexp.MustCompile(`(?m)^\s*mResumedActivity: ActivityRecord\{[0-9a-f]+ u0 ([A-Za-z0-9_.]+/[A-Za-z0-9_.$]+) t([0-9]+)\}\s*$`)
	} else {
		state.Parser = startupActivityParserAPI30
		pattern = regexp.MustCompile(`(?m)^\s*topResumedActivity=ActivityRecord\{[0-9a-f]+ u0 ([A-Za-z0-9_.]+/[A-Za-z0-9_.$]+) t([0-9]+)\}\s*$`)
	}
	matches := pattern.FindAllStringSubmatch(raw, -1)
	if len(matches) != 1 {
		return state
	}
	task, err := strconv.Atoi(matches[0][2])
	if err != nil || task <= 0 {
		return state
	}
	component, componentOK := canonicalStartupComponent(matches[0][1], app)
	if !componentOK {
		state.Rejection = "ACTIVITY_COMPONENT_INVALID"
		return state
	}
	state.Component, state.TaskID, state.Active = component, task, true
	state.Status, state.Rejection = "CAPTURED", ""
	return state
}

func canonicalStartupComponent(value, app string) (string, bool) {
	packageName, className, ok := strings.Cut(value, "/")
	if !ok || packageName == "" || className == "" || !diagnosticClassPattern.MatchString(packageName) {
		return "", false
	}
	if packageName != app {
		return "[OTHER_PACKAGE]/[OTHER_ACTIVITY]", true
	}
	if className == ".MainActivity" {
		className = "org.kurdistanvpn.app.MainActivity"
	} else if strings.HasPrefix(className, ".") || !strings.Contains(className, ".") {
		return "", false
	}
	if !diagnosticClassPattern.MatchString(className) {
		return "", false
	}
	if !safeDiagnosticClass(className) {
		return "", false
	}
	return packageName + "/" + className, true
}

func (observation *launchObservation) captureStartupActivity(parent context.Context, phase string) {
	raw, ok := observation.query(parent, phase+"-activity-state", "shell", "dumpsys", "activity", "activities", observation.app)
	state := parseStartupActivityState(raw, observation.app, phase, observation.api)
	parsed := state.Status == "CAPTURED"
	observation.recordCompositeSource(phase, "ACTIVITY_MANAGER_ACTIVITY", state.Parser, raw, ok, parsed, state.Rejection, 1)
	observation.ActivityStates = append(observation.ActivityStates, state)
	if !ok || !parsed {
		observation.incomplete(phase + " activity state unavailable")
	}
}

func parseProcStatus(raw string) (name string, pid, parent, uid int, ok bool) {
	if len(raw) > 256<<10 {
		return "", 0, 0, 0, false
	}
	pid, parent, uid = -1, -1, -1
	var tgid int = -1
	for _, rawLine := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(rawLine)
		if match := regexp.MustCompile(`^Name:\s*([A-Za-z0-9_.:-]{1,64})$`).FindStringSubmatch(line); match != nil {
			if name != "" {
				return "", 0, 0, 0, false
			}
			name = match[1]
		}
		for label, target := range map[string]*int{"Pid": &pid, "Tgid": &tgid, "PPid": &parent} {
			if match := regexp.MustCompile(`^` + label + `:\s*([0-9]{1,10})$`).FindStringSubmatch(line); match != nil {
				if *target != -1 {
					return "", 0, 0, 0, false
				}
				*target, _ = strconv.Atoi(match[1])
			}
		}
		if match := regexp.MustCompile(`^Uid:\s*([0-9]{1,10})\s+([0-9]{1,10})\s+([0-9]{1,10})\s+([0-9]{1,10})$`).FindStringSubmatch(line); match != nil {
			if uid != -1 || match[1] != match[2] || match[1] != match[3] || match[1] != match[4] {
				return "", 0, 0, 0, false
			}
			uid, _ = strconv.Atoi(match[1])
		}
	}
	return name, pid, parent, uid, name != "" && pid > 0 && tgid == pid && parent >= 0 && uid >= 10000
}

func androidKernelTaskName(process string) (string, bool) {
	if !diagnosticClassPattern.MatchString(process) {
		return "", false
	}
	// Android's set_process_name keeps the final 15 bytes for PR_SET_NAME.
	// The full process name is independently bound by ps, ActivityManager, and
	// pidof; this is only the kernel task-name corroboration from /proc/status.
	const maxTaskNameBytes = 15
	if len(process) <= maxTaskNameBytes {
		return process, true
	}
	return process[len(process)-maxTaskNameBytes:], true
}

func (observation *launchObservation) captureStartupProcess(parent context.Context, phase string) {
	check := startupProcessCrossCheck{Phase: phase, Status: "INCOMPLETE", ObservedUTC: time.Now().UTC(), Rejection: "PROCESS_SNAPSHOT_MISSING"}
	var snapshot *diagnosticProcessSnapshot
	for index := range observation.Processes {
		if observation.Processes[index].Phase == phase {
			snapshot = &observation.Processes[index]
		}
	}
	if snapshot == nil || snapshot.Status != "CAPTURED" {
		observation.ProcessCrossChecks = append(observation.ProcessCrossChecks, check)
		observation.incomplete(phase + " process cross-check unavailable")
		return
	}
	var process *diagnosticProcess
	for index := range snapshot.Processes {
		if snapshot.Processes[index].Name == observation.app {
			if process != nil {
				observation.ProcessCrossChecks = append(observation.ProcessCrossChecks, check)
				observation.incomplete(phase + " process cross-check ambiguous")
				return
			}
			process = &snapshot.Processes[index]
		}
	}
	if process == nil {
		observation.ProcessCrossChecks = append(observation.ProcessCrossChecks, check)
		return
	}
	check.Process, check.PID, check.UID, check.ParentPID, check.StartTicks = process.Name, process.PID, process.UID, process.ParentPID, process.StartTicks
	pidRaw, pidOK := observation.query(parent, phase+"-pidof", "shell", "pidof", observation.app)
	pidFields := strings.Fields(pidRaw)
	pidParsed := len(pidFields) == 1
	if pidParsed {
		check.PIDOf, _ = strconv.Atoi(pidFields[0])
		pidParsed = check.PIDOf > 0
	}
	observation.recordCompositeSource(phase, "PIDOF", startupProcessParserV1, pidRaw, pidOK, pidParsed, "PIDOF_INVALID", len(pidFields))
	statusRaw, statusOK := observation.query(parent, phase+"-proc-status", "shell", "cat", "/proc/"+strconv.Itoa(process.PID)+"/status")
	name, pid, parentPID, uid, statusParsed := parseProcStatus(statusRaw)
	check.ProcName = name
	observation.recordCompositeSource(phase, "PROC_STATUS", startupProcessParserV1, statusRaw, statusOK, statusParsed, "PROC_STATUS_INVALID", 1)
	expectedTaskName, taskNameOK := androidKernelTaskName(process.Name)
	if pidOK && pidParsed && statusOK && statusParsed && taskNameOK && name == expectedTaskName &&
		check.PIDOf == process.PID && pid == process.PID && parentPID == process.ParentPID && uid == process.UID {
		check.Status, check.Rejection = "CAPTURED", ""
	} else {
		check.Rejection = "PROCESS_IDENTITY_CONFLICT_OR_INCOMPLETE"
		observation.incomplete(phase + " process cross-check conflicting or incomplete")
	}
	observation.ProcessCrossChecks = append(observation.ProcessCrossChecks, check)
}

func parseStartupSystemEvents(raw, app string, start, end int64) startupSystemEventEvidence {
	evidence := startupSystemEventEvidence{Status: "INCOMPLETE", Parser: startupEventParserV2, Rejection: "EVENT_STREAM_MALFORMED"}
	if len(raw) > maxLogcatInput || start <= 0 || end <= start {
		return evidence
	}
	order := 0
	for _, rawLine := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "---------") {
			continue
		}
		event, ok := parseEpochLog(rawLine)
		if !ok {
			return evidence
		}
		if event.DeviceNanos <= start || event.DeviceNanos > end {
			continue
		}
		if event.Tag != "am_proc_start" && event.Tag != "am_proc_died" && event.Tag != "am_kill" && event.Tag != "am_anr" && event.Tag != "am_crash" {
			return evidence
		}
		if !strings.HasPrefix(event.Text, "[") || !strings.HasSuffix(event.Text, "]") {
			return evidence
		}
		fields := strings.Split(strings.TrimSuffix(strings.TrimPrefix(event.Text, "["), "]"), ",")
		for index := range fields {
			fields[index] = strings.TrimSpace(fields[index])
		}
		if len(fields) < 3 {
			return evidence
		}
		userID, userErr := strconv.Atoi(fields[0])
		pid, pidErr := strconv.Atoi(fields[1])
		if userErr != nil || pidErr != nil || userID < 0 || pid <= 0 {
			return evidence
		}
		canonical := startupSystemEvent{ReceivedOrder: order + 1, DeviceNanos: event.DeviceNanos, UserID: userID, PID: pid, UID: -1}
		switch event.Tag {
		case "am_proc_start":
			if len(fields) < 4 {
				return evidence
			}
			if !exactDiagnosticProcess(fields[3], app) {
				continue
			}
			if len(fields) < 6 {
				return evidence
			}
			uid, err := strconv.Atoi(fields[2])
			component, componentOK := canonicalStartupComponent(fields[5], app)
			if err != nil || uid < 0 || !componentOK {
				return evidence
			}
			canonical.Type, canonical.UID, canonical.Process, canonical.Component = "PROCESS_START", uid, fields[3], component
		case "am_proc_died":
			if !exactDiagnosticProcess(fields[2], app) {
				continue
			}
			canonical.Type, canonical.Process = "PROCESS_DIED", fields[2]
		case "am_kill":
			if !exactDiagnosticProcess(fields[2], app) {
				continue
			}
			canonical.Type, canonical.Process = "PROCESS_KILLED", fields[2]
		case "am_anr":
			if !exactDiagnosticProcess(fields[2], app) {
				continue
			}
			canonical.Type, canonical.Process = "ANR", fields[2]
		case "am_crash":
			if !exactDiagnosticProcess(fields[2], app) {
				continue
			}
			canonical.Type, canonical.Process = "CRASH", fields[2]
		}
		order++
		canonical.ReceivedOrder = order
		evidence.Events = append(evidence.Events, canonical)
		if len(evidence.Events) > 256 {
			return evidence
		}
	}
	evidence.Status, evidence.Rejection = "CAPTURED", ""
	return evidence
}

func canonicalStartupSystemEventEvidence(events []startupSystemEvent) string {
	var output strings.Builder
	for _, event := range events {
		fmt.Fprintf(&output, "%d|%d|%s|%d|%d|%d|%s|%s\n", event.ReceivedOrder, event.DeviceNanos,
			event.Type, event.UserID, event.PID, event.UID, event.Process, event.Component)
	}
	return output.String()
}

func validateCompositeStartup(observation *launchObservation, previous, current *diagnosticProcess) error {
	if observation == nil || current == nil || !validStartupSubject(observation.Subject, observation) ||
		observation.BootSession.Status != "CAPTURED" || observation.BootSession.API != observation.api ||
		observation.BootSession.ABI != observation.Subject.ABI || len(observation.CompositeSources) == 0 {
		return errLaunchIncomplete
	}
	for index, source := range observation.CompositeSources {
		optionalEventsUnavailable := source.Source == "ACTIVITY_MANAGER_EVENTS" && source.Parser == startupEventParserV2 &&
			source.Status == "OPTIONAL_SOURCE_UNAVAILABLE" && source.Rejection == "NONPRIVILEGED_EVENT_BUFFER_PERMISSION_DENIED" &&
			observation.SystemEvents.Status == "OPTIONAL_SOURCE_UNAVAILABLE"
		if source.ReceivedOrder != index+1 || source.Phase == "" || source.Source == "" || source.Parser == "" ||
			(source.Status != "CAPTURED" && !optionalEventsUnavailable) || source.RecordCount < 0 || source.RawBytes < 0 ||
			!startupDigestPattern.MatchString(source.RawDigest) || source.ObservedUTC.Before(observation.StartedUTC) || source.ObservedUTC.After(observation.FinishedUTC) {
			return errLaunchIncomplete
		}
	}
	if len(observation.ActivityStates) != 1 {
		return errLaunchIncomplete
	}
	activity := observation.ActivityStates[0]
	if activity.Status != "CAPTURED" || !activity.Active || activity.TaskID <= 0 {
		return errLaunchIncomplete
	}
	if activity.Component != observation.app+"/org.kurdistanvpn.app.MainActivity" {
		return errors.New("ActivityManager observed the wrong active activity")
	}
	if len(observation.PackageState) != 2 {
		return errLaunchIncomplete
	}
	wantPackagePhases := []string{"before-launch", "terminal"}
	var first *startupPackageState
	for index := range observation.PackageState {
		state := &observation.PackageState[index]
		if state.Phase != wantPackagePhases[index] || state.Status != "CAPTURED" || state.Package != observation.app ||
			state.UserID != current.UID || state.VersionCode == 0 || state.VersionName == "" {
			return errLaunchIncomplete
		}
		if !state.Installed || state.Suspended || (state.Enabled != 0 && state.Enabled != 1) ||
			(state.Phase == "terminal" && state.Stopped) {
			return errors.New("target package is stopped, suspended, disabled, or unavailable")
		}
		if first == nil {
			first = state
		} else if first.UserID != state.UserID || first.VersionCode != state.VersionCode || first.VersionName != state.VersionName {
			return errLaunchIncomplete
		}
	}
	wantPhases := []string{"immediately-after-launch", "after-survival-interval", "terminal"}
	if len(observation.ProcessCrossChecks) != len(wantPhases) {
		return errLaunchIncomplete
	}
	for index, check := range observation.ProcessCrossChecks {
		expectedTaskName, taskNameOK := androidKernelTaskName(current.Name)
		if check.Phase != wantPhases[index] || check.Status != "CAPTURED" || check.Process != current.Name ||
			check.PID != current.PID || check.PIDOf != current.PID || check.UID != current.UID || check.ParentPID != current.ParentPID ||
			check.StartTicks != current.StartTicks || !taskNameOK || check.ProcName != expectedTaskName ||
			check.ObservedUTC.Before(observation.StartedUTC) || check.ObservedUTC.After(observation.FinishedUTC) {
			return errLaunchIncomplete
		}
	}
	if observation.SystemEvents.Status != "CAPTURED" && observation.SystemEvents.Status != "OPTIONAL_SOURCE_UNAVAILABLE" {
		return errLaunchIncomplete
	}
	startCount := 0
	last := observation.WindowStartNanos
	for index, event := range observation.SystemEvents.Events {
		if event.ReceivedOrder != index+1 || event.DeviceNanos < last || event.DeviceNanos <= observation.WindowStartNanos || event.DeviceNanos > observation.WindowEndNanos {
			return errLaunchIncomplete
		}
		last = event.DeviceNanos
		if event.Process != current.Name || event.PID != current.PID {
			continue
		}
		switch event.Type {
		case "PROCESS_START":
			if event.UID != current.UID || event.Component != observation.app+"/org.kurdistanvpn.app.MainActivity" {
				return errLaunchIncomplete
			}
			startCount++
		case "CRASH":
			return errors.New("current target crash observed")
		case "ANR":
			return errors.New("current target ANR observed")
		case "PROCESS_DIED", "PROCESS_KILLED":
			return errors.New("current target termination observed")
		default:
			return errLaunchIncomplete
		}
	}
	if observation.SystemEvents.Status == "CAPTURED" && previous == nil {
		if startCount != 1 {
			return errLaunchIncomplete
		}
	} else if previous != nil && (*previous != *current || (observation.SystemEvents.Status == "CAPTURED" && startCount != 0)) {
		return errLaunchIncomplete
	}
	return nil
}
