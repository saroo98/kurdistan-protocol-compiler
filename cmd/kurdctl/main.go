// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command kurdctl administers one owner-controlled Kurd deployment. It makes
// no network request and never accepts a passphrase as a command-line value.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"kurdistan/internal/selfhost"
)

const version = "kurdctl-phase16-v1"

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: kurdctl <init|recovery|status|doctor|profile|keys|node|deployment|clock|lock|backup|restore|upgrade|rollback|logs|version>")
		return 2
	}
	if args[0] == "--help" {
		writeUsage(stdout)
		return 0
	}
	var err error
	switch args[0] {
	case "init":
		err = runInit(args[1:], stdin, stdout)
	case "recovery":
		err = runRecovery(args[1:], stdin, stdout)
	case "status":
		err = runStatus(args[1:], stdout)
	case "doctor":
		err = runDoctor(args[1:], stdout)
	case "profile":
		err = runProfile(args[1:], stdin, stdout)
	case "keys":
		err = runKeys(args[1:], stdin, stdout)
	case "node":
		err = runNode(args[1:], stdout)
	case "deployment":
		err = runDeployment(args[1:], stdin, stdout)
	case "clock":
		err = runClock(args[1:], stdin, stdout)
	case "lock":
		err = runLock(args[1:], stdout)
	case "backup":
		err = runBackup(args[1:], stdin, stdout)
	case "restore":
		err = runRestore(args[1:], stdin, stdout)
	case "upgrade":
		err = runUpgrade(args[1:], stdout, stderr)
	case "rollback":
		err = runRollback(args[1:], stdout, stderr)
	case "logs":
		err = runLogs(args[1:], stdout)
	case "version":
		err = writeJSON(stdout, map[string]any{"schema": "kurdctl-version-v1", "version": version})
	default:
		err = selfhost.ErrInvalidInput
	}
	if err == nil {
		return 0
	}
	fmt.Fprintf(stderr, "kurdctl: %v\n", err)
	switch {
	case errors.Is(err, selfhost.ErrInvalidInput):
		return 2
	case errors.Is(err, selfhost.ErrNotFound):
		return 3
	case errors.Is(err, selfhost.ErrRecoveryRejected), errors.Is(err, selfhost.ErrRollback), errors.Is(err, selfhost.ErrClockUnhealthy):
		return 4
	case errors.Is(err, selfhost.ErrBusy):
		return 5
	default:
		return 1
	}
}

func writeUsage(output io.Writer) {
	fmt.Fprint(output, `Usage: kurdctl <command> [options]

Authority and recovery:
  init
  recovery confirm
  status
  doctor
  keys rotate issuer
  keys rotate relay
  deployment disable
  deployment enable
  clock repair
  lock repair

Profiles:
  profile create
  profile list
  profile show
  profile verify
  profile rotate
  profile revoke

Node and maintenance:
  node drain
  node resume
  backup create
  backup verify
  restore preview
  restore apply
  upgrade check
  upgrade apply
  rollback
  logs export-redacted
  version

Passphrases are read from standard input and are never accepted as arguments.
`)
}

func runKeys(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) < 2 || args[0] != "rotate" || args[1] != "issuer" && args[1] != "relay" {
		return selfhost.ErrInvalidInput
	}
	set := newFlags("keys rotate " + args[1])
	dataDir := set.String("data-dir", "", "state directory")
	recovery := set.String("recovery-file", "", "recovery artifact")
	confirm := set.String("confirm", "", "must equal key type")
	if set.Parse(args[2:]) != nil || set.NArg() != 0 || *confirm != args[1] {
		return selfhost.ErrInvalidInput
	}
	passphrase, err := readPassphrase(stdin)
	if err != nil {
		return err
	}
	defer zero(passphrase)
	options := selfhost.RecoveryActionOptions{RecoveryPath: *recovery, RecoveryPassphrase: passphrase, Now: time.Now().UTC()}
	var result selfhost.KeyRotationResult
	if args[1] == "issuer" {
		result, err = selfhost.RotateIssuer(*dataDir, options)
	} else {
		result, err = selfhost.RotateRelay(*dataDir, options)
	}
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runInit(args []string, stdin io.Reader, stdout io.Writer) error {
	set := newFlags("init")
	dataDir := set.String("data-dir", "", "state directory")
	name := set.String("name", "", "deployment name")
	endpoint := set.String("endpoint", "", "relay host:port")
	recovery := set.String("recovery-file", "", "offline recovery output")
	if set.Parse(args) != nil || set.NArg() != 0 {
		return selfhost.ErrInvalidInput
	}
	passphrase, err := readPassphrase(stdin)
	if err != nil {
		return err
	}
	defer zero(passphrase)
	result, err := selfhost.Initialize(selfhost.InitOptions{DataDir: *dataDir, DeploymentName: *name, Endpoint: *endpoint, RecoveryPath: *recovery, RecoveryPassphrase: passphrase, Now: time.Now().UTC()})
	if err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"schema": "kurdctl-init-v1", "deploymentId": result.DeploymentID, "rootFingerprint": result.RootFingerprint, "recoveryPath": result.RecoveryPath, "next": "kurdctl recovery confirm"})
}

func runRecovery(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "confirm" {
		return selfhost.ErrInvalidInput
	}
	set := newFlags("recovery confirm")
	dataDir := set.String("data-dir", "", "state directory")
	recovery := set.String("recovery-file", "", "recovery artifact")
	if set.Parse(args[1:]) != nil || set.NArg() != 0 {
		return selfhost.ErrInvalidInput
	}
	passphrase, err := readPassphrase(stdin)
	if err != nil {
		return err
	}
	defer zero(passphrase)
	if err := selfhost.ConfirmRecovery(*dataDir, *recovery, passphrase, time.Now().UTC()); err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"schema": "kurdctl-recovery-confirm-v1", "confirmed": true})
}

func runStatus(args []string, stdout io.Writer) error {
	set := newFlags("status")
	dataDir := set.String("data-dir", "", "state directory")
	if set.Parse(args) != nil || set.NArg() != 0 {
		return selfhost.ErrInvalidInput
	}
	value, err := selfhost.LoadStatus(*dataDir)
	if err != nil {
		return err
	}
	return writeJSON(stdout, value)
}

func runDoctor(args []string, stdout io.Writer) error {
	set := newFlags("doctor")
	dataDir := set.String("data-dir", "", "state directory")
	if set.Parse(args) != nil || set.NArg() != 0 {
		return selfhost.ErrInvalidInput
	}
	value, err := selfhost.Doctor(*dataDir, time.Now().UTC())
	if writeErr := writeJSON(stdout, value); writeErr != nil {
		return writeErr
	}
	if err != nil || value.Overall != "PASS" {
		return errors.New("doctor reported a failed check")
	}
	return nil
}

func runProfile(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return selfhost.ErrInvalidInput
	}
	switch args[0] {
	case "create":
		set := newFlags("profile create")
		dataDir := set.String("data-dir", "", "state directory")
		name := set.String("name", "", "profile name")
		validFor := set.Duration("valid-for", 7*24*time.Hour, "profile validity")
		outputDir := set.String("output-dir", "", "exclusive output directory")
		if set.Parse(args[1:]) != nil || set.NArg() != 0 {
			return selfhost.ErrInvalidInput
		}
		issued, err := selfhost.CreateProfile(*dataDir, selfhost.CreateProfileOptions{Name: *name, ValidFor: *validFor, Now: time.Now().UTC()})
		if err != nil {
			return err
		}
		paths, err := writeIssued(*outputDir, issued)
		if err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{"schema": "kurdctl-profile-create-v1", "profileId": issued.ProfileID, "contentId": issued.ContentID, "generation": issued.Generation, "files": paths})
	case "list":
		set := newFlags("profile list")
		dataDir := set.String("data-dir", "", "state directory")
		if set.Parse(args[1:]) != nil || set.NArg() != 0 {
			return selfhost.ErrInvalidInput
		}
		profiles, err := selfhost.ListProfiles(*dataDir)
		if err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{"schema": "kurdctl-profile-list-v1", "profiles": profiles})
	case "show":
		return runProfileShow(args[1:], stdout)
	case "verify":
		return runProfileVerify(args[1:], stdout)
	case "rotate":
		return runProfileRotate(args[1:], stdin, stdout)
	case "revoke":
		return runProfileRevoke(args[1:], stdin, stdout)
	default:
		return selfhost.ErrInvalidInput
	}
}

func runProfileVerify(args []string, stdout io.Writer) error {
	set := newFlags("profile verify")
	file := set.String("file", "", "exact Kurd profile artifact")
	minimumGeneration := set.Uint64("minimum-generation", 1, "minimum accepted generation")
	if set.Parse(args) != nil || set.NArg() != 0 || *file == "" || *minimumGeneration == 0 {
		return selfhost.ErrInvalidInput
	}
	artifact, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	verified, err := selfhost.VerifyBundle(artifact, time.Now().UTC(), *minimumGeneration)
	clear(artifact)
	if err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{
		"schema": "kurdctl-profile-verification-v1", "deploymentId": verified.DeploymentID,
		"rootFingerprint": verified.RootFingerprint, "profileId": verified.ProfileID,
		"contentId": verified.ContentID, "generation": verified.Generation,
		"validUntil": verified.ValidUntil, "endpoint": verified.Endpoint,
	})
}

func runProfileShow(args []string, stdout io.Writer) error {
	set := newFlags("profile show")
	dataDir := set.String("data-dir", "", "state directory")
	id := set.String("id", "", "profile ID")
	reveal := set.String("reveal", "summary", "summary|uri|terminal")
	qr := set.Bool("qr", false, "render the profile QR in the terminal")
	if set.Parse(args) != nil || set.NArg() != 0 || *qr && *reveal != "summary" {
		return selfhost.ErrInvalidInput
	}
	if *qr {
		*reveal = "terminal"
	}
	issued, err := selfhost.LoadProfile(*dataDir, *id)
	if err != nil {
		return err
	}
	switch *reveal {
	case "summary":
		return writeJSON(stdout, map[string]any{"schema": "kurdctl-profile-show-v1", "profileId": issued.ProfileID, "contentId": issued.ContentID, "generation": issued.Generation, "qrChunks": len(issued.QRChunks)})
	case "uri":
		_, err = fmt.Fprintln(stdout, issued.URI)
		return err
	case "terminal":
		for index, chunk := range issued.QRChunks {
			qr, renderErr := selfhost.RenderTerminalQR(chunk)
			if renderErr != nil {
				return renderErr
			}
			fmt.Fprintf(stdout, "Chunk %d/%d\n%s", index+1, len(issued.QRChunks), qr)
		}
		return nil
	default:
		return selfhost.ErrInvalidInput
	}
}

func runProfileRotate(args []string, stdin io.Reader, stdout io.Writer) error {
	set := newFlags("profile rotate")
	dataDir := set.String("data-dir", "", "state directory")
	id := set.String("id", "", "profile ID")
	recovery := set.String("recovery-file", "", "recovery artifact")
	validFor := set.Duration("valid-for", 7*24*time.Hour, "profile validity")
	outputDir := set.String("output-dir", "", "exclusive output directory")
	if set.Parse(args) != nil || set.NArg() != 0 {
		return selfhost.ErrInvalidInput
	}
	passphrase, err := readPassphrase(stdin)
	if err != nil {
		return err
	}
	defer zero(passphrase)
	issued, err := selfhost.RotateProfile(*dataDir, selfhost.RotateProfileOptions{ProfileID: *id, RecoveryPath: *recovery, RecoveryPassphrase: passphrase, ValidFor: *validFor, Now: time.Now().UTC()})
	if err != nil {
		return err
	}
	paths, err := writeIssued(*outputDir, issued)
	if err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"schema": "kurdctl-profile-rotate-v1", "profileId": issued.ProfileID, "contentId": issued.ContentID, "generation": issued.Generation, "files": paths})
}

func runProfileRevoke(args []string, stdin io.Reader, stdout io.Writer) error {
	set := newFlags("profile revoke")
	dataDir := set.String("data-dir", "", "state directory")
	id := set.String("id", "", "profile ID")
	recovery := set.String("recovery-file", "", "recovery artifact")
	confirm := set.String("confirm", "", "must equal profile ID")
	if set.Parse(args) != nil || set.NArg() != 0 || *confirm != *id {
		return selfhost.ErrInvalidInput
	}
	passphrase, err := readPassphrase(stdin)
	if err != nil {
		return err
	}
	defer zero(passphrase)
	if err := selfhost.RevokeProfile(*dataDir, selfhost.RevokeProfileOptions{ProfileID: *id, RecoveryPath: *recovery, RecoveryPassphrase: passphrase, Now: time.Now().UTC()}); err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"schema": "kurdctl-profile-revoke-v1", "profileId": *id, "revoked": true})
}

func runNode(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "drain" && args[0] != "resume" {
		return selfhost.ErrInvalidInput
	}
	set := newFlags("node " + args[0])
	dataDir := set.String("data-dir", "", "state directory")
	if set.Parse(args[1:]) != nil || set.NArg() != 0 {
		return selfhost.ErrInvalidInput
	}
	drained := args[0] == "drain"
	if err := selfhost.SetDrained(*dataDir, drained, time.Now().UTC()); err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"schema": "kurdctl-node-state-v1", "drained": drained})
}

func runDeployment(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "disable" && args[0] != "enable" {
		return selfhost.ErrInvalidInput
	}
	set := newFlags("deployment " + args[0])
	dataDir := set.String("data-dir", "", "state directory")
	recovery := set.String("recovery-file", "", "recovery artifact")
	confirm := set.String("confirm", "", "must equal deployment action")
	if set.Parse(args[1:]) != nil || set.NArg() != 0 || *confirm != args[0] {
		return selfhost.ErrInvalidInput
	}
	passphrase, err := readPassphrase(stdin)
	if err != nil {
		return err
	}
	defer zero(passphrase)
	if err := selfhost.SetDeploymentDisabled(*dataDir, args[0] == "disable", selfhost.RecoveryActionOptions{RecoveryPath: *recovery, RecoveryPassphrase: passphrase, Now: time.Now().UTC()}); err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"schema": "kurdctl-deployment-state-v1", "disabled": args[0] == "disable"})
}

func runClock(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "repair" {
		return selfhost.ErrInvalidInput
	}
	set := newFlags("clock repair")
	dataDir := set.String("data-dir", "", "state directory")
	recovery := set.String("recovery-file", "", "recovery artifact")
	confirm := set.String("confirm", "", "must equal repair-clock")
	if set.Parse(args[1:]) != nil || set.NArg() != 0 || *confirm != "repair-clock" {
		return selfhost.ErrInvalidInput
	}
	passphrase, err := readPassphrase(stdin)
	if err != nil {
		return err
	}
	defer zero(passphrase)
	if err := selfhost.RepairClock(*dataDir, selfhost.RecoveryActionOptions{RecoveryPath: *recovery, RecoveryPassphrase: passphrase, Now: time.Now().UTC()}); err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"schema": "kurdctl-clock-repair-v1", "repaired": true})
}

func runLock(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "repair" {
		return selfhost.ErrInvalidInput
	}
	set := newFlags("lock repair")
	dataDir := set.String("data-dir", "", "state directory")
	confirm := set.String("confirm", "", "must equal stale-lock")
	if set.Parse(args[1:]) != nil || set.NArg() != 0 || *confirm != "stale-lock" {
		return selfhost.ErrInvalidInput
	}
	if err := selfhost.RepairStaleLock(*dataDir, *confirm, time.Now().UTC()); err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"schema": "kurdctl-lock-repair-v1", "repaired": true})
}

var executeMaintenance = func(script string, args []string, stdout, stderr io.Writer) error {
	command := exec.Command("sh", append([]string{script}, args...)...)
	command.Stdout, command.Stderr = stdout, stderr
	return command.Run()
}

func runUpgrade(args []string, stdout, stderr io.Writer) error {
	if runtime.GOOS != "linux" || len(args) == 0 || args[0] != "check" && args[0] != "apply" {
		return selfhost.ErrInvalidInput
	}
	set := newFlags("upgrade " + args[0])
	packageDir := set.String("package-dir", "", "verified extracted native package directory")
	confirm := set.String("confirm", "", "must equal upgrade for apply")
	if set.Parse(args[1:]) != nil || set.NArg() != 0 || *packageDir == "" || args[0] == "apply" && *confirm != "upgrade" {
		return selfhost.ErrInvalidInput
	}
	directory, err := filepath.Abs(*packageDir)
	if err != nil {
		return err
	}
	script := filepath.Join(directory, "upgrade.sh")
	info, err := os.Lstat(script)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return selfhost.ErrInvalidInput
	}
	mode := "--check"
	if args[0] == "apply" {
		mode = "--apply"
	}
	return executeMaintenance(script, []string{mode}, stdout, stderr)
}

func runRollback(args []string, stdout, stderr io.Writer) error {
	if runtime.GOOS != "linux" {
		return selfhost.ErrInvalidInput
	}
	set := newFlags("rollback")
	confirm := set.String("confirm", "", "must equal rollback")
	if set.Parse(args) != nil || set.NArg() != 0 || *confirm != "rollback" {
		return selfhost.ErrInvalidInput
	}
	script := "/usr/local/lib/kurd-node/rollback.sh"
	info, err := os.Lstat(script)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return selfhost.ErrNotFound
	}
	return executeMaintenance(script, []string{"--apply", "--confirm", "rollback"}, stdout, stderr)
}

func runBackup(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "create" && args[0] != "verify" {
		return selfhost.ErrInvalidInput
	}
	set := newFlags("backup " + args[0])
	dataDir := set.String("data-dir", "", "state directory")
	file := set.String("file", "", "backup file")
	if set.Parse(args[1:]) != nil || set.NArg() != 0 {
		return selfhost.ErrInvalidInput
	}
	passphrase, err := readPassphrase(stdin)
	if err != nil {
		return err
	}
	defer zero(passphrase)
	var result selfhost.BackupSummary
	if args[0] == "create" {
		result, err = selfhost.CreateBackup(selfhost.BackupOptions{DataDir: *dataDir, Destination: *file, Passphrase: passphrase, Now: time.Now().UTC()})
	} else {
		result, err = selfhost.VerifyBackup(*file, passphrase)
	}
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runRestore(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "preview" && args[0] != "apply" {
		return selfhost.ErrInvalidInput
	}
	set := newFlags("restore " + args[0])
	dataDir := set.String("data-dir", "", "state directory")
	file := set.String("file", "", "backup file")
	digest := set.String("expected-digest", "", "preview digest")
	if set.Parse(args[1:]) != nil || set.NArg() != 0 {
		return selfhost.ErrInvalidInput
	}
	passphrase, err := readPassphrase(stdin)
	if err != nil {
		return err
	}
	defer zero(passphrase)
	options := selfhost.RestoreOptions{BackupPath: *file, DataDir: *dataDir, ExpectedDigest: *digest, Passphrase: passphrase, Now: time.Now().UTC()}
	if args[0] == "preview" {
		result, err := selfhost.PreviewRestore(options)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	}
	if err := selfhost.ApplyRestore(options); err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"schema": "kurdctl-restore-apply-v1", "restored": true, "state": "QUARANTINED"})
}

func runLogs(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "export-redacted" {
		return selfhost.ErrInvalidInput
	}
	set := newFlags("logs export-redacted")
	dataDir := set.String("data-dir", "", "state directory")
	output := set.String("output", "", "output file")
	if set.Parse(args[1:]) != nil || set.NArg() != 0 {
		return selfhost.ErrInvalidInput
	}
	if err := selfhost.ExportRedactedAudit(*dataDir, *output); err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"schema": "kurdctl-redacted-audit-v1", "output": *output})
}

func writeIssued(outputDir string, issued selfhost.IssuedProfile) (map[string]string, error) {
	if outputDir == "" {
		return nil, selfhost.ErrInvalidInput
	}
	if err := os.Mkdir(outputDir, 0o700); err != nil {
		return nil, err
	}
	paths := map[string]string{}
	writes := map[string][]byte{
		"artifact": []byte{}, "uri": []byte(issued.URI + "\n"),
	}
	writes["artifact"] = issued.Artifact
	for label, value := range writes {
		name := "profile.kurd-profile"
		if label == "uri" {
			name = "profile.kurd-uri.txt"
		}
		path := filepath.Join(outputDir, name)
		if err := writeExclusive(path, value); err != nil {
			return nil, err
		}
		paths[label] = path
	}
	for index, chunk := range issued.QRChunks {
		name := "profile-qr-" + strconv.Itoa(index+1)
		pngValue, err := selfhost.RenderPNGQR(chunk, 8)
		if err != nil {
			return nil, err
		}
		svgValue, err := selfhost.RenderSVGQR(chunk, 8)
		if err != nil {
			return nil, err
		}
		for suffix, value := range map[string][]byte{"png": pngValue, "svg": svgValue} {
			path := filepath.Join(outputDir, name+"."+suffix)
			if err := writeExclusive(path, value); err != nil {
				return nil, err
			}
			paths["qr"+strconv.Itoa(index+1)+suffix] = path
		}
	}
	return paths, nil
}

func readPassphrase(input io.Reader) ([]byte, error) {
	reader := bufio.NewReader(io.LimitReader(input, 2048))
	value, err := reader.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, selfhost.ErrInvalidInput
	}
	value = bytes.TrimSuffix(value, []byte{'\n'})
	value = bytes.TrimSuffix(value, []byte{'\r'})
	if len(value) == 0 {
		return nil, selfhost.ErrInvalidInput
	}
	return value, nil
}

func writeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(true)
	return encoder.Encode(value)
}

func writeExclusive(path string, value []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(value); err != nil {
		file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}

func newFlags(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	return set
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
