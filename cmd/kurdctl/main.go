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
	"strings"
	"time"

	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/selfhost"
)

const version = "kurdctl-phase16-v1"

var (
	errCLIInvalidInput  = selfhost.ErrInvalidInput
	errRequestRejected  = errors.New("request rejected")
	errOutputExists     = errors.New("output exists")
	errOutputIncomplete = errors.New("output incomplete")
)

type committedOutputError struct {
	cause      error
	profileID  string
	generation uint64
}

func (e committedOutputError) Error() string { return "committed profile output incomplete" }
func (e committedOutputError) Unwrap() error { return e.cause }

type profileOutputFilesV2 struct {
	Artifact string                  `json:"artifact"`
	URI      string                  `json:"uri"`
	QR       []profileOutputQRFileV2 `json:"qr"`
}

type profileOutputQRFileV2 struct {
	Part uint   `json:"part"`
	PNG  string `json:"png"`
	SVG  string `json:"svg"`
}

type profileMutationResponseV2 struct {
	Schema      string               `json:"schema"`
	ProfileID   string               `json:"profileId"`
	ContentID   string               `json:"contentId"`
	Generation  uint64               `json:"generation"`
	ValidUntil  int64                `json:"validUntil"`
	Mode        string               `json:"mode"`
	Sealed      bool                 `json:"sealed"`
	Connectable bool                 `json:"connectable"`
	Files       profileOutputFilesV2 `json:"files"`
	QRCount     int                  `json:"qrCount"`
}

type profileRedactedResponseV2 struct {
	Schema      string `json:"schema"`
	ProfileID   string `json:"profileId"`
	ContentID   string `json:"contentId"`
	Generation  uint64 `json:"generation"`
	ValidUntil  int64  `json:"validUntil"`
	Mode        string `json:"mode"`
	Sealed      bool   `json:"sealed"`
	Connectable bool   `json:"connectable"`
	Revoked     bool   `json:"revoked"`
	QRCount     int    `json:"qrCount"`
}

type profileVerificationResponseV2 struct {
	Schema      string `json:"schema"`
	ProfileID   string `json:"profileId"`
	ContentID   string `json:"contentId"`
	Generation  uint64 `json:"generation"`
	ValidUntil  int64  `json:"validUntil"`
	Mode        string `json:"mode"`
	Sealed      bool   `json:"sealed"`
	Connectable bool   `json:"connectable"`
}

type keyRotationResponseV2 struct {
	Schema          string `json:"schema"`
	Kind            string `json:"kind"`
	DelegationEpoch uint64 `json:"delegationEpoch"`
	RevocationEpoch uint64 `json:"revocationEpoch"`
	RelayEpoch      uint64 `json:"relayEpoch"`
	TLSEpoch        uint64 `json:"tlsEpoch"`
	RevokedProfiles int    `json:"revokedProfiles"`
}

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
	message, code := categorizeCLIError(err)
	fmt.Fprintf(stderr, "kurdctl: %s\n", message)
	return code
}

func categorizeCLIError(err error) (string, int) {
	var committed committedOutputError
	switch {
	case errors.As(err, &committed):
		category := "output incomplete"
		if errors.Is(committed.cause, errOutputExists) {
			category = "output exists"
		} else if errors.Is(committed.cause, errUnsupportedFilesystem) {
			category = "unsupported filesystem"
		}
		return fmt.Sprintf("%s profile_id=%s generation=%d", category, committed.profileID, committed.generation), 6
	case errors.Is(err, errRequestRejected), errors.Is(err, selfhost.ErrRecipientReplay):
		return "request rejected", 4
	case errors.Is(err, selfhost.ErrRecipientRegistry):
		return "recipient registry rejected", 4
	case errors.Is(err, selfhost.ErrRecipientAuthority):
		return "recipient authority rejected", 4
	case errors.Is(err, selfhost.ErrAddressExhausted):
		return "capacity exhausted", 4
	case errors.Is(err, selfhost.ErrTLSUnavailable):
		return "tls validity rejected", 4
	case errors.Is(err, errOutputExists):
		return "output exists", 6
	case errors.Is(err, errOutputIncomplete):
		return "output incomplete", 6
	case errors.Is(err, errUnsupportedFilesystem):
		return "unsupported filesystem", 6
	case errors.Is(err, selfhost.ErrStateCorrupt):
		return "state corrupt", 4
	case errors.Is(err, selfhost.ErrInvalidInput):
		return "invalid input", 2
	case errors.Is(err, selfhost.ErrNotFound):
		return "not found", 3
	case errors.Is(err, selfhost.ErrRecoveryRejected), errors.Is(err, selfhost.ErrRollback), errors.Is(err, selfhost.ErrClockUnhealthy):
		return "recovery rejected", 4
	case errors.Is(err, selfhost.ErrBusy):
		return "busy", 5
	default:
		return "operation failed", 1
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
  keys rotate tls
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
	if len(args) < 2 || args[0] != "rotate" || args[1] != "issuer" && args[1] != "relay" && args[1] != "tls" || rejectDuplicateFlags(args[2:], "data-dir", "recovery-file", "confirm") {
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
	} else if args[1] == "relay" {
		result, err = selfhost.RotateRelay(*dataDir, options)
	} else {
		result, err = selfhost.RotateTLS(*dataDir, options)
	}
	if err != nil {
		return err
	}
	return writeJSON(stdout, keyRotationResponseV2{
		Schema: "kurdctl-key-rotation-v2", Kind: result.Kind, DelegationEpoch: result.DelegationEpoch,
		RevocationEpoch: result.RevocationEpoch, RelayEpoch: result.RelayEpoch, TLSEpoch: result.TLSEpoch,
		RevokedProfiles: result.RevokedProfiles,
	})
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
		recipientRequest := set.String("recipient-request", "", "exact device enrollment request")
		registryDir := set.String("recipient-registry-dir", "", "owner-local recipient-use registry")
		confirmRecipientReuse := set.String("confirm-recipient-reuse", "", "must equal recipient-reuse for cross-deployment reuse")
		authorityOnly := set.Bool("authority-only", false, "issue a non-connectable authority-only artifact")
		outputDir := set.String("output-dir", "", "exclusive output directory")
		if rejectDuplicateFlags(args[1:], "data-dir", "name", "valid-for", "recipient-request", "recipient-registry-dir", "confirm-recipient-reuse", "authority-only", "output-dir") ||
			set.Parse(args[1:]) != nil || set.NArg() != 0 || *dataDir == "" || *name == "" || *outputDir == "" || *authorityOnly == (*recipientRequest != "") ||
			*authorityOnly && (*registryDir != "" || *confirmRecipientReuse != "") {
			return selfhost.ErrInvalidInput
		}
		var requestBytes []byte
		var liveProgram []byte
		var err error
		if !*authorityOnly {
			requestBytes, err = readBoundedRequest(*recipientRequest, enrollment.MaxRequestBytes)
			if err != nil {
				return err
			}
			if *registryDir == "" {
				*registryDir, err = defaultRecipientRegistryDir()
				if err != nil || prepareRecipientRegistryParent(*registryDir) != nil {
					zero(requestBytes)
					return errUnsupportedFilesystem
				}
			}
			liveProgram, err = compileLiveProgramV1()
			if err != nil {
				zero(requestBytes)
				return err
			}
		}
		issued, err := selfhost.CreateProfile(*dataDir, selfhost.CreateProfileOptions{
			Name: *name, ValidFor: *validFor, Now: time.Now().UTC(), RecipientRequest: requestBytes,
			LiveProgram: liveProgram, RegistryDir: *registryDir, ConfirmRecipientReuse: *confirmRecipientReuse,
		})
		zero(requestBytes)
		zero(liveProgram)
		if err != nil {
			return err
		}
		paths, err := writeIssued(*outputDir, issued)
		if err != nil {
			return committedOutputError{cause: err, profileID: issued.ProfileID, generation: issued.Generation}
		}
		return writeJSON(stdout, profileMutationResponse("kurdctl-profile-create-v2", issued, paths))
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
	artifact, err := readBoundedRequest(*file, envelope.MaxTotalInputBytes)
	if err != nil {
		return errRequestRejected
	}
	verified, err := selfhost.VerifyBundle(artifact, time.Now().UTC(), *minimumGeneration)
	clear(artifact)
	if err != nil {
		return err
	}
	return writeJSON(stdout, profileVerificationResponseV2{
		Schema: "kurdctl-profile-verification-v2", ProfileID: verified.ProfileID,
		ContentID: verified.ContentID, Generation: verified.Generation, ValidUntil: verified.ValidUntil,
		Mode: "authority-only", Sealed: false, Connectable: false,
	})
}

func runProfileShow(args []string, stdout io.Writer) error {
	set := newFlags("profile show")
	dataDir := set.String("data-dir", "", "state directory")
	id := set.String("id", "", "profile ID")
	profileID := set.String("profile-id", "", "profile ID")
	redacted := set.Bool("redacted", false, "show only the redacted summary")
	outputDir := set.String("output-dir", "", "exclusive output directory")
	reveal := set.String("reveal", "summary", "summary|uri|terminal")
	qr := set.Bool("qr", false, "render the profile QR in the terminal")
	if rejectDuplicateFlags(args, "data-dir", "id", "profile-id", "redacted", "output-dir", "reveal", "qr") || set.Parse(args) != nil || set.NArg() != 0 || *dataDir == "" ||
		*id != "" && *profileID != "" || *redacted && (*outputDir != "" || *qr || *reveal != "summary") || *outputDir != "" && (*qr || *reveal != "summary") || *qr && *reveal != "summary" {
		return selfhost.ErrInvalidInput
	}
	if *profileID != "" {
		*id = *profileID
	}
	if *redacted {
		*reveal = "summary"
	}
	if *qr {
		*reveal = "terminal"
	}
	issued, err := selfhost.LoadProfile(*dataDir, *id)
	if err != nil {
		return err
	}
	if *outputDir != "" {
		paths, writeErr := writeIssued(*outputDir, issued)
		if writeErr != nil {
			return writeErr
		}
		return writeJSON(stdout, profileMutationResponse("kurdctl-profile-export-v2", issued, paths))
	}
	switch *reveal {
	case "summary":
		return writeJSON(stdout, profileRedactedResponseV2{
			Schema: "kurdctl-profile-show-v2", ProfileID: issued.ProfileID, ContentID: issued.ContentID,
			Generation: issued.Generation, ValidUntil: issued.ValidUntil, Mode: issued.Mode,
			Sealed: issued.Sealed, Connectable: issued.Connectable, Revoked: issued.Revoked, QRCount: len(issued.QRChunks),
		})
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
	profileID := set.String("profile-id", "", "profile ID")
	recovery := set.String("recovery-file", "", "recovery artifact")
	validFor := set.Duration("valid-for", 7*24*time.Hour, "profile validity")
	recipientRequest := set.String("recipient-request", "", "fresh exact device enrollment request")
	registryDir := set.String("recipient-registry-dir", "", "owner-local recipient-use registry")
	confirmRecipientReuse := set.String("confirm-recipient-reuse", "", "must equal recipient-reuse for cross-deployment reuse")
	outputDir := set.String("output-dir", "", "exclusive output directory")
	if rejectDuplicateFlags(args, "data-dir", "id", "profile-id", "recovery-file", "valid-for", "recipient-request", "recipient-registry-dir", "confirm-recipient-reuse", "output-dir") ||
		set.Parse(args) != nil || set.NArg() != 0 || *dataDir == "" || *outputDir == "" || *recovery == "" || *id != "" && *profileID != "" {
		return selfhost.ErrInvalidInput
	}
	if *profileID != "" {
		*id = *profileID
	}
	var requestBytes []byte
	var err error
	if *recipientRequest != "" {
		requestBytes, err = readBoundedRequest(*recipientRequest, enrollment.MaxRequestBytes)
		if err != nil {
			return err
		}
		if *registryDir == "" {
			*registryDir, err = defaultRecipientRegistryDir()
			if err != nil || prepareRecipientRegistryParent(*registryDir) != nil {
				zero(requestBytes)
				return errUnsupportedFilesystem
			}
		}
	}
	passphrase, err := readPassphrase(stdin)
	if err != nil {
		return err
	}
	defer zero(passphrase)
	liveProgram, err := compileLiveProgramV1()
	if err != nil {
		zero(requestBytes)
		return err
	}
	issued, err := selfhost.RotateProfile(*dataDir, selfhost.RotateProfileOptions{
		ProfileID: *id, RecoveryPath: *recovery, RecoveryPassphrase: passphrase, ValidFor: *validFor, Now: time.Now().UTC(),
		RecipientRequest: requestBytes, LiveProgram: liveProgram, RegistryDir: *registryDir, ConfirmRecipientReuse: *confirmRecipientReuse,
	})
	zero(requestBytes)
	zero(liveProgram)
	if err != nil {
		return err
	}
	paths, err := writeIssued(*outputDir, issued)
	if err != nil {
		return committedOutputError{cause: err, profileID: issued.ProfileID, generation: issued.Generation}
	}
	return writeJSON(stdout, profileMutationResponse("kurdctl-profile-rotate-v2", issued, paths))
}

func runProfileRevoke(args []string, stdin io.Reader, stdout io.Writer) error {
	set := newFlags("profile revoke")
	dataDir := set.String("data-dir", "", "state directory")
	id := set.String("id", "", "profile ID")
	profileID := set.String("profile-id", "", "profile ID")
	recovery := set.String("recovery-file", "", "recovery artifact")
	confirm := set.String("confirm", "", "must equal profile ID")
	confirmProfile := set.String("confirm-profile", "", "must equal profile ID")
	if rejectDuplicateFlags(args, "data-dir", "id", "profile-id", "recovery-file", "confirm", "confirm-profile") || set.Parse(args) != nil || set.NArg() != 0 ||
		*id != "" && *profileID != "" || *confirm != "" && *confirmProfile != "" {
		return selfhost.ErrInvalidInput
	}
	if *profileID != "" {
		*id = *profileID
	}
	if *confirmProfile != "" {
		*confirm = *confirmProfile
	}
	if *confirm != *id {
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

type issuedFileWriterV2 func(root *privateOutputRoot, name string, value []byte) error

func writeIssued(outputDir string, issued selfhost.IssuedProfile) (profileOutputFilesV2, error) {
	return writeIssuedWithWriter(outputDir, issued, writePrivateFile)
}

func writeIssuedWithWriter(outputDir string, issued selfhost.IssuedProfile, writer issuedFileWriterV2) (profileOutputFilesV2, error) {
	if outputDir == "" {
		return profileOutputFilesV2{}, selfhost.ErrInvalidInput
	}
	if writer == nil {
		return profileOutputFilesV2{}, selfhost.ErrInvalidInput
	}
	type renderedFile struct {
		name  string
		value []byte
	}
	rendered := []renderedFile{
		{name: "profile.kurd-profile", value: bytes.Clone(issued.Artifact)},
		{name: "profile.kurd-uri.txt", value: []byte(issued.URI + "\n")},
	}
	paths := profileOutputFilesV2{
		Artifact: filepath.Join(outputDir, "profile.kurd-profile"),
		URI:      filepath.Join(outputDir, "profile.kurd-uri.txt"),
		QR:       make([]profileOutputQRFileV2, 0, len(issued.QRChunks)),
	}
	for index, chunk := range issued.QRChunks {
		name := "profile-qr-" + strconv.Itoa(index+1)
		pngValue, err := selfhost.RenderPNGQR(chunk, 8)
		if err != nil {
			return profileOutputFilesV2{}, err
		}
		svgValue, err := selfhost.RenderSVGQR(chunk, 8)
		if err != nil {
			return profileOutputFilesV2{}, err
		}
		pngName, svgName := name+".png", name+".svg"
		rendered = append(rendered, renderedFile{name: pngName, value: pngValue}, renderedFile{name: svgName, value: svgValue})
		paths.QR = append(paths.QR, profileOutputQRFileV2{Part: uint(index + 1), PNG: filepath.Join(outputDir, pngName), SVG: filepath.Join(outputDir, svgName)})
	}
	root, err := createPrivateOutputRoot(outputDir)
	if err != nil {
		return profileOutputFilesV2{}, err
	}
	defer root.Close()
	for _, file := range rendered {
		if err := writer(root, file.name, file.value); err != nil {
			return profileOutputFilesV2{}, err
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

func newFlags(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	return set
}

func profileMutationResponse(schema string, issued selfhost.IssuedProfile, files profileOutputFilesV2) profileMutationResponseV2 {
	return profileMutationResponseV2{
		Schema: schema, ProfileID: issued.ProfileID, ContentID: issued.ContentID, Generation: issued.Generation,
		ValidUntil: issued.ValidUntil, Mode: issued.Mode, Sealed: issued.Sealed, Connectable: issued.Connectable,
		Files: files, QRCount: len(files.QR),
	}
}

func rejectDuplicateFlags(args []string, names ...string) bool {
	seen := make(map[string]bool, len(names))
	watched := make(map[string]struct{}, len(names))
	for _, name := range names {
		watched[name] = struct{}{}
	}
	for _, argument := range args {
		if argument == "--" {
			return true
		}
		if !strings.HasPrefix(argument, "--") {
			continue
		}
		name := strings.TrimPrefix(argument, "--")
		if index := strings.IndexByte(name, '='); index >= 0 {
			name = name[:index]
		}
		if _, ok := watched[name]; !ok {
			continue
		}
		if seen[name] {
			return true
		}
		seen[name] = true
	}
	return false
}

func defaultRecipientRegistryDir() (string, error) {
	configuration, err := os.UserConfigDir()
	if err != nil || configuration == "" || !filepath.IsAbs(configuration) {
		return "", errUnsupportedFilesystem
	}
	return filepath.Join(filepath.Clean(configuration), "kurdistan-vpn", "recipient-use-v1"), nil
}

func prepareRecipientRegistryParent(registryDir string) error {
	parent := filepath.Dir(filepath.Clean(registryDir))
	if parent == "." || parent == string(os.PathSeparator) {
		return errUnsupportedFilesystem
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return errUnsupportedFilesystem
	}
	return protectPrivatePath(parent, true)
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
