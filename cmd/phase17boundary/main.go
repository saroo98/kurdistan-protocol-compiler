// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase17boundary actively observes the Android and owner-VPS route
// and DNS boundary, then emits only a bounded categorical receipt.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"kurdistan/internal/phase17boundary"
)

const (
	boundaryAppPackage  = "org.kurdistanvpn.app.internal"
	boundaryTestRunner  = "org.kurdistanvpn.app.internal.test/androidx.test.runner.AndroidJUnitRunner"
	boundaryTestClass   = "org.kurdistanvpn.app.Phase17FieldActionDeviceTest#runRequestedFieldAction"
	boundaryDirectory   = "files/phase17-field"
	boundaryResultFile  = boundaryDirectory + "/result.txt"
	boundaryAttemptFile = boundaryDirectory + "/attempt.txt"
	maximumChildOutput  = 64 << 10
)

type observerRunner interface {
	Run(context.Context, []byte, string, ...string) ([]byte, error)
}

type observerRunnerFunc func(context.Context, []byte, string, ...string) ([]byte, error)

func (run observerRunnerFunc) Run(ctx context.Context, stdin []byte, name string, arguments ...string) ([]byte, error) {
	if run == nil {
		return nil, errors.New("observer runner unavailable")
	}
	return run(ctx, stdin, name, arguments...)
}

type realObserverRunner struct{}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	return runWithObserver(arguments, stdout, stderr, realObserverRunner{})
}

func runWithObserver(arguments []string, stdout, stderr io.Writer, runner observerRunner) int {
	flags := flag.NewFlagSet("phase17boundary", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requestPath := flags.String("request", "", "ephemeral canonical boundary request")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *requestPath == "" || runner == nil {
		return fail(stderr)
	}
	file, size, err := openRegular(*requestPath, phase17boundary.MaximumRequestBytes)
	if err != nil {
		return fail(stderr)
	}
	request, decodeErr := phase17boundary.DecodeRequest(file, size)
	closeErr := file.Close()
	if decodeErr != nil || closeErr != nil {
		return fail(stderr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	observation, err := observeBoundary(ctx, runner, request)
	if err != nil {
		return fail(stderr)
	}
	receipt, err := phase17boundary.Evaluate(request, observation)
	if err != nil {
		return fail(stderr)
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return fail(stderr)
	}
	if _, err := stdout.Write(raw); err != nil {
		return fail(stderr)
	}
	return 0
}

func observeBoundary(ctx context.Context, runner observerRunner, request phase17boundary.Request) (phase17boundary.Observation, error) {
	android, err := observeAndroid(ctx, runner, request)
	if err != nil {
		return phase17boundary.Observation{}, errors.New("Android boundary observer failed")
	}
	vps, err := observeVPS(ctx, runner, request)
	if err != nil {
		return phase17boundary.Observation{}, errors.New("VPS boundary observer failed")
	}
	return phase17boundary.Combine(android, vps), nil
}

func observeAndroid(ctx context.Context, runner observerRunner, request phase17boundary.Request) (result phase17boundary.AndroidObservation, resultErr error) {
	cleanup := func(cleanupCtx context.Context) error {
		raw, err := runner.Run(cleanupCtx, nil, request.ADBPath,
			"-s", request.DeviceSerial, "shell", "run-as", boundaryAppPackage,
			"rm", "-f", boundaryResultFile, boundaryAttemptFile)
		clear(raw)
		return err
	}
	if err := cleanup(ctx); err != nil {
		return result, err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := cleanup(cleanupCtx); err != nil {
			resultErr = errors.Join(resultErr, errors.New("Android boundary cleanup failed"))
		}
	}()
	pending := []byte("PENDING:" + request.AttemptID + "\n")
	raw, err := runner.Run(ctx, pending, request.ADBPath,
		"-s", request.DeviceSerial, "shell", "run-as", boundaryAppPackage, "sh", "-c",
		shellQuote("umask 077; mkdir -p "+boundaryDirectory+"; cat > "+boundaryAttemptFile))
	clear(raw)
	clear(pending)
	if err != nil {
		return result, err
	}
	verifyIPv6 := strconv.FormatBool(request.VerifyIPv6)
	raw, err = runner.Run(ctx, nil, request.ADBPath,
		"-s", request.DeviceSerial, "shell", "am", "instrument", "-w", "-r",
		"-e", "phase17FieldAction", "boundary",
		"-e", "phase17ProbeUrl", request.ProbeURL,
		"-e", "phase17VerifyIPv6", verifyIPv6,
		"-e", "phase17AttemptId", request.AttemptID,
		"-e", "class", boundaryTestClass, boundaryTestRunner)
	clear(raw)
	if err != nil {
		return result, err
	}
	attempt, err := readAppPrivate(ctx, runner, request, boundaryAttemptFile, 128)
	if err != nil {
		return result, err
	}
	defer clear(attempt)
	if string(attempt) != "STARTED:"+request.AttemptID+"\n" {
		return result, errors.New("Android boundary attempt correlation rejected")
	}
	resultRaw, err := readAppPrivate(ctx, runner, request, boundaryResultFile, phase17boundary.MaximumResultBytes)
	if err != nil {
		return result, err
	}
	defer clear(resultRaw)
	return phase17boundary.DecodeAndroidObservation(resultRaw, request.AttemptID)
}

func readAppPrivate(ctx context.Context, runner observerRunner, request phase17boundary.Request, path string, maximum int) ([]byte, error) {
	raw, err := runner.Run(ctx, nil, request.ADBPath,
		"-s", request.DeviceSerial, "exec-out", "run-as", boundaryAppPackage, "base64", path)
	if err != nil {
		clear(raw)
		return nil, err
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	clear(raw)
	if decodeErr != nil || len(decoded) == 0 || len(decoded) > maximum {
		clear(decoded)
		return nil, errors.New("Android boundary file rejected")
	}
	return decoded, nil
}

func observeVPS(ctx context.Context, runner observerRunner, request phase17boundary.Request) (phase17boundary.VPSObservation, error) {
	remote := fmt.Sprintf("sudo -n sh -s -- %s %d %t", request.AttemptID, request.RelayPort, request.VerifyIPv6)
	raw, err := runner.Run(ctx, []byte(vpsBoundaryScript()), request.SSHPath,
		"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=20",
		"--", request.SSHAlias, remote)
	if err != nil {
		clear(raw)
		return phase17boundary.VPSObservation{}, err
	}
	defer clear(raw)
	return phase17boundary.DecodeVPSObservation(raw, request.AttemptID)
}

func vpsBoundaryScript() string {
	return `set -eu
attempt=$1
relay_port=$2
verify_ipv6=$3
route_policy=false
dns_pinned=false
relay_bound=false
source_guard=false
ipv6_policy=false
ip link show dev kurd0 >/dev/null 2>&1 && \
  ip -o -4 addr show dev kurd0 | grep -F '10.77.0.1/' >/dev/null && \
  [ "$(sysctl -n net.ipv4.ip_forward)" = 1 ] && route_policy=true
rules=$(nft list table inet kurd_node)
printf '%s' "$rules" | grep -F 'iifname "kurd0" ip saddr != 10.77.0.0/16 drop' >/dev/null && \
  printf '%s' "$rules" | grep -F 'iifname "kurd0" ip daddr @blocked_ipv4 drop' >/dev/null && \
  printf '%s' "$rules" | grep -F 'oifname "kurd0" drop' >/dev/null && \
  printf '%s' "$rules" | grep -F 'ip saddr 10.77.0.0/16 masquerade' >/dev/null && source_guard=true
systemctl is-active --quiet unbound.service && \
  ss -H -lun 'sport = :53' | grep -F '10.77.0.1:53' >/dev/null && \
  ss -H -ltn 'sport = :53' | grep -F '10.77.0.1:53' >/dev/null && dns_pinned=true
ss -H -ltn "sport = :$relay_port" | grep -q . && relay_bound=true
if [ "$verify_ipv6" = false ]; then
  ipv6_policy=true
else
  ip -o -6 addr show dev kurd0 | grep -F 'fd4b:7572:6400::1/' >/dev/null && \
    [ "$(sysctl -n net.ipv6.conf.all.forwarding)" = 1 ] && \
    printf '%s' "$rules" | grep -F 'ip6 saddr != fd4b:7572:6400::/64 drop' >/dev/null && \
    printf '%s' "$rules" | grep -F 'ip6 saddr fd4b:7572:6400::/64 masquerade' >/dev/null && \
    ss -H -lun 'sport = :53' | grep -F '[fd4b:7572:6400::1]:53' >/dev/null && \
    ss -H -ltn 'sport = :53' | grep -F '[fd4b:7572:6400::1]:53' >/dev/null && ipv6_policy=true
fi
printf '{"schema":"kurdistan-phase17-boundary-vps-v1","attemptId":"%s","routePolicy":%s,"dnsPinned":%s,"relayBound":%s,"sourceGuard":%s,"ipv6Policy":%s,"coverageGap":false}' \
  "$attempt" "$route_policy" "$dns_pinned" "$relay_bound" "$source_guard" "$ipv6_policy"
`
}

func (realObserverRunner) Run(ctx context.Context, stdin []byte, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	if stdin != nil {
		command.Stdin = bytes.NewReader(stdin)
	}
	output := boundedBuffer{maximum: maximumChildOutput}
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	if output.overflow {
		clear(output.data)
		return nil, errors.New("observer output exceeded bound")
	}
	if err != nil {
		clear(output.data)
		return nil, errors.New("observer child process failed")
	}
	return output.data, nil
}

type boundedBuffer struct {
	data     []byte
	overflow bool
	maximum  int
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	if len(buffer.data)+len(data) > buffer.maximum {
		buffer.overflow = true
		remaining := buffer.maximum - len(buffer.data)
		if remaining > 0 {
			buffer.data = append(buffer.data, data[:remaining]...)
		}
		return len(data), nil
	}
	buffer.data = append(buffer.data, data...)
	return len(data), nil
}

func openRegular(path string, maximum int64) (*os.File, int64, error) {
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() ||
		before.Size() < 1 || before.Size() > maximum {
		return nil, 0, errors.New("boundary request rejected")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || opened.Size() != before.Size() {
		_ = file.Close()
		return nil, 0, errors.New("boundary request changed while opening")
	}
	return file, opened.Size(), nil
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func fail(stderr io.Writer) int {
	_, _ = fmt.Fprintln(stderr, "PHASE17_BOUNDARY_UNAVAILABLE")
	return 1
}
