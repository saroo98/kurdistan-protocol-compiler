// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const hostBootPowerShell = `$value = (Get-CimInstance -ClassName Win32_OperatingSystem -Property LastBootUpTime -ErrorAction Stop).LastBootUpTime; if ($null -eq $value) { throw 'boot identity unavailable' }; [Console]::Out.Write($value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture))`

type hostBootExecutor func(context.Context, string, ...string) ([]byte, error)

func ReadCurrentHostBootIdentity(ctx context.Context, powershellPath string) ([]byte, error) {
	return readCurrentHostBootIdentity(ctx, powershellPath, executeHostBootProbe)
}

func readCurrentHostBootIdentity(ctx context.Context, powershellPath string, execute hostBootExecutor) ([]byte, error) {
	if ctx == nil || execute == nil || !filepath.IsAbs(powershellPath) || strings.ContainsAny(powershellPath, "\r\n\x00") {
		return nil, errors.New("qualification host boot probe rejected")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := execute(
		probeCtx, powershellPath,
		"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", hostBootPowerShell,
	)
	if err != nil || probeCtx.Err() != nil || len(raw) == 0 || len(raw) > 256 {
		Clear(raw)
		return nil, errors.New("qualification host boot identity unavailable")
	}
	defer Clear(raw)
	value := bytes.TrimSpace(raw)
	if len(value) == 0 || bytes.ContainsAny(value, "\r\n\x00") {
		return nil, errors.New("qualification host boot identity rejected")
	}
	parsed, err := time.Parse(time.RFC3339Nano, string(value))
	if err != nil || parsed.Location() != time.UTC {
		return nil, errors.New("qualification host boot identity rejected")
	}
	return []byte(parsed.UTC().Format(time.RFC3339Nano)), nil
}

func executeHostBootProbe(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, arguments...)
	output := &boundedHostBootBuffer{maximum: 256}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil || output.overflow {
		Clear(output.data)
		return nil, errors.New("qualification host boot command failed")
	}
	return output.data, nil
}

type boundedHostBootBuffer struct {
	data     []byte
	maximum  int
	overflow bool
}

func (buffer *boundedHostBootBuffer) Write(value []byte) (int, error) {
	if len(buffer.data)+len(value) > buffer.maximum {
		buffer.overflow = true
		remaining := buffer.maximum - len(buffer.data)
		if remaining > 0 {
			buffer.data = append(buffer.data, value[:remaining]...)
		}
		return len(value), nil
	}
	buffer.data = append(buffer.data, value...)
	return len(value), nil
}
