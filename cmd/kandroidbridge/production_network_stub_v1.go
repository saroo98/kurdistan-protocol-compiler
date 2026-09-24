//go:build !android && !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"errors"
	"kurdistan/internal/product/runtimepolicy"
)

const productionPlatformSupportedV1 = false

func productionPrepareSocketV1(*productionAttemptTransportV1, runtimepolicy.EndpointV2) error {
	return errors.New("protected transport unsupported")
}
func productionConnectorBytesV1() uint64 { return 0 }

func productionCloseFDV1(int) error { return errors.New("protected transport unsupported") }
func (n *productionAttemptTransportV1) connectV1(context.Context, runtimepolicy.EndpointV2) error {
	return errors.New("protected transport unsupported")
}
