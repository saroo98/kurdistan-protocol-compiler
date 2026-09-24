// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package winprivate

import (
	"errors"
	"testing"
)

func TestOperationErrorsRetainNativeCausesAndJoinOrder(t *testing.T) {
	first, second := errors.New("first"), errors.New("second")
	err := errors.Join(
		&OpError{Op: "publish", Err: first},
		&OpError{Op: "close", Err: second},
	)
	if !errors.Is(err, first) || !errors.Is(err, second) {
		t.Fatalf("lost cause: %v", err)
	}
	if err.Error() != "publish: first\nclose: second" {
		t.Fatalf("changed error order: %v", err)
	}
	if (&OpError{Op: "invalid handle"}).Error() != "invalid handle" {
		t.Fatal("nil native cause must remain representable")
	}
}
