// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package winprivate

import "errors"

var (
	ErrUnsafe     = errors.New("unsupported filesystem")
	ErrExists     = errors.New("private path already exists")
	ErrIncomplete = errors.New("private file creation incomplete")
)

type OpError struct {
	Op  string
	Err error
}

func (e *OpError) Error() string {
	if e.Err == nil {
		return e.Op
	}
	return e.Op + ": " + e.Err.Error()
}

func (e *OpError) Unwrap() error { return e.Err }
