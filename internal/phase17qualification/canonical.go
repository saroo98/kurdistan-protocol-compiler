// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

var rawMessageType = reflect.TypeOf(json.RawMessage{})

// MarshalCanonical produces the deliberately narrow canonical JSON form used
// by private Phase 17 qualification receipts. It accepts fixed structs and
// their scalar/slice fields, but rejects maps, interfaces, pointers, floats,
// and other representations whose semantics could be ambiguous.
func MarshalCanonical(value any) ([]byte, error) {
	if value == nil {
		return nil, errors.New("canonical value is nil")
	}
	if err := validateCanonicalValue(reflect.ValueOf(value), true); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	raw := output.Bytes()
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return nil, errors.New("canonical encoder omitted terminator")
	}
	return append([]byte(nil), raw[:len(raw)-1]...), nil
}

func validateCanonicalValue(value reflect.Value, top bool) error {
	if !value.IsValid() {
		return errors.New("canonical value is invalid")
	}
	typeOf := value.Type()
	if typeOf == rawMessageType {
		if top {
			return errors.New("canonical top-level raw message rejected")
		}
		if value.IsNil() || len(value.Bytes()) == 0 || !json.Valid(value.Bytes()) {
			return errors.New("canonical raw message rejected")
		}
		return nil
	}
	switch value.Kind() {
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			field := typeOf.Field(index)
			if field.PkgPath != "" {
				return fmt.Errorf("canonical struct contains unexported field %q", field.Name)
			}
			if err := validateCanonicalValue(value.Field(index), false); err != nil {
				return fmt.Errorf("canonical field %s: %w", field.Name, err)
			}
		}
		return nil
	case reflect.Slice, reflect.Array:
		if value.Kind() == reflect.Slice && value.IsNil() {
			return errors.New("canonical slice is nil")
		}
		for index := 0; index < value.Len(); index++ {
			if err := validateCanonicalValue(value.Index(index), false); err != nil {
				return fmt.Errorf("canonical element %d: %w", index, err)
			}
		}
		return nil
	case reflect.String, reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return nil
	case reflect.Map, reflect.Interface, reflect.Pointer, reflect.Float32, reflect.Float64,
		reflect.Complex64, reflect.Complex128, reflect.Func, reflect.Chan, reflect.UnsafePointer:
		return fmt.Errorf("canonical kind %s rejected", value.Kind())
	default:
		return fmt.Errorf("canonical kind %s unsupported", value.Kind())
	}
}
