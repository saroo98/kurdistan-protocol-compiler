package ir

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

var (
	ErrProfileMalformed          = errors.New("profile malformed")
	ErrProfileVersionUnsupported = errors.New("profile version unsupported")
	ErrProfileVersionMismatch    = errors.New("profile version mismatch")
	ErrMigrationRequired         = errors.New("profile migration required")
	ErrProfileInvalid            = errors.New("profile invalid")
	ErrProfileMismatch           = errors.New("profile mismatch")
)

const maxProfileBytesV1 = 1 << 20

type tupleClassV1 uint8

const (
	tupleInvalidV1 tupleClassV1 = iota
	tupleLegacyV1
	tupleCurrentV1
	tupleMixedV1
	tupleUnsupportedV1
)

func DecodeProfileV1(raw []byte) (*Profile, error) {
	p, class, err := decodeProfileSyntaxV1(raw)
	if err != nil {
		return nil, err
	}
	switch class {
	case tupleLegacyV1:
		return nil, ErrMigrationRequired
	case tupleMixedV1:
		return nil, ErrProfileVersionMismatch
	case tupleUnsupportedV1:
		return nil, ErrProfileVersionUnsupported
	case tupleCurrentV1:
	default:
		return nil, ErrProfileMalformed
	}
	if Validate(p) != nil {
		return nil, ErrProfileInvalid
	}
	return p, nil
}

func DecodeLegacyProfileForMigrationV1(raw []byte) (*Profile, error) {
	p, class, err := decodeProfileSyntaxV1(raw)
	if err != nil {
		return nil, err
	}
	switch class {
	case tupleCurrentV1:
		return nil, ErrMigrationRequired
	case tupleMixedV1:
		return nil, ErrProfileVersionMismatch
	case tupleUnsupportedV1:
		return nil, ErrProfileVersionUnsupported
	case tupleLegacyV1:
	default:
		return nil, ErrProfileMalformed
	}
	if p.GenerationHash == "" {
		return nil, ErrProfileInvalid
	}
	h, e := CanonicalHash(p)
	if e != nil || h != p.GenerationHash {
		return nil, ErrProfileInvalid
	}
	probe, e := cloneProfileV1(p)
	if e != nil {
		return nil, ErrProfileInvalid
	}
	setCurrentTupleV1(probe)
	probe.GenerationHash = ""
	if Validate(probe) != nil {
		return nil, ErrProfileInvalid
	}
	return p, nil
}

func decodeProfileSyntaxV1(raw []byte) (*Profile, tupleClassV1, error) {
	if len(raw) == 0 || len(raw) > maxProfileBytesV1 {
		return nil, tupleInvalidV1, ErrProfileMalformed
	}
	if err := strictJSONV1(raw); err != nil {
		return nil, tupleInvalidV1, ErrProfileMalformed
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p Profile
	if dec.Decode(&p) != nil {
		return nil, tupleInvalidV1, ErrProfileMalformed
	}
	return &p, classifyTupleV1(&p), nil
}

func strictJSONV1(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := scanValueV1(d); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing")
	}
	return nil
}
func scanValueV1(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			key, ok := k.(string)
			if !ok || seen[key] {
				return errors.New("duplicate")
			}
			seen[key] = true
			if e = scanValueV1(d); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return errors.New("object")
		}
	case '[':
		for d.More() {
			if e := scanValueV1(d); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return errors.New("array")
		}
	default:
		return errors.New("delimiter")
	}
	return nil
}
func classifyTupleV1(p *Profile) tupleClassV1 {
	v := []string{p.Version, p.Compatibility.SchemaVersion, p.Security.SecurityVersion, p.Compatibility.CompilerSecurityVersion, p.Compatibility.MinimumRuntimeVersion}
	for _, x := range v {
		if x == "" {
			return tupleInvalidV1
		}
	}
	legacy := []string{LegacySchemaVersionV1, LegacySchemaVersionV1, LegacySecurityVersionV1, LegacySecurityVersionV1, LegacySecurityVersionV1}
	current := []string{SupportedVersion, SupportedVersion, SupportedSecurityVersion, SupportedSecurityVersion, SupportedSecurityVersion}
	l, c := true, true
	recognized := true
	for i, x := range v {
		l = l && x == legacy[i]
		c = c && x == current[i]
		recognized = recognized && (x == legacy[i] || x == current[i])
	}
	if l {
		return tupleLegacyV1
	}
	if c {
		return tupleCurrentV1
	}
	if recognized {
		return tupleMixedV1
	}
	return tupleUnsupportedV1
}
func setCurrentTupleV1(p *Profile) {
	p.Version = SupportedVersion
	p.Compatibility.SchemaVersion = SupportedVersion
	p.Security.SecurityVersion = SupportedSecurityVersion
	p.Compatibility.CompilerSecurityVersion = SupportedSecurityVersion
	p.Compatibility.MinimumRuntimeVersion = SupportedSecurityVersion
}
func cloneProfileV1(p *Profile) (*Profile, error) {
	raw, e := json.Marshal(p)
	if e != nil {
		return nil, e
	}
	var out Profile
	e = json.Unmarshal(raw, &out)
	return &out, e
}
