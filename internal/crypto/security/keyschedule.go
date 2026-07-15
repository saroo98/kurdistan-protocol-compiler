// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const (
	keyScheduleKeyBytes   = 32
	keyScheduleNonceBytes = 12
)

const (
	keyLabelC2SKey    = "kurdistan/hkdf/v1/c2s-key"
	keyLabelS2CKey    = "kurdistan/hkdf/v1/s2c-key"
	keyLabelC2SNonce  = "kurdistan/hkdf/v1/c2s-nonce"
	keyLabelS2CNonce  = "kurdistan/hkdf/v1/s2c-nonce"
	keyLabelExporter  = "kurdistan/hkdf/v1/exporter"
	keyLabelRekey     = "kurdistan/hkdf/v1/rekey"
	keyLabelRekeySalt = "kurdistan/hkdf/v1/rekey-salt"
)

const (
	legacyKeyScheduleSaltPrefix = "kurdistan-key-schedule-v1:"
	legacyKeyScheduleInfoPrefix = "kurdistan-hkdf-v1/"
)

var ErrKDFInvalid = errors.New("kdf_invalid")

// KDFError is the stable, operand-free error category for the exact v1 key
// schedule. Its wrapped cause preserves the existing package error sentinels.
type KDFError struct {
	reason string
	cause  error
}

func (e *KDFError) Error() string {
	return "kdf_invalid"
}

func (e *KDFError) GoString() string {
	return "kdf_invalid"
}

func (e *KDFError) Unwrap() error {
	return e.cause
}

func (e *KDFError) Is(target error) bool {
	return target == ErrKDFInvalid
}

func kdfInvalid(cause error, reason string) error {
	return &KDFError{reason: reason, cause: cause}
}

// KeyScheduleInput contains the authenticated epoch-zero application secret and
// final transcript produced by the v1 handshake. Both byte fields must contain
// exactly 32 bytes and must not be all-zero. Calling DeriveKeyScheduleV1
// transfers ownership of ApplicationSecret; the supplied slice is wiped on
// every return path.
type KeyScheduleInput struct {
	ApplicationSecret []byte `json:"-"`
	TranscriptHash    []byte `json:"-"`
	Suite             Suite  `json:"suite"`
}

func (KeyScheduleInput) String() string {
	return "KeyScheduleInput{<redacted>}"
}

func (KeyScheduleInput) GoString() string {
	return "KeyScheduleInput{<redacted>}"
}

type KeySchedule struct {
	Suite           Suite  `json:"suite"`
	Epoch           uint64 `json:"-"`
	ClientWriteKey  []byte `json:"-"`
	ServerWriteKey  []byte `json:"-"`
	ClientNonceBase []byte `json:"-"`
	ServerNonceBase []byte `json:"-"`
	ExporterSecret  []byte `json:"-"`
	rekeySecret     []byte

	transcriptHash [sha256.Size]byte
	boundEpoch     uint64
	exactV1        bool
}

func (KeySchedule) String() string {
	return "KeySchedule{<redacted>}"
}

func (KeySchedule) GoString() string {
	return "KeySchedule{<redacted>}"
}

// Destroy wipes the mutable secret material held by a schedule and resets it.
// It is safe to call more than once. Lifecycle code must call Destroy only after
// atomically replacing or closing the schedule.
func (schedule *KeySchedule) Destroy() {
	if schedule == nil {
		return
	}
	wipeKeySchedule(schedule)
	*schedule = KeySchedule{}
}

// DeriveKeyScheduleV1 expands the exact RFC 5869 HKDF-SHA256 epoch-zero
// application secret produced by the authenticated v1 handshake. It does not
// repeat the handshake/application Extract steps or accept profile defaults.
func DeriveKeyScheduleV1(input KeyScheduleInput) (KeySchedule, error) {
	return deriveKeyScheduleV1(input, nil)
}

func deriveKeyScheduleV1(input KeyScheduleInput, observeInternalSecret func([]byte)) (KeySchedule, error) {
	return deriveKeyScheduleV1WithExpand(input, observeInternalSecret, expandKeyScheduleV1)
}

func deriveKeyScheduleV1WithExpand(input KeyScheduleInput, observeInternalSecret func([]byte), expand keyScheduleExpandFunc) (KeySchedule, error) {
	defer wipeKeyBytes(input.ApplicationSecret)
	for _, field := range []struct {
		name  string
		value []byte
		err   error
	}{
		{"application_secret", input.ApplicationSecret, ErrInvalidConfig},
		{"transcript", input.TranscriptHash, ErrInvalidTranscript},
	} {
		if err := validateKeyScheduleBytes(field.value); err != nil {
			return KeySchedule{}, kdfInvalid(field.err, field.name)
		}
	}
	if !SuiteSupported(input.Suite) {
		return KeySchedule{}, kdfInvalid(ErrInvalidSuite, "suite")
	}
	epochPRK := append([]byte(nil), input.ApplicationSecret...)
	defer wipeKeyBytes(epochPRK)
	if observeInternalSecret != nil {
		observeInternalSecret(epochPRK)
	}
	var transcript [sha256.Size]byte
	copy(transcript[:], input.TranscriptHash)
	return deriveEpochKeyScheduleWithExpand(input.Suite, epochPRK, transcript, 0, expand)
}

// RatchetKeyScheduleV1 derives exactly the next epoch. The caller cannot choose
// an epoch, and a modified or skipped public epoch is rejected.
func RatchetKeyScheduleV1(current KeySchedule) (KeySchedule, error) {
	return ratchetKeyScheduleV1(current, nil, expandKeyScheduleV1)
}

func ratchetKeyScheduleV1(current KeySchedule, observeEpochPRK func([]byte), expand keyScheduleExpandFunc) (KeySchedule, error) {
	if err := validateRatchetSourceV1(current); err != nil {
		return KeySchedule{}, err
	}
	if current.Epoch == math.MaxUint64 {
		return KeySchedule{}, kdfInvalid(ErrInvalidConfig, "epoch_overflow")
	}
	next := current.Epoch + 1
	nextBytes := keyScheduleU64(next)
	nextSalt := keyScheduleHash(keyLabelRekeySalt, current.transcriptHash[:], nextBytes[:])
	epochPRK, err := hkdf.Extract(sha256.New, current.rekeySecret, nextSalt[:])
	if err != nil {
		return KeySchedule{}, kdfInvalid(ErrInvalidConfig, "ratchet_extract")
	}
	defer wipeKeyBytes(epochPRK)
	if observeEpochPRK != nil {
		observeEpochPRK(epochPRK)
	}
	pending, err := deriveEpochKeyScheduleWithExpand(current.Suite, epochPRK, current.transcriptHash, next, expand)
	if err != nil {
		return KeySchedule{}, err
	}
	if err := validateCrossEpochSeparationV1(current, pending); err != nil {
		pending.Destroy()
		return KeySchedule{}, err
	}
	return pending, nil
}

type keyScheduleExpandFunc func([]byte, string, [sha256.Size]byte, uint64, int) ([]byte, error)

func deriveEpochKeySchedule(suite Suite, epochPRK []byte, transcript [sha256.Size]byte, epoch uint64) (KeySchedule, error) {
	return deriveEpochKeyScheduleWithExpand(suite, epochPRK, transcript, epoch, expandKeyScheduleV1)
}

func deriveEpochKeyScheduleWithExpand(suite Suite, epochPRK []byte, transcript [sha256.Size]byte, epoch uint64, expand keyScheduleExpandFunc) (schedule KeySchedule, err error) {
	if !SuiteSupported(suite) {
		return KeySchedule{}, kdfInvalid(ErrInvalidSuite, "suite")
	}
	if err := validateKeyScheduleBytes(epochPRK); err != nil {
		return KeySchedule{}, kdfInvalid(ErrInvalidConfig, "epoch_prk")
	}
	if allZeroKeyBytes(transcript[:]) {
		return KeySchedule{}, kdfInvalid(ErrInvalidTranscript, "transcript")
	}
	if expand == nil {
		return KeySchedule{}, kdfInvalid(ErrInvalidConfig, "expand_function")
	}
	schedule = KeySchedule{
		Suite:          suite,
		Epoch:          epoch,
		transcriptHash: transcript,
		boundEpoch:     epoch,
		exactV1:        true,
	}
	defer func() {
		if err != nil {
			wipeKeySchedule(&schedule)
			schedule = KeySchedule{}
		}
	}()
	for _, output := range []struct {
		label  string
		length int
		target *[]byte
	}{
		{keyLabelC2SKey, keyScheduleKeyBytes, &schedule.ClientWriteKey},
		{keyLabelS2CKey, keyScheduleKeyBytes, &schedule.ServerWriteKey},
		{keyLabelC2SNonce, keyScheduleNonceBytes, &schedule.ClientNonceBase},
		{keyLabelS2CNonce, keyScheduleNonceBytes, &schedule.ServerNonceBase},
		{keyLabelExporter, keyScheduleKeyBytes, &schedule.ExporterSecret},
		{keyLabelRekey, keyScheduleKeyBytes, &schedule.rekeySecret},
	} {
		*output.target, err = expand(epochPRK, output.label, transcript, epoch, output.length)
		if err != nil {
			if !errors.Is(err, ErrKDFInvalid) {
				err = kdfInvalid(ErrInvalidConfig, "expand")
			}
			return schedule, err
		}
	}
	if err = validateRatchetSourceV1(schedule); err != nil {
		return schedule, err
	}
	return schedule, nil
}

func expandKeyScheduleV1(epochPRK []byte, label string, transcript [sha256.Size]byte, epoch uint64, length int) ([]byte, error) {
	wantLength, ok := keyScheduleOutputLength(label)
	if !ok {
		return nil, kdfInvalid(ErrInvalidConfig, "label")
	}
	if length != wantLength {
		return nil, kdfInvalid(ErrInvalidConfig, "output_length")
	}
	if err := validateKeyScheduleBytes(epochPRK); err != nil {
		return nil, kdfInvalid(ErrInvalidConfig, "epoch_prk")
	}
	if allZeroKeyBytes(transcript[:]) {
		return nil, kdfInvalid(ErrInvalidTranscript, "transcript")
	}
	value, err := hkdf.Expand(sha256.New, epochPRK, string(keyScheduleInfo(label, transcript, epoch)), length)
	if err != nil {
		return nil, kdfInvalid(ErrInvalidConfig, "expand")
	}
	return value, nil
}

func keyScheduleOutputLength(label string) (int, bool) {
	switch label {
	case keyLabelC2SKey, keyLabelS2CKey, keyLabelExporter, keyLabelRekey:
		return keyScheduleKeyBytes, true
	case keyLabelC2SNonce, keyLabelS2CNonce:
		return keyScheduleNonceBytes, true
	default:
		return 0, false
	}
}

func keyScheduleHash(label string, parts ...[]byte) [sha256.Size]byte {
	var input bytes.Buffer
	writeKeyScheduleLP(&input, []byte(label))
	for _, part := range parts {
		writeKeyScheduleLP(&input, part)
	}
	return sha256.Sum256(input.Bytes())
}

func keyScheduleInfo(label string, transcript [sha256.Size]byte, epoch uint64) []byte {
	var out bytes.Buffer
	writeKeyScheduleLP(&out, []byte(label))
	out.Write(transcript[:])
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], epoch)
	out.Write(raw[:])
	return out.Bytes()
}

func keyScheduleU64(value uint64) [8]byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	return raw
}

func writeKeyScheduleLP(out *bytes.Buffer, value []byte) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], uint32(len(value)))
	out.Write(raw[:])
	out.Write(value)
}

func allZeroKeyBytes(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func validateKeyScheduleBytes(value []byte) error {
	if len(value) != sha256.Size || allZeroKeyBytes(value) {
		return ErrInvalidConfig
	}
	return nil
}

func validateRatchetSourceV1(current KeySchedule) error {
	if !current.exactV1 {
		return kdfInvalid(ErrInvalidConfig, "schedule_version")
	}
	if current.Epoch != current.boundEpoch {
		return kdfInvalid(ErrInvalidConfig, "epoch_skip")
	}
	if !SuiteSupported(current.Suite) {
		return kdfInvalid(ErrInvalidSuite, "suite")
	}
	if allZeroKeyBytes(current.transcriptHash[:]) {
		return kdfInvalid(ErrInvalidTranscript, "transcript")
	}
	for _, output := range []struct {
		name   string
		value  []byte
		length int
	}{
		{"client_write_key", current.ClientWriteKey, keyScheduleKeyBytes},
		{"server_write_key", current.ServerWriteKey, keyScheduleKeyBytes},
		{"client_nonce_base", current.ClientNonceBase, keyScheduleNonceBytes},
		{"server_nonce_base", current.ServerNonceBase, keyScheduleNonceBytes},
		{"exporter_secret", current.ExporterSecret, keyScheduleKeyBytes},
		{"rekey_secret", current.rekeySecret, keyScheduleKeyBytes},
	} {
		if len(output.value) != output.length || allZeroKeyBytes(output.value) {
			return kdfInvalid(ErrInvalidConfig, output.name)
		}
	}
	equalLengthOutputs := [][]byte{
		current.ClientWriteKey,
		current.ServerWriteKey,
		current.ExporterSecret,
		current.rekeySecret,
	}
	for left := 0; left < len(equalLengthOutputs); left++ {
		for right := left + 1; right < len(equalLengthOutputs); right++ {
			if bytes.Equal(equalLengthOutputs[left], equalLengthOutputs[right]) {
				return kdfInvalid(ErrInvalidConfig, "key_domain")
			}
		}
	}
	if bytes.Equal(current.ClientNonceBase, current.ServerNonceBase) {
		return kdfInvalid(ErrInvalidConfig, "nonce_domain")
	}
	return nil
}

func validateCrossEpochSeparationV1(current, pending KeySchedule) error {
	for _, pair := range []struct {
		current []byte
		pending []byte
	}{
		{current.ClientWriteKey, pending.ClientWriteKey},
		{current.ServerWriteKey, pending.ServerWriteKey},
		{current.ClientNonceBase, pending.ClientNonceBase},
		{current.ServerNonceBase, pending.ServerNonceBase},
		{current.ExporterSecret, pending.ExporterSecret},
		{current.rekeySecret, pending.rekeySecret},
	} {
		if bytes.Equal(pair.current, pair.pending) {
			return kdfInvalid(ErrInvalidConfig, "epoch_domain")
		}
	}
	return nil
}

func wipeKeyBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

// DeriveKeySchedule is retained only for pre-integration lab callers.
//
// Deprecated: this compatibility API is not the frozen authenticated v1 key
// schedule. New authenticated code must use DeriveKeyScheduleV1. Existing
// compatibility callers remain until an explicitly scoped migration order.
func DeriveKeySchedule(inputSecret []byte, transcriptHash string, suite Suite) (KeySchedule, error) {
	if len(inputSecret) == 0 {
		return KeySchedule{}, fmt.Errorf("%w: empty input secret", ErrInvalidConfig)
	}
	if transcriptHash == "" {
		return KeySchedule{}, fmt.Errorf("%w: missing transcript hash", ErrInvalidTranscript)
	}
	if !SuiteSupported(suite) {
		return KeySchedule{}, ErrInvalidSuite
	}
	prk, err := hkdf.Extract(sha256.New, inputSecret, []byte(legacyKeyScheduleSaltPrefix+transcriptHash))
	if err != nil {
		return KeySchedule{}, fmt.Errorf("%w: legacy extract", ErrInvalidConfig)
	}
	defer wipeKeyBytes(prk)
	var schedule KeySchedule
	schedule.Suite = suite
	defer func() {
		if err != nil {
			wipeKeySchedule(&schedule)
		}
	}()
	for _, output := range []struct {
		label  string
		length int
		target *[]byte
	}{
		{"client_write", keyScheduleKeyBytes, &schedule.ClientWriteKey},
		{"server_write", keyScheduleKeyBytes, &schedule.ServerWriteKey},
		{"client_nonce_base", keyScheduleNonceBytes, &schedule.ClientNonceBase},
		{"server_nonce_base", keyScheduleNonceBytes, &schedule.ServerNonceBase},
		{"exporter_secret", keyScheduleKeyBytes, &schedule.ExporterSecret},
	} {
		*output.target, err = hkdf.Expand(sha256.New, prk, legacyKeyScheduleInfoPrefix+output.label, output.length)
		if err != nil {
			return KeySchedule{}, fmt.Errorf("%w: legacy expand", ErrInvalidConfig)
		}
	}
	return schedule, nil
}

func KeyScheduleTrace(k KeySchedule) map[string]any {
	trace := map[string]any{
		"suite":             k.Suite,
		"client_write_key":  "<redacted>",
		"server_write_key":  "<redacted>",
		"client_nonce_base": "<redacted>",
		"server_nonce_base": "<redacted>",
		"exporter_secret":   "<redacted>",
		"key_bytes":         len(k.ClientWriteKey),
		"nonce_base_bytes":  len(k.ClientNonceBase),
	}
	if k.exactV1 {
		trace["rekey_secret"] = "<redacted>"
	}
	return trace
}

func wipeKeySchedule(schedule *KeySchedule) {
	wipeKeyBytes(schedule.ClientWriteKey)
	wipeKeyBytes(schedule.ServerWriteKey)
	wipeKeyBytes(schedule.ClientNonceBase)
	wipeKeyBytes(schedule.ServerNonceBase)
	wipeKeyBytes(schedule.ExporterSecret)
	wipeKeyBytes(schedule.rekeySecret)
}
