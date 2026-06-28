// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxysem

func RunIntent(intent RelayIntent, request TargetRequest, seed int64) ([]TargetChunk, TargetResult, error) {
	if err := ValidateRelayIntent(intent); err != nil {
		return nil, TargetResult{}, err
	}
	if request.StreamID == 0 {
		request.StreamID = intent.StreamID
	}
	if request.Bytes > intent.MaxRequestBytes {
		return nil, TargetResult{}, ErrOversizedTarget
	}
	chunks, result, err := DefaultRegistry().Run(intent.Target, request, seed)
	if err != nil {
		return nil, TargetResult{}, err
	}
	if result.ResponseBytes > intent.MaxResponseBytes {
		return nil, TargetResult{}, ErrOversizedTarget
	}
	return chunks, result, nil
}
