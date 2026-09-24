// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"context"
	"math"
	"time"
	"unsafe"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/wirev1"
	"kurdistan/internal/transport/tlstcp"
)

type processHandshakeCallHoldersV1 struct {
	ctx       context.Context
	carrier   *tlstcp.Conn
	handshake *ProcessWireClientHandshakeV1
	encoded   [4][]byte
	result    *auth.ProcessHandshakeResultV1
	err       error
}

type processHandshakeFrameHoldersV1 struct {
	ctx               context.Context
	carrier           *tlstcp.Conn
	encoded           []byte
	frame, codecFrame wirev1.Frame
	length            [4]byte
	deadline          time.Time
	err               error
}

// ProcessClientHandshakeWorkspaceV1 adds the concrete wrapper and framed
// helper stages to auth's pure pre-secret equations. No serializer, credential,
// handshake, or carrier constructor is called. It is not an admission receipt.
func ProcessClientHandshakeWorkspaceV1(p liveprogram.ProgramV1, clientID, relayID string) (uint64, error) {
	b, err := auth.ProjectedClientWorkspaceV1(p, clientID, relayID)
	if err != nil {
		return 0, err
	}
	overflow := false
	add := func(values ...uint64) uint64 {
		var n uint64
		for _, v := range values {
			if v > math.MaxUint64-n {
				overflow = true
				return 0
			}
			n += v
		}
		return n
	}
	clone := func(n uint64) uint64 {
		if n == 0 {
			return 0
		}
		return add(n, n, 8)
	}
	h, q, m := b.HelloBytes, b.PeerHelloBytes, uint64(p.Limits.MaxFrameBytes)
	wrapper := uint64(unsafe.Sizeof(ProcessWireClientHandshakeV1{}))
	call := uint64(unsafe.Sizeof(processHandshakeCallHoldersV1{}))
	frame := uint64(unsafe.Sizeof(processHandshakeFrameHoldersV1{}))
	constructor := add(uint64(unsafe.Sizeof(auth.ProcessHandshakeConfigV1{})), uint64(unsafe.Sizeof(auth.Dependencies{})), wrapper, b.Stages[1])
	hello := max(b.Stages[2], add(b.AwaitHelloBytes, clone(h), clone(h), 48, h))
	sendHello := add(b.AwaitHelloBytes, 48, h, clone(h), 48, h, 4, frame)
	receiveHello := add(b.AwaitHelloBytes, m, clone(m-48), 4, frame)
	acceptHello := add(b.Stages[3], 48, q, clone(q))
	finishWrap := add(b.AwaitFinishBytes, clone(136), clone(136), 184)
	sendFinish := add(b.AwaitFinishBytes, 184, clone(136), 184, 4, frame)
	receiveFinish := add(b.AwaitFinishBytes, m, clone(m-48), 4, frame)
	// The control frame may carry q bytes before the auth finish's semantic
	//132-byte body check. Encoded frame and decoded payload remain distinct.
	acceptFinish := add(b.Stages[4], 48, q, clone(q))
	peak := max(b.Stages[0], constructor, add(wrapper, call, max(hello, sendHello, receiveHello, acceptHello, finishWrap, sendFinish, receiveFinish, acceptFinish, b.Stages[5])))
	if overflow {
		return 0, ErrProfileIncompatible
	}
	return peak, nil
}

// CompleteProcessClientHandshakeV1 performs only the existing framed Kurd
// handshake. The caller owns carrier cancellation/Close and must serialize this
// call with other handshake access. The returned result is fresh and unconsumed:
// no endpoint, record stream, exporter Bind, or readiness event is created here.
func CompleteProcessClientHandshakeV1(ctx context.Context, carrier *tlstcp.Conn, handshake *ProcessWireClientHandshakeV1) (*auth.ProcessHandshakeResultV1, error) {
	if handshake != nil {
		defer handshake.Close()
	}
	if ctx == nil || carrier == nil || handshake == nil {
		return nil, ErrProcessSessionV1
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	clientHello, err := handshake.Start()
	if err != nil {
		clear(clientHello)
		return nil, err
	}
	err = sendEncodedProcessFrameV1(ctx, carrier, clientHello)
	clear(clientHello)
	clientHello = nil
	if err != nil {
		return nil, err
	}
	serverHello, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		clear(serverHello)
		return nil, err
	}
	clientFinish, err := handshake.AcceptServerHello(serverHello)
	clear(serverHello)
	serverHello = nil
	if err != nil {
		clear(clientFinish)
		return nil, err
	}
	err = sendEncodedProcessFrameV1(ctx, carrier, clientFinish)
	clear(clientFinish)
	clientFinish = nil
	if err != nil {
		return nil, err
	}
	serverFinish, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		clear(serverFinish)
		return nil, err
	}
	result, err := handshake.AcceptServerFinish(serverFinish)
	clear(serverFinish)
	serverFinish = nil
	if err != nil {
		if result != nil {
			result.Close()
		}
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		result.Close()
		return nil, err
	}
	return result, nil
}
