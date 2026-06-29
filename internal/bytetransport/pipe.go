// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransport

import "fmt"

type BytePipe struct {
	cfg           ByteTransportConfig
	queue         []EncodedFrame
	bufferedBytes int
	closed        bool
	reset         bool
	backpressure  int
}

func NewBytePipe(cfg ByteTransportConfig) (*BytePipe, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	return &BytePipe{cfg: cfg}, nil
}

func (p *BytePipe) Write(frame EncodedFrame) error {
	if p == nil {
		return fmt.Errorf("%w: nil pipe", ErrInvalidConfig)
	}
	if p.reset {
		return ErrPipeReset
	}
	if p.closed {
		return ErrPipeClosed
	}
	if len(frame.Bytes) > p.cfg.MaxFrameBytes {
		return ErrFrameTooLarge
	}
	if len(p.queue) >= p.cfg.MaxPipeQueueDepth || p.bufferedBytes+len(frame.Bytes) > p.cfg.MaxBufferedBytes {
		p.backpressure++
		return ErrBackpressure
	}
	p.queue = append(p.queue, frame)
	p.bufferedBytes += len(frame.Bytes)
	return nil
}

func (p *BytePipe) Read() (EncodedFrame, error) {
	if p == nil {
		return EncodedFrame{}, fmt.Errorf("%w: nil pipe", ErrInvalidConfig)
	}
	if p.reset {
		return EncodedFrame{}, ErrPipeReset
	}
	if len(p.queue) == 0 {
		if p.closed {
			return EncodedFrame{}, ErrPipeClosed
		}
		return EncodedFrame{}, fmt.Errorf("%w: empty", ErrPipeClosed)
	}
	frame := p.queue[0]
	copy(p.queue, p.queue[1:])
	p.queue = p.queue[:len(p.queue)-1]
	p.bufferedBytes -= len(frame.Bytes)
	return frame, nil
}

func (p *BytePipe) Close() {
	if p != nil {
		p.closed = true
	}
}

func (p *BytePipe) Reset() {
	if p != nil {
		p.reset = true
		p.queue = nil
		p.bufferedBytes = 0
	}
}

func (p *BytePipe) BackpressureEvents() int {
	if p == nil {
		return 0
	}
	return p.backpressure
}

func (p *BytePipe) BufferedBytes() int {
	if p == nil {
		return 0
	}
	return p.bufferedBytes
}
