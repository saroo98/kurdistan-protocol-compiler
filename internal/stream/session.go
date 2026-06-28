package stream

import (
	"fmt"
	"sort"

	"kurdistan/internal/ir"
)

type Config struct {
	IDStrategy                string
	IDEncodingMode            string
	MaxConcurrentStreams      int
	InitialStreamWindowBytes  int
	InitialSessionWindowBytes int
	WindowUpdatePolicy        string
	PriorityPolicy            string
	ClosePolicy               string
	ResetPolicy               string
	MaxStreamID               uint32
}

type WriteResult struct {
	StreamID               uint32
	BytesAccepted          int
	Backpressured          bool
	StreamWindowRemaining  int
	SessionWindowRemaining int
}

type Session struct {
	cfg           Config
	nextID        uint32
	sessionWindow int
	streams       map[uint32]*Stream
	openOrder     []uint32
}

func ConfigFromProfile(p *ir.Profile) Config {
	if p == nil {
		return Config{}
	}
	return Config{
		IDStrategy:                p.Stream.IDStrategy,
		IDEncodingMode:            p.Stream.IDEncodingMode,
		MaxConcurrentStreams:      p.Stream.MaxConcurrentStreams,
		InitialStreamWindowBytes:  p.Stream.InitialStreamWindowBytes,
		InitialSessionWindowBytes: p.Stream.InitialSessionWindowBytes,
		WindowUpdatePolicy:        p.Stream.WindowUpdatePolicy,
		PriorityPolicy:            p.Stream.PriorityPolicy,
		ClosePolicy:               p.Stream.ClosePolicy,
		ResetPolicy:               p.Stream.ResetPolicy,
		MaxStreamID:               p.Stream.MaxStreamID,
	}
}

func NewSession(cfg Config) (*Session, error) {
	if cfg.MaxConcurrentStreams <= 0 || cfg.InitialStreamWindowBytes <= 0 || cfg.InitialSessionWindowBytes <= 0 {
		return nil, fmt.Errorf("%w: positive stream count and windows are required", ErrInvalidConfig)
	}
	if cfg.InitialSessionWindowBytes < cfg.InitialStreamWindowBytes {
		return nil, fmt.Errorf("%w: session window smaller than stream window", ErrInvalidConfig)
	}
	if cfg.MaxStreamID == 0 {
		cfg.MaxStreamID = 1 << 24
	}
	if cfg.IDStrategy == "" {
		cfg.IDStrategy = "sequential_odd_even"
	}
	if cfg.PriorityPolicy == "" {
		cfg.PriorityPolicy = "fifo"
	}
	if cfg.ClosePolicy == "" {
		cfg.ClosePolicy = "explicit_close"
	}
	if cfg.ResetPolicy == "" {
		cfg.ResetPolicy = "immediate_reset"
	}
	return &Session{
		cfg:           cfg,
		nextID:        1,
		sessionWindow: cfg.InitialSessionWindowBytes,
		streams:       map[uint32]*Stream{},
	}, nil
}

func (s *Session) OpenStream(priority string) (uint32, error) {
	if s.activeStreamCount() >= s.cfg.MaxConcurrentStreams {
		return 0, ErrMaxConcurrentStreams
	}
	if priority == "" {
		priority = "bulk"
	}
	id, err := s.allocateID()
	if err != nil {
		return 0, err
	}
	s.streams[id] = &Stream{
		ID:          id,
		Priority:    priority,
		State:       StateOpen,
		windowBytes: s.cfg.InitialStreamWindowBytes,
	}
	s.openOrder = append(s.openOrder, id)
	return id, nil
}

func (s *Session) WriteData(id uint32, payload []byte) (WriteResult, error) {
	st, ok := s.streams[id]
	if !ok {
		return WriteResult{StreamID: id}, ErrUnknownStream
	}
	if st.State == StateClosed || st.State == StateReset || st.State == StateHalfClosedLocal {
		return WriteResult{StreamID: id}, ErrStreamClosed
	}
	n := len(payload)
	result := WriteResult{StreamID: id, StreamWindowRemaining: st.windowBytes, SessionWindowRemaining: s.sessionWindow}
	if n > st.windowBytes || n > s.sessionWindow {
		st.blocked = true
		result.Backpressured = true
		return result, ErrBackpressure
	}
	st.windowBytes -= n
	s.sessionWindow -= n
	st.pendingBytes += n
	st.blocked = false
	_, _ = st.buffer.Write(payload)
	result.BytesAccepted = n
	result.StreamWindowRemaining = st.windowBytes
	result.SessionWindowRemaining = s.sessionWindow
	return result, nil
}

func (s *Session) ReadData(id uint32) []byte {
	st, ok := s.streams[id]
	if !ok {
		return nil
	}
	out := append([]byte(nil), st.buffer.Bytes()...)
	st.buffer.Reset()
	st.pendingBytes = 0
	return out
}

func (s *Session) CloseLocal(id uint32) error {
	st, ok := s.streams[id]
	if !ok {
		return ErrUnknownStream
	}
	switch st.State {
	case StateOpen:
		st.State = StateHalfClosedLocal
	case StateHalfClosedRemote:
		st.State = StateClosed
	case StateClosed, StateReset:
		return ErrStreamClosed
	}
	return nil
}

func (s *Session) CloseRemote(id uint32) error {
	st, ok := s.streams[id]
	if !ok {
		return ErrUnknownStream
	}
	switch st.State {
	case StateOpen:
		st.State = StateHalfClosedRemote
	case StateHalfClosedLocal:
		st.State = StateClosed
	case StateClosed, StateReset:
		return ErrStreamClosed
	}
	return nil
}

func (s *Session) Reset(id uint32, reason string) error {
	st, ok := s.streams[id]
	if !ok {
		return ErrUnknownStream
	}
	st.State = StateReset
	st.resetReason = reason
	st.blocked = false
	return nil
}

func (s *Session) WindowUpdate(id uint32, credit int) error {
	if credit <= 0 {
		return fmt.Errorf("%w: positive credit is required", ErrInvalidConfig)
	}
	st, ok := s.streams[id]
	if !ok {
		return ErrUnknownStream
	}
	if st.State == StateClosed || st.State == StateReset {
		return ErrStreamClosed
	}
	st.windowBytes += credit
	s.sessionWindow += credit
	if st.windowBytes > 0 && s.sessionWindow > 0 {
		st.blocked = false
	}
	return nil
}

func (s *Session) State(id uint32) State {
	if st, ok := s.streams[id]; ok {
		return st.State
	}
	return StateIdle
}

func (s *Session) StreamWindow(id uint32) int {
	if st, ok := s.streams[id]; ok {
		return st.windowBytes
	}
	return 0
}

func (s *Session) SessionWindow() int {
	return s.sessionWindow
}

func (s *Session) ScheduleActiveStreams() []uint32 {
	candidates := make([]*Stream, 0, len(s.streams))
	for _, id := range s.openOrder {
		st := s.streams[id]
		if st == nil || st.blocked || st.State == StateClosed || st.State == StateReset {
			continue
		}
		candidates = append(candidates, st)
	}
	switch s.cfg.PriorityPolicy {
	case "interactive_first":
		sort.SliceStable(candidates, func(i, j int) bool {
			if candidates[i].Priority != candidates[j].Priority {
				return candidates[i].Priority == "interactive"
			}
			return candidates[i].ID < candidates[j].ID
		})
	case "smallest_pending_first":
		sort.SliceStable(candidates, func(i, j int) bool {
			if candidates[i].pendingBytes == candidates[j].pendingBytes {
				return candidates[i].ID < candidates[j].ID
			}
			return candidates[i].pendingBytes < candidates[j].pendingBytes
		})
	case "weighted_round_robin":
		sort.SliceStable(candidates, func(i, j int) bool {
			if candidates[i].Priority != candidates[j].Priority {
				return candidates[i].Priority == "interactive"
			}
			return candidates[i].ID < candidates[j].ID
		})
	}
	out := make([]uint32, 0, len(candidates))
	for _, st := range candidates {
		out = append(out, st.ID)
	}
	return out
}

func (s *Session) activeStreamCount() int {
	count := 0
	for _, st := range s.streams {
		if st.State != StateClosed && st.State != StateReset {
			count++
		}
	}
	return count
}

func (s *Session) allocateID() (uint32, error) {
	id := s.nextID
	if id == 0 || id > s.cfg.MaxStreamID {
		return 0, fmt.Errorf("%w: stream id overflow", ErrInvalidConfig)
	}
	switch s.cfg.IDStrategy {
	case "sequential_odd_even":
		s.nextID += 2
	case "randomized_bounded_ids", "table_mapped_ids", "varint_ids":
		s.nextID++
	default:
		s.nextID++
	}
	return id, nil
}
