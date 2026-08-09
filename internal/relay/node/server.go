// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/wirev1"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
	"kurdistan/internal/transport/tlstcp"
)

var (
	ErrServerConfig   = errors.New("relay node: invalid server configuration")
	ErrServerState    = errors.New("relay node: runtime authority unavailable")
	ErrServerRun      = errors.New("relay node: server stopped")
	ErrServerSession  = errors.New("relay node: session rejected")
	ErrServerRegistry = errors.New("relay node: registry stopped")
	ErrServerListener = errors.New("relay node: listener stopped")
	ErrServerControl  = errors.New("relay node: control stopped")
	ErrServerReload   = errors.New("relay node: reload stopped")
)

type SessionRejectCodeV1 string
type SessionStageCodeV1 string
type SessionTerminationCodeV1 string

const (
	SessionRejectInvalidV1               SessionRejectCodeV1 = "invalid"
	SessionRejectHealthV1                SessionRejectCodeV1 = "health"
	SessionRejectSourceLimitV1           SessionRejectCodeV1 = "source-limit"
	SessionRejectPrefaceV1               SessionRejectCodeV1 = "preface"
	SessionRejectEntropyV1               SessionRejectCodeV1 = "entropy"
	SessionRejectStateV1                 SessionRejectCodeV1 = "state"
	SessionRejectAdmissionV1             SessionRejectCodeV1 = "admission"
	SessionRejectPlanV1                  SessionRejectCodeV1 = "plan"
	SessionRejectAuthV1                  SessionRejectCodeV1 = "auth"
	SessionRejectAuthConfigV1            SessionRejectCodeV1 = "auth-config"
	SessionRejectAuthConfigProfileV1     SessionRejectCodeV1 = "auth-config-profile"
	SessionRejectAuthConfigPolicyV1      SessionRejectCodeV1 = "auth-config-policy"
	SessionRejectAuthConfigFloorV1       SessionRejectCodeV1 = "auth-config-floor"
	SessionRejectAuthUnknownIdentityV1   SessionRejectCodeV1 = "auth-unknown-identity"
	SessionRejectAuthUntrustedIdentityV1 SessionRejectCodeV1 = "auth-untrusted-identity"
	SessionRejectAuthLimitV1             SessionRejectCodeV1 = "auth-limit"
	SessionRejectAuthCredentialsV1       SessionRejectCodeV1 = "auth-credentials"
	SessionRejectAddressV1               SessionRejectCodeV1 = "address"
	SessionRejectLifetimeV1              SessionRejectCodeV1 = "lifetime"
	SessionRejectCapacityV1              SessionRejectCodeV1 = "capacity"
	SessionRejectTLSV1                   SessionRejectCodeV1 = "tls"
	SessionRejectPacketPumpV1            SessionRejectCodeV1 = "packet-pump"
	SessionRejectPumpTUNV1               SessionRejectCodeV1 = "packet-pump-tun"
	SessionRejectPumpCarrierV1           SessionRejectCodeV1 = "packet-pump-carrier"
	SessionRejectPumpRecordV1            SessionRejectCodeV1 = "packet-pump-record"
	SessionRejectPumpQueueV1             SessionRejectCodeV1 = "packet-pump-queue"
	SessionRejectPumpIdleV1              SessionRejectCodeV1 = "packet-pump-idle"
)

const (
	SessionTerminationCompleteV1  SessionTerminationCodeV1 = "complete"
	SessionTerminationLifetimeV1  SessionTerminationCodeV1 = "lifetime"
	SessionTerminationQueueV1     SessionTerminationCodeV1 = "queue"
	SessionTerminationProfileV1   SessionTerminationCodeV1 = "profile"
	SessionTerminationAuthorityV1 SessionTerminationCodeV1 = "authority"
	SessionTerminationRegistryV1  SessionTerminationCodeV1 = "registry"
	SessionTerminationCancelledV1 SessionTerminationCodeV1 = "cancelled"
)

const (
	SessionStageAcceptedV1       SessionStageCodeV1 = "accepted"
	SessionStagePrefaceReadyV1   SessionStageCodeV1 = "preface-ready"
	SessionStageAuthorityReadyV1 SessionStageCodeV1 = "authority-ready"
	SessionStageTLSStartV1       SessionStageCodeV1 = "tls-start"
	SessionStageTLSReadyV1       SessionStageCodeV1 = "tls-ready"
	SessionStageKurdReadyV1      SessionStageCodeV1 = "kurd-ready"
	SessionStagePumpReadyV1      SessionStageCodeV1 = "pump-ready"
)

type RelaySnapshotV1 interface {
	StatusV1() (selfhost.RelayRuntimeStatusV1, bool)
	AdmissionByProfileV1(string, uint64) (selfhost.RelayAdmissionV1, bool)
	Local(string) (ed25519.PrivateKey, error)
	Peer(string) (ed25519.PublicKey, error)
	ServerTLSConfigV1() (*tls.Config, error)
	Close()
}

type ServerV1 struct {
	config           Config
	health           *HealthMachine
	registry         *SessionRegistry
	listener         net.Listener
	control          net.Listener
	authorizeControl func(net.Conn) error
	limiter          *SourceLimiterV1
	replay           *auth.HandshakeReplayCache
	workers          chan struct{}

	stateMu       sync.RWMutex
	snapshot      RelaySnapshotV1
	listenerReady bool
	tunnelReady   bool
	entropyMu     sync.Mutex
	runMu         sync.Mutex
	running       bool
	used          bool

	transientMu       sync.Mutex
	transientSequence uint64
	transients        map[string]transientSessionV1

	connectionMu       sync.Mutex
	connectionSequence uint64
	connectionsClosed  bool
	connections        map[uint64]net.Conn
}

type transientSessionV1 struct {
	profileID string
	cancel    context.CancelFunc
	token     uint64
}

func NewServerV1(config Config, listener net.Listener, tunnel io.ReadWriteCloser, control net.Listener, authorizeControl func(net.Conn) error) (*ServerV1, error) {
	if config.Validate() != nil || listener == nil || tunnel == nil || control == nil || authorizeControl == nil {
		return nil, ErrServerConfig
	}
	registry, err := NewSessionRegistry(tunnel, config.MaxSessions, config.SessionQueuePackets)
	if err != nil {
		return nil, ErrServerConfig
	}
	var sourceKey [32]byte
	if _, err := io.ReadFull(config.Entropy, sourceKey[:]); err != nil {
		_ = registry.Close()
		clear(sourceKey[:])
		return nil, ErrServerConfig
	}
	limiter, err := NewSourceLimiterV1(sourceKey[:], config.MaxSourceEntries, config.MaxSourceAttempts, config.SourceWindow, config.Now)
	clear(sourceKey[:])
	if err != nil {
		_ = registry.Close()
		return nil, ErrServerConfig
	}
	replay, err := auth.NewHandshakeReplayCache(65536)
	if err != nil {
		limiter.Close()
		_ = registry.Close()
		return nil, ErrServerConfig
	}
	return &ServerV1{
		config: config, health: NewHealthMachine(), registry: registry,
		listener: listener, control: control, authorizeControl: authorizeControl,
		limiter: limiter, replay: replay, workers: make(chan struct{}, config.MaxHandshakeWorkers),
		listenerReady: true, tunnelReady: true, transients: make(map[string]transientSessionV1),
		connections: make(map[uint64]net.Conn),
	}, nil
}

func (server *ServerV1) Run(ctx context.Context) error {
	if server == nil || ctx == nil || server.listener == nil || server.control == nil || server.authorizeControl == nil || server.limiter == nil || server.replay == nil {
		return ErrServerConfig
	}
	server.runMu.Lock()
	if server.running || server.used {
		server.runMu.Unlock()
		return ErrServerConfig
	}
	server.running = true
	server.used = true
	server.runMu.Unlock()
	defer func() {
		server.runMu.Lock()
		server.running = false
		server.runMu.Unlock()
	}()
	if err := server.Reload(); err != nil {
		server.health.Stop()
		_ = server.listener.Close()
		_ = server.control.Close()
		_ = server.registry.Close()
		server.shutdownV1()
		return err
	}

	runContext, cancel := context.WithCancel(ctx)
	errorsOut := make(chan error, 4)
	var wait sync.WaitGroup
	start := func(run func(context.Context) error) {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := run(runContext); err != nil && runContext.Err() == nil {
				select {
				case errorsOut <- err:
				default:
				}
			}
		}()
	}
	start(func(runContext context.Context) error {
		if err := server.registry.Run(runContext); err != nil {
			return errors.Join(ErrServerRegistry, err)
		}
		return nil
	})
	start(func(runContext context.Context) error {
		if err := server.acceptLoopV1(runContext); err != nil {
			return errors.Join(ErrServerListener, err)
		}
		return nil
	})
	start(func(runContext context.Context) error {
		if err := ServeControlV1(runContext, server.control, server.authorizeControl,
			ControlActionsV1{Health: server.health, Registry: server.registry, Reload: server.Reload, StopProfile: server.stopProfileV1},
			server.config.ControlTimeout, server.config.ControlWorkers); err != nil {
			return errors.Join(ErrServerControl, err)
		}
		return nil
	})
	start(func(runContext context.Context) error {
		if err := server.reloadLoopV1(runContext); err != nil {
			return errors.Join(ErrServerReload, err)
		}
		return nil
	})

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errorsOut:
	}
	server.health.Stop()
	cancel()
	_ = server.listener.Close()
	_ = server.control.Close()
	server.stopAllTransientsV1()
	server.closeAllConnectionsV1()
	_ = server.registry.Close()
	wait.Wait()
	server.shutdownV1()
	if runErr != nil {
		return errors.Join(ErrServerRun, runErr)
	}
	return nil
}

func (server *ServerV1) Reload() error {
	if server == nil || server.health == nil || server.registry == nil || server.config.LoadSnapshot == nil || server.config.Now == nil {
		return ErrServerConfig
	}
	server.stateMu.Lock()
	defer server.stateMu.Unlock()

	now := server.config.Now().UTC()
	candidate, err := server.config.LoadSnapshot(server.config.DataDir, now)
	if err != nil || candidate == nil {
		state := HealthDegraded
		switch {
		case errors.Is(err, selfhost.ErrDrained):
			state = HealthDraining
		case errors.Is(err, selfhost.ErrRelayRuntimeUnavailable):
			state = HealthDisabled
		}
		server.failClosedStateV1(state)
		if state == HealthDraining || state == HealthDisabled {
			return nil
		}
		return errors.Join(ErrServerState, err)
	}
	status, ok := candidate.StatusV1()
	tlsConfig, tlsErr := candidate.ServerTLSConfigV1()
	tlsValid := validRelayTLSConfigV1(tlsConfig)
	destroyTLSConfigV1(tlsConfig)
	dnsContext, cancel := context.WithTimeout(context.Background(), server.config.HandshakeTimeout)
	dnsReady := server.config.DNSReady != nil && server.config.DNSReady(dnsContext)
	cancel()
	if !ok || !validRelayRuntimeStatusV1(status) || !tlsValid || tlsErr != nil || !dnsReady {
		candidate.Close()
		state := HealthDegraded
		if status.Drained {
			state = HealthDraining
		}
		server.failClosedStateV1(state)
		return ErrServerState
	}
	if server.snapshot != nil {
		current, currentOK := server.snapshot.StatusV1()
		if currentOK && current == status {
			candidate.Close()
			server.health.SetDrain(false)
			server.health.SetDisabled(false)
			server.health.Update(server.readyRequirementsV1())
			return nil
		}
		server.stopAllTransientsV1()
		server.registry.StopAll()
		server.snapshot.Close()
	}
	server.snapshot = candidate
	server.health.SetDrain(false)
	server.health.SetDisabled(false)
	server.health.Update(server.readyRequirementsV1())
	return nil
}

func (server *ServerV1) acceptLoopV1(ctx context.Context) error {
	var sessions sync.WaitGroup
	defer sessions.Wait()
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return ErrServerRun
		}
		if !server.health.Snapshot().AcceptingSessions {
			_ = server.rejectSessionV1(SessionRejectHealthV1)
			_ = connection.Close()
			continue
		}
		if !server.limiter.Allow(connection.RemoteAddr()) {
			_ = server.rejectSessionV1(SessionRejectSourceLimitV1)
			_ = connection.Close()
			continue
		}
		select {
		case server.workers <- struct{}{}:
			connectionToken, tracked := server.trackConnectionV1(connection)
			if !tracked {
				<-server.workers
				_ = connection.Close()
				continue
			}
			sessions.Add(1)
			go func() {
				defer func() {
					server.releaseConnectionV1(connectionToken)
					<-server.workers
					sessions.Done()
				}()
				_ = server.handleSessionV1(ctx, connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (server *ServerV1) reloadLoopV1(ctx context.Context) error {
	ticker := time.NewTicker(server.config.ReloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_ = server.Reload()
		}
	}
}

func (server *ServerV1) handleSessionV1(runContext context.Context, raw net.Conn) error {
	if raw == nil {
		return server.rejectSessionV1(SessionRejectInvalidV1)
	}
	server.observeSessionStageV1(SessionStageAcceptedV1)
	defer raw.Close()
	prefaceContext, cancelPreface := context.WithTimeout(runContext, server.config.HandshakeTimeout)
	defer cancelPreface()
	if deadline, ok := prefaceContext.Deadline(); !ok || raw.SetDeadline(deadline) != nil {
		return server.rejectSessionV1(SessionRejectInvalidV1)
	}
	preface, err := sessionplan.ReadRelayAdmissionPrefaceV1(raw)
	cancelPreface()
	if err != nil {
		return server.rejectSessionV1(SessionRejectPrefaceV1)
	}
	server.observeSessionStageV1(SessionStagePrefaceReadyV1)
	sessionID, err := server.nextSessionIDV1()
	if err != nil {
		return server.rejectSessionV1(SessionRejectEntropyV1)
	}

	server.stateMu.RLock()
	if server.snapshot == nil || !server.health.Snapshot().AcceptingSessions {
		server.stateMu.RUnlock()
		return server.rejectSessionV1(SessionRejectStateV1)
	}
	snapshot := server.snapshot
	admission, ok := snapshot.AdmissionByProfileV1(preface.ProfileContentID, preface.ProfileGeneration)
	if !ok {
		server.stateMu.RUnlock()
		return server.rejectSessionV1(SessionRejectAdmissionV1)
	}
	plan, err := sessionplan.BuildRelayV2At(sessionplan.RelayAuthorityV2{
		ProfileContentID: admission.ContentID, ProfileGeneration: admission.Generation,
		ValidFrom: admission.ValidFrom, ValidUntil: admission.ValidUntil, RuntimePolicy: admission.RuntimePolicy,
		StrategyIDs: admission.StrategyIDs, RelayIDs: admission.RelayIDs,
	}, preface, server.config.Now().UTC())
	program, programErr := liveprogram.DecodeV1(admission.RuntimePolicy.LiveProgram)
	tlsConfig, tlsErr := snapshot.ServerTLSConfigV1()
	defer destroyTLSConfigV1(tlsConfig)
	status, statusOK := snapshot.StatusV1()
	if err != nil || programErr != nil || tlsErr != nil || !validRelayTLSConfigV1(tlsConfig) || !statusOK || status.RelayKeyID != plan.RelayKeyID {
		server.stateMu.RUnlock()
		return server.rejectSessionV1(SessionRejectPlanV1)
	}
	processConfig, err := auth.NewProjectedProcessHandshakeConfigV1(admission.ClientAuthKeyID, status.RelayKeyID, program, "tls13-tcp")
	if err != nil {
		server.stateMu.RUnlock()
		return server.rejectSessionV1(sessionRejectAuthConfigV1(err))
	}
	handshake, err := kruntime.NewProcessWireRelayHandshakeV1(processConfig, auth.Dependencies{Identity: snapshot, Trust: snapshot}, server.replay, plan.Digest)
	if err != nil {
		server.stateMu.RUnlock()
		return server.rejectSessionV1(sessionRejectHandshakeV1(err))
	}
	defer handshake.Close()
	assigned4, assigned6, ok := assignedAddressesV1(admission.AssignedIPv4, admission.AssignedIPv6)
	if !ok || assigned4 != plan.ClientIPv4 || assigned6 != plan.ClientIPv6 {
		server.stateMu.RUnlock()
		return server.rejectSessionV1(SessionRejectAddressV1)
	}
	maximumSession := time.Duration(program.Limits.MaxSessionMillis) * time.Millisecond
	if maximumSession <= 0 || maximumSession > 24*time.Hour {
		server.stateMu.RUnlock()
		return server.rejectSessionV1(SessionRejectLifetimeV1)
	}
	sessionContext, cancelSession := context.WithTimeout(runContext, maximumSession)
	transientToken, tracked := server.trackTransientV1(sessionID, admission.ProfileID, cancelSession)
	if !tracked {
		cancelSession()
		server.stateMu.RUnlock()
		return server.rejectSessionV1(SessionRejectCapacityV1)
	}
	server.stateMu.RUnlock()
	defer cancelSession()
	defer server.releaseTransientV1(sessionID, transientToken)
	server.observeSessionStageV1(SessionStageAuthorityReadyV1)

	handshakeContext, cancelHandshake := context.WithTimeout(sessionContext, server.config.HandshakeTimeout)
	defer cancelHandshake()
	if deadline, ok := handshakeContext.Deadline(); !ok || raw.SetDeadline(deadline) != nil {
		return server.rejectSessionV1(SessionRejectInvalidV1)
	}
	server.observeSessionStageV1(SessionStageTLSStartV1)
	carrier, err := tlstcp.Server(handshakeContext, raw, tlsConfig, plan.Digest, uint32(program.Limits.MaxFrameBytes))
	destroyTLSConfigV1(tlsConfig)
	if err != nil {
		return server.rejectSessionV1(SessionRejectTLSV1)
	}
	server.observeSessionStageV1(SessionStageTLSReadyV1)
	if err := raw.SetDeadline(time.Time{}); err != nil {
		_ = carrier.Close()
		return ErrServerSession
	}
	endpoint, err := acceptRelayDuplexEndpointV1(handshakeContext, carrier, handshake, plan.Digest, program)
	cancelHandshake()
	if err != nil {
		_ = carrier.Close()
		return ErrServerSession
	}
	server.observeSessionStageV1(SessionStageKurdReadyV1)

	server.stateMu.RLock()
	currentStatus, currentOK := selfhost.RelayRuntimeStatusV1{}, false
	if server.snapshot != nil {
		currentStatus, currentOK = server.snapshot.StatusV1()
	}
	if sessionContext.Err() != nil || !currentOK || currentStatus != status || !server.health.Snapshot().AcceptingSessions {
		server.stateMu.RUnlock()
		endpoint.Abort()
		_ = carrier.Close()
		return ErrServerSession
	}
	device, err := server.registry.Register(SessionSpec{
		ID: sessionID, ProfileID: admission.ProfileID, ClientKeyID: admission.ClientAuthKeyID,
		AssignedIPv4: assigned4, AssignedIPv6: assigned6, Cancel: cancelSession,
	})
	if err != nil {
		server.stateMu.RUnlock()
		endpoint.Abort()
		_ = carrier.Close()
		return server.rejectSessionV1(sessionRejectRegistryV1(err))
	}
	server.releaseTransientV1(sessionID, transientToken)
	server.stateMu.RUnlock()
	defer device.Close()

	idleTimeout := plan.IdleTimeout
	if idleTimeout <= 0 || idleTimeout > server.config.SessionIdleTimeout {
		idleTimeout = server.config.SessionIdleTimeout
	}
	duplexCarrier, err := kruntime.NewProcessTLSTCPDuplexCarrierV1(sessionContext, carrier, idleTimeout)
	if err != nil {
		endpoint.Abort()
		_ = carrier.Close()
		return ErrServerSession
	}
	pump, err := kruntime.NewPacketPumpV1(kruntime.PacketPumpConfigV1{
		TUN: device, Carrier: duplexCarrier, Endpoint: endpoint, Program: program, Direction: kruntime.DirectionRelayV1,
		AssignedIPv4: assigned4, AssignedIPv6: assigned6, QueuePackets: plan.MaxQueuePackets,
		IncompleteOps: plan.MaxIncompleteOps, BufferBudget: server.config.SessionBufferBudget, IdleTimeout: idleTimeout,
	})
	if err != nil {
		_ = duplexCarrier.Close()
		endpoint.Abort()
		return server.rejectSessionV1(SessionRejectPacketPumpV1)
	}
	defer pump.Close()
	server.observeSessionStageV1(SessionStagePumpReadyV1)
	pumpErr := pump.Run(sessionContext)
	server.observeSessionPacketPumpSnapshotV1(pump.SnapshotV1())
	contextErr := sessionContext.Err()
	if pumpErr != nil && contextErr == nil {
		return server.rejectSessionV1(sessionRejectPacketPumpV1(pumpErr))
	}
	server.observeSessionTerminationV1(sessionTerminationCodeV1(pumpErr, contextErr, device.StopCodeV1()))
	return nil
}

func sessionTerminationCodeV1(_ error, contextErr error, stopCode SessionStopCodeV1) SessionTerminationCodeV1 {
	if errors.Is(contextErr, context.DeadlineExceeded) {
		return SessionTerminationLifetimeV1
	}
	if errors.Is(contextErr, context.Canceled) {
		switch stopCode {
		case SessionStopQueueV1:
			return SessionTerminationQueueV1
		case SessionStopProfileV1:
			return SessionTerminationProfileV1
		case SessionStopAllV1:
			return SessionTerminationAuthorityV1
		case SessionStopRegistryV1:
			return SessionTerminationRegistryV1
		default:
			return SessionTerminationCancelledV1
		}
	}
	return SessionTerminationCompleteV1
}

func sessionRejectPacketPumpV1(err error) SessionRejectCodeV1 {
	stage, ok := kruntime.PacketPumpFailureStageV1(err)
	if !ok {
		return SessionRejectPacketPumpV1
	}
	return sessionRejectPacketPumpStageV1(stage)
}

func sessionRejectHandshakeV1(err error) SessionRejectCodeV1 {
	var handshakeErr *auth.HandshakeError
	if !errors.As(err, &handshakeErr) {
		return SessionRejectAuthCredentialsV1
	}
	switch handshakeErr.Code {
	case auth.FailureUnknownIdentity:
		return SessionRejectAuthUnknownIdentityV1
	case auth.FailureUntrustedIdentity:
		return SessionRejectAuthUntrustedIdentityV1
	case auth.FailureInternalLimit:
		return SessionRejectAuthLimitV1
	default:
		return SessionRejectAuthCredentialsV1
	}
}

func sessionRejectAuthConfigV1(err error) SessionRejectCodeV1 {
	var handshakeErr *auth.HandshakeError
	if !errors.As(err, &handshakeErr) {
		return SessionRejectAuthConfigV1
	}
	switch handshakeErr.Code {
	case auth.FailureProfileMismatch:
		return SessionRejectAuthConfigProfileV1
	case auth.FailurePolicyMismatch:
		return SessionRejectAuthConfigPolicyV1
	case auth.FailurePolicyFloorRejected:
		return SessionRejectAuthConfigFloorV1
	default:
		return SessionRejectAuthConfigV1
	}
}

func sessionRejectRegistryV1(err error) SessionRejectCodeV1 {
	if errors.Is(err, ErrSessionLimit) {
		return SessionRejectCapacityV1
	}
	return SessionRejectAdmissionV1
}

func sessionRejectPacketPumpStageV1(stage kruntime.PacketPumpStageV1) SessionRejectCodeV1 {
	switch stage {
	case kruntime.PacketPumpStageTUNReadV1, kruntime.PacketPumpStageTUNWriteV1, kruntime.PacketPumpStageTUNValidateV1:
		return SessionRejectPumpTUNV1
	case kruntime.PacketPumpStageCarrierReadV1, kruntime.PacketPumpStageCarrierWriteV1:
		return SessionRejectPumpCarrierV1
	case kruntime.PacketPumpStageOutboundQueueV1, kruntime.PacketPumpStageAuthenticatedQueueV1:
		return SessionRejectPumpQueueV1
	case kruntime.PacketPumpStageIdleV1:
		return SessionRejectPumpIdleV1
	case kruntime.PacketPumpStageSealV1, kruntime.PacketPumpStageRecordOpenV1, kruntime.PacketPumpStageInnerOperationV1,
		kruntime.PacketPumpStageInnerValidateV1, kruntime.PacketPumpStageReplayCommitV1:
		return SessionRejectPumpRecordV1
	default:
		return SessionRejectPacketPumpV1
	}
}

func (server *ServerV1) rejectSessionV1(code SessionRejectCodeV1) error {
	if server != nil && server.config.SessionRejected != nil {
		server.config.SessionRejected(code)
	}
	return ErrServerSession
}

func (server *ServerV1) observeSessionStageV1(stage SessionStageCodeV1) {
	if server != nil && server.config.SessionProgress != nil {
		server.config.SessionProgress(stage)
	}
}

func (server *ServerV1) observeSessionTerminationV1(code SessionTerminationCodeV1) {
	if server != nil && server.config.SessionTerminated != nil {
		server.config.SessionTerminated(code)
	}
}

func (server *ServerV1) observeSessionPacketPumpSnapshotV1(snapshot kruntime.PacketPumpSnapshotV1) {
	if server != nil && server.config.SessionPacketPumpSnapshot != nil {
		server.config.SessionPacketPumpSnapshot(snapshot)
	}
}

func acceptRelayDuplexEndpointV1(ctx context.Context, carrier *tlstcp.Conn, handshake *kruntime.ProcessWireRelayHandshakeV1, digest [32]byte, program liveprogram.ProgramV1) (*kruntime.ProcessRelayDuplexEndpointV1, error) {
	clientHello, err := receiveProcessFrameV1(ctx, carrier)
	if err != nil {
		return nil, ErrServerSession
	}
	serverHello, err := handshake.AcceptClientHello(clientHello)
	clear(clientHello)
	if err != nil || sendProcessFrameV1(ctx, carrier, serverHello) != nil {
		clear(serverHello)
		return nil, ErrServerSession
	}
	clear(serverHello)
	clientFinish, err := receiveProcessFrameV1(ctx, carrier)
	if err != nil {
		return nil, ErrServerSession
	}
	serverFinish, result, err := handshake.AcceptClientFinish(clientFinish)
	clear(clientFinish)
	if err != nil || sendProcessFrameV1(ctx, carrier, serverFinish) != nil {
		clear(serverFinish)
		if result != nil {
			result.Close()
		}
		return nil, ErrServerSession
	}
	clear(serverFinish)
	endpoint, err := kruntime.NewProcessRelayDuplexEndpointV1(result, digest, program)
	if err != nil {
		result.Close()
		return nil, ErrServerSession
	}
	binding, err := carrier.CarrierBinding()
	if err != nil {
		endpoint.Abort()
		return nil, ErrServerSession
	}
	profileBind, err := receiveProcessFrameV1(ctx, carrier)
	if err != nil {
		endpoint.Abort()
		return nil, ErrServerSession
	}
	ready, err := endpoint.AcceptProfileBind(profileBind, binding)
	clear(profileBind)
	if err != nil || sendProcessFrameV1(ctx, carrier, ready) != nil {
		clear(ready)
		endpoint.Abort()
		return nil, ErrServerSession
	}
	clear(ready)
	return endpoint, nil
}

func receiveProcessFrameV1(ctx context.Context, carrier *tlstcp.Conn) ([]byte, error) {
	frame, err := carrier.Receive(ctx)
	if err != nil {
		return nil, ErrServerSession
	}
	encoded, err := wirev1.Encode(frame)
	clear(frame.Payload)
	if err != nil {
		return nil, ErrServerSession
	}
	return encoded, nil
}

func sendProcessFrameV1(ctx context.Context, carrier *tlstcp.Conn, encoded []byte) error {
	if len(encoded) == 0 {
		return ErrServerSession
	}
	frame, err := wirev1.Decode(encoded)
	if err != nil {
		return ErrServerSession
	}
	defer clear(frame.Payload)
	if err := carrier.Send(ctx, frame); err != nil {
		return ErrServerSession
	}
	return nil
}

func assignedAddressesV1(ipv4, ipv6 []byte) ([4]byte, [16]byte, bool) {
	var address4 [4]byte
	var address6 [16]byte
	if len(ipv4) != 0 && len(ipv4) != len(address4) || len(ipv6) != 0 && len(ipv6) != len(address6) || len(ipv4) == 0 && len(ipv6) == 0 {
		return address4, address6, false
	}
	copy(address4[:], ipv4)
	copy(address6[:], ipv6)
	return address4, address6, true
}

func (server *ServerV1) nextSessionIDV1() (string, error) {
	var value [16]byte
	server.entropyMu.Lock()
	_, err := io.ReadFull(server.config.Entropy, value[:])
	server.entropyMu.Unlock()
	if err != nil {
		clear(value[:])
		return "", ErrServerSession
	}
	encoded := hex.EncodeToString(value[:])
	clear(value[:])
	return encoded, nil
}

func (server *ServerV1) shutdownV1() {
	server.stopAllTransientsV1()
	server.stateMu.Lock()
	if server.snapshot != nil {
		server.snapshot.Close()
		server.snapshot = nil
	}
	server.stateMu.Unlock()
	if server.limiter != nil {
		server.limiter.Close()
	}
}

func (server *ServerV1) failClosedStateV1(state HealthState) {
	server.stopAllTransientsV1()
	server.registry.StopAll()
	if server.snapshot != nil {
		server.snapshot.Close()
		server.snapshot = nil
	}
	server.health.SetDrain(false)
	server.health.SetDisabled(false)
	server.health.Update(HealthRequirements{Listener: server.listenerReady, Tunnel: server.tunnelReady})
	switch state {
	case HealthDraining:
		server.health.SetDrain(true)
	case HealthDisabled:
		server.health.SetDisabled(true)
	}
}

func (server *ServerV1) readyRequirementsV1() HealthRequirements {
	return HealthRequirements{
		Listener: server.listenerReady, Tunnel: server.tunnelReady, VerifiedState: true,
		TLSIdentity: true, RelayIdentity: true, DNS: true,
	}
}

func validRelayRuntimeStatusV1(status selfhost.RelayRuntimeStatusV1) bool {
	return status.Revision > 0 && status.Generation > 0 && status.RelayEpoch > 0 && status.TLSEpoch > 0 &&
		status.RelayKeyID != "" && len(status.RelayKeyID) <= 128 && status.TLSKeyID != "" && len(status.TLSKeyID) <= 128 &&
		status.RelayPublic != ([32]byte{}) && !status.Drained
}

func validRelayTLSConfigV1(config *tls.Config) bool {
	private, privateOK := ed25519.PrivateKey(nil), false
	if config != nil && len(config.Certificates) == 1 {
		private, privateOK = config.Certificates[0].PrivateKey.(ed25519.PrivateKey)
	}
	return config != nil && config.MinVersion == tls.VersionTLS13 && config.MaxVersion == tls.VersionTLS13 &&
		len(config.NextProtos) == 1 && config.NextProtos[0] == tlstcp.ALPN && len(config.Certificates) == 1 &&
		len(config.Certificates[0].Certificate) == 1 && len(config.Certificates[0].Certificate[0]) > 0 &&
		privateOK && len(private) == ed25519.PrivateKeySize
}

func destroyTLSConfigV1(config *tls.Config) {
	if config == nil {
		return
	}
	for index := range config.Certificates {
		for _, certificate := range config.Certificates[index].Certificate {
			clear(certificate)
		}
		if private, ok := config.Certificates[index].PrivateKey.(ed25519.PrivateKey); ok {
			clear(private)
		}
		config.Certificates[index] = tls.Certificate{}
	}
	config.Certificates = nil
}

func (server *ServerV1) trackTransientV1(sessionID, profileID string, cancel context.CancelFunc) (uint64, bool) {
	if server == nil || !boundedSessionIDV1(sessionID) || !boundedSessionIDV1(profileID) || cancel == nil {
		return 0, false
	}
	server.transientMu.Lock()
	defer server.transientMu.Unlock()
	if server.transients == nil {
		server.transients = make(map[string]transientSessionV1)
	}
	if _, exists := server.transients[sessionID]; exists {
		return 0, false
	}
	server.transientSequence++
	if server.transientSequence == 0 {
		server.transientSequence++
	}
	token := server.transientSequence
	server.transients[sessionID] = transientSessionV1{profileID: profileID, cancel: cancel, token: token}
	return token, true
}

func (server *ServerV1) releaseTransientV1(sessionID string, token uint64) {
	if server == nil || sessionID == "" || token == 0 {
		return
	}
	server.transientMu.Lock()
	if transient, exists := server.transients[sessionID]; exists && transient.token == token {
		delete(server.transients, sessionID)
	}
	server.transientMu.Unlock()
}

func (server *ServerV1) stopAllTransientsV1() int {
	if server == nil {
		return 0
	}
	server.transientMu.Lock()
	transients := server.transients
	server.transients = make(map[string]transientSessionV1)
	server.transientMu.Unlock()
	for _, transient := range transients {
		transient.cancel()
	}
	return len(transients)
}

func (server *ServerV1) trackConnectionV1(connection net.Conn) (uint64, bool) {
	if server == nil || connection == nil {
		return 0, false
	}
	server.connectionMu.Lock()
	defer server.connectionMu.Unlock()
	if server.connectionsClosed {
		return 0, false
	}
	if server.connections == nil {
		server.connections = make(map[uint64]net.Conn)
	}
	server.connectionSequence++
	if server.connectionSequence == 0 {
		server.connectionSequence++
	}
	token := server.connectionSequence
	server.connections[token] = connection
	return token, true
}

func (server *ServerV1) releaseConnectionV1(token uint64) {
	if server == nil || token == 0 {
		return
	}
	server.connectionMu.Lock()
	delete(server.connections, token)
	server.connectionMu.Unlock()
}

func (server *ServerV1) closeAllConnectionsV1() int {
	if server == nil {
		return 0
	}
	server.connectionMu.Lock()
	server.connectionsClosed = true
	connections := server.connections
	server.connections = make(map[uint64]net.Conn)
	server.connectionMu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	return len(connections)
}

func (server *ServerV1) stopProfileV1(profileID string) int {
	if server == nil || !boundedSessionIDV1(profileID) {
		return 0
	}
	server.stateMu.Lock()
	defer server.stateMu.Unlock()
	server.transientMu.Lock()
	transients := make([]context.CancelFunc, 0)
	for sessionID, transient := range server.transients {
		if transient.profileID == profileID {
			transients = append(transients, transient.cancel)
			delete(server.transients, sessionID)
		}
	}
	server.transientMu.Unlock()
	for _, cancel := range transients {
		cancel()
	}
	stopped := len(transients)
	if server.registry != nil {
		stopped += server.registry.StopProfile(profileID)
	}
	return stopped
}
