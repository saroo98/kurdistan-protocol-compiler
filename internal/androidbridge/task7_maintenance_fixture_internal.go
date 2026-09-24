//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"time"
)

type task7HandshakeKeyV1 struct{}
type task7HandshakeObservationV1 struct {
	observed bool
	category int64
}

// Only the synchronous fixture caller installs this private context value.
// Never retain the error or any certificate reached by errors.As.
func maintenanceObserveHandshakeFailureV1(ctx context.Context, err error) {
	o, ok := ctx.Value(task7HandshakeKeyV1{}).(*task7HandshakeObservationV1)
	if !ok || o == nil || o.observed {
		return
	}
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	category := int64(6)
	switch {
	case errors.As(err, &authority):
		category = 1
	case errors.As(err, &hostname):
		category = 2
	case errors.As(err, &invalid):
		category = 3
	case errors.Is(err, context.DeadlineExceeded):
		category = 4
	case errors.Is(err, context.Canceled):
		category = 5
	}
	o.category = category
	o.observed = true
}

// Task7MaintenanceFixtureRunV1 measures one real, already-adopted scoped parent.
// Native success means a prepared observation, never an update/candidate result.
func Task7MaintenanceFixtureRunV1(registry *HandleRegistry, parent Handle, caseID uint32, inv MaintenanceOutputInvocationV1) (out [24]int64, result MaintenanceResultV1) {
	for i := range out {
		out[i] = -1
	}
	out[0] = 1
	out[1] = int64(caseID)
	if (caseID < 1 || caseID > 3) && caseID != 301 && caseID != 302 {
		return out, MaintenanceInvalidRequest
	}
	if !inv.validV1() {
		return out, MaintenanceInvalidState
	}
	p, result := maintenanceParentOutputV1(registry, parent, inv)
	if result != 0 {
		return out, result
	}
	op, result := p.beginOperationOutputV1(inv, false)
	if result != 0 {
		return out, result
	}
	out[2] = 1
	defer func() {
		p.finishOperation(op)
		<-op.done
		p.mu.Lock()
		if p.operation == nil {
			out[18] = 1
		} else {
			out[18] = 0
		}
		out[19] = 0
		if p.pendingCandidate != nil {
			out[19] = 1
		}
		out[20] = 0
		if p.candidate != nil {
			out[20] = 1
		}
		out[21] = int64(p.cleanupCode)
		p.mu.Unlock()
	}()
	p.mu.Lock()
	refused := p.candidate != nil || p.pendingCandidate != nil
	if caseID == 1 || caseID == 2 {
		refused = refused || p.roots != nil || p.rootBlob != nil
	}
	p.mu.Unlock()
	if refused {
		return out, MaintenanceInvalidState
	}
	result = p.revalidatePlatform(op)
	out[3] = int64(result)
	if result != 0 {
		return out, result
	}
	now, mono, result := p.trustedNowAndMonotonic(op)
	if result != 0 {
		return out, result
	}
	if result = p.boundOperation(op, now, mono, now.Add(5*time.Second)); result != 0 {
		return out, result
	}
	op.completionGuard = func() MaintenanceResultV1 { return p.networkStatus(op) }
	if result = p.checkCompletion(op); result != 0 {
		return out, result
	}
	if caseID != 3 {
		result = p.loadRoots(op)
		out[4] = int64(result)
		if result != 0 {
			return out, result
		}
		count, used, ok := task7RootFramePrefixV1(p.rootBlob)
		if !ok {
			return out, MaintenanceInternalFailure
		}
		out[5] = int64(count)
		out[6] = int64(used)
	}
	result = p.networkStatus(op)
	out[7] = int64(result)
	if result != 0 {
		return out, result
	}
	if caseID == 2 {
		task7MaintenanceNegativeTLSV1(p, op, &out)
		if out[8] != int64(MaintenanceTLSRejected) || out[9] != 1 || out[10] != 1 || out[11] != 1 || out[12] != 1 || out[13] != 0 || out[14] != 0 || out[15] != 0 || out[16] != 1 {
			if result = p.checkCompletion(op); result != 0 {
				return out, result
			}
			return out, MaintenanceInternalFailure
		}
	}
	if caseID == 301 || caseID == 302 {
		task7MaintenanceHTTPSFixtureV1(p, op, &out, caseID == 302)
		valid := out[10] == 1 && out[15] == 0 && out[16] == 1 && out[9] == 1
		if caseID == 301 {
			valid = valid && out[8] == 0 && out[13] == 1 && out[14] > 0 && out[14] <= 65536
		} else {
			valid = valid && out[8] == int64(MaintenanceCancelled) && out[13] == 0 && out[14] == 0
		}
		if !valid {
			return out, MaintenanceInternalFailure
		}
	}
	result = p.checkCompletion(op)
	out[17] = int64(result)
	if result != 0 {
		return out, result
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.operationCanPublishLocked(op) || p.cleanupCode != CodeOK || p.cleanupPending || p.pendingCandidate != nil || p.candidate != nil {
		return out, MaintenanceCancelled
	}
	result = p.outputPrepareLockedV1(inv, 0, op.deadline, false)
	return out, result
}

// A private component route, never a production DNS/destination override. Real
// parent guards and system roots above remain intact; this pool is fixture-only.
func task7MaintenanceHTTPSFixtureV1(p *maintenanceAuthorityV1, op *maintenanceOperationV1, out *[24]int64, blocked bool) {
	now, status := p.trustedNow(op)
	if status != 0 {
		return
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"updates.example"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return
	}
	defer clear(der)
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	fetch := func(payload []byte) ([]byte, error) {
		ctx, cancel := context.WithCancel(op.ctx)
		defer cancel()
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return nil, err
		}
		deadline, _ := op.ctx.Deadline()
		if err = listener.SetDeadline(deadline); err != nil {
			listener.Close()
			return nil, err
		}
		var accepted, requests, selected int64
		joined := make(chan struct{})
		go func() {
			defer close(joined)
			raw, e := listener.AcceptTCP()
			if e != nil {
				return
			}
			accepted = 1
			defer raw.Close()
			if raw.SetDeadline(deadline) != nil {
				return
			}
			if blocked {
				var header [5]byte
				var hello [16384]byte
				defer clear(hello[:])
				if _, e = io.ReadFull(raw, header[:]); e != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(header[3:5]))
				if header[0] != 22 || header[1] != 3 || n < 1 || n > len(hello) {
					return
				}
				if _, e = io.ReadFull(raw, hello[:n]); e != nil {
					return
				}
				selected = 1
				cancel()
				return
			}
			server := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
			if server.Handshake() != nil {
				return
			}
			selected = 1
			request, e := http.ReadRequest(bufio.NewReaderSize(server, 4096))
			if e != nil {
				return
			}
			defer request.Body.Close()
			if request.Method != "GET" || request.URL.Path != "/profile" {
				return
			}
			requests = 1
			if _, e = fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(payload)); e == nil {
				_, _ = server.Write(payload)
			}
		}()
		stopDone := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { defer close(stopDone); listener.Close() })
		defer func() {
			listener.Close()
			if !stop() {
				<-stopDone
			}
			<-joined
			out[10] = accepted
			out[11] = selected
			out[13] = requests
			out[16] = 1
		}()
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
		if err != nil {
			return nil, err
		}
		body := make([]byte, 65536)
		var cleanup ErrorCode
		n, result := maintenanceHTTPSOwnedV1(ctx, raw, "https://updates.example/profile", "updates.example", pool, p.now, body, func() MaintenanceResultV1 { return p.checkCompletion(op) }, &cleanup)
		out[8] = int64(result)
		out[14] = int64(n)
		out[15] = int64(cleanup)
		if result != 0 {
			clear(body)
			return nil, errors.New("fixture HTTPS rejected")
		}
		return body[:n], nil
	}
	if blocked {
		_, _ = fetch(nil)
		if out[8] == int64(MaintenanceCancelled) && out[11] == 1 {
			out[9] = 1
		}
		return
	}
	n, err := p.owner.Task7FixtureSignedRoundTripV1(now, fetch)
	if err == nil && n > 0 {
		out[9] = 1
	}
}

// Walk only the already parsed retained frame prefix. No DER or subject copy.
func task7RootFramePrefixV1(raw []byte) (int, int, bool) {
	if len(raw) < 3 || len(raw) > 1048576 || raw[0] != 1 {
		return 0, 0, false
	}
	count := int(binary.BigEndian.Uint16(raw[1:3]))
	if count < 1 || count > 512 {
		return 0, 0, false
	}
	pos := 3
	for i := 0; i < count; i++ {
		if len(raw)-pos < 4 {
			return 0, 0, false
		}
		n := int(binary.BigEndian.Uint32(raw[pos : pos+4]))
		pos += 4
		if n < 1 || n > 16384 || n > len(raw)-pos {
			return 0, 0, false
		}
		pos += n
	}
	return count, pos, true
}

func task7MaintenanceNegativeTLSV1(p *maintenanceAuthorityV1, op *maintenanceOperationV1, out *[24]int64) {
	out[9] = -1
	now, result := p.trustedNow(op)
	if result != 0 {
		out[8] = int64(result)
		return
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"updates.example"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		return
	}
	defer clear(der)
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return
	}
	if parsed.VerifyHostname("updates.example") != nil || now.Before(parsed.NotBefore) || !now.Before(parsed.NotAfter) || len(parsed.ExtKeyUsage) != 1 || parsed.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return
	}
	out[12] = 1
	if result = p.checkCompletion(op); result != 0 {
		out[8] = int64(result)
		return
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	deadline, _ := op.ctx.Deadline()
	if listener.SetDeadline(deadline) != nil {
		listener.Close()
		return
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	var accepted, selected, requests int64
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		raw, err := listener.AcceptTCP()
		if err != nil {
			return
		}
		accepted = 1
		defer raw.Close()
		if raw.SetDeadline(deadline) != nil {
			return
		}
		server := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { selected = 1; return &certificate, nil }})
		if server.Handshake() != nil {
			return
		}
		request, err := http.ReadRequest(bufio.NewReaderSize(server, 4096))
		if err == nil {
			requests = 1
			request.Body.Close()
		}
	}()
	// The listener close callback has its own join, just like the maintained raw socket.
	stopDone := make(chan struct{})
	stop := context.AfterFunc(op.ctx, func() { defer close(stopDone); listener.Close() })
	defer func() {
		listener.Close()
		if !stop() {
			<-stopDone
		}
		<-joined
		out[10] = accepted
		out[11] = selected
		out[13] = requests
		out[16] = 1
	}()
	dialer := net.Dialer{}
	raw, err := dialer.DialContext(op.ctx, "tcp4", listener.Addr().String())
	if err != nil {
		out[8] = int64(p.transportOutcome(op, MaintenanceNetworkUnavailable))
		return
	}
	observation := &task7HandshakeObservationV1{category: -1}
	ctx := context.WithValue(op.ctx, task7HandshakeKeyV1{}, observation)
	var body [3]byte
	defer clear(body[:])
	var cleanup ErrorCode
	n, result := maintenanceHTTPSOwnedV1(ctx, raw, "https://updates.example/profile", "updates.example", p.roots, p.now, body[:], func() MaintenanceResultV1 { return p.checkCompletion(op) }, &cleanup)
	out[8] = int64(result)
	out[9] = observation.category
	out[14] = int64(n)
	out[15] = int64(cleanup)
}
