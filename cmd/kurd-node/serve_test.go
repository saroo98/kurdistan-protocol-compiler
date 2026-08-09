// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"kurdistan/internal/relay/node"
	kruntime "kurdistan/internal/runtime"
)

func TestSessionRejectReporterIsCategoricalAndBounded(t *testing.T) {
	var output bytes.Buffer
	report := newSessionRejectReporterV1(&output, 2)
	report(node.SessionRejectAdmissionV1)
	report(node.SessionRejectTLSV1)
	report(node.SessionRejectStateV1)

	if got := output.String(); got != "kurd-node serve: session-rejected:admission\nkurd-node serve: session-rejected:tls\n" {
		t.Fatalf("unexpected categorical report %q", got)
	}
	for _, prohibited := range []string{"profile", "endpoint", "address", "key", "credential"} {
		if strings.Contains(output.String(), prohibited) {
			t.Fatalf("session rejection report exposed %q", prohibited)
		}
	}
}

func TestSessionStageReporterIsCategoricalAndBounded(t *testing.T) {
	var output bytes.Buffer
	report := newSessionStageReporterV1(&output, 2)
	report(node.SessionStageAcceptedV1)
	report(node.SessionStageTLSStartV1)
	report(node.SessionStageTLSReadyV1)
	if got := output.String(); got != "kurd-node serve: session-stage:accepted\nkurd-node serve: session-stage:tls-start\n" {
		t.Fatalf("output=%q", got)
	}
	for _, prohibited := range []string{"profile", "endpoint", "address", "key", "credential"} {
		if strings.Contains(output.String(), prohibited) {
			t.Fatalf("output exposed %q", prohibited)
		}
	}
}

func TestSessionPacketPumpReportsRemainCategorical(t *testing.T) {
	var output bytes.Buffer
	reportStage := newSessionStageReporterV1(&output, 4)
	reportReject := newSessionRejectReporterV1(&output, 4)
	reportStage(node.SessionStageKurdReadyV1)
	reportStage(node.SessionStagePumpReadyV1)
	reportReject(node.SessionRejectPacketPumpV1)

	if got := output.String(); got != "kurd-node serve: session-stage:kurd-ready\nkurd-node serve: session-stage:pump-ready\nkurd-node serve: session-rejected:packet-pump\n" {
		t.Fatalf("unexpected categorical output %q", got)
	}
	for _, prohibited := range []string{"profile", "endpoint", "address", "key", "credential", "payload", "destination"} {
		if strings.Contains(output.String(), prohibited) {
			t.Fatalf("output exposed %q", prohibited)
		}
	}
}

func TestSessionTerminationReporterIsCategoricalAndBounded(t *testing.T) {
	var output bytes.Buffer
	report := newSessionTerminationReporterV1(&output, 2)
	report(node.SessionTerminationQueueV1)
	report(node.SessionTerminationLifetimeV1)
	report(node.SessionTerminationProfileV1)
	if got := output.String(); got != "kurd-node serve: session-terminated:queue\nkurd-node serve: session-terminated:lifetime\n" {
		t.Fatalf("output=%q", got)
	}
	for _, prohibited := range []string{"profileId", "endpoint", "address", "key", "credential", "payload", "destination"} {
		if strings.Contains(output.String(), prohibited) {
			t.Fatalf("output exposed %q", prohibited)
		}
	}
}

func TestSessionPacketPumpSnapshotReporterIsAggregateOnlyAndBounded(t *testing.T) {
	var output bytes.Buffer
	report := newSessionPacketPumpSnapshotReporterV1(&output, 1)
	report(kruntime.PacketPumpSnapshotV1{
		TUNPacketsRead:                  2,
		OutboundPacketsAccepted:         1,
		CarrierRecordsWritten:           3,
		CarrierRecordsRead:              4,
		AuthenticatedOperations:         5,
		InnerPacketsAccepted:            6,
		InnerPacketsRejected:            7,
		TUNWriteAttempts:                8,
		TUNWriteFailures:                9,
		TUNWriteFailureCode:             kruntime.PacketPumpTUNWriteFailureInvalidV1,
		TUNWriteErrno:                   22,
		TUNPacketsWritten:               10,
		RejectedTUNPackets:              1,
		RelayGatewayDNSPackets:          11,
		RelayGatewayDNSChecksumFailures: 12,
		RelayTransportMalformedPackets:  13,
		RelayReturnTCPPackets:           14,
		RelayReturnTCPSYNPackets:        15,
		RelayReturnTCPACKPackets:        16,
		RelayReturnTCPRSTPackets:        17,
		RelayReturnTCPFINPackets:        18,
		RelayReturnTCPChecksumFailures:  19,
		RelayReturnOversizePackets:      20,
	})
	report(kruntime.PacketPumpSnapshotV1{TUNPacketsRead: 99})

	if got := output.String(); got != "kurd-node serve: session-pump:tun-read=2:outbound=1:carrier-write=3:carrier-read=4:authenticated=5:inner-accepted=6:inner-rejected=7:tun-attempts=8:tun-failures=9:tun-failure-code=invalid:tun-errno=22:tun-write=10:rejected=1:gateway-udp53=11:gateway-checksum-fail=12:transport-malformed=13:return-tcp=14:return-syn=15:return-ack=16:return-rst=17:return-fin=18:return-checksum-fail=19:return-oversize=20\n" {
		t.Fatalf("output=%q", got)
	}
	for _, prohibited := range []string{"profile", "endpoint", "address", "key", "credential", "payload", "destination", "dns"} {
		if strings.Contains(output.String(), prohibited) {
			t.Fatalf("output exposed %q", prohibited)
		}
	}
}

func TestServerStopCategoryIsBounded(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{err: node.ErrServerRegistry, want: "registry"},
		{err: node.ErrServerListener, want: "listener"},
		{err: node.ErrServerControl, want: "control"},
		{err: node.ErrServerReload, want: "reload"},
		{err: errors.New("private detail"), want: "unknown"},
	}
	for _, test := range tests {
		if got := serverStopCategoryV1(test.err); got != test.want {
			t.Fatalf("category=%q want=%q", got, test.want)
		}
	}
}
