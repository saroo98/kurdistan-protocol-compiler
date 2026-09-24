// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"errors"
	"math"
	"slices"
	"time"

	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/liveprogram"
)

const (
	productionNativeReconnectMaxV1 = uint8(10)
	productionNativeTCPFlowMaxV1   = uint16(4096)
	productionNativeUDPFlowMaxV1   = uint16(2048)
	productionNativeProxyClientsV1 = uint8(16)
	productionNativeProxyStreamsV1 = uint8(64)
	productionNativeAggregateV1    = uint32(128 << 20)
)

// productionProjectionV1 is a private calculation result. It owns plan but
// installs no service, reserves no runtime capacity, and attests no enforcement.
type productionProjectionV1 struct {
	plan    sessionplan.PlanV2
	request productionSettingsV1

	effectiveMode, effectiveDNSMode                                        uint8
	effectiveMTU                                                           uint16
	signedCapabilityMask, nativeCapabilityMask, effectiveCapabilityMask    uint16
	packetMax                                                              uint32
	queuePackets, incompleteOps                                            uint16
	payloadProtocolMask                                                    uint8
	signedReconnectMax, nativeReconnectMax, effectiveAutomaticReconnectMax uint8
	fallbackAttemptMax                                                     uint8
	dialTimeoutMillis, signedIdleTimeoutMillis                             uint32
	effectiveSessionIdleMillis                                             uint32
	effectiveAggregateBufferBytes                                          uint32
	rawFlowStatus                                                          uint8
	effectiveTCPFlowMax, effectiveUDPFlowMax                               uint16
	effectiveFlowIdleMillis                                                uint32
	signedStreamMax, nativeStreamMax, effectiveStreamMax                   uint8
	nativeClientMax, effectiveClientMax                                    uint8
	signedProxyBufferBytes, effectiveProxyBufferBytes                      uint32
	effectiveProxyIdleSeconds, signedConnectMillis                         uint16
	perDirectionQueueBytes                                                 uint32
	streamChunkMax                                                         uint16
	probeMaxConcurrent, probeMaxSamples                                    uint8
	probeMinAttemptIntervalMillis                                          uint32
	probeAttemptsPerMinute                                                 uint8
	probeMaxTotalMillis                                                    uint16
	updateMaxArtifactBytes                                                 uint32
	updateMaxTimeoutMillis                                                 uint16
	updateMinCheckIntervalSeconds                                          uint32
}

func (value *productionProjectionV1) Destroy() {
	if value == nil {
		return
	}
	value.plan.Destroy()
	*value = productionProjectionV1{}
}

func projectProductionSettingsV1(settings productionSettingsV1, authority sessionplan.RequestV2, now time.Time) (productionProjectionV1, productionStatusV1) {
	if now.IsZero() {
		return productionProjectionV1{}, productionTrustUnavailableV1
	}
	if authority.Profile.ValidUntil > 0 && now.Unix() >= authority.Profile.ValidUntil {
		return productionProjectionV1{}, productionAuthorityExpiredV1
	}
	if authority.Profile.ValidFrom > 0 && now.Unix() < authority.Profile.ValidFrom {
		return productionProjectionV1{}, productionVerificationRejectedV1
	}
	if settings.allowLAN || settings.excludedCount != 0 {
		return productionProjectionV1{}, productionPolicyRejectedV1
	}
	if settings.dnsMode == 3 {
		return productionProjectionV1{}, productionDNSPolicyRejectedV1
	}
	if settings.tunnelMode < 1 || settings.tunnelMode > 3 {
		return productionProjectionV1{}, productionInvalidRequestV1
	}
	policy := authority.RuntimePolicy
	proxyActive := settings.tunnelMode == 2 || settings.tunnelMode == 3
	if proxyActive && (policy.SchemaVersion != runtimepolicy.SchemaVersionV3 || policy.Services == nil || policy.Services.Proxy == nil) {
		return productionProjectionV1{}, productionNotAdmittedV1
	}

	strategy := ""
	switch settings.selection {
	case 1, 2:
		if !slices.Contains(authority.Profile.StrategyIDs, productionStrategyNativeIDV1) {
			return productionProjectionV1{}, productionNotAdmittedV1
		}
		strategy = productionStrategyNativeIDV1
	case 3:
		var ok bool
		strategy, ok = productionStrategyNativeV1(settings.manualStrategy, authority.Profile.StrategyIDs)
		if !ok {
			return productionProjectionV1{}, productionNotAdmittedV1
		}
	default:
		return productionProjectionV1{}, productionInvalidRequestV1
	}

	var ipMode runtimepolicy.IPModeV2
	switch settings.ipMode {
	case 1:
	case 2:
		ipMode = runtimepolicy.IPModeIPv4Only
	case 3:
		ipMode = runtimepolicy.IPModeIPv6Only
	case 4:
		ipMode = runtimepolicy.IPModeDualStack
	default:
		return productionProjectionV1{}, productionInvalidRequestV1
	}

	narrowing := sessionplan.NarrowingRequestV2{StrategyID: strategy, IPMode: ipMode, MTU: min(settings.mtu, uint16(1280))}
	build := func(requested sessionplan.NarrowingRequestV2) (sessionplan.PlanV2, productionStatusV1) {
		plan, err := sessionplan.BuildV2At(sessionplan.RequestV2{Profile: authority.Profile, ActivationReceipt: authority.ActivationReceipt, RuntimePolicy: authority.RuntimePolicy, Requested: requested}, now)
		if err == nil {
			return plan, productionSuccessV1
		}
		switch {
		case errors.Is(err, sessionplan.ErrWideningV2):
			return sessionplan.PlanV2{}, productionPolicyRejectedV1
		case errors.Is(err, sessionplan.ErrUnsupportedV2):
			return sessionplan.PlanV2{}, productionNotAdmittedV1
		default:
			return sessionplan.PlanV2{}, productionInvalidRequestV1
		}
	}
	plan, status := build(narrowing)
	if status != productionSuccessV1 {
		if ipMode != "" && (status == productionNotAdmittedV1 || status == productionPolicyRejectedV1) {
			return productionProjectionV1{}, productionPolicyRejectedV1
		}
		return productionProjectionV1{}, status
	}
	if settings.dnsMode == 4 {
		canonical := productionPlanDNSV1(plan)
		defer retireProductionDNSRowsV1(canonical)
		requested := make([][]byte, 0, 2)
		defer func() { retireProductionDNSRowsV1(requested) }()
		requested = append(requested, productionAddressBytesV1(settings.customPrimary))
		if settings.customSecondary.family != 0 {
			requested = append(requested, productionAddressBytesV1(settings.customSecondary))
		}
		if !productionSameAddressSetV1(requested, canonical) {
			plan.Destroy()
			return productionProjectionV1{}, productionDNSPolicyRejectedV1
		}
		plan.Destroy()
		narrowing.DNSServers = canonical
		plan, status = build(narrowing)
		if status != productionSuccessV1 {
			return productionProjectionV1{}, productionDNSPolicyRejectedV1
		}
	} else if settings.dnsMode != 1 && settings.dnsMode != 2 {
		plan.Destroy()
		return productionProjectionV1{}, productionInvalidRequestV1
	}

	projection := productionProjectionV1{plan: plan, request: settings, effectiveMode: settings.tunnelMode, effectiveDNSMode: settings.dnsMode, effectiveMTU: plan.MTU, packetMax: uint32(plan.MTU), queuePackets: plan.MaxQueuePackets, incompleteOps: plan.MaxIncompleteOps, signedReconnectMax: plan.MaxReconnectAttempts, nativeReconnectMax: productionNativeReconnectMaxV1, dialTimeoutMillis: durationMillisProductionV1(plan.DialTimeout), signedIdleTimeoutMillis: durationMillisProductionV1(plan.IdleTimeout)}
	projection.effectiveAutomaticReconnectMax = 0
	if settings.reconnectOnFailure {
		projection.effectiveAutomaticReconnectMax = min(settings.reconnectMaximum, plan.MaxReconnectAttempts, productionNativeReconnectMaxV1)
	}
	projection.fallbackAttemptMax = min(uint8(policy.Fallback.TotalAttempts), uint8(len(plan.Endpoints)), plan.MaxReconnectAttempts)
	projection.payloadProtocolMask = productionProtocolMaskV1(plan.PayloadProtocols)
	projection.signedCapabilityMask = productionSignedCapabilitiesV1(policy, plan)
	projection.nativeCapabilityMask = productionCapabilityMaskV1
	projection.effectiveCapabilityMask = projection.signedCapabilityMask & projection.nativeCapabilityMask
	if settings.tunnelMode == 1 {
		projection.effectiveCapabilityMask &^= productionCapabilityProxyStreamV1
	}
	if settings.tunnelMode == 3 {
		projection.effectiveCapabilityMask &^= productionCapabilityRawIPV1
	}

	requestedMiB := uint32(settings.memoryMiB)
	if requestedMiB == 0 {
		requestedMiB = 80
	}
	projection.effectiveAggregateBufferBytes = min(requestedMiB<<20, productionNativeAggregateV1)
	projection.effectiveSessionIdleMillis = min(uint32(settings.expertIdleSeconds)*1000, projection.signedIdleTimeoutMillis, uint32(3600000))
	if settings.tunnelMode == 3 {
		projection.rawFlowStatus = 2
	} else {
		projection.rawFlowStatus = 1
		projection.effectiveTCPFlowMax = min(settings.tcpLimit, productionNativeTCPFlowMaxV1)
		projection.effectiveUDPFlowMax = min(settings.udpLimit, productionNativeUDPFlowMaxV1)
		projection.effectiveFlowIdleMillis = projection.effectiveSessionIdleMillis
	}
	if proxyActive {
		if status := projection.projectProxyV1(policy); status != productionSuccessV1 {
			projection.Destroy()
			return productionProjectionV1{}, status
		}
	}
	projection.projectOperationsV1(policy)
	return projection, productionSuccessV1
}

func retireProductionDNSRowsV1(rows [][]byte) {
	for _, row := range rows {
		clear(row)
	}
	clear(rows)
}

func (value *productionProjectionV1) projectProxyV1(policy runtimepolicy.PolicyV2) productionStatusV1 {
	proxy := policy.Services.Proxy
	if proxy == nil || proxy.ConnectTimeoutMillis > math.MaxUint16 {
		return productionNotAdmittedV1
	}
	value.signedStreamMax = proxy.MaxConcurrentStreams
	value.nativeStreamMax = productionNativeProxyStreamsV1
	value.effectiveStreamMax = min(value.request.proxyStreams, value.signedStreamMax, value.nativeStreamMax)
	value.nativeClientMax = productionNativeProxyClientsV1
	value.effectiveClientMax = min(value.request.proxyClients, value.nativeClientMax)
	value.signedProxyBufferBytes = proxy.MaxBufferBytes
	requestedBytes := uint32(value.request.proxyMemoryMiB) << 20
	value.effectiveProxyBufferBytes = min(requestedBytes, proxy.MaxBufferBytes, productionNativeAggregateV1, value.effectiveAggregateBufferBytes)
	value.effectiveProxyIdleSeconds = min(value.request.proxyIdleSeconds, uint16(proxy.IdleTimeoutSeconds), uint16(3600))
	value.signedConnectMillis = uint16(proxy.ConnectTimeoutMillis)
	value.perDirectionQueueBytes = min(proxy.MaxQueuedBytesPerDirection, uint32(65536))
	program, err := liveprogram.DecodeV1(policy.LiveProgram)
	if err != nil {
		return productionInternalFailureV1
	}
	maximum := 0
	for _, message := range program.Messages {
		if message.Semantic == "data" {
			maximum = min(message.MaxPayloadBytes, program.Limits.MaxPayloadBytes)
			break
		}
	}
	chunk := min(16384, maximum-8, int(value.perDirectionQueueBytes))
	if chunk < 1 {
		return productionInternalFailureV1
	}
	value.streamChunkMax = uint16(chunk)
	return productionSuccessV1
}

func (value *productionProjectionV1) projectOperationsV1(policy runtimepolicy.PolicyV2) {
	if policy.Services == nil {
		return
	}
	if probes := policy.Services.Probes; probes != nil {
		value.probeMaxConcurrent = probes.MaxConcurrentOperations
		value.probeMaxSamples = probes.MaxSamplesPerOperation
		value.probeMinAttemptIntervalMillis = probes.MinAttemptIntervalMillis
		value.probeAttemptsPerMinute = probes.MaxAttemptsPerMinute
		value.probeMaxTotalMillis = uint16(probes.MaxOperationMillis)
	}
	if update := policy.Services.Update; update != nil {
		value.updateMaxArtifactBytes = update.MaxArtifactBytes
		value.updateMaxTimeoutMillis = uint16(update.TimeoutMillis)
		value.updateMinCheckIntervalSeconds = update.MinCheckIntervalSeconds
	}
}

func productionSignedCapabilitiesV1(policy runtimepolicy.PolicyV2, plan sessionplan.PlanV2) uint16 {
	var mask uint16
	if len(plan.PayloadProtocols) != 0 {
		mask |= productionCapabilityRawIPV1
	}
	if policy.Services == nil {
		return mask
	}
	if policy.Services.Proxy != nil {
		mask |= productionCapabilityProxyStreamV1
	}
	if probes := policy.Services.Probes; probes != nil {
		for _, target := range probes.Targets {
			if slices.Contains(target.Modes, uint8(1)) {
				mask |= productionCapabilityProbeDisconnectedV1
			}
			if slices.Contains(target.Modes, uint8(2)) {
				mask |= productionCapabilityProbeActiveV1
			}
		}
	}
	if policy.Services.Update != nil {
		mask |= productionCapabilityUpdateV1
	}
	return mask
}

func productionProtocolMaskV1(protocols []runtimepolicy.PayloadProtocolV2) uint8 {
	var mask uint8
	for _, protocol := range protocols {
		switch protocol {
		case runtimepolicy.PayloadProtocolICMP:
			mask |= 1 << 0
		case runtimepolicy.PayloadProtocolICMPv6:
			mask |= 1 << 1
		case runtimepolicy.PayloadProtocolTCP:
			mask |= 1 << 2
		case runtimepolicy.PayloadProtocolUDP:
			mask |= 1 << 3
		}
	}
	return mask
}

func productionPlanDNSV1(plan sessionplan.PlanV2) [][]byte {
	values := make([][]byte, 0, 2)
	if plan.IPMode == runtimepolicy.IPModeIPv4Only || plan.IPMode == runtimepolicy.IPModeDualStack {
		values = append(values, append([]byte(nil), plan.DNSIPv4[:]...))
	}
	if plan.IPMode == runtimepolicy.IPModeIPv6Only || plan.IPMode == runtimepolicy.IPModeDualStack {
		values = append(values, append([]byte(nil), plan.DNSIPv6[:]...))
	}
	return values
}

func productionAddressBytesV1(value productionAddressV1) []byte {
	if value.family == 4 {
		return value.value[:4]
	}
	if value.family == 6 {
		return value.value[:]
	}
	return nil
}

func productionSameAddressSetV1(requested, admitted [][]byte) bool {
	if len(requested) != len(admitted) {
		return false
	}
	used := make([]bool, len(admitted))
	for _, value := range requested {
		found := false
		for index, candidate := range admitted {
			if !used[index] && bytes.Equal(value, candidate) {
				used[index], found = true, true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func durationMillisProductionV1(value time.Duration) uint32 {
	millis := value.Milliseconds()
	if millis <= 0 || millis > math.MaxUint32 {
		return 0
	}
	return uint32(millis)
}
