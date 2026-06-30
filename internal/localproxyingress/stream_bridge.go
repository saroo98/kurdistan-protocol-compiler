// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

import "kurdistan/internal/proxyingress"

type StreamBridgeResult struct {
	RequestID            string `json:"request_id"`
	StreamOpened         bool   `json:"stream_opened"`
	TargetDescriptorSent bool   `json:"target_descriptor_sent"`
	DataIntentCount      int    `json:"data_intent_count"`
	CloseIntentCount     int    `json:"close_intent_count"`
	ResetIntentCount     int    `json:"reset_intent_count"`
	ErrorIntentCount     int    `json:"error_intent_count"`
	BackpressureCount    int    `json:"backpressure_count"`
	RuntimeMappingHash   string `json:"runtime_mapping_hash"`
	ProxySemIntentHash   string `json:"proxysem_intent_hash"`
	PayloadLogged        bool   `json:"payload_logged"`
	SecretLogged         bool   `json:"secret_logged"`
}

func BridgeEvents(request proxyingress.SyntheticProxyRequest, events []SyntheticIngressEvent, contract proxyingress.ProxyIngressContract) (StreamBridgeResult, error) {
	plan, err := proxyingress.BuildRuntimeStreamMappingPlan(request, contract)
	if err != nil {
		return StreamBridgeResult{}, err
	}
	result := StreamBridgeResult{RequestID: request.RequestID, RuntimeMappingHash: plan.MappingHash}
	for _, event := range events {
		switch event.Kind {
		case RequestEventOpen:
			result.StreamOpened = true
			result.TargetDescriptorSent = true
		case RequestEventData:
			result.DataIntentCount++
		case RequestEventClose:
			result.CloseIntentCount++
		case RequestEventReset:
			result.ResetIntentCount++
		case RequestEventTargetErr:
			result.ErrorIntentCount++
		case RequestEventBackpress:
			result.BackpressureCount++
		}
		result.PayloadLogged = result.PayloadLogged || event.PayloadLogged
		result.SecretLogged = result.SecretLogged || event.SecretLogged
	}
	result.ProxySemIntentHash = HashValue(struct {
		RequestID string `json:"request_id"`
		Open      bool   `json:"open"`
		Data      int    `json:"data"`
		Close     int    `json:"close"`
		Reset     int    `json:"reset"`
		Error     int    `json:"error"`
		Pressure  int    `json:"pressure"`
	}{request.RequestID, result.StreamOpened, result.DataIntentCount, result.CloseIntentCount, result.ResetIntentCount, result.ErrorIntentCount, result.BackpressureCount})
	return result, nil
}
