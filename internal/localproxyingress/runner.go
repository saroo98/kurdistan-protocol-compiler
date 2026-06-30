// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

import (
	"context"
	"fmt"

	"kurdistan/internal/proxyingress"
)

func RunScenario(ctx context.Context, scenario string, cfg LocalProxyIngressConfig) (LocalProxyIngressSummary, error) {
	_ = ctx
	if err := ValidateConfig(cfg); err != nil {
		return LocalProxyIngressSummary{}, err
	}
	contract := Contract()
	events, err := GenerateEvents(scenario)
	if err != nil {
		return LocalProxyIngressSummary{}, err
	}
	q := NewQueue(cfg.MaxQueuedEvents)
	for _, event := range events {
		if err := q.Enqueue(event); err != nil {
			continue
		}
	}
	grouped := GroupByRequest(q.Drain())
	summary := LocalProxyIngressSummary{Version: string(Version), Scenario: scenario, ContractID: cfg.ContractID, QueueStats: q.Stats}
	for _, requestID := range orderedRequestIDs(grouped) {
		result := runRequest(requestID, grouped[requestID], contract, cfg)
		summary.Results = append(summary.Results, result)
		summary.RequestCount++
		summary.EventsProcessed += result.EventsProcessed
		summary.BackpressureEvents += result.BackpressureEvents
		summary.ResetEvents += result.ResetEvents
		summary.TargetErrorEvents += result.ErrorEvents
		summary.PayloadLogged = summary.PayloadLogged || result.PayloadLogged
		summary.SecretLogged = summary.SecretLogged || result.SecretLogged
		if result.Accepted {
			summary.AcceptedRequests++
			summary.StreamMappings++
			summary.TargetBindings++
		}
		if result.Rejected {
			summary.RejectedRequests++
		}
		if result.Conclusion == "lifecycle_violation" {
			summary.LifecycleViolations++
		}
	}
	if q.Stats.OverflowRejected > 0 {
		summary.RejectedRequests += q.Stats.OverflowRejected
	}
	summary.SummaryHash = HashValue(summaryHashInput(summary))
	return summary, ValidateSummary(summary)
}

func runRequest(requestID string, events []SyntheticIngressEvent, contract proxyingress.ProxyIngressContract, cfg LocalProxyIngressConfig) LocalProxyIngressResult {
	result := LocalProxyIngressResult{RequestID: requestID, Conclusion: "passed"}
	if len(events) > cfg.MaxEventsPerRequest {
		result.Rejected = true
		result.FinalState = "rejected"
		result.Conclusion = "request_limit"
		return result
	}
	lifecycle := requestLifecycle{}
	for i, event := range events {
		result.EventsProcessed++
		result.PayloadLogged = result.PayloadLogged || event.PayloadLogged
		result.SecretLogged = result.SecretLogged || event.SecretLogged
		if err := ValidateEvent(event, contract); err != nil {
			result.Rejected = true
			result.FinalState = "rejected"
			result.Conclusion = "target_rejected"
			return result
		}
		if err := lifecycle.apply(event); err != nil {
			result.Rejected = true
			result.FinalState = lifecycle.finalState()
			result.Conclusion = "lifecycle_violation"
			return result
		}
		switch event.Kind {
		case RequestEventData:
			result.DataEvents++
		case RequestEventClose:
			result.CloseEvents++
		case RequestEventReset:
			result.ResetEvents++
		case RequestEventTargetErr:
			result.ErrorEvents++
		case RequestEventBackpress:
			result.BackpressureEvents++
		}
		if i == 0 && event.Kind == RequestEventOpen {
			result.TargetDescriptorClass = string(event.Target.TargetKind)
			result.StreamClass = event.FlowClass
		}
	}
	request := proxyingress.SyntheticProxyRequest{
		RequestID:            requestID,
		IngressKind:          proxyingress.IngressKindSyntheticConnect,
		Target:               events[0].Target,
		ClientFlowID:         "flow_" + requestID,
		RequestState:         proxyingress.RequestCreated,
		RequestedStreamClass: firstNonEmpty(result.StreamClass, "interactive"),
		RequestedPolicyClass: "policy_local_ingress",
		ByteBudgetBucket:     events[0].ByteCountBucket,
		DeadlineBucket:       "deadline_local",
		BackpressureClass:    "pressure_runtime",
	}
	bridge, err := BridgeEvents(request, events, contract)
	if err != nil {
		result.Rejected = true
		result.FinalState = "rejected"
		result.Conclusion = fmt.Sprintf("mapping_rejected")
		return result
	}
	result.RuntimeMappingHash = bridge.RuntimeMappingHash
	result.ProxySemIntentHash = bridge.ProxySemIntentHash
	result.Accepted = lifecycle.opened && !result.Rejected
	result.FinalState = lifecycle.finalState()
	return result
}

func firstNonEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
