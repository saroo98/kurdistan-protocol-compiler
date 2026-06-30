// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingress

type RuntimeStreamMappingPlan struct {
	RequestID              string `json:"request_id"`
	StreamClass            string `json:"stream_class"`
	OpenIntent             string `json:"open_intent"`
	TargetDescriptorIntent string `json:"target_descriptor_intent"`
	DataIntent             string `json:"data_intent"`
	CloseIntent            string `json:"close_intent"`
	ResetIntent            string `json:"reset_intent"`
	ErrorIntent            string `json:"error_intent"`
	BackpressureIntent     string `json:"backpressure_intent"`
	RequiresSecureContext  bool   `json:"requires_secure_context"`
	RequiresReplayWindow   bool   `json:"requires_replay_window"`
	RequiresTraceHygiene   bool   `json:"requires_trace_hygiene"`
	MappingHash            string `json:"mapping_hash"`
	PayloadLogged          bool   `json:"payload_logged"`
	SecretLogged           bool   `json:"secret_logged"`
}

func BuildRuntimeStreamMappingPlan(request SyntheticProxyRequest, contract ProxyIngressContract) (RuntimeStreamMappingPlan, error) {
	if err := ValidateContract(contract); err != nil {
		return RuntimeStreamMappingPlan{}, err
	}
	if err := ValidateRequest(request, contract); err != nil {
		return RuntimeStreamMappingPlan{}, err
	}
	if request.RequestState == RequestRejected || request.RequestState == RequestFailed || request.RequestState == RequestClosed {
		return RuntimeStreamMappingPlan{}, ErrInvalidMapping
	}
	plan := RuntimeStreamMappingPlan{
		RequestID:              request.RequestID,
		StreamClass:            request.RequestedStreamClass,
		OpenIntent:             "open_stream",
		TargetDescriptorIntent: "target_descriptor:" + string(request.Target.TargetKind),
		DataIntent:             "target_data:" + request.ByteBudgetBucket,
		CloseIntent:            "target_close",
		ResetIntent:            "target_reset",
		ErrorIntent:            "target_error",
		BackpressureIntent:     request.BackpressureClass,
		RequiresSecureContext:  true,
		RequiresReplayWindow:   true,
		RequiresTraceHygiene:   true,
	}
	plan.MappingHash = HashValue(struct {
		RequestID   string `json:"request_id"`
		StreamClass string `json:"stream_class"`
		TargetKind  string `json:"target_kind"`
		Bucket      string `json:"bucket"`
	}{request.RequestID, plan.StreamClass, string(request.Target.TargetKind), request.ByteBudgetBucket})
	return plan, nil
}

func BuildMappingPlans(requests []SyntheticProxyRequest, contract ProxyIngressContract) ([]RuntimeStreamMappingPlan, error) {
	plans := make([]RuntimeStreamMappingPlan, 0, len(requests))
	for _, request := range requests {
		plan, err := BuildRuntimeStreamMappingPlan(request, contract)
		if err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}
	return plans, nil
}
