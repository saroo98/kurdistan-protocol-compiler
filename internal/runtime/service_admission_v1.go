// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"net/netip"
	"reflect"
	"slices"
	"time"
	"unsafe"

	"kurdistan/internal/product/runtimepolicy"
)

// Error returns a closed, payload-free category. Success is represented by nil
// at API boundaries, never by returning ServiceSuccessV1 as an error.
func (r ServiceResultV1) Error() string {
	switch r {
	case ServiceSuccessV1:
		return "service_success"
	case ServiceNotAdmittedV1:
		return "service_not_admitted"
	case ServiceInvalidRequestV1:
		return "service_invalid_request"
	case ServiceDestinationDeniedV1:
		return "service_destination_denied"
	case ServiceResourceLimitV1:
		return "service_resource_limit"
	case ServiceTimeoutV1:
		return "service_timeout"
	case ServiceUnreachableV1:
		return "service_unreachable"
	case ServiceCancelledV1:
		return "service_cancelled"
	case ServiceAuthorityExpiredV1:
		return "service_authority_expired"
	case ServiceAuthorityRevokedV1:
		return "service_authority_revoked"
	default:
		return "service_internal_failure"
	}
}

type ProxyRequestV1 struct {
	Kind    uint8
	Address []byte
	Port    uint16
}
type ProbeModeV1 uint8

const (
	ProbeDisconnectedDefaultV1 ProbeModeV1 = iota + 1
	ProbeActiveRelayV1
)

type ProbeRequestV1 struct {
	TargetID                                 uint16
	Method                                   uint8
	AttemptTimeoutMillis, TotalTimeoutMillis uint16
	Samples                                  uint8
}

// ServiceAdmissionV1 is an immutable policy snapshot, not proof of profile
// signature/lifetime or current VPN mode. The native owner supplies verified
// policy and revalidates current authority and mode before each operation.
type ServiceAdmissionV1 struct{ policy runtimepolicy.PolicyV2 }
type ProbeAdmissionV1 struct {
	target    runtimepolicy.ProbeTargetV1
	request   ProbeRequestV1
	mode      ProbeModeV1
	interval  time.Duration
	perMinute uint8
}

// Validation precedes Clone so malformed unbounded authority is never copied.
// Callers must not mutate policy concurrently with construction.
func NewServiceAdmissionV1(policy runtimepolicy.PolicyV2, now time.Time) (*ServiceAdmissionV1, error) {
	if runtimepolicy.ValidateV3At(policy, now) != nil {
		return nil, ServiceNotAdmittedV1
	}
	a := &ServiceAdmissionV1{policy: policy.Clone()}
	if a.retainedBytesV1() > serviceAdmissionMaximumBytesV1() {
		a.Destroy()
		return nil, ServiceResourceLimitV1
	}
	return a, nil
}

// Destroy retires the exclusively owned snapshot after all admission users join.
func (a *ServiceAdmissionV1) Destroy() {
	if a != nil {
		a.policy.Destroy()
	}
}

func (a *ServiceAdmissionV1) retainedBytesV1() uint64 {
	if a == nil {
		return 0
	}
	return uint64(unsafe.Sizeof(*a)) + productionBackingBytesV1(reflect.ValueOf(a.policy))
}

// Source-shaped admitted clone bound. PolicyV2 is embedded in the admission;
// immutable text stays charged even though Clone shares its backing.
func serviceAdmissionMaximumBytesV1() uint64 {
	c := func(n uint64) uint64 {
		if n == 0 {
			return 0
		}
		return 2*n + 8
	}
	e, p, t := uint64(unsafe.Sizeof(runtimepolicy.EndpointV2{})), uint64(unsafe.Sizeof(runtimepolicy.PrefixV2{})), uint64(unsafe.Sizeof(runtimepolicy.ProbeTargetV1{}))
	s, i, l, v := uint64(unsafe.Sizeof([]byte{})), uint64(unsafe.Sizeof(runtimepolicy.IPModeV2(""))), uint64(unsafe.Sizeof(runtimepolicy.PayloadProtocolV2(""))), uint64(unsafe.Sizeof(runtimepolicy.PortRangeV1{}))
	return uint64(unsafe.Sizeof(ServiceAdmissionV1{})) + c(49152) + c(4096) + c(4*e) + 4*c(16) + 2*c(4) + 2*c(16) + c(2*p) + 2*c(16) + c(2*s) + 2*c(16) + c(3*i) + c(4*l) + c(4) +
		uint64(unsafe.Sizeof(runtimepolicy.ServicesV1{})) + uint64(unsafe.Sizeof(runtimepolicy.ProxyV1{})) + uint64(unsafe.Sizeof(runtimepolicy.ProbesV1{})) + uint64(unsafe.Sizeof(runtimepolicy.UpdateV1{})) +
		c(3) + c(64*p) + 64*c(16) + c(16*v) + c(16*t) + 16*(c(16)+c(1)+c(2)) + 65536
}

// AdmitProxy returns independent address storage, preserving domain bytes. It
// performs no client DNS. Numeric destinations receive the same safety filter.
func (a *ServiceAdmissionV1) AdmitProxy(r ProxyRequestV1) (ProxyRequestV1, error) {
	if !validServiceAddressV1(r.Kind, r.Address, r.Port) {
		return ProxyRequestV1{}, ServiceInvalidRequestV1
	}
	if a == nil || a.policy.Services == nil || a.policy.Services.Proxy == nil {
		return ProxyRequestV1{}, ServiceNotAdmittedV1
	}
	p := a.policy.Services.Proxy
	if !slices.Contains(p.AddressKinds, r.Kind) {
		return ProxyRequestV1{}, ServiceNotAdmittedV1
	}
	allowedPort := false
	for _, ports := range p.DestinationPorts {
		if r.Port >= ports.First && r.Port <= ports.Last {
			allowedPort = true
			break
		}
	}
	if !allowedPort {
		return ProxyRequestV1{}, ServiceDestinationDeniedV1
	}
	if r.Kind != 2 {
		ip, _ := netip.AddrFromSlice(r.Address)
		if !a.proxyAddress(ip) {
			return ProxyRequestV1{}, ServiceDestinationDeniedV1
		}
	}
	return ProxyRequestV1{Kind: r.Kind, Address: bytes.Clone(r.Address), Port: r.Port}, nil
}
func (a *ServiceAdmissionV1) proxyAddress(ip netip.Addr) bool {
	if !runtimepolicy.IsPublicServiceAddress(ip) || ip.Is4() && len(a.policy.ClientIPv4) == 0 || ip.Is6() && len(a.policy.ClientIPv6) == 0 {
		return false
	}
	for _, cidr := range a.policy.Services.Proxy.DestinationCIDRs {
		address, _ := netip.AddrFromSlice(cidr.Address)
		if netip.PrefixFrom(address, int(cidr.PrefixLen)).Contains(ip) {
			return true
		}
	}
	return false
}

// ProxyCandidates accepts one resolver answer only for domain requests. Numeric
// requests require an empty answer and cannot be redirected. At most 16 distinct
// answers, including denied addresses, are accepted; only two sorted safe
// numeric values are returned. It never resolves, dials or retains input.
func (a *ServiceAdmissionV1) ProxyCandidates(r ProxyRequestV1, answers []netip.Addr) ([]netip.Addr, error) {
	admitted, err := a.AdmitProxy(r)
	if err != nil {
		return nil, err
	}
	if admitted.Kind != 2 {
		if len(answers) != 0 {
			return nil, ServiceInvalidRequestV1
		}
		ip, _ := netip.AddrFromSlice(admitted.Address)
		return []netip.Addr{ip}, nil
	}
	var distinct [16]netip.Addr
	count := 0
	for _, ip := range answers {
		if slices.Contains(distinct[:count], ip) {
			continue
		}
		if count == len(distinct) {
			return nil, ServiceDestinationDeniedV1
		}
		distinct[count] = ip
		count++
	}
	safe := distinct[:0]
	for _, ip := range distinct[:count] {
		if a.proxyAddress(ip) {
			safe = append(safe, ip)
		}
	}
	if len(safe) == 0 {
		return nil, ServiceDestinationDeniedV1
	}
	slices.SortFunc(safe, func(x, y netip.Addr) int { return x.Compare(y) })
	return slices.Clone(safe[:min(2, len(safe))]), nil
}

// concurrency is a native/local narrowing value, not authority to create more
// concurrent operations. The later owner atomically reserves actual capacity.
func (a *ServiceAdmissionV1) AdmitProbe(r ProbeRequestV1, mode ProbeModeV1, concurrency uint8) (ProbeAdmissionV1, error) {
	var p *runtimepolicy.ProbesV1
	if a != nil && a.policy.Services != nil {
		p = a.policy.Services.Probes
	}
	return admitProbePolicyV1(p, r, mode, concurrency, false)
}

// AdmitProbePolicyV1 is only a native verified-policy insertion seam. It does
// not authenticate signatures, current lifetime, IP-family authority or mode.
// The caller retains immutable policy ownership through this synchronous call.
func AdmitProbePolicyV1(p *runtimepolicy.ProbesV1, r ProbeRequestV1, mode ProbeModeV1, concurrency uint8) (ProbeAdmissionV1, error) {
	return admitProbePolicyV1(p, r, mode, concurrency, true)
}

func admitProbePolicyV1(p *runtimepolicy.ProbesV1, r ProbeRequestV1, mode ProbeModeV1, concurrency uint8, bounded bool) (ProbeAdmissionV1, error) {
	if r.TargetID == 0 || r.Samples < 1 || r.Samples > 10 || r.AttemptTimeoutMillis < 1000 || r.AttemptTimeoutMillis > 30000 || r.TotalTimeoutMillis < 1000 || r.TotalTimeoutMillis > 30000 || concurrency < 1 || concurrency > 4 {
		return ProbeAdmissionV1{}, ServiceInvalidRequestV1
	}
	if r.Method != 1 || (mode != ProbeDisconnectedDefaultV1 && mode != ProbeActiveRelayV1) || p == nil {
		return ProbeAdmissionV1{}, ServiceNotAdmittedV1
	}
	if bounded && !boundedProbePolicyV1(p) {
		return ProbeAdmissionV1{}, ServiceNotAdmittedV1
	}
	if concurrency > p.MaxConcurrentOperations || r.Samples > p.MaxSamplesPerOperation || uint32(r.TotalTimeoutMillis) > p.MaxOperationMillis {
		return ProbeAdmissionV1{}, ServiceInvalidRequestV1
	}
	for _, target := range p.Targets {
		if target.ID != r.TargetID {
			continue
		}
		if !slices.Contains(target.Methods, r.Method) || !slices.Contains(target.Modes, uint8(mode)) {
			return ProbeAdmissionV1{}, ServiceNotAdmittedV1
		}
		if uint32(r.AttemptTimeoutMillis) > target.TimeoutMillis {
			return ProbeAdmissionV1{}, ServiceInvalidRequestV1
		}
		admitted := ProbeAdmissionV1{target: target, request: r, mode: mode, interval: time.Duration(p.MinAttemptIntervalMillis) * time.Millisecond, perMinute: p.MaxAttemptsPerMinute}
		admitted.target = admitted.Target()
		return admitted, nil
	}
	return ProbeAdmissionV1{}, ServiceNotAdmittedV1
}

// These constructor guards bound every field before selected-target cloning;
// the shared body above alone selects method, target and request narrowing.
func boundedProbePolicyV1(p *runtimepolicy.ProbesV1) bool {
	if len(p.Targets) < 1 || len(p.Targets) > 16 || p.MaxConcurrentOperations < 1 || p.MaxConcurrentOperations > 4 || p.MaxSamplesPerOperation < 1 || p.MaxSamplesPerOperation > 10 || p.MinAttemptIntervalMillis < 1000 || p.MinAttemptIntervalMillis > 3600000 || p.MaxAttemptsPerMinute < 1 || p.MaxAttemptsPerMinute > 60 || p.MaxOperationMillis < 1000 || p.MaxOperationMillis > 30000 {
		return false
	}
	for i, t := range p.Targets {
		if t.ID == 0 || i > 0 && p.Targets[i-1].ID >= t.ID || (len(t.Address) != 4 && len(t.Address) != 16) || t.Port == 0 || len(t.Methods) != 1 || t.Methods[0] != 1 || len(t.Modes) < 1 || len(t.Modes) > 2 || t.TimeoutMillis < 1000 || t.TimeoutMillis > 30000 || t.TimeoutMillis > p.MaxOperationMillis {
			return false
		}
		for j, m := range t.Modes {
			if m < 1 || m > 2 || j > 0 && t.Modes[j-1] >= m {
				return false
			}
		}
		address, ok := netip.AddrFromSlice(t.Address)
		if !ok || !runtimepolicy.IsPublicServiceAddress(address) {
			return false
		}
	}
	return true
}

// Destroy clears this admission's owned target slices. Value copies are
// borrowed aliases, not independently destroyable owners.
func (a *ProbeAdmissionV1) Destroy() {
	if a == nil {
		return
	}
	clear(a.target.Address)
	clear(a.target.Methods)
	clear(a.target.Modes)
	*a = ProbeAdmissionV1{}
}

// Target returns a defensive copy of exact signed destination authority. It is
// never reconstructed from request bytes or a relay endpoint.
func (a ProbeAdmissionV1) Target() runtimepolicy.ProbeTargetV1 {
	target := a.target
	target.Address = bytes.Clone(target.Address)
	target.Methods = slices.Clone(target.Methods)
	target.Modes = slices.Clone(target.Modes)
	return target
}
