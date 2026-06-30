// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingress

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	domainLike = regexp.MustCompile(`(?i)^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)+$`)
	emailLike  = regexp.MustCompile(`(?i)^[^@]+@[^@]+\.[^@]+$`)
)

var forbiddenKeys = []string{
	"raw_payload", "payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "ciphertext", "plaintext",
	"pcap", "packet_dump", "capture_bytes", "destination_address", "endpoint", "real_host", "proxy_ip",
	"server_ip", "domain", "sni", "host_header", "url", "uri", "ip_address", "cloud_provider", "aws",
	"gcp", "azure", "region", "instance_id", "credential", "secret", "derived_key", "client_write_key",
	"server_write_key", "nonce", "nonce_base", "auth_tag", "proof_material", "private_key", "session_secret",
	"dns_query", "resolver",
}

func ValidateContract(contract ProxyIngressContract) error {
	if contract.Version != string(Version) || contract.ContractID == "" {
		return ErrInvalidContract
	}
	if !limitsBounded(contract.Limits) {
		return fmt.Errorf("%w: unbounded limits", ErrInvalidContract)
	}
	if len(contract.SupportedKinds) == 0 || len(contract.SupportedTargetKinds) == 0 || len(contract.RequiredCapabilities) == 0 {
		return fmt.Errorf("%w: missing required contract fields", ErrInvalidContract)
	}
	for _, kind := range contract.SupportedKinds {
		if !supportedIngressKind(kind) {
			return fmt.Errorf("%w: unsupported ingress kind", ErrInvalidContract)
		}
	}
	for _, kind := range contract.SupportedTargetKinds {
		if !supportedTargetKind(kind) {
			return fmt.Errorf("%w: unsupported target kind", ErrInvalidContract)
		}
	}
	if contract.PayloadLogged || contract.SecretLogged {
		return ErrUnsafeMetadata
	}
	if err := ScanForLeak(contract); err != nil {
		return err
	}
	expected := ContractHash(contract)
	if contract.ContractHash != "" && contract.ContractHash != expected {
		return fmt.Errorf("%w: contract hash mismatch", ErrInvalidContract)
	}
	return nil
}

func ValidateTargetDescriptor(target TargetDescriptor, limits ProxyIngressLimits) error {
	if !supportedTargetKind(target.TargetKind) {
		return fmt.Errorf("%w: unsupported target kind", ErrInvalidTarget)
	}
	if target.DescriptorID == "" || target.ServiceClass == "" || target.AddressClass == "" {
		return fmt.Errorf("%w: missing target fields", ErrInvalidTarget)
	}
	if target.PayloadLogged || target.SecretLogged {
		return ErrUnsafeMetadata
	}
	if len(target.DescriptorID)+len(target.ServiceClass)+len(target.PortClass)+len(target.NameClass)+len(target.AddressClass)+len(target.MetadataClass)+len(target.OpaqueHash) > limits.MaxTargetDescriptorBytes {
		return fmt.Errorf("%w: descriptor too large", ErrInvalidTarget)
	}
	for _, value := range []string{target.DescriptorID, target.ServiceClass, target.PortClass, target.NameClass, target.AddressClass, target.MetadataClass, target.OpaqueHash} {
		if unsafeValue(value) {
			return fmt.Errorf("%w: unsafe target value", ErrInvalidTarget)
		}
	}
	if err := ScanForLeak(target); err != nil {
		return err
	}
	return nil
}

func ValidateRequest(request SyntheticProxyRequest, contract ProxyIngressContract) error {
	if request.RequestID == "" || request.ClientFlowID == "" || request.RequestState == "" {
		return fmt.Errorf("%w: missing request fields", ErrInvalidRequest)
	}
	if request.PayloadLogged || request.SecretLogged {
		return ErrUnsafeMetadata
	}
	if !containsIngress(contract.SupportedKinds, request.IngressKind) {
		return fmt.Errorf("%w: unsupported ingress kind", ErrInvalidRequest)
	}
	if request.RequestState != RequestCreated && request.RequestState != RequestValidated && request.RequestState != RequestMapped && request.RequestState != RequestAccepted {
		return fmt.Errorf("%w: bad request state", ErrInvalidRequest)
	}
	for _, value := range []string{request.RequestID, request.ClientFlowID, request.RequestedStreamClass, request.RequestedPolicyClass, request.ByteBudgetBucket, request.DeadlineBucket, request.BackpressureClass} {
		if value == "" || unsafeValue(value) {
			return fmt.Errorf("%w: unsafe request field", ErrInvalidRequest)
		}
	}
	if err := ValidateTargetDescriptor(request.Target, contract.Limits); err != nil {
		return err
	}
	if err := ScanForLeak(request); err != nil {
		return err
	}
	return nil
}

func ValidateRequests(requests []SyntheticProxyRequest, contract ProxyIngressContract) error {
	seen := map[string]bool{}
	for _, request := range requests {
		if seen[request.RequestID] {
			return fmt.Errorf("%w: duplicate request", ErrInvalidRequest)
		}
		seen[request.RequestID] = true
		if err := ValidateRequest(request, contract); err != nil {
			return err
		}
	}
	return nil
}

func ScanForLeak(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	return scan(decoded, "")
}

func scan(value any, key string) error {
	switch v := value.(type) {
	case map[string]any:
		for childKey, child := range v {
			lower := strings.ToLower(childKey)
			if forbiddenKey(lower) {
				return fmt.Errorf("%w: forbidden field", ErrUnsafeMetadata)
			}
			if (lower == "payload_logged" || lower == "secret_logged") && child == true {
				return ErrUnsafeMetadata
			}
			if err := scan(child, lower); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := scan(child, key); err != nil {
				return err
			}
		}
	case string:
		if unsafeValue(v) {
			return fmt.Errorf("%w: unsafe string value", ErrUnsafeMetadata)
		}
	}
	return nil
}

func unsafeValue(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	for _, r := range value {
		if r < 32 || r > 126 {
			return true
		}
	}
	if strings.Contains(lower, "://") || strings.HasPrefix(lower, "www.") || strings.Contains(lower, "/") || strings.Contains(lower, "\\") || strings.Contains(lower, "host_header") || strings.Contains(lower, "sni") || strings.Contains(lower, "credential") || strings.Contains(lower, "secret") || strings.Contains(lower, "payload") || strings.Contains(lower, "raw_bytes") || strings.Contains(lower, "cloud") || strings.Contains(lower, "resolver") || strings.Contains(lower, "dns") || strings.Contains(lower, "region") || strings.Contains(lower, "instance_id") || strings.Contains(lower, "aws") || strings.Contains(lower, "gcp") || strings.Contains(lower, "azure") {
		return true
	}
	if ip := net.ParseIP(lower); ip != nil {
		return true
	}
	if strings.Count(lower, ":") >= 2 {
		return true
	}
	if domainLike.MatchString(lower) || emailLike.MatchString(lower) {
		return true
	}
	return false
}

func forbiddenKey(key string) bool {
	switch key {
	case "payload_logged", "secret_logged", "payload_hygiene", "secret_hygiene":
		return false
	}
	for _, marker := range forbiddenKeys {
		if key == marker || strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func supportedIngressKind(kind IngressKind) bool {
	for _, allowed := range SupportedIngressKinds() {
		if kind == allowed {
			return true
		}
	}
	return false
}

func supportedTargetKind(kind TargetKind) bool {
	for _, allowed := range SupportedTargetKinds() {
		if kind == allowed {
			return true
		}
	}
	return false
}

func containsIngress(values []IngressKind, want IngressKind) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func longString(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat("x", n)
}
