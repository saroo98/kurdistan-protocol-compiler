// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimepolicy

import (
	"bytes"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"kurdistan/internal/product/envelope"
)

const MaxServicesEncodedBytes = 8192

// ServicesV1 is signed authority, not a request or an implicit default.
// Nil optional maps encode as empty arrays. At least one must be present.
type ServicesV1 struct {
	Version uint64
	Proxy   *ProxyV1
	Probes  *ProbesV1
	Update  *UpdateV1
}

type ProxyV1 struct {
	AddressKinds               []uint8 // 1 IPv4, 2 canonical domain, 3 IPv6.
	DestinationCIDRs           []PrefixV2
	DestinationPorts           []PortRangeV1
	MaxConcurrentStreams       uint8
	MaxBufferBytes             uint32
	ConnectTimeoutMillis       uint32
	IdleTimeoutSeconds         uint32
	MaxQueuedBytesPerDirection uint32
}

type PortRangeV1 struct{ First, Last uint16 }

type ProbesV1 struct {
	Targets                  []ProbeTargetV1
	MaxConcurrentOperations  uint8
	MaxSamplesPerOperation   uint8
	MinAttemptIntervalMillis uint32
	MaxAttemptsPerMinute     uint8
	MaxOperationMillis       uint32
}

type ProbeTargetV1 struct {
	ID            uint16
	Address       []byte
	Port          uint16
	Methods       []uint8 // Exactly [1]: TCP_CONNECT.
	Modes         []uint8 // 1 DISCONNECTED_DEFAULT, 2 ACTIVE_RELAY.
	TimeoutMillis uint32
}

type UpdateV1 struct {
	URL                     string
	ProfileID               string
	MaxArtifactBytes        uint32
	TimeoutMillis           uint32
	MinCheckIntervalSeconds uint32
}

func (s *ServicesV1) clone() *ServicesV1 {
	if s == nil {
		return nil
	}
	out := *s
	if s.Proxy != nil {
		p := *s.Proxy
		p.AddressKinds = append([]uint8(nil), p.AddressKinds...)
		p.DestinationCIDRs = append([]PrefixV2(nil), p.DestinationCIDRs...)
		for i := range p.DestinationCIDRs {
			p.DestinationCIDRs[i].Address = bytes.Clone(p.DestinationCIDRs[i].Address)
		}
		p.DestinationPorts = append([]PortRangeV1(nil), p.DestinationPorts...)
		out.Proxy = &p
	}
	if s.Probes != nil {
		p := *s.Probes
		p.Targets = append([]ProbeTargetV1(nil), p.Targets...)
		for i := range p.Targets {
			p.Targets[i].Address = bytes.Clone(p.Targets[i].Address)
			p.Targets[i].Methods = append([]uint8(nil), p.Targets[i].Methods...)
			p.Targets[i].Modes = append([]uint8(nil), p.Targets[i].Modes...)
		}
		out.Probes = &p
	}
	if s.Update != nil {
		u := *s.Update
		out.Update = &u
	}
	return &out
}

var deniedServicePrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
}
var publicServiceIPv6 = netip.MustParsePrefix("2000::/3")

// IsPublicServiceAddress implements the conservative native V1 destination
// class. It does not grant signed CIDR, target, URL or IP-family authority.
func IsPublicServiceAddress(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() {
		return false
	}
	if a.Is6() && !publicServiceIPv6.Contains(a) {
		return false
	}
	for _, p := range deniedServicePrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// IsCanonicalProxyDomain is a pure byte-grammar check, not DNS resolution.
// ASCII punycode labels are admitted without Unicode normalization.
func IsCanonicalProxyDomain(value string) bool {
	if len(value) < 1 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func validUpdateURL(value string) bool {
	if len(value) < 1 || len(value) > 2048 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] <= 32 || value[i] >= 127 {
			return false
		}
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" || strings.ContainsAny(value, "?#%\\") || u.RawQuery != "" || u.ForceQuery || u.Path == "" || u.Path[0] != '/' || u.RawPath != "" {
		return false
	}
	host := u.Hostname()
	canonicalHost := host
	if ip, err := netip.ParseAddr(host); err == nil {
		if !IsPublicServiceAddress(ip) || ip.String() != host {
			return false
		}
		if ip.Is6() {
			canonicalHost = "[" + host + "]"
		}
	} else if !IsCanonicalProxyDomain(host) {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 || n == 443 || strconv.FormatUint(n, 10) != port {
			return false
		}
		canonicalHost += ":" + port
	}
	if u.Host != canonicalHost {
		return false
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	if strings.Contains(u.Path, "//") {
		return false
	}
	for i := 0; i < len(u.Path); i++ {
		c := u.Path[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~/", rune(c))) {
			return false
		}
	}
	return u.String() == value
}

func validateServices(s *ServicesV1, ipv4, ipv6 bool) error {
	if s == nil || s.Version != 1 || s.Proxy == nil && s.Probes == nil && s.Update == nil {
		return fail(ErrorInvalid)
	}
	if s.Proxy != nil {
		if err := validateProxy(s.Proxy, ipv4, ipv6); err != nil {
			return err
		}
	}
	if s.Probes != nil {
		if err := validateProbes(s.Probes, ipv4, ipv6); err != nil {
			return err
		}
	}
	if u := s.Update; u != nil {
		if !validUpdateURL(u.URL) || len(u.ProfileID) == 0 || len(u.ProfileID) > envelope.MaxCanonicalIDBytes || u.MaxArtifactBytes < 1 || u.MaxArtifactBytes > envelope.MaxTotalInputBytes || u.TimeoutMillis < 1000 || u.TimeoutMillis > 30000 || u.MinCheckIntervalSeconds < 60 || u.MinCheckIntervalSeconds > 604800 {
			return fail(ErrorInvalid)
		}
		// Match the enclosing canonical ID grammar without accepting a locator as ID.
		for _, c := range u.ProfileID {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':') {
				return fail(ErrorInvalid)
			}
		}
	}
	encoded, err := marshal(servicesMap(s))
	if err != nil || len(encoded) > MaxServicesEncodedBytes {
		return fail(ErrorSize)
	}
	return nil
}

func sortedServiceValues(values []uint8, max uint8) bool {
	if len(values) == 0 || len(values) > int(max) {
		return false
	}
	for i, v := range values {
		if v < 1 || v > max || i > 0 && values[i-1] >= v {
			return false
		}
	}
	return true
}

func validateProxy(p *ProxyV1, ipv4, ipv6 bool) error {
	if !sortedServiceValues(p.AddressKinds, 3) || len(p.DestinationCIDRs) < 1 || len(p.DestinationCIDRs) > 64 || len(p.DestinationPorts) < 1 || len(p.DestinationPorts) > 16 || p.MaxConcurrentStreams < 1 || p.MaxConcurrentStreams > 64 || p.MaxBufferBytes < 16777216 || p.MaxBufferBytes > 134217728 || p.ConnectTimeoutMillis < 1000 || p.ConnectTimeoutMillis > 30000 || p.IdleTimeoutSeconds < 30 || p.IdleTimeoutSeconds > 3600 || p.MaxQueuedBytesPerDirection < 1024 || p.MaxQueuedBytesPerDirection > 65536 {
		return fail(ErrorInvalid)
	}
	for _, kind := range p.AddressKinds {
		if kind == 1 && !ipv4 || kind == 3 && !ipv6 || kind == 2 && !ipv4 && !ipv6 {
			return fail(ErrorInvalid)
		}
	}
	prefixes := make([]netip.Prefix, 0, len(p.DestinationCIDRs))
	for i, cidr := range p.DestinationCIDRs {
		a, ok := netip.AddrFromSlice(cidr.Address)
		if !ok || a.Is4In6() || a.Is4() && !ipv4 || a.Is6() && !ipv6 || int(cidr.PrefixLen) > a.BitLen() {
			return fail(ErrorInvalid)
		}
		prefix := netip.PrefixFrom(a, int(cidr.PrefixLen))
		if prefix.Masked() != prefix {
			return fail(ErrorInvalid)
		}
		if i > 0 {
			previous := p.DestinationCIDRs[i-1]
			order := bytes.Compare(previous.Address, cidr.Address)
			if len(previous.Address) > len(cidr.Address) || len(previous.Address) == len(cidr.Address) && (order > 0 || order == 0 && previous.PrefixLen >= cidr.PrefixLen) {
				return fail(ErrorInvalid)
			}
		}
		for _, previous := range prefixes {
			if previous.Overlaps(prefix) {
				return fail(ErrorInvalid)
			}
		}
		prefixes = append(prefixes, prefix)
	}
	for i, r := range p.DestinationPorts {
		if r.First == 0 || r.First > r.Last || i > 0 && uint32(p.DestinationPorts[i-1].Last)+1 >= uint32(r.First) {
			return fail(ErrorInvalid)
		}
	}
	return nil
}

func validateProbes(p *ProbesV1, ipv4, ipv6 bool) error {
	if len(p.Targets) < 1 || len(p.Targets) > 16 || p.MaxConcurrentOperations < 1 || p.MaxConcurrentOperations > 4 || p.MaxSamplesPerOperation < 1 || p.MaxSamplesPerOperation > 10 || p.MinAttemptIntervalMillis < 1000 || p.MinAttemptIntervalMillis > 3600000 || p.MaxAttemptsPerMinute < 1 || p.MaxAttemptsPerMinute > 60 || p.MaxOperationMillis < 1000 || p.MaxOperationMillis > 30000 {
		return fail(ErrorInvalid)
	}
	for i, t := range p.Targets {
		a, ok := netip.AddrFromSlice(t.Address)
		if t.ID == 0 || i > 0 && p.Targets[i-1].ID >= t.ID || !ok || !IsPublicServiceAddress(a) || a.Is4() && !ipv4 || a.Is6() && !ipv6 || t.Port == 0 || len(t.Methods) != 1 || t.Methods[0] != 1 || !sortedServiceValues(t.Modes, 2) || t.TimeoutMillis < 1000 || t.TimeoutMillis > 30000 || t.TimeoutMillis > p.MaxOperationMillis {
			return fail(ErrorInvalid)
		}
	}
	return nil
}
