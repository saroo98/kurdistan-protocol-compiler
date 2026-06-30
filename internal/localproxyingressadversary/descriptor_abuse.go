// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

import (
	"fmt"
	"strings"

	"kurdistan/internal/proxyingress"
)

type DescriptorAbuseCase struct {
	Name           string `json:"name"`
	InputClass     string `json:"input_class"`
	ExpectedReject bool   `json:"expected_reject"`
	RejectBucket   string `json:"reject_bucket"`
	PanicAllowed   bool   `json:"panic_allowed"`
}

type DescriptorAbuseReport struct {
	Version           string                `json:"version"`
	CaseCount         int                   `json:"case_count"`
	Cases             []DescriptorAbuseCase `json:"cases"`
	Rejected          int                   `json:"rejected"`
	UnexpectedAccepts []string              `json:"unexpected_accepts,omitempty"`
	ErrorEchoLeaks    []string              `json:"error_echo_leaks,omitempty"`
	ReportHash        string                `json:"report_hash"`
	PayloadLogged     bool                  `json:"payload_logged"`
	SecretLogged      bool                  `json:"secret_logged"`
	Conclusion        string                `json:"conclusion"`
}

var descriptorAbuseClasses = []string{
	"ipv4_literal",
	"ipv6_literal",
	"domain_name",
	"subdomain_name",
	"url_http",
	"url_https",
	"url_with_port",
	"email_like",
	"sni_key",
	"host_header_key",
	"dns_query_key",
	"resolver_key",
	"cloud_provider_key",
	"region_key",
	"instance_id_key",
	"credential_key",
	"base64_like_payload",
	"hex_blob_like_payload",
	"oversized_descriptor",
	"unicode_confusable_descriptor",
	"control_character_descriptor",
	"path_like_descriptor",
}

func DescriptorAbuseCases() []DescriptorAbuseCase {
	out := make([]DescriptorAbuseCase, 0, len(descriptorAbuseClasses))
	for _, class := range descriptorAbuseClasses {
		out = append(out, DescriptorAbuseCase{Name: class, InputClass: class, ExpectedReject: true, RejectBucket: "unsafe_descriptor", PanicAllowed: false})
	}
	return out
}

func RunDescriptorAbuseHardening() DescriptorAbuseReport {
	cases := DescriptorAbuseCases()
	report := DescriptorAbuseReport{Version: Version, CaseCount: len(cases), Cases: cases, Conclusion: "passed"}
	contract := proxyingress.DefaultContract()
	for _, tc := range cases {
		target := descriptorForClass(tc.InputClass)
		err := proxyingress.ValidateTargetDescriptor(target, contract.Limits)
		if tc.ExpectedReject && err == nil {
			report.UnexpectedAccepts = append(report.UnexpectedAccepts, tc.Name)
			continue
		}
		if tc.ExpectedReject {
			report.Rejected++
		}
		if err != nil && leaksUnsafeValue(err.Error(), target) {
			report.ErrorEchoLeaks = append(report.ErrorEchoLeaks, tc.Name)
		}
	}
	if len(report.UnexpectedAccepts) > 0 || len(report.ErrorEchoLeaks) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	report.ReportHash = HashValue(descriptorReportHashInput(report))
	return report
}

func ValidateDescriptorAbuseReport(report DescriptorAbuseReport) error {
	if report.Version != Version || report.CaseCount != len(report.Cases) || len(report.Cases) == 0 || report.Conclusion != "passed" {
		return ErrInvalidReport
	}
	if report.Rejected != report.CaseCount || len(report.UnexpectedAccepts) != 0 || len(report.ErrorEchoLeaks) != 0 || report.PayloadLogged || report.SecretLogged {
		return ErrInvalidReport
	}
	if report.ReportHash != "" && report.ReportHash != HashValue(descriptorReportHashInput(report)) {
		return ErrInvalidReport
	}
	return scanSafeFixture(report)
}

func descriptorForClass(class string) proxyingress.TargetDescriptor {
	target := proxyingress.ValidTargetDescriptors()[0]
	target.DescriptorID = "unsafe_marker_" + class
	switch class {
	case "ipv4_literal":
		target.DescriptorID = strings.Join([]string{"127", "0", "0", "1"}, ".")
	case "ipv6_literal":
		target.DescriptorID = "2001" + ":" + "db8" + "::1"
	case "domain_name":
		target.DescriptorID = "alpha" + "." + "invalid"
	case "subdomain_name":
		target.DescriptorID = "node" + "." + "alpha" + "." + "invalid"
	case "url_http":
		target.DescriptorID = "http" + "://" + "alpha"
	case "url_https":
		target.DescriptorID = "https" + "://" + "alpha"
	case "url_with_port":
		target.DescriptorID = "http" + "://" + "alpha" + ":443"
	case "email_like":
		target.DescriptorID = "user" + "@" + "alpha" + "." + "invalid"
	case "sni_key":
		target.MetadataClass = "sni_marker"
	case "host_header_key":
		target.MetadataClass = "host_header_marker"
	case "dns_query_key":
		target.MetadataClass = "dns_query_marker"
	case "resolver_key":
		target.MetadataClass = "resolver_marker"
	case "cloud_provider_key":
		target.MetadataClass = "cloud_provider_marker"
	case "region_key":
		target.MetadataClass = "region_marker"
	case "instance_id_key":
		target.MetadataClass = "instance_id_marker"
	case "credential_key":
		target.MetadataClass = "credential_marker"
	case "base64_like_payload":
		target.DescriptorID = "payload_base64_" + strings.Repeat("A", 44)
	case "hex_blob_like_payload":
		target.DescriptorID = "payload_hex_" + strings.Repeat("a", 64)
	case "oversized_descriptor":
		target.DescriptorID = "oversized_" + strings.Repeat("x", 300)
	case "unicode_confusable_descriptor":
		target.DescriptorID = "synthetic_\u0430lpha"
	case "control_character_descriptor":
		target.DescriptorID = "synthetic\nalpha"
	case "path_like_descriptor":
		target.DescriptorID = "synthetic" + "/" + "path"
	}
	return target
}

func leaksUnsafeValue(message string, target proxyingress.TargetDescriptor) bool {
	for _, value := range []string{target.DescriptorID, target.MetadataClass, target.ServiceClass, target.AddressClass} {
		if value != "" && strings.Contains(message, value) {
			return true
		}
	}
	return false
}

func descriptorReportHashInput(report DescriptorAbuseReport) DescriptorAbuseReport {
	report.ReportHash = ""
	return report
}

func descriptorAbuseCaseByName(name string) (DescriptorAbuseCase, error) {
	for _, tc := range DescriptorAbuseCases() {
		if tc.Name == name {
			return tc, nil
		}
	}
	return DescriptorAbuseCase{}, fmt.Errorf("%w: unknown descriptor abuse class", ErrInvalidDescriptor)
}
