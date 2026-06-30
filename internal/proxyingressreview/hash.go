// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingressreview

import "kurdistan/internal/proxyingress"

func HashValue(value any) string {
	return proxyingress.HashValue(value)
}

func reviewHashInput(review ProxyIngressDesignReview) ProxyIngressDesignReview {
	review.ReviewHash = ""
	return review
}

func GenerateGoldenReview() (ProxyIngressDesignReview, ProxyIngressMisuseReport, ProxyIngressParityReport, error) {
	set, err := proxyingress.GoldenFixtureSet()
	if err != nil {
		return ProxyIngressDesignReview{}, ProxyIngressMisuseReport{}, ProxyIngressParityReport{}, err
	}
	review, err := RunReview(set.Contract, set.Requests, set.Mappings, set.Lifecycle, DefaultFailureModes())
	if err != nil {
		return ProxyIngressDesignReview{}, ProxyIngressMisuseReport{}, ProxyIngressParityReport{}, err
	}
	misuse := ScanMisuse(set.Contract, set.Requests, set.Mappings, set.Lifecycle, review)
	parity := CompareParity(review, review, set.Contract, set.Contract)
	return review, misuse, parity, nil
}
