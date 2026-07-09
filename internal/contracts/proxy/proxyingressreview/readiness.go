// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingressreview

func ReadyForPrototype(review ProxyIngressDesignReview) bool {
	return review.GoNoGoDecision == DecisionGo && len(review.BlockingIssues) == 0 && !review.PayloadLogged && !review.SecretLogged
}
