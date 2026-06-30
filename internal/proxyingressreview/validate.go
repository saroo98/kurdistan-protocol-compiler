// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingressreview

import "fmt"

func ValidateReview(review ProxyIngressDesignReview) error {
	if review.Version != Version || review.ReviewID == "" || review.ContractID == "" {
		return ErrInvalidReview
	}
	if review.PayloadLogged || review.SecretLogged {
		return fmt.Errorf("%w: hygiene flags", ErrInvalidReview)
	}
	if err := ValidateFailureModeMatrix(review.FailureModes); err != nil {
		return err
	}
	for _, item := range review.ChecklistItems {
		if item.ID == "" || item.Category == "" || item.Status == "" {
			return fmt.Errorf("%w: invalid checklist item", ErrInvalidReview)
		}
		if item.Blocking && item.Status != "passed" && review.GoNoGoDecision == DecisionGo {
			return fmt.Errorf("%w: blocking item passed go decision", ErrInvalidReview)
		}
	}
	if review.GoNoGoDecision == DecisionGo && len(review.BlockingIssues) > 0 {
		return fmt.Errorf("%w: go despite blocker", ErrInvalidReview)
	}
	expected := HashValue(reviewHashInput(review))
	if review.ReviewHash != "" && review.ReviewHash != expected {
		return fmt.Errorf("%w: hash mismatch", ErrInvalidReview)
	}
	return nil
}
