// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package measurementreview

type MeasurementSummary struct {
	FieldCount     int    `json:"field_count"`
	ConsentMode    string `json:"consent_mode"`
	RetentionClass string `json:"retention_class"`
	PayloadLogged  bool   `json:"payload_logged"`
	SecretLogged   bool   `json:"secret_logged"`
	Conclusion     string `json:"conclusion"`
}

func Summary(review MeasurementReview) MeasurementSummary {
	return MeasurementSummary{
		FieldCount:     len(review.Fields),
		ConsentMode:    review.Policy.ConsentMode,
		RetentionClass: review.Policy.RetentionClass,
		PayloadLogged:  review.PayloadLogged,
		SecretLogged:   review.SecretLogged,
		Conclusion:     review.Conclusion,
	}
}
