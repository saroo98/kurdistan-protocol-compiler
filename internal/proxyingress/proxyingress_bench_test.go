// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingress

import "testing"

func BenchmarkContractValidation(b *testing.B) {
	contract := DefaultContract()
	for i := 0; i < b.N; i++ {
		if err := ValidateContract(contract); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTargetDescriptorValidation(b *testing.B) {
	target := ValidTargetDescriptors()[0]
	limits := DefaultLimits()
	for i := 0; i < b.N; i++ {
		if err := ValidateTargetDescriptor(target, limits); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRuntimeMappingPlan(b *testing.B) {
	request := ValidRequests()[0]
	contract := DefaultContract()
	for i := 0; i < b.N; i++ {
		if _, err := BuildRuntimeStreamMappingPlan(request, contract); err != nil {
			b.Fatal(err)
		}
	}
}
