package ir_test

import (
	"encoding/json"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func FuzzValidateProfileJSON(f *testing.F) {
	p, err := compiler.Generate(701)
	if err != nil {
		f.Fatal(err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":"0.1.0-lab","id":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		var profile ir.Profile
		if err := json.Unmarshal(data, &profile); err != nil {
			return
		}
		_ = ir.Validate(&profile)
	})
}
