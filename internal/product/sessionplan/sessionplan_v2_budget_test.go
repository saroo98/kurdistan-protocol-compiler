package sessionplan

import (
	"kurdistan/internal/product/envelope"
	"reflect"
	"testing"
	"time"
)

func TestAdmittedCalculationBoundsV2NamedStagesAndActualHolders(t *testing.T) {
	bound, ok := AdmittedCalculationBoundsV2(envelope.MaxPayloadBytes)
	if !ok || bound.DecoderBytes != 24215673 || bound.BuildBytes != bound.PolicyBytes+131080+bound.PlanBytes+bound.DecoderBytes+bound.SelectionBytes || bound.SuffixBytes != max(bound.DecoderBytes, bound.BuildBytes, bound.ReturnBytes) {
		t.Fatal("source stage drift", bound)
	}
	for _, request := range []RequestV2{fixtureRequestV2(t), fixtureRequestV3(t)} {
		plan, err := BuildV2At(request, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if actualOwnedCalculationV2(reflect.ValueOf(plan)) > bound.PlanBytes || actualOwnedCalculationV2(reflect.ValueOf(request.RuntimePolicy)) > bound.PolicyBytes {
			t.Fatal("actual holder exceeds bound")
		}
		plan.Destroy()
	}
	if _, ok := AdmittedCalculationBoundsV2(envelope.MaxPayloadBytes + 1); ok {
		t.Fatal("unbounded profile")
	}
	t.Logf("named calculation bounds: %+v", bound)
}
func actualOwnedCalculationV2(v reflect.Value) uint64 {
	var n uint64
	switch v.Kind() {
	case reflect.String:
		n = uint64(v.Len())
	case reflect.Pointer:
		if !v.IsNil() {
			n = uint64(v.Type().Elem().Size()) + actualOwnedCalculationV2(v.Elem())
		}
	case reflect.Slice:
		n = uint64(v.Cap()) * uint64(v.Type().Elem().Size())
		for i := 0; i < v.Len(); i++ {
			n += actualOwnedCalculationV2(v.Index(i))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			n += actualOwnedCalculationV2(v.Field(i))
		}
	}
	return n
}
