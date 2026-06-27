package adversary

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/labtrace"
	ktrace "kurdistan/internal/trace"
)

func TestExtractFeaturesDeterministicAndPayloadFree(t *testing.T) {
	events := []ktrace.Event{
		{TimeUnixNano: 10, ProfileID: "kp_test", EventType: "first_contact", State: "secret_state_a", Semantic: "setup", Direction: "client_to_server", FrameBytes: 32, PayloadBytes: 19, PaddingBytes: 3, SchedulerMode: "balanced", Note: "contains payload text"},
		{TimeUnixNano: 20, ProfileID: "kp_test", EventType: "frame_encode", State: "secret_state_b", Semantic: "data", Direction: "server_to_client", FrameBytes: 64, PayloadBytes: 51, PaddingBytes: 7, SchedulerMode: "balanced"},
		{TimeUnixNano: 30, ProfileID: "kp_test", EventType: "close", Note: "normal_close"},
	}
	a := ExtractFeatures(events)
	b := ExtractFeatures(events)
	if string(mustJSON(t, a)) != string(mustJSON(t, b)) {
		t.Fatalf("feature extraction is not deterministic:\n%s\n%s", mustJSON(t, a), mustJSON(t, b))
	}
	raw := string(mustJSON(t, a))
	for _, forbidden := range []string{"payload text", "secret_state_a", "secret_state_b"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("features leaked forbidden value %q: %s", forbidden, raw)
		}
	}
	if a.Features["total_frames"] != 2 {
		t.Fatalf("total_frames = %v, want 2", a.Features["total_frames"])
	}
}

func TestExtractFeaturesHandlesEmptyAndMalformedTrace(t *testing.T) {
	vector := ExtractFeatures(nil)
	if vector.Features == nil || vector.Buckets == nil {
		t.Fatalf("empty trace should produce initialized maps: %+v", vector)
	}
	malformed := ExtractFeatures([]ktrace.Event{{FrameBytes: -1, PayloadBytes: -4, PaddingBytes: -9}})
	if malformed.Features["total_bytes"] != 0 {
		t.Fatalf("negative sizes should be clamped: %+v", malformed.Features)
	}
}

func TestDistanceIsDeterministicSymmetricAndFinite(t *testing.T) {
	a := ExtractFeatures(FixedProtocolTraces(2)[0])
	b := ExtractFeatures(NoisyFixedProtocolTraces(2, 7)[0])
	if got := Distance(a, a); got != 0 {
		t.Fatalf("identical distance = %v, want 0", got)
	}
	ab := Distance(a, b)
	ba := Distance(b, a)
	if math.IsNaN(ab) || math.IsInf(ab, 0) || math.IsNaN(ba) || math.IsInf(ba, 0) {
		t.Fatalf("distance must be finite: ab=%v ba=%v", ab, ba)
	}
	if math.Abs(ab-ba) > 0.000001 {
		t.Fatalf("distance not symmetric: ab=%v ba=%v", ab, ba)
	}
	if ab <= 0 {
		t.Fatalf("obviously different vectors should have positive distance")
	}
}

func TestControlsClusterAsExpected(t *testing.T) {
	fixed := ExtractFeatureVectors(FixedProtocolTraces(8))
	fixedReport := Cluster(fixed, DefaultClusterThreshold)
	if fixedReport.ClusterCount != 1 || fixedReport.PairwiseStats.MaxDistance > 0.001 {
		t.Fatalf("fixed control should cluster tightly: %+v", fixedReport)
	}

	noisy := ExtractFeatureVectors(NoisyFixedProtocolTraces(8, 1))
	noisyReport := Cluster(noisy, DefaultClusterThreshold)
	if noisyReport.ClusterCount != 1 || noisyReport.PairwiseStats.MaxDistance > 0.25 {
		t.Fatalf("noisy fixed control should remain suspiciously clustered: %+v", noisyReport)
	}

	random := ExtractFeatureVectors(RandomByteProtocolTraces(8, 1))
	randomReport := Cluster(random, DefaultClusterThreshold)
	if randomReport.PairwiseStats.AverageDistance <= noisyReport.PairwiseStats.AverageDistance {
		t.Fatalf("random control should be noisier than noisy-fixed control: random=%+v noisy=%+v", randomReport.PairwiseStats, noisyReport.PairwiseStats)
	}
}

func TestGeneratedSameProfileIsCloserThanDifferentProfiles(t *testing.T) {
	p1, err := compiler.Generate(101)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := compiler.Generate(102)
	if err != nil {
		t.Fatal(err)
	}
	a, err := labtrace.CaptureTrace(context.Background(), p1, []byte("hello kurdistan"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := labtrace.CaptureTrace(context.Background(), p1, []byte("hello kurdistan"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := labtrace.CaptureTrace(context.Background(), p2, []byte("hello kurdistan"))
	if err != nil {
		t.Fatal(err)
	}
	same := Distance(ExtractFeatures(a), ExtractFeatures(b))
	different := Distance(ExtractFeatures(a), ExtractFeatures(c))
	if same > 0.12 {
		t.Fatalf("same-profile distance too high: %v", same)
	}
	if different <= same {
		t.Fatalf("different profile should be farther than same profile: same=%v different=%v", same, different)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
