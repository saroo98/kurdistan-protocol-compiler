package adversary

import "testing"

func BenchmarkFeatureExtraction(b *testing.B) {
	trace := NoisyFixedProtocolTraces(1, 1)[0]
	for i := 0; i < b.N; i++ {
		_ = ExtractFeatures(trace)
	}
}

func BenchmarkPairwiseDistanceMatrix100(b *testing.B) {
	vectors := ExtractFeatureVectors(RandomByteProtocolTraces(100, 1))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for a := 0; a < len(vectors); a++ {
			for c := a + 1; c < len(vectors); c++ {
				_ = Distance(vectors[a], vectors[c])
			}
		}
	}
}

func BenchmarkClustering100(b *testing.B) {
	vectors := ExtractFeatureVectors(RandomByteProtocolTraces(100, 2))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Cluster(vectors, DefaultClusterThreshold)
	}
}
