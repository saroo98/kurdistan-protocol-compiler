package stream

import "testing"

func BenchmarkOpenStreamsFour(b *testing.B) {
	benchmarkOpenStreams(b, 4)
}

func BenchmarkOpenStreamsSixteen(b *testing.B) {
	benchmarkOpenStreams(b, 16)
}

func benchmarkOpenStreams(b *testing.B, n int) {
	cfg := Config{
		MaxConcurrentStreams:      n,
		InitialStreamWindowBytes:  16 * 1024,
		InitialSessionWindowBytes: n * 16 * 1024,
		PriorityPolicy:            "fifo",
	}
	for i := 0; i < b.N; i++ {
		session, err := NewSession(cfg)
		if err != nil {
			b.Fatal(err)
		}
		for streamIndex := 0; streamIndex < n; streamIndex++ {
			if _, err := session.OpenStream("bulk"); err != nil {
				b.Fatal(err)
			}
		}
	}
}
