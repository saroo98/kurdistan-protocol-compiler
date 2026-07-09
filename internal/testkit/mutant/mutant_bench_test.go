package mutant

import "testing"

func BenchmarkMutantCorpusGeneration(b *testing.B) {
	for _, mode := range Modes() {
		b.Run(mode, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := GenerateProfiles(mode, int64(i*100+1), 40); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
