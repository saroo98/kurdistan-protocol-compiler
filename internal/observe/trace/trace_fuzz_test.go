package trace

import (
	"bytes"
	"testing"
)

func FuzzDecodeJSONL(f *testing.F) {
	f.Add([]byte(`{"time_unix_nano":1,"role":"client","profile_id":"kp","event_type":"frame","frame_bytes":10}` + "\n"))
	f.Add([]byte(`not-json`))
	f.Add([]byte(`{"event_type":"frame"}` + "\n" + `{"event_type":"close","note":"local"}` + "\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		_, _ = DecodeJSONL(bytes.NewReader(data))
	})
}
