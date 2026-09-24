// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"bufio"
	"io"
	"net/http"
)

const maintenanceHTTPHeaderBytesV1 = 16384

// Standard Request.Write has no proxy, redirect, decompression or retry path.
func maintenanceWriteHTTPV1(w io.Writer, signedURL string) MaintenanceResultV1 {
	request, err := http.NewRequest(http.MethodGet, signedURL, nil)
	if err != nil {
		return MaintenanceInternalFailure
	}
	request.Close = true
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "")
	writer := bufio.NewWriterSize(w, 4096)
	if err = request.Write(writer); err != nil {
		return MaintenanceFetchRejected
	}
	if err = writer.Flush(); err != nil {
		return MaintenanceFetchRejected
	}
	return MaintenanceSuccess
}

// dst was reserved and allocated by the admitted worker. All failure paths
// close raw transport before Body.Close, which could otherwise drain it.
func maintenanceReadHTTPV1(r io.Reader, request *http.Request, dst []byte, closeRaw func()) (n int, result MaintenanceResultV1) {
	result = MaintenanceFetchRejected
	defer func() {
		if result != MaintenanceSuccess {
			clear(dst)
			n = 0
		}
	}()
	limiter := &io.LimitedReader{R: r, N: maintenanceHTTPHeaderBytesV1}
	reader := bufio.NewReaderSize(limiter, 4096)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		closeRaw()
		return 0, result
	}
	defer func() { closeRaw(); _ = response.Body.Close() }()
	consumed := maintenanceHTTPHeaderBytesV1 - limiter.N - int64(reader.Buffered())
	if consumed > maintenanceHTTPHeaderBytesV1 || response.ProtoMajor != 1 || response.ProtoMinor > 1 || response.StatusCode != 200 {
		return 0, result
	}
	for _, h := range []struct{ name, value string }{{"Content-Type", "application/octet-stream"}, {"Content-Encoding", "identity"}} {
		values := response.Header.Values(h.name)
		if len(values) > 1 || len(values) == 1 && values[0] != h.value {
			return 0, result
		}
	}
	if response.ContentLength > int64(len(dst)) {
		return 0, MaintenanceSizeLimit
	}
	// Preserve the same reader's prefetched body. This allows even one-byte
	// chunks plus the maintained excess-framing and trailer limits, without an
	// unbounded wire allowance. Body retention remains exactly cap(dst).
	limiter.N = int64(20*(len(dst)+1) + 32768)
	for n < len(dst) {
		count, err := response.Body.Read(dst[n:])
		n += count
		if err == io.EOF {
			if n == 0 {
				return 0, MaintenanceFetchRejected
			}
			return n, MaintenanceSuccess
		}
		if err != nil {
			return 0, MaintenanceFetchRejected
		}
		if count == 0 {
			return 0, MaintenanceFetchRejected
		}
	}
	var overflow [1]byte
	count, err := response.Body.Read(overflow[:])
	clear(overflow[:])
	if count > 0 {
		return 0, MaintenanceSizeLimit
	}
	if err != io.EOF || n == 0 {
		return 0, MaintenanceFetchRejected
	}
	return n, MaintenanceSuccess
}
