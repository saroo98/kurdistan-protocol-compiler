<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 8 Third-Party Dependency Notices

This notice covers the Go modules first selected by KIP-0077. Exact module
versions and checksums remain authoritative in `go.mod` and `go.sum`.

## github.com/fxamacker/cbor/v2 v2.9.2

Copyright (c) 2019-present Faye Amacker

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## github.com/x448/float16 v0.8.4

Copyright (c) 2019 Montgomery Edwards and Faye Amacker

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

`github.com/veraison/go-cose` and the Python interoperability libraries are
evaluation/test tools only. They are not production Go dependencies in this
work order.

## Independent Python interoperability environment

The Windows amd64 reference fixture is generated with Python 3.12.10. Its
complete test-only dependency closure is pinned to exact PyPI artifact URLs and
SHA-256 hashes in
`testdata/evidence/independent/requirements-win-amd64-py312.lock`. The lock
contains `cbor2` 6.1.3, `cryptography` 46.0.7, `pyhpke` 0.6.5, and their exact
`cffi` 2.0.0 and `pycparser` 2.23 transitive artifacts. None is imported by Go
production code.

From a clean checkout on Windows amd64 with Python 3.12.10 installed, run:

```powershell
Set-Location <repository-root>
powershell -NoProfile -ExecutionPolicy Bypass -File .\testdata\evidence\independent\regenerate_phase8_interop.ps1
```

The script creates a fresh temporary virtual environment, installs with pip
`--require-hashes` and `--no-cache-dir`, verifies the Python and installed
package versions at runtime, regenerates the fixture, and requires a
byte-for-byte match with the committed report. It records no hostname, user,
serial number, or credential.
