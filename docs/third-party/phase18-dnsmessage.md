<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 18 DNS message dependency notice

`internal/net/boundeddns` directly compiles
`golang.org/x/net/dns/dnsmessage` from `golang.org/x/net v0.56.0`.
Exact versions and checksums are recorded in `go.mod` and `go.sum`.
The existing `golang.org/x/crypto v0.54.0` already requires this x/net
version. Promoting it to a direct compiled dependency does not upgrade the
selected crypto or sys versions. The package itself imports only the standard
`errors` package. This notice is not a vulnerability-clearance claim.

The maintained message codec is needed because standard `net.Resolver` does
not expose this component's fixed result/admission bounds, owned socket/join
semantics or a public DNS message codec. No upstream codec is copied.

## Component boundaries

The component uses incremental Parser methods and a noncompressed Builder
whose complete single-question capacity is checked before writing into its
512-byte slab. It does not use Message.Pack/Unpack, All* record collectors,
compression maps, default DNS, hosts, search suffixes, caches or detached
query workers. Query IDs come from standard `crypto/rand`.

UDP is bounded to 512 bytes, detected using a 513-byte receive slab. A validated
TC reply permits one TCP exchange to the same constructor-owned numeric server.
TCP uses its complete 16-bit framing range, 12..65535 bytes, and a separate
two-byte prefix. Four irrelevant UDP replies, two stable-order servers, serial
requested families, eight CNAME links and sixteen distinct addresses bound
local work. Whole-family results come from one server. Deadline or cancellation
never advances to another server.

Every declared section is traversed through Header and typed decode or Skip.
A copied Parser first validates declared RDATA extent. Address RDLENGTH is
checked explicitly. The maintained parser does not expose a final offset or
exact compressed-name RDATA consumption. This component therefore does not
claim byte-exact CNAME/SOA consumption or trailing-byte canonicality. Negative
classification follows the selected recursive NOERROR/SOA/NS rules, not the AA
bit alone, and is not authenticated negative proof or a cache.

Destinations still require the consuming signed-policy/public-address checks
and, for HTTPS, normal hostname authentication. DNS service endpoints are
trusted constructor wiring, not request-supplied destination authority. Future
Android owners must validate private-DNS permission and bind every numeric
socket creation to the current validated network lease without unbound retry.

## Ownership and accounting

Each fixed admission slot reserves the full advertised operation capacity
before domain validation allocates, before copying names, and before context
or callback creation. The existing grammar helper's worst malformed input
allocates 254 string headers; the inventory reserves 4096 bytes for its pinned
64-bit allocation class. Wire slabs retain 66562 bytes, with sixteen private
numeric results, nine chain names and separately inventoried fixed typed parser
scratch, including SOA's two names. Workspaces are cleared after socket cleanup
and callback join, then their slots are released.

`OperationOwnedBytes` uses compiled struct sizes plus conservative small-object
allowances. `FixedOwnedBytes` charges the resolver and fixed slot array once.
The containing owner must charge each operation reservation before launching
it. Caller output is separate caller-owned storage that overlaps the private
results during publication. These figures do not bound opaque netFD/TLS state,
OS socket buffers, recursive-server memory, Go runtime stacks/heap/GC or RSS.

The operation owns one cancellation callback, which captures socket state but
no query/result workspace. Cleanup stops it or joins its completion signal.
`context.AfterFunc` does not itself provide a join; context propagation and
timers can also use bounded standard-library callback/goroutine state. Pinned
Go 1.26.6 numeric DialTCP/DialUDP avoid hostname resolution. Windows net joins
its private fd-cancellation callback; the Unix failure path may finish its
bounded SetWriteDeadline callback after closing the fd. TCP's pinned numeric
path also permits two rare retries after its initial creation. Platform
ControlContext wiring must revalidate/bind every creation, including retries.
No zero-goroutine or exactly-one-kernel-socket claim is made.

## Complete upstream LICENSE from golang.org/x/net v0.56.0

```text
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
