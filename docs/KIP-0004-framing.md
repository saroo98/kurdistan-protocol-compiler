<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0004: Framing

The framing package encodes stable semantic operations through a generated profile. Supported v0 operations are `open_stream`, `data`, `close_stream`, `padding`, and `error`.

The generated wire mapping changes the type tag for each semantic operation. Length modes include varint prefix, fixed 2-byte prefix, fixed 4-byte prefix, and lab suffix mode. Type modes include generated explicit tags, profile-derived tags, header-order-derived tags, and table-indexed symbols with a profile-derived byte.

Header order varies across generated profiles. Length is handled by the selected frame envelope, while `type`, `stream`, and `flags` are ordered by the profile.

Fragmentation modes split large payloads into chunks so frame limits are enforced. Decode reconstructs fragments only under the correct profile. Malformed input returns errors and must not panic.

Padding placement can be none, prefix, suffix, inter-frame, or probabilistic. The decoder uses the profile padding placement and encoded padding length to strip padding without exposing payload contents to traces.
