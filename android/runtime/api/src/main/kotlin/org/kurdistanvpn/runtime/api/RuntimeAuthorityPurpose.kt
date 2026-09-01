// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.api

/** PRE_TUN and PRE_ACTIVE are ordered checks within the FULL_AUTHORITY arm, not concurrent
 * authority requests. Both process epochs, both pipe IDs and the deadline remain bound; each
 * response's MAC capability is still one-use. A retry starts an entirely fresh runtime arm. */
enum class RuntimeAuthorityPurpose(val wire: Int) { FULL_AUTHORITY(1), PRE_TUN(2), PRE_ACTIVE(3) }
enum class RuntimeAuthorityTrigger(val wire: Int) { MANUAL(1), AUTOMATIC(2), NETWORK_RETRY(3) }
