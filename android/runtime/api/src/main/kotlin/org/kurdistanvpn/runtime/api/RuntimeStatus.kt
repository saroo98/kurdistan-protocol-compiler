// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.api

import org.kurdistanvpn.core.model.RuntimeAvailability

data class UnavailableRuntime(
    val reason: RuntimeAvailability = RuntimeAvailability.PHASE_9_NO_RUNTIME,
)
