// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.nativeapi.NativeCompatibility
import org.kurdistanvpn.core.nativeapi.NativeResult

internal fun readCoreCompatibility(query: () -> NativeResult<NativeCompatibility>): NativeResult<NativeCompatibility> =
    try {
        query()
    } catch (cancelled: java.util.concurrent.CancellationException) {
        throw cancelled
    } catch (_: LinkageError) {
        NativeResult.Failure(OperationError.INTERNAL_FAILURE)
    } catch (_: Exception) {
        NativeResult.Failure(OperationError.INTERNAL_FAILURE)
    }

/** Binary compatibility never authorizes a storage migration or reset. */
internal fun coreStartupFailure(result: NativeResult<NativeCompatibility>): AppState? = when (result) {
    is NativeResult.Failure -> AppState.CoreUnavailable
    is NativeResult.Success -> if (result.value.bridgeVersion != "kurd-android-bridge-v1" ||
        result.value.goCoreVersion != "kurd-go-core-phase9-v1") AppState.CoreIncompatible else null
}
