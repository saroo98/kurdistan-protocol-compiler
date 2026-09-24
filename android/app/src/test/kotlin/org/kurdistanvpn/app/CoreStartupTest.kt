// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.nativeapi.NativeCompatibility
import org.kurdistanvpn.core.nativeapi.NativeResult

class CoreStartupTest {
    private val compatible = NativeCompatibility("kurd-android-bridge-v1", "kurd-go-core-phase9-v1",
        "profile", "strategy", "relay", "diagnostic", 1, 1024, 1, 1024, 1024, 1)

    @Test fun supportedCoreDoesNotRequireRecovery() {
        assertNull(coreStartupFailure(NativeResult.Success(compatible)))
    }

    @Test fun binaryMismatchIsNotStorageMigration() {
        assertSame(AppState.CoreIncompatible,
            coreStartupFailure(NativeResult.Success(compatible.copy(bridgeVersion = "unsupported"))))
        assertSame(AppState.CoreIncompatible,
            coreStartupFailure(NativeResult.Success(compatible.copy(goCoreVersion = "unsupported"))))
    }

    @Test fun failedQueryIsUnavailableNotMigration() {
        assertSame(AppState.CoreUnavailable,
            coreStartupFailure(NativeResult.Failure(OperationError.INTERNAL_FAILURE)))
    }

    @Test fun missingNativeLibraryIsUnavailableAndCancellationStillPropagates() {
        assertSame(AppState.CoreUnavailable, coreStartupFailure(readCoreCompatibility {
            throw UnsatisfiedLinkError("test library absent")
        }))
        assertSame(AppState.CoreUnavailable, coreStartupFailure(readCoreCompatibility {
            throw IllegalStateException("test query failed")
        }))
        assertThrows(java.util.concurrent.CancellationException::class.java) {
            readCoreCompatibility { throw java.util.concurrent.CancellationException() }
        }
    }
}
