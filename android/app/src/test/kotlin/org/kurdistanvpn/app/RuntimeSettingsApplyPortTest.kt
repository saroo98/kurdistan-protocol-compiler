// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.data.settings.*
import org.kurdistanvpn.runtime.api.*
import org.kurdistanvpn.runtime.android.RuntimeControlBinder

class RuntimeSettingsApplyPortTest {
    @Test fun idleTransactionRetainsItsOwnerUntilFinishAndRejectsOverlappingPrepare() = runBlocking {
        var retained = 0
        var released = 0
        val port = RuntimeSettingsApplyPort({ _, _ -> error("Idle transaction needs no transition") },
            { VpnRuntimeSnapshot() }, retainOwner = { retained++ }, releaseOwner = { released++ })
        assertEquals(SettingsPortResult.Success(SettingsRuntimeIntent.ALREADY_STOPPED), port.prepare())
        assertTrue(port.prepare() is SettingsPortResult.Rejected)
        assertEquals(1, retained)
        assertEquals(0, released)
        port.finish(); port.finish()
        assertEquals(1, released)
        assertEquals(SettingsPortResult.Success(SettingsRuntimeIntent.ALREADY_STOPPED), port.prepare())
        port.finish()
        assertEquals(2, retained); assertEquals(2, released)
    }

    @Test fun failedOwnerReadReleasesRetentionAndPermitsTheNextTransaction() = runBlocking {
        var fail = true
        var released = 0
        val port = RuntimeSettingsApplyPort({ _, _ -> null },
            { if (fail) error("Unavailable owner") else VpnRuntimeSnapshot() }, releaseOwner = { released++ })
        assertTrue(port.prepare() is SettingsPortResult.Rejected)
        assertEquals(1, released)
        fail = false
        assertEquals(SettingsPortResult.Success(SettingsRuntimeIntent.ALREADY_STOPPED), port.prepare())
        port.finish()
        assertEquals(2, released)
    }

    @Test fun degradedSessionCanPrepareOnlyWithServiceAuthorization() = runBlocking {
        for (admitted in listOf(false, true)) {
            var current = VpnRuntimeSnapshot(state = VpnRuntimeState.DEGRADED)
            val port = RuntimeSettingsApplyPort({ operation, _ ->
                assertEquals(RuntimeControlBinder.SETTINGS_PREPARE, operation)
                if (admitted) { current = VpnRuntimeSnapshot(); "a".repeat(32) } else null
            }, { current })
            assertEquals(if (admitted) SettingsPortResult.Success(SettingsRuntimeIntent.RECONNECT_ONCE)
                else SettingsPortResult.Rejected(ProductFailureCode.OPERATION_INTERRUPTED), port.prepare())
        }
    }
    @Test fun olderAndroidRejectsChangingTunMeteringBeforeTouchingRuntime() = runBlocking {
        val before = ProductSettings()
        val changed = before.copy(tunnel = before.tunnel.copy(metered = true))
        for (api in listOf(26, 28, 29)) {
            val port = RuntimeSettingsApplyPort({ _, _ -> error("Must not touch lifecycle during validation") },
                { error("Must not query lifecycle during validation") }, api)
            assertEquals(api >= 29, port.validate(before, changed) is SettingsPortResult.Success)
            assertTrue(port.validate(before, before) is SettingsPortResult.Success)
        }
    }
    @Test fun acknowledgesOnlyCorrelatedAppliedJournalAndDoesNotResumeAfterUserStop() = runBlocking {
        var current = VpnRuntimeSnapshot(state = VpnRuntimeState.ACTIVE_KURD_LIVE)
        var valid = true
        var resumes = 0
        val port = RuntimeSettingsApplyPort({ operation, _ ->
            if (!valid) null else when (operation) {
                RuntimeControlBinder.SETTINGS_PREPARE, RuntimeControlBinder.SETTINGS_STOP -> {
                    current = VpnRuntimeSnapshot(); "a".repeat(32)
                }
                RuntimeControlBinder.SETTINGS_RESUME -> {
                    resumes++
                    current = VpnRuntimeSnapshot(state = VpnRuntimeState.ACTIVE_KURD_LIVE,
                        runtimeRequestId = "b".repeat(32), appliedRevision = 6)
                    "b".repeat(32)
                }
                else -> "a".repeat(32)
            }
        }, { current })
        assertEquals(SettingsPortResult.Success(SettingsRuntimeIntent.RECONNECT_ONCE), port.prepare())
        assertEquals(SettingsPortResult.Success(Unit), port.apply(SettingsRuntimeIntent.RECONNECT_ONCE,
            SettingsStoreState(6, 2, ProductSettings())))
        valid = false
        current = VpnRuntimeSnapshot()
        assertTrue(port.restore(SettingsRuntimeIntent.RECONNECT_ONCE, SettingsStoreState(8, 1, ProductSettings())) is SettingsPortResult.Rejected)
        assertEquals(1, resumes)
        port.finish()
    }

    @Test fun wrongAppliedRevisionIsNotReportedAsSuccessfulReconnect() = runBlocking {
        var current = VpnRuntimeSnapshot(state = VpnRuntimeState.ACTIVE_KURD_LIVE)
        val port = RuntimeSettingsApplyPort({ operation, _ ->
            current = if (operation == RuntimeControlBinder.SETTINGS_RESUME)
                VpnRuntimeSnapshot(state = VpnRuntimeState.ACTIVE_KURD_LIVE, runtimeRequestId = "b".repeat(32), appliedRevision = 8)
                else VpnRuntimeSnapshot()
            if (operation == RuntimeControlBinder.SETTINGS_RESUME) "b".repeat(32) else "a".repeat(32)
        }, { current })
        port.prepare()
        assertTrue(port.apply(SettingsRuntimeIntent.RECONNECT_ONCE, SettingsStoreState(6, 2, ProductSettings())) is SettingsPortResult.Rejected)
        assertEquals(VpnRuntimeState.IDLE, current.state)
        port.finish()
    }
}
