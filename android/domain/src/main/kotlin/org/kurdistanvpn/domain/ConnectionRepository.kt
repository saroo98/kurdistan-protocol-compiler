// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.domain

import kotlinx.coroutines.flow.Flow
import org.kurdistanvpn.core.model.*

/** Categorical results only. Exceptions, native authority and transport material stay in adapters. */
sealed interface DomainResult<out T> {
    data class Success<T>(val value: T) : DomainResult<T>
    data class Rejected(val failure: ProductFailure) : DomainResult<Nothing>
}

/** A command acknowledgement is not proof of connection. Only observeState supplies that truth. */
enum class ConnectionCommandResult { ACCEPTED, ALREADY_STOPPED }

interface ConnectionRepository {
    fun observeState(): Flow<ConnectionState>
    /** Fresh authority and revision validation is mandatory; a checked domain projection is not accepted. */
    suspend fun connect(profileId: CatalogId, expectedSettingsRevision: Long): DomainResult<ConnectionCommandResult>
    suspend fun disconnect(): DomainResult<ConnectionCommandResult>
    /** Zero means indefinite; timed suppression is bounded to one day and never schedules connection. */
    suspend fun pause(durationMillis: Long = 0): DomainResult<ConnectionCommandResult>
    suspend fun resume(): DomainResult<ConnectionCommandResult>
    suspend fun reconnect(): DomainResult<ConnectionCommandResult>
    /** Emergency operations bypass app lock and preempt reconnect/fallback/probes. */
    suspend fun recoverInternet(): DomainResult<ConnectionCommandResult>
}
