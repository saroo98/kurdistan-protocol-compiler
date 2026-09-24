// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import java.io.*
import org.kurdistanvpn.core.nativeapi.NativeCompatibility

/** Last-applied input bindings. Not native authority, a session, a credential or permission to connect. */
class RuntimeBootstrapRecord(val settingsRevision: Long, val profileId: String?, val profileGeneration: Long,
    planDigest: ByteArray, val compatibility: NativeCompatibility) {
    private val digest = planDigest.clone()
    val connectable: Boolean get() = profileId != null
    init {
        require(settingsRevision > 0) { "INVALID_BOOTSTRAP" }
        require(if (profileId == null) profileGeneration == 0L && digest.isEmpty()
            else profileId.matches(Regex("[a-z0-9][a-z0-9-]{0,63}")) && profileGeneration > 0 && digest.size == 32 && digest.any { it != 0.toByte() }) { "INVALID_BOOTSTRAP" }
        require(strings(compatibility).all { it.matches(Regex("[A-Za-z0-9_.-]{1,128}")) } && numbers(compatibility).all { it > 0 }) { "INVALID_BOOTSTRAP_COMPATIBILITY" }
    }
    fun matches(settings: Long, profile: String?, generation: Long, nativeDigest: ByteArray, current: NativeCompatibility): Boolean =
        settingsRevision == settings && profileId == profile && profileGeneration == generation && digest.contentEquals(nativeDigest) && compatibility == current
    fun encode(): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { w ->
            w.writeInt(MAGIC); w.writeByte(1); w.writeByte(SecureDataClass.RUNTIME_BOOTSTRAP.wireValue)
            w.writeLong(settingsRevision); w.writeUTF(profileId.orEmpty()); w.writeLong(profileGeneration)
            w.writeByte(digest.size); w.write(digest); strings(compatibility).forEach(w::writeUTF); numbers(compatibility).forEach(w::writeInt)
        }
        return output.toByteArray().also { require(it.size <= MAX_BYTES) }
    }
    override fun toString(): String = "RuntimeBootstrapRecord(redacted)"
    companion object {
        const val RECORD_ID = "runtime-bootstrap-current"
        const val MAX_BYTES = 2048
        private const val MAGIC = 0x4b524231
        private fun strings(c: NativeCompatibility) = listOf(c.bridgeVersion, c.goCoreVersion, c.profileSchema, c.strategyRegistry, c.relaySchema, c.diagnosticSchema)
        private fun numbers(c: NativeCompatibility) = listOf(c.cryptoSuite, c.maxInputBytes, c.maxQrChunks, c.maxQrChunkChars, c.maxResultBytes, c.maxConcurrentHandles)
        fun decode(input: ByteArray): RuntimeBootstrapRecord {
            require(input.size in 25..MAX_BYTES) { "MALFORMED_BOOTSTRAP" }
            val owned = input.clone()
            try {
                val r = DataInputStream(ByteArrayInputStream(owned))
                require(r.readInt() == MAGIC && r.readUnsignedByte() == 1 && r.readUnsignedByte() == SecureDataClass.RUNTIME_BOOTSTRAP.wireValue)
                val revision = r.readLong(); val profile = r.readUTF().takeIf { it.isNotEmpty() }; val generation = r.readLong()
                val size = r.readUnsignedByte().also { require(it == 0 || it == 32) }
                val digest = ByteArray(size).also(r::readFully)
                try {
                    val c = NativeCompatibility(r.readUTF(), r.readUTF(), r.readUTF(), r.readUTF(), r.readUTF(), r.readUTF(),
                        r.readInt(), r.readInt(), r.readInt(), r.readInt(), r.readInt(), r.readInt())
                    val result = RuntimeBootstrapRecord(revision, profile, generation, digest, c)
                    require(r.available() == 0)
                    val canonical = result.encode(); try { require(owned.contentEquals(canonical)) } finally { canonical.fill(0) }
                    return result
                } finally { digest.fill(0) }
            } catch (_: IOException) { throw IllegalArgumentException("MALFORMED_BOOTSTRAP") }
            catch (_: RuntimeException) { throw IllegalArgumentException("MALFORMED_BOOTSTRAP") }
            finally { owned.fill(0) }
        }
    }
}

/** Version 2 binds the production projection; it is never decoded as legacy authority. */
class RuntimeProductionBootstrapRecord(val settingsRevision: Long, val profileId: String?,
    val profileGeneration: ULong, planDigest: ByteArray, val compatibility: NativeCompatibility) {
    private val digest: ByteArray
    val connectable: Boolean get() = profileId != null
    init {
        require(settingsRevision > 0)
        require(if(profileId==null) profileGeneration==0uL && planDigest.isEmpty()
            else profileId.matches(Regex("[a-z0-9][a-z0-9-]{0,63}")) && profileGeneration!=0uL &&
                planDigest.size==32 && planDigest.any{it!=0.toByte()})
        require(strings(compatibility).all{it.matches(Regex("[A-Za-z0-9_.-]{1,128}"))} && numbers(compatibility).all{it>0})
        digest=planDigest.clone()
    }
    fun matches(settings:Long,profile:String?,generation:ULong,nativeDigest:ByteArray,current:NativeCompatibility):Boolean =
        settingsRevision==settings && profileId==profile && profileGeneration==generation &&
            digest.contentEquals(nativeDigest) && compatibility==current
    fun encode():ByteArray {
        val output=object:ByteArrayOutputStream(RuntimeBootstrapRecord.MAX_BYTES) {
            override fun close(){buf.fill(0);reset()}
        }
        return output.use {
            val writer=DataOutputStream(output)
            writer.writeInt(0x4b524231);writer.writeByte(2);writer.writeByte(SecureDataClass.RUNTIME_BOOTSTRAP.wireValue)
            writer.writeLong(settingsRevision);writer.writeUTF(profileId.orEmpty());writer.writeLong(profileGeneration.toLong())
            writer.writeByte(digest.size);writer.write(digest);strings(compatibility).forEach(writer::writeUTF);numbers(compatibility).forEach(writer::writeInt)
            check(output.size()<=RuntimeBootstrapRecord.MAX_BYTES)
            output.toByteArray()
        }
    }
    override fun toString()="RuntimeProductionBootstrapRecord(redacted)"
    companion object {
        private fun strings(c:NativeCompatibility)=listOf(c.bridgeVersion,c.goCoreVersion,c.profileSchema,c.strategyRegistry,c.relaySchema,c.diagnosticSchema)
        private fun numbers(c:NativeCompatibility)=listOf(c.cryptoSuite,c.maxInputBytes,c.maxQrChunks,c.maxQrChunkChars,c.maxResultBytes,c.maxConcurrentHandles)
        fun decode(input:ByteArray):RuntimeProductionBootstrapRecord {
            require(input.size in 25..RuntimeBootstrapRecord.MAX_BYTES)
            val owned=input.clone()
            try {
                val reader=DataInputStream(ByteArrayInputStream(owned))
                require(reader.readInt()==0x4b524231 && reader.readUnsignedByte()==2 &&
                    reader.readUnsignedByte()==SecureDataClass.RUNTIME_BOOTSTRAP.wireValue)
                val revision=reader.readLong();val profile=reader.readUTF().takeIf{it.isNotEmpty()};val generation=reader.readLong().toULong()
                val size=reader.readUnsignedByte().also{require(it==0||it==32)}
                val digest=ByteArray(size)
                try {
                    reader.readFully(digest)
                    val compatibility=NativeCompatibility(reader.readUTF(),reader.readUTF(),reader.readUTF(),reader.readUTF(),reader.readUTF(),reader.readUTF(),
                        reader.readInt(),reader.readInt(),reader.readInt(),reader.readInt(),reader.readInt(),reader.readInt())
                    require(reader.available()==0)
                    val result=RuntimeProductionBootstrapRecord(revision,profile,generation,digest,compatibility)
                    val canonical=result.encode()
                    try{require(owned.contentEquals(canonical))}finally{canonical.fill(0)}
                    return result
                } finally{digest.fill(0)}
            } catch(_:IOException){throw IllegalArgumentException("MALFORMED_PRODUCTION_BOOTSTRAP")}
            catch(_:RuntimeException){throw IllegalArgumentException("MALFORMED_PRODUCTION_BOOTSTRAP")}
            finally{owned.fill(0)}
        }
    }
}
