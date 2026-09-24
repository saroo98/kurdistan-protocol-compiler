// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.kurdistanvpn.core.nativeapi.*

/** Syntax and paired-facts scope only. Role is fixed by the actual JNI output lane. */
internal object ProductionSelectorCodecV1 {
    fun decodeActive(input: ByteBuffer, facts: NativeProductionBootstrapFactsV1): NativeActiveProductionSelectorsV1 =
        Active(Owner(decode(input,facts)))
    fun decodeDisconnected(input: ByteBuffer, facts: NativeProductionBootstrapFactsV1): NativeDisconnectedProductionSelectorsV1 =
        Disconnected(Owner(decode(input,facts)))

    private fun decode(input: ByteBuffer,facts: NativeProductionBootstrapFactsV1): ByteArray {
        require(input.remaining() in 54..512)
        val reader=input.duplicate().order(ByteOrder.BIG_ENDIAN)
        require(reader.int==0x4b504131 && reader.get()==1.toByte() && reader.get()==1.toByte() && reader.short==0.toShort())
        require(reader.int==input.remaining() && reader.long.toULong()==facts.generation)
        val digest=facts.planDigest
        try { for(value in digest) require(reader.get()==value) } finally {digest.fill(0)}
        fun id(): String {
            require(reader.hasRemaining());val n=reader.get().toInt() and 255
            require(n in 1..64 && reader.remaining()>=n)
            val chars=CharArray(n)
            try {
                repeat(n){ val c=reader.get().toInt() and 255; require(c in 33..126);chars[it]=c.toChar() }
                return String(chars)
            } finally {chars.fill('\u0000')}
        }
        require(reader.hasRemaining());val strategies=reader.get().toInt() and 255
        require(strategies in 0..1)
        if(strategies==1) require(id()=="strategy-kurd-tls13-tcp")
        require(reader.hasRemaining());val probes=reader.get().toInt() and 255;require(probes in 0..16)
        var previous=""
        repeat(probes) {
            val value=id();require(value.startsWith("probe-"))
            val digits=value.substring(6);val target=digits.toIntOrNull()
            require(target!=null && target in 1..65535 && digits==target.toString())
            require(it==0 || previous.length<value.length || previous.length==value.length && previous<value)
            previous=value
        }
        require(!reader.hasRemaining())
        val owned=ByteArray(input.remaining())
        return try {input.duplicate().get(owned);owned} catch(error:Throwable) {owned.fill(0);throw error}
    }
    private class Owner(private var bytes: ByteArray?) : AutoCloseable {
        @Synchronized fun copyTo(output:ByteBuffer):Int {
            val current=checkNotNull(bytes);require(!output.isReadOnly && output.remaining()>=current.size)
            output.duplicate().put(current);return current.size
        }
        @Synchronized fun contains(value:String,strategy:Boolean):Boolean {
            val current=checkNotNull(bytes);var offset=52
            val strategies=current[offset++].toInt() and 255
            repeat(strategies){val n=current[offset++].toInt() and 255
                if(strategy && matches(current,offset,n,value))return true
                offset+=n}
            val probes=current[offset++].toInt() and 255
            repeat(probes){val n=current[offset++].toInt() and 255
                if(!strategy && matches(current,offset,n,value))return true
                offset+=n}
            return false
        }
        private fun matches(bytes:ByteArray,offset:Int,n:Int,value:String):Boolean =
            n==value.length && (0 until n).all{bytes[offset+it].toInt()==value[it].code}
        @Synchronized override fun close(){bytes?.fill(0);bytes=null}
    }
    private class Active(private val owner:Owner):NativeActiveProductionSelectorsV1 {
        override fun copyTo(output:ByteBuffer)=owner.copyTo(output)
        override fun containsStrategy(id:String)=owner.contains(id,true)
        override fun containsProbe(target:Int)=owner.contains("probe-$target",false)
        override fun close()=owner.close()
        override fun toString()="NativeActiveProductionSelectorsV1(redacted)"
    }
    private class Disconnected(private val owner:Owner):NativeDisconnectedProductionSelectorsV1 {
        override fun copyTo(output:ByteBuffer)=owner.copyTo(output)
        override fun containsStrategy(id:String)=owner.contains(id,true)
        override fun containsProbe(target:Int)=owner.contains("probe-$target",false)
        override fun close()=owner.close()
        override fun toString()="NativeDisconnectedProductionSelectorsV1(redacted)"
    }
}
