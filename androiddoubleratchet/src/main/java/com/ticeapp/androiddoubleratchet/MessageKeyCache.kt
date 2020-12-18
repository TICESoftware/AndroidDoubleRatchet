package com.ticeapp.androiddoubleratchet

public interface MessageKeyCache {
    fun add(messageKey: ByteArray, messageNumber: Int, publicKey: ByteArray)
    fun getMessageKey(messageNumber: Int, publicKey: ByteArray): ByteArray?
    fun remove(publicKey: ByteArray, messageNumber: Int)
}