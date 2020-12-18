package com.ticeapp.androiddoubleratchet

public interface MessageKeyCache {
    suspend fun add(messageKey: ByteArray, messageNumber: Int, publicKey: ByteArray)
    suspend fun getMessageKey(messageNumber: Int, publicKey: ByteArray): ByteArray?
    suspend fun remove(publicKey: ByteArray, messageNumber: Int)
}