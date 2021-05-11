package com.ticeapp.androiddoubleratchet

import com.goterl.lazysodium.utils.Key
import java.math.BigInteger

class Message @ExperimentalUnsignedTypes constructor(val header: Header, val cipher: ByteArray)
class Header(val publicKey: Key, val numberOfMessagesInPreviousSendingChain: Int, val messageNumber: Int) {
    @ExperimentalUnsignedTypes
    fun bytes(): UByteArray {
        var bytes = publicKey.asBytes.clone().toUByteArray()
        bytes += byteArray(numberOfMessagesInPreviousSendingChain, 8)
        bytes += byteArray(messageNumber, 8)

        return bytes
    }

    private fun byteArray(value: Int, byteCount: Int): UByteArray {
        val valueBytes = BigInteger.valueOf(value.toLong()).toByteArray().toUByteArray()

        if (valueBytes.size > byteCount) {
            throw IllegalArgumentException("Binary representation of given value needs more bytes then specified by byteCount.")
        }

        val paddingBytes = ByteArray(byteCount - valueBytes.size).toUByteArray()

        return paddingBytes + valueBytes
    }
}