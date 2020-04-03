package com.ticeapp.androiddoubleratchet

import com.goterl.lazycode.lazysodium.utils.Key
import java.math.BigInteger

class Message(val header: Header, val cipher: ByteArray)
class Header(val publicKey: Key, val numberOfMessagesInPreviousSendingChain: Int, val messageNumber: Int) {
    fun bytes(): ByteArray {
        var bytes = publicKey.asBytes.clone()
        bytes += byteArray(numberOfMessagesInPreviousSendingChain, 8)
        bytes += byteArray(messageNumber, 8)

        return bytes
    }

    private fun byteArray(value: Int, byteCount: Int): ByteArray {
        val valueBytes = BigInteger.valueOf(value.toLong()).toByteArray()

        if (valueBytes.size > byteCount) {
            throw IllegalArgumentException("Binary representation of given value needs more bytes then specified by byteCount.")
        }

        val paddingBytes = ByteArray(byteCount - valueBytes.size)

        return paddingBytes + valueBytes
    }
}