package com.ticeapp.androiddoubleratchet

import com.goterl.lazycode.lazysodium.utils.Key
import java.math.BigInteger

class Message(val header: Header, val cipher: ByteArray)
class Header(val publicKey: Key, val numberOfMessagesInPreviousSendingChain: Int, val messageNumber: Int) {
    fun bytes(): ByteArray {
        var bytes = publicKey.asBytes.clone()

        if (numberOfMessagesInPreviousSendingChain < Int.MAX_VALUE) {
            bytes += ByteArray(4) // Padding to be compatible with 64-bit
        }

        bytes += BigInteger.valueOf(numberOfMessagesInPreviousSendingChain.toLong()).toByteArray()

        if (messageNumber < Int.MAX_VALUE) {
            bytes += ByteArray(4) // Padding to be compatible with 64-bit
        }

        bytes += BigInteger.valueOf(messageNumber.toLong()).toByteArray()

        return bytes
    }
}