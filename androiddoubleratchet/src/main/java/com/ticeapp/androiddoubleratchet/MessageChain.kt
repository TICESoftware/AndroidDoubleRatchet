package com.ticeapp.androiddoubleratchet

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.Auth
import com.goterl.lazysodium.utils.Key

internal class MessageChain(var chainKey: ChainKey? = null, private val sodium: Auth.Native) {
    private val messageKeyInput = ByteArray(1) { 1.toByte() }
    private val chainKeyInput = ByteArray(1) { 2.toByte() }

    // KDF_CK(ck)
    fun nextMessageKey(): Key {
        val chainKey = chainKey ?: throw DRError.ChainKeyMissingException()

        val messageKey = ByteArray(Auth.BYTES)
        val newChainKey = ByteArray(Auth.BYTES)

        if (!sodium.cryptoAuth(messageKey, messageKeyInput, messageKeyInput.size.toLong(), chainKey.asBytes) ||
            !sodium.cryptoAuth(newChainKey, chainKeyInput, chainKeyInput.size.toLong(), chainKey.asBytes)) {
            throw DRError.MessageChainRatchetStepFailed()
        }

        this.chainKey = Key.fromBytes(newChainKey)
        return Key.fromBytes(messageKey)
    }
}