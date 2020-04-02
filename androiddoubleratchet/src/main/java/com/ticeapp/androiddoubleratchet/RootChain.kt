package com.ticeapp.androiddoubleratchet

import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid
import com.goterl.lazycode.lazysodium.interfaces.KeyExchange
import com.goterl.lazycode.lazysodium.utils.Key
import com.goterl.lazycode.lazysodium.utils.KeyPair
import com.ticeapp.androidhkdf.deriveHKDFKey

internal typealias ChainKey = Key

internal class RootChain(var keyPair: KeyPair, var remotePublicKey: Key?, var rootKey: Key, val info: String) {
    fun ratchetStep(side: Side): ChainKey {
        val remotePublicKey = remotePublicKey ?: throw DRError.RemotePublicKeyMissingException()

        val input = side.calculateSessionKey(keyPair, remotePublicKey)
        val derivedHKDFKey = deriveHKDFKey(input, rootKey.asBytes, info, L = 64)

        rootKey = Key.fromBytes(derivedHKDFKey.sliceArray(0..31))
        return ChainKey.fromBytes(derivedHKDFKey.sliceArray(32..63))
    }
}