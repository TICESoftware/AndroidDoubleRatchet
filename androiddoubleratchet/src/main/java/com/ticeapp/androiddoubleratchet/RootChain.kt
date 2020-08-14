package com.ticeapp.androiddoubleratchet

import android.util.Base64
import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid
import com.goterl.lazycode.lazysodium.interfaces.KeyExchange
import com.goterl.lazycode.lazysodium.utils.Key
import com.goterl.lazycode.lazysodium.utils.KeyPair
import com.ticeapp.androidhkdf.deriveHKDFKey

internal typealias ChainKey = Key

internal class RootChain(var keyPair: KeyPair, var remotePublicKey: Key?, var rootKey: Key, val info: String, private val sodium: LazySodiumAndroid) {
    fun ratchetStep(side: Side): ChainKey {
        val remotePublicKey = remotePublicKey ?: throw DRError.RemotePublicKeyMissingException()

        val input = calculateSessionKey(keyPair, remotePublicKey, side)
        val derivedHKDFKey = deriveHKDFKey(input, rootKey.asBytes, info, L = 64, sodium = sodium)

        rootKey = Key.fromBytes(derivedHKDFKey.sliceArray(0..31))
        return ChainKey.fromBytes(derivedHKDFKey.sliceArray(32..63))
    }

    private fun calculateSessionKey(ownKeyPair: KeyPair, remotePublicKey: Key, side: Side): ByteArray {
        return when(side) {
            Side.SENDING -> sodium.cryptoKxServerSessionKeys(ownKeyPair.publicKey, ownKeyPair.secretKey, remotePublicKey).tx
            Side.RECEIVING -> sodium.cryptoKxClientSessionKeys(ownKeyPair.publicKey, ownKeyPair.secretKey, remotePublicKey).rx
        }
    }
}