package com.ticeapp.androiddoubleratchet

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.utils.Key
import com.goterl.lazysodium.utils.KeyPair
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