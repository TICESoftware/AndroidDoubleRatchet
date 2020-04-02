package com.ticeapp.androiddoubleratchet

import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid
import com.goterl.lazycode.lazysodium.utils.Key
import com.goterl.lazycode.lazysodium.utils.KeyPair

internal interface DHCalculator {
    fun calculateSessionKey(ownKeyPair: KeyPair, remotePublicKey: Key): ByteArray
}

internal enum class Side : DHCalculator {
    SENDING {
        override fun calculateSessionKey(ownKeyPair: KeyPair, remotePublicKey: Key): ByteArray = LazySodiumAndroid(
            SodiumAndroid()
        ).cryptoKxServerSessionKeys(ownKeyPair.publicKey, ownKeyPair.secretKey, remotePublicKey).tx
    },
    RECEIVING {
        override fun calculateSessionKey(ownKeyPair: KeyPair, remotePublicKey: Key): ByteArray = LazySodiumAndroid(
            SodiumAndroid()
        ).cryptoKxClientSessionKeys(ownKeyPair.publicKey, ownKeyPair.secretKey, remotePublicKey).rx
    }
}