package com.ticeapp.androiddoubleratchet

import com.goterl.lazycode.lazysodium.utils.Key

public interface MessageKeyCache {
    fun add(messageKey: Key, messageNumber: Int, publicKey: Key)
    fun getMessageKey(messageNumber: Int, publicKey: Key): Key?
    fun remove(publicKey: Key, messageNumber: Int)
}