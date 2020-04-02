package com.ticeapp.androiddoubleratchet

import com.goterl.lazycode.lazysodium.utils.Key

internal class MessageKeyCache {
    data class MessageIndex(val publicKey: Key, val messageNumber: Int)

    internal val maxCache: Int
    private var skippedMessageKeys: HashMap<MessageIndex, Key>
    private var messageKeyCache: ArrayList<MessageIndex>

    val cacheState: MessageKeyCacheState
        get() {
            return ArrayList(messageKeyCache.map { MessageKeyCacheEntry(it.publicKey, it.messageNumber, skippedMessageKeys[it]!!) })
        }

    @ExperimentalStdlibApi
    constructor(maxCache: Int, cacheState: MessageKeyCacheState = ArrayList()) {
        this.maxCache = maxCache
        this.skippedMessageKeys = HashMap()
        this.messageKeyCache = ArrayList()

        for (cacheEntry in cacheState) {
            add(cacheEntry.messageKey, cacheEntry.messageNumber, cacheEntry.publicKey)
        }
    }

    @ExperimentalStdlibApi
    internal fun add(messageKey: Key, messageNumber: Int, publicKey: Key) {
        val messageIndex = MessageIndex(publicKey, messageNumber)

        skippedMessageKeys[messageIndex] = messageKey
        messageKeyCache.add(messageIndex)

        while (messageKeyCache.size > maxCache) {
            val removedIndex = messageKeyCache.removeFirst()
            skippedMessageKeys.remove(removedIndex)
        }
    }

    internal fun getMessageKey(messageNumber: Int, publicKey: Key): Key? {
        val messageIndex = MessageIndex(publicKey, messageNumber)

        return skippedMessageKeys[messageIndex]?.also {
            skippedMessageKeys.remove(messageIndex)
            messageKeyCache.remove(messageIndex)
        }
    }
}

typealias MessageKeyCacheState = ArrayList<MessageKeyCacheEntry>
data class MessageKeyCacheEntry(val publicKey: Key, val messageNumber: Int, val messageKey: Key)