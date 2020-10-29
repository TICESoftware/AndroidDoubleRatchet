package com.ticeapp.androiddoubleratchet

import android.util.Base64
import com.goterl.lazycode.lazysodium.utils.Key
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

internal class MessageKeyCache {
    data class MessageIndex(val publicKey: Key, val messageNumber: Int)

    internal val maxCache: Int
    private var skippedMessageKeys: HashMap<MessageIndex, Key>
    private var messageKeyCache: MutableList<MessageIndex>

    val cacheState: MessageKeyCacheState
        get() {
            return messageKeyCache.map { MessageKeyCacheEntry(it.publicKey, it.messageNumber, skippedMessageKeys[it]!!) }
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

typealias MessageKeyCacheState = List<MessageKeyCacheEntry>

@Serializable
data class MessageKeyCacheEntry(@Serializable(with = KeySerializer::class) val publicKey: Key, val messageNumber: Int, @Serializable(with = KeySerializer::class) val messageKey: Key)

class KeySerializer: KSerializer<Key> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Key", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: Key) = encoder.encodeString(Base64.encodeToString(value.asBytes, Base64.NO_WRAP))
    override fun deserialize(decoder: Decoder): Key = Key.fromBytes(Base64Coder.decode(decoder.decodeString()))
    override fun patch(decoder: Decoder, old: Key): Key = deserialize(decoder)
}