package com.ticeapp.androiddoubleratchet

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.AEAD
import com.goterl.lazysodium.utils.Key
import com.goterl.lazysodium.utils.KeyPair

class DoubleRatchet {
    private val sodium: LazySodiumAndroid

    val maxSkip: Int

    private val rootChain: RootChain
    private val sendingChain: MessageChain
    private val receivingChain: MessageChain

    private var sendMessageNumber: Int
    private var receivedMessageNumber: Int
    private var previousSendingChainLength: Int
    private val messageKeyCache: MessageKeyCache?

    val publicKey: Key
        get () = rootChain.keyPair.publicKey

    val sessionState: SessionState
        get() = SessionState(
            rootChain.rootKey,
            rootChain.keyPair,
            rootChain.remotePublicKey,
            sendingChain.chainKey,
            receivingChain.chainKey,
            sendMessageNumber,
            receivedMessageNumber,
            previousSendingChainLength,
            rootChain.info,
            maxSkip,
        )

    @ExperimentalStdlibApi
    constructor(keyPair: KeyPair?, remotePublicKey: Key?, sharedSecret: ByteArray, maxSkip: Int, info: String, messageKeyCache: MessageKeyCache?, sodium: LazySodiumAndroid?) {
        require(sharedSecret.size == 32)

        this.sodium = sodium ?: LazySodiumAndroid(SodiumAndroid(), Base64Coder)

        val keyPair = keyPair ?: this.sodium.cryptoKxKeypair()

        this.maxSkip = maxSkip
        this.rootChain = RootChain(keyPair, remotePublicKey, rootKey = Key.fromBytes(sharedSecret), info = info, sodium = this.sodium)
        this.sendingChain = MessageChain(sodium = this.sodium)
        this.receivingChain = MessageChain(sodium = this.sodium)

        this.sendMessageNumber = 0
        this.receivedMessageNumber = 0
        this.previousSendingChainLength = 0
        this.messageKeyCache = messageKeyCache

        if (remotePublicKey != null) {
            sendingChain.chainKey = rootChain.ratchetStep(Side.SENDING)
        }
    }

    @ExperimentalStdlibApi
    constructor(sessionState: SessionState, messageKeyCache: MessageKeyCache?, sodium: LazySodiumAndroid?) {
        this.sodium = sodium ?: LazySodiumAndroid(SodiumAndroid(), Base64Coder)

        this.maxSkip = sessionState.maxSkip

        this.rootChain = RootChain(sessionState.rootChainKeyPair, sessionState.rootChainRemotePublicKey, sessionState.rootKey, sessionState.info, sodium = this.sodium)
        this.sendingChain = MessageChain(sessionState.sendingChainKey, sodium = this.sodium)
        this.receivingChain = MessageChain(sessionState.receivingChainKey, sodium = this.sodium)
        this.sendMessageNumber = sessionState.sendMessageNumber
        this.receivedMessageNumber = sessionState.receivedMessageNumber
        this.previousSendingChainLength = sessionState.previousSendingChainLength
        this.messageKeyCache = messageKeyCache
    }

    @ExperimentalUnsignedTypes
    fun encrypt(plaintext: ByteArray, associatedData: ByteArray? = null): Message {
        val messageKey = sendingChain.nextMessageKey()
        val header = Header(rootChain.keyPair.publicKey, previousSendingChainLength, sendMessageNumber)

        sendMessageNumber++

        var headerData = header.bytes().asByteArray()
        associatedData?.let { headerData += it }

        val nonce = sodium.nonce(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES)
        val cipher = ByteArray(plaintext.size + AEAD.XCHACHA20POLY1305_IETF_ABYTES)
        sodium.cryptoAeadXChaCha20Poly1305IetfEncrypt(cipher, null, plaintext, plaintext.size.toLong(), headerData, headerData.size.toLong(), null, nonce, messageKey.asBytes)

        val nonceAndCipher = nonce + cipher
        return Message(header, nonceAndCipher)
    }

    @ExperimentalUnsignedTypes
    @ExperimentalStdlibApi
    suspend fun decrypt(message: Message, associatedData: ByteArray? = null): ByteArray {
        messageKeyCache?.getMessageKey(message.header.messageNumber, message.header.publicKey.asBytes)?.let {
            return decrypt(message, Key.fromBytes(it), associatedData)
        }

        if (message.header.publicKey == rootChain.remotePublicKey &&
                message.header.messageNumber < receivedMessageNumber) {
            throw DRError.DiscardOldMessageException()
        }

        val remotePublicKey = rootChain.remotePublicKey ?: message.header.publicKey
        if (message.header.publicKey != rootChain.remotePublicKey) {
            skipReceivedMessages(message.header.numberOfMessagesInPreviousSendingChain, remotePublicKey)
            doubleRatchetStep(message.header.publicKey)
        }

        skipReceivedMessages(message.header.messageNumber, message.header.publicKey)

        val messageKey = receivingChain.nextMessageKey()
        val plaintext = decrypt(message, messageKey, associatedData)
        receivedMessageNumber++
        return plaintext
    }

    @ExperimentalUnsignedTypes
    private fun decrypt(message: Message, key: Key, associatedData: ByteArray?): ByteArray {
        var headerData = message.header.bytes().toByteArray()
        associatedData?.let { headerData += it }

        val nonce = message.cipher.sliceArray(0 until AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES)
        val cipher = message.cipher.sliceArray(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES until message.cipher.size)

        val plaintextLength = cipher.size - AEAD.XCHACHA20POLY1305_IETF_ABYTES
        val plaintext = ByteArray(plaintextLength)
        sodium.cryptoAeadXChaCha20Poly1305IetfDecrypt(plaintext, null, null, cipher, cipher.size.toLong(), headerData, headerData.size.toLong(), nonce, key.asBytes)
        return plaintext
    }

    @ExperimentalStdlibApi
    private suspend fun skipReceivedMessages(nextMessageNumber: Int, remotePublicKey: Key) {
        if (nextMessageNumber - receivedMessageNumber > maxSkip) {
            throw DRError.ExceededMaxSkipException()
        }

        while (receivedMessageNumber < nextMessageNumber) {
            val skippedMessageKey = receivingChain.nextMessageKey()
            messageKeyCache?.add(skippedMessageKey.asBytes, receivedMessageNumber, remotePublicKey.asBytes)
            receivedMessageNumber++
        }
    }

    private fun doubleRatchetStep(publicKey: Key) {
        previousSendingChainLength = sendMessageNumber
        sendMessageNumber = 0
        receivedMessageNumber = 0

        rootChain.remotePublicKey = publicKey

        receivingChain.chainKey = rootChain.ratchetStep(Side.RECEIVING)

        rootChain.keyPair = sodium.cryptoKxKeypair()

        sendingChain.chainKey = rootChain.ratchetStep(Side.SENDING)
    }
}