package com.ticeapp.androiddoubleratchetapp

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid
import com.goterl.lazycode.lazysodium.utils.Key
import com.goterl.lazycode.lazysodium.utils.KeyPair
import com.ticeapp.androiddoubleratchet.DRError
import com.ticeapp.androiddoubleratchet.DoubleRatchet
import com.ticeapp.androiddoubleratchet.Header
import com.ticeapp.androiddoubleratchet.Message
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.json.*

class MainActivity : AppCompatActivity() {

    @ExperimentalStdlibApi
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        testLibrary()
        testGenerateKeyPair()
        testInitiateConversation()
        testProcessFirstMessage()
    }

    @ExperimentalStdlibApi
    private fun testLibrary() {
        testRatchetSteps()
        testUnidirectionalConversation()
        testLostMessages()
        testLostMessagesAndRatchetStep()
        testExceedMaxSkipMessages()
        testExceedMaxCacheMessageKeys()
        testEncryptAssociatedData()
        testReinitializeSession()
        testMessageHeaderEncoding()
    }

    @ExperimentalStdlibApi
    private fun testRatchetSteps() {
        val sodium = LazySodiumAndroid(SodiumAndroid())

        val sharedSecret = sodium.sodiumHex2Bin("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
        val info = "DoubleRatchetTest"

        val bob = DoubleRatchet(null, null, sharedSecret, 20, 20, info)
        val alice = DoubleRatchet(null, bob.publicKey, sharedSecret, 20, 20, info)

        val bobPublicKeySnapshot = bob.publicKey

        val message = "aliceToBob".encodeToByteArray()
        val encryptedMessage = alice.encrypt(message)
        val decryptedMessage = bob.decrypt(encryptedMessage)

        if (!decryptedMessage.contentEquals(message) ||
                bob.publicKey == bobPublicKeySnapshot) {
            throw Exception("Test failed")
        }

        val alicePublicKeySnapshot = alice.publicKey

        val response = "bobToAlice".encodeToByteArray()
        val encryptedResponse = bob.encrypt(response)
        val decryptedResponse = alice.decrypt(encryptedResponse)

        if (!decryptedResponse.contentEquals(response) ||
            alice.publicKey == alicePublicKeySnapshot) {
            throw Exception("Test failed")
        }
    }

    @ExperimentalStdlibApi
    private fun testUnidirectionalConversation() {
        val sodium = LazySodiumAndroid(SodiumAndroid())

        val sharedSecret = sodium.sodiumHex2Bin("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
        val info = "DoubleRatchetTest"

        val bob = DoubleRatchet(null, null, sharedSecret, 20, 20, info)
        val alice = DoubleRatchet(null, bob.publicKey, sharedSecret, 20, 20, info)

        val alicePublicKeySnapshot = alice.publicKey

        for (i in 0..1) {
            val message = "aliceToBob $i".encodeToByteArray()
            val encryptedMessage = alice.encrypt(message)
            val decryptedMessage = bob.decrypt(encryptedMessage)

            if (!decryptedMessage.contentEquals(message)) {
                throw Exception("Test failed")
            }
        }

        if (alice.publicKey != alicePublicKeySnapshot) {
            throw Exception("Test failed")
        }
    }

    @ExperimentalStdlibApi
    private fun testLostMessages() {
        val sodium = LazySodiumAndroid(SodiumAndroid())

        val sharedSecret = sodium.sodiumHex2Bin("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
        val info = "DoubleRatchetTest"

        val bob = DoubleRatchet(null, null, sharedSecret, 20, 20, info)
        val alice = DoubleRatchet(null, bob.publicKey, sharedSecret, 20, 20, info)

        val delayedMessages: MutableList<Message> = mutableListOf()

        for (i in 0..2) {
            val message = "aliceToBob $i".encodeToByteArray()
            val encryptedMessage = alice.encrypt(message)
            delayedMessages.add(encryptedMessage)
        }

        for (i in 2 downTo 0) {
            val decryptedMessage = bob.decrypt(delayedMessages[i])

            if (!decryptedMessage.contentEquals("aliceToBob $i".encodeToByteArray())) {
                throw Exception("Test failed")
            }
        }
    }

    @ExperimentalStdlibApi
    private fun testLostMessagesAndRatchetStep() {
        val sodium = LazySodiumAndroid(SodiumAndroid())

        val sharedSecret = sodium.sodiumHex2Bin("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
        val info = "DoubleRatchetTest"

        val bob = DoubleRatchet(null, null, sharedSecret, 20, 20, info)
        val alice = DoubleRatchet(null, bob.publicKey, sharedSecret, 20, 20, info)

        val message = "aliceToBob".encodeToByteArray()

        for (i in 0..1) {
            val encryptedMessage = alice.encrypt(message)
            bob.decrypt(encryptedMessage)
        }

        val delayedMessages: MutableList<Message> = mutableListOf()
        for (i in 0..1) {
            if (i == 1) {
                // Ratchet step
                val encryptedMessage = bob.encrypt(message)
                alice.decrypt(encryptedMessage)
            }
            val message = "aliceToBob $i".encodeToByteArray()
            val encryptedMessage = alice.encrypt(message)
            delayedMessages.add(encryptedMessage)
        }

        val successfulMessage = "aliceToBob 2".encodeToByteArray()
        val successfulEncryptedRatchetMessage = alice.encrypt(successfulMessage)
        val successfulPlaintext = bob.decrypt(successfulEncryptedRatchetMessage)
        if (!successfulPlaintext.contentEquals(successfulMessage)) {
            throw Exception("Test failed")
        }

        for (i in 1 downTo 0) {
            val decryptedMessage = bob.decrypt(delayedMessages[i])
            if (!decryptedMessage.contentEquals("aliceToBob $i".encodeToByteArray())) {
                throw Exception("Test failed")
            }
        }
    }

    @ExperimentalStdlibApi
    private fun testExceedMaxSkipMessages() {
        val sodium = LazySodiumAndroid(SodiumAndroid())

        val sharedSecret = sodium.sodiumHex2Bin("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
        val info = "DoubleRatchetTest"

        val bob = DoubleRatchet(null, null, sharedSecret, 1, 2, info)
        val alice = DoubleRatchet(null, bob.publicKey, sharedSecret, 1, 2, info)

        for (i in 0..1) {
            alice.encrypt("Message".encodeToByteArray())
        }

        val encryptedMessage = alice.encrypt("Message".encodeToByteArray())

        try {
            bob.decrypt(encryptedMessage)
        } catch (e: DRError.ExceededMaxSkipException) {
            return
        }

        throw Exception("Test failed")
    }

    @ExperimentalStdlibApi
    private fun testExceedMaxCacheMessageKeys() {
        val sodium = LazySodiumAndroid(SodiumAndroid())

        val sharedSecret = sodium.sodiumHex2Bin("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
        val info = "DoubleRatchetTest"

        val bob = DoubleRatchet(null, null, sharedSecret, 20, 1, info)
        val alice = DoubleRatchet(null, bob.publicKey, sharedSecret, 20, 1, info)

        val delayedMessages: MutableList<Message> = mutableListOf()

        for (i in 0..2) {
            val message = "aliceToBob $i".encodeToByteArray()
            val encryptedMessage = alice.encrypt(message)
            delayedMessages.add(encryptedMessage)
        }

        for (i in 2 downTo 1) {
            val plaintext = bob.decrypt(delayedMessages[i])

            if (!plaintext.contentEquals("aliceToBob $i".encodeToByteArray())) {
                throw Exception("Test failed")
            }
        }

        try {
            bob.decrypt(delayedMessages[0])
        } catch (e: DRError.DiscardOldMessageException) {
            return
        }

        throw Exception("Test failed")
    }

    @ExperimentalStdlibApi
    private fun testEncryptAssociatedData() {
        val sodium = LazySodiumAndroid(SodiumAndroid())

        val sharedSecret = sodium.sodiumHex2Bin("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
        val info = "DoubleRatchetTest"

        val bob = DoubleRatchet(null, null, sharedSecret, 20, 20, info)
        val alice = DoubleRatchet(null, bob.publicKey, sharedSecret, 20, 20, info)

        val message = "aliceToBob".encodeToByteArray()
        val associatedData = "AD".encodeToByteArray()
        val encryptedMessage = alice.encrypt(message, associatedData)
        val decryptedMessage = bob.decrypt(encryptedMessage, associatedData)

        if (!decryptedMessage.contentEquals(message)) {
            throw Exception("Test failed")
        }
    }

    @ExperimentalStdlibApi
    private fun testReinitializeSession() {
        val sodium = LazySodiumAndroid(SodiumAndroid())

        val sharedSecret = sodium.sodiumHex2Bin("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
        val info = "DoubleRatchetTest"

        var bob = DoubleRatchet(null, null, sharedSecret, 20, 20, info)
        var alice = DoubleRatchet(null, bob.publicKey, sharedSecret, 20, 20, info)

        val message = "aliceToBob".encodeToByteArray()
        val encryptedMessage = alice.encrypt(message)
        val decryptedMessage = bob.decrypt(encryptedMessage)

        bob = DoubleRatchet(bob.sessionState)
        alice = DoubleRatchet(alice.sessionState)

        val messageAliceToBob = "aliceToBob".encodeToByteArray()
        val encryptedMessageAliceToBob = alice.encrypt(messageAliceToBob)
        val plaintextAliceToBob = bob.decrypt(encryptedMessageAliceToBob)

        val messageBobToAlice = "bobToAlice".encodeToByteArray()
        val encryptedMessageBobToAlice = bob.encrypt(messageBobToAlice)
        val plaintextBobToAlice = alice.decrypt(encryptedMessageBobToAlice)

        if (!plaintextAliceToBob.contentEquals(messageAliceToBob) ||
            !plaintextBobToAlice.contentEquals(messageBobToAlice)) {
            throw Exception("Test failed")
        }
    }

    private fun testMessageHeaderEncoding() {
        val sodium = LazySodiumAndroid(SodiumAndroid())

        val pubKey = Key.fromHexString("0efd0d78c9ba26b39588848ddf69b02807fb85916c2b004d7af759f932544443")
        val header = Header(pubKey, 123456789, 987654321)

        val headerBytesAre = header.bytes()
        val headerBytesShouldBe = sodium.sodiumHex2Bin("0efd0d78c9ba26b39588848ddf69b02807fb85916c2b004d7af759f93254444300000000075bcd15000000003ade68b1")

        if (!headerBytesShouldBe.contentEquals(headerBytesAre)) {
            throw Exception("Test failed")
        }
    }

    private fun testGenerateKeyPair() {
        val sodium = LazySodiumAndroid(SodiumAndroid())

        val keyPair = sodium.cryptoKxKeypair()
        val keyPairString = Json.stringify(KeyPairSerializer, keyPair)

        println(keyPairString)
    }

    @ExperimentalStdlibApi
    private fun testInitiateConversation() {
        val ownKeyPairString = """{"secretKey":"326873752B2547AEB5C2A652FEDAC5EBFD652E0F944F0AF1E66C640985A627A9","publicKey":"D3A6E65CD63116F38C361F0CC857216E792552D740C79F603D23262C6DC20F56"}"""
        val otherKeyPairString = """{"secretKey":"e0f8e1fb1e2a33e63d4e67a1488dd2c802d79d8c4ab2fc2684ab2cb4175b55b2","publicKey":"9258fd6cf6ee77f0518d91265438a02a60c71a449a56b9ce4ceec0015b17e35a"}"""
        val sharedSecretString = """1208db7dad21875cf6ba8c96f8fbfae00fb4c06ab3cbd1597b635c3989b1a67a"""

        val sodium = LazySodiumAndroid(SodiumAndroid())

        val ownKeyPair = Json.parse(KeyPairSerializer, ownKeyPairString)
        val otherKeyPair = Json.parse(KeyPairSerializer, otherKeyPairString)
        val sharedSecret = sodium.sodiumHex2Bin(sharedSecretString)

        val doubleRatchet = DoubleRatchet(ownKeyPair, otherKeyPair.publicKey, sharedSecret, 20, 20, "Info")

        val firstMessage = "firstMessage".encodeToByteArray()
        val firstEncryptedMessage = doubleRatchet.encrypt(firstMessage)

        val firstEncryptedMessageString = Json.stringify(MessageSerializer, firstEncryptedMessage)

        println(firstEncryptedMessageString)
    }

    @ExperimentalStdlibApi
    private fun testProcessFirstMessage() {
        val ownKeyPairString = """{"secretKey":"326873752B2547AEB5C2A652FEDAC5EBFD652E0F944F0AF1E66C640985A627A9","publicKey":"D3A6E65CD63116F38C361F0CC857216E792552D740C79F603D23262C6DC20F56"}"""
        val sharedSecretString = """1208db7dad21875cf6ba8c96f8fbfae00fb4c06ab3cbd1597b635c3989b1a67a"""
        val firstEncryptedMessageString = """{"header":{"publicKey":"9258fd6cf6ee77f0518d91265438a02a60c71a449a56b9ce4ceec0015b17e35a","numberOfMessagesInPreviousSendingChain":0,"messageNumber":0},"cipher":"f685b57b98741d652e67a8d86df779dddbb9fcab9befa2ead084b00f906103d112b68dc3d53adaffaee22370ea50922bbb867d05"}"""

        val sodium = LazySodiumAndroid(SodiumAndroid())

        val ownKeyPair = Json.parse(KeyPairSerializer, ownKeyPairString)
        val sharedSecret = sodium.sodiumHex2Bin(sharedSecretString)
        val firstEncryptedMessage = Json.parse(MessageSerializer, firstEncryptedMessageString)

        val doubleRatchet = DoubleRatchet(ownKeyPair, null, sharedSecret, 20, 20, "Info")

        val decryptedMessage = doubleRatchet.decrypt(firstEncryptedMessage)

        if (sodium.str(decryptedMessage) != "firstMessage") {
            throw Exception("Test failed")
        }
    }

    object ByteArraySerializer: SerializationStrategy<ByteArray>, DeserializationStrategy<ByteArray> {
        override val descriptor: SerialDescriptor = PrimitiveDescriptor("ByteArrayHex", PrimitiveKind.STRING)
        override fun serialize(encoder: Encoder, value: ByteArray) = encoder.encodeString(LazySodiumAndroid(SodiumAndroid()).sodiumBin2Hex(value))
        override fun deserialize(decoder: Decoder): ByteArray = LazySodiumAndroid(SodiumAndroid()).sodiumHex2Bin(decoder.decodeString())
        override fun patch(decoder: Decoder, old: ByteArray): ByteArray = deserialize(decoder)
    }

    object KeySerializer: SerializationStrategy<Key>, DeserializationStrategy<Key> {
        override val descriptor: SerialDescriptor = PrimitiveDescriptor("Key", PrimitiveKind.STRING)
        override fun serialize(encoder: Encoder, value: Key) {
            encoder.encodeString(value.asHexString)
        }

        override fun deserialize(decoder: Decoder): Key = Key.fromHexString(decoder.decodeString())
        override fun patch(decoder: Decoder, old: Key): Key = deserialize(decoder)
    }

    object KeyPairSerializer: SerializationStrategy<KeyPair>, DeserializationStrategy<KeyPair> {
        @ImplicitReflectionSerializer
        override val descriptor: SerialDescriptor = SerialDescriptor("KeyPair") {
            element<String>("secretKey")
            element<String>("publicKey")
        }
        @ImplicitReflectionSerializer
        override fun serialize(encoder: Encoder, value: KeyPair) {
            val composite = encoder.beginStructure(descriptor)
            composite.encodeSerializableElement(descriptor, 0, KeySerializer, value.secretKey)
            composite.encodeSerializableElement(descriptor, 1, KeySerializer, value.publicKey)
            composite.endStructure(descriptor)
        }

        @ImplicitReflectionSerializer
        override fun deserialize(decoder: Decoder): KeyPair {
            val composite = decoder.beginStructure(descriptor)
            var index = composite.decodeElementIndex(descriptor)
            val secretKey = composite.decodeSerializableElement(descriptor, 0, KeySerializer)
            index = composite.decodeElementIndex(descriptor)
            val publicKey = composite.decodeSerializableElement(descriptor, 1, KeySerializer)
            index = composite.decodeElementIndex(descriptor)
            composite.endStructure(descriptor)

            return KeyPair(publicKey, secretKey)
        }
        @ImplicitReflectionSerializer
        override fun patch(decoder: Decoder, old: KeyPair): KeyPair = deserialize(decoder)
    }

    object HeaderSerializer: SerializationStrategy<Header>, DeserializationStrategy<Header> {
        @ImplicitReflectionSerializer
        override val descriptor: SerialDescriptor = SerialDescriptor("Header") {
            element<String>("publicKey")
            element<String>("numberOfMessagesInPreviousSendingChain")
            element<String>("messageNumber")
        }
        @ImplicitReflectionSerializer
        override fun serialize(encoder: Encoder, value: Header) {
            val composite = encoder.beginStructure(descriptor)
            composite.encodeSerializableElement(descriptor, 0, KeySerializer, value.publicKey)
            composite.encodeIntElement(descriptor, 1, value.numberOfMessagesInPreviousSendingChain)
            composite.encodeIntElement(descriptor, 2, value.messageNumber)
            composite.endStructure(descriptor)
        }

        @ImplicitReflectionSerializer
        override fun deserialize(decoder: Decoder): Header {
            val composite = decoder.beginStructure(descriptor)
            var index = composite.decodeElementIndex(descriptor)
            val publicKey = composite.decodeSerializableElement(descriptor, 0, KeySerializer)
            index = composite.decodeElementIndex(descriptor)
            val numberOfMessagesInPreviousSendingChain = composite.decodeIntElement(descriptor, 1)
            index = composite.decodeElementIndex(descriptor)
            val messageNumber = composite.decodeIntElement(descriptor, 2)
            index = composite.decodeElementIndex(descriptor)
            composite.endStructure(descriptor)

            return Header(publicKey, numberOfMessagesInPreviousSendingChain, messageNumber)
        }
        @ImplicitReflectionSerializer
        override fun patch(decoder: Decoder, old: Header): Header = deserialize(decoder)
    }

    object MessageSerializer: SerializationStrategy<Message>, DeserializationStrategy<Message> {
        @ImplicitReflectionSerializer
        override val descriptor: SerialDescriptor = SerialDescriptor("Message") {
            element<String>("header")
            element<String>("cipher")
        }
        @ImplicitReflectionSerializer
        override fun serialize(encoder: Encoder, value: Message) {
            val composite = encoder.beginStructure(descriptor)
            composite.encodeSerializableElement(descriptor, 0, HeaderSerializer, value.header)
            composite.encodeSerializableElement(descriptor, 1, ByteArraySerializer, value.cipher)
            composite.endStructure(descriptor)
        }

        @ImplicitReflectionSerializer
        override fun deserialize(decoder: Decoder): Message {
            val composite = decoder.beginStructure(descriptor)
            var index = composite.decodeElementIndex(descriptor)
            val header = composite.decodeSerializableElement(descriptor, 0, HeaderSerializer)
            index = composite.decodeElementIndex(descriptor)
            val cipher = composite.decodeSerializableElement(descriptor, 1, ByteArraySerializer)
            index = composite.decodeElementIndex(descriptor)
            composite.endStructure(descriptor)

            return Message(header, cipher)
        }
        @ImplicitReflectionSerializer
        override fun patch(decoder: Decoder, old: Message): Message = deserialize(decoder)
    }
}
