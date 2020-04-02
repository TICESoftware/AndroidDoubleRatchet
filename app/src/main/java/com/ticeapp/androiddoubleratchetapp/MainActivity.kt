package com.ticeapp.androiddoubleratchetapp

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid
import com.goterl.lazycode.lazysodium.utils.Key
import com.ticeapp.androiddoubleratchet.DRError
import com.ticeapp.androiddoubleratchet.DoubleRatchet
import com.ticeapp.androiddoubleratchet.Header
import com.ticeapp.androiddoubleratchet.Message

class MainActivity : AppCompatActivity() {

    @ExperimentalStdlibApi
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        testLibrary()
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
}
