# AndroidDoubleRatchet

Implementation of the <a href="https://www.signal.org/docs/specifications/doubleratchet/#external-functions">Double Ratchet</a> protocol in Kotlin for Android. The cryptographic operations are provided by <a href="https://github.com/terl/lazysodium-android.git">Lazysodium</a> entirely.

## Installation

### Jitpack
To integrate the library via jitpack add the jitpack repository to your root `build.gradle` file:

```
allprojects {
  repositories {
    ...
    maven { url  "https://dl.bintray.com/terl/lazysodium-maven" }
    maven { url 'https://jitpack.io' }
  }
}
```

You can then add the dependency to your app's `build.gradle` file where `$VERSION` specifies the specific version of the library:

```
dependencies {
  implementation 'com.github.TICESoftware:AndroidDoubleRatchet:$VERSION'
  implementation "com.goterl:lazysodium-android:4.1.0@aar"
  implementation 'net.java.dev.jna:jna:5.5.0@aar'
}
 ```


## Usage

Alice and Bob calculate a shared secret using a secure channel. After that one party can start the conversation as soon as she gets to know the public key of the other one.

```kotlin
import com.ticeapp.androiddoubleratchet.DoubleRatchet

val sharedSecret: ByteArray = ...
val info = "DoubleRatchetExample"

val bob = DoubleRatchet(keyPair = null, remotePublicKey = null, sharedSecret = sharedSecret, maxSkip = 20, maxCache = 20, info = info)

// Bob sends his public key to Alice using another channel
// sendToAlice(bob.publicKey)

val alice = DoubleRatchet(keyPair = null, remotePublicKey = bob.publicKey, sharedSecret = sharedSecret, maxSkip = 20, maxCache = 20, info = info)

// Now the conversation begins
val message = "Hello, Bob!".encodeToByteArray()
val encryptedMessage = alice.encrypt(message)
val decryptedMessage = bob.decrypt(encryptedMessage)

println(decryptedMessage.decodeToString()) // Hello, Bob!
```
