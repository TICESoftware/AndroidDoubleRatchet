package com.ticeapp.androiddoubleratchet

import com.goterl.lazycode.lazysodium.utils.Key
import com.goterl.lazycode.lazysodium.utils.KeyPair

data class SessionState(val rootKey: Key, val rootChainKeyPair: KeyPair, val rootChainRemotePublicKey: Key?, val sendingChainKey: ChainKey?, val receivingChainKey: ChainKey?, val sendMessageNumber: Int, val receivedMessageNumber: Int, val previousSendingChainLength: Int, val messageKeyCacheState: MessageKeyCacheState, val info: String, val maxSkip: Int, val maxCache: Int)