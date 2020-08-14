package com.ticeapp.androiddoubleratchet

import android.util.Base64
import com.goterl.lazycode.lazysodium.interfaces.MessageEncoder

object Base64Coder: MessageEncoder {
    override fun encode(cipher: ByteArray?): String = Base64.encodeToString(cipher, Base64.NO_WRAP)
    override fun decode(cipherText: String?): ByteArray = Base64.decode(cipherText, Base64.NO_WRAP)
}