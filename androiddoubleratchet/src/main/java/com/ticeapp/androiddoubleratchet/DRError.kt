package com.ticeapp.androiddoubleratchet

sealed class DRError: Exception() {
    class RemotePublicKeyMissingException: DRError()
    class ChainKeyMissingException: DRError()
    class MessageChainRatchetStepFailed: DRError()
    class ExceededMaxSkipException: DRError()
    class DiscardOldMessageException: DRError()
}