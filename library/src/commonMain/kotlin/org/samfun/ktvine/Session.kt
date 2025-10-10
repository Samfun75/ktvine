package org.samfun.ktvine

import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.crypto.randomBytes
import org.samfun.ktvine.proto.SignedDrmCertificate

class Session(val number: Int) {
    val id: ByteString = randomBytes(16).toByteString()
    var serviceCertificate: SignedDrmCertificate? = null
    val context: MutableMap<ByteString, Pair<ByteArray, ByteArray>> = mutableMapOf()
    val keys: MutableList<Key> = mutableListOf()
}
