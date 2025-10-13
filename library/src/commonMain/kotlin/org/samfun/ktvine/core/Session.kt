package org.samfun.ktvine.core

import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.crypto.randomBytes
import org.samfun.ktvine.proto.SignedDrmCertificate

/** Internal session state used by [org.samfun.ktvine.cdm.Cdm]. */
class Session(val number: Int) {
    /** Randomly generated session id. */
    val id: ByteString = randomBytes(16).toByteString()
    /** Optional service certificate configured for privacy mode. */
    var serviceCertificate: SignedDrmCertificate? = null
    /** Request contexts used to derive keys during license parsing, keyed by request_id. */
    val context: MutableMap<ByteString, Pair<ByteArray, ByteArray>> = mutableMapOf()
    /** Decrypted keys available after a successful [org.samfun.ktvine.cdm.Cdm.parseLicense] call. */
    val keys: MutableList<Key> = mutableListOf()
}