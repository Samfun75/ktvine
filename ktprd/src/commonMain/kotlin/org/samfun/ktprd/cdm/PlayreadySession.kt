package org.samfun.ktprd.cdm

import kotlinx.coroutines.sync.Mutex
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.samfun.ktprd.core.EccKey
import org.samfun.ktprd.core.PlayreadyKey
import org.samfun.ktprd.soap.XmlKey
import org.samfun.ktvine.crypto.randomBytes

/**
 * Per-session state.
 *
 * The [xmlKey] is generated once, on the first challenge, and then retained: a license response is
 * decrypted against the key its challenge carried, so a session that rolled a new one per challenge
 * could not read its own licenses back. Deferring it keeps [PlayreadyCdm.open] free of a P-256
 * scalar multiplication for a session that never builds a challenge.
 */
internal class PlayreadySession(val number: Int) {
    val lock: Mutex = Mutex()

    val id: ByteString = randomBytes(16).toByteString()

    val xmlKey: XmlKey by lazy { XmlKey.generate() }

    /** Recorded when a challenge is built, so [PlayreadyCdm.parseLicense] can refuse without one. */
    var signingKey: EccKey? = null
    var encryptionKey: EccKey? = null

    val keys: MutableList<PlayreadyKey> = mutableListOf()
}
