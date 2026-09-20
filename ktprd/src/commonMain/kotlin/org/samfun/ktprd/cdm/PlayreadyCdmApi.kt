@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktprd.cdm

import okio.ByteString
import org.samfun.ktprd.core.PlayreadyKey
import org.samfun.ktprd.core.WrmHeader
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * The operations a PlayReady CDM offers, whether it runs in this process or behind an HTTP server.
 *
 * [PlayreadyCdm] implements this locally; `ktprd-remote`'s `RemotePlayreadyCdm` implements it
 * against a pyplayready-compatible server, so callers can swap one for the other.
 *
 * This mirrors ktvine's `CdmApi` in shape — suspending throughout, sessions addressed by an okio
 * `ByteString` — but not in signature: a PlayReady challenge is a SOAP document rather than a
 * protobuf message, and there is no privacy mode or service certificate in this protocol.
 */
public interface PlayreadyCdmApi {

    /**
     * Open a session.
     * @return the session identifier to pass to every other call
     */
    public suspend fun open(): ByteString

    /** Close a session and release its slot. */
    public suspend fun close(sessionId: ByteString)

    /**
     * Build a signed license challenge for [wrmHeader].
     *
     * @param revocationLists the revocation lists to advertise; `null` advertises none
     * @return the SOAP document to POST to the license server
     */
    public suspend fun getLicenseChallenge(
        sessionId: ByteString,
        wrmHeader: WrmHeader,
        revocationLists: List<Uuid>? = null,
    ): String

    /** Verify and parse a license response, loading its keys into the session. */
    public suspend fun parseLicense(sessionId: ByteString, licenseMessage: String)

    /** The decrypted keys for the session. */
    public suspend fun getKeys(sessionId: ByteString): List<PlayreadyKey>
}
