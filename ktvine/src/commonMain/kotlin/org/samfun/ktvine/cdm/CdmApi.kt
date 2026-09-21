package org.samfun.ktvine.cdm

import okio.ByteString
import org.samfun.ktvine.core.Key
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.proto.License
import org.samfun.ktvine.proto.LicenseRequest
import org.samfun.ktvine.proto.LicenseType

/**
 * The operations a CDM offers, whether it runs in this process or behind an HTTP server.
 *
 * [Cdm] implements this locally. `ktvine-remote`'s `RemoteCdm` implements it against a
 * pywidevine-compatible server, so callers can swap one for the other.
 *
 * This is deliberately the *common* subset. Things a remote server has no endpoint for —
 * reading back the parsed `License`, entitlement key unwrapping — stay on [Cdm].
 */
public interface CdmApi {

    /**
     * Open a session.
     * @return the session identifier to pass to every other call
     */
    public suspend fun open(): ByteString

    /** Close a session and release its slot. */
    public suspend fun close(sessionId: ByteString)

    /**
     * Set or clear the service certificate used for privacy mode.
     * @return the certificate's provider id, or the previous one when clearing
     */
    public suspend fun setServiceCertificate(sessionId: ByteString, certificateBase64: String?): String?

    /** The service certificate currently set for the session, Base64-encoded, or `null`. */
    public suspend fun getServiceCertificateBase64(sessionId: ByteString): String?

    /**
     * Build a signed license request for [pssh].
     * @return the serialized `SignedMessage(LICENSE_REQUEST)` to POST to a license server
     */
    public suspend fun getLicenseChallenge(
        sessionId: ByteString,
        pssh: PSSH,
        licenseType: LicenseType = LicenseType.STREAMING,
        privacyMode: Boolean = true,
        requestType: LicenseRequest.RequestType = LicenseRequest.RequestType.NEW,
    ): ByteArray

    /** Verify and parse a license response, loading its keys into the session. */
    public suspend fun parseLicense(sessionId: ByteString, licenseMessage: ByteArray)

    /** The decrypted keys for the session, optionally filtered by type. */
    public suspend fun getKeys(sessionId: ByteString, type: License.KeyContainer.KeyType? = null): List<Key>
}
