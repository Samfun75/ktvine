@file:OptIn(ExperimentalUuidApi::class, ExperimentalTime::class)

package org.samfun.ktprd.cdm

import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okio.ByteString
import org.samfun.ktprd.bcert.CertificateChain
import org.samfun.ktprd.core.EccKey
import org.samfun.ktprd.core.PlayreadyDevice
import org.samfun.ktprd.core.PlayreadyKey
import org.samfun.ktprd.core.WrmHeader
import org.samfun.ktprd.crypto.EcPoint
import org.samfun.ktprd.revocation.RevocationList
import org.samfun.ktprd.revocation.RevocationStore
import org.samfun.ktprd.soap.ChallengeBuilder
import org.samfun.ktprd.soap.LicenseResponse
import org.samfun.ktprd.soap.RevocationListVersion
import org.samfun.ktprd.soap.SoapMessage
import org.samfun.ktprd.utils.InvalidLicenseResponseException
import org.samfun.ktprd.utils.KtprdException
import org.samfun.ktprd.utils.KtprdLog
import org.samfun.ktvine.crypto.randomBytes
import org.samfun.ktvine.utils.InvalidSessionException
import org.samfun.ktvine.utils.TooManySessionsException
import kotlin.time.Clock
import kotlin.time.ExperimentalTime
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * A PlayReady Content Decryption Module.
 *
 * Build one from a `.prd` with [fromDevice], open a session, hand a `WRMHEADER` to
 * [getLicenseChallenge], POST the result to the license server yourself, feed the response to
 * [parseLicense], and read the content keys out with [getKeys].
 *
 * Like ktvine's Widevine `Cdm`, this ships no HTTP client: moving bytes to and from a license
 * server is the caller's business.
 */
public class PlayreadyCdm internal constructor(
    public val securityLevel: Int,
    private val certificateChain: CertificateChain?,
    private val encryptionKey: EccKey?,
    private val signingKey: EccKey?,
    public val clientVersion: String = DEFAULT_CLIENT_VERSION,
    private val revocationStore: RevocationStore = RevocationStore.None,
    // A seam for the offline exchange test, which has to play the server and therefore needs a
    // server key it holds the private half of. Never varied in production.
    private val wmrmPublicPoint: EcPoint = WMRM_PUBLIC_POINT,
) : PlayreadyCdmApi {

    private val sessions = linkedMapOf<ByteString, PlayreadySession>()

    private var sessionCounter = 0

    // Guards the session map and the counter. A session's own lock guards its contents; the two
    // are never held at once, so they cannot deadlock.
    private val sessionsLock = Mutex()

    private suspend fun session(sessionId: ByteString): PlayreadySession = sessionsLock.withLock { sessions[sessionId] }
        ?: throw InvalidSessionException("Session identifier ${sessionId.hex()} is invalid.")

    override suspend fun open(): ByteString = sessionsLock.withLock {
        // >= rather than >, so the cap is the number of sessions and not one more than it.
        if (sessions.size >= MAX_NUM_OF_SESSIONS) {
            throw TooManySessionsException("Too many Sessions open ($MAX_NUM_OF_SESSIONS).")
        }
        val session = PlayreadySession(++sessionCounter)
        sessions[session.id] = session
        session.id
    }

    override suspend fun close(sessionId: ByteString) {
        sessionsLock.withLock {
            sessions.remove(sessionId)
                ?: throw InvalidSessionException("Session identifier ${sessionId.hex()} is invalid.")
        }
    }

    override suspend fun getLicenseChallenge(
        sessionId: ByteString,
        wrmHeader: WrmHeader,
        revocationLists: List<Uuid>?,
    ): String {
        val session = session(sessionId)

        val chain = certificateChain
            ?: throw KtprdException("This CDM has no certificate chain, so it cannot build a challenge")
        val signing = signingKey
            ?: throw KtprdException("This CDM has no signing key, so it cannot build a challenge")
        val encryption = encryptionKey
            ?: throw KtprdException("This CDM has no encryption key, so it cannot read a license back")

        return session.lock.withLock {
            session.signingKey = signing
            session.encryptionKey = encryption

            ChallengeBuilder.build(
                wrmHeader = wrmHeader.xml,
                protocolVersion = wrmHeader.protocolVersion,
                certificateChain = chain,
                signingKey = signing,
                xmlKey = session.xmlKey,
                wmrmPublicPoint = wmrmPublicPoint,
                clientVersion = clientVersion,
                revocationLists = revocationLists?.map { RevocationListVersion(it, storedVersion(it)) },
                nonce = randomBytes(NONCE_SIZE),
                clientTimeSeconds = Clock.System.now().epochSeconds,
            )
        }
    }

    override suspend fun parseLicense(sessionId: ByteString, licenseMessage: String) {
        val session = session(sessionId)

        if (licenseMessage.isBlank()) throw InvalidLicenseResponseException("Cannot parse an empty license message")

        val response = session.lock.withLock {
            val encryption = session.encryptionKey
                ?: throw InvalidSessionException("Cannot parse a license without first building a challenge")

            SoapMessage.raiseFaults(licenseMessage)

            val response = LicenseResponse.parse(licenseMessage)
            if (response.isVerifiable) response.verify()

            if (response.licenses.isEmpty()) {
                throw InvalidLicenseResponseException("License response carries no licenses")
            }

            response.xmrLicenses().forEach { session.keys += it.contentKey(encryption) }
            response
        }

        response.revocationInfo?.let { storeRevocationInfo(it) }
    }

    override suspend fun getKeys(sessionId: ByteString): List<PlayreadyKey> {
        val session = session(sessionId)
        return session.lock.withLock { session.keys.toList() }
    }

    /** The version of [listId] this client already holds, or `0` when it holds none. */
    private suspend fun storedVersion(listId: Uuid): Long =
        revocationStore.read(RevocationList.CURRENT_LIST_FILE_NAME)?.let { RevocationList.versionOf(it, listId) } ?: 0

    /** Never fatal: the keys are already recovered, and the cost is a stale version next time. */
    private suspend fun storeRevocationInfo(incoming: String) {
        try {
            val current = revocationStore.read(RevocationList.CURRENT_LIST_FILE_NAME)?.decodeToString()
            val merged = if (current == null) incoming else RevocationList.merge(current, incoming)
            revocationStore.write(RevocationList.CURRENT_LIST_FILE_NAME, merged.encodeToByteArray())
        } catch (e: Throwable) {
            KtprdLog.w { "Could not store the revocation data this license came with: $e" }
        }
    }

    public companion object {
        /** The most sessions that may be open at once. */
        public const val MAX_NUM_OF_SESSIONS: Int = 16

        /** The client version a challenge declares unless the caller overrides it. */
        public const val DEFAULT_CLIENT_VERSION: String = "10.0.16384.10011"

        private const val NONCE_SIZE = 16

        /**
         * Microsoft's WMRM server public key.
         *
         * Every license challenge encrypts its session point to this; it is the same for every
         * PlayReady server, which is why it is a constant rather than something a server sends.
         */
        internal val WMRM_PUBLIC_POINT: EcPoint = EcPoint.of(
            BigInteger.parseString("c8b6af16ee941aadaa5389b4af2c10e356be42af175ef3face93254e7b0b3d9b", 16),
            BigInteger.parseString("982b27b5cb2341326e56aa857dbfd5c634ce2cf9ea74fca8f2af5957efeea562", 16),
        )

        /**
         * Build a CDM from a provisioned device.
         *
         * @param revocationStore where to keep revocation data the server sends back; the default
         *   keeps none, so every challenge advertises version 0
         */
        public fun fromDevice(
            device: PlayreadyDevice,
            clientVersion: String = DEFAULT_CLIENT_VERSION,
            revocationStore: RevocationStore = RevocationStore.None,
        ): PlayreadyCdm = PlayreadyCdm(
            securityLevel = device.securityLevel,
            certificateChain = device.groupCertificate,
            encryptionKey = device.encryptionKey,
            signingKey = device.signingKey,
            clientVersion = clientVersion,
            revocationStore = revocationStore,
        )
    }
}
