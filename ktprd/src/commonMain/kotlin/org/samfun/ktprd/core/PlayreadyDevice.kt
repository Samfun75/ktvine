package org.samfun.ktprd.core

import okio.FileSystem
import okio.Path
import okio.Path.Companion.toPath
import org.samfun.ktprd.bcert.CertificateChain
import org.samfun.ktprd.utils.ByteReader
import org.samfun.ktprd.utils.ByteWriter
import org.samfun.ktprd.utils.InvalidPrdException
import kotlin.io.encoding.Base64

/**
 * A provisioned PlayReady device — the contents of a `.prd` file.
 *
 * A device is a certificate chain whose leaf attests to two key pairs: [signingKey], which signs
 * license challenges, and [encryptionKey], to which the server encrypts content-key material. A v3
 * device also keeps the [groupKey] that issued the leaf, which is what lets it be reprovisioned.
 */
public class PlayreadyDevice internal constructor(
    /** The issuing group key. Absent in a v2 device, which therefore cannot be reprovisioned. */
    public val groupKey: EccKey?,
    public val encryptionKey: EccKey,
    public val signingKey: EccKey,
    public val groupCertificate: CertificateChain,
) {
    /** `150`, `2000` or `3000`, read from the chain's leaf. */
    public val securityLevel: Int = groupCertificate.securityLevel
        ?: throw InvalidPrdException("Device certificate chain declares no security level")

    /**
     * A filesystem-safe name for this device, as `manufacturer_model_slNNNN`.
     *
     * This is the naming a `.prd` is conventionally stored under, so tooling that writes devices
     * out lands on the same filename the reference implementation would pick.
     */
    public val name: String
        get() {
            val label = "${groupCertificate.name.orEmpty()}_sl$securityLevel"
            return label
                .filter { it.isLetterOrDigit() || it == '_' || it == '-' || it == ' ' }
                .trim()
                .lowercase()
                .replace(' ', '_')
        }

    override fun toString(): String =
        "PlayreadyDevice(name=$name, securityLevel=$securityLevel, provisioned=${groupKey != null})"

    /**
     * Serialize back to a `.prd` blob.
     *
     * @param version `3` keeps the group key, `2` drops it
     * @throws InvalidPrdException if v3 is asked for on a device that has no group key
     */
    public fun dumps(version: Int = CURRENT_VERSION): ByteArray {
        val certificate = groupCertificate.dumps()
        val writer = ByteWriter().bytes(MAGIC).u8(version)

        when (version) {
            3 -> {
                val group = groupKey ?: throw InvalidPrdException(
                    "This device has no group key, so it can only be written as version 2",
                )
                writer.bytes(group.dumps())
                    .bytes(encryptionKey.dumps())
                    .bytes(signingKey.dumps())
                    .u32(certificate.size)
                    .bytes(certificate)
            }

            2 -> writer.u32(certificate.size)
                .bytes(certificate)
                .bytes(encryptionKey.dumps())
                .bytes(signingKey.dumps())

            else -> throw InvalidPrdException("Cannot write a PlayReady device as version $version")
        }

        return writer.toByteArray()
    }

    public fun dumpsBase64(): String = Base64.encode(dumps())

    /**
     * Write this device to [path], creating parent directories.
     *
     * [fileSystem] is explicit because `FileSystem.SYSTEM` is not part of okio's common API; pass
     * it from a platform source set, or a fake in tests.
     */
    public fun dump(path: Path, fileSystem: FileSystem, version: Int = CURRENT_VERSION) {
        path.parent?.let { fileSystem.createDirectories(it) }
        fileSystem.write(path) { write(dumps(version)) }
    }

    /** Write this device to [path], creating parent directories. */
    public fun dump(path: String, fileSystem: FileSystem, version: Int = CURRENT_VERSION): Unit =
        dump(path.toPath(), fileSystem, version)

    public companion object {
        private val MAGIC = byteArrayOf('P'.code.toByte(), 'R'.code.toByte(), 'D'.code.toByte())

        /** The version this library writes by default. */
        public const val CURRENT_VERSION: Int = 3

        /**
         * Parse a `.prd` blob.
         *
         * Version 1 is recognised and rejected: it predates device-specific signing and encryption
         * keys, so there is nothing in it to build a CDM from.
         *
         * @throws InvalidPrdException if the magic, version or lengths are wrong
         */
        public fun loads(data: ByteArray): PlayreadyDevice {
            val reader = ByteReader(data)

            val magic = reader.bytes(3, "PRD magic")
            if (!magic.contentEquals(MAGIC)) {
                throw InvalidPrdException("Data does not seem to be a PlayReady device (bad magic)")
            }

            return when (val version = reader.u8("PRD version")) {
                3 -> {
                    val groupKey = EccKey.loads(reader.bytes(EccKey.BLOB_SIZE, "group key"))
                    val encryptionKey = EccKey.loads(reader.bytes(EccKey.BLOB_SIZE, "encryption key"))
                    val signingKey = EccKey.loads(reader.bytes(EccKey.BLOB_SIZE, "signing key"))
                    PlayreadyDevice(groupKey, encryptionKey, signingKey, readChain(reader))
                }

                2 -> {
                    val chain = readChain(reader)
                    val encryptionKey = EccKey.loads(reader.bytes(EccKey.BLOB_SIZE, "encryption key"))
                    val signingKey = EccKey.loads(reader.bytes(EccKey.BLOB_SIZE, "signing key"))
                    PlayreadyDevice(null, encryptionKey, signingKey, chain)
                }

                1 -> throw InvalidPrdException(
                    "PlayReady device is version 1, which carries no signing or encryption key",
                )

                else -> throw InvalidPrdException("Unsupported PlayReady device version $version")
            }
        }

        /** Parse a Base64-encoded `.prd` blob. */
        public fun loads(data: String): PlayreadyDevice = loads(
            try {
                Base64.decode(data.trim())
            } catch (e: Throwable) {
                throw InvalidPrdException("PlayReady device is not valid Base64, $e")
            },
        )

        /**
         * Read a `.prd` file from [path].
         *
         * [fileSystem] is explicit because `FileSystem.SYSTEM` is not part of okio's common API;
         * pass it from a platform source set, or a fake in tests.
         */
        public fun load(path: Path, fileSystem: FileSystem): PlayreadyDevice =
            loads(fileSystem.read(path) { readByteArray() })

        /** Read a `.prd` file from [path]. */
        public fun load(path: String, fileSystem: FileSystem): PlayreadyDevice = load(path.toPath(), fileSystem)

        /**
         * Assemble a device from its raw parts, as `create-device` style provisioning produces.
         *
         * @throws InvalidPrdException if the chain's leaf does not hold both public keys
         */
        public fun of(
            groupKey: EccKey?,
            encryptionKey: EccKey,
            signingKey: EccKey,
            groupCertificate: CertificateChain,
        ): PlayreadyDevice {
            val leaf = groupCertificate.get(0)
            if (!leaf.containsPublicKey(encryptionKey.publicBytes)) {
                throw InvalidPrdException("The certificate chain's leaf does not hold this encryption key")
            }
            if (!leaf.containsPublicKey(signingKey.publicBytes)) {
                throw InvalidPrdException("The certificate chain's leaf does not hold this signing key")
            }
            return PlayreadyDevice(groupKey, encryptionKey, signingKey, groupCertificate)
        }

        private fun readChain(reader: ByteReader): CertificateChain {
            val length = reader.countOf(reader.u32("group certificate length"), "group certificate")
            return CertificateChain.loads(reader.bytes(length, "group certificate"))
        }
    }
}
