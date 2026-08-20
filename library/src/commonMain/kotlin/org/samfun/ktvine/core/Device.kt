package org.samfun.ktvine.core

import okio.Buffer
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString
import okio.FileSystem
import okio.Path
import okio.Path.Companion.toPath
import org.samfun.ktvine.proto.ClientIdentification
import org.samfun.ktvine.proto.DrmCertificate
import org.samfun.ktvine.proto.FileHashes
import org.samfun.ktvine.proto.SignedDrmCertificate
import org.samfun.ktvine.utils.KtvineLog
import org.samfun.ktvine.utils.ValueException
import org.samfun.ktvine.utils.decodeExact
import org.samfun.ktvine.utils.orDecodeError

/**
 * Kotlin Multiplatform representation of a Widevine Device file (WVD).
 * Supports the v2 structure used by pywidevine; v1 blobs can be brought forward with [migrate].
 */
public class Device(
    public val type: DeviceTypes,
    public val securityLevel: Int,
    public val flags: Map<String, Any?>,
    public val privateKeyDer: ByteArray,
    public val clientId: ClientIdentification,
    public val vmp: FileHashes?,
    public val systemId: Int,
    /**
     * The raw flags byte, preserved so [dumps] round-trips. No flags are defined yet, which
     * is why [flags] is always empty.
     */
    public val rawFlags: Int = 0,
) {
    override fun toString(): String = "Device(type=$type, securityLevel=$securityLevel, flags=$flags, " +
        "privateKeyDer=${privateKeyDer.size} bytes, systemId=$systemId)"

    /** Serialize this device back to a WVD v2 blob. */
    public fun dumps(): ByteArray = buildWvdV2(
        type = type,
        securityLevel = securityLevel,
        privateKeyDer = privateKeyDer,
        clientIdBytes = clientId.encode(),
        rawFlags = rawFlags,
    )

    /** Write this device to [path] as a WVD v2 file, creating parent directories. */
    public fun dump(path: Path, fileSystem: FileSystem = FileSystem.SYSTEM) {
        path.parent?.let { fileSystem.createDirectories(it) }
        fileSystem.write(path) { write(dumps()) }
    }

    /** Write this device to [path] as a WVD v2 file, creating parent directories. */
    public fun dump(path: String, fileSystem: FileSystem = FileSystem.SYSTEM): Unit = dump(path.toPath(), fileSystem)

    public companion object {
        private val MAGIC = byteArrayOf('W'.code.toByte(), 'V'.code.toByte(), 'D'.code.toByte())
        private const val HEADER_SIZE = 3 + 1 + 1 + 1 + 1 + 2 + 2

        /**
         * Parse a raw WVD v2 file from bytes.
         * @throws ValueException if the data is not a valid WVD v2 blob
         * @throws DecodeException if an embedded protobuf message is malformed
         */
        public fun loads(data: ByteArray): Device {
            if (data.size < HEADER_SIZE) throw ValueException("Data too short to be a WVD v2")
            var offset = 0

            // magic
            if (!data.copyOfRange(offset, offset + 3).contentEquals(MAGIC)) {
                throw ValueException("Device Data does not seem to be a WVD file (bad magic)")
            }
            offset += 3

            // version
            val version = data[offset].toInt() and 0xFF
            offset += 1
            when {
                version == 2 -> Unit
                // v0 was never used; a v0 blob is data that happens to start with the magic.
                version == 0 -> throw ValueException("Device Data does not seem to be a WVD file (v0).")
                version == 1 -> throw ValueException("WVD v1 is not supported directly, call Device.migrate() first.")
                else -> throw ValueException("Unsupported WVD version $version, only v2 is supported.")
            }

            // type
            val typeByte = data[offset].toInt() and 0xFF
            val type = when (typeByte) {
                DeviceTypes.CHROME.value -> DeviceTypes.CHROME
                DeviceTypes.ANDROID.value -> DeviceTypes.ANDROID
                else -> throw ValueException("Unknown device type byte $typeByte")
            }
            offset += 1

            // security level
            val securityLevel = data[offset].toInt() and 0xFF
            offset += 1

            // flags: one reserved byte, kept verbatim so dumps() round-trips
            val rawFlags = data[offset].toInt() and 0xFF
            offset += 1

            fun readU16(): Int {
                val v = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
                offset += 2
                return v
            }

            val privLen = readU16()
            if (offset + privLen > data.size) throw ValueException("Invalid private key length in WVD")
            val privateKey = data.copyOfRange(offset, offset + privLen)
            offset += privLen

            val clientLen = readU16()
            if (offset + clientLen > data.size) throw ValueException("Invalid client id length in WVD")
            val clientIdBytes = data.copyOfRange(offset, offset + clientLen)
            offset += clientLen

            val clientId = decodeExact(clientIdBytes, "ClientIdentification") {
                ClientIdentification.ADAPTER.decode(it)
            }

            // pywidevine fails loudly here; swallowing it hid corrupt VMP blobs.
            val vmp: FileHashes? = clientId.vmp_data?.let { vmpData ->
                decodeExact(vmpData.toByteArray(), "Client ID's VMP data as FileHashes") {
                    FileHashes.ADAPTER.decode(it)
                }
            }

            val signed = decodeExact(
                clientId.token.orDecodeError("ClientIdentification.token").toByteArray(),
                "the Signed DRM Certificate of the Client ID",
            ) { SignedDrmCertificate.ADAPTER.decode(it) }

            val drm = decodeExact(
                signed.drm_certificate.orDecodeError("SignedDrmCertificate.drm_certificate").toByteArray(),
                "the DRM Certificate of the Client ID",
            ) { DrmCertificate.ADAPTER.decode(it) }

            val systemId = drm.system_id.orDecodeError("DrmCertificate.system_id")

            KtvineLog.d { "Loaded WVD v2 device: type=$type, securityLevel=$securityLevel, systemId=$systemId" }

            return Device(
                type = type,
                securityLevel = securityLevel,
                flags = emptyMap(),
                privateKeyDer = privateKey,
                clientId = clientId,
                vmp = vmp,
                systemId = systemId,
                rawFlags = rawFlags,
            )
        }

        /**
         * Parse a Base64-encoded WVD v2 blob.
         * @throws ValueException if decoding or parsing fails
         */
        public fun loads(data: String): Device {
            val bytes = data.decodeBase64()?.toByteArray()
                ?: throw ValueException("Device Base64 data is invalid")
            return loads(bytes)
        }

        /** Read a WVD v2 file from [path]. */
        public fun load(path: Path, fileSystem: FileSystem = FileSystem.SYSTEM): Device =
            loads(fileSystem.read(path) { readByteArray() })

        /** Read a WVD v2 file from [path]. */
        public fun load(path: String, fileSystem: FileSystem = FileSystem.SYSTEM): Device =
            load(path.toPath(), fileSystem)

        /**
         * Bring a WVD v1 blob forward to v2.
         *
         * v1 stored the VMP blob in a trailing `u16be`-prefixed block; v2 keeps it inside
         * `client_id.vmp_data`.
         *
         * @throws ValueException if the data is already v2, or is not a WVD file at all
         */
        public fun migrate(data: ByteArray): Device {
            if (data.size < 4) throw ValueException("Data too short to be a WVD file")
            if (!data.copyOfRange(0, 3).contentEquals(MAGIC)) {
                throw ValueException("Device Data does not seem to be a WVD file (bad magic)")
            }

            when (val version = data[3].toInt() and 0xFF) {
                2 -> throw ValueException("Device Data is already migrated to the latest version.")
                0 -> throw ValueException("Device Data does not seem to be a WVD file (v0).")
                1 -> Unit
                else -> throw ValueException("Unsupported WVD version $version, cannot migrate.")
            }

            if (data.size < HEADER_SIZE) throw ValueException("Data too short to be a WVD v1")
            var offset = 4

            val typeByte = data[offset].toInt() and 0xFF
            val type = when (typeByte) {
                DeviceTypes.CHROME.value -> DeviceTypes.CHROME
                DeviceTypes.ANDROID.value -> DeviceTypes.ANDROID
                else -> throw ValueException("Unknown device type byte $typeByte")
            }
            offset += 1

            val securityLevel = data[offset].toInt() and 0xFF
            offset += 1
            offset += 1 // v1 flags are discarded, matching pywidevine

            fun readU16(): Int {
                if (offset + 2 > data.size) throw ValueException("Truncated WVD v1")
                val v = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
                offset += 2
                return v
            }

            val privLen = readU16()
            if (offset + privLen > data.size) throw ValueException("Invalid private key length in WVD v1")
            val privateKey = data.copyOfRange(offset, offset + privLen)
            offset += privLen

            val clientLen = readU16()
            if (offset + clientLen > data.size) throw ValueException("Invalid client id length in WVD v1")
            var clientIdBytes = data.copyOfRange(offset, offset + clientLen)
            offset += clientLen

            // The trailing VMP block is what v2 folds into the client id.
            val vmpLen = if (offset + 2 <= data.size) readU16() else 0
            if (vmpLen > 0) {
                if (offset + vmpLen > data.size) throw ValueException("Invalid VMP length in WVD v1")
                val vmpBytes = data.copyOfRange(offset, offset + vmpLen)

                val vmp = decodeExact(vmpBytes, "VMP data as FileHashes") { FileHashes.ADAPTER.decode(it) }
                val clientId = decodeExact(clientIdBytes, "ClientIdentification") {
                    ClientIdentification.ADAPTER.decode(it)
                }

                val newVmpData = vmp.encode()
                val existing = clientId.vmp_data?.toByteArray()
                if (existing != null && !existing.contentEquals(newVmpData)) {
                    KtvineLog.w { "Client ID already has Verified Media Path data; overwriting it" }
                }
                clientIdBytes = clientId.copy(vmp_data = newVmpData.toByteString()).encode()
            }

            return loads(
                buildWvdV2(
                    type = type,
                    securityLevel = securityLevel,
                    privateKeyDer = privateKey,
                    clientIdBytes = clientIdBytes,
                ),
            )
        }

        /** Bring a Base64-encoded WVD v1 blob forward to v2. */
        public fun migrate(data: String): Device {
            val bytes = data.decodeBase64()?.toByteArray()
                ?: throw ValueException("Device Base64 data is invalid")
            return migrate(bytes)
        }

        /**
         * Build a WVD v2 file (bytes) from parts.
         */
        public fun buildWvdV2(
            type: DeviceTypes,
            securityLevel: Int,
            privateKeyDer: ByteArray,
            clientIdBytes: ByteArray,
            rawFlags: Int = 0,
        ): ByteArray {
            val out = Buffer()
            out.write(MAGIC)
            out.writeByte(2) // version
            out.writeByte(type.value)
            out.writeByte(securityLevel)
            out.writeByte(rawFlags)
            out.writeShort(privateKeyDer.size) // okio writes big-endian
            out.write(privateKeyDer)
            out.writeShort(clientIdBytes.size)
            out.write(clientIdBytes)
            return out.readByteArray()
        }
    }
}

/** Types of Widevine devices supported by this library. */
public enum class DeviceTypes(public val value: Int) { CHROME(1), ANDROID(2) }
