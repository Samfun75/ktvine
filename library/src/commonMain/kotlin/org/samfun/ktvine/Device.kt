package org.samfun.ktvine

import okio.ByteString.Companion.decodeBase64
import org.samfun.ktvine.utils.ValueException
import org.samfun.ktvine.proto.ClientIdentification
import org.samfun.ktvine.proto.DrmCertificate
import org.samfun.ktvine.proto.FileHashes
import org.samfun.ktvine.proto.SignedDrmCertificate
import java.io.ByteArrayOutputStream

/**
 * Kotlin Multiplatform representation of a Widevine Device file (WVD).
 * Supports v2 structure used by pywidevine.
 */
class Device(
    val type: DeviceTypes,
    val securityLevel: Int,
    val flags: Map<String, Any?>,
    val privateKeyDer: ByteArray,
    val clientId: ClientIdentification,
    val vmp: FileHashes?,
    val systemId: Int
) {
    override fun toString(): String =
        "Device(type=$type, securityLevel=$securityLevel, flags=$flags, privateKeyDer=${privateKeyDer.size} bytes, systemId=$systemId)"

    companion object {
        private val MAGIC = byteArrayOf('W'.code.toByte(), 'V'.code.toByte(), 'D'.code.toByte())

        fun loads(data: ByteArray): Device {
            require(data.size >= 3 + 1 + 1 + 1 + 1 + 2 + 2) { "Data too short to be a WVD v2" }
            var offset = 0

            // magic
            if (!data.copyOfRange(offset, offset + 3).contentEquals(MAGIC)) {
                throw ValueException("Device Data does not seem to be a WVD file (bad magic)")
            }
            offset += 3

            // version
            val version = data[offset].toInt() and 0xFF
            offset += 1
            if (version != 2) throw ValueException("Unsupported WVD version $version, only v2 supported")

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

            // flags (1 byte reserved/padded)
            /* unused for now */
            offset += 1

            fun readU16(): Int {
                val v = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
                offset += 2
                return v
            }

            val privLen = readU16()
            require(offset + privLen <= data.size) { "Invalid private key length in WVD" }
            val privateKey = data.copyOfRange(offset, offset + privLen)
            offset += privLen

            val clientLen = readU16()
            require(offset + clientLen <= data.size) { "Invalid client id length in WVD" }
            val clientIdBytes = data.copyOfRange(offset, offset + clientLen)
            offset += clientLen

            val clientId = ClientIdentification.ADAPTER.decode(clientIdBytes)

            val vmp: FileHashes? = clientId.vmp_data?.let {
                try { FileHashes.ADAPTER.decode(it) } catch (_: Throwable) { null }
            }

            val signed = SignedDrmCertificate.ADAPTER.decode(clientId.token!!)
            val drm = DrmCertificate.ADAPTER.decode(signed.drm_certificate!!)
            val systemId = drm.system_id!!.toInt()

            return Device(
                type = type,
                securityLevel = securityLevel,
                flags = emptyMap(),
                privateKeyDer = privateKey,
                clientId = clientId,
                vmp = vmp,
                systemId = systemId
            )
        }

        fun loads(data: String): Device {
            val bytes = data.decodeBase64()?.toByteArray()
                ?: throw ValueException("Device Base64 data is invalid")
            return loads(bytes)
        }

        fun buildWvdV2(type: DeviceTypes, securityLevel: Int, privateKeyDer: ByteArray, clientIdBytes: ByteArray): ByteArray {
            val out = ByteArrayOutputStream()
            out.write(byteArrayOf('W'.code.toByte(), 'V'.code.toByte(), 'D'.code.toByte()))
            out.write(byteArrayOf(2)) // version
            out.write(byteArrayOf(type.value.toByte()))
            out.write(byteArrayOf(securityLevel.toByte()))
            out.write(byteArrayOf(0)) // flags reserved
            fun writeU16be(v: Int) { out.write(byteArrayOf(((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())) }
            writeU16be(privateKeyDer.size)
            out.write(privateKeyDer)
            writeU16be(clientIdBytes.size)
            out.write(clientIdBytes)
            return out.toByteArray()
        }
    }
}

enum class DeviceTypes(val value: Int) { CHROME(1), ANDROID(2) }
