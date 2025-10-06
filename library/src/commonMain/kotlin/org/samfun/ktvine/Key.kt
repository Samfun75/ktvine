package org.samfun.ktvine

import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.crypto.aesCbcDecryptNoPadding
import org.samfun.ktvine.crypto.pkcs7Unpad
import org.samfun.ktvine.proto.License
import java.math.BigInteger
import java.util.UUID

class Key(
    val type: String,
    val kid: UUID,
    val key: ByteArray,
    val permissions: List<String> = emptyList()
) {
    override fun toString(): String =
        "Key(type=$type, kid=$kid, key=${key.size} bytes, permissions=$permissions)"

    companion object {
        fun fromContainer(container: License.KeyContainer, encKey: ByteArray): Key {
            val perms = mutableListOf<String>()
            if (container.type == License.KeyContainer.KeyType.OPERATOR_SESSION) {
                val p = container.operator_session_key_permissions
                if (p != null) {
                    if (p.allow_encrypt == true) perms += "allow_encrypt"
                    if (p.allow_decrypt == true) perms += "allow_decrypt"
                    if (p.allow_sign == true) perms += "allow_sign"
                    if (p.allow_signature_verify == true) perms += "allow_signature_verify"
                }
            }

            val iv = container.iv?.toByteArray() ?: ByteArray(16)
            val decrypted = aesCbcDecryptNoPadding(encKey, iv, container.key!!.toByteArray())
            val unpadded = pkcs7Unpad(decrypted)

            return Key(
                type = container.type!!.name,
                kid = kidToUuid(container.id),
                key = unpadded,
                permissions = perms
            )
        }

        fun kidToUuid(kid: ByteString?): UUID {
            if (kid == null || kid.size == 0) return UUID(0L, 0L)
            // ASCII decimal -> parse to BigInteger and pad to 16 bytes
            val s = try { kid.string(Charsets.US_ASCII) } catch (_: Throwable) { null }
            if (s != null && s.all { it.isDigit() }) {
                val bi = BigInteger(s)
                val raw = bi.toByteArray() // big-endian
                val bytes = if (raw.size >= 16) raw.copyOfRange(raw.size - 16, raw.size) else ByteArray(16 - raw.size) + raw
                return bytes.toByteString().uuidFromByteString()
            }
            var bytes = kid.toByteArray()
            if (bytes.size < 16) bytes += ByteArray(16 - bytes.size)
            return bytes.toByteString().uuidFromByteString()
        }
    }
}
