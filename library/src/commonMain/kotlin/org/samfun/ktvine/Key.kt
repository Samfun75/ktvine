package org.samfun.ktvine

import org.samfun.ktvine.crypto.aesCbcDecryptNoPadding
import org.samfun.ktvine.crypto.pkcs7Unpad
import org.samfun.ktvine.proto.License
import org.samfun.ktvine.utils.kidToUuid
import org.samfun.ktvine.utils.toHexString
import java.util.UUID

class Key(
    val type: String,
    val kid: UUID,
    val key: ByteArray,
    val permissions: List<String> = emptyList()
) {
    override fun toString(): String =
        "Key(type=$type, kid=$kid, key=${key.toHexString()}, permissions=$permissions)"

    companion object {
        suspend fun fromContainer(container: License.KeyContainer, encKey: ByteArray): Key {
            val perms = mutableListOf<String>()
            if (container.type == License.KeyContainer.KeyType.OPERATOR_SESSION) {
                container.operator_session_key_permissions?.let { p ->
                    if (p.allow_encrypt == true) perms.add("allow_encrypt")
                    if (p.allow_decrypt == true) perms.add("allow_decrypt")
                    if (p.allow_sign == true) perms.add("allow_sign")
                    if (p.allow_signature_verify == true) perms.add("allow_signature_verify")
                }
            }

            val iv = container.iv?.toByteArray() ?: ByteArray(16)
            val decrypted = aesCbcDecryptNoPadding(encKey, iv, container.key!!.toByteArray())
            val unpadded = pkcs7Unpad(decrypted)

            return Key(
                type = container.type!!.name,
                kid = container.id.kidToUuid(),
                key = unpadded,
                permissions = perms
            )
        }


    }
}
