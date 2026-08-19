@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktvine.core

import org.samfun.ktvine.crypto.aesCbcDecryptNoPadding
import org.samfun.ktvine.crypto.pkcs7Unpad
import org.samfun.ktvine.proto.License
import org.samfun.ktvine.utils.kidToUuid
import org.samfun.ktvine.utils.orDecodeError
import org.samfun.ktvine.utils.toHexString
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Decrypted content key from a Widevine License.
 * Holds key type, KID (as UUID), raw key bytes, and optional permissions for OPERATOR_SESSION keys.
 */
class Key(
    val type: License.KeyContainer.KeyType,
    val kid: Uuid,
    val key: ByteArray,
    val permissions: List<String> = emptyList()
) {
    override fun toString(): String =
        "Key(type=$type, kid=$kid, key=${key.toHexString()}, permissions=$permissions)"

    // Written out by hand: a data class would compare `key` by identity.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Key) return false
        return type == other.type &&
            kid == other.kid &&
            key.contentEquals(other.key) &&
            permissions == other.permissions
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + kid.hashCode()
        result = 31 * result + key.contentHashCode()
        result = 31 * result + permissions.hashCode()
        return result
    }

    companion object {
        /**
         * Build a [Key] from a protobuf [License.KeyContainer] using the provided content encryption key.
         */
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
            val decrypted = aesCbcDecryptNoPadding(
                encKey,
                iv,
                container.key.orDecodeError("KeyContainer.key").toByteArray()
            )
            val unpadded = pkcs7Unpad(decrypted)

            return Key(
                type = container.type.orDecodeError("KeyContainer.type"),
                kid = container.id.kidToUuid(),
                key = unpadded,
                permissions = perms
            )
        }
    }
}
