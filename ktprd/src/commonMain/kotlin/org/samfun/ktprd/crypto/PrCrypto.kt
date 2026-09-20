@file:OptIn(DelicateCryptographyApi::class)

package org.samfun.ktprd.crypto

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.algorithms.SHA1
import dev.whyoleg.cryptography.algorithms.SHA256

private val crypto = CryptographyProvider.Default

/** AES-ECB encrypt a whole number of blocks, no padding. PlayReady uses ECB as a keyed permutation. */
internal suspend fun aesEcbEncrypt(key: ByteArray, data: ByteArray): ByteArray = crypto.get(AES.ECB).keyDecoder()
    .decodeFromByteArray(AES.Key.Format.RAW, key)
    .cipher(padding = false)
    .encrypt(data)

/** AES-ECB decrypt a whole number of blocks, no padding. */
internal suspend fun aesEcbDecrypt(key: ByteArray, data: ByteArray): ByteArray = crypto.get(AES.ECB).keyDecoder()
    .decodeFromByteArray(AES.Key.Format.RAW, key)
    .cipher(padding = false)
    .decrypt(data)

internal suspend fun sha256(data: ByteArray): ByteArray = crypto.get(SHA256).hasher().hash(data)

internal suspend fun sha1(data: ByteArray): ByteArray = crypto.get(SHA1).hasher().hash(data)

internal fun ByteArray.xor(other: ByteArray): ByteArray =
    ByteArray(size) { (this[it].toInt() xor other[it].toInt()).toByte() }
