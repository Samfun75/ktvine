package org.samfun.ktvine.crypto

import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

actual fun rsaPssSignSha1(privateKeyDer: ByteArray, message: ByteArray): ByteArray {
    val privateKey = loadPrivateKey(privateKeyDer)
    val sig = Signature.getInstance("SHA1withRSAandMGF1")
    sig.initSign(privateKey)
    sig.update(message)
    return sig.sign()
}

actual fun rsaPssVerifySha1(publicKeyDer: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
    val publicKey = loadPublicKey(publicKeyDer)
    val sig = Signature.getInstance("SHA1withRSAandMGF1")
    sig.initVerify(publicKey)
    sig.update(message)
    return try { sig.verify(signature) } catch (_: Throwable) { false }
}

actual fun rsaOaepDecryptSha1(privateKeyDer: ByteArray, ciphertext: ByteArray): ByteArray {
    val privateKey = loadPrivateKey(privateKeyDer)
    val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
    cipher.init(Cipher.DECRYPT_MODE, privateKey)
    return cipher.doFinal(ciphertext)
}

actual fun rsaOaepEncryptSha1(publicKeyDer: ByteArray, plaintext: ByteArray): ByteArray {
    val publicKey = loadPublicKey(publicKeyDer)
    val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    return cipher.doFinal(plaintext)
}

actual fun aesCbcEncryptNoPadding(key: ByteArray, iv: ByteArray, plaintextNoPad: ByteArray): ByteArray {
    val k: SecretKey = SecretKeySpec(key, "AES")
    val cipher = Cipher.getInstance("AES/CBC/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, k, IvParameterSpec(iv))
    return cipher.doFinal(plaintextNoPad)
}

actual fun aesCbcDecryptNoPadding(key: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray {
    val k: SecretKey = SecretKeySpec(key, "AES")
    val cipher = Cipher.getInstance("AES/CBC/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, k, IvParameterSpec(iv))
    return cipher.doFinal(ciphertext)
}

actual fun aesEncryptBlock(key: ByteArray, block16: ByteArray): ByteArray {
    val k: SecretKey = SecretKeySpec(key, "AES")
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, k)
    return cipher.doFinal(block16)
}

actual fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(data)
}

actual fun randomBytes(size: Int): ByteArray = ByteArray(size).also { SecureRandom().nextBytes(it) }

private fun loadPrivateKey(der: ByteArray): PrivateKey {
    val kf = KeyFactory.getInstance("RSA")
    return try {
        kf.generatePrivate(PKCS8EncodedKeySpec(der))
    } catch (_: Exception) {
        val spec = parsePkcs1PrivateKey(der)
        kf.generatePrivate(spec)
    }
}

private fun loadPublicKey(der: ByteArray): PublicKey {
    val kf = KeyFactory.getInstance("RSA")
    return try {
        kf.generatePublic(X509EncodedKeySpec(der))
    } catch (_: Exception) {
        val spec = parsePkcs1PublicKey(der)
        kf.generatePublic(spec)
    }
}

private fun parsePkcs1PublicKey(der: ByteArray): RSAPublicKeySpec {
    val r = Asn1Reader(der)
    r.expect(0x30)
    r.readLength()
    r.expect(0x02)
    val mod = r.readInteger()
    r.expect(0x02)
    val exp = r.readInteger()
    return RSAPublicKeySpec(mod, exp)
}

private fun parsePkcs1PrivateKey(der: ByteArray): RSAPrivateKeySpec {
    val r = Asn1Reader(der)
    r.expect(0x30)
    r.readLength()
    r.expect(0x02); r.readInteger()
    r.expect(0x02); val n = r.readInteger()
    r.expect(0x02); r.readInteger()
    r.expect(0x02); val d = r.readInteger()
    return RSAPrivateKeySpec(n, d)
}

private class Asn1Reader(private val data: ByteArray) {
    private var pos = 0
    fun expect(tag: Int) {
        val b = readByte()
        if ((b.toInt() and 0xFF) != tag) error("ASN.1: expected tag ${'$'}tag got ${'$'}b at ${'$'}pos")
    }
    fun readByte(): Byte = data[pos++]
    fun readLength(): Int {
        val b = readByte().toInt() and 0xFF
        return if (b and 0x80 == 0) b else {
            val n = b and 0x7F
            var len = 0
            repeat(n) { len = (len shl 8) or (readByte().toInt() and 0xFF) }
            len
        }
    }
    fun readInteger(): java.math.BigInteger {
        val len = readLength()
        val bytes = data.copyOfRange(pos, pos + len)
        pos += len
        return java.math.BigInteger(1, bytes)
    }
}

