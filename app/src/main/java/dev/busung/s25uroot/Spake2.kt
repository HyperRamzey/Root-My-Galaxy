package dev.busung.s25uroot

import java.math.BigInteger
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * SPAKE2 over Ed25519 for ADB wireless debugging pairing.
 * Mirrors BoringSSL's spake25519 implementation used by adbd.
 *
 * Protocol (client = Alice):
 * - w = password reduced mod L
 * - x = random scalar
 * - T = x*B + w*M  (our message, sent to server)
 * - S = server's message (y*B + w*N)
 * - K = x*(S - w*N)  (shared secret)
 * - AES-128-GCM key = HKDF-SHA256(K, info="adb pairing_auth aes-128-gcm key", len=16)
 */
class Spake2(private val password: ByteArray) {
    private val random = SecureRandom()

    // M and N points from BoringSSL's spake25519 (compressed Ed25519, 32 bytes)
    private val mPoint = hexToBytes("886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
    private val nPoint = hexToBytes("d8a12ba61d599235f67d9cb4d58f1783d3ca43e78f0a1988209f6c31a6e35f26")

    // Ed25519 group order L
    private val groupOrder = BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989")

    private val x: ByteArray
    val ourMessage: ByteArray

    private var aesKey: ByteArray? = null
    private var encSequence: Long = 0
    private var decSequence: Long = 0

    init {
        x = ByteArray(32)
        random.nextBytes(x)
        reduceScalarModL(x)

        val w = passwordToScalar(password)

        // T = x*B + w*M
        val xB = ed25519ScalarMult(x, BASE_POINT)
        val wM = ed25519ScalarMult(w, mPoint)
        ourMessage = ed25519PointAdd(xB, wM)
    }

    fun processTheirMessage(theirMsg: ByteArray): Boolean {
        if (theirMsg.size != 32) return false
        val w = passwordToScalar(password)

        // w*N
        val wN = ed25519ScalarMult(w, nPoint)

        // S - w*N: negate wN (flip sign bit) then add
        val negWN = wN.copyOf()
        negWN[31] = (negWN[31].toInt() xor 0x80).toByte()
        val sMinusWN = ed25519PointAdd(theirMsg, negWN)

        // K = x * (S - w*N)
        val k = ed25519ScalarMult(x, sMinusWN)

        aesKey = hkdfSha256(k, "adb pairing_auth aes-128-gcm key".toByteArray(), 16)
        return true
    }

    fun encrypt(plaintext: ByteArray): ByteArray {
        val key = aesKey ?: error("Key not derived yet")
        val nonce = ByteArray(12)
        val seq = encSequence++
        for (i in 0 until 8) nonce[i] = ((seq shr (i * 8)) and 0xFF).toByte()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        return cipher.doFinal(plaintext)
    }

    fun decrypt(ciphertext: ByteArray): ByteArray? {
        val key = aesKey ?: error("Key not derived yet")
        val nonce = ByteArray(12)
        val seq = decSequence++
        for (i in 0 until 8) nonce[i] = ((seq shr (i * 8)) and 0xFF).toByte()
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            null
        }
    }

    // --- Ed25519 scalar multiplication (double-and-add) ---

    private fun ed25519ScalarMult(scalar: ByteArray, point: ByteArray): ByteArray {
        val k = BigInteger(1, scalar.reversedArray())
        if (k == BigInteger.ZERO) return IDENTITY_POINT

        var result = IDENTITY_POINT
        var addend = point
        var bits = k

        while (bits > BigInteger.ZERO) {
            if (bits.testBit(0)) {
                result = ed25519PointAdd(result, addend)
            }
            addend = ed25519PointAdd(addend, addend) // double
            bits = bits.shiftRight(1)
        }
        return result
    }

    // --- Ed25519 point addition in affine coordinates ---
    // Curve: -x^2 + y^2 = 1 + d*x^2*y^2, p = 2^255 - 19

    private fun ed25519PointAdd(p: ByteArray, q: ByteArray): ByteArray {
        val (x1, y1) = decompress(p)
        val (x2, y2) = decompress(q)

        val d = ED25519_D
        val x1x2y1y2 = x1.multiply(x2).mod(FIELD_P).multiply(y1).mod(FIELD_P).multiply(y2).mod(FIELD_P)
        val dxy = d.multiply(x1x2y1y2).mod(FIELD_P)

        // x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
        val x3num = x1.multiply(y2).add(y1.multiply(x2)).mod(FIELD_P)
        val x3den = BigInteger.ONE.add(dxy).mod(FIELD_P).modInverse(FIELD_P)
        val x3 = x3num.multiply(x3den).mod(FIELD_P)

        // y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)  [a=-1]
        val y3num = y1.multiply(y2).add(x1.multiply(x2)).mod(FIELD_P)
        val y3den = BigInteger.ONE.subtract(dxy).mod(FIELD_P).modInverse(FIELD_P)
        val y3 = y3num.multiply(y3den).mod(FIELD_P)

        return compress(x3, y3)
    }

    private fun decompress(encoded: ByteArray): Pair<BigInteger, BigInteger> {
        val yBytes = encoded.copyOf()
        val sign = (yBytes[31].toInt() shr 7) and 1
        yBytes[31] = (yBytes[31].toInt() and 0x7F).toByte()
        val y = BigInteger(1, yBytes.reversedArray())

        // x^2 = (y^2 - 1) / (d*y^2 + 1)
        val y2 = y.multiply(y).mod(FIELD_P)
        val num = y2.subtract(BigInteger.ONE).mod(FIELD_P)
        val den = ED25519_D.multiply(y2).add(BigInteger.ONE).mod(FIELD_P)
        val x2 = num.multiply(den.modInverse(FIELD_P)).mod(FIELD_P)

        // sqrt: x = x2^((p+3)/8), adjust if needed
        var x = x2.modPow(FIELD_P.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), FIELD_P)
        if (x.multiply(x).mod(FIELD_P) != x2) {
            x = x.multiply(SQRT_M1).mod(FIELD_P)
        }
        // Choose correct sign
        if (x.testBit(0) != (sign == 1)) {
            x = FIELD_P.subtract(x)
        }
        return Pair(x, y)
    }

    private fun compress(x: BigInteger, y: BigInteger): ByteArray {
        val encoded = y.toByteArray().reversedArray()
        val result = ByteArray(32)
        encoded.copyInto(result, 0, 0, minOf(encoded.size, 32))
        if (x.testBit(0)) {
            result[31] = (result[31].toInt() or 0x80).toByte()
        }
        return result
    }

    private fun passwordToScalar(password: ByteArray): ByteArray {
        val big = BigInteger(1, password).mod(groupOrder)
        return bigToLE32(big)
    }

    private fun reduceScalarModL(scalar: ByteArray) {
        val big = BigInteger(1, scalar.reversedArray()).mod(groupOrder)
        bigToLE32(big).copyInto(scalar)
    }

    private fun bigToLE32(big: BigInteger): ByteArray {
        val bytes = big.toByteArray()
        val result = ByteArray(32)
        val src = if (bytes.size > 32) bytes.copyOfRange(bytes.size - 32, bytes.size) else bytes
        for (i in src.indices) result[i] = src[src.size - 1 - i]
        return result
    }

    private fun hkdfSha256(ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val hmac = Mac.getInstance("HmacSHA256")
        hmac.init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
        val prk = hmac.doFinal(ikm)
        hmac.init(SecretKeySpec(prk, "HmacSHA256"))
        hmac.update(info)
        hmac.update(0x01.toByte())
        return hmac.doFinal().copyOf(length)
    }

    companion object {
        // Identity point (0, 1) in compressed form
        private val IDENTITY_POINT = ByteArray(32).also { it[0] = 1 }

        // Ed25519 base point (compressed): y = 4/5 mod p, x sign = 0
        private val BASE_POINT = hexToBytes(
            "5866666666666666666666666666666666666666666666666666666666666666"
        )

        private val FIELD_P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19))
        private val ED25519_D = BigInteger("-121665").multiply(
            BigInteger("121666").modInverse(FIELD_P)
        ).mod(FIELD_P)
        private val SQRT_M1 = BigInteger("2").modPow(
            FIELD_P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), FIELD_P
        )

        fun hexToBytes(hex: String): ByteArray {
            val data = ByteArray(hex.length / 2)
            for (i in 0 until hex.length step 2) {
                data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
            }
            return data
        }
    }
}
