package dev.busung.s25uroot

import android.util.Log
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * SPAKE2 over Ed25519 for ADB wireless-debugging pairing.
 * Mirrors BoringSSL's spake25519 (crypto/curve25519/spake25519.cc) used by adbd,
 * plus AOSP's pairing_auth key derivation (pairing_auth/aes_128_gcm.cpp).
 *
 * Client role = spake2_role_alice.
 *
 * Generate (SPAKE2_generate_msg):
 *   x = RAND(64) reduced mod L, then x8 (cofactor clear)
 *   w = SHA512(password) reduced mod L, then low-3-bits "hack" (add L/2L/4L)
 *   password_hash = SHA512(password)  (full 64 bytes, kept for the transcript)
 *   T = x*B + w*M            (our message)
 *
 * Process (SPAKE2_process_msg):
 *   K = x * (S - w*N)        (shared point, S = peer message)
 *   transcript = SHA512( len||clientName || len||serverName || len||T || len||S
 *                        || len||K || len||password_hash )
 *   key_material = transcript (64 bytes)
 *
 * Cipher init (Aes128Gcm):
 *   aesKey = HKDF-SHA256(ikm=key_material, salt=zeros(32),
 *                        info="adb pairing_auth aes-128-gcm key", len=16)
 *   AES-128-GCM, nonce = 12 bytes, first 8 = little-endian sequence counter.
 */
class Spake2(private val password: ByteArray) {
    private val random = SecureRandom()

    // BoringSSL spake25519 M and N (compressed Ed25519, 32 bytes).
    // M is used by alice (client) to mask; N is used by alice to unmask the peer.
    private val mPoint = hexToBytes("5ada7e4bf6ddd9adb6626d32131c6b5c51a1e347a3478f53cfcf441b88eed12e")
    private val nPoint = hexToBytes("10e3df0ae37d8e7a99b5fe74b44672103dbddcbd06af680d71329a11693bc778")

    // Ed25519 prime-order subgroup order L.
    private val groupOrder = BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989")

    // ADB pairing names include the NUL terminator (C sizeof()).
    private val clientName = "adb pair client\u0000".toByteArray()
    private val serverName = "adb pair server\u0000".toByteArray()

    private val x: ByteArray          // our private scalar (x8)
    private val w: ByteArray          // password scalar (hacked)
    private val passwordHash: ByteArray // full SHA512(password), for transcript
    val ourMessage: ByteArray          // T

    private var aesKey: ByteArray? = null
    private var encSequence: Long = 0
    private var decSequence: Long = 0

    init {
        passwordHash = MessageDigest.getInstance("SHA-512").digest(password)

        // x = random 64 bytes reduced mod L, then x8.
        val randBytes = ByteArray(64)
        random.nextBytes(randBytes)
        var xBig = BigInteger(1, randBytes.reversedArray()).mod(groupOrder)
        xBig = xBig.shiftLeft(3) // multiply by cofactor 8
        x = bigToLE32(xBig)

        // w = SHA512(password) reduced mod L, then low-3-bits hack.
        w = passwordToScalar(passwordHash)

        // T = x*B + w*M
        val xB = ed25519ScalarMult(x, BASE_POINT)
        val wM = ed25519ScalarMult(w, mPoint)
        ourMessage = ed25519PointAdd(xB, wM)
        Log.d(TAG, "init: T=${ourMessage.toHex().take(16)}...")
    }

    fun processTheirMessage(theirMsg: ByteArray): Boolean {
        if (theirMsg.size != 32) {
            Log.e(TAG, "theirMsg size ${theirMsg.size} != 32")
            return false
        }

        // K = x * (S - w*N)
        val wN = ed25519ScalarMult(w, nPoint)
        val negWN = wN.copyOf()
        negWN[31] = (negWN[31].toInt() xor 0x80).toByte() // negate point
        val sMinusWN = ed25519PointAdd(theirMsg, negWN)
        val k = ed25519ScalarMult(x, sMinusWN)
        Log.d(TAG, "K=${k.toHex().take(16)}...")

        // transcript = SHA512( len||clientName || len||serverName || len||T || len||S
        //                      || len||K || len||password_hash )
        val md = MessageDigest.getInstance("SHA-512")
        md.updateLenPrefixed(clientName)
        md.updateLenPrefixed(serverName)
        md.updateLenPrefixed(ourMessage)
        md.updateLenPrefixed(theirMsg)
        md.updateLenPrefixed(k)
        md.updateLenPrefixed(passwordHash)
        val keyMaterial = md.digest()
        Log.d(TAG, "key_material=${keyMaterial.toHex().take(16)}...")

        // aesKey = HKDF-SHA256(key_material, salt=zeros32, info, 16)
        aesKey = hkdfSha256(keyMaterial, "adb pairing_auth aes-128-gcm key".toByteArray(), 16)
        Log.d(TAG, "aesKey=${aesKey!!.toHex()}")
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
            Log.e(TAG, "Decrypt failed: ${e.message}")
            null
        }
    }

    // w = SHA512(password) reduced mod L, then BoringSSL's low-3-bits hack:
    // add L, 2L, 4L conditionally to clear bits 0,1,2 (makes w a multiple of 8).
    private fun passwordToScalar(hash: ByteArray): ByteArray {
        var wBig = BigInteger(1, hash.reversedArray()).mod(groupOrder)
        var order = groupOrder
        if (wBig.testBit(0)) wBig = wBig.add(order)
        order = order.shiftLeft(1)
        if (wBig.testBit(1)) wBig = wBig.add(order)
        order = order.shiftLeft(1)
        if (wBig.testBit(2)) wBig = wBig.add(order)
        return bigToLE32(wBig)
    }

    // --- Ed25519 scalar multiplication (double-and-add) ---
    private fun ed25519ScalarMult(scalar: ByteArray, point: ByteArray): ByteArray {
        val k = BigInteger(1, scalar.reversedArray())
        if (k == BigInteger.ZERO) return IDENTITY_POINT
        var result = IDENTITY_POINT
        var addend = point
        var bits = k
        while (bits > BigInteger.ZERO) {
            if (bits.testBit(0)) result = ed25519PointAdd(result, addend)
            addend = ed25519PointAdd(addend, addend)
            bits = bits.shiftRight(1)
        }
        return result
    }

    // --- Ed25519 point addition in affine coordinates ---
    // Curve: -x^2 + y^2 = 1 + d*x^2*y^2, p = 2^255 - 19
    private fun ed25519PointAdd(p: ByteArray, q: ByteArray): ByteArray {
        val (x1, y1) = decompress(p)
        val (x2, y2) = decompress(q)
        val dxy = ED25519_D.multiply(x1).multiply(x2).multiply(y1).multiply(y2).mod(FIELD_P)
        val x3num = x1.multiply(y2).add(y1.multiply(x2)).mod(FIELD_P)
        val x3den = BigInteger.ONE.add(dxy).mod(FIELD_P).modInverse(FIELD_P)
        val x3 = x3num.multiply(x3den).mod(FIELD_P)
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
        val y2 = y.multiply(y).mod(FIELD_P)
        val num = y2.subtract(BigInteger.ONE).mod(FIELD_P)
        val den = ED25519_D.multiply(y2).add(BigInteger.ONE).mod(FIELD_P)
        val x2 = num.multiply(den.modInverse(FIELD_P)).mod(FIELD_P)
        var x = x2.modPow(FIELD_P.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), FIELD_P)
        if (x.multiply(x).mod(FIELD_P) != x2) x = x.multiply(SQRT_M1).mod(FIELD_P)
        if (x.testBit(0) != (sign == 1)) x = FIELD_P.subtract(x)
        return Pair(x, y)
    }

    private fun compress(x: BigInteger, y: BigInteger): ByteArray {
        val encoded = y.toByteArray().reversedArray()
        val result = ByteArray(32)
        encoded.copyInto(result, 0, 0, minOf(encoded.size, 32))
        if (x.testBit(0)) result[31] = (result[31].toInt() or 0x80).toByte()
        return result
    }

    private fun bigToLE32(big: BigInteger): ByteArray {
        val bytes = big.toByteArray()
        val result = ByteArray(32)
        val src = if (bytes.size > 32) bytes.copyOfRange(bytes.size - 32, bytes.size) else bytes
        for (i in src.indices) result[i] = src[src.size - 1 - i]
        return result
    }

    private fun MessageDigest.updateLenPrefixed(data: ByteArray) {
        val lenLe = ByteArray(8)
        var l = data.size.toLong()
        for (i in 0 until 8) { lenLe[i] = (l and 0xFF).toByte(); l = l ushr 8 }
        update(lenLe)
        update(data)
    }

    private fun hkdfSha256(ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val hmac = Mac.getInstance("HmacSHA256")
        hmac.init(SecretKeySpec(ByteArray(32), "HmacSHA256")) // salt = zeros(32)
        val prk = hmac.doFinal(ikm)
        hmac.init(SecretKeySpec(prk, "HmacSHA256"))
        hmac.update(info)
        hmac.update(0x01.toByte())
        return hmac.doFinal().copyOf(length)
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    companion object {
        private const val TAG = "Spake2"
        private val IDENTITY_POINT = ByteArray(32).also { it[0] = 1 }
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
