package dev.busung.s25uroot

import android.annotation.SuppressLint
import android.content.Context
import android.util.Base64
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayInputStream
import java.io.File
import java.math.BigInteger
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Date
import java.util.Locale
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509ExtendedTrustManager

/**
 * Manages the RSA keypair used for both ADB authentication and TLS pairing.
 * Provides the SSL context (with a self-signed client certificate) needed for
 * the wireless-debugging pairing handshake, and the ADB-wire-format public key
 * sent as PeerInfo during pairing.
 */
class AdbKeyManager(context: Context) {
    private val keyDir = File(context.filesDir, "adb_keys")
    private val keyPair: KeyPair
    val adbPublicKey: ByteArray
    val sslContext: SSLContext

    init {
        keyDir.mkdirs()
        keyPair = loadOrGenerate()
        val publicKey = keyPair.public as RSAPublicKey
        adbPublicKey = encodeAdbPublicKey(publicKey, "rootmygalaxy@localhost")
        sslContext = buildSslContext()
    }

    val publicKey: RSAPublicKey get() = keyPair.public as RSAPublicKey
    val privateKey: RSAPrivateKey get() = keyPair.private as RSAPrivateKey

    private fun loadOrGenerate(): KeyPair {
        val privFile = File(keyDir, "adb_private.der")
        val pubFile = File(keyDir, "adb_public.der")
        if (privFile.exists() && pubFile.exists()) {
            val keyFactory = KeyFactory.getInstance("RSA")
            val privateKey = keyFactory.generatePrivate(
                PKCS8EncodedKeySpec(privFile.readBytes()),
            ) as RSAPrivateKey
            val publicKey = keyFactory.generatePublic(
                X509EncodedKeySpec(pubFile.readBytes()),
            ) as RSAPublicKey
            return KeyPair(publicKey, privateKey)
        }
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048)
        val pair = generator.generateKeyPair()
        privFile.writeBytes(pair.private.encoded)
        pubFile.writeBytes(pair.public.encoded)
        return pair
    }

    private fun buildSslContext(): SSLContext {
        val privateKey = keyPair.private as RSAPrivateKey
        val publicKey = keyPair.public as RSAPublicKey

        // Self-signed certificate for the TLS client
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(privateKey)
        val certHolder = X509v3CertificateBuilder(
            X500Name("CN=00"),
            BigInteger.ONE,
            Date(0),
            Date(2461449600L * 1000),
            Locale.ROOT,
            X500Name("CN=00"),
            SubjectPublicKeyInfo.getInstance(publicKey.encoded),
        ).build(signer)
        val certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(certHolder.encoded)) as X509Certificate

        val keyManager = object : X509ExtendedKeyManager() {
            private val alias = "key"
            override fun chooseClientAlias(keyTypes: Array<out String>?, issuers: Array<out java.security.Principal>?, socket: Socket?): String? {
                keyTypes?.forEach { if (it == "RSA") return alias }
                return null
            }
            override fun getCertificateChain(alias: String?): Array<X509Certificate>? =
                if (alias == this.alias) arrayOf(certificate) else null
            override fun getPrivateKey(alias: String?): PrivateKey? =
                if (alias == this.alias) privateKey else null
            override fun getClientAliases(keyType: String?, issuers: Array<out java.security.Principal>?): Array<String>? = null
            override fun getServerAliases(keyType: String?, issuers: Array<out java.security.Principal>?): Array<String>? = null
            override fun chooseServerAlias(keyType: String?, issuers: Array<out java.security.Principal>?, socket: Socket?): String? = null
        }

        val trustManager = @SuppressLint("TrustAllX509TrustManager")
        object : X509ExtendedTrustManager() {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {}
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {}
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }

        val ctx = SSLContext.getInstance("TLSv1.3")
        ctx.init(arrayOf(keyManager), arrayOf(trustManager), SecureRandom())
        return ctx
    }

    companion object {
        private const val ANDROID_PUBKEY_MODULUS_SIZE = 2048 / 8
        private const val ANDROID_PUBKEY_MODULUS_SIZE_WORDS = ANDROID_PUBKEY_MODULUS_SIZE / 4
        private const val RSA_PUBLIC_KEY_SIZE = 524

        /**
         * Encodes an RSA public key in Android's ADB wire format
         * (same as ~/.android/adbkey.pub).
         */
        fun encodeAdbPublicKey(publicKey: RSAPublicKey, name: String): ByteArray {
            val r32 = BigInteger.ZERO.setBit(32)
            val n0inv = publicKey.modulus.remainder(r32).modInverse(r32).negate()
            val r = BigInteger.ZERO.setBit(ANDROID_PUBKEY_MODULUS_SIZE * 8)
            val rr = r.modPow(BigInteger.valueOf(2), publicKey.modulus)

            val buffer = ByteBuffer.allocate(RSA_PUBLIC_KEY_SIZE).order(ByteOrder.LITTLE_ENDIAN)
            buffer.putInt(ANDROID_PUBKEY_MODULUS_SIZE_WORDS)
            buffer.putInt(n0inv.toInt())
            publicKey.modulus.toAdbEncoded().forEach { buffer.putInt(it) }
            rr.toAdbEncoded().forEach { buffer.putInt(it) }
            buffer.putInt(publicKey.publicExponent.toInt())

            val base64Bytes = Base64.encode(buffer.array(), Base64.NO_WRAP)
            val nameBytes = " $name\u0000".toByteArray()
            val bytes = ByteArray(base64Bytes.size + nameBytes.size)
            base64Bytes.copyInto(bytes)
            nameBytes.copyInto(bytes, base64Bytes.size)
            return bytes
        }

        private fun BigInteger.toAdbEncoded(): IntArray {
            val encoded = IntArray(ANDROID_PUBKEY_MODULUS_SIZE_WORDS)
            val r32 = BigInteger.ZERO.setBit(32)
            var tmp = this.add(BigInteger.ZERO)
            for (i in 0 until ANDROID_PUBKEY_MODULUS_SIZE_WORDS) {
                val out = tmp.divideAndRemainder(r32)
                tmp = out[0]
                encoded[i] = out[1].toInt()
            }
            return encoded
        }
    }
}
