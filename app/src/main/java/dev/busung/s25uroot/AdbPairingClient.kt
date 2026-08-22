package dev.busung.s25uroot

import android.util.Log
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.tls.Certificate
import org.bouncycastle.tls.CertificateEntry
import org.bouncycastle.tls.CertificateRequest
import org.bouncycastle.tls.DefaultTlsClient
import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.SignatureAndHashAlgorithm
import org.bouncycastle.tls.TlsAuthentication
import org.bouncycastle.tls.TlsClientProtocol
import org.bouncycastle.tls.TlsCredentials
import org.bouncycastle.tls.TlsServerCertificate
import org.bouncycastle.tls.crypto.TlsCertificate
import org.bouncycastle.tls.crypto.TlsCryptoParameters
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate
import org.bouncycastle.crypto.util.PrivateKeyFactory
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.math.BigInteger
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.Date
import java.util.Locale

private const val TAG = "AdbPairClient"
private const val MAX_PEER_INFO_SIZE = 8192
private const val MAX_PAYLOAD_SIZE = MAX_PEER_INFO_SIZE * 2
private const val EXPORTED_KEY_LABEL = "adb-label\u0000"
private const val EXPORTED_KEY_SIZE = 64
private const val PAIRING_HEADER_SIZE = 6
private const val KEY_HEADER_VERSION: Byte = 1

/**
 * ADB wireless debugging pairing client.
 * Uses BouncyCastle TLS 1.3 (avoids Conscrypt hidden API restrictions on Android 16).
 * Protocol: TLS 1.3 → SPAKE2 key exchange → encrypted PeerInfo.
 *
 * AOSP's pairing server uses SSL_VERIFY_NONE, so no client certificate is needed.
 */
class AdbPairingClient(
    private val host: String,
    private val port: Int,
    private val pairCode: String,
    private val adbKey: AdbKeyManager,
) : Closeable {
    private lateinit var socket: Socket
    private lateinit var protocol: TlsClientProtocol
    private lateinit var inputStream: DataInputStream
    private lateinit var outputStream: DataOutputStream
    private lateinit var spake2: Spake2

    fun start(): Boolean {
        Log.i(TAG, "Starting pairing with $host:$port")
        setupTlsConnection()
        Log.i(TAG, "TLS ready, exchanging SPAKE2 messages")
        if (!exchangeSpake2Messages()) {
            Log.e(TAG, "SPAKE2 message exchange failed")
            return false
        }
        Log.i(TAG, "SPAKE2 exchange done, exchanging PeerInfo")
        val result = exchangePeerInfo()
        Log.i(TAG, "PeerInfo exchange result: $result")
        return result
    }

    private fun setupTlsConnection() {
        Log.d(TAG, "Connecting to $host:$port")
        socket = Socket(host, port)
        socket.tcpNoDelay = true

        // BouncyCastle TLS 1.3 client — no hidden API issues
        val crypto = BcTlsCrypto(SecureRandom())
        protocol = TlsClientProtocol(socket.getInputStream(), socket.getOutputStream())

        var exportedKeyMaterial: ByteArray? = null

        // Build a self-signed client cert for TLS client auth (AOSP pairing server
        // uses SSL_VERIFY_PEER, so it REQUIRES a client certificate).
        val privateKey = adbKey.privateKey
        val publicKey = adbKey.publicKey
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
        val asn1Cert = org.bouncycastle.asn1.x509.Certificate.getInstance(certHolder.encoded)
        val bcCert = BcTlsCertificate(crypto, asn1Cert)
        val bcPrivateKey = PrivateKeyFactory.createKey(privateKey.encoded)

        val tlsClient = object : DefaultTlsClient(crypto) {
            override fun getProtocolVersions(): Array<ProtocolVersion> =
                arrayOf(ProtocolVersion.TLSv13)

            override fun getAuthentication(): TlsAuthentication = object : TlsAuthentication {
                override fun notifyServerCertificate(serverCertificate: TlsServerCertificate?) {
                    // Accept any server cert (adbd uses self-signed)
                    Log.d(TAG, "Server cert received (accepted)")
                }
                override fun getClientCredentials(certificateRequest: CertificateRequest?): TlsCredentials {
                    // Provide our self-signed client certificate (AOSP pairing server
                    // uses SSL_VERIFY_PEER and requires one). TLS 1.3 requires the
                    // Certificate to carry the request context + per-entry extensions.
                    Log.d(TAG, "getClientCredentials: providing client cert")
                    val requestContext = certificateRequest?.certificateRequestContext ?: ByteArray(0)
                    val entry = CertificateEntry(bcCert, java.util.Hashtable<Any?, Any?>())
                    val clientCert = Certificate(requestContext, arrayOf(entry))
                    return BcDefaultTlsCredentialedSigner(
                        TlsCryptoParameters(context),
                        crypto,
                        bcPrivateKey,
                        clientCert,
                        SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
                    )
                }
            }

            override fun notifyHandshakeComplete() {
                super.notifyHandshakeComplete()
                // EKM is only valid after handshake completion
                exportedKeyMaterial = context.exportKeyingMaterial(
                    EXPORTED_KEY_LABEL, null, EXPORTED_KEY_SIZE,
                )
                Log.d(TAG, "EKM exported in notifyHandshakeComplete: ${exportedKeyMaterial?.size} bytes")
            }
        }

        protocol.connect(tlsClient)
        Log.i(TAG, "TLS 1.3 handshake succeeded (BouncyCastle)")

        val keyMaterial = exportedKeyMaterial
            ?: throw IllegalStateException("Key material not exported during handshake")
        Log.d(TAG, "Key material exported: ${keyMaterial.size} bytes")

        inputStream = DataInputStream(protocol.inputStream)
        outputStream = DataOutputStream(protocol.outputStream)

        // Derive SPAKE2 password: pairing code + TLS key material
        val pairCodeBytes = pairCode.toByteArray()
        val password = ByteArray(pairCodeBytes.size + keyMaterial.size)
        pairCodeBytes.copyInto(password)
        keyMaterial.copyInto(password, pairCodeBytes.size)

        spake2 = Spake2(password)
        Log.d(TAG, "SPAKE2 context created, our message: ${spake2.ourMessage.size} bytes")
    }

    private fun exchangeSpake2Messages(): Boolean {
        val msg = spake2.ourMessage
        Log.d(TAG, "Sending SPAKE2 msg (${msg.size} bytes)")
        writeHeader(PAIRING_TYPE_SPAKE2, msg.size)
        outputStream.write(msg)
        outputStream.flush()

        val header = readHeader() ?: return false
        if (header.type != PAIRING_TYPE_SPAKE2) {
            Log.e(TAG, "Expected SPAKE2 msg, got type=${header.type}")
            return false
        }
        val theirMsg = ByteArray(header.payload)
        inputStream.readFully(theirMsg)
        Log.d(TAG, "Received their SPAKE2 msg (${theirMsg.size} bytes)")

        val ok = spake2.processTheirMessage(theirMsg)
        Log.d(TAG, "processTheirMessage: $ok")
        return ok
    }

    private fun exchangePeerInfo(): Boolean {
        val peerInfo = ByteArray(MAX_PEER_INFO_SIZE)
        peerInfo[0] = 0 // ADB_RSA_PUB_KEY
        val pubKey = adbKey.adbPublicKey
        Log.d(TAG, "Our ADB public key: ${pubKey.size} bytes")
        pubKey.copyInto(peerInfo, 1, 0, pubKey.size.coerceAtMost(MAX_PEER_INFO_SIZE - 1))

        val encrypted = spake2.encrypt(peerInfo) ?: return false
        Log.d(TAG, "Sending encrypted PeerInfo (${encrypted.size} bytes)")
        writeHeader(PAIRING_TYPE_PEER_INFO, encrypted.size)
        outputStream.write(encrypted)
        outputStream.flush()

        val header = readHeader() ?: return false
        if (header.type != PAIRING_TYPE_PEER_INFO) {
            Log.e(TAG, "Expected PEER_INFO, got type=${header.type}")
            return false
        }
        val theirEncrypted = ByteArray(header.payload)
        inputStream.readFully(theirEncrypted)
        Log.d(TAG, "Received their PeerInfo (${theirEncrypted.size} bytes)")

        val decrypted = spake2.decrypt(theirEncrypted)
            ?: throw AdbInvalidPairingCodeException()
        if (decrypted.size != MAX_PEER_INFO_SIZE) {
            Log.e(TAG, "PeerInfo size mismatch: ${decrypted.size}")
            return false
        }
        Log.i(TAG, "Pairing successful")
        return true
    }

    private data class PairingHeader(val type: Byte, val payload: Int)

    private fun writeHeader(type: Byte, payloadSize: Int) {
        val buf = ByteBuffer.allocate(PAIRING_HEADER_SIZE).order(ByteOrder.BIG_ENDIAN)
        buf.put(KEY_HEADER_VERSION)
        buf.put(type)
        buf.putInt(payloadSize)
        outputStream.write(buf.array())
    }

    private fun readHeader(): PairingHeader? {
        val bytes = ByteArray(PAIRING_HEADER_SIZE)
        inputStream.readFully(bytes)
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
        val version = buf.get()
        val type = buf.get()
        val payload = buf.int
        if (version < 1 || version > 1) {
            Log.e(TAG, "Version mismatch: $version")
            return null
        }
        if (type != PAIRING_TYPE_SPAKE2 && type != PAIRING_TYPE_PEER_INFO) {
            Log.e(TAG, "Unknown type: $type")
            return null
        }
        if (payload <= 0 || payload > MAX_PAYLOAD_SIZE) {
            Log.e(TAG, "Invalid payload size: $payload")
            return null
        }
        return PairingHeader(type, payload)
    }

    override fun close() {
        try { protocol.close() } catch (_: Throwable) {}
        try { socket.close() } catch (_: Exception) {}
    }

    companion object {
        private const val PAIRING_TYPE_SPAKE2: Byte = 0
        private const val PAIRING_TYPE_PEER_INFO: Byte = 1
    }
}

class AdbInvalidPairingCodeException : Exception("Invalid pairing code")
