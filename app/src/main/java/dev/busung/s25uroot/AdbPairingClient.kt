package dev.busung.s25uroot

import android.util.Log
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.net.ssl.SSLSocket

private const val TAG = "AdbPairClient"
private const val MAX_PEER_INFO_SIZE = 8192
private const val MAX_PAYLOAD_SIZE = MAX_PEER_INFO_SIZE * 2
private const val EXPORTED_KEY_LABEL = "adb-label\u0000"
private const val EXPORTED_KEY_SIZE = 64
private const val PAIRING_HEADER_SIZE = 6
private const val KEY_HEADER_VERSION: Byte = 1

/**
 * ADB wireless debugging pairing client.
 * Implements the pairing protocol: TLS 1.3 → SPAKE2 key exchange → encrypted PeerInfo.
 * Mirrors AOSP's pairing_connection.cpp / Shizuku's AdbPairingClient.
 */
class AdbPairingClient(
    private val host: String,
    private val port: Int,
    private val pairCode: String,
    private val adbKey: AdbKeyManager,
) : Closeable {
    private lateinit var socket: Socket
    private lateinit var inputStream: DataInputStream
    private lateinit var outputStream: DataOutputStream
    private lateinit var spake2: Spake2

    /**
     * Performs the full pairing handshake. Returns true on success.
     * Throws AdbInvalidPairingCodeException if the code is wrong.
     */
    fun start(): Boolean {
        setupTlsConnection()
        if (!exchangeSpake2Messages()) return false
        return exchangePeerInfo()
    }

    private fun setupTlsConnection() {
        socket = Socket(host, port)
        socket.tcpNoDelay = true

        val sslContext = adbKey.sslContext
        val sslSocket = sslContext.socketFactory.createSocket(socket, host, port, true) as SSLSocket
        sslSocket.startHandshake()
        Log.d(TAG, "TLS handshake succeeded")

        inputStream = DataInputStream(sslSocket.inputStream)
        outputStream = DataOutputStream(sslSocket.outputStream)

        // Derive SPAKE2 password: pairing code + TLS key material
        val pairCodeBytes = pairCode.toByteArray()
        val keyMaterial = exportKeyingMaterial(sslSocket)
        val password = ByteArray(pairCodeBytes.size + keyMaterial.size)
        pairCodeBytes.copyInto(password)
        keyMaterial.copyInto(password, pairCodeBytes.size)

        spake2 = Spake2(password)
    }

    private fun exchangeSpake2Messages(): Boolean {
        // Send our SPAKE2 message
        val msg = spake2.ourMessage
        writeHeader(PAIRING_TYPE_SPAKE2, msg.size)
        outputStream.write(msg)
        outputStream.flush()

        // Read their SPAKE2 message
        val header = readHeader() ?: return false
        if (header.type != PAIRING_TYPE_SPAKE2) return false
        val theirMsg = ByteArray(header.payload)
        inputStream.readFully(theirMsg)

        return spake2.processTheirMessage(theirMsg)
    }

    private fun exchangePeerInfo(): Boolean {
        // Build PeerInfo: type(1) + data(8191) containing our ADB public key
        val peerInfo = ByteArray(MAX_PEER_INFO_SIZE)
        peerInfo[0] = 0 // ADB_RSA_PUB_KEY
        val pubKey = adbKey.adbPublicKey
        pubKey.copyInto(peerInfo, 1, 0, pubKey.size.coerceAtMost(MAX_PEER_INFO_SIZE - 1))

        // Encrypt and send
        val encrypted = spake2.encrypt(peerInfo) ?: return false
        writeHeader(PAIRING_TYPE_PEER_INFO, encrypted.size)
        outputStream.write(encrypted)
        outputStream.flush()

        // Read their PeerInfo
        val header = readHeader() ?: return false
        if (header.type != PAIRING_TYPE_PEER_INFO) return false
        val theirEncrypted = ByteArray(header.payload)
        inputStream.readFully(theirEncrypted)

        val decrypted = spake2.decrypt(theirEncrypted)
            ?: throw AdbInvalidPairingCodeException()
        if (decrypted.size != MAX_PEER_INFO_SIZE) {
            Log.e(TAG, "PeerInfo size mismatch: ${decrypted.size}")
            return false
        }
        Log.d(TAG, "Pairing successful")
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
        try { inputStream.close() } catch (_: Throwable) {}
        try { outputStream.close() } catch (_: Throwable) {}
        try { socket.close() } catch (_: Exception) {}
    }

    /**
     * Exports TLS keying material via Conscrypt (hidden API, accessed via reflection).
     * Equivalent to Conscrypt.exportKeyingMaterial(socket, label, context, length).
     */
    private fun exportKeyingMaterial(sslSocket: SSLSocket): ByteArray {
        val method = sslSocket.javaClass.getMethod(
            "exportKeyingMaterial",
            String::class.java,
            ByteArray::class.java,
            Int::class.javaPrimitiveType,
        )
        return method.invoke(sslSocket, EXPORTED_KEY_LABEL, null, EXPORTED_KEY_SIZE) as ByteArray
    }

    companion object {
        private const val PAIRING_TYPE_SPAKE2: Byte = 0
        private const val PAIRING_TYPE_PEER_INFO: Byte = 1
    }
}

class AdbInvalidPairingCodeException : Exception("Invalid pairing code")
