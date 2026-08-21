package dev.busung.s25uroot

import android.content.Context
import android.util.Base64
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.math.BigInteger
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * Minimal ADB protocol client for connecting to the device's own adbd
 * over localhost (wireless debugging). Provides shell access in the
 * u:r:shell:s0 context without a PC.
 *
 * Protocol reference: https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/PROTOCOL.md
 */
object LocalAdbClient {
    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 30_000
    private const val MAX_PAYLOAD = 256 * 1024
    private const val A_VERSION = 0x01000001
    private const val A_VERSION_MIN = 0x01000000

    // ADB message commands (little-endian on wire)
    private const val A_SYNC = 0x434e5953
    private const val A_CNXN = 0x4e584e43
    private const val A_AUTH = 0x48545541
    private const val A_OPEN = 0x4e45504f
    private const val A_OKAY = 0x59414b4f
    private const val A_CLSE = 0x45534c43
    private const val A_WRTE = 0x45545257

    // AUTH types
    private const val AUTH_TOKEN = 1
    private const val AUTH_SIGNATURE = 2
    private const val AUTH_RSAPUBLICKEY = 3

    private const val HEADER_SIZE = 24

    /**
     * Connects to adbd at the given address and executes a shell command,
     * returning the combined output.
     */
    fun shell(host: String, port: Int, command: String, keyDir: File): ShellResult {
        val socket = Socket()
        socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
        socket.soTimeout = READ_TIMEOUT_MS
        try {
            val input = DataInputStream(socket.getInputStream().buffered())
            val output = DataOutputStream(socket.getOutputStream().buffered())
            val keys = AdbKeyStore.loadOrGenerate(keyDir)

            // Send CNXN
            val banner = "host::features=cmd,shell_v2"
            sendMessage(output, A_CNXN, A_VERSION, MAX_PAYLOAD, banner.toByteArray())

            // Handle AUTH
            authenticate(input, output, keys)

            // Open shell
            val localId = 1
            sendMessage(output, A_OPEN, localId, 0, "shell:$command".toByteArray())

            // Read response until CLSE
            val outputBuilder = StringBuilder()
            var remoteId = 0
            var closed = false
            while (!closed) {
                val msg = readMessage(input)
                when (msg.command) {
                    A_OKAY -> {
                        remoteId = msg.arg0
                    }
                    A_WRTE -> {
                        outputBuilder.append(String(msg.payload))
                        // ACK
                        sendMessage(output, A_OKAY, localId, msg.arg0, ByteArray(0))
                    }
                    A_CLSE -> {
                        closed = true
                    }
                    else -> { /* ignore */ }
                }
            }
            sendMessage(output, A_CLSE, localId, remoteId, ByteArray(0))
            return ShellResult(0, outputBuilder.toString().trim())
        } finally {
            socket.close()
        }
    }

    private fun authenticate(
        input: DataInputStream,
        output: DataOutputStream,
        keys: KeyPair,
    ) {
        var attempts = 0
        while (attempts < 3) {
            val msg = readMessage(input)
            when {
                msg.command == A_CNXN -> return // authenticated
                msg.command == A_AUTH && msg.arg0 == AUTH_TOKEN -> {
                    // Try signature first
                    val signature = signToken(keys.private as RSAPrivateKey, msg.payload)
                    sendMessage(output, A_AUTH, AUTH_SIGNATURE, 0, signature)
                    attempts++
                    // Check if accepted
                    val response = readMessage(input)
                    if (response.command == A_CNXN) return
                    // Not accepted — send public key
                    if (response.command == A_AUTH && response.arg0 == AUTH_TOKEN) {
                        val pubKeyBytes = AdbKeyStore.encodePublicKey(keys.public as RSAPublicKey)
                        sendMessage(output, A_AUTH, AUTH_RSAPUBLICKEY, 0, pubKeyBytes)
                        val finalResponse = readMessage(input)
                        if (finalResponse.command == A_CNXN) return
                        error("ADB authentication rejected")
                    }
                }
                else -> error("Unexpected ADB message during auth: 0x${msg.command.toString(16)}")
            }
        }
        error("ADB authentication failed after $attempts attempts")
    }

    private fun signToken(privateKey: RSAPrivateKey, token: ByteArray): ByteArray {
        val sig = Signature.getInstance("SHA1withRSA")
        sig.initSign(privateKey)
        sig.update(token)
        return sig.sign()
    }

    private fun sendMessage(
        output: DataOutputStream,
        command: Int,
        arg0: Int,
        arg1: Int,
        payload: ByteArray,
    ) {
        val header = ByteArray(HEADER_SIZE)
        putLE32(header, 0, command)
        putLE32(header, 4, arg0)
        putLE32(header, 8, arg1)
        putLE32(header, 12, payload.size)
        putLE32(header, 16, checksum(payload))
        putLE32(header, 20, command xor -0x1) // magic
        output.write(header)
        if (payload.isNotEmpty()) output.write(payload)
        output.flush()
    }

    private data class AdbMessage(val command: Int, val arg0: Int, val arg1: Int, val payload: ByteArray)

    private fun readMessage(input: DataInputStream): AdbMessage {
        val header = ByteArray(HEADER_SIZE)
        input.readFully(header)
        val command = getLE32(header, 0)
        val arg0 = getLE32(header, 4)
        val arg1 = getLE32(header, 8)
        val length = getLE32(header, 12)
        val payload = if (length > 0) {
            val data = ByteArray(length)
            input.readFully(data)
            data
        } else ByteArray(0)
        return AdbMessage(command, arg0, arg1, payload)
    }

    private fun checksum(data: ByteArray): Int = data.sumOf { it.toInt() and 0xFF }

    private fun putLE32(buf: ByteArray, offset: Int, value: Int) {
        buf[offset] = (value and 0xFF).toByte()
        buf[offset + 1] = ((value shr 8) and 0xFF).toByte()
        buf[offset + 2] = ((value shr 16) and 0xFF).toByte()
        buf[offset + 3] = ((value shr 24) and 0xFF).toByte()
    }

    private fun getLE32(buf: ByteArray, offset: Int): Int =
        (buf[offset].toInt() and 0xFF) or
            ((buf[offset + 1].toInt() and 0xFF) shl 8) or
            ((buf[offset + 2].toInt() and 0xFF) shl 16) or
            ((buf[offset + 3].toInt() and 0xFF) shl 24)

    /**
     * Pushes a file to the device via the ADB sync protocol.
     * Equivalent to `adb push localPath remotePath`.
     */
    fun push(host: String, port: Int, localFile: File, remotePath: String, mode: Int, keyDir: File) {
        val socket = Socket()
        socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
        socket.soTimeout = READ_TIMEOUT_MS
        try {
            val input = DataInputStream(socket.getInputStream().buffered())
            val output = DataOutputStream(socket.getOutputStream().buffered())
            val keys = AdbKeyStore.loadOrGenerate(keyDir)

            val banner = "host::features=cmd,shell_v2"
            sendMessage(output, A_CNXN, A_VERSION, MAX_PAYLOAD, banner.toByteArray())
            authenticate(input, output, keys)

            // Open sync service
            val localId = 1
            sendMessage(output, A_OPEN, localId, 0, "sync:".toByteArray())
            var remoteId = 0
            var msg = readMessage(input)
            if (msg.command == A_OKAY) remoteId = msg.arg0
            else error("Failed to open sync service: 0x${msg.command.toString(16)}")

            // SEND: "SEND" + len + "path,mode"
            val pathWithMode = "$remotePath,$mode"
            val sendPayload = ByteArray(8 + pathWithMode.length)
            sendPayload[0] = 'S'.code.toByte()
            sendPayload[1] = 'E'.code.toByte()
            sendPayload[2] = 'N'.code.toByte()
            sendPayload[3] = 'D'.code.toByte()
            putLE32(sendPayload, 4, pathWithMode.length)
            System.arraycopy(pathWithMode.toByteArray(), 0, sendPayload, 8, pathWithMode.length)
            sendMessage(output, A_WRTE, localId, remoteId, sendPayload)
            readMessage(input) // OKAY

            // DATA chunks
            val fileBytes = localFile.readBytes()
            val chunkSize = 64 * 1024
            var offset = 0
            while (offset < fileBytes.size) {
                val len = minOf(chunkSize, fileBytes.size - offset)
                val dataPayload = ByteArray(8 + len)
                dataPayload[0] = 'D'.code.toByte()
                dataPayload[1] = 'A'.code.toByte()
                dataPayload[2] = 'T'.code.toByte()
                dataPayload[3] = 'A'.code.toByte()
                putLE32(dataPayload, 4, len)
                System.arraycopy(fileBytes, offset, dataPayload, 8, len)
                sendMessage(output, A_WRTE, localId, remoteId, dataPayload)
                readMessage(input) // OKAY
                offset += len
            }

            // DONE with mtime
            val donePayload = ByteArray(8)
            donePayload[0] = 'D'.code.toByte()
            donePayload[1] = 'O'.code.toByte()
            donePayload[2] = 'N'.code.toByte()
            donePayload[3] = 'E'.code.toByte()
            putLE32(donePayload, 4, (System.currentTimeMillis() / 1000).toInt())
            sendMessage(output, A_WRTE, localId, remoteId, donePayload)

            // Read final response (OKAY = success, FAIL = error)
            val finalMsg = readMessage(input)
            if (finalMsg.command == A_WRTE && finalMsg.payload.size >= 4) {
                val status = String(finalMsg.payload, 0, 4)
                if (status == "FAIL") {
                    val failLen = getLE32(finalMsg.payload, 4)
                    val failMsg = if (finalMsg.payload.size > 8) {
                        String(finalMsg.payload, 8, minOf(failLen, finalMsg.payload.size - 8))
                    } else "unknown"
                    error("ADB sync push failed: $failMsg")
                }
            }
            sendMessage(output, A_CLSE, localId, remoteId, ByteArray(0))
        } finally {
            socket.close()
        }
    }

    data class ShellResult(val exitCode: Int, val output: String)
}

/**
 * Manages the RSA keypair used for ADB authentication.
 * Keys are stored in the app's private directory.
 */
object AdbKeyStore {
    private const val KEY_SIZE = 2048
    private const val PRIVATE_KEY_FILE = "adb_private.der"
    private const val PUBLIC_KEY_FILE = "adb_public.der"

    fun loadOrGenerate(keyDir: File): KeyPair {
        keyDir.mkdirs()
        val privFile = File(keyDir, PRIVATE_KEY_FILE)
        val pubFile = File(keyDir, PUBLIC_KEY_FILE)
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
        generator.initialize(KEY_SIZE)
        val keyPair = generator.generateKeyPair()
        privFile.writeBytes(keyPair.private.encoded)
        pubFile.writeBytes(keyPair.public.encoded)
        return keyPair
    }

    /**
     * Encodes the RSA public key in Android's ADB wire format.
     * This is the same format as ~/.android/adbkey.pub:
     * base64(mincrypt RSAPublicKey struct) + " adbd@localhost"
     */
    fun encodePublicKey(publicKey: RSAPublicKey): ByteArray {
        val modulus = publicKey.modulus
        val n = modulus.toByteArray()
        // Ensure exactly 256 bytes (little-endian, unsigned)
        val nBytes = ByteArray(256)
        val src = if (n.size > 256) n.copyOfRange(n.size - 256, n.size) else n
        // Convert big-endian to little-endian
        for (i in src.indices) {
            nBytes[i] = src[src.size - 1 - i]
        }

        // Compute n0inv = -1/n[0] mod 2^32
        val n0 = BigInteger(1, byteArrayOf(nBytes[3], nBytes[2], nBytes[1], nBytes[0]))
        val n0inv = n0.modInverse(BigInteger.ONE.shiftLeft(32)).negate()
            .mod(BigInteger.ONE.shiftLeft(32)).toInt()

        // Compute rr = (2^(2048*2)) mod n = R^2 mod n
        val r = BigInteger.ONE.shiftLeft(2048)
        val rr = r.multiply(r).mod(modulus)
        val rrBytes = ByteArray(256)
        val rrSrc = rr.toByteArray()
        val rrTrimmed = if (rrSrc.size > 256) rrSrc.copyOfRange(rrSrc.size - 256, rrSrc.size) else rrSrc
        for (i in rrTrimmed.indices) {
            rrBytes[i] = rrTrimmed[rrTrimmed.size - 1 - i]
        }

        // Build the struct: len(4) + n0inv(4) + n(256) + rr(256) + exponent(4) = 524 bytes
        val struct = ByteArray(4 + 4 + 256 + 256 + 4)
        putLE32(struct, 0, 64) // len in uint32 words
        putLE32(struct, 4, n0inv)
        System.arraycopy(nBytes, 0, struct, 8, 256)
        System.arraycopy(rrBytes, 0, struct, 264, 256)
        putLE32(struct, 520, publicKey.publicExponent.toInt())

        val encoded = Base64.encodeToString(struct, Base64.NO_WRAP)
        return "$encoded adbd@localhost\n".toByteArray()
    }

    private fun putLE32(buf: ByteArray, offset: Int, value: Int) {
        buf[offset] = (value and 0xFF).toByte()
        buf[offset + 1] = ((value shr 8) and 0xFF).toByte()
        buf[offset + 2] = ((value shr 16) and 0xFF).toByte()
        buf[offset + 3] = ((value shr 24) and 0xFF).toByte()
    }
}
