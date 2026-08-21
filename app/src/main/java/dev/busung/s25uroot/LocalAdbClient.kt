package dev.busung.s25uroot

import android.content.Context
import android.util.Log
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.Signature
import javax.net.ssl.SSLSocket

private const val TAG = "LocalAdbClient"

/**
 * Minimal ADB protocol client for connecting to the device's own adbd
 * over wireless debugging (TLS). Provides shell access in the
 * u:r:shell:s0 context without a PC.
 *
 * Supports both STLS (wireless debugging, Android 11+) and legacy
 * RSA-token authentication.
 */
class LocalAdbClient(
    private val host: String,
    private val port: Int,
    private val keyManager: AdbKeyManager,
) : Closeable {
    private lateinit var socket: Socket
    private lateinit var plainInput: DataInputStream
    private lateinit var plainOutput: DataOutputStream
    private var useTls = false
    private lateinit var tlsSocket: SSLSocket
    private lateinit var tlsInput: DataInputStream
    private lateinit var tlsOutput: DataOutputStream

    private val inputStream get() = if (useTls) tlsInput else plainInput
    private val outputStream get() = if (useTls) tlsOutput else plainOutput

    /**
     * Connects and authenticates to adbd.
     */
    fun connect() {
        socket = Socket()
        socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
        socket.tcpNoDelay = true
        socket.soTimeout = READ_TIMEOUT_MS
        plainInput = DataInputStream(socket.getInputStream().buffered())
        plainOutput = DataOutputStream(socket.getOutputStream().buffered())

        write(A_CNXN, A_VERSION, A_MAXDATA, "host::features=cmd,shell_v2")
        var message = read()

        if (message.command == A_STLS) {
            // Wireless debugging: upgrade to TLS
            write(A_STLS, A_STLS_VERSION, 0)
            val sslContext = keyManager.sslContext
            tlsSocket = sslContext.socketFactory.createSocket(socket, host, port, true) as SSLSocket
            tlsSocket.startHandshake()
            Log.d(TAG, "TLS handshake succeeded")
            tlsInput = DataInputStream(tlsSocket.inputStream)
            tlsOutput = DataOutputStream(tlsSocket.outputStream)
            useTls = true
            message = read()
        } else if (message.command == A_AUTH && message.arg0 == ADB_AUTH_TOKEN) {
            // Legacy RSA auth
            val sig = signToken(message.data!!)
            writeBytes(A_AUTH, ADB_AUTH_SIGNATURE, 0, sig)
            message = read()
            if (message.command != A_CNXN) {
                writeBytes(A_AUTH, ADB_AUTH_RSAPUBLICKEY, 0, keyManager.adbPublicKey)
                message = read()
            }
        }

        if (message.command != A_CNXN) error("ADB connection failed: 0x${message.command.toString(16)}")
        Log.d(TAG, "Connected: ${String(message.data ?: ByteArray(0))}")
    }

    /**
     * Executes a shell command and returns the output.
     */
    fun shell(command: String): ShellResult {
        val localId = 1
        write(A_OPEN, localId, 0, "shell:$command")
        var message = read()
        val output = StringBuilder()

        when (message.command) {
            A_OKAY -> {
                while (true) {
                    message = read()
                    val remoteId = message.arg0
                    if (message.command == A_WRTE) {
                        if (message.data != null && message.data.isNotEmpty()) {
                            output.append(String(message.data))
                        }
                        write(A_OKAY, localId, remoteId)
                    } else if (message.command == A_CLSE) {
                        write(A_CLSE, localId, remoteId)
                        break
                    } else {
                        error("Unexpected message: 0x${message.command.toString(16)}")
                    }
                }
            }
            A_CLSE -> {
                write(A_CLSE, localId, message.arg0)
            }
            else -> error("Unexpected response to OPEN: 0x${message.command.toString(16)}")
        }
        return ShellResult(0, output.toString().trim())
    }

    /**
     * Pushes a file via the ADB sync protocol.
     */
    fun push(localFile: File, remotePath: String, mode: Int = 0b111101101) {
        val localId = 1
        write(A_OPEN, localId, 0, "sync:")
        var message = read()
        if (message.command != A_OKAY) error("Failed to open sync: 0x${message.command.toString(16)}")
        val remoteId = message.arg0

        // SEND
        val pathWithMode = "$remotePath,$mode"
        val sendPayload = ByteBuffer.allocate(8 + pathWithMode.length).order(ByteOrder.LITTLE_ENDIAN)
        sendPayload.put("SEND".toByteArray())
        sendPayload.putInt(pathWithMode.length)
        sendPayload.put(pathWithMode.toByteArray())
        writeSync(localId, remoteId, sendPayload.array())

        // DATA chunks
        val fileBytes = localFile.readBytes()
        val chunkSize = 64 * 1024
        var offset = 0
        while (offset < fileBytes.size) {
            val len = minOf(chunkSize, fileBytes.size - offset)
            val dataPayload = ByteBuffer.allocate(8 + len).order(ByteOrder.LITTLE_ENDIAN)
            dataPayload.put("DATA".toByteArray())
            dataPayload.putInt(len)
            dataPayload.put(fileBytes, offset, len)
            writeSync(localId, remoteId, dataPayload.array())
            offset += len
        }

        // DONE
        val donePayload = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        donePayload.put("DONE".toByteArray())
        donePayload.putInt((System.currentTimeMillis() / 1000).toInt())
        writeSync(localId, remoteId, donePayload.array())

        // Read final response
        message = read()
        if (message.command == A_WRTE && message.data != null && message.data.size >= 4) {
            write(A_OKAY, localId, message.arg0)
            val status = String(message.data, 0, 4)
            if (status == "FAIL") {
                val failLen = ByteBuffer.wrap(message.data, 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
                val failMsg = if (message.data.size > 8) {
                    String(message.data, 8, minOf(failLen, message.data.size - 8))
                } else "unknown"
                error("ADB push failed: $failMsg")
            }
        }
        write(A_CLSE, localId, remoteId)
    }

    private fun writeSync(localId: Int, remoteId: Int, payload: ByteArray) {
        writeBytes(A_WRTE, localId, remoteId, payload)
        val ack = read()
        if (ack.command != A_OKAY) error("Sync write not acknowledged: 0x${ack.command.toString(16)}")
    }

    private fun signToken(token: ByteArray): ByteArray {
        val sig = Signature.getInstance("SHA1withRSA")
        sig.initSign(keyManager.privateKey)
        sig.update(token)
        return sig.sign()
    }

    private data class AdbMessage(
        val command: Int,
        val arg0: Int,
        val arg1: Int,
        val data: ByteArray?,
    )

    private fun writeBytes(command: Int, arg0: Int, arg1: Int, data: ByteArray) {
        writeRaw(command, arg0, arg1, data)
    }

    private fun write(command: Int, arg0: Int, arg1: Int) {
        writeRaw(command, arg0, arg1, null)
    }

    private fun write(command: Int, arg0: Int, arg1: Int, data: String) {
        writeRaw(command, arg0, arg1, "$data\u0000".toByteArray())
    }

    private fun writeRaw(command: Int, arg0: Int, arg1: Int, payload: ByteArray?) {
        val length = payload?.size ?: 0
        val checksum = payload?.sumOf { it.toInt() and 0xFF } ?: 0
        val magic = command xor -0x1
        val header = ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        header.putInt(command)
        header.putInt(arg0)
        header.putInt(arg1)
        header.putInt(length)
        header.putInt(checksum)
        header.putInt(magic)
        outputStream.write(header.array())
        if (payload != null) outputStream.write(payload)
        outputStream.flush()
    }

    private fun read(): AdbMessage {
        val header = ByteArray(HEADER_SIZE)
        inputStream.readFully(header)
        val buf = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
        val command = buf.int
        val arg0 = buf.int
        val arg1 = buf.int
        val dataLength = buf.int
        buf.int // checksum
        buf.int // magic
        val data = if (dataLength > 0) {
            val d = ByteArray(dataLength)
            inputStream.readFully(d)
            d
        } else null
        return AdbMessage(command, arg0, arg1, data)
    }

    override fun close() {
        try { plainInput.close() } catch (_: Throwable) {}
        try { plainOutput.close() } catch (_: Throwable) {}
        try { socket.close() } catch (_: Exception) {}
        if (useTls) {
            try { tlsInput.close() } catch (_: Throwable) {}
            try { tlsOutput.close() } catch (_: Throwable) {}
            try { tlsSocket.close() } catch (_: Exception) {}
        }
    }

    data class ShellResult(val exitCode: Int, val output: String)

    companion object {
        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val READ_TIMEOUT_MS = 120_000
        private const val HEADER_SIZE = 24

        private const val A_CNXN = 0x4e584e43
        private const val A_AUTH = 0x48545541
        private const val A_OPEN = 0x4e45504f
        private const val A_OKAY = 0x59414b4f
        private const val A_CLSE = 0x45534c43
        private const val A_WRTE = 0x45545257
        private const val A_STLS = 0x534c5453

        private const val A_VERSION = 0x01000000
        private const val A_MAXDATA = 256 * 1024
        private const val A_STLS_VERSION = 0x01000000

        private const val ADB_AUTH_TOKEN = 1
        private const val ADB_AUTH_SIGNATURE = 2
        private const val ADB_AUTH_RSAPUBLICKEY = 3

        /**
         * Convenience: connect, run a shell command, close.
         */
        fun shellOnce(host: String, port: Int, keyManager: AdbKeyManager, command: String): ShellResult {
            return LocalAdbClient(host, port, keyManager).use { client ->
                client.connect()
                client.shell(command)
            }
        }
    }
}
