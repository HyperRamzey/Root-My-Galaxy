package dev.busung.s25uroot

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException

/**
 * The pairing-revocation classifier: adbd rejects an unpaired client
 * certificate with a TLS alert. On Android's Conscrypt + TLS 1.3 the alert
 * arrives AFTER startHandshake() returns, on the first read, as a plain
 * SSLException("Read error: ssl=…") — the exact message observed on the
 * F946B:
 *
 *   Read error: ssl=0xb40000761f147548: Failure in SSL library, usually a
 *   protocol error
 *   error:10000416:SSL routines:OPENSSL_internal:SSLV3_ALERT_CERTIFICATE_UNKNOWN
 */
class PairingLostClassifierTest {
    private val observedDeviceMessage =
        "Read error: ssl=0xb40000761f147548: Failure in SSL library, usually a protocol error\n" +
            "error:10000416:SSL routines:OPENSSL_internal:SSLV3_ALERT_CERTIFICATE_UNKNOWN " +
            "(external/boringssl/src/ssl/tls_record.cc:486 0xb40000761398cac0:0x00000003)"

    @Test
    fun classifiesObservedConscryptReadError() {
        assertTrue(
            LocalAdbClient.isPairingLostError(SSLException(observedDeviceMessage)),
        )
    }

    @Test
    fun classifiesHandshakeExceptionShape() {
        assertTrue(
            LocalAdbClient.isPairingLostError(
                SSLHandshakeException("Handshake failed: SSLV3_ALERT_CERTIFICATE_UNKNOWN"),
            ),
        )
    }

    @Test
    fun classifiesWhenWrappedInCauseChain() {
        val root = SSLException(observedDeviceMessage)
        val wrapper = SSLException("connection closed during handshake", root)
        assertTrue(LocalAdbClient.isPairingLostError(wrapper))
    }

    @Test
    fun otherTlsAlertsAreNotPairingLoss() {
        // A protocol error that is NOT the certificate-unknown verdict —
        // must not be reported as "unpaired".
        assertFalse(
            LocalAdbClient.isPairingLostError(
                SSLException(
                    "Read error: ssl=0x1: Failure in SSL library, usually a protocol error\n" +
                        "error:10000410:SSL routines:OPENSSL_internal:SSLV3_ALERT_HANDSHAKE_FAILURE",
                ),
            ),
        )
        assertFalse(
            LocalAdbClient.isPairingLostError(SSLHandshakeException("Connection closed")),
        )
    }

    @Test
    fun nonSslErrorsAreNotPairingLoss() {
        assertFalse(
            LocalAdbClient.isPairingLostError(java.io.IOException("Connection reset")),
        )
    }

    @Test
    fun markerIsStableForMessageMatching() {
        // RootOnBootService / InstallViewModel detect the rethrown failure by
        // this marker embedded in the IOException message. It must stay
        // non-empty and match the constant the callers reference.
        val marker = LocalAdbClient.PAIRING_LOST_MARKER
        assertTrue(marker.isNotBlank())
    }
}
