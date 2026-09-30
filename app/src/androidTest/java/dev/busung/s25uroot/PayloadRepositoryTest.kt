package dev.busung.s25uroot

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PayloadRepositoryTest {
    @Test
    fun manifestMatchesDeviceAndArtifactsDownload() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val repository = PayloadRepository(context)
        val snapshot = DeviceSnapshot.current()
        val profile = repository.resolveTarget(snapshot)
        // Gate on the same feed-resolved firmware the resolver used. A firmware
        // no feed entry claims resolves to "no opinion", whereas the strict
        // per-profile read would reject it and make this assertion report a
        // mismatch for a profile the resolver legitimately returned.
        val firmware = repository.lastCachedTargets()
            ?.let { targets -> PayloadRepository.effectiveFirmware(targets, snapshot) }
        assertTrue(profile.matches(snapshot, firmware))

        val payloads = repository.download(profile) { }
        assertEquals(profile.exploit.size, payloads.exploit.length())
        assertEquals(profile.kernelSu.size, payloads.kernelSu.length())
        assertTrue(payloads.exploit.canRead())
        assertTrue(payloads.kernelSu.canRead())
    }
}
