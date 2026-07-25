package com.shroud.client

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pins AnonRouting against the reference vectors in
 * crypto/anon_routing.py. Drift here is silent at runtime: messages land
 * on a routing tag nobody polls and sealed envelopes never open. The web
 * client shipped exactly that way for months.
 *
 * AnonRouting touches only java.security / javax.crypto, so this runs as
 * a plain JVM unit test with no device or emulator.
 */
class AnonRoutingVectorsTest {

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    @Test
    fun matchesPythonReference() {
        val a = ByteArray(32) { it.toByte() }
        val b = ByteArray(32) { (100 + it).toByte() }
        val root = ByteArray(32) { 0xAB.toByte() }

        // The reference pair_id is 14238346497009308455, which exceeds
        // Long.MAX_VALUE. Kotlin's signed Long holds the same 64 bits as
        // the unsigned value, and putLong() writes those bytes, so the
        // derived tag matches. Compare against the wrapped form.
        val pair = AnonRouting.pairId(a, b)
        assertEquals("pair_id drifted", -4208397576700243161L, pair)
        assertEquals(
            "pair_id bits differ from reference",
            "14238346497009308455", pair.toULong().toString()
        )

        val want = mapOf(
            0L      to "0878c6e14dea3a235c954bb9277e6570f6be47b45ac427c5bf83440e88304216",
            1L      to "c1ee572ddd805462bc00f0307996b9747dc9cc97f9fce3bb85a7f9ce3cbe3e6d",
            472000L to "d9ccbe248ee1e6401eb76751638d06debb9262181fe936c3ff744a842f2a4057"
        )
        for ((epoch, expected) in want) {
            assertEquals(
                "routing tag drifted at epoch $epoch",
                expected, hex(AnonRouting.routingTag(root, pair, epoch))
            )
        }
    }

    @Test
    fun epochBoundariesMatchReference() {
        assertEquals(1L, AnonRouting.epochFor(3600L))
        assertEquals(1L, AnonRouting.epochFor(7199L))
        assertEquals(2L, AnonRouting.epochFor(7200L))
    }

}
