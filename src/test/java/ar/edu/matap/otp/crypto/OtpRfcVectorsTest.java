package ar.edu.matap.otp.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** Vectores de prueba oficiales: RFC 4226 (Apéndice D) y RFC 6238 (Apéndice B, SHA-1). */
class OtpRfcVectorsTest {
    private static final byte[] KEY = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    @Test
    void hotpRfc4226() {
        String[] expected = {"755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"};
        for (int c = 0; c < expected.length; c++) {
            assertEquals(expected[c], Hotp.generate(KEY, c, 6), "contador " + c);
        }
    }

    @Test
    void hotpIntermediateValuesRfc4226() {
        Hotp.Trace t = Hotp.trace(KEY, 0, 6);
        assertEquals("cc93cf18508d94934c64b65d8ba7667fb7cde4b0", t.hmacHex());
        assertEquals(1284755224L, t.binary());
    }

    @Test
    void totpRfc6238() {
        long[] times = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        String[] expected = {"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"};
        for (int i = 0; i < times.length; i++) {
            assertEquals(expected[i], Totp.generate(KEY, times[i], 30, 8), "t = " + times[i]);
        }
    }

    @Test
    void base32RoundTrip() {
        assertEquals("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Base32.encode(KEY));
        assertArrayEquals(KEY, Base32.decode("gezd gnbv gy3t qojq gezd gnbv gy3t qojq"));
        assertThrows(IllegalArgumentException.class, () -> Base32.decode("ABC1"));
    }
}
