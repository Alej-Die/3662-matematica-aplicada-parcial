package ar.edu.matap.otp.crypto;

/**
 * TOTP (RFC 6238): TOTP(K, t) = HOTP(K, T), con T = floor((t - T0) / X).
 * t = tiempo Unix en segundos, T0 = 0, X = período (30 s).
 */
public final class Totp {
    private Totp() {}

    public static long timeStep(long epochSeconds, int period) {
        return Math.floorDiv(epochSeconds, (long) period);
    }

    public static String generate(byte[] key, long epochSeconds, int period, int digits) {
        return Hotp.generate(key, timeStep(epochSeconds, period), digits);
    }

    public static Hotp.Trace trace(byte[] key, long epochSeconds, int period, int digits) {
        return Hotp.trace(key, timeStep(epochSeconds, period), digits);
    }
}
