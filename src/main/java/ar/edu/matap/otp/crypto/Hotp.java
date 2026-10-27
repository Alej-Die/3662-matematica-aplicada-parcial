package ar.edu.matap.otp.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.HexFormat;

/**
 * HOTP (RFC 4226): HOTP(K, C) = Truncate(HMAC-SHA1(K, C)) mod 10^d
 * Implementado a mano sobre la primitiva HMAC-SHA1 de la JDK.
 */
public final class Hotp {
    private Hotp() {}

    /** Valores intermedios del cálculo, para mostrarlos paso a paso en la GUI. */
    public record Trace(long counter, String counterHex, String hmacHex, int offset,
                        String truncatedHex, long binary, int digits, long modulus, String code) {}

    public static String generate(byte[] key, long counter, int digits) {
        return trace(key, counter, digits).code();
    }

    public static Trace trace(byte[] key, long counter, int digits) {
        if (digits < 6 || digits > 8) {
            throw new IllegalArgumentException("La cantidad de dígitos debe estar entre 6 y 8.");
        }
        // 1) Contador como entero de 8 bytes big-endian
        byte[] message = ByteBuffer.allocate(8).putLong(counter).array();

        // 2) HS = HMAC-SHA1(K, C)  -> 20 bytes
        byte[] hs = hmacSha1(key, message);

        // 3) Truncamiento dinámico: los 4 bits bajos del último byte indican el offset
        int offset = hs[hs.length - 1] & 0x0F;
        // 4 bytes desde el offset, descartando el bit de signo -> entero de 31 bits
        long binary = ((hs[offset] & 0x7FL) << 24)
                | ((hs[offset + 1] & 0xFFL) << 16)
                | ((hs[offset + 2] & 0xFFL) << 8)
                | (hs[offset + 3] & 0xFFL);

        // 4) Reducción modular a d dígitos decimales
        long modulus = (long) Math.pow(10, digits);
        String code = String.format("%0" + digits + "d", binary % modulus);

        HexFormat hex = HexFormat.of();
        return new Trace(counter, hex.formatHex(message), hex.formatHex(hs), offset,
                hex.formatHex(hs, offset, offset + 4), binary, digits, modulus, code);
    }

    private static byte[] hmacSha1(byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("No se pudo calcular HMAC-SHA1", e);
        }
    }
}
