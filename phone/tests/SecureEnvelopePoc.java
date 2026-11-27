package com.luhui.phoneproxy;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/** JVM proof for the pure AES/GCM envelope used by Android Keystore storage. */
public final class SecureEnvelopePoc {
    private static int passed;
    private static int failed;

    private static void check(String name, boolean condition, String detail) {
        if (condition) {
            passed++;
            System.out.println("PASS " + name);
        } else {
            failed++;
            System.out.println("FAIL " + name + " " + detail);
        }
    }

    public static void main(String[] args) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        SecretKey key = generator.generateKey();
        SecretKey wrong = generator.generateKey();
        byte[] plaintext = "vless://synthetic@example.com:443".getBytes("UTF-8");
        byte[] aad = "uris".getBytes("UTF-8");
        byte[] first = SecureEnvelope.encrypt(key, plaintext, aad);
        byte[] second = SecureEnvelope.encrypt(key, plaintext, aad);
        check("round trip", Arrays.equals(plaintext, SecureEnvelope.decrypt(key, first, aad)),
                "plaintext mismatch");
        check("randomized IV", !Arrays.equals(first, second), "deterministic encryption");

        boolean rejected = false;
        try { SecureEnvelope.decrypt(wrong, first, aad); }
        catch (GeneralSecurityException expected) { rejected = true; }
        check("wrong key rejected", rejected, "wrong key accepted");

        rejected = false;
        try { SecureEnvelope.decrypt(key, first, "other".getBytes("UTF-8")); }
        catch (GeneralSecurityException expected) { rejected = true; }
        check("wrong associated data rejected", rejected, "blob swapping accepted");

        byte[] tampered = first.clone();
        tampered[tampered.length - 1] ^= 1;
        rejected = false;
        try { SecureEnvelope.decrypt(key, tampered, aad); }
        catch (GeneralSecurityException expected) { rejected = true; }
        check("ciphertext tamper rejected", rejected, "tampering accepted");

        rejected = false;
        try { SecureEnvelope.decrypt(key, Arrays.copyOf(first, first.length - 1), aad); }
        catch (GeneralSecurityException expected) { rejected = true; }
        check("truncated envelope rejected", rejected, "truncation accepted");

        rejected = false;
        try { SecureEnvelope.encrypt(key, plaintext, new byte[0]); }
        catch (IllegalArgumentException expected) { rejected = true; }
        check("empty associated data rejected", rejected, "unbound blob accepted");

        System.out.println("{\"cases\":" + (passed + failed) + ",\"passed\":" + passed
                + ",\"failed\":" + failed + "}");
        if (failed > 0) System.exit(1);
    }
}
