package com.luhui.phoneproxy;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Pure AES/GCM envelope: version || random IV || ciphertext || tag. */
public final class SecureEnvelope {
    public static final int VERSION = 1;
    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;
    private static final int MAX_PLAINTEXT = 2 * 1024 * 1024;

    private SecureEnvelope() {}

    public static byte[] encrypt(SecretKey key, byte[] plaintext, byte[] associatedData)
            throws GeneralSecurityException {
        if (key == null || plaintext == null || plaintext.length > MAX_PLAINTEXT) {
            throw new IllegalArgumentException("invalid encryption input");
        }
        checkAad(associatedData);
        byte[] iv = new byte[IV_LENGTH];
        java.security.SecureRandom random = new java.security.SecureRandom();
        random.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(associatedData);
        byte[] sealed = cipher.doFinal(plaintext);
        byte[] envelope = new byte[1 + IV_LENGTH + sealed.length];
        envelope[0] = VERSION;
        System.arraycopy(iv, 0, envelope, 1, IV_LENGTH);
        System.arraycopy(sealed, 0, envelope, 1 + IV_LENGTH, sealed.length);
        return envelope;
    }

    public static byte[] decrypt(SecretKey key, byte[] envelope, byte[] associatedData)
            throws GeneralSecurityException {
        if (key == null || envelope == null || envelope.length < 1 + IV_LENGTH + TAG_BITS / 8
                || envelope[0] != VERSION) {
            throw new GeneralSecurityException("invalid envelope");
        }
        checkAad(associatedData);
        byte[] iv = Arrays.copyOfRange(envelope, 1, 1 + IV_LENGTH);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(associatedData);
        return cipher.doFinal(envelope, 1 + IV_LENGTH, envelope.length - 1 - IV_LENGTH);
    }

    private static void checkAad(byte[] associatedData) {
        if (associatedData == null || associatedData.length == 0 || associatedData.length > 256) {
            throw new IllegalArgumentException("invalid associated data");
        }
    }

    static String aad(String key) {
        return "PhoneProxy SecureStore " + key;
    }

    static byte[] aadBytes(String key) {
        return aad(key).getBytes(StandardCharsets.UTF_8);
    }
}
