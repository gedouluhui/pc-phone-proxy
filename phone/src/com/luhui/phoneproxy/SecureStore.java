package com.luhui.phoneproxy;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.GeneralSecurityException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/** Android Keystore AES/GCM storage for credential-bearing strings. */
public final class SecureStore {
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String ALIAS = "phoneproxy.credentials.v1";
    private static final String PREFS = "secure_credentials";
    private static final int MAX_VALUE_BYTES = 1024 * 1024;
    private static volatile String warning;

    private SecureStore() {}

    public static synchronized String get(Context context, String key) throws GeneralSecurityException {
        if (context == null || key == null || key.isEmpty()) throw new IllegalArgumentException("invalid key");
        String encoded = prefs(context).getString(key, null);
        if (encoded == null) return null;
        byte[] envelope = decodeHex(encoded);
        byte[] plaintext = SecureEnvelope.decrypt(secretKey(), envelope, SecureEnvelope.aadBytes(key));
        if (plaintext.length > MAX_VALUE_BYTES) throw new GeneralSecurityException("value too large");
        warning = null;
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    public static synchronized boolean put(Context context, String key, String value) {
        if (context == null || key == null || key.isEmpty() || value == null) return false;
        try {
            byte[] plaintext = value.getBytes(StandardCharsets.UTF_8);
            if (plaintext.length > MAX_VALUE_BYTES) return false;
            byte[] envelope = SecureEnvelope.encrypt(secretKey(), plaintext, SecureEnvelope.aadBytes(key));
            boolean saved = prefs(context).edit().putString(key, encodeHex(envelope)).commit();
            if (saved) warning = null;
            return saved;
        } catch (GeneralSecurityException | RuntimeException error) {
            warning = "安全凭据存储不可用";
            return false;
        }
    }

    /**
     * Read encrypted data, or migrate a legacy plaintext value.  Plaintext is
     * deleted only after the encrypted value is durably committed.  If Keystore
     * is unavailable the legacy value is preserved for recovery and a non-secret
     * warning is exposed; new writes never fall back to plaintext.
     */
    public static synchronized String migrateLegacy(Context context, String legacyPrefs,
                                                     String legacyKey, String secureKey) {
        if (context == null || legacyKey == null || secureKey == null) return null;
        SharedPreferences legacy = context.getApplicationContext()
                .getSharedPreferences(legacyPrefs, Context.MODE_PRIVATE);
        String old = null;
        try { old = legacy.getString(legacyKey, null); }
        catch (RuntimeException ignored) {}
        try {
            String encrypted = get(context, secureKey);
            if (encrypted != null) {
                removeLegacy(legacy, legacyKey);
                return encrypted;
            }
        } catch (GeneralSecurityException | RuntimeException error) {
            warning = "安全凭据存储不可用，暂保留旧数据";
        }
        if (old == null) return null;
        if (!prefs(context).contains(secureKey) && put(context, secureKey, old)) {
            removeLegacy(legacy, legacyKey);
            return old;
        }
        warning = "安全凭据存储不可用，暂保留旧数据";
        return old;
    }

    private static void removeLegacy(SharedPreferences legacy, String key) {
        try {
            if (legacy.contains(key) && !legacy.edit().remove(key).commit()) {
                warning = "加密已完成，但旧明文删除失败";
            }
        } catch (RuntimeException error) {
            warning = "加密已完成，但旧明文删除失败";
        }
    }

    public static boolean deleteLegacy(Context context, String legacyPrefs, String legacyKey) {
        try {
            SharedPreferences legacy = context.getApplicationContext()
                    .getSharedPreferences(legacyPrefs, Context.MODE_PRIVATE);
            removeLegacy(legacy, legacyKey);
            return !legacy.contains(legacyKey);
        } catch (RuntimeException error) {
            warning = "加密已完成，但旧明文删除失败";
            return false;
        }
    }

    public static String warning() {
        return warning;
    }

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static SecretKey secretKey() throws GeneralSecurityException {
        KeyStore store = loadStore();
        if (!store.containsAlias(ALIAS)) {
            KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
                    ANDROID_KEYSTORE);
            generator.init(new KeyGenParameterSpec.Builder(
                    ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .build());
            generator.generateKey();
            store = loadStore();
        }
        java.security.Key key = store.getKey(ALIAS, null);
        if (!(key instanceof SecretKey)) throw new GeneralSecurityException("invalid Keystore key");
        return (SecretKey) key;
    }

    private static KeyStore loadStore() throws GeneralSecurityException {
        try {
            KeyStore store = KeyStore.getInstance(ANDROID_KEYSTORE);
            store.load(null);
            return store;
        } catch (IOException error) {
            throw new GeneralSecurityException("Android Keystore unavailable", error);
        }
    }

    private static String encodeHex(byte[] value) {
        char[] out = new char[value.length * 2];
        final char[] digits = "0123456789abcdef".toCharArray();
        for (int i = 0; i < value.length; i++) {
            int b = value[i] & 0xff;
            out[i * 2] = digits[b >>> 4];
            out[i * 2 + 1] = digits[b & 0x0f];
        }
        return new String(out);
    }

    private static byte[] decodeHex(String value) throws GeneralSecurityException {
        if (value == null || value.length() == 0 || value.length() % 2 != 0
                || value.length() > MAX_VALUE_BYTES * 2 + 4096) {
            throw new GeneralSecurityException("invalid secure value");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(value.length() / 2);
        for (int i = 0; i < value.length(); i += 2) {
            int high = Character.digit(value.charAt(i), 16);
            int low = Character.digit(value.charAt(i + 1), 16);
            if (high < 0 || low < 0) throw new GeneralSecurityException("invalid secure value");
            out.write((high << 4) | low);
        }
        return out.toByteArray();
    }
}
