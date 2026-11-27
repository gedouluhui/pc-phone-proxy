package com.luhui.phoneproxy;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/** Verifies the exact bytes of a versioned public-source manifest. */
public final class SourceManifest {
    public static final int SCHEMA = 1;
    public static final int BUILTIN_VERSION = 1;
    private static final int MAX_SOURCES = 40;

    /** DER SubjectPublicKeyInfo, generated offline; the private key is never shipped. */
    static final String PUBLIC_KEY_DER_B64 =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr8JhISHlK1JkfT7cmC3I"
            + "aEx/4+J/q2riUiXOfcfHAieLv/BFrNnf4VMXCF90VbkRn0a/oyBmQ6nuA6ZtT/MH"
            + "0mY7pdK80e17dr99ZTnkPlpbhOsspNOxfvg6MykJZeRQgxY/T1Rv0JMbFYWK34r2"
            + "EHec+wxZfCYtjgtCLG5jricXX0KPgQn/kE7Nl4qJhkjs3zTyA2iLAft2x7bNvA8K"
            + "KvNkWCyD1Z7EyYEScuovjyhmGLkAubOcN+C7byEcNX7+Ly46tn52oxce5Hhj5oiM"
            + "jLZ7QpYcqCXVkia7vqp1bClvE2uiZkOFQjylXklh/3m8Hoy1tMvi6Zno7SS2SysG"
            + "kwIDAQAB";

    public static final class Manifest {
        public final int version;
        public final String[][] sources;

        Manifest(int version, String[][] sources) {
            this.version = version;
            this.sources = sources;
        }
    }

    private SourceManifest() {}

    public static Manifest verify(byte[] data, byte[] signature) throws Exception {
        return verifyWithKey(data, signature, publicKey());
    }

    static Manifest verifyWithKey(byte[] data, byte[] signature, PublicKey key) throws Exception {
        if (data == null || data.length == 0 || data.length > 65536
                || signature == null || signature.length != 256) {
            throw new IllegalArgumentException("invalid manifest or signature size");
        }
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(key);
        verifier.update(data);
        if (!verifier.verify(signature)) throw new SecurityException("manifest signature mismatch");
        return parse(data);
    }

    private static PublicKey publicKey() throws Exception {
        byte[] der = decodeBase64(PUBLIC_KEY_DER_B64);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    private static Manifest parse(byte[] data) throws Exception {
        JSONObject root = new JSONObject(new String(data, StandardCharsets.UTF_8));
        if (root.optInt("schema", -1) != SCHEMA) throw new IllegalArgumentException("unsupported schema");
        int version = root.optInt("version", -1);
        if (version < 1 || version > 1_000_000) throw new IllegalArgumentException("invalid version");
        JSONArray array = root.optJSONArray("sources");
        if (array == null || array.length() < 3 || array.length() > MAX_SOURCES) {
            throw new IllegalArgumentException("invalid source count");
        }
        String[][] sources = new String[array.length()][2];
        Set<String> names = new HashSet<>();
        Set<String> urls = new HashSet<>();
        for (int i = 0; i < array.length(); i++) {
            JSONObject item = array.optJSONObject(i);
            if (item == null) throw new IllegalArgumentException("invalid source entry");
            String name = item.optString("name", "").trim();
            String url = item.optString("url", "").trim();
            if (!name.matches("[A-Za-z0-9._-]{1,40}") || !names.add(name)) {
                throw new IllegalArgumentException("invalid or duplicate source name");
            }
            if (!allowedSourceUrl(url) || !urls.add(url)) {
                throw new IllegalArgumentException("invalid or duplicate source URL");
            }
            sources[i][0] = name;
            sources[i][1] = url;
        }
        return new Manifest(version, sources);
    }

    public static boolean allowedSourceUrl(String url) {
        if (url == null || url.length() > 300 || !url.startsWith("https://")) return false;
        if (url.matches(".*[\\s\\\\@].*")) return false;
        try {
            java.net.URI uri = SubscriptionGuard.check(url);
            String host = uri.getHost().toLowerCase(Locale.ROOT);
            return host.equals("raw.githubusercontent.com")
                    || host.equals("cdn.jsdelivr.net")
                    || host.equals("gist.githubusercontent.com");
        } catch (Exception ignored) {
            return false;
        }
    }

    public static boolean isNewer(int version, int previous) {
        return version > previous;
    }

    private static byte[] decodeBase64(String value) {
        int length = value.length();
        if (length == 0 || length % 4 != 0) throw new IllegalArgumentException("invalid public key");
        byte[] out = new byte[length / 4 * 3];
        int offset = 0;
        for (int i = 0; i < length; i += 4) {
            int a = digit(value.charAt(i)), b = digit(value.charAt(i + 1));
            int c = digit(value.charAt(i + 2)), d = digit(value.charAt(i + 3));
            if (a < 0 || b < 0 || c < 0 || d < 0) throw new IllegalArgumentException("invalid public key");
            out[offset++] = (byte) ((a << 2) | (b >>> 4));
            if (value.charAt(i + 2) != '=') out[offset++] = (byte) ((b << 4) | (c >>> 2));
            if (value.charAt(i + 3) != '=') out[offset++] = (byte) ((c << 6) | d);
        }
        return java.util.Arrays.copyOf(out, offset);
    }

    private static int digit(char value) {
        if (value >= 'A' && value <= 'Z') return value - 'A';
        if (value >= 'a' && value <= 'z') return value - 'a' + 26;
        if (value >= '0' && value <= '9') return value - '0' + 52;
        if (value == '+') return 62;
        if (value == '/') return 63;
        return -1;
    }
}
