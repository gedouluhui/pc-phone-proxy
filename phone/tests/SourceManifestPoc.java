package com.luhui.phoneproxy;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Arrays;

/** JVM proof for signed, versioned source manifests. */
public final class SourceManifestPoc {
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

    private static byte[] manifest(int version, String url, boolean duplicateNames) {
        String second = duplicateNames ? "one" : "two";
        return ("{\"schema\":1,\"version\":" + version + ",\"sources\":["
                + "{\"name\":\"one\",\"url\":\"" + url + "\"},"
                + "{\"name\":\"" + second + "\",\"url\":\"https://raw.githubusercontent.com/a/b/main/two.txt\"},"
                + "{\"name\":\"three\",\"url\":\"https://raw.githubusercontent.com/a/b/main/three.txt\"}]}")
                .getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] sign(byte[] data, KeyPair keys) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(keys.getPrivate());
        signer.update(data);
        return signer.sign();
    }

    public static void main(String[] args) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keys = generator.generateKeyPair();
        KeyPair wrong = generator.generateKeyPair();
        String validUrl = "https://raw.githubusercontent.com/a/b/main/one.txt";
        byte[] data = manifest(2, validUrl, false);
        byte[] signature = sign(data, keys);
        SourceManifest.Manifest parsed = SourceManifest.verifyWithKey(data, signature, keys.getPublic());
        check("valid signature and schema", parsed.version == 2 && parsed.sources.length == 3,
                "version=" + parsed.version);

        boolean rejected = false;
        try {
            SourceManifest.verifyWithKey(new String(data, StandardCharsets.UTF_8)
                    .replace("\"version\":2", "\"version\":3").getBytes(StandardCharsets.UTF_8),
                    signature, keys.getPublic());
        } catch (Exception expected) { rejected = true; }
        check("tampered manifest rejected", rejected, "tampering accepted");

        rejected = false;
        try { SourceManifest.verifyWithKey(data, new byte[0], keys.getPublic()); }
        catch (Exception expected) { rejected = true; }
        check("missing signature rejected", rejected, "missing signature accepted");

        rejected = false;
        try { SourceManifest.verifyWithKey(data, signature, wrong.getPublic()); }
        catch (Exception expected) { rejected = true; }
        check("wrong public key rejected", rejected, "wrong key accepted");

        byte[] badSchema = ("{\"schema\":2,\"version\":2,\"sources\":[]}").getBytes(StandardCharsets.UTF_8);
        rejected = false;
        try { SourceManifest.verifyWithKey(badSchema, sign(badSchema, keys), keys.getPublic()); }
        catch (Exception expected) { rejected = true; }
        check("unsupported schema rejected", rejected, "schema accepted");

        rejected = false;
        try {
            SourceManifest.verifyWithKey(manifest(2, "https://127.0.0.1/nodes", false),
                    sign(manifest(2, "https://127.0.0.1/nodes", false), keys), keys.getPublic());
        } catch (Exception expected) { rejected = true; }
        check("private source URL rejected", rejected, "private URL accepted");

        rejected = false;
        try {
            byte[] duplicate = manifest(2, validUrl, true);
            SourceManifest.verifyWithKey(duplicate, sign(duplicate, keys), keys.getPublic());
        } catch (Exception expected) { rejected = true; }
        check("duplicate source names rejected", rejected, "duplicates accepted");

        check("version replay rejected", !SourceManifest.isNewer(2, 2)
                && !SourceManifest.isNewer(1, 2) && SourceManifest.isNewer(3, 2), "replay accepted");

        byte[] committed = Files.readAllBytes(Paths.get(System.getenv("PROXY_MANIFEST")));
        byte[] committedSignature = Files.readAllBytes(Paths.get(System.getenv("PROXY_SIGNATURE")));
        SourceManifest.Manifest builtin = SourceManifest.verify(committed, committedSignature);
        check("APK public key verifies committed manifest", builtin.version == 1
                && builtin.sources.length == 12, "embedded key or signature mismatch");

        System.out.println("{\"cases\":" + (passed + failed) + ",\"passed\":" + passed
                + ",\"failed\":" + failed + "}");
        if (failed > 0) System.exit(1);
    }
}
