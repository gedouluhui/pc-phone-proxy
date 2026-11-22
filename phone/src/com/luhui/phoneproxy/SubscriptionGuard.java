package com.luhui.phoneproxy;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/**
 * Validates a subscription URL before the app opens a connection.
 *
 * <p>The importer accepts a URL from a text field, so the URL is untrusted input
 * that decides where the app connects. Without a guard a pasted {@code file://}
 * or {@code http://127.0.0.1} reaches {@code HttpURLConnection} and turns the
 * import button into a local file reader or an SSRF primitive. This class is
 * deliberately dependency-free so the same code compiles for Android and for
 * the JVM proof (see tests/SubscriptionGuardPoc.java).
 */
public final class SubscriptionGuard {

    public static final int MAX_URL_LENGTH = 2048;
    public static final int MAX_REDIRECTS = 3;

    private SubscriptionGuard() {
    }

    /** Thrown when a URL must not be fetched. Never carries the URL itself. */
    public static final class Rejected extends Exception {
        public final String reason;

        Rejected(String reason) {
            super(reason);
            this.reason = reason;
        }
    }

    /** Returns a parsed, validated URL or throws with a machine-readable reason. */
    public static URI check(String raw) throws Rejected {
        if (raw == null) {
            throw new Rejected("empty");
        }
        String value = raw.trim();
        if (value.isEmpty()) {
            throw new Rejected("empty");
        }
        if (value.length() > MAX_URL_LENGTH) {
            throw new Rejected("too_long");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            // CR/LF would let a value split a header; other controls and spaces
            // never belong in a URL the app builds itself.
            if (c <= 0x20 || c == 0x7f || c == '\\') {
                throw new Rejected("control_character");
            }
        }
        URI uri;
        try {
            uri = new URI(value);
        } catch (URISyntaxException error) {
            throw new Rejected("malformed");
        }
        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new Rejected("missing_scheme");
        }
        scheme = scheme.toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new Rejected("scheme_not_allowed");
        }
        if (uri.getRawUserInfo() != null) {
            throw new Rejected("credentials_in_url");
        }
        if (uri.getRawFragment() != null) {
            throw new Rejected("fragment_not_allowed");
        }
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            // java.net.URI refuses to call some legacy literals (127.1) and some
            // malformed names a host. Parse the raw authority so the refusal
            // carries the right reason instead of a blanket "no host".
            host = authorityHost(uri);
        }
        checkHost(host);
        int port = uri.getPort();
        if (port == 0 || port > 65535) {
            throw new Rejected("port_not_allowed");
        }
        return uri;
    }

    /** Extracts a host from the raw authority when {@code URI.getHost()} is null. */
    static String authorityHost(URI uri) throws Rejected {
        String authority = uri.getRawAuthority();
        if (authority == null || authority.isEmpty()) {
            throw new Rejected("missing_host");
        }
        int at = authority.lastIndexOf('@');
        if (at >= 0) {
            throw new Rejected("credentials_in_url");
        }
        if (authority.startsWith("[")) {
            int close = authority.indexOf(']');
            if (close < 0) {
                throw new Rejected("host_invalid");
            }
            return authority.substring(0, close + 1);
        }
        int colon = authority.lastIndexOf(':');
        if (colon >= 0) {
            authority = authority.substring(0, colon);
        }
        if (authority.isEmpty()) {
            throw new Rejected("missing_host");
        }
        return authority;
    }

    /** Rejects loopback, private, link-local and metadata endpoints. */
    static void checkHost(String host) throws Rejected {
        String name = host.toLowerCase(Locale.ROOT);
        if (name.startsWith("[") && name.endsWith("]")) {
            name = name.substring(1, name.length() - 1);
        }
        if (name.endsWith(".")) {
            name = name.substring(0, name.length() - 1);
        }
        if (name.isEmpty() || name.length() > 253) {
            throw new Rejected("host_invalid");
        }
        if (name.equals("localhost") || name.endsWith(".localhost") || name.endsWith(".local")
                || name.equals("metadata.google.internal") || name.equals("metadata")) {
            throw new Rejected("host_local");
        }
        if (name.indexOf(':') >= 0) {
            checkIpv6(name);
            return;
        }
        if (name.matches("[0-9.]+") || name.matches("0[xX][0-9a-fA-F.]+")) {
            checkIpv4Literal(name);
            return;
        }
        // A hostname must look like DNS labels; anything else is a parsing trick.
        if (!name.matches("[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*")) {
            throw new Rejected("host_invalid");
        }
    }

    private static void checkIpv4Literal(String name) throws Rejected {
        long[] parts = parseIpv4Parts(name);
        long value = 0;
        for (long part : parts) {
            if (part < 0 || part > 255) {
                throw new Rejected("host_invalid");
            }
            value = (value << 8) | part;
        }
        long first = (value >> 24) & 0xff;
        long second = (value >> 16) & 0xff;
        if (first == 0 || first == 10 || first == 127) {
            throw new Rejected("host_private");
        }
        if (first == 169 && second == 254) {
            throw new Rejected("host_link_local");
        }
        if (first == 172 && second >= 16 && second <= 31) {
            throw new Rejected("host_private");
        }
        if (first == 192 && second == 168) {
            throw new Rejected("host_private");
        }
        if (first == 100 && second >= 64 && second <= 127) {
            throw new Rejected("host_private");
        }
        if (value >= 0xE0000000L) {
            throw new Rejected("host_reserved");
        }
    }

    /**
     * Parses the legacy literal forms browsers still accept: {@code 2130706433},
     * {@code 0x7f000001}, {@code 0177.0.0.1}, {@code 127.1}.
     */
    private static long[] parseIpv4Parts(String name) throws Rejected {
        String[] raw = name.split("\\.", -1);
        if (raw.length > 4) {
            throw new Rejected("host_invalid");
        }
        long[] parts = new long[4];
        for (int i = 0; i < 4; i++) {
            if (i < raw.length) {
                parts[i] = parseNumber(raw[i]);
            } else {
                parts[i] = 0;
            }
        }
        if (raw.length == 1) {
            long value = parts[0];
            return new long[]{(value >> 24) & 0xff, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff};
        }
        return parts;
    }

    private static long parseNumber(String text) throws Rejected {
        if (text.isEmpty()) {
            throw new Rejected("host_invalid");
        }
        try {
            if (text.length() > 1 && (text.startsWith("0x") || text.startsWith("0X"))) {
                return Long.parseLong(text.substring(2), 16);
            }
            if (text.length() > 1 && text.startsWith("0")) {
                return Long.parseLong(text.substring(1), 8);
            }
            return Long.parseLong(text, 10);
        } catch (NumberFormatException error) {
            throw new Rejected("host_invalid");
        }
    }

    private static void checkIpv6(String name) throws Rejected {
        String value = name;
        int zone = value.indexOf('%');
        if (zone >= 0) {
            value = value.substring(0, zone);
        }
        if (value.equals("::1") || value.equals("::")) {
            throw new Rejected("host_local");
        }
        String lower = value.toLowerCase(Locale.ROOT);
        if (lower.startsWith("fe80") || lower.startsWith("fc") || lower.startsWith("fd")) {
            throw new Rejected("host_private");
        }
        // ::ffff:127.0.0.1 and similar mapped forms must be judged as IPv4.
        int mapped = lower.lastIndexOf("::ffff:");
        if (mapped >= 0) {
            checkIpv4Literal(lower.substring(mapped + 7));
        }
    }

    /**
     * 解析目标域名并检查每一个 A/AAAA 结果。字符串检查拦不住 DNS rebinding：
     * 攻击者让公网域名解析到 127.0.0.1 / 169.254.169.254 即可绕过第一道防线。
     * 必须在后台线程调用（会做真实 DNS 查询）。
     */
    public static void checkResolved(String host) throws Rejected {
        if (host == null || host.trim().isEmpty()) {
            throw new Rejected("host_missing");
        }
        java.net.InetAddress[] all;
        try {
            all = java.net.InetAddress.getAllByName(host.trim());
        } catch (java.net.UnknownHostException error) {
            throw new Rejected("host_unresolved");
        }
        for (java.net.InetAddress address : all) {
            if (isBlockedAddress(address)) {
                throw new Rejected("host_resolved_private");
            }
        }
    }

    private static boolean isBlockedAddress(java.net.InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress()
                || address.isLinkLocalAddress() || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }
        byte[] raw = address.getAddress();
        if (raw.length == 4) {
            int first = raw[0] & 0xff, second = raw[1] & 0xff;
            if (first == 0) return true;                                  // 0.0.0.0/8
            if (first == 100 && second >= 64 && second <= 127) return true; // 100.64/10 CGNAT
            return false;
        }
        int firstByte = raw[0] & 0xff;
        if ((firstByte & 0xfe) == 0xfc) return true;   // fc00::/7 ULA
        if (firstByte == 0xff) return true;            // ff00::/8 多播
        boolean mapped = true;
        for (int i = 0; i < 10; i++) {
            if (raw[i] != 0) { mapped = false; break; }
        }
        if (mapped && (raw[10] & 0xff) == 0xff && (raw[11] & 0xff) == 0xff) {
            int a = raw[12] & 0xff, b = raw[13] & 0xff;
            return a == 0 || a == 10 || a == 127
                    || (a == 169 && b == 254)
                    || (a == 192 && b == 168)
                    || (a == 172 && b >= 16 && b <= 31);
        }
        return false;
    }
}
