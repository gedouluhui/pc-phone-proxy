package com.luhui.phoneproxy;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Subscription transport that resolves once, validates every address, and
 * connects only to the validated IP. HTTPS still uses the original hostname for
 * SNI, certificate checks and endpoint identification. No ambient proxy or
 * HttpURLConnection fallback exists.
 */
public final class ValidatedHttp {
    public static final int MAX_BYTES = 2 * 1024 * 1024;
    public static final int MAX_REDIRECTS = SubscriptionGuard.MAX_REDIRECTS;
    private static final int MAX_HEADER_BYTES = 64 * 1024;
    private static final int CONNECT_TIMEOUT_MS = 8000;
    private static final int READ_TIMEOUT_MS = 20000;

    public interface Resolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    public interface Cancellation {
        boolean isCancelled();
    }

    public static final class FetchException extends Exception {
        public final int status;
        public FetchException(String message) { this(message, 0); }
        public FetchException(String message, int status) {
            super(message);
            this.status = status;
        }
    }

    private ValidatedHttp() {}

    public static byte[] fetch(String url, int maxBytes, int timeoutMs) throws Exception {
        return fetch(url, maxBytes, timeoutMs, () -> false);
    }

    public static byte[] fetch(String url, int maxBytes, int timeoutMs,
                               Cancellation cancellation) throws Exception {
        return fetchInternal(url, maxBytes, timeoutMs, ValidatedHttp::defaultResolve,
                false, cancellation);
    }

    /** Package-private test seam; production callers cannot enable private targets or HTTP. */
    static byte[] fetch(String url, int maxBytes, int timeoutMs, Resolver resolver,
                        boolean allowPrivateTest, Cancellation cancellation) throws Exception {
        return fetchInternal(url, maxBytes, timeoutMs, resolver, allowPrivateTest, cancellation);
    }

    private static InetAddress[] defaultResolve(String host) throws UnknownHostException {
        try {
            return SubscriptionGuard.resolvePublic(host);
        } catch (SubscriptionGuard.Rejected rejected) {
            UnknownHostException error = new UnknownHostException(host);
            error.initCause(rejected);
            throw error;
        }
    }

    private static byte[] fetchInternal(String url, int maxBytes, int timeoutMs, Resolver resolver,
                                        boolean allowPrivateTest, Cancellation cancellation) throws Exception {
        if (maxBytes <= 0 || maxBytes > MAX_BYTES) {
            throw new FetchException("invalid byte limit");
        }
        if (timeoutMs <= 0) {
            throw new FetchException("invalid timeout");
        }
        Cancellation cancel = cancellation == null ? () -> false : cancellation;
        URI target = SubscriptionGuard.check(url);
        if (!allowPrivateTest && !"https".equalsIgnoreCase(target.getScheme())) {
            throw new FetchException("HTTPS required");
        }
        long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
        int remaining = maxBytes;
        for (int hop = 0; hop <= MAX_REDIRECTS; hop++) {
            ensureActive(cancel);
            int left = remainingMillis(deadline);
            if (left <= 0) throw new FetchException("download timed out");
            target = SubscriptionGuard.check(target.toString());
            InetAddress address = resolveAndValidate(target, resolver, allowPrivateTest, cancel);
            Response response = request(target, address, Math.min(left, timeoutMs), remaining, cancel);
            remaining -= response.body.length;
            if (response.location == null) {
                if (response.status != 200) throw new FetchException("HTTP " + response.status, response.status);
                return response.body;
            }
            if (hop >= MAX_REDIRECTS) throw new FetchException("too many redirects", response.status);
            URI next = target.resolve(response.location.trim());
            validateRedirect(target, next);
            target = next;
        }
        throw new FetchException("too many redirects");
    }

    static void validateRedirect(URI oldTarget, URI newTarget) throws Exception {
        if ("https".equalsIgnoreCase(oldTarget.getScheme())
                && !"https".equalsIgnoreCase(newTarget.getScheme())) {
            throw new FetchException("HTTPS downgrade rejected");
        }
        SubscriptionGuard.check(newTarget.toString());
    }

    private static InetAddress resolveAndValidate(URI target, Resolver resolver,
                                                   boolean allowPrivateTest,
                                                   Cancellation cancel) throws Exception {
        ensureActive(cancel);
        InetAddress[] all;
        try {
            all = resolver.resolve(target.getHost());
        } catch (UnknownHostException error) {
            throw new FetchException("hostname resolution failed");
        }
        ensureActive(cancel);
        if (all == null || all.length == 0) throw new FetchException("hostname unresolved");
        for (InetAddress address : all) {
            if (address == null || (!allowPrivateTest && SubscriptionGuard.isBlockedAddress(address))) {
                throw new FetchException("private or invalid resolved address");
            }
        }
        return all[0];
    }

    private static Response request(URI target, InetAddress address, int timeoutMs,
                                    int maxBytes, Cancellation cancel) throws Exception {
        int port = target.getPort() == -1
                ? ("https".equalsIgnoreCase(target.getScheme()) ? 443 : 80) : target.getPort();
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(address, port), Math.min(CONNECT_TIMEOUT_MS, timeoutMs));
            socket.setSoTimeout(Math.min(READ_TIMEOUT_MS, timeoutMs));
            if ("https".equalsIgnoreCase(target.getScheme())) {
                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket tls = (SSLSocket) factory.createSocket(socket, target.getHost(), port, true);
                SSLParameters parameters = tls.getSSLParameters();
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                tls.setSSLParameters(parameters);
                tls.startHandshake();
                socket = tls;
            }
            ensureActive(cancel);
            String path = target.getRawPath() == null || target.getRawPath().isEmpty()
                    ? "/" : target.getRawPath();
            if (target.getRawQuery() != null) path += "?" + target.getRawQuery();
            String host = authority(target.getHost(), port);
            String request = "GET " + path + " HTTP/1.1\r\nHost: " + host
                    + "\r\nUser-Agent: PhoneProxy\r\nAccept: */*\r\nAccept-Encoding: identity"
                    + "\r\nConnection: close\r\n\r\n";
            OutputStream out = socket.getOutputStream();
            out.write(request.getBytes(StandardCharsets.US_ASCII));
            out.flush();
            return readResponse(socket.getInputStream(), maxBytes, cancel);
        } catch (FetchException error) {
            throw error;
        } catch (IOException error) {
            throw new FetchException("network request failed");
        } finally {
            close(socket);
        }
    }

    private static Response readResponse(InputStream input, int maxBytes,
                                         Cancellation cancel) throws Exception {
        for (int interim = 0; interim < 5; interim++) {
            String statusLine = readLine(input, MAX_HEADER_BYTES, cancel);
            String[] parts = statusLine.split(" ", 3);
            if (parts.length < 2 || !parts[0].startsWith("HTTP/")) {
                throw new FetchException("invalid HTTP response");
            }
            int status;
            try { status = Integer.parseInt(parts[1]); }
            catch (NumberFormatException error) { throw new FetchException("invalid HTTP status"); }
            Map<String, String> headers = new HashMap<>();
            int headerBytes = statusLine.length() + 2;
            while (true) {
                String line = readLine(input, MAX_HEADER_BYTES, cancel);
                headerBytes += line.length() + 2;
                if (headerBytes > MAX_HEADER_BYTES) throw new FetchException("response headers too large");
                if (line.isEmpty()) break;
                int colon = line.indexOf(':');
                if (colon <= 0) throw new FetchException("invalid response header");
                String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                String value = line.substring(colon + 1).trim();
                String previous = headers.get(name);
                headers.put(name, previous == null ? value : previous + "," + value);
            }
            if (status < 200) continue; // consume a bounded number of interim responses
            byte[] body = readBody(input, headers, maxBytes, cancel);
            return new Response(status, headers.get("location"), body);
        }
        throw new FetchException("too many interim responses");
    }

    private static final class Response {
        final int status;
        final String location;
        final byte[] body;
        Response(int status, String location, byte[] body) { this.status = status; this.location = location; this.body = body; }
    }

    private static byte[] readBody(InputStream input, Map<String, String> headers,
                                   int maxBytes, Cancellation cancel) throws Exception {
        String length = headers.get("content-length");
        if (length != null) {
            final int declared;
            try { declared = Integer.parseInt(length.trim()); }
            catch (NumberFormatException error) { throw new FetchException("invalid Content-Length"); }
            if (declared < 0 || declared > maxBytes) throw new FetchException("body exceeds byte limit");
            return readExact(input, declared, cancel);
        }
        String transferEncoding = headers.get("transfer-encoding");
        if (transferEncoding != null
                && transferEncoding.toLowerCase(Locale.ROOT).contains("chunked")) {
            return readChunked(input, maxBytes, cancel);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        while (true) {
            ensureActive(cancel);
            int count = input.read(buffer);
            if (count < 0) break;
            if (out.size() + count > maxBytes) throw new FetchException("body exceeds byte limit");
            out.write(buffer, 0, count);
        }
        return out.toByteArray();
    }

    private static byte[] readExact(InputStream input, int length, Cancellation cancel) throws Exception {
        byte[] out = new byte[length];
        int offset = 0;
        while (offset < length) {
            ensureActive(cancel);
            int count = input.read(out, offset, length - offset);
            if (count < 0) throw new EOFException("truncated HTTP body");
            offset += count;
        }
        return out;
    }

    private static byte[] readChunked(InputStream input, int maxBytes,
                                      Cancellation cancel) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (true) {
            String line = readLine(input, 4096, cancel);
            int semicolon = line.indexOf(';');
            String sizeText = (semicolon < 0 ? line : line.substring(0, semicolon)).trim();
            final int size;
            try { size = Integer.parseInt(sizeText, 16); }
            catch (NumberFormatException error) { throw new FetchException("invalid chunk size"); }
            if (size < 0 || out.size() + size > maxBytes) throw new FetchException("body exceeds byte limit");
            if (size == 0) {
                int trailers = 0;
                while (true) {
                    String trailer = readLine(input, MAX_HEADER_BYTES, cancel);
                    if (trailer.isEmpty()) break;
                    if (++trailers > 100) throw new FetchException("too many trailers");
                }
                return out.toByteArray();
            }
            byte[] chunk = readExact(input, size, cancel);
            out.write(chunk);
            if (input.read() != '\r' || input.read() != '\n') {
                throw new FetchException("invalid chunk terminator");
            }
        }
    }

    private static String authority(String host, int port) {
        String value = host.indexOf(':') >= 0 ? "[" + host + "]" : host;
        return value + ":" + port;
    }

    private static void ensureActive(Cancellation cancel) throws FetchException {
        if (cancel.isCancelled()) throw new FetchException("cancelled");
    }

    private static int remainingMillis(long deadline) {
        return (int) Math.max(0L, (deadline - System.nanoTime()) / 1_000_000L);
    }

    private static String readLine(InputStream input, int limit, Cancellation cancel) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (true) {
            ensureActive(cancel);
            int value = input.read();
            if (value < 0) throw new EOFException("unexpected EOF");
            if (value == '\n') break;
            if (value == '\r') {
                int next = input.read();
                if (next != '\n') throw new FetchException("invalid HTTP line ending");
                break;
            }
            out.write(value);
            if (out.size() > limit) throw new FetchException("HTTP line too large");
        }
        return new String(out.toByteArray(), StandardCharsets.ISO_8859_1);
    }

    private static void close(java.io.Closeable value) {
        if (value == null) return;
        try { value.close(); } catch (IOException ignored) {}
    }
}
