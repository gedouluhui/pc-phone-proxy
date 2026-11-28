package com.luhui.phoneproxy;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;

/** JVM proof for the production DNS-pinned subscription transport. */
public final class ValidatedHttpPoc {
    private static int passed;
    private static int failed;

    private static final class Resolver implements ValidatedHttp.Resolver {
        final AtomicInteger calls = new AtomicInteger();
        InetAddress[] answers;
        Resolver(InetAddress... answers) { this.answers = answers; }
        @Override public InetAddress[] resolve(String host) throws UnknownHostException {
            calls.incrementAndGet();
            return answers;
        }
    }

    private static final class Cancellation implements com.luhui.phoneproxy.Cancellation {
        boolean cancelled;
        @Override public boolean isCancelled() { return cancelled; }
    }

    private static void check(String name, boolean condition, String detail) {
        if (condition) {
            passed++;
            System.out.println("PASS " + name);
        } else {
            failed++;
            System.out.println("FAIL " + name + " " + detail);
        }
    }

    private static void send(HttpExchange exchange, int status, byte[] body) throws IOException {
        exchange.sendResponseHeaders(status, body.length);
        OutputStream out = exchange.getResponseBody();
        out.write(body);
        out.close();
    }

    public static void main(String[] args) throws Exception {
        final List<String> hosts = new ArrayList<>();
        final List<String> paths = new ArrayList<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            hosts.add(exchange.getRequestHeaders().getFirst("Host"));
            paths.add(exchange.getRequestURI().toString());
            String path = exchange.getRequestURI().getPath();
            if ("/redirect".equals(path)) {
                exchange.getResponseHeaders().add("Location", "/ok");
                send(exchange, 302, new byte[0]);
            } else if ("/loop".equals(path)) {
                exchange.getResponseHeaders().add("Location", "/loop");
                send(exchange, 302, new byte[0]);
            } else if ("/redirect-big".equals(path)) {
                exchange.getResponseHeaders().add("Location", "/ok");
                send(exchange, 302, new byte[100]);
            } else if ("/big".equals(path)) {
                send(exchange, 200, new byte[100]);
            } else if ("/fail".equals(path)) {
                send(exchange, 503, "unavailable".getBytes(StandardCharsets.UTF_8));
            } else if ("/chunked".equals(path)) {
                exchange.sendResponseHeaders(200, 0);
                OutputStream out = exchange.getResponseBody();
                out.write("hello world".getBytes(StandardCharsets.UTF_8));
                out.close();
            } else {
                send(exchange, 200, "trusted-list\n".getBytes(StandardCharsets.UTF_8));
            }
        });
        server.start();
        try {
            int port = server.getAddress().getPort();
            InetAddress loopback = InetAddress.getByName("127.0.0.1");
            InetAddress publicAddress = InetAddress.getByName("93.184.216.34");

            boolean rejected = false;
            try {
                ValidatedHttp.fetch(String.format(Locale.ROOT, "http://127.0.0.1:%d/ok", port), 1024, 2000);
            } catch (ValidatedHttp.FetchException | SubscriptionGuard.Rejected expected) {
                rejected = true;
            }
            check("private literal rejected", rejected, "accepted loopback");

            Resolver mixed = new Resolver(publicAddress, loopback);
            rejected = false;
            try {
                ValidatedHttp.fetch("https://public.test/nodes", 1024, 2000, mixed, false, () -> false);
            } catch (ValidatedHttp.FetchException | SubscriptionGuard.Rejected expected) {
                rejected = true;
            }
            check("mixed DNS answers fail closed", rejected && mixed.calls.get() == 1,
                    "calls=" + mixed.calls.get());

            Resolver pinned = new Resolver(loopback);
            byte[] body = ValidatedHttp.fetch(String.format(Locale.ROOT, "http://public.test:%d/ok?x=1", port),
                    1024, 2000, pinned, true, () -> false);
            check("single resolution and pinned connection", pinned.calls.get() == 1
                            && new String(body, StandardCharsets.UTF_8).equals("trusted-list\n"),
                    "calls=" + pinned.calls.get());
            check("Host preserves original authority", hosts.get(hosts.size() - 1)
                            .equals("public.test:" + port), hosts.get(hosts.size() - 1));

            Resolver redirects = new Resolver(loopback);
            body = ValidatedHttp.fetch(String.format(Locale.ROOT, "http://public.test:%d/redirect", port),
                    1024, 2000, redirects, true, () -> false);
            check("redirect reparses and repins", redirects.calls.get() == 2
                            && new String(body, StandardCharsets.UTF_8).equals("trusted-list\n"),
                    "calls=" + redirects.calls.get());

            rejected = false;
            try {
                ValidatedHttp.fetch(String.format(Locale.ROOT, "http://public.test:%d/loop", port),
                        1024, 2000, new Resolver(loopback), true, () -> false);
            } catch (ValidatedHttp.FetchException expected) {
                rejected = true;
            }
            check("redirect loop bounded", rejected, "loop followed indefinitely");

            rejected = false;
            try {
                ValidatedHttp.validateRedirect(URI.create("https://example.com/a"),
                        URI.create("http://example.com/b"));
            } catch (ValidatedHttp.FetchException | SubscriptionGuard.Rejected expected) {
                rejected = true;
            }
            check("HTTPS downgrade rejected", rejected, "downgrade accepted");

            rejected = false;
            try {
                ValidatedHttp.fetch(String.format(Locale.ROOT, "http://public.test:%d/big", port),
                        20, 2000, new Resolver(loopback), true, () -> false);
            } catch (ValidatedHttp.FetchException expected) {
                rejected = true;
            }
            check("body byte limit enforced", rejected, "oversized body accepted");

            rejected = false;
            try {
                ValidatedHttp.fetch(String.format(Locale.ROOT, "http://public.test:%d/redirect-big", port),
                        50, 2000, new Resolver(loopback), true, () -> false);
            } catch (ValidatedHttp.FetchException expected) {
                rejected = true;
            }
            check("redirect bodies share byte budget", rejected, "budget reset per hop");

            body = ValidatedHttp.fetch(String.format(Locale.ROOT, "http://public.test:%d/chunked", port),
                    1024, 2000, new Resolver(loopback), true, () -> false);
            check("chunked body decoded", new String(body, StandardCharsets.UTF_8).equals("hello world"),
                    new String(body, StandardCharsets.UTF_8));

            int status = 0;
            try {
                ValidatedHttp.fetch(String.format(Locale.ROOT, "http://public.test:%d/fail", port),
                        1024, 2000, new Resolver(loopback), true, () -> false);
            } catch (ValidatedHttp.FetchException expected) {
                status = expected.status;
            }
            check("non-200 is hard failure", status == 503, "status=" + status);

            Cancellation cancellation = new Cancellation();
            cancellation.cancelled = true;
            Resolver cancelledResolver = new Resolver(loopback);
            rejected = false;
            try {
                ValidatedHttp.fetch(String.format(Locale.ROOT, "http://public.test:%d/ok", port),
                        1024, 2000, cancelledResolver, true, cancellation);
            } catch (ValidatedHttp.FetchException expected) {
                rejected = true;
            }
            check("cancellation precedes DNS and socket", rejected && cancelledResolver.calls.get() == 0,
                    "calls=" + cancelledResolver.calls.get());

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream input = new FileInputStream(System.getenv("PROXY_TEST_KEYSTORE"))) {
                keyStore.load(input, "changeit".toCharArray());
            }
            KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keys.init(keyStore, "changeit".toCharArray());
            TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trust.init(keyStore);
            SSLContext tlsContext = SSLContext.getInstance("TLS");
            tlsContext.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
            SSLContext.setDefault(tlsContext);
            SSLServerSocket tlsServer = (SSLServerSocket) tlsContext.getServerSocketFactory()
                    .createServerSocket(0, 50, loopback);
            AtomicReference<String> tlsRequest = new AtomicReference<>();
            AtomicReference<Throwable> tlsError = new AtomicReference<>();
            Thread tlsThread = new Thread(() -> {
                try (javax.net.ssl.SSLSocket accepted = (javax.net.ssl.SSLSocket) tlsServer.accept()) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(
                            accepted.getInputStream(), StandardCharsets.US_ASCII));
                    StringBuilder request = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null && !line.isEmpty()) request.append(line).append('\n');
                    tlsRequest.set(request.toString());
                    OutputStream out = accepted.getOutputStream();
                    out.write("HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhello tls\n"
                            .getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                } catch (Throwable error) {
                    tlsError.set(error);
                }
            }, "tls-poc-server");
            tlsThread.setDaemon(true);
            tlsThread.start();
            try {
                body = ValidatedHttp.fetch(String.format(Locale.ROOT, "https://public.test:%d/ok",
                                tlsServer.getLocalPort()), 1024, 4000, new Resolver(loopback), true, () -> false);
                tlsThread.join(5000);
                check("HTTPS pins IP while verifying original hostname", tlsError.get() == null
                                && new String(body, StandardCharsets.UTF_8).equals("hello tls\n")
                                && tlsRequest.get() != null
                                && tlsRequest.get().contains("Host: public.test:" + tlsServer.getLocalPort()),
                        tlsError.get() == null ? "request=" + tlsRequest.get() : tlsError.get().toString());
            } finally {
                tlsServer.close();
            }

            SSLServerSocket wrongServer = (SSLServerSocket) tlsContext.getServerSocketFactory()
                    .createServerSocket(0, 50, loopback);
            Thread wrongThread = new Thread(() -> {
                try (javax.net.ssl.SSLSocket accepted = (javax.net.ssl.SSLSocket) wrongServer.accept()) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(
                            accepted.getInputStream(), StandardCharsets.US_ASCII));
                    String line;
                    while ((line = reader.readLine()) != null && !line.isEmpty()) { }
                    OutputStream out = accepted.getOutputStream();
                    out.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                            .getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                } catch (Throwable expected) {
                    // A certificate for public.test must not authenticate wrong.test.
                }
            }, "tls-wrong-host-poc");
            wrongThread.setDaemon(true);
            wrongThread.start();
            rejected = false;
            try {
                ValidatedHttp.fetch(String.format(Locale.ROOT, "https://wrong.test:%d/ok",
                                wrongServer.getLocalPort()), 1024, 4000, new Resolver(loopback), true, () -> false);
            } catch (ValidatedHttp.FetchException expected) {
                rejected = true;
            } finally {
                wrongServer.close();
            }
            check("wrong TLS hostname is rejected", rejected, "certificate hostname bypassed");
        } finally {
            server.stop(0);
        }
        System.out.println("{\"cases\":" + (passed + failed) + ",\"passed\":" + passed
                + ",\"failed\":" + failed + "}");
        if (failed > 0) System.exit(1);
    }
}
