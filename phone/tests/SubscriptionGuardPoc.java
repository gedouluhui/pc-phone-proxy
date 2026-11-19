/**
 * JVM proof for SubscriptionGuard: run with
 *   python phone/tests/run_guard_poc.py
 * or directly after compiling:
 *   javac -d out src/com/luhui/phoneproxy/SubscriptionGuard.java tests/SubscriptionGuardPoc.java
 *   java -cp out SubscriptionGuardPoc
 *
 * The point is not coverage of every URL on the internet. It is that the
 * import path can only ever open a public http(s) endpoint: the exact inputs a
 * user can paste must either be accepted or be rejected with a named reason.
 */
import com.luhui.phoneproxy.SubscriptionGuard;

import java.util.ArrayList;
import java.util.List;

public final class SubscriptionGuardPoc {

    private static final List<String[]> CASES = new ArrayList<>();

    private static void allow(String url) {
        CASES.add(new String[]{url == null ? "<null>" : url, null});
    }

    private static void reject(String url, String reason) {
        CASES.add(new String[]{url == null ? "<null>" : url, reason});
    }

    static {
        allow("https://example.com/subs/nodes.txt");
        allow("https://raw.githubusercontent.com/owner/repo/main/nodes.txt");
        allow("http://203.0.113.10/nodes.txt");
        allow("https://sub.example.com:8443/api?token=abc");

        reject(null, "empty");
        reject("", "empty");
        reject("   ", "empty");
        reject("example.com/nodes.txt", "missing_scheme");
        reject("file:///etc/passwd", "scheme_not_allowed");
        reject("FILE:///sdcard/nodes.txt", "scheme_not_allowed");
        reject("javascript:alert(1)", "scheme_not_allowed");
        reject("data:text/plain;base64,Zm9v", "scheme_not_allowed");
        reject("ftp://example.com/nodes.txt", "scheme_not_allowed");
        reject("http://127.0.0.1:8080/nodes.txt", "host_private");
        reject("http://127.1/", "host_private");
        reject("http://2130706433/", "host_private");
        reject("http://0x7f000001/", "host_private");
        reject("http://0177.0.0.1/", "host_private");
        reject("http://localhost:1234/nodes", "host_local");
        reject("http://sub.localhost/", "host_local");
        reject("http://printer.local/", "host_local");
        reject("http://169.254.169.254/latest/meta-data/", "host_link_local");
        reject("http://metadata.google.internal/", "host_local");
        reject("http://10.0.0.5/nodes", "host_private");
        reject("http://172.20.1.1/nodes", "host_private");
        reject("http://192.168.1.1/nodes", "host_private");
        reject("http://100.64.0.1/nodes", "host_private");
        reject("http://[::1]/nodes", "host_local");
        reject("http://[fe80::1]/nodes", "host_private");
        reject("http://[::ffff:127.0.0.1]/nodes", "host_private");
        reject("http://user:pass@example.com/nodes", "credentials_in_url");
        reject("http://example.com/nodes#fragment", "fragment_not_allowed");
        reject("http://example.com:0/nodes", "port_not_allowed");
        reject("http://exa mple.com/nodes", "control_character");
        reject("http://example.com/a\r\nHost: evil", "control_character");
        reject("http://example.com\\@127.0.0.1/", "control_character");
        reject("http://-bad.example.com/", "host_invalid");
        reject("http://example..com/", "host_invalid");
        reject("http://" + repeat("a", 3000) + ".com/", "too_long");
    }

    private static String repeat(String text, int count) {
        StringBuilder builder = new StringBuilder(text.length() * count);
        for (int i = 0; i < count; i++) {
            builder.append(text);
        }
        return builder.toString();
    }

    public static void main(String[] args) {
        int passed = 0;
        int failed = 0;
        for (String[] testCase : CASES) {
            String url = testCase[0];
            String expected = testCase[1];
            String actual;
            try {
                SubscriptionGuard.check("<null>".equals(url) ? null : url);
                actual = null;
            } catch (SubscriptionGuard.Rejected rejected) {
                actual = rejected.reason;
            }
            boolean ok = expected == null ? actual == null : expected.equals(actual);
            String shown = "<null>".equals(url) ? "<null>" : (url.length() > 72 ? url.substring(0, 69) + "..." : url);
            System.out.println((ok ? "PASS " : "FAIL ") + shown
                    + "  expected=" + (expected == null ? "allow" : expected)
                    + "  actual=" + (actual == null ? "allow" : actual));
            if (ok) {
                passed++;
            } else {
                failed++;
            }
        }
        System.out.println("{\"cases\":" + CASES.size() + ",\"passed\":" + passed + ",\"failed\":" + failed + "}");
        if (failed > 0) {
            System.exit(1);
        }
    }
}
