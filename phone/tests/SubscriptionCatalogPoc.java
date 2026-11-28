package com.luhui.phoneproxy;

import java.util.List;

/** JVM proof for encrypted subscription catalog schema and CRUD helpers. */
public final class SubscriptionCatalogPoc {
    private static int passed;
    private static int failed;
    private static void check(String name, boolean condition) {
        if (condition) { passed++; System.out.println("PASS " + name); }
        else { failed++; System.out.println("FAIL " + name); }
    }

    public static void main(String[] args) throws Exception {
        String url = "https://example.com/sub?token=synthetic";
        List<SubscriptionCatalog.Record> records = SubscriptionCatalog.parse("[]");
        records = SubscriptionCatalog.upsert(records, "Daily", url);
        check("upsert", records.size() == 1 && records.get(0).enabled);
        records = SubscriptionCatalog.upsert(records, "Daily renamed", url);
        check("upsert does not duplicate", records.size() == 1
                && records.get(0).name.equals("Daily renamed"));
        records = SubscriptionCatalog.setEnabled(records, url, false);
        check("disable", !records.get(0).enabled);
        records = SubscriptionCatalog.touch(records, url, 123, 45);
        check("update metadata", records.get(0).lastUpdate == 123 && records.get(0).lastCount == 45);
        String encoded = SubscriptionCatalog.serialize(records);
        check("round trip", SubscriptionCatalog.parse(encoded).get(0).url.equals(url));
        check("remove", SubscriptionCatalog.remove(records, url).isEmpty());

        boolean rejected = false;
        try { SubscriptionCatalog.upsert(records, "bad", "http://127.0.0.1/sub"); }
        catch (IllegalArgumentException expected) { rejected = true; }
        check("private HTTP subscription rejected", rejected);

        rejected = false;
        try { SubscriptionCatalog.upsert(records, "Daily renamed", "https://example.com/other"); }
        catch (IllegalArgumentException expected) { rejected = true; }
        check("duplicate names cannot enter catalog", rejected);

        rejected = false;
        try { SubscriptionCatalog.parse("[{\"name\":\"x\",\"url\":\"https://example.com/a\"},"
                + "{\"name\":\"x\",\"url\":\"https://example.com/b\"}]"); }
        catch (IllegalArgumentException expected) { rejected = true; }
        check("duplicate names rejected", rejected);

        rejected = false;
        try { SubscriptionCatalog.parse("{\"not\":\"an array\"}"); }
        catch (IllegalArgumentException expected) { rejected = true; }
        check("wrong schema rejected", rejected);

        System.out.println("{\"cases\":" + (passed + failed) + ",\"passed\":" + passed
                + ",\"failed\":" + failed + "}");
        if (failed > 0) System.exit(1);
    }
}
