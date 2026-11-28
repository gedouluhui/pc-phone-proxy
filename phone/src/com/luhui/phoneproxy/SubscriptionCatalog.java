package com.luhui.phoneproxy;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/** Schema-validated subscription records; URLs are persisted only via SecureStore. */
public final class SubscriptionCatalog {
    public static final int MAX_RECORDS = 20;

    public static final class Record {
        public final String name;
        public final String url;
        public final boolean enabled;
        public final long lastUpdate;
        public final int lastCount;

        Record(String name, String url, boolean enabled, long lastUpdate, int lastCount) {
            this.name = name;
            this.url = url;
            this.enabled = enabled;
            this.lastUpdate = lastUpdate;
            this.lastCount = lastCount;
        }
    }

    private SubscriptionCatalog() {}

    public static List<Record> parse(String raw) {
        if (raw == null || raw.trim().isEmpty()) return new ArrayList<>();
        try {
            JSONArray array = new JSONArray(raw);
            if (array.length() > MAX_RECORDS) throw new IllegalArgumentException("too many subscriptions");
            List<Record> records = new ArrayList<>();
            java.util.Set<String> names = new java.util.HashSet<>();
            java.util.Set<String> urls = new java.util.HashSet<>();
            for (int i = 0; i < array.length(); i++) {
                JSONObject item = array.optJSONObject(i);
                if (item == null) throw new IllegalArgumentException("invalid subscription");
                String name = item.optString("name", "").trim();
                String url = item.optString("url", "").trim();
                validate(name, url);
                if (!names.add(name) || !urls.add(url)) {
                    throw new IllegalArgumentException("duplicate subscription");
                }
                long updated = item.optLong("lastUpdate", 0);
                int count = item.optInt("lastCount", 0);
                if (updated < 0 || count < 0 || count > 100000) {
                    throw new IllegalArgumentException("invalid subscription metadata");
                }
                records.add(new Record(name, url, item.optBoolean("enabled", true), updated, count));
            }
            return records;
        } catch (org.json.JSONException error) {
            throw new IllegalArgumentException("invalid subscription catalog", error);
        }
    }

    public static String serialize(List<Record> records) {
        JSONArray array = new JSONArray();
        try {
            for (Record record : records) {
                array.put(new JSONObject().put("name", record.name).put("url", record.url)
                        .put("enabled", record.enabled).put("lastUpdate", record.lastUpdate)
                        .put("lastCount", record.lastCount));
            }
        } catch (org.json.JSONException error) {
            throw new IllegalArgumentException("cannot serialize subscriptions", error);
        }
        return array.toString();
    }

    public static List<Record> upsert(List<Record> records, String name, String url) {
        validate(name, url);
        List<Record> result = copy(records);
        for (int i = 0; i < result.size(); i++) {
            Record old = result.get(i);
            if (old.name.equals(name) && !old.url.equals(url)) {
                throw new IllegalArgumentException("duplicate subscription name");
            }
            if (old.url.equals(url)) {
                result.set(i, new Record(name, url, old.enabled, old.lastUpdate, old.lastCount));
                return result;
            }
        }
        if (result.size() >= MAX_RECORDS) throw new IllegalArgumentException("too many subscriptions");
        result.add(new Record(name, url, true, 0, 0));
        return result;
    }

    public static List<Record> remove(List<Record> records, String url) {
        List<Record> result = copy(records);
        result.removeIf(record -> record.url.equals(url));
        return result;
    }

    public static List<Record> setEnabled(List<Record> records, String url, boolean enabled) {
        List<Record> result = copy(records);
        for (int i = 0; i < result.size(); i++) {
            Record old = result.get(i);
            if (old.url.equals(url)) {
                result.set(i, new Record(old.name, url, enabled, old.lastUpdate, old.lastCount));
            }
        }
        return result;
    }

    public static List<Record> touch(List<Record> records, String url, long when, int count) {
        List<Record> result = copy(records);
        for (int i = 0; i < result.size(); i++) {
            Record old = result.get(i);
            if (old.url.equals(url)) {
                result.set(i, new Record(old.name, url, old.enabled, when, count));
            }
        }
        return result;
    }

    private static List<Record> copy(List<Record> records) {
        return records == null ? new ArrayList<Record>() : new ArrayList<>(records);
    }

    private static void validate(String name, String url) {
        name = name == null ? null : name.trim();
        if (name == null || name.isEmpty() || name.length() > 40) {
            throw new IllegalArgumentException("invalid subscription name");
        }
        for (int i = 0; i < name.length(); i++) {
            if (name.charAt(i) < 0x20 || name.charAt(i) == 0x7f) {
                throw new IllegalArgumentException("invalid subscription name");
            }
        }
        if (url == null || !url.startsWith("https://")) {
            throw new IllegalArgumentException("HTTPS subscription required");
        }
        try {
            SubscriptionGuard.check(url);
        } catch (SubscriptionGuard.Rejected error) {
            throw new IllegalArgumentException("invalid subscription URL");
        }
    }
}
