import com.luhui.phoneproxy.NodeConfigCodec;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/** JVM proof for canonical node identity and fail-closed AI routing. */
public final class NodeTrustHarness {
    public static void main(String[] args) throws Exception {
        JSONObject a = NodeConfigCodec.parseUri(
                "trojan://one@1.2.3.4:443?security=tls&sni=a.example.com#a");
        JSONObject b = NodeConfigCodec.parseUri(
                "trojan://two@1.2.3.4:443?security=tls&sni=a.example.com#b");
        a.put("tag", "proxy-a");
        JSONObject tagged = new JSONObject(a.toString());
        if (!NodeConfigCodec.outboundIdentity(a).equals(NodeConfigCodec.outboundIdentity(tagged))) {
            throw new AssertionError("tag changed node identity");
        }
        java.util.List<String> keys = new java.util.ArrayList<>();
        java.util.Iterator<String> iterator = a.keys();
        while (iterator.hasNext()) keys.add(iterator.next());
        java.util.Collections.reverse(keys);
        JSONObject reordered = new JSONObject();
        for (String key : keys) reordered.put(key, a.get(key));
        if (!NodeConfigCodec.outboundIdentity(a).equals(NodeConfigCodec.outboundIdentity(reordered))) {
            throw new AssertionError("JSON key order changed node identity");
        }
        if (NodeConfigCodec.outboundIdentity(a).equals(NodeConfigCodec.outboundIdentity(b))) {
            throw new AssertionError("credentials did not change node identity");
        }
        boolean hasStaticAi = false;
        for (String domain : com.luhui.phoneproxy.RoutingPolicy.AI_DOMAINS) {
            if ("oaistatic.com".equals(domain) || "oaiusercontent.com".equals(domain)) hasStaticAi = true;
        }
        if (!hasStaticAi) throw new AssertionError("shared AI policy lost static OpenAI domains");

        b.put("tag", "proxy-b");
        Set<String> cg = new HashSet<>();
        cg.add("b");
        JSONObject cfg = new JSONObject(NodeConfigCodec.fullConfig(
                Arrays.asList(a, b), cg, "auto", "proxy-a", null));
        JSONObject cgBalancer = null;
        JSONArray balancers = cfg.getJSONObject("routing").getJSONArray("balancers");
        for (int i = 0; i < balancers.length(); i++) {
            JSONObject item = balancers.getJSONObject(i);
            if ("cg-balancer".equals(item.getString("tag"))) cgBalancer = item;
        }
        if (cgBalancer == null || !"cg-b".equals(cgBalancer.optString("fallbackTag"))) {
            throw new AssertionError("AI balancer fell back to ungated proxy-a");
        }

        JSONObject noCg = new JSONObject(NodeConfigCodec.fullConfig(
                Arrays.asList(a, b), Collections.emptySet(), "auto", "proxy-a", null));
        boolean hasBlock = false;
        JSONArray outs = noCg.getJSONArray("outbounds");
        for (int i = 0; i < outs.length(); i++) {
            JSONObject out = outs.getJSONObject(i);
            if ("ai-block".equals(out.optString("tag"))
                    && "blackhole".equals(out.optString("protocol"))) hasBlock = true;
        }
        if (!hasBlock) throw new AssertionError("missing AI blackhole");

        JSONObject fixedUngated = new JSONObject(NodeConfigCodec.fullConfig(
                Arrays.asList(a, b), cg, "a", "proxy-a", null));
        boolean aiBlocked = false;
        JSONArray rules = fixedUngated.getJSONObject("routing").getJSONArray("rules");
        for (int i = 0; i < rules.length(); i++) {
            JSONObject rule = rules.getJSONObject(i);
            JSONArray domains = rule.optJSONArray("domain");
            if (domains != null && "ai-block".equals(rule.optString("outboundTag"))) {
                for (int j = 0; j < domains.length(); j++) {
                    if ("domain:chatgpt.com".equals(domains.getString(j))) aiBlocked = true;
                }
            }
        }
        if (!aiBlocked) throw new AssertionError("fixed ungated node did not block AI");

        System.out.println("node trust OK");
    }
}
