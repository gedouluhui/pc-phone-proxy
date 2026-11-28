package com.luhui.phoneproxy;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;

import org.json.JSONArray;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** v2：一键启动 + 节点池选择/测速 + 导入（剪贴板/订阅）+ 实时流量。 */
public class MainActivity extends Activity implements ProxyVpnService.Listener {

    private static final int REQ_VPN = 100;
    private static final int REQ_NOTIF = 101;

    private TextView status;
    private TextView traffic;
    private TextView logView;
    private Button button;
    private Button measureBtn;
    private Button gateBtn;
    private Button importBtn;
    private Spinner spinner;

    private ArrayAdapter<String> nodeAdapter;
    private final List<String> nodeLabels = new ArrayList<>();
    private final List<String> nodeTags = new ArrayList<>();
    private final List<ConfigBuilder.Node> nodeList = new ArrayList<>();
    private volatile boolean labelRefreshPending = false;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final StringBuilder logBuf = new StringBuilder();
    private String pendingNode = "auto";
    private String appliedSelection = "auto";
    private int gateOk = 0;
    private int gateTotal = 0;
    private boolean populating = false;
    private boolean emptyHinted = false;
    private TaskControl importControl;
    private int secondaryColor;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        boolean dark = (getResources().getConfiguration().uiMode
                & android.content.res.Configuration.UI_MODE_NIGHT_MASK)
                == android.content.res.Configuration.UI_MODE_NIGHT_YES;
        int background = Color.parseColor(dark ? "#121212" : "#F5F6F8");
        int foreground = Color.parseColor(dark ? "#F2F2F2" : "#1A1A1A");
        int secondary = Color.parseColor(dark ? "#C7C7C7" : "#555555");
        int muted = Color.parseColor(dark ? "#9FA3A8" : "#888888");
        int accent = Color.parseColor(dark ? "#8AB4F8" : "#3B6EA5");
        secondaryColor = secondary;

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(background);
        int pad = dp(20);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("手机代理");
        title.setTextSize(26);
        title.setTypeface(null, Typeface.BOLD);
        title.setTextColor(foreground);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("本机实测延迟+带宽选线 · 死节点自动替换 · 国内直连");
        sub.setTextSize(13);
        sub.setTextColor(muted);
        sub.setPadding(0, dp(4), 0, dp(16));
        root.addView(sub);

        status = new TextView(this);
        status.setTextSize(16);
        status.setTextColor(secondary);
        status.setPadding(0, 0, 0, dp(12));
        root.addView(status);

        TextView nodeLabel = new TextView(this);
        nodeLabel.setText("节点");
        nodeLabel.setTextSize(13);
        nodeLabel.setTextColor(muted);
        root.addView(nodeLabel);

        spinner = new Spinner(this);
        spinner.setContentDescription("选择代理节点");
        spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id) {
                if (populating || pos < 0 || pos >= nodeTags.size()) return;
                pendingNode = nodeTags.get(pos);
                if (ProxyVpnService.state == ProxyVpnService.STATE_RUNNING
                        && !pendingNode.equals(appliedSelection)) {
                    appendLog("切换到 " + (pendingNode.equals("auto") ? "自动选线" : pendingNode) + " …");
                    applyStart(pendingNode);
                }
            }
            @Override public void onNothingSelected(AdapterView<?> p) {}
        });
        root.addView(spinner);

        LinearLayout tools = new LinearLayout(this);
        tools.setOrientation(LinearLayout.HORIZONTAL);
        tools.setPadding(0, dp(8), 0, 0);

        measureBtn = new Button(this);
        measureBtn.setText("测速");
        measureBtn.setTextSize(14);
        measureBtn.setAllCaps(false);
        measureBtn.setOnClickListener(v -> {
            appendLog("开始测速…");
            Intent i = new Intent(this, ProxyVpnService.class)
                    .setAction(ProxyVpnService.ACTION_MEASURE);
            startService(i);
        });
        LinearLayout.LayoutParams mp = new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        mp.rightMargin = dp(8);
        tools.addView(measureBtn, mp);

        gateBtn = new Button(this);
        gateBtn.setText("AI 闸门");
        gateBtn.setTextSize(14);
        gateBtn.setAllCaps(false);
        // 为什么要单独一个按钮：测速只证明「连得上」，不证明「ChatGPT 认这个出口」。
        // 挂到 60 秒级自动跑会让免费节点池的 CPU/流量白烧，交给用户按需点一次。
        gateBtn.setOnClickListener(v -> {
            gateOk = 0;
            gateTotal = 0;
            gateBtn.setText("验证中…");
            appendLog("验证 AI 出口（ChatGPT / Claude）…");
            toast("开始验证，约 1-2 分钟");
            Intent i = new Intent(this, ProxyVpnService.class)
                    .setAction(ProxyVpnService.ACTION_GATE);
            startService(i);
        });
        LinearLayout.LayoutParams gp = new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        gp.rightMargin = dp(8);
        tools.addView(gateBtn, gp);

        importBtn = new Button(this);
        importBtn.setText("导入节点 / 订阅");
        importBtn.setTextSize(14);
        importBtn.setAllCaps(false);
        importBtn.setOnClickListener(v -> showImportDialog());
        tools.addView(importBtn, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        for (int i = 0; i < tools.getChildCount(); i++) {
            tools.getChildAt(i).setMinimumHeight(dp(48));
            tools.getChildAt(i).setContentDescription(((Button) tools.getChildAt(i)).getText());
        }
        root.addView(tools);

        button = new Button(this);
        button.setTextSize(18);
        button.setAllCaps(false);
        button.setContentDescription("连接或断开代理");
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(56));
        bp.topMargin = dp(16);
        bp.bottomMargin = dp(10);
        button.setLayoutParams(bp);
        button.setOnClickListener(v -> onButton());
        root.addView(button);

        traffic = new TextView(this);
        traffic.setTextSize(13);
        traffic.setTextColor(accent);
        traffic.setPadding(0, 0, 0, dp(8));
        traffic.setText("");
        root.addView(traffic);

        logView = new TextView(this);
        logView.setTextSize(12);
        logView.setTextColor(secondary);
        logView.setTextIsSelectable(true);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(logView);
        root.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);

        rebuildSpinner();

        refresh(ProxyVpnService.state,
                ProxyVpnService.state == ProxyVpnService.STATE_RUNNING
                        ? "已连接 · " + ProxyVpnService.runningNode : "未连接");

        // 公版不带任何内置节点；空池时给一次明确引导，别让用户点启动后只看到失败。
        if (nodeList.isEmpty()) {
            appendLog("节点池为空：直接点「启动代理」会自动从公开源找节点；也可以导入自己的订阅。");
            ui.post(this::showEmptyHint);
        }

        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            // Ask once. Android shows the dialog again on every request, and a
            // user who said no should not be asked at each cold start; the app
            // works without the notification permission.
            boolean asked = getSharedPreferences("phoneproxy", MODE_PRIVATE)
                    .getBoolean("notif_asked", false);
            if (!asked) {
                getSharedPreferences("phoneproxy", MODE_PRIVATE).edit()
                        .putBoolean("notif_asked", true).apply();
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIF);
            }
        }
    }

    // ------------------------------------------------------------- 节点列表

    private void rebuildSpinner() {
        populating = true;
        nodeLabels.clear();
        nodeTags.clear();
        nodeList.clear();
        nodeLabels.add("自动 · 智能选线（故障自动切换）");
        nodeTags.add("auto");
        try {
            // v3.0：按本机实测排序——能用的（延迟升序）在最上面，未测的居中，不可用的沉底
            for (ConfigBuilder.Node n : NodePool.sortedForDisplay(this, ConfigBuilder.loadNodes(this))) {
                nodeList.add(n);
                nodeTags.add(n.tag);
                nodeLabels.add(labelFor(n));
            }
        } catch (Exception e) {
            nodeLabels.add("节点读取失败");
            nodeTags.add("auto");
        }
        nodeAdapter = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_item, nodeLabels);
        nodeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner.setAdapter(nodeAdapter);
        int idx = nodeTags.indexOf(pendingNode);
        spinner.setSelection(idx < 0 ? 0 : idx);
        populating = false;
    }

    private String labelFor(ConfigBuilder.Node n) {
        // 状态来自 NodeHealth（按节点指纹持久化，重启 App 也在），不再只看本次会话
        NodeHealth.Entry e = NodeHealth.get(this, n.key);
        long now = System.currentTimeMillis();
        String suffix;
        if (e == null || e.testedAt == 0) suffix = " · 未测";
        else if (e.ms > 0) suffix = " · " + e.ms + "ms"
                + (now - e.testedAt > NodeHealth.FRESH_MS ? "（较早）" : "");
        else suffix = " · 不可用";
        // v3.1：实测带宽（12 小时内）与「需要分片才通」标记
        if (e != null && e.ms > 0 && e.kbps > 0 && now - e.speedAt <= NodePool.SPEED_USE_MS) {
            suffix += e.kbps >= 1024
                    ? String.format(Locale.US, " · %.1fMB/s", e.kbps / 1024.0)
                    : " · " + e.kbps + "KB/s";
        }
        if (e != null && e.frag && e.ms > 0) suffix += " · 分片";
        // AI✓ = 这个节点实测过得了 ChatGPT/Claude 的地区闸门（AI 域名只走这些）
        return n.name + (n.cg ? " · AI✓" : "") + suffix;
    }

    private void refreshLabels() {
        if (nodeAdapter == null) return;
        populating = true;
        for (int i = 0; i < nodeList.size() && i + 1 < nodeLabels.size(); i++) {
            nodeLabels.set(i + 1, labelFor(nodeList.get(i)));
        }
        nodeAdapter.notifyDataSetChanged();
        populating = false;
    }

    // ------------------------------------------------------------- 导入

    private void showImportDialog() {
        final String[] items = {
                "从公开源导入（抓取后在本机逐个实测，只留能连上的）",
                "粘贴分享链接 / 订阅地址",
                "清理不可用的导入节点",
                "清空已导入的节点",
                "每应用代理（留空＝全部应用）"
        };
        new AlertDialog.Builder(this)
                .setTitle("导入节点")
                .setItems(items, (d, which) -> {
                    if (which == 0) importFromPublicSources();
                    else if (which == 1) showPasteDialog();
                    else if (which == 2) pruneDead();
                    else if (which == 3) clearImported();
                    else showAppProxyDialog();
                })
                .setNegativeButton("取消", null)
                .show();
    }

    /**
     * 从内置的公开源列表抓节点。APK 里只有 URL、没有任何凭据：每次都是运行时现抓，
     * 所以公开版装完点这一下就能用，而仓库与安装包都不会泄露别人的节点。
     */
    private void importFromPublicSources() {
        appendLog("从公开源抓节点，并在本机网络逐个实测（1~4 分钟，只留能连上的；APK 不含任何凭据）…");
        importBtn.setEnabled(false);
        new Thread(() -> {
            List<String> logs = new ArrayList<>();
            try {
                final int added = NodePool.refreshFromPublic(this, logs, 240000L, 0,
                        (node, ms, done, all) -> {
                            if (done == all || done % 40 == 0) appendLog("  实测 " + done + "/" + all);
                        },
                        () -> runOnUiThread(() -> {
                            appendLog("后台实测收尾：又有新节点测通，已入池");
                            rebuildSpinner();
                        }));
                final int total = ConfigBuilder.loadImportedUris(this).size();
                runOnUiThread(() -> {
                    importBtn.setEnabled(true);
                    for (String l : logs) appendLog("  · " + l);
                    appendLog("公开源结果：新增 " + added + " 个实测可用节点，导入池共 " + total + " 个");
                    rebuildSpinner();
                    if (added > 0) {
                        toast("新增 " + added + " 个能连上的节点");
                        if (ProxyVpnService.state == ProxyVpnService.STATE_RUNNING) {
                            applyStart(pendingNode, true);
                        }
                    } else {
                        toast("这次没找到能连上的新节点，稍后或换个网络再试");
                    }
                });
            } catch (Throwable e) {
                runOnUiThread(() -> {
                    importBtn.setEnabled(true);
                    for (String l : logs) appendLog("  · " + l);
                    toast("抓取失败：" + e.getMessage());
                    appendLog("抓取失败：" + e.getMessage());
                });
            }
        }, "public-sources").start();
    }

    private void pruneDead() {
        int n = NodePool.pruneDeadImports(this, 1);
        toast(n > 0 ? "清理了 " + n + " 个不可用节点" : "没有可清理的（未实测的节点不会被删）");
        appendLog("清理不可用导入节点：" + n + " 个");
        rebuildSpinner();
        if (n > 0 && ProxyVpnService.state == ProxyVpnService.STATE_RUNNING) {
            applyStart(pendingNode, true);
        }
    }

    private void showPasteDialog() {
        EditText et = new EditText(this);
        et.setHint("粘贴 vless:// vmess:// ss:// trojan:// hysteria2:// 链接\n或 http(s) 订阅链接；支持多行");
        et.setMinLines(3);
        et.setGravity(Gravity.TOP | Gravity.START);
        String clip = clipboardText();
        if (clip != null && (clip.contains("://"))) et.setText(clip);

        new AlertDialog.Builder(this)
                .setTitle("粘贴导入")
                .setView(et)
                .setPositiveButton("导入", (d, w) -> doImport(et.getText().toString()))
                .setNegativeButton("取消", null)
                .show();
    }

    private String clipboardText() {
        try {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null && cm.hasPrimaryClip() && cm.getPrimaryClip() != null
                    && cm.getPrimaryClip().getItemCount() > 0) {
                CharSequence t = cm.getPrimaryClip().getItemAt(0).coerceToText(this);
                return t == null ? null : t.toString();
            }
        } catch (Exception ignored) {}
        return null;
    }

    private void doImport(String text) {
        final String t = text == null ? "" : text.trim();
        if (t.isEmpty()) {
            toast("没有可导入的内容");
            return;
        }
        if (importControl != null) importControl.cancel();
        final TaskControl control = new TaskControl();
        importControl = control;
        new Thread(() -> {
            List<String> logs = new ArrayList<>();
            try {
                if (control.isCancelled()) return;
                List<String> uris;
                if (looksLikeSubscription(t)) {
                    appendLog("拉取订阅…");
                    uris = ConfigBuilder.fetchSubscription(t, control);
                } else {
                    uris = ConfigBuilder.splitUris(t);
                }
                if (control.isCancelled()) return;
                uris = ConfigBuilder.screenImports(this, uris, logs);
                if (control.isCancelled()) return;
                int added = NodePool.addUris(this, uris);
                int total = ConfigBuilder.loadImportedUris(this).size();
                runOnUiThread(() -> {
                    if (control.isCancelled() || isFinishing()) return;
                    for (String l : logs) appendLog("  · " + l);
                    toast("导入 " + added + " 个新节点（共 " + total + "），开始实测…");
                    appendLog("导入 " + added + " 个新节点（共 " + total + "）；自己的订阅不做筛除，只实测标注");
                    rebuildSpinner();
                    startService(new Intent(this, ProxyVpnService.class)
                            .setAction(ProxyVpnService.ACTION_MEASURE));
                    if (ProxyVpnService.state == ProxyVpnService.STATE_RUNNING) {
                        applyStart(pendingNode, true); // 强制重启使新节点生效
                    }
                });
            } catch (Exception e) {
                if (control.isCancelled()) return;
                runOnUiThread(() -> {
                    if (control.isCancelled() || isFinishing()) return;
                    toast("导入失败：" + e.getMessage());
                    appendLog("导入失败：" + e.getMessage());
                });
            }
        }, "import").start();
    }

    /** http(s) 且带路径/查询串 → 视为订阅；否则按节点链接解析。 */
    private boolean looksLikeSubscription(String t) {
        if (!t.matches("(?is)^https?://.*")) return false;
        if (t.contains("\n") || t.contains("://") && t.indexOf("://") != t.lastIndexOf("://")) {
            return false;
        }
        String rest = t.substring(t.indexOf("://") + 3);
        int slash = rest.indexOf('/');
        int q = rest.indexOf('?');
        return (slash >= 0 && rest.substring(slash).length() > 1) || q >= 0;
    }

    private void showAppProxyDialog() {
        try {
            List<android.content.pm.ApplicationInfo> apps = getPackageManager().getInstalledApplications(0);
            List<String> packages = new ArrayList<>();
            List<String> labels = new ArrayList<>();
            for (android.content.pm.ApplicationInfo info : apps) {
                if (info.packageName.equals(getPackageName())) continue;
                packages.add(info.packageName);
                labels.add(getPackageManager().getApplicationLabel(info) + "\n" + info.packageName);
            }
            HashSet<String> selected = new HashSet<>();
            try {
                String raw = SecureStore.get(this, "allowed_apps");
                if (raw != null) {
                    JSONArray array = new JSONArray(raw);
                    for (int i = 0; i < array.length(); i++) selected.add(array.optString(i));
                }
            } catch (Exception ignored) {}
            boolean[] checked = new boolean[packages.size()];
            for (int i = 0; i < packages.size(); i++) checked[i] = selected.contains(packages.get(i));
            new AlertDialog.Builder(this)
                    .setTitle("每应用代理")
                    .setMultiChoiceItems(labels.toArray(new String[0]), checked, (dialog, which, isChecked) -> {
                        if (isChecked) selected.add(packages.get(which));
                        else selected.remove(packages.get(which));
                    })
                    .setPositiveButton("保存并重连", (dialog, which) -> {
                        JSONArray array = new JSONArray();
                        for (String value : selected) array.put(value);
                        if (!SecureStore.put(this, "allowed_apps", array.toString())) {
                            toast("安全存储不可用，未保存");
                            return;
                        }
                        toast(selected.isEmpty() ? "已恢复全部应用代理" : "已保存 " + selected.size() + " 个应用");
                        if (ProxyVpnService.state == ProxyVpnService.STATE_RUNNING) applyStart(pendingNode, true);
                    })
                    .setNegativeButton("取消", null)
                    .show();
        } catch (Exception error) {
            toast("无法读取应用列表：" + error.getMessage());
        }
    }

    private void clearImported() {
        ConfigBuilder.saveImportedUris(this, new ArrayList<>());
        ConfigBuilder.clearKernelBad(this);
        toast("已清空导入节点");
        appendLog("已清空导入节点");
        rebuildSpinner();
        if (ProxyVpnService.state == ProxyVpnService.STATE_RUNNING) {
            applyStart(pendingNode, true);
        }
    }

    // ------------------------------------------------------------- 启停

    private void onButton() {
        if (ProxyVpnService.state == ProxyVpnService.STATE_RUNNING) {
            Intent i = new Intent(this, ProxyVpnService.class)
                    .setAction(ProxyVpnService.ACTION_STOP);
            startService(i);
            return;
        }
        if (ProxyVpnService.state == ProxyVpnService.STATE_CONNECTING) return;
        if (nodeList.isEmpty()) {
            appendLog("节点池为空：启动时会自动从公开源抓取并实测，约 1~3 分钟…");
        }
        Intent consent = VpnService.prepare(this);
        if (consent != null) {
            try {
                startActivityForResult(consent, REQ_VPN);
            } catch (Exception e) {
                appendLog("无法请求 VPN 授权：" + e.getMessage());
            }
            return;
        }
        applyStart(pendingNode);
    }

    private void showEmptyHint() {
        if (emptyHinted || isFinishing()) return;
        emptyHinted = true;
        new AlertDialog.Builder(this)
                .setTitle("还没有节点")
                .setMessage("这个版本不自带任何节点，避免把别人的节点凭据公开。\n\n"
                        + "直接点「启动代理」：App 会自动从公开源抓节点、在你当前的网络下逐个实测，"
                        + "只用能连上的（约 1~3 分钟）。\n\n"
                        + "也可以点「导入节点 / 订阅」粘贴自己的分享链接或订阅地址。")
                .setPositiveButton("去导入", (d, w) -> showImportDialog())
                .setNegativeButton("稍后", null)
                .show();
    }

    private void showKillSwitchGuide() {
        if (isFinishing() || getSharedPreferences("phoneproxy", MODE_PRIVATE)
                .getBoolean("kill_switch_guided", false)) return;
        getSharedPreferences("phoneproxy", MODE_PRIVATE).edit()
                .putBoolean("kill_switch_guided", true).apply();
        new AlertDialog.Builder(this)
                .setTitle("开启 VPN 防泄漏")
                .setMessage("当前 TUN 已接管 IPv4/IPv6。若要在隧道意外断开时也阻止裸连，"
                        + "请到系统 VPN 设置为本应用开启「始终开启 VPN」和「阻止无 VPN 的连接」。"
                        + "不同 Android 版本的名称可能不同。")
                .setPositiveButton("打开 VPN 设置", (d, w) -> {
                    try { startActivity(new Intent(android.provider.Settings.ACTION_VPN_SETTINGS)); }
                    catch (Exception ignored) { appendLog("无法打开系统 VPN 设置，请手动前往设置"); }
                })
                .setNegativeButton("稍后", null)
                .show();
    }

    private void applyStart(String node) {
        applyStart(node, false);
    }

    private void applyStart(String node, boolean force) {
        appliedSelection = node == null ? "auto" : node;
        Intent i = new Intent(this, ProxyVpnService.class)
                .setAction(ProxyVpnService.ACTION_START)
                .putExtra(ProxyVpnService.EXTRA_NODE, appliedSelection)
                .putExtra(ProxyVpnService.EXTRA_FORCE, force);
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(i);
        else startService(i);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) applyStart(pendingNode);
            else appendLog("VPN 授权被拒绝，无法启动");
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        ProxyVpnService.listener = this;
        String d;
        if (ProxyVpnService.state == ProxyVpnService.STATE_RUNNING) {
            d = "已连接 · " + ProxyVpnService.runningNode;
        } else if (ProxyVpnService.state == ProxyVpnService.STATE_CONNECTING) {
            d = "正在连接…";
        } else {
            d = "未连接";
        }
        refresh(ProxyVpnService.state, d);
        rebuildSpinner();
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (ProxyVpnService.listener == this) ProxyVpnService.listener = null;
    }

    @Override
    protected void onDestroy() {
        if (importControl != null) importControl.cancel();
        ui.removeCallbacksAndMessages(null);
        super.onDestroy();
    }

    // ------------------------------------------------------- Listener 回调

    @Override
    public void onStateChanged(int state, String detail) {
        ui.post(() -> {
            refresh(state, detail);
            if (state == ProxyVpnService.STATE_RUNNING) {
                appliedSelection = ProxyVpnService.currentSelection;
                showKillSwitchGuide();
            }
        });
    }

    @Override
    public void onLog(String line) {
        ui.post(() -> appendLog(line));
    }

    @Override
    public void onTraffic(long upBps, long downBps, String activeTag) {
        ui.post(() -> {
            if (ProxyVpnService.state != ProxyVpnService.STATE_RUNNING) {
                traffic.setText("");
                return;
            }
            StringBuilder sb = new StringBuilder();
            sb.append("↓ ").append(fmtSpeed(downBps))
              .append("   ↑ ").append(fmtSpeed(upBps));
            if (activeTag != null && !activeTag.isEmpty()) {
                sb.append("   走 ").append(activeTag);
            }
            traffic.setText(sb.toString());
        });
    }

    @Override
    public void onMeasure(String tag, long ms) {
        // 实测几百个节点时回调很密，合并成每 400ms 刷一次标签
        if (labelRefreshPending) return;
        labelRefreshPending = true;
        ui.postDelayed(() -> {
            labelRefreshPending = false;
            refreshLabels();
        }, 400);
    }

    @Override
    public void onNodesChanged() {
        ui.post(this::rebuildSpinner);
    }

    @Override
    public void onGate(String tag, boolean ok, int done, int total) {
        ui.post(() -> {
            gateTotal = total;
            if (ok) gateOk++;
            if (done >= total) {
                gateBtn.setText("AI 闸门");
                appendLog("AI 闸门结果：" + gateOk + "/" + total
                        + " 个节点能过 ChatGPT/Claude"
                        + (gateOk == 0 ? "（这批都不行，换节点源或换网络）" : ""));
                gateOk = 0;
                gateTotal = 0;
                rebuildSpinner();   // 重新读一遍 cg 标记，标签上的 AI✓ 才会更新
            } else if (!ok) {
                appendLog("  " + tag + " 未通过 AI 闸门（" + done + "/" + total + "）");
                gateBtn.setText("验证中 " + done + "/" + total);
            } else {
                gateBtn.setText("验证中 " + done + "/" + total);
            }
        });
    }

    // ------------------------------------------------------------- 视图

    private void refresh(int state, String detail) {
        status.setText(detail);
        switch (state) {
            case ProxyVpnService.STATE_RUNNING:
                button.setText("断开代理");
                button.setEnabled(true);
                spinner.setEnabled(true); // 运行中可直接换节点
                status.setTextColor(Color.parseColor("#1B7F3B"));
                break;
            case ProxyVpnService.STATE_CONNECTING:
                button.setText("正在连接…");
                button.setEnabled(false);
                spinner.setEnabled(false);
                status.setTextColor(Color.parseColor("#B26A00"));
                break;
            default:
                button.setText("启动代理");
                button.setEnabled(true);
                spinner.setEnabled(true);
                status.setTextColor(secondaryColor);
                traffic.setText("");
        }
    }

    private void appendLog(String line) {
        // The import and probe paths log from background threads; touching a
        // TextView there throws CalledFromWrongThreadException and swallows the
        // real error (found on the emulator, v2.5 build).
        if (Looper.myLooper() != Looper.getMainLooper()) {
            runOnUiThread(() -> appendLog(line));
            return;
        }
        logBuf.append(line).append('\n');
        if (logBuf.length() > 8000) logBuf.delete(0, logBuf.length() - 8000);
        logView.setText(logBuf.toString());
    }

    private void toast(String s) {
        // Same reason: a toast from a background thread is a no-op on newer
        // Android versions and hides the message the user needs.
        if (Looper.myLooper() != Looper.getMainLooper()) {
            runOnUiThread(() -> toast(s));
            return;
        }
        android.widget.Toast.makeText(this, s, android.widget.Toast.LENGTH_SHORT).show();
    }

    private String fmtSpeed(long bps) {
        if (bps < 1024) return bps + " B/s";
        if (bps < 1024 * 1024) return String.format(Locale.US, "%.0f KB/s", bps / 1024.0);
        return String.format(Locale.US, "%.1f MB/s", bps / 1048576.0);
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
