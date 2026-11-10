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

import java.util.ArrayList;
import java.util.HashMap;
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
    private Button importBtn;
    private Spinner spinner;

    private ArrayAdapter<String> nodeAdapter;
    private final List<String> nodeLabels = new ArrayList<>();
    private final List<String> nodeTags = new ArrayList<>();
    private final List<ConfigBuilder.Node> nodeList = new ArrayList<>();
    private final Map<String, Long> nodeMs = new HashMap<>();

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final StringBuilder logBuf = new StringBuilder();
    private String pendingNode = "auto";
    private String appliedSelection = "auto";
    private boolean populating = false;
    private boolean emptyHinted = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#F5F6F8"));
        int pad = dp(20);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("手机代理");
        title.setTextSize(26);
        title.setTypeface(null, Typeface.BOLD);
        title.setTextColor(Color.parseColor("#1A1A1A"));
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("与电脑共用节点池 · 自动选线 · 国内外自动分流");
        sub.setTextSize(13);
        sub.setTextColor(Color.parseColor("#888888"));
        sub.setPadding(0, dp(4), 0, dp(16));
        root.addView(sub);

        status = new TextView(this);
        status.setTextSize(16);
        status.setTextColor(Color.parseColor("#555555"));
        status.setPadding(0, 0, 0, dp(12));
        root.addView(status);

        TextView nodeLabel = new TextView(this);
        nodeLabel.setText("节点");
        nodeLabel.setTextSize(13);
        nodeLabel.setTextColor(Color.parseColor("#888888"));
        root.addView(nodeLabel);

        spinner = new Spinner(this);
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

        importBtn = new Button(this);
        importBtn.setText("导入节点 / 订阅");
        importBtn.setTextSize(14);
        importBtn.setAllCaps(false);
        importBtn.setOnClickListener(v -> showImportDialog());
        tools.addView(importBtn, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(tools);

        button = new Button(this);
        button.setTextSize(18);
        button.setAllCaps(false);
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(56));
        bp.topMargin = dp(16);
        bp.bottomMargin = dp(10);
        button.setLayoutParams(bp);
        button.setOnClickListener(v -> onButton());
        root.addView(button);

        traffic = new TextView(this);
        traffic.setTextSize(13);
        traffic.setTextColor(Color.parseColor("#3B6EA5"));
        traffic.setPadding(0, 0, 0, dp(8));
        traffic.setText("");
        root.addView(traffic);

        logView = new TextView(this);
        logView.setTextSize(12);
        logView.setTextColor(Color.parseColor("#666666"));
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
            appendLog("节点池为空：先点「导入节点 / 订阅」粘贴分享链接或订阅地址。");
            ui.post(this::showEmptyHint);
        }

        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIF);
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
            for (ConfigBuilder.Node n : ConfigBuilder.loadNodes(this)) {
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
        Long ms = nodeMs.get(n.tag);
        String suffix = "";
        if (ms != null) suffix = ms < 0 ? " · 不可用" : " · " + ms + "ms";
        return n.name + suffix;
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
        EditText et = new EditText(this);
        et.setHint("粘贴 vless:// vmess:// ss:// trojan:// 链接\n或 http(s) 订阅链接；支持多行");
        et.setMinLines(3);
        et.setGravity(Gravity.TOP | Gravity.START);
        String clip = clipboardText();
        if (clip != null && (clip.contains("://"))) et.setText(clip);

        new AlertDialog.Builder(this)
                .setTitle("导入节点")
                .setView(et)
                .setPositiveButton("导入", (d, w) -> doImport(et.getText().toString()))
                .setNeutralButton("清空已导入", (d, w) -> clearImported())
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
        new Thread(() -> {
            try {
                List<String> uris;
                if (looksLikeSubscription(t)) {
                    appendLog("拉取订阅…");
                    uris = ConfigBuilder.fetchSubscription(t);
                } else {
                    uris = ConfigBuilder.splitUris(t);
                }
                int added = ConfigBuilder.addImportedUris(this, uris);
                int total = ConfigBuilder.loadImportedUris(this).size();
                runOnUiThread(() -> {
                    toast("导入 " + added + " 个新节点（共 " + total + "）");
                    appendLog("导入 " + added + " 个新节点（共 " + total + "）");
                    rebuildSpinner();
                    if (ProxyVpnService.state == ProxyVpnService.STATE_RUNNING) {
                        applyStart(pendingNode, true); // 强制重启使新节点生效
                    }
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
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

    private void clearImported() {
        ConfigBuilder.saveImportedUris(this, new ArrayList<>());
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
            appendLog("还没有节点，先导入再启动。");
            showEmptyHint();
            return;
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
                        + "点「导入节点 / 订阅」，粘贴分享链接（每行一条），"
                        + "或 http(s) 订阅地址；导入后会自动连接。")
                .setPositiveButton("去导入", (d, w) -> showImportDialog())
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

    // ------------------------------------------------------- Listener 回调

    @Override
    public void onStateChanged(int state, String detail) {
        ui.post(() -> {
            refresh(state, detail);
            if (state == ProxyVpnService.STATE_RUNNING) {
                appliedSelection = ProxyVpnService.currentSelection;
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
        ui.post(() -> {
            nodeMs.put(tag, ms);
            refreshLabels();
        });
    }

    @Override
    public void onNodesChanged() {
        ui.post(this::rebuildSpinner);
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
                status.setTextColor(Color.parseColor("#555555"));
                traffic.setText("");
        }
    }

    private void appendLog(String line) {
        logBuf.append(line).append('\n');
        if (logBuf.length() > 8000) logBuf.delete(0, logBuf.length() - 8000);
        logView.setText(logBuf.toString());
    }

    private void toast(String s) {
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
