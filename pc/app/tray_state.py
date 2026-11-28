# -*- coding: utf-8 -*-
"""Credential-free view model for the Windows tray."""


class Model:
    def __init__(self):
        self.state = "idle"
        self.mode = "split"
        self.healthy = 0
        self.detail = ""

    def update(self, status):
        status = status if isinstance(status, dict) else {}
        state = status.get("state")
        self.state = state if state in ("idle", "connecting", "running") else "idle"
        mode = status.get("mode")
        self.mode = mode if mode in ("split", "tun") else self.mode
        try:
            self.healthy = max(0, int(status.get("healthy", 0)))
        except (TypeError, ValueError):
            self.healthy = 0
        # Never surface arbitrary status fields: diagnostics may contain URIs.
        self.detail = str(status.get("detail", ""))[:120]

    def disconnect(self):
        self.state = "idle"
        self.healthy = 0
        self.detail = ""

    def label(self):
        state = {"idle": "未连接", "connecting": "连接中", "running": "运行中"}[self.state]
        mode = "TUN" if self.mode == "tun" else "分流"
        health = " · 健康出口 %d" % self.healthy if self.state == "running" and self.healthy else ""
        return "PhoneProxy · %s · %s%s" % (state, mode, health)
