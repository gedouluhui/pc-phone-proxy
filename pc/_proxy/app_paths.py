# -*- coding: utf-8 -*-
"""Read-only code lives in HERE; installed mutable state lives in DATA_DIR."""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.environ.get("PHONEPROXY_DATA_DIR") or HERE)


def data(*parts):
    return os.path.join(DATA_DIR, *parts)


def ensure_data():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(os.path.join(DATA_DIR, "logs"), exist_ok=True)
    return DATA_DIR
