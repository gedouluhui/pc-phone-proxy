"""Load real source without importing Windows/runtime proxy dependencies."""
import ast
import json
from pathlib import Path
import re
import time
import types

SOURCE = Path(__file__).resolve().parents[1] / "pc" / "_proxy"


def tree(name):
    path = SOURCE / (name + ".py")
    return ast.parse(path.read_text(encoding="utf-8")), str(path)


def functions(name, names, **namespace):
    parsed, path = tree(name)
    body = [n for n in parsed.body if isinstance(n, ast.FunctionDef) and n.name in names]
    assert {n.name for n in body} == set(names)
    exec(compile(ast.Module(body=body, type_ignores=[]), path, "exec"), namespace)
    return types.SimpleNamespace(**namespace)


def load_pac():
    parsed, path = tree("pacroute")
    constants = {"DEFAULT_GENERAL", "DEFAULT_FAST", "DEFAULT_HK", "DEFAULT_STEAM",
                 "DOMESTIC", "SENSITIVE", "DIRECT", "FAST", "GENERAL", "GOOGLE_APP",
                 "HK", "STEAM", "STEAM_DIRECT"}
    body = []
    for n in parsed.body:
        if isinstance(n, ast.FunctionDef):
            if n.name == "write_pac":
                break
            body.append(n)
        elif isinstance(n, ast.Assign) and all(isinstance(t, ast.Name) and t.id in constants
                                             for t in n.targets):
            body.append(n)
        elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id in constants:
            body.append(n)
        elif isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Attribute) and isinstance(n.value.func.value, ast.Name) and n.value.func.value.id == "FAST":
            body.append(n)
    namespace = {"json": json, "re": re, "time": time}
    exec(compile(ast.Module(body=body, type_ignores=[]), path, "exec"), namespace)
    # The functions retain this dict as their globals, so tests can inject list intersections.
    return namespace
