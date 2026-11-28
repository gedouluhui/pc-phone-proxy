"""Release guard regressions; only synthetic ZIPs and node lists are used."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import runpy
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
import zlib
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PHONE = ROOT / "phone"
sys.path.insert(0, str(PHONE))


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = load_module("check_release_under_test", PHONE / "check_release.py")


class ReleaseGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="proxy-guard-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.apk = self.root / "test.apk"

    def make_apk(self, data=b"[]", names=("assets/nodes.json",)):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.apk, "w", zipfile.ZIP_DEFLATED) as archive:
                for name in names:
                    archive.writestr(name, data)
        return self.apk

    def cli(self, paths=None, tracked="", git_rc=0, git_error=None):
        output = io.StringIO()
        def git_run(args, **kwargs):
            if git_error:
                raise git_error
            # Model the selected git output protocol, including the old newline CLI.
            stdout = tracked if "-z" in args else tracked.replace("\0", "\n")
            return subprocess.CompletedProcess(args, git_rc, stdout, "fixture git error")

        with mock.patch.object(check, "ROOT", self.root), \
                mock.patch.object(check, "HERE", self.root / "phone"), \
                mock.patch.object(sys, "argv", [str(PHONE / "check_release.py")] +
                                  [str(p) for p in (paths or [])]), \
                mock.patch.object(check.subprocess, "run", side_effect=git_run), \
                contextlib.redirect_stdout(output):
            rc = check.main()
        return rc, output.getvalue()

    def assert_bad(self, reason):
        rc, output = self.cli([self.apk])
        self.assertNotEqual(rc, 0, output)
        self.assertIn(reason.lower(), output.lower())

    def test_empty_array_passes(self):
        self.make_apk()
        rc, output = self.cli([self.apk])
        self.assertEqual(rc, 0, output)
        self.assertEqual(check.nodes_in(self.apk), [])

    def test_object_rejected(self):
        self.make_apk(b"{}")
        self.assert_bad("array")

    def test_null_rejected(self):
        self.make_apk(b"null")
        self.assert_bad("array")

    def test_scalar_rejected(self):
        self.make_apk(b'""')
        self.assert_bad("array")

    def test_invalid_json_rejected(self):
        self.make_apk(b"[broken")
        self.assert_bad("invalid JSON")

    def test_invalid_utf8_rejected(self):
        self.make_apk(b"\xff")
        self.assert_bad("UTF-8")

    def test_nonempty_nodes_rejected_without_logging_uri(self):
        uri = "vless://synthetic-only@example.invalid:443"
        self.make_apk(json.dumps([{"uri": uri}]).encode())
        self.assert_bad("non-empty")
        self.assertNotIn(uri, self.cli([self.apk])[1])

    def test_missing_resource_rejected(self):
        self.make_apk(names=("assets/other.json",))
        self.assert_bad("missing")

    def test_duplicate_resource_rejected(self):
        self.make_apk(names=("assets/nodes.json", "assets/nodes.json"))
        self.assert_bad("duplicate")

    def test_oversized_resource_rejected(self):
        self.make_apk(b"[" + b" " * (2 * 1024 * 1024) + b"]")
        self.assert_bad("too large")

    def forge_empty_metadata(self):
        # Keep the actual compressed bytes/length; forge BOTH size and CRC headers.
        data = bytearray(self.apk.read_bytes())
        central = data.rindex(b"PK\x01\x02")
        for offset in (14, central + 16):
            struct.pack_into("<I", data, offset, zlib.crc32(b"[]"))
        for offset in (22, central + 24):
            struct.pack_into("<I", data, offset, 2)
        self.apk.write_bytes(data)

    def raw_apk(self, compressed, size=2, crc=None):
        """One DEFLATED entry with independent raw stream and declared metadata."""
        name = b"assets/nodes.json"
        crc = zlib.crc32(b"[]") if crc is None else crc
        local = struct.pack("<4s5H3I2H", b"PK\x03\x04", 20, 0, 8, 0, 0,
                            crc, len(compressed), size, len(name), 0) + name + compressed
        central = struct.pack("<4s6H3I5H2I", b"PK\x01\x02", 20, 20, 0, 8, 0, 0,
                              crc, len(compressed), size, len(name), 0, 0, 0, 0, 0, 0) + name
        end = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 1, 1,
                          len(central), len(local), 0)
        self.apk.write_bytes(local + central + end)

    @staticmethod
    def deflate(data):
        compressor = zlib.compressobj(wbits=-15)
        return compressor.compress(data) + compressor.flush()

    def test_forged_deflate_over_limit_rejected(self):
        self.make_apk(b"[]" + b" " * (2 * 1024 * 1024))
        self.forge_empty_metadata()
        with self.assertRaisesRegex(ValueError, "too large"):
            check.nodes_in(self.apk)
        self.assert_bad("too large")

    def test_forged_deflate_over_limit_real_cli(self):
        self.make_apk(b"[]" + b" " * (2 * 1024 * 1024))
        self.forge_empty_metadata()
        result = subprocess.run([sys.executable, "-B", str(PHONE / "check_release.py"),
                                 str(self.apk)], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", cwd=str(ROOT), timeout=30)
        self.assertNotEqual(result.returncode, 0, "forged APK passed the real CLI")
        self.assertIn("too large", result.stdout.lower())
        self.assertNotIn("assets/nodes.json = []", result.stdout)

    def test_forged_small_size_rejected(self):
        for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            with self.subTest(method=method):
                with zipfile.ZipFile(self.apk, "w", method) as archive:
                    archive.writestr("assets/nodes.json", b"[]    ")
                self.forge_empty_metadata()
                self.assert_bad("invalid APK")

    def test_declared_size_larger_than_stream_rejected(self):
        self.raw_apk(self.deflate(b"[]"), size=3)
        self.assert_bad("invalid APK")

    def test_crc_mismatch_rejected(self):
        self.raw_apk(self.deflate(b"[]"), crc=0)
        self.assert_bad("invalid APK")

    def test_truncated_deflate_rejected(self):
        # The last byte carries stream termination, not additional JSON output.
        self.raw_apk(self.deflate(b"[]")[:-1])
        self.assert_bad("invalid APK")

    def test_deflate_trailing_data_rejected(self):
        for suffix in (b"trailing", self.deflate(b"[]"), b"x" * (70 * 1024)):
            with self.subTest(suffix_bytes=len(suffix)):
                self.raw_apk(self.deflate(b"[]") + suffix)
                self.assert_bad("invalid APK")

    def test_invalid_deflate_rejected(self):
        self.raw_apk(b"\xff")
        self.assert_bad("invalid APK")

    def test_local_central_mismatch_rejected(self):
        # Local flags, method, CRC, compressed/uncompressed lengths and name.
        for offset, fmt, value in ((6, "H", 0x800), (8, "H", 0), (14, "I", 0),
                                   (18, "I", 1), (22, "I", 1), (30, "B", ord("X"))):
            with self.subTest(offset=offset):
                self.make_apk()
                data = bytearray(self.apk.read_bytes())
                struct.pack_into("<" + fmt, data, offset, value)
                self.apk.write_bytes(data)
                self.assert_bad("invalid APK")

    def test_central_name_with_nul_suffix_rejected(self):
        # ZipInfo.filename drops NUL suffixes; compare against the original name.
        self.make_apk()
        data = bytearray(self.apk.read_bytes())
        central = data.rindex(b"PK\x01\x02")
        end = data.rindex(b"PK\x05\x06")
        suffix = b"\0different-name"
        struct.pack_into("<H", data, central + 28, len(b"assets/nodes.json") + len(suffix))
        struct.pack_into("<I", data, end + 12, end - central + len(suffix))
        data[end:end] = suffix
        self.apk.write_bytes(data)
        self.assert_bad("invalid APK")

    def test_unsupported_compression_rejected(self):
        for method in (zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
            with self.subTest(method=method):
                with zipfile.ZipFile(self.apk, "w", method) as archive:
                    archive.writestr("assets/nodes.json", b"[]")
                self.assert_bad("invalid APK")

    def test_supported_methods_at_limit_pass(self):
        for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            for size in (2, 1024 * 1024):
                for level in (0, 9):
                    with self.subTest(method=method, size=size, compression_level=level):
                        with zipfile.ZipFile(self.apk, "w", method, compresslevel=level) as archive:
                            archive.writestr("assets/nodes.json", b"[]" + b" " * (size - 2))
                        self.assertEqual(check.nodes_in(self.apk), [])

    def test_deflate_uses_cumulative_output_budget(self):
        real_factory = zlib.decompressobj
        case = self

        class BudgetedInflater:
            def __init__(self, *args, **kwargs):
                self.inner = real_factory(*args, **kwargs)
                self.produced = 0

            def decompress(self, data, max_length=0):
                case.assertGreater(max_length, 0, "unbounded decompression")
                case.assertLessEqual(max_length, 1024 * 1024 + 1 - self.produced)
                result = self.inner.decompress(data, max_length)
                self.produced += len(result)
                return result

            def flush(self, *args, **kwargs):
                raise AssertionError("flush must not bypass the output budget")

            def __getattr__(self, name):
                return getattr(self.inner, name)

        for level in (0, 9):
            with self.subTest(compression_level=level):
                # Level 0 spans many input chunks, so a per-call (rather than
                # cumulative) MAX+1 budget would also be caught by the wrapper.
                compressor = zlib.compressobj(level=level, wbits=-15)
                payload = b"[]" + b" " * (2 * 1024 * 1024)
                self.raw_apk(compressor.compress(payload) + compressor.flush())
                with mock.patch("release_guard.zlib.decompressobj", BudgetedInflater):
                    with self.assertRaisesRegex(ValueError, "too large"):
                        check.nodes_in(self.apk)

    def test_corrupt_zip_rejected(self):
        self.apk.write_bytes(b"not a zip")
        self.assert_bad("invalid APK")

    def test_explicit_missing_apk_rejected(self):
        self.assert_bad("missing")

    def test_explicit_missing_apk_real_cli(self):
        result = subprocess.run([sys.executable, "-B", str(PHONE / "check_release.py"),
                                 str(self.apk)], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", cwd=str(ROOT))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("missing", result.stdout.lower())

    def test_default_absent_artifacts_allowed(self):
        self.assertEqual(self.cli()[0], 0)

    def test_default_existing_bad_artifact_rejected(self):
        dist = self.root / "dist"
        dist.mkdir()
        (dist / "手机代理-公版.apk").write_bytes(b"invalid")
        self.assertNotEqual(self.cli()[0], 0)

    def test_git_failure_rejected(self):
        rc, output = self.cli(git_rc=128)
        self.assertNotEqual(rc, 0, output)
        self.assertIn("git", output.lower())

    def test_git_unavailable_rejected(self):
        rc, output = self.cli(git_error=OSError("fixture unavailable"))
        self.assertNotEqual(rc, 0, output)
        self.assertIn("git", output.lower())

    def test_nested_sensitive_paths_rejected(self):
        for path in ("pc/_proxy/pinned.json", "copy/phone/assets/nodes.json",
                     "pc/_proxy/pinned_health.json", "nested/pool.json",
                     "nested/node_deep.json", "copy/phone/pc_test_config.json",
                     "keys/sub/RELEASE.JKS", "keys/sub/key.keystore",
                     "directory with spaces/release.apk"):
            with self.subTest(path=path):
                rc, output = self.cli(tracked=path + "\0")
                self.assertNotEqual(rc, 0, output)

    def test_sample_and_similar_names_allowed(self):
        rc, output = self.cli(tracked="phone/assets/nodes.sample.json\0"
                             "docs/pinned.json.example\0pc/pool.json.backup.txt\0")
        self.assertEqual(rc, 0, output)

    def test_invalid_pure_check_raises(self):
        self.make_apk(b"{}")
        with self.assertRaises(ValueError):
            check.nodes_in(self.apk)


def build_fixture_worker(script, scenario, args):
    """Run the actual build entrypoint, replacing ONLY native tool subprocesses.

    All files live in the parent test's TemporaryDirectory. These are synthetic
    ZIP pipeline tests, not native compilation, cryptographic signing or APKs.
    """
    events = []
    locks = []
    lock_observation = {}
    lock_stage = None
    lock_path = None
    root = Path(script).parent
    sys.path.insert(0, str(root))
    sys.argv = [script] + args

    def tool_run(argv, **kwargs):
        nonlocal lock_stage, lock_path
        argv = [str(arg) for arg in argv]
        tool = Path(argv[0]).name.lower().replace(".exe", "").replace(".bat", "")
        events.append({"argv": argv, "password_env_present": bool(
            kwargs.get("env", {}).get("PROXY_KS_PASS"))})
        rc = 0
        if tool == "keytool":
            Path(argv[argv.index("-keystore") + 1]).write_bytes(b"synthetic key placeholder")
        elif tool == "javac":
            dest = Path(argv[argv.index("-d") + 1]) / "com/luhui/phoneproxy"
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "Main.class").write_bytes(b"fake class")
            if scenario == "change-input":
                (root / "assets/nodes.sample.json").write_text('[{"uri":"fake"}]')
        elif tool == "d8":
            Path(argv[argv.index("--output") + 1], "classes.dex").write_bytes(b"fake dex")
        elif tool == "aapt2":
            dest = Path(argv[argv.index("-o") + 1])
            with zipfile.ZipFile(dest, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"synthetic manifest")
        elif tool == "zipalign":
            if "-c" not in argv:
                shutil.copyfile(argv[-2], argv[-1])
        elif tool == "apksigner" and argv[1] == "sign":
            dest = Path(argv[argv.index("--out") + 1])
            shutil.copyfile(argv[-1], dest)
            if scenario == "sign-fail":
                dest.write_bytes(b"partial signing output")
                rc = 7
            elif scenario.startswith("signed-"):
                data = {"signed-object": b"{}", "signed-null": b"null",
                        "signed-invalid": b"[bad", "signed-nonempty": b"[{}]"}.get(scenario, b"[]")
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    with zipfile.ZipFile(dest, "w") as archive:
                        archive.writestr("AndroidManifest.xml", b"synthetic manifest")
                        if scenario != "signed-missing":
                            archive.writestr("assets/nodes.json", data)
                        if scenario == "signed-duplicate":
                            archive.writestr("assets/nodes.json", data)
        elif tool == "apksigner" and argv[1] == "verify":
            if scenario in ("cleanup-locked", "promotion-locked", "cleanup-locked-verify-fail"):
                lock_stage = Path(kwargs["cwd"])
                lock_observation["verified_digest"] = hashlib.sha256(Path(argv[-1]).read_bytes()).hexdigest()
                if scenario == "promotion-locked":
                    lock_path = Path(os.environ["PROXY_APK_OUT"])
                else:
                    # An exception including this path would leak a configuration value.
                    lock_path = lock_stage / (os.environ["PROXY_KS_PASS"] + ".tmp")
                    lock_path.write_bytes(b"synthetic locked staging file")
                locks.append(lock_path.open("rb"))
                try:
                    lock_path.unlink()
                except PermissionError:
                    lock_observation["windows_delete_denied"] = True
                else:
                    raise AssertionError("fixture did not obtain a real Windows delete lock")
            if scenario in ("verify-fail", "cleanup-locked-verify-fail"):
                rc = 9
        else:
            raise AssertionError("Unexpected native command in fixture: " + tool)
        stdout = ""
        if scenario == "echo-secret" and tool == "apksigner":
            stdout = kwargs.get("env", {}).get("PROXY_KS_PASS", "")
        return subprocess.CompletedProcess(argv, rc, stdout, "synthetic failure" if rc else "")

    try:
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch("subprocess.run", side_effect=tool_run))
            if scenario in ("no-sdk", "import-no-sdk"):
                real_isdir = os.path.isdir
                stack.enter_context(mock.patch("os.path.isdir", side_effect=lambda path:
                    str(path).startswith(os.environ["JAVA_HOME"]) and real_isdir(path)))
            if scenario == "release-key-vanishes":
                real_isdir = os.path.isdir

                def remove_key_during_discovery(path):
                    key = Path(os.environ["PROXY_KEYSTORE"])
                    if key.exists():
                        key.unlink()
                    return real_isdir(path)

                stack.enter_context(mock.patch("os.path.isdir", side_effect=remove_key_during_discovery))
            if scenario in ("import-only", "import-no-sdk"):
                load_module("isolated_build", Path(script))
            else:
                runpy.run_path(script, run_name="__main__")
    finally:
        try:
            # Observe AFTER production main/TemporaryDirectory return, BEFORE unlock.
            if locks:
                lock_observation["staging_remains"] = lock_stage.exists()
                lock_observation["locked_file_remains"] = lock_path.exists()
                (root.parent / "lock-observation.json").write_text(
                    json.dumps(lock_observation), encoding="utf-8")
            (root.parent / "events.json").write_text(json.dumps(events), encoding="utf-8")
        finally:
            for handle in locks:
                handle.close()


class BuildGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="proxy-build-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.phone = self.root / "phone"
        self.phone.mkdir()
        for name in ("build_apk.py", "release_guard.py"):
            shutil.copyfile(PHONE / name, self.phone / name)
        tools = self.root / "tools"
        tools.mkdir()
        shutil.copyfile(ROOT / "tools" / "verify_sources.py", tools / "verify_sources.py")
        for name in ("sources.json", "sources.sig", "source_signing_public.pem"):
            shutil.copyfile(PHONE / name, self.phone / name)
        (self.phone / "assets").mkdir()
        (self.phone / "assets/nodes.sample.json").write_bytes(b"[]")
        self.jdk = self.root / "fake-jdk"
        (self.jdk / "bin").mkdir(parents=True)
        (self.jdk / "bin/javac.exe").touch()
        (self.jdk / "bin/javac").touch()
        self.sdk = self.root / "fake-sdk"
        (self.sdk / "build-tools/99.0.0").mkdir(parents=True)
        (self.sdk / "platforms/android-35").mkdir(parents=True)
        (self.sdk / "platforms/android-35/android.jar").touch()
        xray = self.phone / "libs/xray"
        (xray / "assets").mkdir(parents=True)
        (xray / "classes.jar").write_bytes(b"fake jar")
        for name in ("geoip.dat", "geosite.dat"):
            (xray / "assets" / name).write_bytes(b"fake data")
        for abi in ("arm64-v8a", "armeabi-v7a", "x86", "x86_64"):
            (xray / "jni" / abi).mkdir(parents=True)
            (xray / "jni" / abi / "libgojni.so").write_bytes(b"fake lib")
        self.output = self.root / "output dir" / "final.apk"
        self.output.parent.mkdir()
        self.key = self.root / "test.keystore"
        self.key.write_bytes(b"synthetic key placeholder")
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith("PROXY_") and key not in
                    ("JAVA_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT", "PYTHONPATH")}
        self.env.update(JAVA_HOME=str(self.jdk), ANDROID_HOME=str(self.sdk),
                        PROXY_KEYSTORE=str(self.key), PROXY_APK_OUT=str(self.output),
                        PROXY_KS_ALIAS="fixture-alias", PROXY_KS_PASS="fixture-only-password",
                        PYTHONIOENCODING="utf-8", TMP=str(self.root), TEMP=str(self.root))

    def build(self, scenario="success", args=("--public",)):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()),
                                 "--build-fixture", str(self.phone / "build_apk.py"),
                                 scenario] + list(args), env=self.env, cwd=str(self.root),
                                capture_output=True, text=True, encoding="utf-8", timeout=30)
        events_file = self.root / "events.json"
        self.events = json.loads(events_file.read_text()) if events_file.exists() else []
        return result

    def two_nodes(self):
        data = [{"uri": "vless://synthetic-one@example.invalid:443"},
                {"uri": "trojan://synthetic-two@example.invalid:443"}]
        (self.phone / "assets/nodes.json").write_text(json.dumps(data), encoding="utf-8")

    def existing_good(self):
        with zipfile.ZipFile(self.output, "w") as archive:
            archive.writestr("assets/nodes.json", "[]")
            archive.writestr("old-marker", "previous-good-output")
        return self.output.read_bytes()

    def test_public_rejects_two_nodes_before_tools(self):
        self.two_nodes()
        result = self.build()
        self.assertNotEqual(result.returncode, 0, "non-empty input must fail")
        self.assertIn("node preflight", (result.stdout + result.stderr).lower())
        self.assertFalse(self.output.exists())
        self.assertEqual(self.events, [])

    def test_node_preflight_precedes_missing_sdk(self):
        self.two_nodes()
        result = self.build("no-sdk")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("node preflight", (result.stdout + result.stderr).lower())
        self.assertNotIn("SDK not found", result.stdout + result.stderr)
        self.assertFalse(self.output.exists())

    def test_explicit_empty_input_overrides_local_pool(self):
        self.two_nodes()
        self.env["PROXY_NODES_JSON"] = str(self.phone / "assets/nodes.sample.json")
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(check.nodes_in(self.output), [])

    def test_invalid_selected_inputs_fail_before_tools(self):
        for data in (b"{}", b"null", b"[bad", b"\xff", b"[" + b" " * (2 * 1024 * 1024) + b"]"):
            with self.subTest(kind=data[:5]):
                (self.phone / "assets/nodes.sample.json").write_bytes(data)
                result = self.build()
                self.assertNotEqual(result.returncode, 0, "invalid selected input must fail")
                self.assertIn("node preflight", (result.stdout + result.stderr).lower())
                self.assertEqual(self.events, [])

    def test_explicit_missing_input_fails_before_tools(self):
        self.env["PROXY_NODES_JSON"] = str(self.root / "absent.json")
        result = self.build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("node preflight", (result.stdout + result.stderr).lower())
        self.assertEqual(self.events, [])

    def test_sign_failure_does_not_create_final(self):
        result = self.build("sign-fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists(), "partial signing output was published")

    def test_failed_verification_preserves_existing_apk(self):
        before = self.existing_good()
        result = self.build("verify-fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_bytes(), before, "previous APK was overwritten")

    def test_invalid_signed_assets_never_replace_existing_apk(self):
        for scenario in ("signed-object", "signed-null", "signed-missing", "signed-duplicate",
                         "signed-invalid", "signed-nonempty"):
            with self.subTest(scenario=scenario):
                before = self.existing_good()
                result = self.build(scenario)
                self.assertNotEqual(result.returncode, 0, "invalid signed APK was accepted")
                self.assertEqual(self.output.read_bytes(), before, "previous APK was overwritten")

    def test_import_does_not_build_or_discover_tools(self):
        result = self.build("import-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events, [], "import executed native tools")
        self.assertFalse(self.output.exists())

    def test_signer_uses_env_password_and_selected_alias(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        argv = next(event["argv"] for event in self.events if "sign" in event["argv"])
        self.assertIn("env:PROXY_KS_PASS", argv)
        self.assertNotIn("pass:android", argv)
        self.assertEqual(argv[argv.index("--ks-key-alias") + 1], "fixture-alias")
        self.assertTrue(all(self.env["PROXY_KS_PASS"] not in arg for arg in argv),
                        "password literal leaked into signer argv")
        verify = next(event["argv"] for event in self.events if "verify" in event["argv"])
        self.assertNotEqual(Path(verify[-1]), self.output, "verification happens after publication")

    def test_keytool_uses_same_env_password_and_alias(self):
        self.key.unlink()
        result = self.build()
        self.assertEqual(result.returncode, 0, "synthetic key generation failed")
        argv = next(event["argv"] for event in self.events if "-genkeypair" in event["argv"])
        self.assertIn("-storepass:env", argv)
        self.assertIn("-keypass:env", argv)
        self.assertEqual(argv[argv.index("-alias") + 1], "fixture-alias")
        self.assertTrue(all(self.env["PROXY_KS_PASS"] not in arg for arg in argv),
                        "password literal leaked into keytool argv")

    def test_tool_output_does_not_log_password(self):
        result = self.build("echo-secret")
        self.assertEqual(result.returncode, 0)
        self.assertTrue(self.env["PROXY_KS_PASS"] not in result.stdout + result.stderr,
                        "password literal leaked into build log")

    def test_release_flags_both_require_empty_input(self):
        self.two_nodes()
        for flag in ("PROXY_RELEASE", "PROXY_RELEASE_BUILD"):
            with self.subTest(flag=flag):
                self.env.pop("PROXY_RELEASE", None)
                self.env.pop("PROXY_RELEASE_BUILD", None)
                self.env[flag] = "1"
                result = self.build(args=())
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("node preflight", (result.stdout + result.stderr).lower())
                self.assertEqual(self.events, [])

    def test_release_flags_never_generate_keystore(self):
        self.key.unlink()
        for flag in ("PROXY_RELEASE", "PROXY_RELEASE_BUILD"):
            with self.subTest(flag=flag):
                self.env.pop("PROXY_RELEASE", None)
                self.env.pop("PROXY_RELEASE_BUILD", None)
                self.env[flag] = "1"
                result = self.build()
                self.assertNotEqual(result.returncode, 0, "release generated a key")
                self.assertFalse(self.key.exists())
                self.assertFalse(self.output.exists())
                self.assertEqual(self.events, [])

    def test_private_mode_still_embeds_selected_nodes(self):
        self.two_nodes()
        result = self.build(args=())
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(len(json.loads(archive.read("assets/nodes.json"))), 2)

    def test_preflight_input_is_snapshotted(self):
        result = self.build("change-input")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(check.nodes_in(self.output), [])

    def test_release_key_disappearing_after_preflight_never_regenerates(self):
        self.env["PROXY_RELEASE"] = "1"
        result = self.build("release-key-vanishes")
        self.assertNotEqual(result.returncode, 0, "release silently generated a new signing identity")
        self.assertFalse(self.key.exists())
        self.assertFalse(self.output.exists())
        self.assertFalse(any("-genkeypair" in event["argv"] for event in self.events))

    def test_import_needs_no_sdk(self):
        result = self.build("import-no-sdk")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events, [])

    def test_direct_build_script_rejects_nodes_without_tool_wrappers(self):
        self.two_nodes()
        result = subprocess.run([sys.executable, "-B", str(self.phone / "build_apk.py"), "--public"],
                                env=self.env, cwd=str(self.root), capture_output=True,
                                text=True, encoding="utf-8", timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("node preflight", (result.stdout + result.stderr).lower())
        self.assertFalse(self.output.exists())
        self.assertTrue("synthetic-one" not in result.stdout + result.stderr,
                        "node URI was logged")

    def test_release_rejects_demo_password_for_both_aliases(self):
        self.env.pop("PROXY_KS_PASS")
        for flag in ("PROXY_RELEASE", "PROXY_RELEASE_BUILD"):
            with self.subTest(flag=flag):
                self.env.pop("PROXY_RELEASE", None)
                self.env.pop("PROXY_RELEASE_BUILD", None)
                self.env[flag] = "1"
                result = self.build()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("signing preflight", (result.stdout + result.stderr).lower())
                self.assertEqual(self.events, [])

    def assert_safe_lock_log(self, result):
        diagnostic = result.stdout + result.stderr
        self.assertTrue(all(value not in diagnostic for value in
                            (self.env["PROXY_KS_PASS"], self.env["PROXY_KS_ALIAS"], str(self.key))),
                        "sensitive signing configuration leaked into diagnostics")
        self.assertNotIn("Traceback", diagnostic)
        return diagnostic

    @unittest.skipUnless(os.name == "nt", "requires real Windows delete-sharing semantics")
    def test_windows_cleanup_lock_after_commit_reports_success(self):
        before = self.existing_good()
        result = self.build("cleanup-locked")
        observation = json.loads((self.root / "lock-observation.json").read_text())
        after = self.output.read_bytes()
        self.assertTrue(observation["windows_delete_denied"])
        self.assertTrue(observation["staging_remains"])
        self.assertTrue(observation["locked_file_remains"])
        self.assertNotEqual(after, before, "verified new APK was not promoted")
        self.assertEqual(hashlib.sha256(after).hexdigest(), observation["verified_digest"])
        self.assertEqual(check.nodes_in(self.output), [])
        diagnostic = self.assert_safe_lock_log(result)
        self.assertEqual(result.returncode, 0,
                         "verified APK promoted and staging remains, but main returned failure")
        self.assertIn("产物已验证并晋升，但暂存清理失败", diagnostic)
        self.assertIn("APK OK", diagnostic)
        self.assertNotIn("not promoted", diagnostic)
        self.assertNotIn("FAIL:", diagnostic)

    @unittest.skipUnless(os.name == "nt", "requires real Windows delete-sharing semantics")
    def test_windows_locked_final_preserved_before_commit(self):
        before = self.existing_good()
        result = self.build("promotion-locked")
        observation = json.loads((self.root / "lock-observation.json").read_text())
        self.assertTrue(observation["windows_delete_denied"])
        self.assertTrue(observation["locked_file_remains"])
        self.assertFalse(observation["staging_remains"])
        self.assertEqual(self.output.read_bytes(), before)
        self.assertNotEqual(result.returncode, 0)
        diagnostic = self.assert_safe_lock_log(result)
        self.assertIn("not promoted", diagnostic)
        self.assertNotIn("APK OK", diagnostic)
        self.assertNotIn("产物已验证并晋升", diagnostic)

    @unittest.skipUnless(os.name == "nt", "requires real Windows delete-sharing semantics")
    def test_windows_cleanup_lock_on_verification_failure_preserves_final(self):
        before = self.existing_good()
        result = self.build("cleanup-locked-verify-fail")
        observation = json.loads((self.root / "lock-observation.json").read_text())
        self.assertTrue(observation["windows_delete_denied"])
        self.assertTrue(observation["staging_remains"])
        self.assertTrue(observation["locked_file_remains"])
        self.assertEqual(self.output.read_bytes(), before)
        self.assertNotEqual(result.returncode, 0)
        diagnostic = self.assert_safe_lock_log(result)
        self.assertIn("not promoted", diagnostic)
        self.assertNotIn("APK OK", diagnostic)
        self.assertNotIn("产物已验证并晋升", diagnostic)

    def test_each_build_uses_clean_independent_staging(self):
        staged_paths = []
        for _ in range(2):
            result = self.build()
            self.assertEqual(result.returncode, 0, result.stderr)
            sign = next(event["argv"] for event in self.events if "sign" in event["argv"])
            staged = Path(sign[sign.index("--out") + 1])
            self.assertNotEqual(staged, self.output)
            self.assertFalse(staged.parent.exists(), "staging directory was not cleaned")
            staged_paths.append(staged)
        self.assertNotEqual(*staged_paths, "builds shared a fixed staging path")
        for name in ("obj", "dexout", "res.zip", "base.apk", "unsigned.apk", "aligned.apk"):
            self.assertFalse((self.phone / name).exists(), "shared intermediate artifact remains")
        self.assertFalse((self.root / "phoneproxy_public_nodes.json").exists())


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--build-fixture":
        build_fixture_worker(sys.argv[2], sys.argv[3], sys.argv[4:])
    else:
        unittest.main(verbosity=2)
