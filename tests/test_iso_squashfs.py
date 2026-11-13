import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from actions.package import Package
from actions.scanner import iso_helper, squashfs_helper


class FakeEntry:
    def __init__(self, archive_path, display_path=None):
        self.archive_path = archive_path
        self.display_path = display_path or archive_path.lstrip("/")
        self.path_type = "rockridge"


class FakeIsoReader:
    """按显示路径返回预置内容，模拟 pycdlib 的 ISO 读取接口。"""

    def __init__(self, contents):
        self.contents = contents
        self.extracted = []

    def list_entries(self):
        return [FakeEntry(f"/{path}", path) for path in self.contents]

    def extract_file(self, entry, target_path):
        self.extracted.append(entry.display_path)
        content = self.contents[entry.display_path]
        if isinstance(content, Path):
            shutil.copyfile(content, target_path)
        else:
            Path(target_path).write_bytes(content)

    def close(self):
        pass


class SquashfsDiscoveryTests(unittest.TestCase):
    def test_module_order_is_preserved(self):
        reader = FakeIsoReader({
            "live/filesystem.module":
                b"filesystem.squashfs\nfilesystem-extra.squashfs\n",
            "live/filesystem.squashfs": b"base",
            "live/filesystem-extra.squashfs": b"extra",
        })
        with tempfile.TemporaryDirectory() as work_dir:
            layers = squashfs_helper.discover_layers(
                reader, reader.list_entries(), work_dir)

        self.assertEqual(
            [layer.entry.display_path for layer in layers],
            ["live/filesystem.squashfs", "live/filesystem-extra.squashfs"])

    def test_module_accepts_absolute_paths_and_ignores_comments(self):
        reader = FakeIsoReader({
            "casper/filesystem.module":
                b"# comment\n\n/casper/filesystem.squashfs\n",
            "casper/filesystem.squashfs": b"base",
        })
        with tempfile.TemporaryDirectory() as work_dir:
            layers = squashfs_helper.discover_layers(
                reader, reader.list_entries(), work_dir)

        self.assertEqual(
            [layer.entry.display_path for layer in layers],
            ["casper/filesystem.squashfs"])

    def test_module_skips_missing_and_non_squashfs_entries(self):
        reader = FakeIsoReader({
            "live/filesystem.module":
                b"filesystem.squashfs\nmissing.squashfs\nnotes.txt\n",
            "live/filesystem.squashfs": b"base",
            "live/notes.txt": b"text",
        })
        with tempfile.TemporaryDirectory() as work_dir:
            layers = squashfs_helper.discover_layers(
                reader, reader.list_entries(), work_dir)

        self.assertEqual(
            [layer.entry.display_path for layer in layers],
            ["live/filesystem.squashfs"])

    def test_module_matches_iso9660_uppercase_names(self):
        reader = FakeIsoReader({
            "LIVE/FILESYSTEM.MODULE": b"FILESYSTEM.SQUASHFS\n",
            "LIVE/FILESYSTEM.SQUASHFS": b"base",
        })
        with tempfile.TemporaryDirectory() as work_dir:
            layers = squashfs_helper.discover_layers(
                reader, reader.list_entries(), work_dir)

        self.assertEqual(
            [layer.entry.display_path for layer in layers],
            ["LIVE/FILESYSTEM.SQUASHFS"])

    def test_fallback_ignores_oem_squashfs_at_iso_root(self):
        reader = FakeIsoReader({
            "live/filesystem.squashfs": b"base",
            "live/filesystem-extra.squashfs": b"extra",
            "oem.squashfs": b"oem",
        })
        with tempfile.TemporaryDirectory() as work_dir:
            layers = squashfs_helper.discover_layers(
                reader, reader.list_entries(), work_dir)

        self.assertEqual(
            [layer.entry.display_path for layer in layers],
            ["live/filesystem-extra.squashfs", "live/filesystem.squashfs"])


class WhiteoutTests(unittest.TestCase):
    def test_whiteout_removes_hidden_lower_file_and_marker(self):
        with tempfile.TemporaryDirectory() as rootfs:
            Path(rootfs, "usr", "bin").mkdir(parents=True)
            Path(rootfs, "usr", "bin", "tool").write_text("lower")
            Path(rootfs, "usr", "bin", ".wh.tool").write_text("")

            squashfs_helper._apply_whiteouts(rootfs)

            self.assertFalse(Path(rootfs, "usr", "bin", "tool").exists())
            self.assertFalse(Path(rootfs, "usr", "bin", ".wh.tool").exists())


def _build_squashfs(source_dir, output_path):
    subprocess.run(
        ["mksquashfs", str(source_dir), str(output_path),
         "-noappend", "-no-progress", "-no-xattrs", "-quiet"],
        check=True, capture_output=True)


def _write_dpkg_package(rootfs, name, version, files, contents):
    """在 rootfs 中写入 dpkg status、list 与 md5sums 条目。"""

    status_path = Path(rootfs, "var/lib/dpkg/status")
    status_path.parent.mkdir(parents=True, exist_ok=True)
    entry = (
        f"Package: {name}\n"
        f"Status: install ok installed\n"
        f"Architecture: amd64\n"
        f"Version: {version}\n"
        f"Maintainer: Demo <demo@example.com>\n"
        f"Description: {name} package\n\n"
    )
    existing = status_path.read_text() if status_path.exists() else ""
    status_path.write_text(existing + entry)

    info_dir = Path(rootfs, "var/lib/dpkg/info")
    info_dir.mkdir(parents=True, exist_ok=True)
    Path(info_dir, f"{name}.list").write_text(
        "".join(f"{path}\n" for path in files))
    checksums = []
    for path in files:
        target = Path(rootfs, path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(contents[name][path])
        digest = hashlib.md5(contents[name][path]).hexdigest()
        checksums.append(f"{digest}  {path}\n")
    Path(info_dir, f"{name}.md5sums").write_text("".join(checksums))


@unittest.skipUnless(
    shutil.which("mksquashfs") and shutil.which("unsquashfs"),
    "需要 squashfs-tools 才能验证多层叠加")
class SquashfsIsoScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_dir = tempfile.mkdtemp(prefix="linx_squashfs_test_")
        base = Path(cls.base_dir, "base")
        extra = Path(cls.base_dir, "extra")

        base_contents = {
            "demo": {"usr/bin/demo": b"base-demo"},
            "libc6": {"lib/x86_64-linux-gnu/libc.so.6": b"libc"},
        }
        _write_dpkg_package(
            base, "demo", "1.0", ["usr/bin/demo"], base_contents)
        _write_dpkg_package(
            base, "libc6", "2.36",
            ["lib/x86_64-linux-gnu/libc.so.6"], base_contents)
        Path(base, "usr/share/doc/demo").mkdir(parents=True)
        Path(base, "usr/share/doc/demo/copyright").write_text(
            "License: GPL-2+\n")

        extra_contents = {
            "demo": {"usr/bin/demo": b"top-demo"},
            "extra": {"usr/bin/extra": b"extra-tool"},
        }
        _write_dpkg_package(
            extra, "demo", "1.0", ["usr/bin/demo"], extra_contents)
        _write_dpkg_package(
            extra, "extra", "2.0", ["usr/bin/extra"], extra_contents)
        with open(extra / "var/lib/dpkg/status", "a") as status_file:
            status_file.write(
                "Package: libc6\n"
                "Status: install ok installed\n"
                "Architecture: amd64\n"
                "Version: 2.36\n"
                "Description: libc6 package\n\n")
        Path(extra, "usr/share/doc/demo").mkdir(parents=True)
        Path(extra, "usr/share/doc/demo/copyright").write_text(
            "License: MIT\n")

        cls.base_image = Path(cls.base_dir, "filesystem.squashfs")
        cls.extra_image = Path(cls.base_dir, "filesystem-extra.squashfs")
        _build_squashfs(base, cls.base_image)
        _build_squashfs(extra, cls.extra_image)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base_dir, ignore_errors=True)

    def test_scan_merges_layers_and_reads_dpkg_database(self):
        reader = FakeIsoReader({
            "live/filesystem.module":
                b"filesystem.squashfs\nfilesystem-extra.squashfs\n",
            "live/filesystem.squashfs": self.base_image,
            "live/filesystem-extra.squashfs": self.extra_image,
        })

        with mock.patch.object(iso_helper, "PyCdlibIsoReader",
                               return_value=reader):
            result, package_type = iso_helper.scan_iso(
                "demo.iso",
                "uos-desktop-25-professional-2500-amd64.iso",
                "2026-06-16T00:00:00Z", True, None)

        self.assertEqual(package_type, "deb")
        packages = result["packages_sbom"]["packages"]
        self.assertEqual(
            [package["name"] for package in packages],
            ["demo", "extra", "libc6"])
        self.assertEqual(result["packages_sbom"]["os_name"], "uos")
        self.assertEqual(
            result["packages_sbom"]["os_version"],
            "desktop-25-professional")
        self.assertEqual(result["packages_sbom"]["os_arch"], "x86_64")

        demo_files = {
            item["path"]: item for item in result["files_sbom"]["files"]
            if item["path"] == "/usr/bin/demo"
        }
        self.assertEqual(
            demo_files["/usr/bin/demo"]["checksums"]["value"],
            hashlib.md5(b"top-demo").hexdigest())

    def test_scan_falls_back_to_iso_packages_without_rootfs_database(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir, "source")
            Path(source, "etc").mkdir(parents=True)
            Path(source, "etc/os-release").write_text(
                'NAME="Demo OS"\nVERSION_ID="1"\n')
            image = Path(tmpdir, "filesystem.squashfs")
            _build_squashfs(source, image)

            reader = FakeIsoReader({
                "live/filesystem.module": b"filesystem.squashfs\n",
                "live/filesystem.squashfs": image,
                "pool/main/demo.deb": b"package",
            })
            package = Package(
                "demo", "1.0", None, "amd64", "deb", "SHA1", "abcdef123456")

            with mock.patch.object(iso_helper, "PyCdlibIsoReader",
                                   return_value=reader), \
                    mock.patch.object(iso_helper, "load_originators",
                                      return_value=[]), \
                    mock.patch.object(iso_helper, "save_originators"), \
                    mock.patch.object(iso_helper, "process_deb_package",
                                      return_value=(package, [], [])):
                result, package_type = iso_helper.scan_iso(
                    "demo.iso", "demo-1.0-amd64.iso",
                    "2026-06-16T00:00:00Z", True, None)

        self.assertEqual(package_type, "deb")
        self.assertEqual(
            result["packages_sbom"]["packages"][0]["name"], "demo")

    def test_scan_expands_layers_in_requested_work_dir_and_cleans_up(self):
        reader = FakeIsoReader({
            "live/filesystem.module": b"filesystem.squashfs\n",
            "live/filesystem.squashfs": self.base_image,
            "live/filesystem.size": b"1048576\n",
        })

        with tempfile.TemporaryDirectory() as work_parent:
            with mock.patch.object(iso_helper, "PyCdlibIsoReader",
                                   return_value=reader):
                result, package_type = iso_helper.scan_iso(
                    "demo.iso",
                    "uos-desktop-25-professional-2500-amd64.iso",
                    "2026-06-16T00:00:00Z", True, None,
                    work_dir=work_parent)

            self.assertEqual(os.listdir(work_parent), [])

        self.assertEqual(package_type, "deb")
        self.assertEqual(
            [package["name"] for package in result["packages_sbom"]["packages"]],
            ["demo", "libc6"])


class ExpectedSizeTests(unittest.TestCase):
    def test_reads_filesystem_size_from_live_directory(self):
        reader = FakeIsoReader({
            "live/filesystem.size": b"25129492480\n",
            "live/filesystem.squashfs": b"base",
        })
        with tempfile.TemporaryDirectory() as work_dir:
            size = squashfs_helper.read_expected_size(
                reader, reader.list_entries(), work_dir)

        self.assertEqual(size, 25129492480)

    def test_ignores_missing_or_invalid_size(self):
        reader = FakeIsoReader({"live/filesystem.size": b"not-a-number\n"})
        with tempfile.TemporaryDirectory() as work_dir:
            size = squashfs_helper.read_expected_size(
                reader, reader.list_entries(), work_dir)

        self.assertIsNone(size)


class WorkDirectoryTests(unittest.TestCase):
    def test_selects_first_candidate_with_enough_space(self):
        with tempfile.TemporaryDirectory() as tmp_root, \
                tempfile.TemporaryDirectory() as iso_root:
            small = os.path.join(tmp_root, "tmp")
            large = os.path.join(iso_root, "iso")
            os.makedirs(small)
            os.makedirs(large)
            free_by_path = {os.path.realpath(small): 1024,
                            os.path.realpath(large): 10 ** 12}

            def fake_free_space(path):
                return free_by_path.get(os.path.realpath(path))

            with mock.patch.object(
                    squashfs_helper.tempfile, "gettempdir",
                    return_value=small), \
                    mock.patch.object(squashfs_helper, "_free_space",
                                      side_effect=fake_free_space):
                with squashfs_helper.work_directory(
                        required_bytes=10 ** 11,
                        candidates=[large]) as work_dir:
                    self.assertEqual(
                        os.path.realpath(os.path.dirname(work_dir)),
                        os.path.realpath(large))
                    self.assertTrue(os.path.isdir(work_dir))

                self.assertFalse(os.path.exists(work_dir))

    def test_unknown_size_prefers_candidate_with_most_free_space(self):
        with tempfile.TemporaryDirectory() as tmp_root, \
                tempfile.TemporaryDirectory() as iso_root:
            small = os.path.join(tmp_root, "tmp")
            large = os.path.join(iso_root, "iso")
            os.makedirs(small)
            os.makedirs(large)
            free_by_path = {os.path.realpath(small): 1024,
                            os.path.realpath(large): 10 ** 12}

            def fake_free_space(path):
                return free_by_path.get(os.path.realpath(path))

            with mock.patch.object(
                    squashfs_helper.tempfile, "gettempdir",
                    return_value=small), \
                    mock.patch.object(squashfs_helper, "_free_space",
                                      side_effect=fake_free_space):
                with squashfs_helper.work_directory(
                        candidates=[large]) as work_dir:
                    self.assertEqual(
                        os.path.realpath(os.path.dirname(work_dir)),
                        os.path.realpath(large))

    def test_rejects_requested_work_dir_without_enough_space(self):
        with tempfile.TemporaryDirectory() as work_root, \
                mock.patch.object(squashfs_helper, "_free_space",
                                  return_value=1024):
            with self.assertRaises(RuntimeError) as context:
                with squashfs_helper.work_directory(
                        requested=work_root, required_bytes=10 ** 11):
                    self.fail("空间不足时不应进入工作目录")

        message = str(context.exception)
        self.assertIn("--work-dir", message)
        self.assertIn("93.1 GiB", message)

    def test_reports_all_candidates_when_none_has_enough_space(self):
        with tempfile.TemporaryDirectory() as tmp_root, \
                tempfile.TemporaryDirectory() as iso_root, \
                mock.patch.object(squashfs_helper.tempfile, "gettempdir",
                                  return_value=tmp_root), \
                mock.patch.object(squashfs_helper, "_free_space",
                                  return_value=1024):
            with self.assertRaises(RuntimeError) as context:
                with squashfs_helper.work_directory(
                        required_bytes=10 ** 11, candidates=[iso_root]):
                    self.fail("空间不足时不应进入工作目录")

        message = str(context.exception)
        self.assertIn(tmp_root, message)
        self.assertIn(iso_root, message)
        self.assertIn("--work-dir", message)

    def test_unsquashfs_write_failure_reports_disk_space(self):
        layer = squashfs_helper.SquashfsLayer(FakeEntry("/live/x.squashfs"), "x", 1)
        failed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="",
            stderr="FATAL ERROR: writer: failed to write file /tmp/w/rootfs/a.file")

        with mock.patch.object(squashfs_helper.subprocess, "run",
                               return_value=failed), \
                mock.patch.object(squashfs_helper, "_free_space",
                                  return_value=1024):
            with self.assertRaises(RuntimeError) as context:
                squashfs_helper._extract_squashfs(
                    "/usr/bin/unsquashfs", "image.squashfs", "/tmp/w/rootfs",
                    layer, expected_size=25129492480)

        message = str(context.exception)
        self.assertIn("failed to write file", message)
        self.assertIn("磁盘空间不足", message)
        self.assertIn("--work-dir", message)


if __name__ == "__main__":
    unittest.main()
