import ast
import gc
import importlib.util
import gzip
import tarfile
import tempfile
import unittest
import warnings
import zipfile
from io import BytesIO
from pathlib import Path
from unittest import mock

warnings.simplefilter("ignore", ResourceWarning)
warnings.simplefilter("ignore", DeprecationWarning)

import zstandard

from actions.data_helper import calculate_md5, calculate_sha1, remove_duplicates
from actions.licenses_helper import _extract_deb_license_list, rpm_licenses_scanner
from actions.package import Package
from actions.scanner import (
    iso_helper,
    originators_helper,
    package_helper,
    relationships_helper,
    repo_helper,
    scancode_helper,
    spdx_sbom_helper,
    src_package_helper,
    suppliers_helper,
)


ROOT_DIR = Path(__file__).resolve().parents[1]


class CodeQualityTests(unittest.TestCase):
    def test_imports_stay_at_module_top_level(self):
        for path in [ROOT_DIR / "linx-xiling.py", *(ROOT_DIR / "actions").rglob("*.py")]:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                for child in ast.iter_child_nodes(node):
                    child.parent = node
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    self.assertIsInstance(
                        getattr(node, "parent", None),
                        ast.Module,
                        f"{path} line {node.lineno} has a local import")


def load_cli_module():
    spec = importlib.util.spec_from_file_location(
        "linx_xiling_cli", ROOT_DIR / "linx-xiling.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_ar_member(target, name, content):
    encoded_name = (name + "/").encode("ascii")
    header = (
        encoded_name.ljust(16) +
        b"0".ljust(12) +
        b"0".ljust(6) +
        b"0".ljust(6) +
        b"100644".ljust(8) +
        str(len(content)).encode("ascii").ljust(10) +
        b"`\n"
    )
    target.write(header)
    target.write(content)
    if len(content) % 2:
        target.write(b"\n")


def make_tar_gz(members):
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, content in members.items():
            data = content.encode("utf-8") if isinstance(content, str) else content
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, BytesIO(data))
    return buffer.getvalue()


def make_minimal_deb(path):
    control = """Package: demo
Version: 1.0
Architecture: amd64
Maintainer: Demo Maintainer <demo@example.test>
Homepage: https://example.test/demo
Description: Demo package
Depends: libc6 (>= 2.36)
"""
    copyright_text = "License: MIT\n"
    control_tar = make_tar_gz({"./control": control})
    data_tar = make_tar_gz({
        "./usr/bin/demo": "#!/bin/sh\n",
        "./usr/share/doc/demo/copyright": copyright_text,
    })
    with open(path, "wb") as deb:
        deb.write(b"!<arch>\n")
        write_ar_member(deb, "debian-binary", b"2.0\n")
        write_ar_member(deb, "control.tar.gz", control_tar)
        write_ar_member(deb, "data.tar.gz", data_tar)


class OutputFormatTests(unittest.TestCase):
    def setUp(self):
        self.cli = load_cli_module()

    def test_resolve_output_formats_defaults_to_linx_and_spdx(self):
        self.assertEqual(self.cli.resolve_output_formats(None), ["linx", "spdx"])

    def test_resolve_output_formats_deduplicates_user_choices(self):
        self.assertEqual(
            self.cli.resolve_output_formats(["spdx", "linx", "spdx"]),
            ["spdx", "linx"])

    def test_save_sbom_can_write_only_spdx(self):
        linx_sbom = {
            "packages_sbom": {
                "packages": [{
                    "id": "Package-demo-abc123",
                    "name": "demo",
                    "version": "1.0",
                    "architecture": "x86_64",
                    "package_type": "rpm",
                    "depends": [],
                    "source": "NOASSERTION",
                    "licenses": [],
                    "suppliers": [],
                    "description": "demo package",
                    "checksum": {"algorithm": "SHA1", "value": "abc123"},
                }]
            },
            "licenses_sbom": {"licenses": []},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            self.cli.save_sbom(
                linx_sbom, "rpm", "demo", "20260616000000",
                "2026-06-16T00:00:00Z", tmpdir, ["spdx"])
            output_dir = Path(tmpdir) / "demo"
            self.assertTrue((output_dir / "spdx-sbom_demo_20260616000000.json").exists())
            self.assertFalse(any(output_dir.glob("linx-sbom_*")))

    def test_save_sbom_can_write_only_linx(self):
        linx_sbom = {
            "packages_sbom": {"packages": []},
            "files_sbom": {"files": []},
            "licenses_sbom": {"licenses": []},
            "package_relationships_sbom": {"package_relationships": []},
            "file_relationships_sbom": {"file_relationships": []},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            self.cli.save_sbom(
                linx_sbom, "rpm", "demo", "20260616000000",
                "2026-06-16T00:00:00Z", tmpdir, ["linx"])
            output_dir = Path(tmpdir) / "demo"
            self.assertTrue(any(output_dir.glob("linx-sbom_*")))
            self.assertFalse((output_dir / "spdx-sbom_demo_20260616000000.json").exists())

    def test_parse_arguments_has_no_deprecated_sbom_option(self):
        with mock.patch("sys.argv", ["linx-xiling.py", "-p", "a.rpm", "-o", "out", "-f", "spdx"]):
            args = self.cli.parse_arguments()
        self.assertEqual(args.format, ["spdx"])
        self.assertFalse(hasattr(args, "sbom"))


class PackageScannerTests(unittest.TestCase):
    def test_failed_rpm_scan_returns_empty_sbom(self):
        with mock.patch.object(package_helper, "read_data_from_json", return_value=[]), \
                mock.patch.object(package_helper, "save_data_to_json"), \
                mock.patch.object(package_helper, "process_rpm_package",
                                  return_value=(None, [], [], None)):
            result = package_helper.package_scanner(
                "broken.rpm", "rpm", "2026-06-16T00:00:00Z",
                None, None, None, True, False)

        self.assertEqual(result["packages_sbom"]["packages"], [])
        self.assertEqual(result["files_sbom"]["files"], [])
        self.assertEqual(result["file_relationships_sbom"]["file_relationships"], [])

    def test_deb_scan_error_returns_consistent_tuple(self):
        with tempfile.NamedTemporaryFile() as pkg, \
                mock.patch.object(package_helper, "_get_deb_info", side_effect=OSError("bad deb")):
            package, licenses, originators = package_helper.process_deb_package(pkg.name, [])

        self.assertIsNone(package)
        self.assertEqual(licenses, [])
        self.assertEqual(originators, [])

    def test_source_tar_does_not_call_src_rpm_file_scan(self):
        with mock.patch.object(package_helper, "process_src_package") as process_src, \
                mock.patch.object(package_helper, "scan_src_rpm") as scan_src:
            package = Package("generic", "", "", "source", "source", "MD5", "abc")
            process_src.return_value = (package, [], [])
            result = package_helper.process_source_package(
                "generic.tar.gz", [], None, None, None, True, False)

        self.assertIs(result[0], package)
        scan_src.assert_not_called()

    def test_process_deb_package_reads_minimal_deb(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            deb_path = Path(tmpdir) / "demo.deb"
            make_minimal_deb(deb_path)

            package, licenses, originators = package_helper.process_deb_package(
                str(deb_path), [])

        self.assertEqual(package.name, "demo")
        self.assertEqual(package.version, "1.0")
        self.assertEqual(package.arch, "amd64")
        self.assertIn("libc6 (>= 2.36)", package.declared_dependencies)
        self.assertTrue(any(file["name"] == "demo" for file in package.files))
        self.assertEqual(originators[0]["homepage"], "https://example.test/demo")
        self.assertIsInstance(licenses, list)

    def test_process_deb_package_closes_deb_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            deb_path = Path(tmpdir) / "demo.deb"
            make_minimal_deb(deb_path)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", ResourceWarning)
                package_helper.process_deb_package(str(deb_path), [])
                gc.collect()

        resource_warnings = [
            warning for warning in caught
            if issubclass(warning.category, ResourceWarning)
        ]
        self.assertEqual(resource_warnings, [])

    def test_process_rpm_package_reads_mocked_headers(self):
        class FakeRPM:
            headers = {
                "name": b"demo",
                "version": b"1.0",
                "release": b"1.el9",
                "url": b"https://example.test/demo",
                "arch": b"x86_64",
                "sourcerpm": b"demo-1.0.src.rpm",
                "copyright": b"MIT",
                "description": b"Demo RPM",
                "requirename": [b"libc.so.6"],
                "provides": [b"demo", b"libdemo.so"],
            }

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.NamedTemporaryFile() as pkg, \
                mock.patch.object(package_helper.rpmfile, "open", return_value=FakeRPM()), \
                mock.patch.object(package_helper, "rpm_files_scanner", return_value=[]):
            pkg.write(b"fake rpm")
            pkg.flush()
            package, licenses, originators, provides = package_helper.process_rpm_package(
                pkg.name, [])

        self.assertEqual(package.name, "demo")
        self.assertEqual(package.source, "demo-1.0.src.rpm")
        self.assertIn("libc.so.6", package.declared_dependencies)
        self.assertEqual(licenses[0]["name"], "MIT")
        self.assertIn("libdemo.so", provides["provides"])


class RepoScannerTests(unittest.TestCase):
    def test_find_primary_xml_uses_repomd_location(self):
        class Response:
            ok = True
            content = b"""<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="primary">
    <location href="repodata/primary.xml.gz"/>
  </data>
</repomd>"""

        with mock.patch.object(repo_helper.requests, "get", return_value=Response()) as get:
            result = repo_helper.find_primary_xml_in_repo("https://example.test/repo/")

        self.assertEqual(result, "https://example.test/repo/repodata/primary.xml.gz")
        get.assert_called_once_with(
            "https://example.test/repo/repodata/repomd.xml", timeout=10)

    def test_find_primary_xml_falls_back_to_directory_listing(self):
        class Response:
            def __init__(self, text="", ok=False):
                self.ok = ok
                self.text = text
                self.content = text.encode()

            def raise_for_status(self):
                return None

        responses = [
            Response(ok=False),
            Response('<a href="repodata/">repodata/</a>'),
            Response('<a href="primary.xml.gz">primary.xml.gz</a>'),
        ]

        with mock.patch.object(repo_helper.requests, "get", side_effect=responses):
            result = repo_helper.find_primary_xml_in_repo("https://example.test/repo/")

        self.assertEqual(result, "https://example.test/repo/repodata/primary.xml.gz")

    def test_fetch_and_extract_metadata_supports_gzip_and_zstd(self):
        class Response:
            def __init__(self, content):
                self.content = content

            def raise_for_status(self):
                return None

        gz_buffer = BytesIO()
        with gzip.GzipFile(fileobj=gz_buffer, mode="wb") as gz:
            gz.write(b"metadata")
        with mock.patch.object(repo_helper.requests, "get", return_value=Response(gz_buffer.getvalue())):
            self.assertEqual(repo_helper._fetch_and_extract_metadata("https://x/primary.xml.gz"), b"metadata")
            repo_helper.requests.get.assert_called_with(
                "https://x/primary.xml.gz", timeout=repo_helper.REQUEST_TIMEOUT)

        compressed = zstandard.ZstdCompressor().compress(b"metadata-zst")
        with mock.patch.object(repo_helper.requests, "get", return_value=Response(compressed)):
            self.assertEqual(repo_helper._fetch_and_extract_metadata("https://x/primary.xml.zst"), b"metadata-zst")

    def test_parse_sources_extracts_debian_source_package(self):
        source_data = b"""Package: demo
Version: 1.2
Homepage: https://example.test/demo
Checksums-Sha256:
 abcdef 123 demo_1.2.orig.tar.gz
"""
        packages, licenses, originators = repo_helper._parse_sources(source_data, [], disable_tqdm=True)

        self.assertEqual(packages[0].name, "demo")
        self.assertEqual(packages[0].checksum_value, "abcdef")
        self.assertEqual(licenses, [])
        self.assertEqual(originators[0]["homepage"], "https://example.test/demo")

    def test_parse_debian_source_block_keeps_multiline_fields(self):
        block = """Package: demo
Checksums-Sha256:
 abcdef 123 demo_1.2.orig.tar.gz
 012345 456 demo_1.2.debian.tar.xz
Description: demo source
"""
        fields = repo_helper._parse_debian_source_block(block)

        self.assertEqual(fields["Package"], "demo")
        self.assertIn("abcdef 123 demo_1.2.orig.tar.gz", fields["Checksums-Sha256"])
        self.assertIn("012345 456 demo_1.2.debian.tar.xz", fields["Checksums-Sha256"])


class IsoScannerTests(unittest.TestCase):
    class FakeIsoReader:
        def __init__(self, entries):
            self.entries = entries
            self.extracted_paths = []
            self.closed = False

        def list_entries(self):
            return self.entries

        def extract_file(self, entry, target_path):
            self.extracted_paths.append(target_path)
            Path(target_path).write_bytes(b"package")

        def close(self):
            self.closed = True

    def test_select_iso_path_type_uses_ranked_fallback(self):
        class FakeIso:
            def has_udf(self):
                return False

            def has_rock_ridge(self):
                return True

            def has_joliet(self):
                return True

        self.assertEqual(iso_helper._select_iso_path_type(FakeIso()), "rockridge")

    def test_scan_iso_detects_deb_and_extracts_temp_package(self):
        entries = [
            iso_helper.IsoEntry("/README.TXT", "README.TXT", "rockridge"),
            iso_helper.IsoEntry("/pool/main/demo.deb", "pool/main/demo.deb", "rockridge"),
        ]
        reader = self.FakeIsoReader(entries)
        package = Package("demo", "1.0", None, "amd64", "deb", "SHA1", "abcdef123456")

        def fake_process(path, originators):
            self.assertTrue(Path(path).exists())
            return package, [], originators

        with mock.patch.object(iso_helper, "PyCdlibIsoReader", return_value=reader), \
                mock.patch.object(iso_helper, "read_data_from_json", return_value=[]), \
                mock.patch.object(iso_helper, "save_data_to_json"), \
                mock.patch.object(iso_helper, "process_deb_package", side_effect=fake_process):
            result, package_type = iso_helper.scan_iso(
                "demo.iso", "demo-1.0-amd64.iso", "2026-06-16T00:00:00Z",
                True, None)

        self.assertEqual(package_type, "deb")
        self.assertTrue(reader.closed)
        self.assertEqual(len(reader.extracted_paths), 1)
        self.assertFalse(Path(reader.extracted_paths[0]).exists())
        self.assertEqual(result["packages_sbom"]["packages"][0]["name"], "demo")
        self.assertEqual(result["packages_sbom"]["os_arch"], "x86_64")

    def test_scan_iso_keeps_deb_precedence_when_both_package_types_exist(self):
        entries = [
            iso_helper.IsoEntry("/pool/main/demo.deb", "pool/main/demo.deb", "rockridge"),
            iso_helper.IsoEntry("/Packages/demo.rpm", "Packages/demo.rpm", "rockridge"),
        ]
        reader = self.FakeIsoReader(entries)
        package = Package("demo", "1.0", None, "amd64", "deb", "SHA1", "abcdef123456")

        with mock.patch.object(iso_helper, "PyCdlibIsoReader", return_value=reader), \
                mock.patch.object(iso_helper, "read_data_from_json", return_value=[]), \
                mock.patch.object(iso_helper, "save_data_to_json"), \
                mock.patch.object(iso_helper, "process_deb_package", return_value=(package, [], [])), \
                mock.patch.object(iso_helper, "process_rpm_package") as process_rpm:
            _, package_type = iso_helper.scan_iso(
                "demo.iso", "demo-1.0-amd64.iso", "2026-06-16T00:00:00Z",
                True, None)

        self.assertEqual(package_type, "deb")
        process_rpm.assert_not_called()

    def test_scan_iso_detects_rpm_package(self):
        entries = [
            iso_helper.IsoEntry("/Packages/demo.x86_64.rpm", "Packages/demo.x86_64.rpm", "rockridge"),
        ]
        reader = self.FakeIsoReader(entries)
        package = Package("demo", "1.0", "1", "x86_64", "rpm", "SHA1", "abcdef123456")

        with mock.patch.object(iso_helper, "PyCdlibIsoReader", return_value=reader), \
                mock.patch.object(iso_helper, "read_data_from_json", return_value=[]), \
                mock.patch.object(iso_helper, "save_data_to_json"), \
                mock.patch.object(iso_helper, "process_rpm_package",
                                  return_value=(package, [], [], {"id": package.id, "provides": ["demo"]})):
            result, package_type = iso_helper.scan_iso(
                "demo.iso", "demo-1.0-x86_64.iso", "2026-06-16T00:00:00Z",
                True, None)

        self.assertEqual(package_type, "rpm")
        self.assertEqual(result["packages_sbom"]["packages"][0]["package_type"], "rpm")

    def test_scan_iso_without_packages_raises_existing_error(self):
        reader = self.FakeIsoReader([
            iso_helper.IsoEntry("/README.TXT", "README.TXT", "rockridge"),
        ])

        with mock.patch.object(iso_helper, "PyCdlibIsoReader", return_value=reader):
            with self.assertRaisesRegex(ValueError, "未侦测到有效的包系统"):
                iso_helper.scan_iso(
                    "demo.iso", "demo-1.0-x86_64.iso", "2026-06-16T00:00:00Z",
                    True, None)

        self.assertTrue(reader.closed)

    def test_detect_iso_arch_prefers_debian_repo_paths(self):
        entries = [
            iso_helper.IsoEntry(
                "/dists/buster/main/binary-ppc64el/Packages.gz",
                "dists/buster/main/binary-ppc64el/Packages.gz",
                "rockridge"),
            iso_helper.IsoEntry(
                "/pool/main/demo_1.0_all.deb",
                "pool/main/demo_1.0_all.deb",
                "rockridge"),
        ]

        self.assertEqual(iso_helper.detect_iso_arch(entries, [], "demo.iso"), "ppc64el")

    def test_detect_iso_arch_normalizes_amd64_repo_path(self):
        self.assertEqual(
            iso_helper.detect_iso_arch(["dists/stable/main/binary-amd64/Packages.gz"], [], "demo.iso"),
            "x86_64")

    def test_detect_iso_arch_uses_package_metadata_before_filenames(self):
        entries = ["pool/main/demo_1.0_ppc64el.deb"]
        packages = [
            {"architecture": "all"},
            {"architecture": "amd64"},
            {"architecture": "amd64"},
        ]

        self.assertEqual(iso_helper.detect_iso_arch(entries, packages, "demo.iso"), "x86_64")

    def test_detect_iso_arch_keeps_efi_fallbacks(self):
        self.assertEqual(iso_helper.detect_iso_arch(["EFI/BOOT/BOOTX64.EFI"], [], "demo.iso"), "x86_64")
        self.assertEqual(iso_helper.detect_iso_arch(["EFI/BOOT/BOOTAA64.EFI"], [], "demo.iso"), "aarch64")
        self.assertEqual(
            iso_helper.detect_iso_arch(["EFI/BOOT/BOOTLOONGARCH64.EFI"], [], "demo.iso"),
            "loongarch64")


class SourcePackageStrategyTests(unittest.TestCase):
    def test_dsc_source_package_returns_package_object(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dsc_path = Path(tmpdir) / "demo_1.0.dsc"
            dsc_path.write_text(
                "Source: demo\nVersion: 1.0\nHomepage: https://example.test/demo\n",
                encoding="utf-8")

            package, licenses, originators = src_package_helper.process_src_package(
                str(dsc_path), [])

        self.assertEqual(package.name, "demo")
        self.assertEqual(package.version, "1.0")
        self.assertEqual(licenses, [])
        self.assertEqual(originators[0]["homepage"], "https://example.test/demo")

    def test_tar_with_debian_control_uses_debian_source_strategy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            control_path = Path(tmpdir) / "control"
            control_path.write_text(
                "Source: debdemo\nVersion: 2.0\nBuild-Depends: debhelper\n",
                encoding="utf-8")
            tar_path = Path(tmpdir) / "debdemo.tar.gz"
            with tarfile.open(tar_path, "w:gz") as tar:
                tar.add(control_path, arcname="debdemo/debian/control")

            package, licenses, originators = src_package_helper.process_src_package(
                str(tar_path), [])

        self.assertEqual(package.name, "debdemo")
        self.assertIn("debhelper", package.declared_dependencies)
        self.assertEqual(licenses, [])

    def test_zip_without_known_metadata_uses_zip_strategy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = Path(tmpdir) / "generic.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("README.txt", "hello")

            package, licenses, originators = src_package_helper.process_src_package(
                str(zip_path), [])

        self.assertEqual(package.name, "generic")
        self.assertEqual(package.description, "zip source package")
        self.assertEqual(licenses, [])

    def test_rpm_spec_source_package_parses_macros_and_dependencies(self):
        spec = """%global pkgname specdemo
Name: %{pkgname}
Version: 1.0
Release: 2
License: MIT
URL: https://example.test/specdemo
Requires: python3, libc >= 2.0
%description
Spec demo package
"""
        package, licenses, originators = src_package_helper._process_spec(
            spec, "abc123", [])

        self.assertEqual(package.name, "specdemo")
        self.assertEqual(package.version, "1.0")
        self.assertIn("python3", package.declared_dependencies)
        self.assertIn("libc >= 2.0", package.declared_dependencies)
        self.assertEqual(licenses[0]["name"], "MIT")
        self.assertEqual(originators[0]["homepage"], "https://example.test/specdemo")

    def test_detect_source_package_kind(self):
        self.assertEqual(src_package_helper._detect_source_package_kind("a.src.rpm"), "src_rpm")
        self.assertEqual(src_package_helper._detect_source_package_kind("a.tar.gz"), "tar")
        self.assertEqual(src_package_helper._detect_source_package_kind("a.zip"), "zip")
        self.assertEqual(src_package_helper._detect_source_package_kind("a.dsc"), "debian_source")


class RelationshipAndMetadataTests(unittest.TestCase):
    def test_deb_relationships_strip_versions_and_choices(self):
        packages = [
            {"id": "Package-app", "name": "app", "depends": ["libc (>= 2.0)", "python3:any | python"]},
            {"id": "Package-libc", "name": "libc", "depends": []},
            {"id": "Package-python3", "name": "python3", "depends": []},
        ]

        relationships = relationships_helper.get_deb_relationships(packages, disable_tqdm=True)

        self.assertIn({"id": "Package-app", "related_element": "Package-libc", "relationship_type": "DEPENDS_ON"}, relationships)
        self.assertIn({"id": "Package-app", "related_element": "Package-python3", "relationship_type": "DEPENDS_ON"}, relationships)

    def test_rpm_relationships_match_provides(self):
        packages = [
            {"id": "Package-app", "depends": ["libfoo"]},
            {"id": "Package-lib", "depends": []},
        ]
        provides = [{"id": "Package-lib", "provides": ["libfoo"]}]

        self.assertEqual(
            relationships_helper.get_rpm_relationships(packages, provides, disable_tqdm=True),
            [{"id": "Package-app", "related_element": "Package-lib", "relationship_type": "DEPENDS_ON"}])

    def test_package_json_and_file_relationships(self):
        package = Package("demo", "1.0", "1", "x86_64", "rpm", "SHA1", "abcdef123456")
        package.add_file({"id": "File-demo", "name": "demo", "path": "/usr/bin/demo"})
        package.add_declared_dep("libc")

        self.assertEqual(package.get_json()["version"], "1.0-1")
        self.assertEqual(package.get_json()["depends"], ["libc"])
        self.assertEqual(package.get_file_relationships()[0]["relationship_type"], "CONTAINS")

    def test_originators_and_suppliers(self):
        originators = [{"homepage": "https://example.test", "name": "Example", "is_organization": True}]
        name, is_org, updated = originators_helper.extract_originator_name(
            "https://example.test", originators)
        self.assertEqual((name, is_org, updated), ("Example", True, originators))

        suppliers = suppliers_helper.get_suppliers(
            "demo.el9", "https://upstream.test", "Upstream", suppliers_helper.RPM_SUPPLIERS)
        self.assertEqual(suppliers[0]["name"], "Red Hat Enterprise Linux")
        self.assertEqual(suppliers[-1]["name"], "Upstream")

    def test_data_helpers_and_license_extraction(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"hello")
            f.seek(0)
            self.assertEqual(calculate_md5(f), "5d41402abc4b2a76b9719d911017c592")
            f.seek(0)
            self.assertEqual(calculate_sha1(f), "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")

        self.assertEqual(remove_duplicates([{"id": "a"}, {"id": "a"}, {"id": "b"}]), [{"id": "a"}, {"id": "b"}])
        self.assertEqual(rpm_licenses_scanner("MIT")[0]["name"], "MIT")
        self.assertIn("GPL-2.0-only", _extract_deb_license_list("See /usr/share/common-licenses/GPL-2.0."))


class SPDXConversionTests(unittest.TestCase):
    def test_convert_to_spdx_includes_files_licenses_and_relationships(self):
        linx_sbom = {
            "packages_sbom": {"packages": [{
                "id": "Package-demo-abc",
                "name": "demo",
                "version": "1.0",
                "architecture": "x86_64",
                "licenses": ["LicenseRef-mit"],
                "suppliers": [{"name": "Example", "link": "https://example.test"}],
                "description": "demo",
                "checksum": {"algorithm": "SHA1", "value": "abc"},
            }]},
            "files_sbom": {"files": [{
                "id": "File-demo",
                "name": "demo.py",
                "checksums": {"algorithm": "MD5", "value": "def"},
            }]},
            "file_relationships_sbom": {"file_relationships": [{
                "id": "Package-demo-abc",
                "related_element": "File-demo",
                "relationship_type": "CONTAINS",
            }]},
            "package_relationships_sbom": {"package_relationships": [{
                "id": "Package-demo-abc",
                "related_element": "Package-lib-abc",
                "relationship_type": "DEPENDS_ON",
            }]},
            "licenses_sbom": {"licenses": [{"id": "LicenseRef-mit", "name": "MIT"}]},
        }

        spdx = spdx_sbom_helper.convert_to_spdx(
            linx_sbom, "demo", "2026-06-16T00:00:00Z", "rpm")

        self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
        self.assertEqual(spdx["packages"][0]["supplier"], "Organization: Example")
        self.assertEqual(spdx["files"][0]["SPDXID"], "SPDXRef-File-demo")
        self.assertEqual(len(spdx["relationships"]), 2)
        self.assertEqual(spdx["hasExtractedLicensingInfos"][0]["licenseId"], "LicenseRef-mit")

    def test_convert_to_spdx_handles_missing_optional_sections(self):
        linx_sbom = {
            "packages_sbom": {"packages": [{
                "id": "Package-demo-abc",
                "name": "demo",
                "version": "",
                "architecture": "",
                "licenses": [],
                "suppliers": [],
                "description": "",
                "checksum": {},
            }]},
            "licenses_sbom": {"licenses": []},
        }

        spdx = spdx_sbom_helper.convert_to_spdx(
            linx_sbom, "demo", "2026-06-16T00:00:00Z", "source")

        self.assertEqual(spdx["packages"][0]["versionInfo"], "NOASSERTION")
        self.assertEqual(spdx["packages"][0]["supplier"], "NOASSERTION")
        self.assertEqual(spdx["packages"][0]["checksums"][0]["algorithm"], "NOASSERTION")
        self.assertEqual(spdx["files"], [])


class ScanCodeHelperTests(unittest.TestCase):
    def test_should_include_applies_include_then_exclude(self):
        self.assertTrue(scancode_helper._should_include("src/main.c", ["*.c"], ["test/*"]))
        self.assertFalse(scancode_helper._should_include("src/main.py", ["*.c"], None))
        self.assertFalse(scancode_helper._should_include("test/main.c", ["*.c"], ["test/*"]))


if __name__ == "__main__":
    unittest.main()
