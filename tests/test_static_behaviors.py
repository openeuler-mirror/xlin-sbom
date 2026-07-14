import ast
import gc
import gzip
import hashlib
import json
import subprocess
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

from actions import config_helper
from actions.data_helper import calculate_md5, calculate_sha1, remove_duplicates
from actions.licenses_helper import _extract_deb_license_list, rpm_licenses_scanner
from actions.package import Package
from actions.scanner import (
    iso_helper,
    docker_image_helper,
    gbt_sbom_helper,
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


class ConfigHelperTests(unittest.TestCase):
    def test_elasticsearch_tls_config_overrides_defaults(self):
        default_config = json.loads(
            (ROOT_DIR / "assist" / "config.json").read_text(encoding="utf-8"))
        external_config = {
            "elastic_search": {
                "verify_certs": False,
                "ca_certs": "/app/config/es-http-ca.crt",
            },
        }

        config = config_helper.normalize_config(
            config_helper.merge_configs(default_config, external_config),
            default_config)

        self.assertFalse(config["elastic_search"]["verify_certs"])
        self.assertEqual(
            config["elastic_search"]["ca_certs"],
            "/app/config/es-http-ca.crt")

    def test_elasticsearch_tls_config_invalid_values_use_defaults(self):
        default_config = json.loads(
            (ROOT_DIR / "assist" / "config.json").read_text(encoding="utf-8"))
        external_config = {
            "elastic_search": {
                "verify_certs": "false",
                "ca_certs": 123,
            },
        }

        config = config_helper.normalize_config(
            config_helper.merge_configs(default_config, external_config),
            default_config)

        self.assertTrue(config["elastic_search"]["verify_certs"])
        self.assertEqual(config["elastic_search"]["ca_certs"], "")


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


def add_tar_member(target, name, content):
    data = content.encode("utf-8") if isinstance(content, str) else content
    info = tarfile.TarInfo(name)
    info.size = len(data)
    target.addfile(info, BytesIO(data))


def make_tar_layer(members):
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as layer:
        for name, content in members.items():
            add_tar_member(layer, name, content)
    return buffer.getvalue()


def make_minimal_oci_image(path, layers, config=None):
    config = config or {"os": "linux", "architecture": "amd64"}
    config_bytes = json.dumps(config).encode("utf-8")
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    layer_descriptors = []
    layer_blobs = []
    for layer_bytes in layers:
        layer_digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
        layer_descriptors.append({
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": layer_digest,
            "size": len(layer_bytes),
        })
        layer_blobs.append((layer_digest, layer_bytes))
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": len(config_bytes),
        },
        "layers": layer_descriptors,
    }
    manifest_bytes = json.dumps(manifest).encode("utf-8")
    manifest_digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    index = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": manifest_digest,
            "size": len(manifest_bytes),
            "platform": {"os": "linux", "architecture": "amd64"},
            "annotations": {"io.containerd.image.name": "docker.io/library/demo:latest"},
        }],
    }
    with tarfile.open(path, "w") as archive:
        add_tar_member(archive, "oci-layout", '{"imageLayoutVersion":"1.0.0"}')
        add_tar_member(archive, "index.json", json.dumps(index))
        add_tar_member(
            archive, docker_image_helper._blob_path_from_digest(manifest_digest), manifest_bytes)
        add_tar_member(
            archive, docker_image_helper._blob_path_from_digest(config_digest), config_bytes)
        for digest, layer_bytes in layer_blobs:
            add_tar_member(
                archive, docker_image_helper._blob_path_from_digest(digest), layer_bytes)


def make_dpkg_layer():
    status = """Package: libc6
Status: install ok installed
Version: 2.36
Architecture: amd64
Maintainer: Debian <debian@example.test>
Description: libc package

Package: demo
Status: install ok installed
Version: 1.0
Architecture: amd64
Maintainer: Demo Maintainer <demo@example.test>
Homepage: https://example.test/demo
Description: Demo package
Depends: libc6 (>= 2.36)
"""
    return make_tar_layer({
        "etc/os-release": 'NAME="Debian GNU/Linux"\nVERSION_ID="12"\n',
        "var/lib/dpkg/status": status,
        "var/lib/dpkg/info/demo.list": "/usr/bin/demo\n/usr/share/doc/demo/copyright\n",
        "var/lib/dpkg/info/demo.md5sums": (
            "d41d8cd98f00b204e9800998ecf8427e usr/bin/demo\n"
            "0cc175b9c0f1b6a831c399e269772661 usr/share/doc/demo/copyright\n"
        ),
        "var/lib/dpkg/info/libc6:amd64.list": "/lib/libc.so.6\n",
        "var/lib/dpkg/info/libc6:amd64.md5sums": (
            "900150983cd24fb0d6963f7d28e17f72 lib/libc.so.6\n"
        ),
        "usr/share/doc/demo/copyright": "See /usr/share/common-licenses/MIT.\n",
    })


class RegistryResponse:
    def __init__(self, status_code=200, payload=None, content=b"", headers=None):
        self.status_code = status_code
        self._payload = payload
        self.content = content
        self.headers = headers or {}

    def json(self):
        return self._payload if self._payload is not None else json.loads(self.content.decode("utf-8"))

    def iter_content(self, chunk_size=1):
        for index in range(0, len(self.content), chunk_size):
            yield self.content[index:index + chunk_size]



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

    def test_source_brief_mode_skips_fine_scan(self):
        with mock.patch.object(package_helper, "process_src_package") as process_src, \
                mock.patch.object(package_helper, "extract_source_archive") as extract_archive, \
                mock.patch.object(package_helper, "scan_src_dir") as scan_dir, \
                mock.patch.object(package_helper, "run_osv_dependency_scan") as osv_scan:
            package = Package("generic", "", "", "source", "source", "MD5", "abc")
            process_src.return_value = (package, [], [])
            result = package_helper.process_source_package(
                "generic.tar.gz", [], None, None, None, True, True)

        self.assertIs(result[0], package)
        self.assertEqual(result[3], [])
        self.assertEqual(result[4], [])
        extract_archive.assert_not_called()
        scan_dir.assert_not_called()
        osv_scan.assert_not_called()

    def test_source_tar_scan_adds_files_dependencies_and_relationships(self):
        package = Package("generic", "", "", "source", "source", "MD5", "abc")
        file_info = {
            "id": "File-main-py",
            "name": "main.py",
            "path": "src/main.py",
            "licenses": ["LicenseRef-mit"],
            "holders": ["Example"],
            "checksums": {"algorithm": "MD5", "value": "def"},
        }
        file_license = {"id": "LicenseRef-mit", "name": "MIT"}
        osv_data = {
            "results": [{
                "packages": [
                    {
                        "package": {
                            "name": "requests",
                            "version": "2.32.3",
                            "ecosystem": "PyPI",
                        },
                        "licenses": ["Apache-2.0"],
                    },
                    {
                        "package": {
                            "name": "requests",
                            "version": "2.32.3",
                            "ecosystem": "PyPI",
                        },
                        "licenses": ["Apache-2.0"],
                    },
                ]
            }]
        }
        with tempfile.TemporaryDirectory() as tmpdir, \
                mock.patch.object(package_helper, "process_src_package",
                                  return_value=(package, [], [])), \
                mock.patch.object(package_helper, "extract_source_archive",
                                  return_value=tmpdir), \
                mock.patch.object(package_helper, "scan_src_dir",
                                  return_value=([file_info], [file_license])), \
                mock.patch.object(package_helper, "run_osv_dependency_scan",
                                  return_value=osv_data):
            result = package_helper.process_source_package(
                "generic.tar.gz", [], None, None, None, True, False)

        scanned_package, licenses, _, dependencies, relationships = result
        self.assertEqual(scanned_package.files, [file_info])
        self.assertIn("LicenseRef-mit", scanned_package.licenses)
        self.assertIn("requests", scanned_package.declared_dependencies)
        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0].package_type, "pypi")
        self.assertIn("LicenseRef-f2f4f1c7718e", dependencies[0].licenses)
        self.assertEqual(licenses[0], file_license)
        self.assertEqual(
            relationships,
            [{
                "id": package.id,
                "related_element": dependencies[0].id,
                "relationship_type": "DEPENDS_ON",
            }])

    def test_package_scanner_includes_source_dependency_relationships(self):
        package = Package("generic", "", "", "source", "source", "MD5", "abc")
        dependency = Package(
            "requests", "2.32.3", "", "NOASSERTION", "pypi",
            "NOASSERTION", "NOASSERTION")
        relationship = {
            "id": package.id,
            "related_element": dependency.id,
            "relationship_type": "DEPENDS_ON",
        }
        with mock.patch.object(package_helper, "read_data_from_json", return_value=[]), \
                mock.patch.object(package_helper, "save_data_to_json"), \
                mock.patch.object(package_helper, "process_source_package",
                                  return_value=(package, [], [], [dependency], [relationship])):
            result = package_helper.package_scanner(
                "generic.tar.gz", "source", "2026-06-16T00:00:00Z",
                None, None, None, True, False)

        packages = result["packages_sbom"]["packages"]
        self.assertEqual([item["name"] for item in packages], ["generic", "requests"])
        self.assertEqual(
            result["package_relationships_sbom"]["package_relationships"],
            [relationship])

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


class DockerImageScannerTests(unittest.TestCase):
    def test_missing_tar_path_reports_chinese_error(self):
        with self.assertRaisesRegex(ValueError, "离线 Docker 镜像文件不存在"):
            docker_image_helper._is_local_image_archive("missing-image.tar")

    def test_build_docker_output_name_sanitizes_image_reference(self):
        self.assertEqual(
            docker_image_helper.build_docker_output_name("library/debian:bookworm-slim"),
            "library_debian_bookworm-slim")

    def test_scan_local_oci_image_reads_dpkg_database(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "demo-image.tar"
            make_minimal_oci_image(image_path, [make_dpkg_layer()])

            result, package_type, output_name = docker_image_helper.scan_docker_image(
                str(image_path), "2026-06-16T00:00:00Z", "linux/amd64", True)

        packages = result["packages_sbom"]["packages"]
        package_names = {package["name"] for package in packages}
        relationships = result["package_relationships_sbom"]["package_relationships"]
        self.assertEqual(package_type, "docker")
        self.assertEqual(output_name, "demo-image")
        self.assertEqual(result["packages_sbom"]["os_name"], "Debian GNU/Linux")
        self.assertIn("demo", package_names)
        self.assertTrue(result["files_sbom"]["files"])
        self.assertTrue(result["licenses_sbom"]["licenses"])
        self.assertIn("image_config_digest", result["packages_sbom"])
        self.assertTrue(any(rel["relationship_type"] == "DEPENDS_ON" for rel in relationships))

    def test_apply_layer_honors_whiteout(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = Path(tmpdir) / "rootfs"
            rootfs.mkdir()
            layer_one = Path(tmpdir) / "layer1.tar"
            layer_two = Path(tmpdir) / "layer2.tar"
            layer_one.write_bytes(make_tar_layer({"etc/demo.conf": "old"}))
            layer_two.write_bytes(make_tar_layer({"etc/.wh.demo.conf": ""}))

            docker_image_helper._apply_layer_file(str(layer_one), str(rootfs))
            docker_image_helper._apply_layer_file(str(layer_two), str(rootfs))

            self.assertFalse((rootfs / "etc/demo.conf").exists())

    def test_scan_dockerhub_image_uses_registry_api(self):
        layer_bytes = make_dpkg_layer()
        manifest_list = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{
                "digest": "sha256:manifest",
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "platform": {"os": "linux", "architecture": "amd64"},
            }],
        }
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:config"},
            "layers": [{"digest": "sha256:layer"}],
        }
        config = {"os": "linux", "architecture": "amd64"}

        def fake_get(url, **kwargs):
            if url == docker_image_helper.DOCKERHUB_AUTH_URL:
                return RegistryResponse(payload={"token": "token"})
            if url.endswith("/manifests/bookworm-slim"):
                return RegistryResponse(
                    payload=manifest_list,
                    headers={"Docker-Content-Digest": "sha256:index"})
            if url.endswith("/manifests/sha256:manifest"):
                return RegistryResponse(
                    payload=manifest,
                    headers={"Docker-Content-Digest": "sha256:manifest"})
            if url.endswith("/blobs/sha256:config"):
                return RegistryResponse(payload=config)
            if url.endswith("/blobs/sha256:layer"):
                return RegistryResponse(content=layer_bytes)
            return RegistryResponse(status_code=404, payload={})

        with mock.patch.object(docker_image_helper.requests, "get", side_effect=fake_get):
            result, package_type, output_name = docker_image_helper.scan_docker_image(
                "debian:bookworm-slim", "2026-06-16T00:00:00Z", "linux/amd64", True)

        self.assertEqual(package_type, "docker")
        self.assertEqual(output_name, "debian_bookworm-slim")
        self.assertEqual(result["packages_sbom"]["image_digest"], "sha256:manifest")
        self.assertEqual(result["packages_sbom"]["packages"][0]["package_type"], "deb")


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
                "path": "src/demo.py",
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
        self.assertEqual(spdx["files"][0]["fileName"], "src/demo.py")
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

    def test_convert_to_spdx_prefers_package_type_for_docker_scan(self):
        linx_sbom = {
            "packages_sbom": {"packages": [{
                "id": "Package-demo-abc",
                "name": "demo",
                "version": "1.0",
                "architecture": "amd64",
                "package_type": "deb",
                "licenses": [],
                "suppliers": [],
                "description": "demo",
                "checksum": {"algorithm": "SHA1", "value": "abc"},
            }]},
            "licenses_sbom": {"licenses": []},
        }

        spdx = spdx_sbom_helper.convert_to_spdx(
            linx_sbom, "demo", "2026-06-16T00:00:00Z", "docker")

        self.assertTrue(
            spdx["packages"][0]["externalRefs"][0]["referenceLocator"].startswith("pkg:deb/demo@1.0"))


class GBTConversionTests(unittest.TestCase):
    def test_query_es_vulnerabilities_resolves_certificate_verification(self):
        response = mock.Mock()
        response.json.return_value = {"responses": []}
        query = {
            "id": "Package-demo-abc",
            "ecosystem": "PyPI",
            "name": "demo",
            "version": "1.0",
        }
        cases = (
            ({}, True),
            ({"verify_certs": False}, False),
            ({
                "verify_certs": True,
                "ca_certs": "/app/config/es-http-ca.crt",
            }, "/app/config/es-http-ca.crt"),
        )

        for tls_config, expected_verify in cases:
            with self.subTest(tls_config=tls_config):
                es_config = {
                    "hosts": ["https://es.example.test:9200"],
                    "index_name": "osv_vulnerability_db",
                    **tls_config,
                }
                with mock.patch.object(
                        gbt_sbom_helper.requests,
                        "post",
                        return_value=response) as post:
                    gbt_sbom_helper._query_es_vulnerabilities(
                        [query], es_config)

                self.assertEqual(
                    post.call_args.kwargs["verify"], expected_verify)

    def test_parse_creators_and_build_create_tools(self):
        creators = gbt_sbom_helper.parse_creators([
            "Organization: Linx Software, Inc.",
            "Tool: XiLing SBOM Tool",
            "Version: v1.1.0",
        ])

        self.assertEqual(creators["Organization"], "Linx Software, Inc.")
        self.assertEqual(
            gbt_sbom_helper.build_create_tools(creators),
            "XiLing SBOM Toolv1.1.0")

    def test_convert_to_gbt_maps_package_software_and_components(self):
        linx_sbom = {
            "packages_sbom": {"packages": [
                {
                    "id": "Package-app-aaa",
                    "name": "app",
                    "version": "1.0",
                    "licenses": ["LicenseRef-mit"],
                    "suppliers": [{"name": "App Vendor"}],
                    "checksum": {"algorithm": "SHA1", "value": "aaa"},
                },
                {
                    "id": "Package-lib-bbb",
                    "name": "lib",
                    "version": "2.0",
                    "licenses": ["LicenseRef-apache"],
                    "suppliers": [{"name": "Lib Vendor"}],
                    "checksum": {"algorithm": "SHA1", "value": "bbb"},
                },
            ]},
            "licenses_sbom": {"licenses": [
                {"id": "LicenseRef-mit", "name": "MIT"},
                {"id": "LicenseRef-apache", "name": "Apache-2.0"},
            ]},
            "package_relationships_sbom": {"package_relationships": [{
                "id": "Package-app-aaa",
                "related_element": "Package-lib-bbb",
                "relationship_type": "DEPENDS_ON",
            }]},
        }
        with mock.patch.object(
                gbt_sbom_helper,
                "query_gbt_vulnerabilities",
                return_value=[]) as query_vulnerabilities:
            gbt = gbt_sbom_helper.convert_to_gbt(
                linx_sbom, "app", "2026-06-16T00:00:00Z",
                "source", "package", "PyPI", {}, None)

        self.assertEqual(gbt["software"]["softwareName"], "app")
        self.assertEqual(gbt["software"]["licenseName"], "MIT")
        self.assertEqual(gbt["components"][0]["componentName"], "lib")
        self.assertEqual(gbt["components"][0]["licenseName"], ["Apache-2.0"])
        self.assertEqual(gbt["dependencies"][0]["relationship"], "dependsOn")
        self.assertRegex(
            gbt["document"]["listID"],
            r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        self.assertEqual(
            gbt["integrity"],
            {
                "signatureFile": "signature.sig",
                "digitalCertificateFile": "certification.pem",
            })
        subjects = query_vulnerabilities.call_args.args[0]
        self.assertEqual(
            subjects,
            [
                {"id": "Package-app-aaa", "name": "app", "version": "1.0"},
                {"id": "Package-lib-bbb", "name": "lib", "version": "2.0"},
            ])

    def test_convert_to_gbt_uses_noassertion_for_missing_software_license(self):
        linx_sbom = {
            "packages_sbom": {"packages": [{
                "id": "Package-app-aaa",
                "name": "app",
                "version": "1.0",
                "licenses": [],
                "suppliers": [],
                "checksum": {"algorithm": "SHA1", "value": "aaa"},
            }]},
            "licenses_sbom": {"licenses": []},
            "package_relationships_sbom": {"package_relationships": []},
        }
        with mock.patch.object(
                gbt_sbom_helper, "query_gbt_vulnerabilities",
                return_value=[]):
            gbt = gbt_sbom_helper.convert_to_gbt(
                linx_sbom, "app", "2026-06-16T00:00:00Z",
                "rpm", "package", "Debian", {}, None)

        self.assertEqual(gbt["software"]["licenseName"], "NOASSERTION")
        self.assertEqual(gbt["licenses"], [])

    def test_convert_to_gbt_adds_target_contains_for_iso_and_docker(self):
        packages = [
            {
                "id": "Package-libc-aaa",
                "name": "libc",
                "version": "2.36",
                "licenses": [],
                "suppliers": [],
                "checksum": {"algorithm": "SHA1", "value": "aaa"},
            },
            {
                "id": "Package-app-bbb",
                "name": "app",
                "version": "1.0",
                "licenses": [],
                "suppliers": [],
                "checksum": {"algorithm": "SHA1", "value": "bbb"},
            },
        ]
        package_relationships = [{
            "id": "Package-app-bbb",
            "related_element": "Package-libc-aaa",
            "relationship_type": "DEPENDS_ON",
        }]

        for scan_mode in ("iso", "docker"):
            with self.subTest(scan_mode=scan_mode):
                packages_header = {
                    "scan_target": "target-image",
                    "os_name": "DemoOS",
                    "os_version": "1.0",
                    "packages": packages,
                }
                if scan_mode == "docker":
                    packages_header["image_name"] = "docker.io/library/demo:latest"
                linx_sbom = {
                    "packages_sbom": packages_header,
                    "licenses_sbom": {"licenses": []},
                    "package_relationships_sbom": {
                        "package_relationships": package_relationships,
                    },
                }
                with mock.patch.object(
                        gbt_sbom_helper, "query_gbt_vulnerabilities",
                        return_value=[]):
                    gbt = gbt_sbom_helper.convert_to_gbt(
                        linx_sbom, "target-image", "2026-06-16T00:00:00Z",
                        "deb", scan_mode, "Debian", {}, None)

                software_id = gbt["software"]["softwareId"]
                self.assertEqual(gbt["software"]["licenseName"], "NOASSERTION")
                self.assertEqual(
                    [
                        dependency for dependency in gbt["dependencies"]
                        if dependency["relationship"] == "contain"
                    ],
                    [
                        {
                            "identityAId": software_id,
                            "relationship": "contain",
                            "identityBId": "Package-libc-aaa",
                        },
                        {
                            "identityAId": software_id,
                            "relationship": "contain",
                            "identityBId": "Package-app-bbb",
                        },
                    ])
                self.assertIn(
                    {
                        "identityAId": "Package-app-bbb",
                        "relationship": "dependsOn",
                        "identityBId": "Package-libc-aaa",
                    },
                    gbt["dependencies"])

    def test_gbt_vulnerability_subjects_skip_noassertion(self):
        subjects = gbt_sbom_helper._build_vulnerability_subjects(
            None,
            [
                {"id": "Package-lib"},
                {"id": "Package-urllib3"},
            ],
            {
                "softwareName": "NOASSERTION",
                "softwareVersion": "1.0",
            },
            [
                {
                    "componentName": "lib",
                    "componentVersion": "NOASSERTION",
                },
                {
                    "componentName": "urllib3",
                    "componentVersion": "1.25.8",
                },
            ])

        self.assertEqual(
            subjects,
            [{"id": "Package-urllib3", "name": "urllib3", "version": "1.25.8"}])

    def test_gbt_vulnerability_queries_prefer_component_ecosystem(self):
        subjects = gbt_sbom_helper._build_vulnerability_subjects(
            None,
            [{"id": "Package-requests", "package_type": "pypi"}],
            {},
            [{"componentName": "requests", "componentVersion": "2.31.0"}])

        queries = gbt_sbom_helper._build_vulnerability_queries(subjects, "Go")

        self.assertEqual(queries[0]["ecosystem"], "PyPI")

    def test_gbt_vulnerability_queries_fallback_to_cli_ecosystem(self):
        subjects = gbt_sbom_helper._build_vulnerability_subjects(
            None,
            [{"id": "Package-demo", "package_type": "custom"}],
            {},
            [{"componentName": "demo", "componentVersion": "1.0"}])

        queries = gbt_sbom_helper._build_vulnerability_queries(subjects, "Go")

        self.assertEqual(queries[0]["ecosystem"], "Go")

    def test_gbt_vulnerability_queries_skip_without_ecosystem(self):
        subjects = gbt_sbom_helper._build_vulnerability_subjects(
            None,
            [{"id": "Package-demo", "package_type": "custom"}],
            {},
            [{"componentName": "demo", "componentVersion": "1.0"}])

        self.assertEqual(
            gbt_sbom_helper._build_vulnerability_queries(subjects, None),
            [])

    def test_gbt_licenses_split_and_deduplicate_and_expressions(self):
        licenses = gbt_sbom_helper._build_licenses(
            {
                "licenses_sbom": {"licenses": [
                    {"name": "Apache-2.0 AND MIT"},
                    {"name": "MIT"},
                ]},
            },
            {"licenseName": "Apache-2.0 AND MIT"},
            [{"licenseName": ["GPL-3.0 AND Apache-2.0"]}])
        license_names = [license_info["licenseName"] for license_info in licenses]

        self.assertEqual(license_names, ["Apache-2.0", "MIT", "GPL-3.0"])

    def test_gbt_license_enrichment_uses_rules_category_and_patent(self):
        apache = gbt_sbom_helper._build_license("Apache-2.0")

        self.assertEqual(apache["scope"], "Global")
        self.assertTrue(apache["patent"])
        self.assertIn("包含版权和许可", apache["content"])
        self.assertIn("宽松许可证", apache["riskDescription"])

    def test_gbt_license_risk_has_non_commercial_description(self):
        with mock.patch.object(gbt_sbom_helper, "read_data_from_json",
                               return_value=[{
                                   "spdx_license_key": "LicenseRef-test",
                                   "category": "Non-Commercial",
                               }]):
            description = gbt_sbom_helper._get_license_risk_description(
                "LicenseRef-test")

        self.assertIn("非商业许可证", description)
        self.assertIn("禁止", description)

    def test_gbt_vulnerability_matching_uses_versions_only(self):
        source = {
            "id": "GHSA-test",
            "aliases": ["CVE-2026-0001"],
            "affected": [{
                "package": {
                    "ecosystem": "PyPI",
                    "name": "demo",
                    "purl": "pkg:pypi/demo",
                },
                "versions": ["1.0"],
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.1"}]}],
            }],
        }

        matched = gbt_sbom_helper._match_vulnerability(
            {
                "id": "Package-demo-abc",
                "ecosystem": "PyPI",
                "name": "demo",
                "version": "1.0",
            },
            source)
        missed = gbt_sbom_helper._match_vulnerability(
            {
                "id": "Package-demo-abc",
                "ecosystem": "PyPI",
                "name": "demo",
                "version": "1.0.1",
            },
            source)

        self.assertEqual(matched[0]["vulnerabilityId"], "GHSA-test")
        self.assertEqual(matched[0]["affectedObject"], "Package-demo-abc")
        self.assertEqual(matched[0]["repairMethod"], "更新组件版本")
        self.assertEqual(missed, [])

    def test_gbt_vulnerability_fallbacks_without_fixed_or_purl(self):
        source = {
            "id": "GHSA-test",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "demo"},
                "versions": ["1.0"],
                "ranges": [],
            }],
        }

        matched = gbt_sbom_helper._match_vulnerability(
            {
                "id": "Package-demo-abc",
                "ecosystem": "PyPI",
                "name": "demo",
                "version": "1.0",
            },
            source)

        self.assertEqual(matched[0]["affectedObject"], "Package-demo-abc")
        self.assertEqual(matched[0]["otherID"], [])
        self.assertEqual(matched[0]["repairMethod"], "暂无")

    def test_sign_gbt_sbom_generates_verifiable_signature(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sbom_path = Path(tmpdir) / "demo.SBOMDF.json"
            signature_path = Path(tmpdir) / "signature.sig"
            certificate_path = Path(tmpdir) / "certification.pem"
            public_key_path = Path(tmpdir) / "public.pem"
            sbom_path.write_text('{"software":{"softwareName":"demo"}}',
                                 encoding="utf-8")

            gbt_sbom_helper.sign_gbt_sbom(
                str(sbom_path), str(signature_path), str(certificate_path))
            subprocess.run([
                "openssl", "x509", "-in", str(certificate_path),
                "-pubkey", "-noout", "-out", str(public_key_path),
            ], check=True)
            result = subprocess.run([
                "openssl", "dgst", "-sm3",
                "-verify", str(public_key_path),
                "-signature", str(signature_path),
                str(sbom_path),
            ], check=True, stdout=subprocess.PIPE)

        self.assertIn(b"Verified OK", result.stdout)


class ScanCodeHelperTests(unittest.TestCase):
    def test_should_include_applies_include_then_exclude(self):
        self.assertTrue(scancode_helper._should_include("src/main.c", ["*.c"], ["test/*"]))
        self.assertFalse(scancode_helper._should_include("src/main.py", ["*.c"], None))
        self.assertFalse(scancode_helper._should_include("test/main.c", ["*.c"], ["test/*"]))

    def test_include_pattern_does_not_prune_directories(self):
        self.assertFalse(scancode_helper._should_skip_directory("src", ["*.py"]))
        self.assertTrue(scancode_helper._should_skip_directory("test", ["test"]))

    def test_extract_source_archive_skips_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tar_path = Path(tmpdir) / "unsafe.tar"
            with tarfile.open(tar_path, "w") as tar:
                add_tar_member(tar, "safe/main.py", "print('ok')\n")
                add_tar_member(tar, "../evil.py", "bad\n")

            source_dir = scancode_helper.extract_source_archive(str(tar_path))
            try:
                self.assertTrue((Path(source_dir) / "safe" / "main.py").exists())
                self.assertFalse((Path(source_dir).parent / "evil.py").exists())
            finally:
                for path in Path(source_dir).rglob("*"):
                    if path.is_file():
                        path.unlink()
                for path in sorted(Path(source_dir).rglob("*"), reverse=True):
                    if path.is_dir():
                        path.rmdir()
                Path(source_dir).rmdir()

    def test_run_osv_dependency_scan_missing_binary_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir, \
                mock.patch.object(scancode_helper, "OSV_SCANNER", str(Path(tmpdir) / "missing")):
            self.assertEqual(scancode_helper.run_osv_dependency_scan(tmpdir), {})

    def test_run_osv_dependency_scan_accepts_nonzero_exit_with_json(self):
        def fake_run(command, stdout=None, stderr=None, check=False):
            output_path = command[-1]
            Path(output_path).write_text(
                json.dumps({"results": [{"packages": []}]}),
                encoding="utf-8")
            return mock.Mock(returncode=1)

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner_path = Path(tmpdir) / "osv-scanner"
            scanner_path.write_text("#!/bin/sh\n", encoding="utf-8")
            with mock.patch.object(scancode_helper, "OSV_SCANNER", str(scanner_path)), \
                    mock.patch.object(scancode_helper.subprocess, "run", side_effect=fake_run), \
                    mock.patch.object(scancode_helper.logging, "warning") as warning:
                result = scancode_helper.run_osv_dependency_scan(tmpdir)

        self.assertEqual(result, {"results": [{"packages": []}]})
        warning.assert_not_called()


if __name__ == "__main__":
    unittest.main()
