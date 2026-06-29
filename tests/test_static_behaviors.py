import importlib.util
import json
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from actions.scanner import iso_helper, package_helper, repo_helper, src_package_helper


ROOT_DIR = Path(__file__).resolve().parents[1]


def load_cli_module():
    spec = importlib.util.spec_from_file_location(
        "linx_xiling_cli", ROOT_DIR / "linx-xiling.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


class IsoScannerTests(unittest.TestCase):
    def test_rpm_iso_scan_without_packages_dir_returns_empty_lists(self):
        with tempfile.TemporaryDirectory() as tmpdir, \
                mock.patch.object(iso_helper, "read_data_from_json", return_value=[]), \
                mock.patch.object(iso_helper, "save_data_to_json"):
            result = iso_helper.rpm_packages_scanner(
                tmpdir, "demo-1.0-x86_64.iso", "2026-06-16T00:00:00Z",
                True, None)

        self.assertEqual(result["packages_sbom"]["packages"], [])
        self.assertEqual(result["files_sbom"]["files"], [])
        self.assertEqual(result["package_relationships_sbom"]["package_relationships"], [])


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


if __name__ == "__main__":
    unittest.main()
