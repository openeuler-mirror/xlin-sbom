import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from actions import config_helper


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

    def test_parse_arguments_requires_explicit_format(self):
        with mock.patch("sys.argv", ["linx-xiling.py", "-p", "a.rpm", "-o", "out"]):
            with self.assertRaises(SystemExit):
                self.cli.parse_arguments()

    def test_resolve_output_formats_deduplicates_user_choices(self):
        self.assertEqual(
            self.cli.resolve_output_formats(["spdx", "gbt", "linx", "spdx"]),
            ["spdx", "gbt", "linx"])

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

    def test_save_sbom_can_write_gbt_directory(self):
        linx_sbom = {
            "packages_sbom": {"packages": []},
            "licenses_sbom": {"licenses": []},
            "package_relationships_sbom": {"package_relationships": []},
        }
        with tempfile.TemporaryDirectory() as tmpdir, \
                mock.patch.object(self.cli, "convert_to_gbt",
                                  return_value={"integrity": {}}), \
                mock.patch.object(self.cli, "sign_gbt_sbom") as sign:
            self.cli.save_sbom(
                linx_sbom, "rpm", "demo", "20260616000000",
                "2026-06-16T00:00:00Z", tmpdir, ["gbt"],
                "PyPI", {}, "package", None)

            output_dir = Path(tmpdir) / "demo" / "gbt-sbom_demo_20260616000000"
            self.assertTrue(
                (output_dir / "gbt-sbom_demo_20260616000000.SBOMDF.json").exists())
            sign.assert_called_once()

    def test_parse_arguments_has_no_deprecated_sbom_option(self):
        with mock.patch("sys.argv", ["linx-xiling.py", "-p", "a.rpm", "-o", "out", "-f", "spdx"]):
            args = self.cli.parse_arguments()
        self.assertEqual(args.format, ["spdx"])
        self.assertFalse(hasattr(args, "sbom"))

    def test_parse_arguments_keeps_format_as_runtime_cli_option(self):
        with mock.patch("sys.argv", [
                "linx-xiling.py", "-d", "debian:bookworm-slim",
                "-o", "out", "--format", "gbt", "--ecosystem", "Debian:12"]):
            args = self.cli.parse_arguments()
        self.assertEqual(args.docker, "debian:bookworm-slim")
        self.assertEqual(args.format, ["gbt"])
        self.assertEqual(args.ecosystem, "Debian:12")
        for removed_arg in (
                "config", "disable_tqdm", "max_workers", "platform",
                "include", "exclude", "brief"):
            self.assertFalse(hasattr(args, removed_arg))

    def test_parse_arguments_rejects_migrated_runtime_options(self):
        migrated_options = (
            ["--config", "config.json"],
            ["--disable-tqdm"],
            ["--max-workers", "2"],
            ["--platform", "linux/arm64"],
            ["--include", "*.py"],
            ["--exclude", "vendor/*"],
            ["--brief"],
        )
        for option in migrated_options:
            with self.subTest(option=option), \
                    mock.patch(
                        "sys.argv",
                        ["linx-xiling.py", "-p", "a.tar.gz", "-o", "out",
                         "--format", "spdx", *option]):
                with self.assertRaises(SystemExit):
                    self.cli.parse_arguments()

    def test_default_config_provides_source_include_patterns(self):
        config = self.cli.load_scan_config(config_path=None)
        options = self.cli.resolve_runtime_options(config)

        self.assertIn("*.py", options["include"])
        self.assertIn("*LICENSE*", options["include"])
        self.assertEqual(options["exclude"], [])
        self.assertFalse(options["brief"])
        self.assertEqual(
            config["elastic_search"]["index_name"],
            "osv_vulnerability_db")
        self.assertEqual(config["elastic_search"]["api_key"], "")

    def test_default_config_load_failure_raises_error(self):
        with mock.patch.object(
                config_helper, "read_data_from_json", side_effect=OSError("missing")):
            with self.assertRaisesRegex(RuntimeError, "默认配置文件加载失败"):
                self.cli.load_scan_config(config_path=None)

    def test_invalid_default_config_raises_error(self):
        invalid_default_config = {
            "scan": {
                "disable_tqdm": False,
                "max_workers": None,
                "platform": "",
            },
            "source_scan": {
                "include_file_patterns": ["*.py"],
                "exclude_file_patterns": [],
                "brief": False,
            },
            "elastic_search": {
                "hosts": ["http://host.docker.internal:9200"],
                "index_name": "osv_vulnerability_db",
                "api_key": "",
            },
        }
        with mock.patch.object(
                config_helper, "read_data_from_json",
                return_value=invalid_default_config):
            with self.assertRaisesRegex(RuntimeError, "scan.platform"):
                self.cli.load_scan_config(config_path=None)

    def test_missing_external_config_uses_default_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_config = str(Path(tmpdir) / "missing.json")
            config = self.cli.load_scan_config(config_path=missing_config)

        self.assertEqual(config["scan"]["platform"], "linux/amd64")
        self.assertIn("*.py", config["source_scan"]["include_file_patterns"])

    def test_external_config_overrides_default_fields(self):
        external_config = {
            "scan": {
                "disable_tqdm": True,
                "max_workers": 2,
                "platform": "linux/arm64",
            },
            "source_scan": {
                "include_file_patterns": ["*.go"],
                "exclude_file_patterns": ["vendor/*"],
                "brief": True,
            },
            "elastic_search": {
                "hosts": ["http://es.example.test:9200"],
                "index_name": "custom_osv",
                "api_key": "test-key",
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(json.dumps(external_config), encoding="utf-8")
            config = self.cli.load_scan_config(config_path=str(config_path))

        options = self.cli.resolve_runtime_options(config)

        self.assertEqual(options["include"], ["*.go"])
        self.assertEqual(options["exclude"], ["vendor/*"])
        self.assertTrue(options["brief"])
        self.assertTrue(options["disable_tqdm"])
        self.assertEqual(options["max_workers"], 2)
        self.assertEqual(options["platform"], "linux/arm64")
        self.assertEqual(config["elastic_search"]["hosts"], ["http://es.example.test:9200"])
        self.assertEqual(config["elastic_search"]["index_name"], "custom_osv")
        self.assertEqual(config["elastic_search"]["api_key"], "test-key")

    def test_invalid_external_config_fields_fallback_individually(self):
        external_config = {
            "scan": {
                "disable_tqdm": "true",
                "max_workers": 0,
                "platform": "",
                "unknown": "ignored",
            },
            "source_scan": {
                "include_file_patterns": "*.go",
                "exclude_file_patterns": [1],
                "brief": "false",
            },
            "elastic_search": {
                "hosts": "http://bad.example.test:9200",
                "index_name": 1,
                "api_key": [],
            },
            "unknown_root": {},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(json.dumps(external_config), encoding="utf-8")
            config = self.cli.load_scan_config(config_path=str(config_path))

        options = self.cli.resolve_runtime_options(config)

        self.assertFalse(options["disable_tqdm"])
        self.assertIsNone(options["max_workers"])
        self.assertEqual(options["platform"], "linux/amd64")
        self.assertIn("*.py", options["include"])
        self.assertEqual(options["exclude"], [])
        self.assertFalse(options["brief"])
        self.assertEqual(
            config["elastic_search"]["hosts"],
            ["http://host.docker.internal:9200"])
        self.assertEqual(config["elastic_search"]["index_name"], "osv_vulnerability_db")
        self.assertEqual(config["elastic_search"]["api_key"], "")
        self.assertNotIn("unknown", config["scan"])
        self.assertNotIn("unknown_root", config)

    def test_main_passes_config_to_package_scanner_and_keeps_format_cli(self):
        config = {
            "scan": {
                "disable_tqdm": True,
                "max_workers": 3,
                "platform": "linux/amd64",
            },
            "source_scan": {
                "include_file_patterns": ["*.rs"],
                "exclude_file_patterns": ["target/*"],
                "brief": True,
            },
        }
        with mock.patch("sys.argv", [
                "linx-xiling.py", "-p", "demo.tar.gz", "-o", "out",
                "--format", "spdx"]), \
                mock.patch.object(self.cli, "setup_logging"), \
                mock.patch.object(self.cli, "load_scan_config", return_value=config), \
                mock.patch.object(self.cli, "package_scanner", return_value={}) as scanner, \
                mock.patch.object(self.cli, "save_sbom") as save_sbom:
            self.cli.main()

        scanner.assert_called_once_with(
            "demo.tar.gz", "source", mock.ANY,
            ["*.rs"], ["target/*"], 3, True, True)
        self.assertEqual(save_sbom.call_args.args[6], ["spdx"])

    def test_validate_output_request_rejects_gbt_without_ecosystem(self):
        args = mock.Mock(repo=None, package="demo.rpm", ecosystem=None)

        with self.assertRaises(SystemExit):
            self.cli.validate_output_request(args, ["gbt"])

    def test_validate_output_request_allows_source_archive_gbt_without_ecosystem(self):
        args = mock.Mock(repo=None, package="demo.tar.gz", ecosystem=None)

        self.cli.validate_output_request(args, ["gbt"])

    def test_validate_output_request_rejects_non_archive_gbt_without_ecosystem(self):
        requests = (
            {"iso": "demo.iso", "docker": None, "package": None},
            {"iso": None, "docker": "debian:bookworm-slim", "package": None},
            {"iso": None, "docker": None, "package": "demo.deb"},
            {"iso": None, "docker": None, "package": "demo.src.rpm"},
            {"iso": None, "docker": None, "package": "demo.dsc"},
        )

        for request in requests:
            with self.subTest(request=request):
                args = mock.Mock(repo=None, ecosystem=None, **request)
                with self.assertRaises(SystemExit):
                    self.cli.validate_output_request(args, ["gbt"])

    def test_validate_output_request_rejects_repo_gbt(self):
        args = mock.Mock(
            repo="https://example.test/repo",
            package=None,
            ecosystem="PyPI")

        with self.assertRaises(SystemExit):
            self.cli.validate_output_request(args, ["gbt"])

    def test_main_passes_config_platform_to_docker_scanner(self):
        config = {
            "scan": {
                "disable_tqdm": True,
                "max_workers": None,
                "platform": "linux/arm64",
            },
            "source_scan": {
                "include_file_patterns": ["*.py"],
                "exclude_file_patterns": [],
                "brief": False,
            },
        }
        with mock.patch("sys.argv", [
                "linx-xiling.py", "-d", "debian:bookworm-slim", "-o", "out",
                "--format", "spdx"]), \
                mock.patch.object(self.cli, "setup_logging"), \
                mock.patch.object(self.cli, "load_scan_config", return_value=config), \
                mock.patch.object(
                    self.cli, "scan_docker_image",
                    return_value=({}, "docker", "debian")) as scanner, \
                mock.patch.object(self.cli, "save_sbom"):
            self.cli.main()

        scanner.assert_called_once_with(
            "debian:bookworm-slim", mock.ANY, "linux/arm64", True)


if __name__ == "__main__":
    unittest.main()
