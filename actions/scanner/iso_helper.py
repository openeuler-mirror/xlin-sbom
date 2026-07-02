# Copyright 2024 Linx Software, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from actions import ASSIST_DIR
from actions.sbom_helper import build_sbom_header
from actions.scanner.relationships_helper import (
    get_rpm_relationships,
    get_deb_relationships
)
from actions.data_helper import (
    save_data_to_json,
    read_data_from_json,
    remove_duplicates
)
from actions.scanner.package_helper import (
    process_rpm_package,
    process_deb_package
)
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from collections import Counter
import logging
import os
import re
import tempfile
import threading
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
import pycdlib
from tqdm import tqdm

ISO_PATH_TYPES = ("udf", "rockridge", "joliet", "iso9660")
ISO_PATH_TYPE_CONFIG = {
    "udf": ("has_udf", "udf_path"),
    "rockridge": ("has_rock_ridge", "rr_path"),
    "joliet": ("has_joliet", "joliet_path"),
    "iso9660": (None, "iso_path"),
}
NEUTRAL_ARCHES = {"all", "noarch", "src", "source", "nosrc"}
ARCH_ALIASES = {
    "amd64": "x86_64",
    "x64": "x86_64",
    "x86-64": "x86_64",
    "x86_64": "x86_64",
    "i386": "x86",
    "i486": "x86",
    "i586": "x86",
    "i686": "x86",
    "arm64": "aarch64",
    "aarch64": "aarch64",
    "loongarch64": "loongarch64",
    "ppc64el": "ppc64el",
    "ppc64le": "ppc64el",
    "ppc64": "ppc64",
    "s390x": "s390x",
    "riscv64": "riscv64",
    "mips64el": "mips64el",
    "mips64le": "mips64el",
    "noarch": "noarch",
    "all": "all",
}


@dataclass(frozen=True)
class IsoEntry:
    archive_path: str
    display_path: str
    path_type: str


class PyCdlibIsoReader:
    def __init__(self, iso_path: str):
        self._iso = pycdlib.PyCdlib()
        self._iso.open(iso_path)
        self.path_type = _select_iso_path_type(self._iso)

    def close(self) -> None:
        self._iso.close()

    def list_entries(self) -> List[IsoEntry]:
        entries = []
        for directory_path, _, file_names in self._iso.walk(**{_path_keyword(self.path_type): "/"}):
            for file_name in file_names:
                archive_path = _join_iso_path(directory_path, file_name)
                entries.append(IsoEntry(
                    archive_path=archive_path,
                    display_path=_normalize_display_path(archive_path),
                    path_type=self.path_type,
                ))
        return entries

    def extract_file(self, entry: IsoEntry, target_path: str) -> None:
        self._iso.get_file_from_iso(target_path, **{_path_keyword(entry.path_type): entry.archive_path})


def scan_iso(
    iso_path: str,
    iso_filename: str,
    created_time: str,
    disable_tqdm: bool,
    workers: Optional[int],
) -> Tuple[Dict[str, Any], str]:
    reader = PyCdlibIsoReader(iso_path)
    try:
        entries = reader.list_entries()
        deb_entries = _find_package_entries(entries, ".deb")
        rpm_entries = _find_package_entries(entries, ".rpm")

        if deb_entries:
            logging.info("侦测到DEB包系统")
            return _scan_deb_entries(
                reader, deb_entries, entries, iso_filename, created_time,
                disable_tqdm, workers), "deb"
        if rpm_entries:
            logging.info("侦测到RPM包系统")
            return _scan_rpm_entries(
                reader, rpm_entries, entries, iso_filename, created_time,
                disable_tqdm, workers), "rpm"

        raise ValueError("未侦测到有效的包系统")
    finally:
        reader.close()


def _scan_deb_entries(
    reader: Any,
    package_entries: List[IsoEntry],
    all_entries: List[IsoEntry],
    iso_filename: str,
    created_time: str,
    disable_tqdm: bool,
    workers: Optional[int],
) -> Dict[str, Any]:
    packages = []
    files = []
    file_relationships = []
    licenses = []

    originators_file_path = os.path.join(ASSIST_DIR, 'originators.json')
    originators = read_data_from_json(originators_file_path)

    if workers is None:
        logging.info("使用默认的线程数进行扫描")
    else:
        logging.info(f"使用 {workers} 个线程进行扫描")

    reader_lock = threading.Lock()
    with tempfile.TemporaryDirectory(prefix="linx_iso_") as temp_dir:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    _process_iso_package_entry,
                    reader, entry, temp_dir, originators, reader_lock,
                    process_deb_package
                ): entry
                for entry in package_entries
            }

            progress_iter = (
                tqdm(total=len(futures), desc="扫描 DEB 包",
                     unit="包") if not disable_tqdm else None
            )

            for future in as_completed(futures):
                result = future.result()
                if result:
                    package, package_licenses, updated_originators = result
                    if package:
                        packages.append(package)
                        files.extend(package.files)
                        file_relationships.extend(package.get_file_relationships())
                        licenses.extend(package_licenses)
                        originators = updated_originators
                if not disable_tqdm:
                    progress_iter.update(1)

            if not disable_tqdm:
                progress_iter.close()

    files = remove_duplicates(files)
    licenses = remove_duplicates(licenses)

    packages_sbom = [package.get_json() for package in packages]
    packages_sbom.sort(key=lambda x: x.get("name", ""))
    os_arch = detect_iso_arch(all_entries, packages_sbom, iso_filename)

    package_relationships = get_deb_relationships(packages_sbom, disable_tqdm)

    linx_sbom = _build_iso_sbom(
        packages_sbom, files, file_relationships, licenses,
        package_relationships, iso_filename, os_arch, created_time)

    save_data_to_json(originators, originators_file_path)
    return linx_sbom


def _scan_rpm_entries(
    reader: Any,
    package_entries: List[IsoEntry],
    all_entries: List[IsoEntry],
    iso_filename: str,
    created_time: str,
    disable_tqdm: bool,
    workers: Optional[int],
) -> Dict[str, Any]:
    packages = []
    files = []
    file_relationships = []
    licenses = []
    provides_relationships = []

    originators_file_path = os.path.join(ASSIST_DIR, 'originators.json')
    originators = read_data_from_json(originators_file_path)

    if workers is None:
        logging.info("使用默认的线程数进行扫描")
    else:
        logging.info(f"使用 {workers} 个线程进行扫描")

    reader_lock = threading.Lock()
    with tempfile.TemporaryDirectory(prefix="linx_iso_") as temp_dir:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    _process_iso_package_entry,
                    reader, entry, temp_dir, originators, reader_lock,
                    process_rpm_package
                ): entry
                for entry in package_entries
            }

            progress_iter = (
                tqdm(total=len(futures), desc="扫描 RPM 包",
                     unit="包") if not disable_tqdm else None
            )

            for future in as_completed(futures):
                result = future.result()
                if result:
                    package, package_licenses, updated_originators, provides = result
                    if package:
                        packages.append(package)
                        files.extend(package.files)
                        file_relationships.extend(package.get_file_relationships())
                        licenses.extend(package_licenses)
                        originators = updated_originators
                        if provides:
                            provides_relationships.append(provides)
                if not disable_tqdm:
                    progress_iter.update(1)

            if not disable_tqdm:
                progress_iter.close()

    files = remove_duplicates(files)
    licenses = remove_duplicates(licenses)

    packages_sbom = [package.get_json() for package in packages]
    packages_sbom.sort(key=lambda x: x.get("name", ""))
    os_arch = detect_iso_arch(all_entries, packages_sbom, iso_filename)

    package_relationships = get_rpm_relationships(
        packages_sbom, provides_relationships, disable_tqdm)

    linx_sbom = _build_iso_sbom(
        packages_sbom, files, file_relationships, licenses,
        package_relationships, iso_filename, os_arch, created_time)

    save_data_to_json(originators, originators_file_path)
    return linx_sbom


def _process_iso_package_entry(
    reader: Any,
    entry: IsoEntry,
    temp_dir: str,
    originators: List[Dict[str, Any]],
    reader_lock: threading.Lock,
    package_processor: Callable[..., Tuple[Any, ...]],
) -> Optional[Tuple[Any, ...]]:
    suffix = _entry_suffix(entry)
    fd, package_path = tempfile.mkstemp(suffix=suffix, dir=temp_dir)
    os.close(fd)
    try:
        with reader_lock:
            reader.extract_file(entry, package_path)
        return package_processor(package_path, originators)
    except Exception as exc:
        logging.error(f"跳过 ISO 内软件包 {entry.display_path} 由于读取错误: {exc}")
        return None
    finally:
        try:
            os.remove(package_path)
        except FileNotFoundError:
            pass


def _select_iso_path_type(iso: Any) -> str:
    for path_type in ISO_PATH_TYPES:
        has_method_name, _ = ISO_PATH_TYPE_CONFIG[path_type]
        if has_method_name is None:
            return path_type
        has_method = getattr(iso, has_method_name, None)
        if callable(has_method):
            try:
                if has_method():
                    return path_type
            except Exception:
                continue
    return "iso9660"


def _path_keyword(path_type: str) -> str:
    return ISO_PATH_TYPE_CONFIG[path_type][1]


def _find_package_entries(entries: Iterable[IsoEntry], suffix: str) -> List[IsoEntry]:
    return [
        entry for entry in entries
        if _strip_iso_version(entry.display_path).lower().endswith(suffix)
    ]


def detect_iso_arch(
    entries: Iterable[Any],
    packages_sbom: Optional[List[Dict[str, Any]]] = None,
    iso_filename: str = "",
) -> Optional[str]:
    paths = [_entry_display_path(entry) for entry in entries]

    repo_arch = _detect_arch_from_debian_repo_paths(paths)
    if repo_arch:
        return repo_arch

    package_arch = _detect_arch_from_packages(packages_sbom or [])
    if package_arch:
        return package_arch

    filename_arch = _detect_arch_from_package_filenames(paths)
    if filename_arch:
        return filename_arch

    boot_arch = _detect_arch_from_boot_paths(paths)
    if boot_arch:
        return boot_arch

    iso_name_arch = _detect_arch_from_iso_filename(iso_filename)
    if iso_name_arch:
        return iso_name_arch

    logging.warning("未找到操作系统架构信息。")
    return None


def _detect_arch_from_debian_repo_paths(paths: List[str]) -> Optional[str]:
    counter = Counter()
    for path in paths:
        match = re.search(r"(?:^|/)binary-([A-Za-z0-9_+-]+)(?:/|$)", path)
        if match:
            counter[_normalize_arch(match.group(1))] += 1
    return _most_common_machine_arch(counter)


def _detect_arch_from_packages(packages_sbom: List[Dict[str, Any]]) -> Optional[str]:
    counter = Counter()
    for package in packages_sbom:
        arch = _normalize_arch(package.get("architecture"))
        if arch:
            counter[arch] += 1
    return _most_common_machine_arch(counter)


def _detect_arch_from_package_filenames(paths: List[str]) -> Optional[str]:
    counter = Counter()
    for path in paths:
        clean_path = _strip_iso_version(path)
        deb_match = re.search(r"_([A-Za-z0-9][A-Za-z0-9_+-]*)\.deb$", clean_path, re.IGNORECASE)
        if deb_match:
            counter[_normalize_arch(deb_match.group(1))] += 1
            continue

        rpm_match = re.search(r"\.([A-Za-z0-9_]+)\.rpm$", clean_path, re.IGNORECASE)
        if rpm_match:
            counter[_normalize_arch(rpm_match.group(1))] += 1
    return _most_common_machine_arch(counter)


def _detect_arch_from_boot_paths(paths: List[str]) -> Optional[str]:
    upper_paths = [path.upper() for path in paths]
    for path in upper_paths:
        basename = path.rsplit("/", 1)[-1]
        if basename == "BOOTX64.EFI":
            return "x86_64"
        if basename == "BOOTAA64.EFI":
            return "aarch64"
        if basename == "BOOTLOONGARCH64.EFI":
            return "loongarch64"
    for path in paths:
        lower_path = path.lower()
        if "boot/grub/powerpc" in lower_path:
            return "ppc64el"
    return None


def _detect_arch_from_iso_filename(iso_filename: str) -> Optional[str]:
    name = os.path.splitext(os.path.basename(iso_filename))[0].lower()
    for token in re.split(r"[-_.+]", name):
        arch = _normalize_arch(token)
        if arch:
            return arch
    return None


def _most_common_machine_arch(counter: Counter) -> Optional[str]:
    for arch, _ in counter.most_common():
        if arch and arch not in NEUTRAL_ARCHES:
            return arch
    return counter.most_common(1)[0][0] if counter else None


def _normalize_arch(arch: Optional[str]) -> Optional[str]:
    if not arch:
        return None
    normalized = str(arch).strip().lower()
    return ARCH_ALIASES.get(normalized, normalized)


def _entry_display_path(entry: Any) -> str:
    if isinstance(entry, IsoEntry):
        return entry.display_path
    return str(entry).replace("\\", "/").lstrip("/")


def _entry_suffix(entry: IsoEntry) -> str:
    clean_path = _strip_iso_version(entry.display_path)
    _, suffix = os.path.splitext(clean_path)
    return suffix or ".pkg"


def _join_iso_path(directory_path: str, file_name: str) -> str:
    directory_path = str(directory_path).replace("\\", "/")
    file_name = str(file_name).replace("\\", "/")
    if directory_path in ("", "/"):
        return f"/{file_name.lstrip('/')}"
    return f"{directory_path.rstrip('/')}/{file_name.lstrip('/')}"


def _normalize_display_path(path: str) -> str:
    return _strip_iso_version(path.replace("\\", "/").lstrip("/"))


def _strip_iso_version(path: str) -> str:
    return re.sub(r";\d+$", "", path)


def _build_iso_sbom(
    packages_sbom: List[Dict[str, Any]],
    files_sbom: List[Dict[str, Any]],
    file_relationships_sbom: List[Dict[str, Any]],
    licenses_sbom: List[Dict[str, Any]],
    package_relationships_sbom: List[Dict[str, Any]],
    iso_filename: str,
    iso_arch: Optional[str],
    created_time: str
) -> Dict[str, Any]:
    """构建 ISO 扫描的 Linx SBOM 输出结构。

    Args:
        packages_sbom (list): 包清单数据。
        files_sbom (list): 文件清单数据。
        file_relationships_sbom (list): 文件关系清单数据。
        licenses_sbom (list): 许可证清单数据。
        package_relationships_sbom (list): 包关系清单数据。
        iso_filename (str): ISO 文件名称。
        iso_arch (str): 操作系统架构。
        created_time (str): 创建时间的字符串。

    Returns:
        dict: Linx SBOM 输出结构。
    """

    os_name = None
    os_version = None

    parts = iso_filename.split('-')

    if len(parts) < 5:
        logging.warning("不规范的ISO镜像文件名，需手动对ISO镜像数据进行补充。")
    else:
        os_name = parts[0]
        os_version = '-'.join(parts[1:-2])

    return {
        "packages_sbom": build_sbom_header(
            packages_sbom, "packages", iso_filename, created_time,
            os_name, os_version, iso_arch),
        "files_sbom": build_sbom_header(
            files_sbom, "files", iso_filename, created_time,
            os_name, os_version, iso_arch),
        "file_relationships_sbom": build_sbom_header(
            file_relationships_sbom, "file_relationships", iso_filename,
            created_time, os_name, os_version, iso_arch),
        "licenses_sbom": build_sbom_header(
            licenses_sbom, "licenses", iso_filename, created_time,
            os_name, os_version, iso_arch),
        "package_relationships_sbom": build_sbom_header(
            package_relationships_sbom, "package_relationships", iso_filename,
            created_time, os_name, os_version, iso_arch),
    }
