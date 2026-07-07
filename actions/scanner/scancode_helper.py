# Copyright 2025 Linx Software, Inc.
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


import tempfile
import os
import shutil
import logging
import hashlib
import tarfile
import zipfile
import json
import subprocess
import libarchive
from tqdm import tqdm
from multiprocessing import Pool
from fnmatch import fnmatch
from typing import Any, Dict, List, Tuple, Optional
from scancode import api as scancode
from actions import OSV_SCANNER
from actions.data_helper import (
    calculate_md5,
    remove_duplicates
)
from actions.licenses_helper import rpm_licenses_scanner


def _safe_join(base_dir: str, member_name: str) -> Optional[str]:
    """安全拼接解压目标路径。

    Args:
        base_dir (str): 解压根目录。
        member_name (str): 归档成员路径。

    Returns:
        str | None: 位于根目录内的目标路径。若成员路径不安全则返回 None。
    """

    normalized_name = member_name.replace("\\", "/").lstrip("/")
    if not normalized_name or normalized_name.startswith("../") or "/../" in normalized_name:
        logging.warning(f"跳过不安全的归档成员路径: {member_name}")
        return None
    if os.path.isabs(normalized_name) or os.path.splitdrive(normalized_name)[0]:
        logging.warning(f"跳过不安全的归档成员路径: {member_name}")
        return None

    base_real = os.path.realpath(base_dir)
    target_path = os.path.realpath(os.path.join(base_real, normalized_name))
    if target_path != base_real and not target_path.startswith(base_real + os.sep):
        logging.warning(f"跳过越界的归档成员路径: {member_name}")
        return None
    return target_path


def _extract_src_rpm(src_rpm_path: str) -> str:
    """
    解压 .src.rpm 文件并提取其中的源代码压缩文件，返回解压后的源代码目录路径。

    Args:
        src_rpm_path (str): .src.rpm 文件的路径。

    Returns:
        str: 解压后的源代码目录路径。

    Raises:
        ValueError: 如果未在 .src.rpm 文件中找到源代码压缩文件。
    """

    # 创建一个临时目录用于解压 .src.rpm 文件
    temp_dir = tempfile.mkdtemp()

    try:
        # 解压 .src.rpm 文件
        with libarchive.file_reader(src_rpm_path) as archive:
            for entry in archive:
                pathname = _safe_join(temp_dir, entry.pathname)
                if pathname is None:
                    continue
                if entry.isdir:
                    os.makedirs(pathname, exist_ok=True)
                elif entry.isfile:
                    parent_dir = os.path.dirname(pathname)
                    os.makedirs(parent_dir, exist_ok=True)
                    with open(pathname, 'wb') as f:
                        for block in entry.get_blocks():
                            f.write(block)

        # 在解压后的文件中查找源代码压缩文件
        source_archive = None
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith(('.tar.xz', '.tar.gz', '.tgz', '.tar.bz2')):
                    source_archive = os.path.join(root, file)
                    break
            if source_archive:
                break

        if not source_archive:
            raise ValueError("未在 .src.rpm 文件中找到源代码压缩文件")

        # 创建一个临时目录用于解压源代码压缩文件
        source_dir = tempfile.mkdtemp()

        # 解压源代码压缩文件
        with libarchive.file_reader(source_archive) as archive:
            for entry in archive:
                pathname = _safe_join(source_dir, entry.pathname)
                if pathname is None:
                    continue
                if entry.isdir:
                    os.makedirs(pathname, exist_ok=True)
                elif entry.isfile:
                    parent_dir = os.path.dirname(pathname)
                    os.makedirs(parent_dir, exist_ok=True)
                    with open(pathname, 'wb') as f:
                        for block in entry.get_blocks():
                            f.write(block)

        # 返回解压后的源代码目录路径
        return source_dir

    finally:
        # 清理 .src.rpm 的临时目录
        shutil.rmtree(temp_dir)


def _should_include(member_name: str, include_patterns: Optional[List[str]], exclude_patterns: Optional[List[str]]) -> bool:
    """
    判断一个文件或目录名是否应该被包含在处理范围内。

    Args:
        member_name (str): 文件或目录的名称。
        include_patterns (list): 要包含的文件模式列表（可以为空）。 · 
        exclude_patterns (list): 要排除的文件模式列表（可以为空）。

    Returns:
        bool: 如果文件或目录名符合包含模式且不符合排除模式，则返回True；否则返回False。
    """

    if include_patterns:
        if not any(fnmatch(member_name, pattern) for pattern in include_patterns):
            return False
    if exclude_patterns:
        if any(fnmatch(member_name, pattern) for pattern in exclude_patterns):
            return False
    return True


def _should_skip_directory(member_name: str, exclude_patterns: Optional[List[str]]) -> bool:
    """判断目录是否应被排除。

    Args:
        member_name (str): 源码目录内的相对目录路径。
        exclude_patterns (list[str] | None): 排除模式列表。

    Returns:
        bool: 目录命中排除模式时返回 True。
    """

    return bool(exclude_patterns and any(fnmatch(member_name, pattern) for pattern in exclude_patterns))


def _relative_source_path(source_dir: str, member_path: str) -> str:
    """生成源码目录内的 POSIX 相对路径。

    Args:
        source_dir (str): 源码根目录。
        member_path (str): 文件实际路径。

    Returns:
        str: 使用 `/` 分隔的相对路径。
    """

    return os.path.relpath(member_path, source_dir).replace(os.sep, "/")


def _process_member(member: Tuple[str, str]) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    处理指定的文件成员，提取其许可证、版权信息以及其他元数据。

    Args:
        member (tuple[str, str]): 源码根目录和待处理文件路径。

    Returns:
        tuple: 包含两个元素：
            - file_info (dict): 提取的文件信息，包括以下字段：
                - id (str): 文件的唯一标识符，由文件名和MD5哈希值生成。
                - name (str): 文件名。
                - path (str): 文件的处理后路径。
                - licenses (list of str): 检测到的许可证ID列表。
                - holders (list of str): 版权持有者列表。
                - checksums (dict): 文件的校验信息，包含算法（algorithm）和值（value）。
            - license_id_list (list of str): 许可证扫描器返回的许可证ID列表。
    """

    source_dir, member_path = member
    try:
        licenses = scancode.get_licenses(location=member_path, include_text=True)
        copyright_data = scancode.get_copyrights(location=member_path)
    except Exception as e:
        logging.error(f"处理源码文件失败: {member_path} - {e}")
        return None, []

    detected_license_expression_spdx = licenses.get(
        'detected_license_expression_spdx')
    holders = list(set(item['holder']
                   for item in copyright_data.get('holders', [])))

    processed_file_path = _relative_source_path(source_dir, member_path)
    id_md5 = hashlib.md5(processed_file_path.encode()).hexdigest()[:12]
    name = os.path.basename(member_path)
    if detected_license_expression_spdx:
        licenses = rpm_licenses_scanner(detected_license_expression_spdx)
        license_id_list = [license.get("id") for license in licenses]
    else:
        licenses = []
        license_id_list = []

    with open(member_path, 'rb') as f:
        file_md5 = calculate_md5(f)

    file_info = {
        "id": f"File-{name}-{id_md5}",
        "name": name,
        "path": processed_file_path,
        "licenses": license_id_list,
        "holders": holders,
        "checksums": {
            "algorithm": "MD5",
            "value": file_md5
        }
    }

    return file_info, licenses


def scan_src_dir(
    source_dir: str,
    include: Optional[List[str]],
    exclude: Optional[List[str]],
    workers: Optional[int],
    disable_tqdm: bool
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """扫描源码目录中的文件并提取许可证信息。

    Args:
        source_dir (str): 已解压的源码目录。
        include (list[str] | None): 要包含的文件模式。
        exclude (list[str] | None): 要排除的文件模式。
        workers (int | None): 并行处理进程数。
        disable_tqdm (bool): 是否禁用进度条。

    Returns:
        tuple: 文件清单和去重后的许可证清单。
    """

    members = []
    file_list = []
    license_list = []

    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [
            directory for directory in dirs
            if not _should_skip_directory(
                _relative_source_path(source_dir, os.path.join(root, directory)),
                exclude)
        ]
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = _relative_source_path(source_dir, file_path)
            if _should_include(relative_path, include, exclude):
                members.append((source_dir, file_path))
    total_files = len(members)

    if workers is None:
        logging.info("使用默认的线程数进行扫描")
        workers = 4
    else:
        logging.info(f"使用 {workers} 个线程进行扫描")

    with Pool(processes=workers) as pool:
        for file_info, licenses in tqdm(pool.imap_unordered(_process_member, members), total=total_files, desc="扫描文件：", disable=disable_tqdm):
            if file_info:
                file_list.append(file_info)
            if licenses:
                license_list.extend(licenses)

    license_list = remove_duplicates(license_list)
    file_list.sort(key=lambda x: x.get("id", ""))
    return file_list, license_list


def extract_source_archive(archive_path: str) -> str:
    """安全解压普通源码归档。

    Args:
        archive_path (str): 源码归档路径。

    Returns:
        str: 解压后的临时源码目录。

    Raises:
        ValueError: 当前文件不是支持的源码归档。
    """

    source_dir = tempfile.mkdtemp()
    lower_path = archive_path.lower()
    try:
        if lower_path.endswith(('.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz', '.tar')):
            with tarfile.open(archive_path, 'r:*') as archive:
                for member in archive.getmembers():
                    if member.isdir():
                        target_dir = _safe_join(source_dir, member.name)
                        if target_dir:
                            os.makedirs(target_dir, exist_ok=True)
                        continue
                    if not member.isfile():
                        continue
                    target_path = _safe_join(source_dir, member.name)
                    if target_path is None:
                        continue
                    parent_dir = os.path.dirname(target_path)
                    os.makedirs(parent_dir, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        continue
                    with source, open(target_path, 'wb') as target:
                        shutil.copyfileobj(source, target)
            return source_dir

        if lower_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as archive:
                for member in archive.infolist():
                    if member.is_dir():
                        target_dir = _safe_join(source_dir, member.filename)
                        if target_dir:
                            os.makedirs(target_dir, exist_ok=True)
                        continue
                    target_path = _safe_join(source_dir, member.filename)
                    if target_path is None:
                        continue
                    parent_dir = os.path.dirname(target_path)
                    os.makedirs(parent_dir, exist_ok=True)
                    with archive.open(member) as source, open(target_path, 'wb') as target:
                        shutil.copyfileobj(source, target)
            return source_dir

        raise ValueError(f"不支持的源码归档格式: {archive_path}")
    except Exception:
        shutil.rmtree(source_dir, ignore_errors=True)
        raise


def run_osv_dependency_scan(source_dir: str) -> Dict[str, Any]:
    """调用 OSV Scanner 扫描源码目录依赖。

    Args:
        source_dir (str): 已解压的源码目录。

    Returns:
        dict: OSV Scanner 输出的 JSON 数据。扫描失败时返回空字典。
    """

    if not os.path.exists(OSV_SCANNER):
        logging.warning(f"未找到 OSV Scanner: {OSV_SCANNER}")
        return {}

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as output:
        output_path = output.name

    command = [
        OSV_SCANNER,
        "scan",
        "-r", source_dir,
        "--licenses",
        "--all-packages",
        "--format", "json",
        "--output", output_path
    ]
    try:
        subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )
        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            logging.warning("OSV Scanner 未生成依赖扫描结果")
            return {}
        with open(output_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logging.warning(f"OSV Scanner 依赖扫描失败: {e}")
        return {}
    finally:
        if os.path.exists(output_path):
            os.remove(output_path)


def scan_src_rpm(
    src_rpm_path: str,
    include: Optional[List[str]],
    exclude: Optional[List[str]],
    workers: Optional[int],
    disable_tqdm: bool
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    扫描 .src.rpm 文件中的源代码文件，提取每个文件的元数据和许可证信息。

    Args:
        src_rpm_path (str): .src.rpm 文件的路径。
        include (list of str): 要包含的文件模式列表（例如 ['*.c', '*.h']）。
        exclude (list of str): 要排除的文件模式列表（例如 ['test/*', '*.log']）。
        workers (int or None): 并行处理文件的进程数。如果为 None，则使用默认值 4。
        disable_tqdm (bool): 是否禁用进度条显示。

    Returns:
        tuple: 包含两个元素：
            - file_list (list of dict): 每个文件的信息，包括：
                - id (str): 文件的唯一标识符。
                - name (str): 文件名。
                - path (str): 文件路径。
                - licenses (list of str): 检测到的许可证 ID 列表。
                - holders (list of str): 版权持有者列表。
                - checksums (dict): 文件的校验值，包含算法和值。
            - license_list (list of dict): 所有检测到的许可证信息列表，去重后。
    """

    source_dir = _extract_src_rpm(src_rpm_path)
    try:
        return scan_src_dir(source_dir, include, exclude, workers, disable_tqdm)
    finally:
        shutil.rmtree(source_dir, ignore_errors=True)
