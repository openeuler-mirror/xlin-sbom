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

from helper import ASSIST_DIR
from helper.relationships_helper import get_rpm_relationships
from helper.json_helper import save_data_to_json, read_data_from_json
from helper.package_helper import process_rpm_package
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import logging


creators_file_path = os.path.join(ASSIST_DIR, 'creators.json')


def rpm_packages_scanner(mnt_dir, iso_filename, created_time, disable_tqdm, workers):
    """
    扫描并处理 RPM 包，生成软件物料清单（SBOM）。

    Args:
        mnt_dir (str): 挂载目录的路径。
        iso_filename (str): ISO 文件的名称。
        created_time (str): 创建时间的字符串。

    Returns:
        dict: 包含处理后的软件包信息的 SBOM 字典，包括软件包、文件、文件关系、许可证和组件依赖关系。
    """

    from tqdm import tqdm

    packages = []
    files = []
    file_relationships = []
    licenses = []
    provides_relationships = []

    # 定位必要的目录和文件
    originators_file_path = os.path.join(ASSIST_DIR, 'originators.json')
    originators = read_data_from_json(originators_file_path)
    rpm_dir = None
    for root, dirs, _ in os.walk(mnt_dir):
        if 'Packages' in dirs:
            rpm_dir = os.path.join(root, 'Packages')
            break

    if rpm_dir is not None:
        # 收集所有 RPM 文件的路径
        rpm_files = [os.path.join(root, f) for root, _, files in os.walk(rpm_dir)
                     for f in files if f.endswith('.rpm')]
    else:
        logging.error("未找到 Packages 目录。")

    os_arch = _get_os_arch(mnt_dir)

    # 并发处理RPM文件以提高效率
    if workers is None:
        logging.info("使用默认的线程数进行扫描")
    else:
        logging.info(f"使用 {workers} 个线程进行扫描")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(process_rpm_package, full_path, originators): full_path
            for full_path in rpm_files
        }

        # 根据 disable_tqdm 决定是否使用 tqdm
        progress_iter = (
            tqdm(total=len(futures), desc="扫描 RPM 包",
                 unit="包") if not disable_tqdm else None
        )

        for future in as_completed(futures):
            package_info, package_licenses, package_files, package_file_relationships, updated_originators, provides = future.result()
            if package_info:
                packages.append(package_info)
                files.extend(package_files)
                file_relationships.extend(package_file_relationships)
                licenses.extend(package_licenses)
                originators = updated_originators
                provides_relationships.append(provides)
            if not disable_tqdm:
                progress_iter.update(1)

        if not disable_tqdm:
            progress_iter.close()

    # files去重
    files = _remove_duplicates(files)

    # licenses去重
    licenses = _remove_duplicates(licenses)

    # 对结果按软件包名称排序
    packages.sort(key=lambda x: x.get("name", ""))

    # 处理组件依赖关系
    package_relationships = get_rpm_relationships(
        packages, provides_relationships, disable_tqdm)

    linx_sbom = {
        "packages_sbom": _add_header(packages, "packages", iso_filename, os_arch, created_time),
        "files_sbom": _add_header(files, "files", iso_filename, os_arch, created_time),
        "file_relationships_sbom": _add_header(file_relationships, "file_relationships", iso_filename, os_arch, created_time),
        "licenses_sbom": _add_header(licenses, "licenses", iso_filename, os_arch, created_time),
        "package_relationships_sbom": _add_header(package_relationships, "package_relationships", iso_filename, os_arch, created_time),
    }

    # 保存更新后的发起者信息
    save_data_to_json(originators, originators_file_path)

    # 返回处理后的软件包信息列表
    return linx_sbom


def _remove_duplicates(list):
    """
    从给定的列表中移除具有重复ID的项，并返回一个新列表，其中每个ID只出现一次。

    Args:
        list (list of dict): 包含字典元素的列表，每个字典必须有'id'键用于唯一标识。

    Returns:
        list of dict: 不含重复ID项的新列表。
    """

    unique_list = []
    seen_ids = set()
    for item in list:
        item_id = item.get("id")
        if item_id not in seen_ids:
            seen_ids.add(item_id)
            unique_list.append(item)
    return unique_list


def _add_header(sbom_data, data_name, iso_filename, iso_arch, created_time):
    """
    为 SBOM 数据添加头部信息。

    Args:
        sbom_data (list): SBOM 数据列表。
        data_name (str): 数据类型名称（如 "packages"、"files" 等）。
        iso_file_name (str): ISO 文件名称。
        iso_arch (str): 操作系统架构。
        created_time (str): 创建时间的字符串。

    Returns:
        dict: 包含头部信息的 SBOM 字典。
    """

    os_name = None
    os_version = None

    parts = iso_filename.split('-')

    if len(parts) < 5:
        logging.warning(f"不规范的ISO镜像文件名，需手动对{data_name}清单的ISO镜像数据进行补充。")
    else:
        os_name = parts[0]
        os_version = '-'.join(parts[1:-2])

    sbom = {
        "os_name": os_name or "NOASSERTION",
        "os_version": os_version or "NOASSERTION",
        "os_arch": iso_arch or "NOASSERTION",
        "creation_info": {
            "creators": read_data_from_json(creators_file_path),
            "created": created_time
        },
        data_name: sbom_data
    }
    return sbom


def _get_os_arch(mnt_dir):
    """
    获取操作系统的架构信息。

    Args:
        mnt_dir (str): 挂载目录的路径。

    Returns:
        str: 操作系统的架构信息。如果未找到对应的架构文件，则返回 `None`。
    """

    os_arch = None
    for root, _, f in os.walk(mnt_dir):
        if 'BOOTX64.EFI' in [fn.upper() for fn in f]:
            os_arch = 'x86_64'
            break
        elif 'BOOTAA64.EFI' in [fn.upper() for fn in f]:
            os_arch = 'aarch64'
            break
        elif 'BOOTLOONGARCH64.EFI' in [fn.upper() for fn in f]:
            os_arch = 'loongarch64'
            break
    if os_arch is None:
        logging.warning("未找到操作系统架构信息。")

    return os_arch
