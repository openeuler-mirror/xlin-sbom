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
from actions.package import Package
from actions.scanner.package_files_helper import rpm_files_scanner
from actions.licenses_helper import rpm_licenses_scanner
from actions.data_helper import calculate_sha1, save_data_to_json, read_data_from_json
from actions.scanner.suppliers_helper import get_suppliers, RPM_SUPPLIERS
from actions.scanner.originators_helper import extract_originator_name
from actions.scanner.src_package_helper import process_src_package
from actions.scanner.scancode_helper import scan_src_rpm
import logging
import rpmfile
import os


creators_file_path = os.path.join(ASSIST_DIR, 'creators.json')


def package_scanner(pkg_path, pkg_type, created_time, checksum_values, include, exclude, workers, disable_tqdm, brief_mode):
    """
    扫描指定路径下的软件包，并根据软件包类型提取相关信息。

    Args:
        pkg_path (str): 软件包的文件路径。
        pkg_type (str): 软件包的类型。
        created_time (str): 创建时间，用于记录 SBOM 中的时间戳。
        checksum_values (list): 校验值列表，用于增量更新。
        include (list): 包含的文件模式列表，用于源码扫描。
        exclude (list): 排除的文件模式列表，用于源码扫描。
        workers (int): 并行处理的工作线程数，用于源码扫描。
        disable_tqdm (bool): 是否禁用进度条显示，用于源码扫描。
        brief_mode (bool): 是否启用简要模式，若为 True 则跳过文件扫描，用于源码扫描。
    Returns:
        dict: 包含处理后的软件包信息列表，包括 `packages_sbom`, `files_sbom`, `file_relationships_sbom`, `licenses_sbom`。
    """

    originators_file_path = os.path.join(ASSIST_DIR, 'originators.json')
    originators = read_data_from_json(originators_file_path)
    pkg_name = os.path.basename(pkg_path)

    if pkg_type == "rpm":
        package, licenses, originators, provides = process_rpm_package(
            pkg_path, originators, checksum_values)

    elif pkg_type == "source":
        package, licenses, files, file_relationships, originators = process_source_package(
            pkg_path, originators, include, exclude, workers, disable_tqdm, brief_mode)

    packages_sbom = [package.get_json()]
    file_relationships_sbom = package.get_file_relationships()

    linx_sbom = {
        "packages_sbom": _add_header(packages_sbom, "packages", pkg_name, created_time),
        "files_sbom": _add_header(package.files, "files", pkg_name, created_time),
        "file_relationships_sbom": _add_header(file_relationships_sbom, "file_relationships", pkg_name, created_time),
        "licenses_sbom": _add_header(licenses, "licenses", pkg_name, created_time),
    }

    # 保存更新后的发起者信息
    save_data_to_json(originators, originators_file_path)

    # 返回处理后的软件包信息列表
    return linx_sbom


def process_rpm_package(pkg_path, originators, checksum_values):

    with open(pkg_path, 'rb') as f:
        package_sha1 = calculate_sha1(f)
        if package_sha1 in checksum_values:
            return None
    try:
        with rpmfile.open(pkg_path) as rpm:
            name = _safe_decode(rpm.headers.get('name'))
            version = _safe_decode(rpm.headers.get('version'))
            release = _safe_decode(rpm.headers.get('release'))
            homepage = _safe_decode(rpm.headers.get('url'))
            architecture = _safe_decode(rpm.headers.get('arch'))
            src_rpm = _safe_decode(rpm.headers.get('sourcerpm'))

            # 提取发起者名称、判断是否为组织及更新发起者列表
            originator_name, is_organization, originators = extract_originator_name(
                homepage, originators)

            suppliers = get_suppliers(
                release, homepage, originator_name, RPM_SUPPLIERS)

            # 创建Package对象
            package = Package(name, version, release,
                              architecture, "rpm", "SHA1", package_sha1)

            # 设置源码包名
            package.set_source(src_rpm)

            # 获取许可证信息
            licenses = rpm_licenses_scanner(
                _safe_decode(rpm.headers.get('copyright')))
            for license in licenses:
                package.add_license(license.get("id"))

            # 设置供应商信息
            for supplier in suppliers:
                package.add_supplier(supplier)

            # 设置描述信息
            package.set_description(_safe_decode(
                rpm.headers.get('description')))

            # 获取依赖信息
            for dep in rpm.headers.get('requirename'):
                package.add_declared_dep(_safe_decode(dep))

            # 获取文件信息
            files = rpm_files_scanner(pkg_path)
            for file in files:
                package.add_file(file)

            provides = {
                "id": package.id,
                "provides": list(set(_safe_decode(file) for file in rpm.headers.get('provides'))),
            }

        return package, licenses, originators, provides

    except Exception as e:
        logging.error(f'跳过 {pkg_path} 由于读取错误: {e}')
        return None


def process_source_package(pkg_path, originators, include, exclude, workers, disable_tqdm, brief_mode):
    """
    处理源码包，提取相关信息并生成相应的数据结构。

    Args:
        pkg_path (str): 源码包的完整路径。
        originators (dict): 发起者信息字典。
        include (list): 包含的文件模式列表。
        exclude (list): 排除的文件模式列表。
        workers (int): 并行处理的工作线程数。
        disable_tqdm (bool): 是否禁用进度条显示。
        brief_mode (bool): 是否启用简要模式，若为 True 则跳过文件扫描。

    Returns:
        tuple: 包含以下元素的元组：
            - package_info (dict): 软件包信息。
            - licenses (list): 许可证列表。
            - files (list): 文件列表。
            - file_relationships (list): 文件关系列表。
            - originators (dict): 更新后的发起者信息字典。
    """

    package_info, licenses, originators = process_src_package(
        pkg_path, originators)
    files = []
    file_relationships = []
    if not brief_mode:
        files, file_licenses = scan_src_rpm(
            pkg_path, include, exclude, workers, disable_tqdm)
        licenses.extend(file_licenses)
        file_relationships = get_file_relationships(
            files, package_info["id"])
    return package_info, licenses, files, file_relationships, originators


def _safe_decode(value):
    """
    安全地将字节串解码为 UTF-8 编码的字符串。

    Args:
        value (bytes or str): 需要解码的字节串或字符串。

    Returns:
        str: 解码后的字符串。如果输入值为 `None`，则返回空字符串。
    """

    return value.decode('utf-8') if value is not None else ''


def _add_header(sbom_data, data_name, pkg_name, created_time):
    """
    为 SBOM 数据添加头部信息。

    Args:
        sbom_data (list): SBOM 数据列表。
        data_name (str): 数据类型名称（如 "packages"、"files" 等）。
        created_time (str): 创建时间的字符串。

    Returns:
        dict: 包含头部信息的 SBOM 字典。
    """

    sbom = {
        "scan_target": pkg_name,
        "creation_info": {
            "creators": read_data_from_json(creators_file_path),
            "created": created_time
        },
        data_name: sbom_data
    }
    return sbom
