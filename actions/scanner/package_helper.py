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
from actions.scanner.package_files_helper import (
    rpm_files_scanner,
    deb_files_scanner
)
from actions.licenses_helper import (
    rpm_licenses_scanner,
    deb_licenses_scanner
)
from actions.data_helper import (
    calculate_sha256,
    save_data_to_json,
    read_data_from_json
)
from actions.scanner.suppliers_helper import (
    get_suppliers,
    RPM_SUPPLIERS,
    DEB_SUPPLIERS
)
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

    if pkg_type == "deb":
        result = process_deb_package(pkg_path, originators, checksum_values)
        if result is None:
            logging.info(f"跳过已存在的DEB包: {pkg_path}")
            linx_sbom = {
                "packages_sbom": _add_header([], "packages", pkg_name, created_time),
                "files_sbom": _add_header([], "files", pkg_name, created_time),
                "file_relationships_sbom": _add_header([], "file_relationships", pkg_name, created_time),
                "licenses_sbom": _add_header([], "licenses", pkg_name, created_time),
            }
            save_data_to_json(originators, originators_file_path)
            return linx_sbom
        package, licenses, originators = result
    elif pkg_type == "rpm":
        result = process_rpm_package(pkg_path, originators, checksum_values)
        if result is None:
            logging.info(f"跳过已存在的RPM包: {pkg_path}")
            linx_sbom = {
                "packages_sbom": _add_header([], "packages", pkg_name, created_time),
                "files_sbom": _add_header([], "files", pkg_name, created_time),
                "file_relationships_sbom": _add_header([], "file_relationships", pkg_name, created_time),
                "licenses_sbom": _add_header([], "licenses", pkg_name, created_time),
            }
            save_data_to_json(originators, originators_file_path)
            return linx_sbom
        package, licenses, originators, _provides = result

    elif pkg_type == "source":
        package, licenses, originators = process_source_package(
            pkg_path, originators, include, exclude, workers, disable_tqdm, brief_mode)
    else:
        logging.error(f"不支持的软件包类型: {pkg_type}")
        raise ValueError(f"不支持的软件包类型: {pkg_type}")

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


def process_deb_package(pkg_path, originators, checksum_values):
    """
    处理 DEB 包，提取元数据并返回 Package 对象及关联信息。

    Args:
        pkg_path (str): DEB 包的文件路径。
        originators (list): 发起者信息列表。
        checksum_values (list): 已有校验值列表，用于增量更新跳过。

    Returns:
        tuple: (Package, licenses, originators) 三元组。
               若包已在 SBOM 中存在则返回 None。
    """
    with open(pkg_path, 'rb') as f:
        package_sha256 = calculate_sha256(f)
        if package_sha256 in checksum_values:
            return None

    try:
        control_info = _get_deb_info(pkg_path)
    except OSError as e:
        logging.error(f'跳过 {pkg_path} 由于读取错误: {e}')
        return None

    # 提取发起者名称、判断是否为组织及更新发起者列表
    originator_name, is_organization, originators = extract_originator_name(
        control_info.get("Homepage"), originators)

    # 创建Package对象
    name = control_info.get("Package")
    version = control_info.get("Version")
    architecture = control_info.get("Architecture")
    package = Package(name, version, None,
                        architecture, "deb", "SHA256", package_sha256)
    
    # 获取文件信息
    deb, files = deb_files_scanner(pkg_path)
    for file in files:
        package.add_file(file)

    # 获取许可证信息
    licenses = deb_licenses_scanner(deb, files)
    for license in licenses:
        package.add_license(license.get("id"))

    # 设置供应商信息
    suppliers = get_suppliers(control_info.get('Maintainer', ''), control_info.get(
        'Homepage', ''), originator_name, DEB_SUPPLIERS)
    for supplier in suppliers:
        package.add_supplier(supplier)

    # 设置描述信息
    package.set_description(control_info.get("Description"))

    # 获取依赖信息
    depends = _convert_to_list(control_info.get(
        "Depends")) + _convert_to_list(control_info.get("Pre-Depends"))
    for depend in depends:
        package.add_declared_dep(depend)

    return package, licenses, originators


def process_rpm_package(pkg_path, originators, checksum_values):
    """
    处理 RPM 包，提取元数据并返回 Package 对象及关联信息。

    Args:
        pkg_path (str): RPM 包的文件路径。
        originators (list): 发起者信息列表。
        checksum_values (list): 已有校验值列表，用于增量更新跳过。

    Returns:
        tuple: (Package, licenses, originators, provides) 四元组。
               若包已在 SBOM 中存在则返回 None。
    """

    with open(pkg_path, 'rb') as f:
        package_sha256 = calculate_sha256(f)
        if package_sha256 in checksum_values:
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
                              architecture, "rpm", "SHA256", package_sha256)

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
        requirename_values = rpm.headers.get('requirename')
        if isinstance(requirename_values, (str, bytes)):
            requirename_values = [requirename_values]
        for dep in requirename_values or []:
            package.add_declared_dep(_safe_decode(dep))

        # 获取文件信息
        files = rpm_files_scanner(pkg_path)
        for file in files:
            package.add_file(file)

        provides_values = rpm.headers.get('provides')
        if isinstance(provides_values, (str, bytes)):
            provides_values = [provides_values]
        provides = {
            "id": package.id,
            "provides": list(set(_safe_decode(file) for file in provides_values or [])),
        }

        return package, licenses, originators, provides

    except Exception as e:
        logging.error(f'跳过 {pkg_path} 由于读取错误: {e}')
        return None


def process_source_package(pkg_path, originators, include, exclude, workers, disable_tqdm, brief_mode):
    package, licenses, originators = process_src_package(
        pkg_path, originators)
    files = []
    file_relationships = []
    if not brief_mode:
        files, file_licenses = scan_src_rpm(
            pkg_path, include, exclude, workers, disable_tqdm)
        licenses.extend(file_licenses)
        for file in files:
            package.add_file(file)
    return package, licenses, originators


def _convert_to_list(dependencies_str):
    """
    将依赖项字符串转换为列表。

    Args:
        dependencies_str (str): 依赖项字符串，各依赖项之间用逗号分隔。

    Returns:
        list: 包含依赖项的列表。如果输入字符串为空，则返回空列表。
    """

    return [dependency.strip() for dependency in dependencies_str.split(",")] if dependencies_str else []


def _get_deb_info(deb_package):
    """
    获取 DEB 包的控制信息。

    Args:
        deb_package (str): DEB 包的路径。

    Returns:
        dict: 包含 DEB 包控制信息的字典。
    """

    import debian.debfile

    deb = debian.debfile.DebFile(deb_package)
    control_info = deb.control.debcontrol()
    return control_info


def _safe_decode(value):
    """
    安全地将字节串解码为 UTF-8 编码的字符串。

    Args:
        value (bytes or str): 需要解码的字节串或字符串。

    Returns:
        str: 解码后的字符串。如果输入值为 `None`，则返回空字符串。
    """

    if value is None:
        return ''
    if isinstance(value, str):
        return value
    return value.decode('utf-8', errors='replace')


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
