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
from actions.sbom_helper import build_sbom_header
from actions.scanner.package_files_helper import (
    rpm_files_scanner,
    deb_files_scanner
)
from actions.licenses_helper import (
    rpm_licenses_scanner,
    deb_licenses_scanner
)
from actions.data_helper import (
    calculate_sha1,
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
import debian.debfile
import os


def package_scanner(pkg_path, pkg_type, created_time, include, exclude, workers, disable_tqdm, brief_mode):
    """
    扫描指定路径下的软件包，并根据软件包类型提取相关信息。

    Args:
        pkg_path (str): 软件包的文件路径。
        pkg_type (str): 软件包的类型。
        created_time (str): 创建时间，用于记录 SBOM 中的时间戳。
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
        package, licenses, originators = process_deb_package(
            pkg_path, originators)
    elif pkg_type == "rpm":
        package, licenses, originators, provides = process_rpm_package(
            pkg_path, originators)

    elif pkg_type == "source":
        package, licenses, originators = process_source_package(
            pkg_path, originators, include, exclude, workers, disable_tqdm, brief_mode)

    packages_sbom = [package.get_json()] if package else []
    package_files = package.files if package else []
    file_relationships_sbom = package.get_file_relationships() if package else []

    linx_sbom = {
        "packages_sbom": build_sbom_header(packages_sbom, "packages", pkg_name, created_time),
        "files_sbom": build_sbom_header(package_files, "files", pkg_name, created_time),
        "file_relationships_sbom": build_sbom_header(file_relationships_sbom, "file_relationships", pkg_name, created_time),
        "licenses_sbom": build_sbom_header(licenses, "licenses", pkg_name, created_time),
    }

    # 保存更新后的发起者信息
    save_data_to_json(originators, originators_file_path)

    # 返回处理后的软件包信息列表
    return linx_sbom


def process_deb_package(pkg_path, originators):
    with open(pkg_path, 'rb') as f:
        package_sha1 = calculate_sha1(f)

    try:
        with debian.debfile.DebFile(pkg_path) as deb:
            control_info = _get_deb_info(deb)
            package, licenses, originators = _build_deb_package(
                deb, control_info, package_sha1, originators)
    except OSError as e:
        logging.error(f'跳过 {pkg_path} 由于读取错误: {e}')
        return None, [], originators
    except Exception as e:
        logging.error(f'跳过 {pkg_path} 由于读取错误: {e}')
        return None, [], originators

    return package, licenses, originators


def _build_deb_package(deb, control_info, package_sha1, originators):
    """
    根据已读取的 DEB 控制信息构建包对象。

    Args:
        deb (debian.debfile.DebFile): 已打开的 DEB 包对象。
        control_info (dict): DEB control 字段信息。
        package_sha1 (str): DEB 文件的 SHA1 校验值。
        originators (list): 发起者辅助数据。

    Returns:
        tuple: 包含包对象、许可证列表和更新后的发起者列表。
    """
    # 提取发起者名称、判断是否为组织及更新发起者列表
    originator_name, is_organization, originators = extract_originator_name(
        control_info.get("Homepage"), originators)

    # 创建Package对象
    name = control_info.get("Package")
    version = control_info.get("Version")
    architecture = control_info.get("Architecture")
    package = Package(name, version, None,
                        architecture, "deb", "SHA1", package_sha1)
    
    # 获取文件信息
    files = deb_files_scanner(deb)
    for file_info in files:
        package.add_file(file_info)

    # 获取许可证信息
    licenses = deb_licenses_scanner(deb, files)
    for license_info in licenses:
        package.add_license(license_info.get("id"))

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


def process_rpm_package(pkg_path, originators):

    with open(pkg_path, 'rb') as f:
        package_sha1 = calculate_sha1(f)
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
            for license_info in licenses:
                package.add_license(license_info.get("id"))

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
            for file_info in files:
                package.add_file(file_info)

            provides = {
                "id": package.id,
                "provides": list(set(_safe_decode(provide) for provide in rpm.headers.get('provides'))),
            }

        return package, licenses, originators, provides

    except Exception as e:
        logging.error(f'跳过 {pkg_path} 由于读取错误: {e}')
        return None, [], originators, None


def process_source_package(pkg_path, originators, include, exclude, workers, disable_tqdm, brief_mode):
    package, licenses, originators = process_src_package(
        pkg_path, originators)
    files = []
    if not brief_mode and pkg_path.endswith('.src.rpm'):
        files, file_licenses = scan_src_rpm(
            pkg_path, include, exclude, workers, disable_tqdm)
        licenses.extend(file_licenses)
        for file_info in files:
            package.add_file(file_info)
    elif not brief_mode:
        logging.info("当前版本仅对 .src.rpm 执行源码文件级扫描，其他源码包格式已按独立策略生成包级SBOM")
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

    return deb_package.control.debcontrol()


def _safe_decode(value):
    """
    安全地将字节串解码为 UTF-8 编码的字符串。

    Args:
        value (bytes or str): 需要解码的字节串或字符串。

    Returns:
        str: 解码后的字符串。如果输入值为 `None`，则返回空字符串。
    """

    return value.decode('utf-8') if value is not None else ''
