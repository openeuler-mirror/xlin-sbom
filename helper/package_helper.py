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
from helper.package_files_helper import rpm_files_scanner
from helper.licenses_helper import rpm_licenses_scanner
from helper.hash_helper import calculate_sha1
from helper.suppliers_helper import get_suppliers, RPM_SUPPLIERS
from helper.originators_helper import extract_originator_name
from helper.relationships_helper import get_file_relationships
from helper.json_helper import save_data_to_json, read_data_from_json
from helper.src_package_helper import process_src_package
import logging
import rpmfile
import os


creators_file_path = os.path.join(ASSIST_DIR, 'creators.json')


def package_scanner(pkg_path, pkg_type, created_time):
    """
    扫描指定路径下的软件包，并根据软件包类型提取相关信息。

    Args:
        pkg_path (str): 软件包的文件路径。
        pkg_type (str): 软件包的类型。
        created_time (str): 创建时间，用于记录 SBOM 中的时间戳。
    Returns:
        dict: 包含处理后的软件包信息列表，包括 `packages_sbom`, `files_sbom`, `file_relationships_sbom`, `licenses_sbom`。
    """

    packages = []
    licenses = []
    files = []
    file_relationships = []
    originators_file_path = os.path.join(ASSIST_DIR, 'originators.json')
    originators = read_data_from_json(originators_file_path)

    if pkg_type == "rpm":
        package, licenses, files, file_relationships, originators, provides = process_rpm_package(
            pkg_path, originators)
    elif pkg_type == "source":
        package, licenses, files, file_relationships, originators = process_source_package(
            pkg_path, originators)
    packages.append(package)
    linx_sbom = {
        "packages_sbom": _add_header(packages, "packages", created_time),
        "files_sbom": _add_header(files, "files", created_time),
        "file_relationships_sbom": _add_header(file_relationships, "file_relationships", created_time),
        "licenses_sbom": _add_header(licenses, "licenses", created_time),
    }

    # 保存更新后的发起者信息
    save_data_to_json(originators, originators_file_path)

    # 返回处理后的软件包信息列表
    return linx_sbom


def process_rpm_package(pkg_path, originators):
    """
    处理单个 RPM 包，提取相关信息并生成相应的数据结构。

    Args:
        pkg_path (str): RPM 包的完整路径。
        originators (dict): 发起者信息字典。

    Returns:
        tuple: 包含以下元素的元组：
            - package_info (dict): 软件包信息。
            - licenses (list): 许可证列表。
            - files (list): 文件列表。
            - file_relationships (list): 文件关系列表。
            - originators (dict): 更新后的发起者信息字典。
            - provides (dict): 提供的文件列表及其关系。
    """

    with open(pkg_path, 'rb') as f:
        package_sha1 = calculate_sha1(f)
    try:
        with rpmfile.open(pkg_path) as rpm:
            name = _safe_decode(rpm.headers.get('name'))
            version = _safe_decode(rpm.headers.get('version'))
            release = _safe_decode(rpm.headers.get('release'))
            full_version = f"{version}-{release}"
            homepage = _safe_decode(rpm.headers.get('url'))
            architecture = _safe_decode(rpm.headers.get('arch'))

            # 提取发起者名称、判断是否为组织及更新发起者列表
            originator_name, is_organization, originators = extract_originator_name(
                homepage, originators)

            suppliers = get_suppliers(
                release, homepage, originator_name, RPM_SUPPLIERS)

            id_md5 = _safe_decode(rpm.headers.get('md5'))
            licenses = rpm_licenses_scanner(
                _safe_decode(rpm.headers.get('copyright')))
            license_id_list = [license.get("id") for license in licenses]
            files = rpm_files_scanner(pkg_path)
            package_info = {
                "id": f"Package-{name}-{id_md5}",
                "name": name,
                "version": full_version,
                "architecture": architecture,
                "package_type": "rpm",
                "depends": list(set(_safe_decode(dep) for dep in rpm.headers.get('requirename'))),
                "licenses": license_id_list,
                "suppliers": suppliers,
                "description": _safe_decode(rpm.headers.get('description')),
                "checksum": {
                    "value": package_sha1,
                    "algorithm": "SHA1"
                }
            }
            file_relationships = get_file_relationships(
                files, package_info["id"])
            provides = {
                "id": package_info.get('id'),
                "provides": list(set(_safe_decode(file) for file in rpm.headers.get('provides'))),
            }

        return package_info, licenses, files, file_relationships, originators, provides

    except Exception as e:
        logging.error(f'跳过 {pkg_path} 由于读取错误: {e}')
        return None


def process_source_package(pkg_path, originators):
    # TO-DO
    # return package_info, licenses, files, file_relationships, originators

    process_src_package(pkg_path, originators)
    package_info = {
        "id": "Package-Source",
        "name": "Source",
        "version": "Source",
        "architecture": "Source",
        "package_type": "source",
        "depends": [],
        "licenses": [],
        "suppliers": [],
        "description": "Source",
        "checksum": {
            "value": "Source",
            "algorithm": "Source"
        }
    }
    return package_info, [], [], [], originators

def _safe_decode(value):
    """
    安全地将字节串解码为 UTF-8 编码的字符串。

    Args:
        value (bytes or str): 需要解码的字节串或字符串。

    Returns:
        str: 解码后的字符串。如果输入值为 `None`，则返回空字符串。
    """

    return value.decode('utf-8') if value is not None else ''


def _add_header(sbom_data, data_name, created_time):
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
        "creation_info": {
            "creators": read_data_from_json(creators_file_path),
            "created": created_time
        },
        data_name: sbom_data
    }
    return sbom
