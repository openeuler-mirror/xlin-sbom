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

from actions.data_helper import read_data_from_json
from typing import Any, Dict, List
from actions import ASSIST_DIR
import os


def convert_to_spdx(
    linx_sbom: Dict[str, Any],
    filename: str,
    created_time: str,
    package_type: str
) -> Dict[str, Any]:
    """
    将给定的 SBOM 数据转换为 SPDX 格式。

    Args:
        linx_sbom (dict): 包含 SBOM 数据的字典，包括软件包、文件及其关系。
        filename (str): 生成的 SBOM 文件的基本名称。
        created_time (str): SPDX 文档的创建时间。
        package_type (str): 包类型，用于生成 purl 标识符。

    Returns:
        dict: 转换后的 SPDX SBOM 字典。
    """

    spdx_packages = [
        _build_spdx_package(package, package_type)
        for package in linx_sbom.get('packages_sbom', {}).get('packages', [])
    ]
    spdx_files = [
        _build_spdx_file(file_info)
        for file_info in linx_sbom.get('files_sbom', {}).get('files', [])
    ]
    spdx_relationships = _build_spdx_relationships(linx_sbom)
    spdx_licenses = [
        _build_spdx_license(license_info)
        for license_info in linx_sbom.get('licenses_sbom', {}).get('licenses', [])
    ]

    creators_file_path = os.path.join(ASSIST_DIR, 'creators.json')

    # 构建最终的 SPDX SBOM 字典
    spdx_sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": filename,
        "documentNamespace": filename,
        "creationInfo": {
            "licenseListVersion": "3.23",
            "creators": read_data_from_json(creators_file_path),
            "created": created_time
        },
        "packages": spdx_packages,
        "files": spdx_files,
        "hasExtractedLicensingInfos": spdx_licenses
    }
    if spdx_relationships:
        spdx_sbom["relationships"] = spdx_relationships

    return spdx_sbom


def _no_assertion(value: Any) -> Any:
    """将空值转换为 SPDX 的 NOASSERTION 表达。

    Args:
        value (Any): 待转换的值。

    Returns:
        Any: 原值或 NOASSERTION。
    """

    return "NOASSERTION" if value is None or value == "" else value


def _format_supplier(name: str) -> str:
    """格式化 SPDX supplier 字段。

    Args:
        name (str): 供应商名称。

    Returns:
        str: SPDX supplier 字段值。
    """

    return "NOASSERTION" if not name or name == "NOASSERTION" else f"Organization: {name}"


def _build_spdx_package(package: Dict[str, Any], package_type: str) -> Dict[str, Any]:
    """构建 SPDX package 元素。

    Args:
        package (dict): Linx 包数据。
        package_type (str): 包类型。

    Returns:
        dict: SPDX package 元素。
    """

    license_expression = ' AND '.join(package.get('licenses', []))
    suppliers = package.get('suppliers') or []
    supplier_name = suppliers[0].get('name', 'NOASSERTION') if suppliers else 'NOASSERTION'
    homepage = suppliers[-1].get('link', 'NOASSERTION') if suppliers else 'NOASSERTION'
    architecture = package.get('architecture', '')
    purl_arch = f"?arch={architecture}" if architecture else ""
    checksum = package.get('checksum', {})

    return {
        "name": _no_assertion(package.get('name')),
        "SPDXID": f"SPDXRef-{package.get('id')}",
        "versionInfo": _no_assertion(package.get('version')),
        "supplier": _format_supplier(supplier_name),
        "packageHomePage": _no_assertion(homepage),
        "packageDescription": _no_assertion(package.get('description')),
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": _no_assertion(license_expression),
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE_MANAGER",
                "referenceLocator": (
                    f"pkg:{package_type}/{package.get('name')}@"
                    f"{package.get('version')}{purl_arch}"
                ),
                "referenceType": "purl",
            }
        ],
        "checksums": [
            {
                "algorithm": _no_assertion(checksum.get('algorithm')),
                "checksumValue": _no_assertion(checksum.get('value')),
            }
        ],
    }


def _build_spdx_file(file_info: Dict[str, Any]) -> Dict[str, Any]:
    """构建 SPDX file 元素。

    Args:
        file_info (dict): Linx 文件数据。

    Returns:
        dict: SPDX file 元素。
    """

    checksum = file_info.get('checksums', {})
    return {
        "fileName": file_info.get('name'),
        "SPDXID": f"SPDXRef-{file_info.get('id')}",
        "checksums": [
            {
                "algorithm": checksum.get('algorithm'),
                "checksumValue": checksum.get('value'),
            }
        ],
    }


def _build_spdx_relationships(linx_sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
    """构建 SPDX relationships 列表。

    Args:
        linx_sbom (dict): Linx SBOM 数据。

    Returns:
        list: SPDX relationship 元素列表。
    """

    relationships = []
    for group_name, data_name in (
        ('file_relationships_sbom', 'file_relationships'),
        ('package_relationships_sbom', 'package_relationships'),
    ):
        for relationship in linx_sbom.get(group_name, {}).get(data_name, []):
            relationships.append({
                "spdxElementId": f"SPDXRef-{relationship['id']}",
                "relatedSpdxElement": f"SPDXRef-{relationship['related_element']}",
                "relationshipType": relationship['relationship_type'],
            })
    return relationships


def _build_spdx_license(license_info: Dict[str, Any]) -> Dict[str, str]:
    """构建 SPDX extracted license 元素。

    Args:
        license_info (dict): Linx 许可证数据。

    Returns:
        dict: SPDX extracted license 元素。
    """

    license_name = license_info['name']
    return {
        "licenseId": license_info['id'],
        "name": license_name,
        "extractedText": (
            "The license info found in the package meta data is: "
            f"{license_name}. See the specific package info in this SPDX "
            "document or the package itself for more details."
        ),
    }
