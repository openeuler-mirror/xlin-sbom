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

from helper.json_helper import read_data_from_json
import os


def convert_to_spdx(linx_sbom, os_name, created_time, package_type):
    """
    将给定的 SBOM 数据转换为 SPDX 格式。

    Args:
        linx_sbom (dict): 包含 SBOM 数据的字典，包括软件包、文件及其关系。
        os_name (str): 操作系统的名称。
        created_time (str): SPDX 文档的创建时间。

    Returns:
        dict: 转换后的 SPDX SBOM 字典。
    """

    spdx_packages = []
    spdx_files = []
    spdx_relationships = []
    spdx_licenses = []

    parent_dir = os.path.abspath(os.path.join(
        os.path.dirname(__file__), os.pardir))
    assist_dir = os.path.join(parent_dir, 'assist')
    creators_file_path = os.path.join(assist_dir, 'creators.json')

    def replace_none_value(str):
        if str == None or str == "":
            return "NOASSERTION"
        else:
            return str

    def process_supplier(str):
        if str == None or str == "":
            return "NOASSERTION"
        else:
            return f"Organization: {str}"

    # 遍历每个软件包并创建 SPDX 包元素
    for package in linx_sbom.get('packages_sbom').get('packages'):
        # 处理每个软件包的许可证
        license = ' AND '.join(package.get('licenses', []))
        supplier = package['suppliers'][0].get(
            'name', 'NOASSERTION') if package.get('suppliers') else 'NOASSERTION'

        # 构建 SPDX 包元素
        spdx_package = {
            "name": replace_none_value(package['name']),
            "SPDXID": f"SPDXRef-{package['id']}",
            "versionInfo": replace_none_value(package['version']),
            "supplier": process_supplier(supplier),
            "packageHomePage": replace_none_value(package['suppliers'][-1].get('link', 'NOASSERTION')) if package['suppliers'] else 'NOASSERTION',
            "packageDescription": replace_none_value(package['description']),
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": replace_none_value(license),
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE_MANAGER",
                    "referenceLocator": f"pkg:{package_type}/{package['name']}@{package['version']}?arch={package['architecture']}",
                    "referenceType": "purl",
                }
            ],
            "checksums": [
                {
                    "algorithm": replace_none_value(package['checksum']['algorithm']),
                    "checksumValue": replace_none_value(package['checksum']['value'])
                }
            ]
        }
        spdx_packages.append(spdx_package)

    # 构建 SPDX 文件元素
    if linx_sbom.get('files_sbom'):
        for file in linx_sbom.get('files_sbom').get('files'):
            spdx_file = {
                "fileName": file['name'],
                "SPDXID": f"SPDXRef-{file['name']}-{file['checksums']['value']}",
                "checksums": [
                    {
                        "algorithm": file['checksums']['algorithm'],
                        "checksumValue": file['checksums']['value']
                    }
                ]
            }
            spdx_files.append(spdx_file)

    # 创建 SPDX 文件元素和包与文件的关系
    if linx_sbom.get('file_relationships_sbom'):
        for file_relationship in linx_sbom.get('file_relationships_sbom').get('file_relationships'):
            spdx_file_relationship = {
                "spdxElementId": f"SPDXRef-{file_relationship['id']}",
                "relatedSpdxElement": f"SPDXRef-{file_relationship['related_element']}",
                "relationshipType": file_relationship['relationship_type']
            }
            spdx_relationships.append(spdx_file_relationship)

    # 创建 SPDX 包依赖关系
    if linx_sbom.get('package_relationships_sbom'):
        for package_relationship in linx_sbom.get('package_relationships_sbom').get('package_relationships'):
            spdx_package_relationship = {
                "spdxElementId": f"SPDXRef-{package_relationship['id']}",
                "relatedSpdxElement": f"SPDXRef-{package_relationship['related_element']}",
                "relationshipType": package_relationship['relationship_type']
            }
            spdx_relationships.append(spdx_package_relationship)

    # 创建 SPDX 许可证信息
    for license in linx_sbom.get('licenses_sbom').get('licenses'):
        spdx_license = {
            "licenseId": license['id'],
            "name": license['name'],
            "extractedText": f"The license info found in the package meta data is: {license['name']}. See the specific package info in this SPDX document or the package itself for more details."
        }
        spdx_licenses.append(spdx_license)

    # 构建最终的 SPDX SBOM 字典
    spdx_sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": os_name,
        "documentNamespace": os_name,
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
