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
from helper.data_helper import read_data_from_json
import os
import re
import hashlib


licenses_file_path = os.path.join(ASSIST_DIR, 'licenses.json')
SPDX_LICENSES_LIST = read_data_from_json(licenses_file_path)


def rpm_licenses_scanner(license):
    """
    扫描 RPM 包的许可证信息，并生成许可证信息列表。

    Args:
        license (str): 许可证名称。

    Returns:
        list: 包含许可证信息的列表。如果 `license` 为空字符串，则返回空列表。
    """

    license_info_list = []
    if license != "":
        # 获取许可证标准名称
        license_name = _standardize_license_name(license)
        license_info = {
            "id": f"LicenseRef-{hashlib.md5(license_name.encode()).hexdigest()}",
            "name": license_name,
        }
        license_info_list.append(license_info)
    return license_info_list

def _standardize_license_name(license_input):
    """
    将提供的许可名称标准化为 SPDX 标准名称。

    Args:
        license_input (str): 输入的许可名称，可能是 SPDX 标准名称或其变体。

    Returns:
        str: 标准化的 SPDX 许可名称。如果未找到匹配项，则返回原始输入。
    """

    # 定义分隔符的正则表达式模式
    delimiter_pattern = r'(?i)(\s+or\s+|\s+and\s+|[()&|])'

    # 使用正则表达式按分隔符进行分割
    segments = re.split(delimiter_pattern, license_input)

    # 创建一个用于存放 (alt_name, spdxName) 对的列表
    replacement_pairs = []
    for license_info in SPDX_LICENSES_LIST:
        spdx_name = license_info.get("spdx_name")
        if not spdx_name:
            continue
        for alt_name in license_info.get("alt_names", []):
            replacement_pairs.append((alt_name, spdx_name))

    # 按 alt_name 的长度从长到短排序，确保长的先替换
    replacement_pairs.sort(key=lambda x: len(x[0]), reverse=True)

    # 遍历每个片段，检查是否匹配任何许可证名
    for i, segment in enumerate(segments):
        for alt_name, spdx_name in replacement_pairs:
            # 忽略大小写的匹配
            if segment.strip().lower() == alt_name.lower():
                segments[i] = spdx_name
                break

    # 将片段重新组合为最终字符串，确保空格被保留
    return ''.join(segments)
