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
from actions.data_helper import read_data_from_json
from typing import List, Dict
from scancode import api as scancode
import chardet
import logging
import os
import re
import hashlib
import tempfile


licenses_file_path = os.path.join(ASSIST_DIR, 'licenses.json')
SPDX_LICENSES_LIST = read_data_from_json(licenses_file_path)


def deb_licenses_scanner(deb, files):
    """
    扫描 Debian 包中的许可证信息，并生成许可证信息列表。

    Args:
        deb (DebFile): Debian 包对象。
        files (list): 包含文件信息的列表，每个元素是一个字典，包含 "path" 和 "name" 键。

    Returns:
        list: 包含许可证信息的列表。如果没有找到任何许可证信息，则返回空列表。
    """

    licenses = []

    # 筛选版权文件路径
    copyrights = [file_info["path"]
                  for file_info in files if file_info["name"].endswith("copyright")]

    # 遍历版权文件路径以提取和分析许可证信息
    data_tar = deb.data.tgz()
    for copyright_path in copyrights:
        try:
            # 提取文件内容
            extracted_file = data_tar.extractfile(copyright_path)
            if extracted_file is None:
                continue
            with extracted_file:
                content = extracted_file.read()
        except Exception as e:
            logging.error(f'处理失败: {copyright_path} - {str(e)}')
            continue

        # 解码内容并提取许可证列表
        decoded_content = _decode_content(content)
        license_list = _extract_deb_license_list(decoded_content)
        if len(license_list) == 0:
            license_list = _scancode_scanner(deb, copyright_path)

        # 处理识别到的许可证
        if license_list:
            for license_name in license_list:
                license_info = {
                    "id": f"LicenseRef-{(hashlib.md5(license_name.encode()).hexdigest())[:12]}",
                    "name": license_name,
                }
                licenses.append(license_info)

    return licenses

def rpm_licenses_scanner(license: str) -> List[Dict[str, str]]:
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
            "id": f"LicenseRef-{hashlib.md5(license_name.encode()).hexdigest()[:12]}",
            "name": license_name,
        }
        license_info_list.append(license_info)
    return license_info_list


def _decode_content(file_content):
    """
    解码文件内容，并处理可能出现的编码问题。

    Args:
        file_content (bytes): 文件的二进制内容。

    Returns:
        str: 解码后的文件内容。如果解码失败，则使用错误处理模式进行解码。
    """
    try:
        # 首选UTF-8解码
        return file_content.decode('utf-8')
    except UnicodeDecodeError:
        # 使用chardet检测文件内容的编码
        result = chardet.detect(file_content)
        encoding = result['encoding']
        return file_content.decode(encoding, errors='replace')
    
def _extract_deb_license_list(content):
    # 查找是否有特定格式指示行
    format_line_match = re.search(
        r'^Format:(.*)$', content, re.MULTILINE | re.IGNORECASE)

    # 根据是否找到特定格式行来决定使用哪种扫描方式
    if not format_line_match or ("dep5" not in format_line_match.group(1).strip() and "copyright-format/1.0" not in format_line_match.group(1).strip()):
        # 非标准格式或未找到格式指示，使用通用扫描策略
        license_list = _common_licenses_scanner(content)
    else:
        # 标准格式，使用机器可读格式扫描器
        license_list = _machine_readable_format_scanner(content)

    return license_list


def _machine_readable_format_scanner(content):
    """
    从给定的符合标准格式的files文件内容中提取许可证信息。

    Args:
        content (str): 标准格式的files文件内容。

    Returns:
        List[str]: 提取出的许可证信息列表。
    """
    licenses_set = set()
    files_matched = False

    # 定义正则表达式用于匹配文件和许可证信息
    files_regex = re.compile(r'^Files:(.*)$', re.MULTILINE | re.IGNORECASE)
    license_regex = re.compile(r'^License:(.*)$', re.MULTILINE | re.IGNORECASE)

    for line in content.splitlines():
        # 匹配并记录当前文件
        files_match = files_regex.match(line)
        if files_match:
            files_matched = True
            continue

        # 匹配并记录与当前文件对应的许可证信息，确保信息不重复
        license_match = license_regex.match(line)
        if license_match and files_matched:
            raw_license_info = license_match.group(1).strip()
            # 数据清洗：去除特定值、前后空格、句号和逗号
            cleaned_license_info = (
                raw_license_info.strip()  # 去除前后空格
            ).replace("<special license>", "")  # 移除特定字符串
            # 使用正则表达式去除句号和逗号
            cleaned_license_info = re.sub(
                ',', '', re.sub(r'[.]$', '', cleaned_license_info))
            if cleaned_license_info:  # 确保不是空字符串
                licenses_set.add(
                    _standardize_license_name(cleaned_license_info))
            files_matched = False

    return list(licenses_set)


def _common_licenses_scanner(content):
    """
    扫描提供的文本内容，识别并提取所有引用到 `/usr/share/common-licenses/` 目录下的许可证文件名，
    然后返回一个去重且排序的许可证文件名列表。

    Args:
        content (str): 需要扫描的文本内容。

    Returns:
        list: 一个列表，包含所有独特的许可证文件名，这些文件名从提供的内容中提取并去除了重复项。
              列表按文件名自然顺序排列。
    """

    # 定义正则表达式，匹配许可证文件路径
    license_regex = re.compile(
        r'/usr/share/common-licenses/[0-9A-Za-z_.+-]+[0-9A-Za-z+]')

    # 找到所有匹配项并提取文件名
    matches = license_regex.findall(content)

    # 提取许可证部分（从第5个斜杠开始到字符串末尾），并去除前后空格及末尾句号
    licenses = [
        _standardize_license_name(re.sub(r'[.]$', '', match.split('/', 4)[-1]).strip()) for match in matches
    ]

    # 去重并保持有序
    license_list = list(set(licenses))

    return license_list
    

def _scancode_scanner(deb, copyright_path):
    license_list = set()

    with tempfile.TemporaryDirectory() as tmpdir:
        tar = deb.data.tgz()  # 获取 tarfile 对象
        try:
            member = tar.getmember(copyright_path)
            tar.extract(member, path=tmpdir)
            tmp_path = os.path.join(tmpdir, copyright_path)
            scan_result = scancode.get_licenses(
                location=tmp_path, include_text=True)
            spdx_license = scan_result.get(
                'detected_license_expression_spdx', None)
            if spdx_license:
                license_list.add(spdx_license)
        except KeyError:
            logging.warning(f"路径不存在于包中: {copyright_path}")
        except Exception as e:
            logging.error(f"处理失败: {copyright_path} - {str(e)}")

    return list(license_list)


def _standardize_license_name(license_input: str) -> str:
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
