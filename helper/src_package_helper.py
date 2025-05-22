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

import os
import tarfile
import zipfile
import rpmfile
import hashlib
import io
import logging
from typing import Dict, Any, Tuple, List
from helper.suppliers_helper import get_suppliers, RPM_SUPPLIERS
from helper.originators_helper import extract_originator_name
from helper.licenses_helper import rpm_licenses_scanner


def process_src_package(pkg_path: str, originators: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
    """
    处理源码包并返回其详细信息。

    Args:
        pkg_path (str): 源码包的文件路径。
        originators (Dict[str, Any]): 包含来源者信息的字典，用于在后续处理中提取和更新来源者信息。

    Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]: 如果处理 spec 文件，则返回一个元组，包含三个元素：
        - 第一个元素为字典，包含源码包的详细信息。
        - 第二个元素为列表，包含解析后的许可证信息。
        - 第三个元素为字典，更新后的来源者信息。
    """

    md5_value = _calculate_package_md5(pkg_path)
    package_type, content = _detect_package_type(pkg_path)

    if package_type == 'rpm':
        return _process_spec(content, md5_value, originators)
    elif package_type == 'deb':
        return _process_control(content, md5_value, originators)
    else:
        return _process_other_package(pkg_path, md5_value, originators)


def _calculate_package_md5(file_path: str) -> str:
    """
    计算文件的MD5校验和。

    Args:
        file_path (str): 文件的绝对路径或相对路径。

    Returns:
        str: 文件的MD5校验和，以十六进制字符串形式返回。
    """

    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def _detect_package_type(pkg_path: str) -> Tuple[str, str]:
    """
    检测源码包类型并返回类型和对应文件内容。

    Args:
        pkg_path (str): 源码包的文件路径，可以是绝对路径或相对路径。

    Returns:
        Tuple[str, str]: 返回一个元组，包含两个元素：
            - 第一个元素为字符串，表示检测到的源码包类型（如 'rpm', 'deb' 或 'other'）。
            - 第二个元素为字符串，表示对应文件的内容。如果未检测到特定类型，则返回空字符串。
    """

    MULTI_EXTENSIONS = (
        '.src.rpm',            # rpm源码格式
        '.tar.gz',  '.tgz',    # gzip压缩的tar
        '.tar.bz2', '.tbz2',   # bzip2压缩的tar
        '.tar.xz',  '.txz',    # xz压缩的tar
        '.tar',                # 未压缩的tar
        '.zip'                 # zip格式
    )
    lower_path = pkg_path.lower()

    for ext in MULTI_EXTENSIONS:
        if lower_path.endswith(ext):
            try:
                # 根据类型调用对应处理逻辑
                if ext == '.src.rpm':
                    with rpmfile.open(pkg_path) as rpm:
                        return _detect_from_src_rpm(rpm)
                if ext in ('.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz', '.tar'):
                    with tarfile.open(pkg_path, 'r:*') as tar:
                        return _detect_from_archive(tar, current_depth=0)
                elif ext == '.zip':
                    with zipfile.ZipFile(pkg_path, 'r') as z:
                        return _detect_from_zip(z, current_depth=0)
            except Exception as e:
                logging.error(f"处理 {ext} 格式时出错: {str(e)}")
                continue

    return ('other', '')


def _detect_from_src_rpm(rpm: rpmfile.RPMFile) -> Tuple[str, str]:
    """
    从 RPM 源码包中检测 spec 文件并返回其内容。

    Args:
        rpm (rpmfile.RPMFile): 已打开的 RPM 源码包文件对象，用于读取文件内容。

    Returns:
        Tuple[str, str]: 返回一个元组，包含两个元素：
            - 第一个元素为字符串，表示检测到的源码包类型（如 'rpm' 或 'other'）。
            - 第二个元素为字符串，表示 spec 文件的内容。如果未检测到 spec 文件，则返回空字符串。
    """
    for member in rpm.getmembers():
        if member.name.endswith('.spec'):
            content = rpm.extractfile(member).read().decode(
                'utf-8', errors='ignore')
            return ('rpm', content)
    return ('other', '')


def _detect_from_archive(tar: tarfile.TarFile, current_depth: int) -> Tuple[str, str]:
    """
    从 tar 压缩文件中检测源码包类型并返回类型和对应文件内容。

    Args:
        tar (tarfile.TarFile): 已打开的 tar 压缩文件对象，用于读取文件内容。
        current_depth (int): 当前递归深度，用于控制递归检测的深度。

    Returns:
        Tuple[str, str]: 返回一个元组，包含两个元素：
            - 第一个元素为字符串，表示检测到的源码包类型（如 'rpm', 'deb' 或 'other'）。
            - 第二个元素为字符串，表示对应文件的内容。如果未检测到特定类型，则返回空字符串。
    """

    return _detect_from_members(
        members=tar.getmembers(),
        extract_file=lambda m: tar.extractfile(m).read(),
        current_depth=current_depth
    )


def _detect_from_zip(zipf: zipfile.ZipFile, current_depth: int) -> Tuple[str, str]:
    """
    从 zip 压缩文件中检测源码包类型并返回类型和对应文件内容。

    Args:
        zipf (zipfile.ZipFile): 已打开的 zip 压缩文件对象，用于读取文件内容。
        current_depth (int): 当前递归深度，用于控制递归检测的深度。

    Returns:
        Tuple[str, str]: 返回一个元组，包含两个元素：
            - 第一个元素为字符串，表示检测到的源码包类型（如 'rpm', 'deb' 或 'other'）。
            - 第二个元素为字符串，表示对应文件的内容。如果未检测到特定类型，则返回空字符串。
    """

    return _detect_from_members(
        members=zipf.namelist(),
        extract_file=lambda m: zipf.open(m).read(),
        current_depth=current_depth,
        is_zip=True
    )


def _detect_from_members(members, extract_file, current_depth: int, is_zip=False) -> Tuple[str, str]:
    """
    从压缩文件成员中检测源码包类型并返回类型和对应文件内容。

    Args:
        members (list): 压缩文件中的成员列表。
        extract_file (Callable): 用于提取文件内容的函数。
        current_depth (int): 当前递归深度，用于控制递归检测的深度。
        is_zip (bool, optional): 布尔值，指示当前处理的是否为 zip 压缩文件。默认为 `False`，表示处理 tar 压缩文件。

    Returns:
        Tuple[str, str]: 返回一个元组，包含两个元素：
            - 第一个元素为字符串，表示检测到的源码包类型（如 'rpm', 'deb' 或 'other'）。
            - 第二个元素为字符串，表示对应文件的内容。如果未检测到特定类型，则返回空字符串。
    """

    MAX_DEPTH = 1
    if current_depth > MAX_DEPTH:
        return ('other', '')

    # 优先检测spec文件
    for member in members:
        member_name = member.name if not is_zip else member
        if member_name.endswith('.spec'):
            try:
                content = extract_file(member).decode('utf-8', errors='ignore')
                return ('rpm', content)
            except Exception as e:
                continue

    # 然后检测control文件
    for member in members:
        member_name = member.name if not is_zip else member
        if 'debian/control' in member_name:
            try:
                content = extract_file(member).decode('utf-8', errors='ignore')
                return ('deb', content)
            except Exception as e:
                continue

    # 最后检测嵌套压缩包
    for member in members:
        member_name = member.name if not is_zip else member
        ext = os.path.splitext(member_name)[1].lower()

        if ext in ('.tar.gz', '.tgz', '.tar.bz2', '.tar.xz', '.tar', '.zip'):
            try:
                data = extract_file(member)
                if ext == '.zip':
                    with zipfile.ZipFile(io.BytesIO(data)) as nested_zip:
                        return _detect_from_zip(nested_zip, current_depth+1)
                else:
                    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as nested_tar:
                        return _detect_from_archive(nested_tar, current_depth+1)
            except Exception as e:
                continue

    return ('other', '')


def _process_spec(spec_content: str, md5_value: str, originators: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
    """
    处理RPM源码包的spec文件内容，并返回源码包的详细信息。

    Args:
        spec_content (str): spec文件的内容，以字符串形式表示。
        md5_value (str): 源码包的MD5校验和，以十六进制字符串形式表示。
        originators (Dict[str, Any]): 包含来源者信息的字典，用于在后续处理中提取和更新来源者信息。

    Returns:
        Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]: 返回一个包含三个元素的元组：
            - 第一个元素为字典，包含源码包的详细信息，如包名、版本、依赖、许可证、供应商等。
            - 第二个元素为列表，包含解析后的许可证信息。
            - 第三个元素为字典，更新后的来源者信息。
    """

    def _process_requires(requires: list[str]):
        """
        处理RPM依赖项。

        Args:
            requires (list[str]): 依赖项列表，每个依赖项为字符串形式。

        Returns:
            list[str]: 处理后的依赖项列表，替换掉宏变量（如 %{name}, %{version}, %{release}）。
        """

        operators = {'>=', '<=', '>', '<', '=', '!=', '~>'}  # 定义可能的操作符集合
        processed_requires = []

        for require in requires:
            tokens = require.split()
            i = 0
            while i < len(tokens):
                if i + 1 < len(tokens) and tokens[i+1] in operators:
                    if i + 2 < len(tokens):
                        req = f"{tokens[i]} {tokens[i+1]} {tokens[i+2]}"
                        i += 3
                    else:
                        req = tokens[i]
                        i += 1
                else:
                    req = tokens[i]
                    i += 1
                processed_req = req.replace('%{name}', name).replace(
                    '%{version}', version).replace('%{release}', release)
                processed_requires.append(processed_req)
        return processed_requires

    # 解析spec文件内容
    spec_data = _parse_spec_content(spec_content)

    name = spec_data.get('name', 'unknown')
    version = spec_data.get('version', '')
    release = spec_data.get('release', '')

    build_requires = _process_requires(
        spec_data.get('buildrequires', []))  # TO-DO
    requires = _process_requires(spec_data.get('requires', []))

    homepage = spec_data.get('url', '')
    originator_name, is_organization, originators = extract_originator_name(
        homepage, originators)
    suppliers = get_suppliers(
        release, homepage, originator_name, RPM_SUPPLIERS)
    licenses = rpm_licenses_scanner(spec_data.get('license', ''))
    license_id_list = [license.get("id") for license in licenses]

    package_info = {
        "id": f"Package-{name}-{md5_value[:12]}",
        "name": name,
        "version": f"{version}-{release}",
        "architecture": spec_data.get('architecture', 'source'),
        "package_type": "source",
        "depends": requires,
        "licenses": license_id_list,
        "suppliers": suppliers,
        "description": spec_data.get('description', ''),
        "checksum": {
            "value": md5_value,
            "algorithm": "MD5"
        }
    }

    return package_info, licenses, originators


def _parse_spec_content(spec_content: str) -> Dict[str, Any]:
    """
    解析 RPM spec 文件内容并提取相关信息。

    Args:
        spec_content (str): spec 文件的内容，以字符串形式表示。

    Returns:
        Dict[str, Any]: 返回一个字典，包含从 spec 文件中提取的信息，包括：
            - `name`: 包名。
            - `version`: 版本号。
            - `release`: 发行号。
            - `license`: 许可证信息。
            - `url`: 主页 URL。
            - `buildrequires`: 构建依赖项列表。
            - `requires`: 运行时依赖项列表。
            - `architecture`: 架构信息。
            - `description`: 包的描述信息。
    """

    parsed = {}
    current_section = None
    description_lines = []
    in_preamble = True

    for line in spec_content.split('\n'):
        stripped_line = line.rstrip()

        if stripped_line.startswith('%package') and in_preamble:
            in_preamble = False

        if stripped_line.startswith('%'):
            current_section = stripped_line.split()[0].lower()
            continue

        if in_preamble:
            if stripped_line.lower().startswith('name:'):
                parsed['name'] = stripped_line.split(':', 1)[1].strip()
            elif stripped_line.lower().startswith('version:'):
                parsed['version'] = stripped_line.split(':', 1)[1].strip()
            elif stripped_line.lower().startswith('release:'):
                parsed['release'] = stripped_line.split(':', 1)[1].strip()
            elif stripped_line.lower().startswith('license:'):
                parsed['license'] = stripped_line.split(':', 1)[1].strip()
            elif stripped_line.lower().startswith('url:'):
                parsed['url'] = stripped_line.split(':', 1)[1].strip()
            elif stripped_line.lower().startswith('buildrequires:'):
                buildrequires = [r.strip() for r in stripped_line.split(
                    ':', 1)[1].split(',') if r.strip()]
                parsed.setdefault('buildrequires', []).extend(buildrequires)
            elif stripped_line.lower().startswith('requires:'):
                requires = [r.strip() for r in stripped_line.split(
                    ':', 1)[1].split(',') if r.strip()]
                parsed.setdefault('requires', []).extend(requires)
            elif stripped_line.lower().startswith('buildarch:'):
                parsed['architecture'] = stripped_line.split(':', 1)[1].strip()

            if current_section == '%description':
                description_lines.append(stripped_line)

    if description_lines:
        parsed['description'] = ' '.join(
            [l.strip() for l in description_lines if l.strip()]
        )

    return parsed


def _process_control(control_content: str, md5_value: str, originators: Dict[str, Any]) -> Dict[str, Any]:
    """
    处理DEB源码包的占位函数
    """
    # TODO: 实现DEB包处理逻辑
    return {
        "id": "",
        "name": "",
        "version": "",
        "architecture": "",
        "package_type": "source",
        "depends": [],
        "licenses": [],
        "suppliers": [],
        "description": "",
        "checksum": {
            "value": md5_value,
            "algorithm": "MD5"
        }
    }, [], originators


def _process_other_package(pkg_path: str, md5_value: str, originators: Dict[str, Any]) -> Dict[str, Any]:
    """
    处理其他类型源码包的占位函数
    """
    # TODO: 实现其他类型处理逻辑
    return {
        "id": "",
        "name": "",
        "version": "",
        "architecture": "",
        "package_type": "source",
        "depends": [],
        "licenses": [],
        "suppliers": [],
        "description": "",
        "checksum": {
            "value": md5_value,
            "algorithm": "MD5"
        }
    }, [], originators
